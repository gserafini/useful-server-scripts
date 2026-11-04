"""tmp_scratch_guard: only stale, root-owned, unused top-level entries lose group/other access."""
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/tmp_scratch_guard.py'
OLD = time.time() - 7200


class GuardTests(unittest.TestCase):
    def setUp(self):
        base = os.environ.get('TMPDIR') or str(Path.home() / '.cache')
        self.root = Path(tempfile.mkdtemp(prefix='scratch-guard-', dir=base))
        self.root.chmod(0o1777)  # behaves like /tmp
        self.log = self.root.parent / (self.root.name + '.log')
        self.disable = self.root.parent / (self.root.name + '.disable')

    def tearDown(self):
        subprocess.run(['rm', '-rf', str(self.root), str(self.log), str(self.disable)], check=False)

    def make(self, name, mode, kind='f', age=OLD):
        p = self.root / name
        if kind == 'd':
            p.mkdir()
            (p / 'inner.json').write_text('{}')
        else:
            p.write_text('data')
        p.chmod(mode)
        os.utime(p, (age, age))
        return p

    def run_guard(self, *extra):
        cmd = [sys.executable, '-I', str(SCRIPT), '--root', str(self.root), '--min-age', '3600',
               '--log', str(self.log), '--disable-file', str(self.disable), *extra]
        return subprocess.run(cmd, capture_output=True, text=True)

    def mode(self, p):
        return os.lstat(p).st_mode & 0o7777

    def test_stale_world_readable_file_and_dir_become_private(self):
        f = self.make('overview_primary_threads.json', 0o644)
        d = self.make('dmarc-fixture-abc123', 0o755, 'd')
        r = self.run_guard()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.mode(f), 0o600)
        self.assertEqual(self.mode(d), 0o700)
        self.assertIn('overview_primary_threads.json', self.log.read_text())

    def test_fresh_private_sticky_system_symlink_untouched(self):
        fresh = self.make('fresh.json', 0o644, age=time.time())
        private = self.make('private.json', 0o600)
        sticky = self.make('shared-sticky', 0o1777, 'd')
        system = self.make('.X11-unix', 0o755, 'd')
        sd = self.make('systemd-private-abc-httpd.service-xyz', 0o755, 'd')
        target = self.make('target.json', 0o644, age=time.time())
        link = self.root / 'link'
        link.symlink_to(target)
        r = self.run_guard()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.mode(fresh), 0o644)
        self.assertEqual(self.mode(private), 0o600)
        self.assertEqual(self.mode(sticky), 0o1777)
        self.assertEqual(self.mode(system), 0o755)
        self.assertEqual(self.mode(sd), 0o755)
        self.assertEqual(self.mode(target), 0o644)  # never followed through the symlink

    def test_non_root_owned_entry_untouched(self):
        p = self.make('tenant.json', 0o644)
        os.chown(p, 65534, 65534)
        r = self.run_guard()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.mode(p), 0o644)

    def test_entry_in_use_untouched(self):
        p = self.make('held-open.json', 0o644)
        with open(p) as fh:  # this test process holds it open
            r = self.run_guard()
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(self.mode(p), 0o644)
        self.assertTrue(fh.closed)

    def test_dry_run_and_disable_file_change_nothing(self):
        p = self.make('stale.json', 0o644)
        r = self.run_guard('--dry-run')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('stale.json', r.stdout)
        self.assertEqual(self.mode(p), 0o644)
        self.disable.write_text('paused for review\n')
        r = self.run_guard()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.mode(p), 0o644)
        self.assertIn('disabled', r.stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
