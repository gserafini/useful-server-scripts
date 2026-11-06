"""php_pool_logrotate: safe paths only, rename-and-create rotation, and no lost lines for the PHP monitor."""
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/php_pool_logrotate.py'
spec = importlib.util.spec_from_file_location('php_pool_logrotate', SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
CORE = '/root/php-monitor/server-watchdog-php-core.js'
POOL = '[x]\nuser = "{user}"\ngroup = "{user}"\nphp_admin_value[error_log] = {log}\nphp_admin_flag[log_errors] = on\n'


class Base(unittest.TestCase):
    def setUp(self):
        base = os.environ.get('TMPDIR') or str(Path.home() / '.cache')
        self.root = Path(tempfile.mkdtemp(prefix='pool-logrotate-', dir=base))
        self.home = self.root / 'home' / 'acct'
        (self.home / 'logs').mkdir(parents=True, mode=0o700)
        self.confs = self.root / 'php-fpm.d'
        self.confs.mkdir()
        self.acct = {'name': 'root', 'uid': os.getuid(), 'gid': os.getgid(), 'group': 'root', 'home': str(self.home)}

    def tearDown(self):
        subprocess.run(['rm', '-rf', str(self.root)], check=False)

    def pool(self, name, log, user='acct'):
        (self.confs / f'{name}.conf').write_text(POOL.format(user=user, log=log))

    def lookup(self, user):
        if user != 'acct':
            raise KeyError(user)
        return self.acct


class PlanTests(Base):
    def test_parse_pool_reads_user_and_error_log(self):
        self.assertEqual(mod.parse_pool(POOL.format(user='bob', log='/home/bob/logs/a_com.php.error.log')),
                         ('bob', '/home/bob/logs/a_com.php.error.log'))
        self.assertIsNone(mod.parse_pool('[x]\nuser = bob\n'))

    def test_only_safe_paths_inside_the_account_logs_dir_are_kept(self):
        logs = self.home / 'logs'
        good = logs / 'a_com.php.error.log'
        good.write_text('x\n')
        (logs / 'linked.php.error.log').symlink_to(good)
        self.pool('good', str(good))
        self.pool('dupe', str(good))
        self.pool('link', str(logs / 'linked.php.error.log'))
        self.pool('outside', str(self.home / 'public_html' / 'error_log'))
        self.pool('name', str(logs / 'access_log'))
        self.pool('stranger', str(logs / 'b_com.php.error.log'), user='nobody-here')
        self.pool('missing', str(logs / 'new_com.php.error.log'))
        by_user, skipped = mod.plan(str(self.confs / '*.conf'), lookup=self.lookup)
        self.assertEqual(sorted(by_user['acct']['logs']), [str(good), str(logs / 'new_com.php.error.log')])
        reasons = sorted(s['reason'] for s in skipped)
        self.assertEqual(reasons, ['file name is not *.php.error.log', 'log is a symlink or not a regular file',
                                   'not directly inside the account logs directory', 'unknown user nobody-here'])

    def test_writable_or_foreign_logs_dir_is_refused(self):
        log = str(self.home / 'logs' / 'a_com.php.error.log')
        os.chmod(self.home / 'logs', 0o770)
        self.assertEqual(mod.reject_reason(self.acct, log), 'logs directory is group or world writable')
        os.chmod(self.home / 'logs', 0o755)
        self.assertEqual(mod.reject_reason(dict(self.acct, uid=self.acct['uid'] + 4242), log), 'logs directory not owned by the account')

    def test_render_rotates_each_account_as_itself_with_rename_and_create(self):
        text = mod.render({'acct': {'acct': self.acct, 'logs': ['/x/b.php.error.log', '/x/a.php.error.log']}})
        self.assertIn('/x/a.php.error.log /x/b.php.error.log {', text)
        for directive in ('su root root', 'create', 'delaycompress', 'dateformat -%Y%m%d-%s', 'missingok', 'notifempty'):
            self.assertIn('    ' + directive + '\n', text)
        self.assertNotIn('copytruncate', text)


class RotationTests(Base):
    def rotate(self, log, rotate=2):
        by_user, _ = mod.plan(str(self.confs / '*.conf'), lookup=self.lookup)
        conf = self.root / 'rot.conf'
        mod.write_checked(str(conf), mod.render(by_user, rotate=rotate), '/usr/sbin/logrotate')
        run = subprocess.run(['/usr/sbin/logrotate', '-f', '-s', str(self.root / 'state'), str(conf)], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        return sorted(p.name for p in log.parent.iterdir() if p.name != log.name)

    def test_rename_create_then_compress_one_cycle_later_and_prune(self):
        log = self.home / 'logs' / 'a_com.php.error.log'
        log.write_text('first\n')
        os.chmod(log, 0o640)
        self.pool('a', str(log))
        ino = log.stat().st_ino
        rotated = self.rotate(log)
        self.assertEqual(len(rotated), 1)
        self.assertRegex(rotated[0], r'^a_com\.php\.error\.log-\d{8}-\d+$')
        self.assertEqual((self.home / 'logs' / rotated[0]).stat().st_ino, ino, 'the old generation keeps its inode')
        self.assertEqual(log.stat().st_size, 0)
        self.assertEqual(log.stat().st_mode & 0o777, 0o640, 'create keeps the original mode')
        for n in range(3):
            log.write_text(f'gen {n}\n')
            os.utime(log)
            import time; time.sleep(1.1)  # the -%s suffix needs a new second per rotation
            rotated = self.rotate(log)
        plain = [r for r in rotated if not r.endswith('.gz')]
        self.assertEqual(len(plain), 1, 'only the newest generation stays uncompressed (delaycompress)')
        self.assertLessEqual(len(rotated), 2, 'rotate 2 prunes older generations')

    def test_empty_log_is_not_rotated(self):
        log = self.home / 'logs' / 'quiet_com.php.error.log'
        log.write_text('')
        self.pool('q', str(log))
        self.assertEqual(self.rotate(log), [])


@unittest.skipUnless(os.path.exists(CORE), 'PHP monitor collector not installed')
class CollectorTests(Base):
    """The production collector must read every line across a rotation, with no gap."""
    def read(self, log, state):
        js = ("const core=require(process.argv[1]);const fs=require('fs');const st=JSON.parse(fs.readFileSync(process.argv[3],'utf8'));"
              "const r=core.readIncrement(process.argv[2],st,{});fs.writeFileSync(process.argv[3],JSON.stringify(st));"
              "console.log(JSON.stringify({lines:r.lines,gaps:r.gaps,missing:r.missing,truncated:!!r.truncated}))")
        out = subprocess.run(['node', '-e', js, CORE, str(log), str(state)], capture_output=True, text=True, check=True)
        return json.loads(out.stdout)

    def test_lines_written_before_and_after_rotation_are_all_read(self):
        log = self.home / 'logs' / 'c_com.php.error.log'
        state = self.root / 'collector.json'
        state.write_text('{}')
        log.write_text('[06-Nov-2026 10:00:00 UTC] one\n')
        self.pool('c', str(log))
        self.assertEqual(self.read(log, state)['lines'], ['[06-Nov-2026 10:00:00 UTC] one'])
        with open(log, 'a') as fh:
            fh.write('[06-Nov-2026 10:01:00 UTC] two, unread at rotation\n')
        RotationTests.rotate(self, log)
        with open(log, 'a') as fh:
            fh.write('[06-Nov-2026 10:02:00 UTC] three\n')
        r = self.read(log, state)
        self.assertEqual(r['lines'], ['[06-Nov-2026 10:01:00 UTC] two, unread at rotation', '[06-Nov-2026 10:02:00 UTC] three'])
        self.assertEqual((r['gaps'], r['missing'], r['truncated']), ([], False, False))

    def test_copytruncate_would_lose_the_interval(self):
        """Why the script never uses copytruncate: the collector reports a gap."""
        log = self.home / 'logs' / 'd_com.php.error.log'
        state = self.root / 'collector.json'
        state.write_text('{}')
        log.write_text('[06-Nov-2026 10:00:00 UTC] one\n')
        self.read(log, state)
        log.write_text('')
        self.assertTrue(self.read(log, state)['truncated'])


if __name__ == '__main__':
    unittest.main()
