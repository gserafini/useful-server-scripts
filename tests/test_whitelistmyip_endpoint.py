"""whitelist_ip.php: caller-locked, data-only intake whose output the processor accepts (server_ops B2003)."""
import importlib.util
import json
import os
import pwd
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENDPOINT = ROOT / 'config/whitelistmyip/whitelist_ip.php'
PHP = os.environ.get('PHP_BIN') or next(
    (p for p in ('/opt/cpanel/ea-php85/root/usr/bin/php', '/usr/local/bin/php', '/usr/bin/php') if os.path.exists(p)), None)
spec = importlib.util.spec_from_file_location('whitelistmyip_process', ROOT / 'scripts/whitelistmyip_process.py')
proc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proc)

PREPEND = r'''<?php
$_SERVER['REMOTE_ADDR'] = getenv('WL_REMOTE_ADDR');
$_REQUEST = json_decode(getenv('WL_REQUEST'), true);
'''


@unittest.skipUnless(PHP, 'php CLI not available')
class EndpointTests(unittest.TestCase):
    def setUp(self):
        base = os.environ.get('TMPDIR') or str(Path.home() / '.cache')
        os.makedirs(base, exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix='whitelistmyip-php-', dir=base))
        self.docroot = self.root / 'home' / 'public_html' / 'version-checker'
        self.docroot.mkdir(parents=True)
        shutil.copy(ENDPOINT, self.docroot / 'whitelist_ip.php')
        self.spool = self.root / 'home' / 'whitelistmyip-spool'
        self.spool.mkdir(mode=0o700)
        self.prepend = self.root / 'prepend.php'
        self.prepend.write_text(PREPEND)

    def tearDown(self):
        subprocess.run(['rm', '-rf', str(self.root)], check=False)

    def call(self, request, caller='198.54.116.2', expect_log=''):
        env = dict(os.environ, WL_REMOTE_ADDR=caller, WL_REQUEST=json.dumps(request))
        out = subprocess.run([PHP, '-n', '-d', f'auto_prepend_file={self.prepend}', '-d', 'display_errors=stderr',
                              '-d', 'log_errors=0', str(self.docroot / 'whitelist_ip.php')],
                             capture_output=True, text=True, env=env, timeout=30)
        if expect_log:
            self.assertIn(expect_log, out.stderr)
        else:
            self.assertEqual(out.stderr, '')
        return json.loads(out.stdout)

    def queued(self):
        return sorted(p for p in self.spool.iterdir() if p.suffix == '.json')

    def valid(self, **changes):
        request = dict(ip='1.2.3.4', name='Pat Client', email='client@example.com',
                       website_url='example.org')
        request.update(changes)
        return request

    def test_unknown_callers_are_refused_without_queueing(self):
        for caller in ('181.214.133.151', '127.0.0.1', '', '198.54.116.20', '198.54.114.20'):
            self.assertEqual(self.call(self.valid(), caller=caller), {'success': False})
        self.assertEqual(self.queued(), [])

    def test_both_form_host_addresses_are_accepted(self):
        for caller in ('198.54.114.2', '198.54.116.2'):
            self.assertEqual(self.call(self.valid(), caller=caller), {'success': True}, caller)
        self.assertEqual(len(self.queued()), 2)

    def test_valid_request_is_queued_once_as_private_json(self):
        self.assertEqual(self.call(self.valid()), {'success': True})
        files = self.queued()
        self.assertEqual(len(files), 1)
        self.assertRegex(files[0].stem, r'^[0-9]{10}-[0-9a-f]{16}$')
        self.assertEqual(stat.S_IMODE(files[0].stat().st_mode), 0o600)
        record = json.loads(files[0].read_text())
        self.assertEqual({k: record[k] for k in ('ip', 'name', 'email', 'website', 'caller')},
                         {'ip': '1.2.3.4', 'name': 'Pat Client', 'email': 'client@example.com',
                          'website': 'example.org', 'caller': '198.54.116.2'})
        self.assertEqual([p.name for p in self.spool.iterdir() if p.name.startswith('.tmp-')], [])

    def test_bad_addresses_and_emails_are_rejected(self):
        for ip in ('10.0.0.1', '127.0.0.1', '192.168.1.1', 'garbage', '1.2.3.4;id', '', '0.0.0.0',
                   '100.64.1.1', '198.18.0.1', '2001:db8::1'):
            self.assertEqual(self.call(self.valid(ip=ip)), {'success': False}, ip)
        for address in ('not-an-email', 'a@b', '', 'x' * 250 + '@example.com'):
            self.assertEqual(self.call(self.valid(email=address)), {'success': False}, address)
        self.assertEqual(self.call(self.valid(ip=['1.2.3.4'])), {'success': False})
        self.assertEqual(self.queued(), [])

    def test_hostile_text_is_flattened_and_never_reaches_a_shell(self):
        name = 'Pat\r\nBcc: x@y.z‮ `id` $(id); rm -rf /'
        self.assertEqual(self.call(self.valid(name=name, website_url='x.org"\n; reboot')), {'success': True})
        record = json.loads(self.queued()[0].read_text())
        self.assertNotIn('\n', record['name'] + record['website'])
        self.assertNotIn('‮', record['name'])
        self.assertEqual(record['name'], 'Pat Bcc: x@y.z `id` $(id); rm -rf /')

    def test_non_string_fields_and_missing_optional_fields_are_tolerated(self):
        self.assertEqual(self.call(self.valid(name=['a'], website_url={'b': 1})), {'success': True})
        record = json.loads(self.queued()[0].read_text())
        self.assertEqual((record['name'], record['website']), ('', ''))

    def test_missing_or_full_spool_fails_closed(self):
        for i in range(50):
            (self.spool / f'17950000{i:02d}-{"0" * 16}.json').write_text('{}')
        self.assertEqual(self.call(self.valid(), expect_log='request spool is full'), {'success': False})
        shutil.rmtree(self.spool)
        self.assertEqual(self.call(self.valid(), expect_log='is missing'), {'success': False})

    def test_processor_accepts_exactly_what_the_endpoint_writes(self):
        self.assertEqual(self.call(self.valid(name='Pat\nClient')), {'success': True})
        cfg = proc.Config(spool_dir=str(self.spool), spool_owner=pwd.getpwuid(os.getuid()).pw_name,
                          state_dir=str(self.root / 'state'))
        accepted, rejected = proc.read_spool(cfg, now=float(self.queued()[0].stem.split('-')[0]))
        self.assertEqual(rejected, [])
        self.assertEqual(len(accepted), 1)
        request = proc.parse_request(accepted[0][1], accepted[0][0], set())
        self.assertEqual((request.ip, request.name, request.email, request.website, request.caller),
                         ('1.2.3.4', 'Pat Client', 'client@example.com', 'example.org', '198.54.116.2'))


if __name__ == '__main__':
    unittest.main()
