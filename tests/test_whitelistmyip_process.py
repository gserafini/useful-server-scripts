"""whitelistmyip_process: validated, shell-free unblocking for WhitelistMyIP.com requests (server_ops B2003)."""
import email
import email.policy
import fcntl
import importlib.util
import json
import os
import pwd
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/whitelistmyip_process.py'
spec = importlib.util.spec_from_file_location('whitelistmyip_process', SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

CLIENT = '1.2.3.4'
OTHER = '5.6.7.8'
NOW = 1795000000.0
ME = pwd.getpwuid(os.getuid()).pw_name
LIFTABLE_DENY = 'lfd: (mod_security) mod_security (id:999051) triggered by 1.2.3.4 (US/United States/-): 5 in the last 3600 secs'
LIFTABLE_TRACK = 'Violations: 5, error_log ModSecurity AH01797: client denied by server configuration'


def scratch(prefix):
    # /tmp is noexec on cPanel hosts; stub binaries must live on an exec filesystem.
    base = os.environ.get('TMPDIR') or str(Path.home() / '.cache')
    os.makedirs(base, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=prefix, dir=base))


class FakeRemote:
    """In-memory dc2-5, answering the processor's SSH calls the way REMOTE_SCRIPT does."""

    def __init__(self):
        self.deny, self.temp, self.tracking = {}, {}, {}
        self.ipset, self.allow, self.wp_login, self.web_allow = set(), set(), set(), {}
        self.country = 'US'
        self.calls = []
        self.fail = False
        self.omit_verify = False

    def evidence(self, ip, prefix=''):
        wp = ip in self.wp_login
        values = dict(deny='yes' if ip in self.deny else 'no', deny_reason=self.deny.get(ip, ''), deny_range='',
                      temp='yes' if ip in self.temp else 'no', temp_detail=self.temp.get(ip, ''),
                      web_allow=','.join(sorted(self.web_allow.get(ip, set()))),
                      ipset_live='yes' if ip in self.ipset else 'no', tracking='yes' if ip in self.tracking else 'no',
                      tracking_reason=self.tracking.get(ip, ''), blocklists='', allow='yes' if ip in self.allow else 'no',
                      wp_login='yes' if wp else 'no', country=self.country,
                      wp_needed='yes' if not wp and self.country != 'US' else 'no')
        return ''.join(f'{prefix}{k}={v}\n' for k, v in values.items())

    def handle(self, remote_command):
        self.calls.append(remote_command)
        if self.fail:
            return mod.Result(255, '', 'ssh: connect to host dc2-5 port 22022: Connection timed out')
        words = shlex.split(remote_command)
        assert words[:3] == ['bash', '-s', '--'], words
        mode, ip = words[3], words[4]
        out = self.evidence(ip)
        if mode == 'apply' and ip not in self.allow:
            if self.deny.pop(ip, None) is not None:
                out += 'action.deny-remove=ok\n'
            if self.temp.pop(ip, None) is not None:
                out += 'action.temp-remove=ok\n'
            if ip in self.ipset or ip in self.tracking:
                self.ipset.discard(ip)
                self.tracking.pop(ip, None)
                out += 'action.ipset-remove=ok\n'
            for port in ('80', '443'):
                if port not in self.web_allow.get(ip, set()):
                    self.web_allow.setdefault(ip, set()).add(port)
                    out += f'action.web-allow-{port}=ok\n'
        if mode in ('apply', 'wp-only') and ip not in self.wp_login and self.country != 'US':
            self.wp_login.add(ip)
            out += 'action.apache-graceful=ok\naction.wp-login-allow=ok\n'
        if mode != 'check' and not self.omit_verify:
            out += self.evidence(ip, 'verify.')
        return mod.Result(0, out, '')


class FakeSystem:
    """File-backed dc3-1 firewall state plus a recording command runner."""

    def __init__(self, root):
        self.root = root
        self.etc = root / 'etc'
        self.etc.mkdir()
        self.deny_file = self.etc / 'csf.deny'
        self.allow_file = self.etc / 'csf.allow'
        self.tempban_file = self.etc / 'csf.tempban'
        self.tempallow_file = self.etc / 'csf.tempallow'
        self.tracking_file = self.etc / 'tracking.log'
        self.wp_file = self.etc / 'csf_whitelist_ips.conf'
        for f in (self.deny_file, self.allow_file, self.tempban_file, self.tempallow_file, self.tracking_file):
            f.write_text('')
        self.wp_file.write_text('Allow from 203.0.113.9\n')
        self.ipset = set()
        self.country = 'US'
        self.configtest_rc = 0
        self.calls = []
        self.mail = []
        self.wakes = []
        self.remote = FakeRemote()
        self.local_ips = ['181.214.133.151', '127.0.0.1', '100.108.148.1']
        self.explode_on = set()
        self.rdns = {}

    def config(self, **overrides):
        spool = self.root / 'spool'
        spool.mkdir(exist_ok=True)
        values = dict(spool_dir=str(spool), spool_owner=ME, state_dir=str(self.root / 'state'),
                      csf_allow=str(self.allow_file), csf_deny=str(self.deny_file),
                      tempban_file=str(self.tempban_file), tempallow_file=str(self.tempallow_file),
                      tracking_file=str(self.tracking_file), blocklist_glob=str(self.etc / 'csf.block.*'),
                      wp_login_allow_file=str(self.wp_file), extra_protected=('162.252.82.190',),
                      endpoint_logs=(str(self.etc / 'domlog'),))
        values.update(overrides)
        return mod.Config(**values)

    # --- state helpers -------------------------------------------------
    def add_deny(self, ip, reason=LIFTABLE_DENY):
        with self.deny_file.open('a') as f:
            f.write(f'{ip} # {reason}\n')

    def add_tracking(self, ip, reason=LIFTABLE_TRACK):
        self.ipset.add(ip)
        with self.tracking_file.open('a') as f:
            f.write(f'{ip} # [2026-10-24 12:16:12] csf_ban_wp_login_attackers inserted IP to ipset [{reason}] (United States)\n')

    def add_temp(self, path, ip, port='', comment='(mod_security) lfd temporary block'):
        with path.open('a') as f:
            f.write(f'{int(NOW)}|{ip}|{port}|in|3600|{comment}\n')

    def lines(self, path):
        return [line for line in path.read_text().splitlines() if line.strip()]

    def has_exact(self, path, ip):
        return any(line.split()[0] == ip for line in self.lines(path))

    def temp_ports(self, ip):
        return sorted(l.split('|')[2] for l in self.lines(self.tempallow_file) if l.split('|')[1] == ip)

    def _drop(self, path, keep):
        path.write_text(''.join(l + '\n' for l in self.lines(path) if keep(l)))

    # --- runner ---------------------------------------------------------
    def run(self, argv, *, input=None, timeout=60, mutating=False):
        self.calls.append((list(argv), input, mutating))
        cmd = os.path.basename(argv[0])
        if cmd in self.explode_on:
            self.explode_on.discard(cmd)
            raise RuntimeError(f'{cmd} exploded')
        if cmd == 'ssh':
            return self.remote.handle(argv[-1])
        if cmd == 'csf':
            return self._csf(argv[1:])
        if cmd == 'ipset':
            assert argv[1] == 'test'
            if argv[3] in self.ipset:
                return mod.Result(0, '', f'Warning: {argv[3]} is in set {argv[2]}.')
            return mod.Result(1, '', f'{argv[3]} is NOT in set {argv[2]}.')
        if cmd == 'csf_ban_wp_login_attackers':
            assert argv[1] == '--unblacklist'
            self.ipset.discard(argv[2])
            self._drop(self.tracking_file, lambda l: l.split()[0] != argv[2])
            return mod.Result(0, f'Removed {argv[2]} from live ipset', '')
        if cmd == 'apachectl':
            if argv[1] == '-t':
                return mod.Result(self.configtest_rc, '', '' if self.configtest_rc == 0 else 'Syntax error on line 3')
            return mod.Result(0, '', '')
        if cmd == 'sendmail':
            self.mail.append(email.message_from_string(input, policy=email.policy.default))
            return mod.Result(0, '', '')
        if cmd == 'node':
            self.wakes.append((list(argv), input))
            return mod.Result(0, 'BRB created', '')
        if cmd == 'geoiplookup':
            return mod.Result(0, f'GeoIP Country Edition: {self.country}, Somewhere\n', '')
        if cmd == 'dig':
            return mod.Result(0, self.rdns.get(argv[-1], 'client-1-2-3-4.example.net.') + '\n', '')
        if cmd == 'imunify360-agent':
            return mod.Result(0, '{"items": []}', '')
        if cmd == 'ip':
            return mod.Result(0, ''.join(f'1: eth0    inet {ip}/24 scope global eth0\n' for ip in self.local_ips), '')
        raise AssertionError(f'unexpected command {argv}')

    def _csf(self, args):
        if args[0] == '-dr':
            self._drop(self.deny_file, lambda l: l.split()[0] != args[1])
        elif args[0] == '-trd':
            self._drop(self.tempban_file, lambda l: l.split('|')[1] != args[1])
        elif args[0] == '-ta':
            ip, ttl, _, port, _, direction, comment = args[1:8]
            assert ttl == '30d' and direction == 'in'
            with self.tempallow_file.open('a') as f:
                f.write(f'{int(NOW)}|{ip}|{port}|{direction}|31536000|{comment}\n')
        else:
            raise AssertionError(f'unexpected csf {args}')
        return mod.Result(0, '', '')

    def commands(self, name):
        return [argv for argv, _, _ in self.calls if os.path.basename(argv[0]) == name]

    def firewall_mutations(self):
        return [argv for argv, _, mutating in self.calls
                if mutating and os.path.basename(argv[0]) not in ('sendmail', 'node', 'ssh')]


class Base(unittest.TestCase):
    def setUp(self):
        self.root = scratch('whitelistmyip-')
        self.sys = FakeSystem(self.root)
        self.cfg = self.sys.config()
        self.clock = [NOW]

    def tearDown(self):
        subprocess.run(['rm', '-rf', str(self.root)], check=False)

    def processor(self, cfg=None):
        return mod.Processor(cfg or self.cfg, self.sys, now=lambda: self.clock[0], log=lambda *_: None)

    def submit(self, ip=CLIENT, name='Pat Client', email_addr='client@example.com', website='example.org', cfg=None):
        record = dict(version=1, received_at='2026-11-19T21:30:00+00:00', ip=ip, name=name,
                      email=email_addr, website=website, caller='198.54.116.2')
        rid = f'{int(self.clock[0])}-{os.urandom(8).hex()}'
        path = Path((cfg or self.cfg).spool_dir) / f'{rid}.json'
        path.write_text(json.dumps(record))
        return rid, path

    def run_one(self, cfg=None):
        summary = self.processor(cfg).run()
        return summary['outcomes'][0]


class ValidationTests(unittest.TestCase):
    def test_clean_text_strips_control_format_and_line_separators(self):
        raw = 'Pat\r\nBcc: evil@example.com‮ \x00 Client'
        self.assertEqual(mod.clean_text(raw, 100), 'Pat Bcc: evil@example.com Client')
        self.assertEqual(mod.clean_text(None, 10), '')
        self.assertEqual(mod.clean_text('x' * 300, 100), 'x' * 100)

    def test_comment_safe_allows_only_inert_ascii(self):
        cleaned = mod.comment_safe('Pat; rm -rf / `id` $(id) "q" \'s\' #h\nInclude /etc/shadow')
        for bad in ';`$"\'#\n|&<>\\':
            self.assertNotIn(bad, cleaned)
        self.assertLessEqual(len(mod.comment_safe('a' * 500)), 120)

    def test_public_addresses_are_accepted_and_normalized(self):
        self.assertEqual(str(mod.validate_ip(' 1.2.3.4 ', set())), CLIENT)
        self.assertEqual(str(mod.validate_ip('2001:4860:4860:0:0:0:0:8888', set())), '2001:4860:4860::8888')
        self.assertEqual(str(mod.validate_ip('::ffff:1.2.3.4', set())), CLIENT)

    def test_non_public_and_protected_addresses_are_refused(self):
        for value in ('10.1.2.3', '127.0.0.1', '192.168.1.5', '192.0.2.10', '100.64.1.1', '169.254.1.1',
                      '224.0.0.1', '::1', 'fe80::1', '0.0.0.0'):
            with self.assertRaises(mod.Refused, msg=value):
                mod.validate_ip(value, set())
        with self.assertRaises(mod.Refused):
            mod.validate_ip('181.214.133.151', {'181.214.133.151'})

    def test_malformed_and_scoped_values_are_invalid(self):
        for value in ('', 'not-an-ip', '1.2.3.4; id', '1.2.3.4\n1.2.3.4', None, 42, '1' * 100,
                      '2a00::1%\nRequire all granted', '2a00::1%eth0', '2001:4860:4860::8888%1'):
            with self.assertRaises(mod.Invalid, msg=repr(value)):
                mod.validate_ip(value, set())

    def test_parse_request_rejects_non_json_and_cleans_text(self):
        for raw in (b'not json', b'[1,2]', b'\xff\xfe', b'"text"'):
            with self.assertRaises(mod.Invalid):
                mod.parse_request(raw, 'id', set())
        raw = json.dumps(dict(ip=CLIENT, name='Pat\nClient', email='a@b.co\r\nBcc: x@y.z',
                              website='example.org\x00')).encode()
        req = mod.parse_request(raw, 'rid', set())
        self.assertEqual((req.ip, req.name, req.website), (CLIENT, 'Pat Client', 'example.org'))
        self.assertNotIn('\n', req.email)


class SpoolTests(Base):
    def test_requests_are_read_once_and_removed(self):
        rid, path = self.submit()
        accepted, rejected = mod.read_spool(self.cfg, NOW)
        self.assertEqual(([a[0] for a in accepted], rejected), ([rid], []))
        self.assertFalse(path.exists())

    def test_symlinked_request_is_never_followed(self):
        secret = self.root / 'secret.txt'
        secret.write_text('root-only data')
        link = Path(self.cfg.spool_dir) / f'{int(NOW)}-{"a" * 16}.json'
        link.symlink_to(secret)
        accepted, rejected = mod.read_spool(self.cfg, NOW)
        self.assertEqual((accepted, len(rejected)), ([], 1))
        self.assertEqual(secret.read_text(), 'root-only data')
        self.assertEqual(list(Path(self.cfg.spool_dir).glob('*.json')), [])

    def test_oversized_misnamed_directories_and_fifos_leave_no_json_behind(self):
        spool = Path(self.cfg.spool_dir)
        (spool / f'{int(NOW)}-{"b" * 16}.json').write_text('x' * (self.cfg.max_file_bytes + 1))
        (spool / 'evil.json').write_text('{}')
        (spool / f'{int(NOW)}-{"c" * 16}.json').mkdir()
        os.mkfifo(spool / f'{int(NOW)}-{"e" * 16}.json')
        (spool / 'notes.txt').write_text('ignored')
        accepted, rejected = mod.read_spool(self.cfg, NOW)
        self.assertEqual((accepted, len(rejected)), ([], 4))
        self.assertEqual(list(spool.glob('*.json')), [])
        self.assertTrue((spool / 'notes.txt').exists())

    def test_swapping_the_spool_for_a_symlink_is_refused(self):
        target = self.root / 'root-files'
        target.mkdir()
        (target / f'{int(NOW)}-{"f" * 16}.json').write_text('{"keep": true}')
        spool = Path(self.cfg.spool_dir)
        spool.rmdir()
        spool.symlink_to(target)
        summary = self.processor().run()
        self.assertIn('cannot open', summary['error'])
        self.assertEqual(sorted(p.name for p in target.iterdir()), [f'{int(NOW)}-{"f" * 16}.json'])

    def test_spool_with_wrong_owner_or_writable_mode_is_refused(self):
        self.submit()
        self.assertIn('must be owned', self.processor(self.sys.config(spool_owner='nobody')).run()['error'])
        os.chmod(self.cfg.spool_dir, 0o777)
        self.assertIn('must be owned', self.processor().run()['error'])
        self.assertEqual(self.sys.firewall_mutations(), [])

    def test_fresh_temp_files_wait_and_stale_ones_are_removed(self):
        spool = Path(self.cfg.spool_dir)
        fresh, stale = spool / '.tmp-fresh', spool / '.tmp-stale'
        fresh.write_text('{}')
        stale.write_text('{}')
        os.utime(stale, (NOW - 7200, NOW - 7200))
        os.utime(fresh, (NOW - 5, NOW - 5))
        mod.read_spool(self.cfg, NOW)
        self.assertTrue(fresh.exists())
        self.assertFalse(stale.exists())


class ReviewGateTests(unittest.TestCase):
    def test_attacks_deliberate_bans_and_gaps_need_a_human(self):
        cases = [
            {'tracking': True, 'tracking_reason': 'inserted IP to ipset [Violations: 6, alfacgiapi] (Denmark)'},
            {'tracking': True, 'tracking_reason': '[Violations: 33, /config.json, .git] (United States)'},
            {'tracking': True, 'tracking_reason': '[Violations: 150, tried to access wp-login] (United States)'},
            {'tracking': True, 'tracking_reason': '[2026-10-16] Manual Blacklist: Coordinated proxy flood (United States)'},
            {'deny': True, 'deny_reason': 'Reviewed repeated hostile scanning from 1.2.3.4 - Thu Oct 22 2026'},
            {'deny': True, 'deny_reason': 'lfd: (sshd) Failed SSH login from 1.2.3.4: 5 in the last 3600 secs'},
            {'deny': True, 'deny_reason': 'lfd: (eximsyntax) Exim syntax errors from 1.2.3.4'},
            {'deny': True, 'deny_reason': 'lfd: (PERMBLOCK) 1.2.3.4 has had more than 4 temp blocks'},
            {'deny': True, 'deny_reason': 'lfd: 1.2.3.4 (CN/China/-): 150 distributed connections'},
            {'deny': True, 'deny_reason': ''},
            {'deny_range': '1.2.3.0/24 # Sweep 2026-10-22 reviewed hostile /24'},
            {'temp': True, 'temp_detail': 'Manually blocked by admin'},
            {'blocklists': ['csf.block.SPAMDROP']},
            {'errors': ['csf.tempban: Permission denied']},
        ]
        for evidence in cases:
            self.assertTrue(mod.review_reasons({'dc3-1': evidence}, 20), evidence)

    def test_ordinary_client_lockouts_can_be_lifted_by_the_client(self):
        cases = [
            {'tracking': True, 'tracking_reason': LIFTABLE_TRACK},
            {'deny': True, 'deny_reason': 'lfd: (cpanel) Failed cPanel login from 9.8.7.6: 5 in the last 3600 secs'},
            {'deny': True, 'deny_reason': LIFTABLE_DENY},
            {'deny': True, 'deny_reason': 'lfd: (imapd) Failed IMAP login from 1.2.3.4: 10 in the last 3600 secs'},
            {'deny': True, 'deny_reason': 'lfd: (smtpauth) Failed SMTP AUTH login from 1.2.3.4'},
            {'temp': True, 'temp_detail': '(cpanel) Failed cPanel login from 1.2.3.4'},
            {},
        ]
        for evidence in cases:
            self.assertEqual(mod.review_reasons({'dc3-1': evidence, 'dc2-5': None}, 20), [], evidence)


class ProcessingTests(Base):
    def test_blocked_client_gets_bans_cleared_and_web_only_allows_on_both_servers(self):
        self.sys.add_deny(CLIENT)
        self.sys.add_tracking(CLIENT)
        self.sys.add_temp(self.sys.tempban_file, CLIENT)
        self.sys.remote.ipset.add(CLIENT)
        self.sys.remote.tracking[CLIENT] = LIFTABLE_TRACK
        rid, path = self.submit()

        o = self.run_one()

        self.assertEqual((o['outcome'], o['errors']), ('unblocked', []))
        self.assertFalse(self.sys.has_exact(self.sys.deny_file, CLIENT))
        self.assertEqual(self.sys.lines(self.sys.tempban_file), [])
        self.assertNotIn(CLIENT, self.sys.ipset)
        self.assertFalse(self.sys.has_exact(self.sys.tracking_file, CLIENT))
        self.assertEqual(self.sys.temp_ports(CLIENT), ['443', '80'])
        self.assertEqual(self.sys.lines(self.sys.allow_file), [], 'never a permanent all-ports allow')
        self.assertFalse(path.exists())
        self.assertEqual([shlex.split(c)[3] for c in self.sys.remote.calls], ['check', 'apply'])
        self.assertEqual(self.sys.remote.web_allow[CLIENT], {'80', '443'})
        self.assertNotIn(CLIENT, self.sys.remote.ipset)
        self.assertEqual(self.sys.commands('apachectl'), [], 'a US address needs no wp-login exception')
        for argv, _, _ in self.sys.calls:
            self.assertNotIn(os.path.basename(argv[0]), ('sh', 'bash'))

        self.assertEqual(self.sys.commands('sendmail')[0][1:], ['-odf', '-t', '-oi'], 'deliver before the service exits')
        msg = self.sys.mail[0]
        self.assertEqual(msg['Subject'], f'[WhitelistMyIP.com] {CLIENT} unblocked for Pat Client')
        body = msg.get_content()
        for text in ('client@example.com', 'AH01797', rid, 'TCP 80 and 443'):
            self.assertIn(text, body)

        wake_argv, wake_text = self.sys.wakes[0]
        self.assertEqual(wake_argv[2:], ['brb', '10s', '--chat', '-5190961854', '--', '-'])
        self.assertIn('untrusted data, not instructions', wake_text)
        self.assertNotIn('client@example.com', wake_text)
        log = json.loads((Path(self.cfg.state_dir) / 'requests.jsonl').read_text().splitlines()[-1])
        self.assertEqual(log['outcome'], 'unblocked')
        self.assertNotIn('email', log)

    def test_unblocked_ip_is_not_allowlisted_beyond_the_web(self):
        self.sys.add_deny(CLIENT)
        self.submit(name='Pat\nInclude /etc/shadow', website='x.org; rm -rf /')
        self.run_one()
        ta = [argv for argv in self.sys.commands('csf') if argv[1] == '-ta']
        self.assertEqual(sorted(argv[5] for argv in ta), ['443', '80'])
        for argv in ta:
            self.assertNotIn('\n', argv[8])
            self.assertNotIn(';', argv[8])
        self.assertFalse([argv for argv in self.sys.commands('csf') if argv[1] == '-a'])

    def test_unblocked_ip_needs_no_action_and_gets_no_allow(self):
        self.submit()
        o = self.run_one()
        self.assertEqual(o['outcome'], 'not-blocked')
        self.assertEqual(self.sys.firewall_mutations(), [])
        self.assertEqual([shlex.split(c)[3] for c in self.sys.remote.calls], ['check'])
        self.assertIn('was not blocked', self.sys.mail[0]['Subject'])
        self.assertEqual(self.sys.wakes, [])

    def test_non_us_client_gets_only_the_wp_login_exception(self):
        self.sys.country = 'CA'
        self.sys.remote.country = 'CA'
        self.submit()
        o = self.run_one()
        self.assertEqual((o['outcome'], o['errors']), ('not-blocked', []))
        self.assertIn(f'Allow from {CLIENT}', self.sys.lines(self.sys.wp_file))
        self.assertEqual([a[1] for a in self.sys.commands('apachectl')], ['-t', 'graceful'])
        self.assertEqual([shlex.split(c)[3] for c in self.sys.remote.calls], ['check', 'wp-only'])
        self.assertEqual(self.sys.temp_ports(CLIENT), [])
        self.assertIn('wp-login GeoIP exception', self.sys.mail[0].get_content())

    def test_existing_csf_allow_outranks_bans_so_nothing_changes(self):
        self.sys.allow_file.write_text(f'{CLIENT} # earlier manual allow\n')
        self.sys.add_tracking(CLIENT)
        self.submit()
        o = self.run_one()
        self.assertEqual(o['outcome'], 'not-blocked')
        self.assertEqual(self.sys.firewall_mutations(), [])

    def test_attack_history_is_held_untouched_until_approved(self):
        self.sys.add_tracking(CLIENT, 'Violations: 6, alfacgiapi')
        rid, _ = self.submit()
        o = self.run_one()
        self.assertEqual(o['outcome'], 'held')
        self.assertEqual(self.sys.firewall_mutations(), [])
        self.assertEqual([shlex.split(c)[3] for c in self.sys.remote.calls], ['check'])
        self.assertIn('HELD', self.sys.mail[0]['Subject'])
        self.assertIn(f'--approve {rid}', self.sys.mail[0].get_content())
        wake_text = self.sys.wakes[0][1]
        self.assertIn('Do not approve', wake_text)
        self.assertNotIn('--approve', wake_text)
        self.assertTrue((Path(self.cfg.state_dir) / 'held' / f'{rid}.json').exists())

        approved = self.processor().approve(rid)
        self.assertEqual(approved['outcome'], 'unblocked')
        self.assertNotIn(CLIENT, self.sys.ipset)
        self.assertEqual(self.sys.temp_ports(CLIENT), ['443', '80'])
        self.assertFalse((Path(self.cfg.state_dir) / 'held' / f'{rid}.json').exists())
        self.assertEqual(len(self.sys.wakes), 1, 'approval does not wake the ops agent again')

    def test_denied_range_and_deliberate_denies_are_held(self):
        self.sys.deny_file.write_text('1.2.3.0/24 # Sweep 2026-10-22 reviewed hostile /24\n')
        self.submit()
        o = self.run_one()
        self.assertEqual(o['outcome'], 'held')
        self.assertTrue(any('denied range' in r for r in o['review']))
        self.assertEqual(self.sys.firewall_mutations(), [])

    def test_approve_rejects_unknown_or_path_like_ids(self):
        for bad in ('../../etc/passwd', 'nope', '', '1795000000-0123456789abcdef'):
            with self.assertRaises(mod.Invalid):
                self.processor().approve(bad)

    def test_refused_address_is_reported_but_never_acted_on(self):
        self.submit(ip='181.214.133.151')
        o = self.run_one()
        self.assertEqual(o['outcome'], 'refused')
        self.assertEqual(self.sys.firewall_mutations(), [])
        self.assertEqual(self.sys.remote.calls, [])
        self.assertIn('refused', self.sys.mail[0]['Subject'])

    def test_invalid_and_scoped_requests_change_nothing(self):
        for ip in ('nonsense', '2a00::1%\nRequire all granted'):
            self.submit(ip=ip)
            self.clock[0] += 1
        summary = self.processor().run()
        self.assertEqual([o['outcome'] for o in summary['outcomes']], ['invalid', 'invalid'])
        self.assertEqual(self.sys.lines(self.sys.wp_file), ['Allow from 203.0.113.9'])
        self.assertEqual((self.sys.mail, self.sys.firewall_mutations(), self.sys.remote.calls), ([], [], []))
        self.assertEqual([argv[0] for argv, _, _ in self.sys.calls], ['/usr/sbin/ip'])

    def test_repeat_submissions_within_ten_minutes_are_quiet(self):
        self.sys.add_tracking(CLIENT)
        self.submit()
        self.processor().run()
        self.clock[0] += 120
        self.submit()
        self.assertEqual(self.run_one()['outcome'], 'duplicate')
        self.assertEqual((len(self.sys.mail), len(self.sys.wakes)), (1, 1))

    def test_one_noisy_ip_cannot_lock_out_other_clients(self):
        cfg = self.sys.config(max_global_per_hour=3)
        for _ in range(30):
            self.submit(cfg=cfg)
            self.clock[0] += 1
        self.processor(cfg).run()
        self.processor(cfg).run()
        self.submit(ip=OTHER, cfg=cfg)
        self.assertEqual(self.run_one(cfg)['outcome'], 'not-blocked')

    def test_rate_limits_apply_within_a_single_batch_and_per_ip(self):
        cfg = self.sys.config(dedupe_seconds=0, max_per_ip_per_day=2, max_global_per_hour=3)
        for ip in (CLIENT, '8.8.8.8', '1.1.1.1', '9.9.9.9', '4.4.4.4'):
            self.sys.add_tracking(ip)
        for ip in (CLIENT, CLIENT, CLIENT, '8.8.8.8', '1.1.1.1', '9.9.9.9', '4.4.4.4'):
            self.submit(ip=ip, cfg=cfg)
            self.clock[0] += 1
        outcomes = [o['outcome'] for o in self.processor(cfg).run()['outcomes']]
        self.assertEqual(outcomes, ['unblocked', 'not-blocked', 'rate-limited', 'unblocked', 'unblocked',
                                    'rate-limited-global', 'rate-limited-global'])
        self.assertIn('9.9.9.9', self.sys.ipset, 'requests over the limit change nothing')
        self.assertEqual(sum('rate limit' in m['Subject'] for m in self.sys.mail), 1)

    def test_each_run_is_capped_and_leaves_the_rest_queued(self):
        cfg = self.sys.config(max_per_run=3)
        for i in range(5):
            self.submit(ip=f'8.8.4.{i + 1}', cfg=cfg)
            self.clock[0] += 1
        self.assertEqual(len(self.processor(cfg).run()['outcomes']), 3)
        self.assertEqual(len(list(Path(cfg.spool_dir).glob('*.json'))), 2)
        self.assertEqual(len((Path(cfg.state_dir) / 'requests.jsonl').read_text().splitlines()), 3)

    def test_failed_apache_configtest_rolls_back_each_new_line(self):
        self.sys.country = 'CA'
        self.sys.configtest_rc = 1
        self.submit()
        self.clock[0] += 1
        self.submit(ip=OTHER)
        summary = self.processor().run()
        self.assertEqual(self.sys.lines(self.sys.wp_file), ['Allow from 203.0.113.9'])
        self.assertEqual([a[1] for a in self.sys.commands('apachectl')], ['-t', '-t'])
        self.assertTrue(all('needs attention' in m['Subject'] for m in self.sys.mail))
        self.assertTrue(all(o['errors'] for o in summary['outcomes']))

    def test_unreachable_dc2_5_still_unblocks_dc3_1_and_says_so(self):
        self.sys.remote.fail = True
        self.sys.add_tracking(CLIENT)
        self.submit()
        o = self.run_one()
        self.assertEqual(o['outcome'], 'unblocked')
        self.assertTrue(any(e.startswith('dc2-5:') for e in o['errors']))
        self.assertEqual(self.sys.temp_ports(CLIENT), ['443', '80'])
        self.assertIn('needs attention', self.sys.mail[0]['Subject'])

    def test_missing_remote_verification_is_an_error(self):
        self.sys.remote.omit_verify = True
        self.sys.add_tracking(CLIENT)
        self.submit()
        o = self.run_one()
        self.assertTrue(any('no verification' in e for e in o['errors']))

    def test_ipv6_skips_the_ipv4_ban_set(self):
        ip6 = '2001:4860:4860::8888'
        self.sys.add_deny(ip6, 'lfd: (cpanel) Failed cPanel login')
        self.submit(ip=ip6)
        o = self.run_one()
        self.assertEqual(o['outcome'], 'unblocked')
        self.assertEqual((self.sys.commands('ipset'), self.sys.commands('csf_ban_wp_login_attackers')), ([], []))
        self.assertEqual(self.sys.temp_ports(ip6), ['443', '80'])

    def test_an_unexpected_error_quarantines_that_request_and_processing_continues(self):
        self.sys.explode_on.add('sendmail')
        self.submit()
        self.clock[0] += 1
        self.submit(ip=OTHER)
        summary = self.processor().run()
        self.assertEqual([o['outcome'] for o in summary['outcomes']], ['invalid', 'not-blocked'])
        self.assertIn('exploded', summary['outcomes'][0]['detail'])
        self.assertEqual(list(Path(self.cfg.spool_dir).glob('*.json')), [])
        subjects = sorted(m['Subject'] for m in self.sys.mail)
        self.assertEqual(len(subjects), 2)
        self.assertIn('processor error', subjects[0] + subjects[1])

    def test_requests_that_change_nothing_cannot_close_the_form(self):
        cfg = self.sys.config(max_global_per_hour=3)
        for i in range(30):
            self.submit(ip=f'100.64.0.{i + 1}', cfg=cfg)
            self.clock[0] += 1
        self.processor(cfg).run()
        self.processor(cfg).run()
        self.sys.add_tracking(OTHER)
        self.submit(ip=OTHER, cfg=cfg)
        self.assertEqual(self.run_one(cfg)['outcome'], 'unblocked')

    def test_informational_email_is_throttled_with_one_notice(self):
        cfg = self.sys.config(max_info_emails_per_hour=3)
        for i in range(6):
            self.submit(ip=f'8.8.4.{i + 1}', cfg=cfg)
            self.clock[0] += 1
        self.processor(cfg).run()
        subjects = [m['Subject'] for m in self.sys.mail]
        self.assertEqual(sum('was not blocked' in s for s in subjects), 3)
        self.assertEqual(sum('paused for the hour' in s for s in subjects), 1)

    def test_unblocking_keeps_other_temp_allows(self):
        self.sys.add_temp(self.sys.tempban_file, CLIENT)
        self.sys.add_temp(self.sys.tempallow_file, CLIENT, port='22', comment='manual SFTP allow')
        self.submit()
        self.assertEqual(self.run_one()['outcome'], 'unblocked')
        self.assertEqual(self.sys.temp_ports(CLIENT), ['22', '443', '80'])
        self.assertEqual(self.sys.lines(self.sys.tempban_file), [])

    def test_pathological_json_is_invalid_not_a_crash(self):
        path = Path(self.cfg.spool_dir) / f'{int(NOW) - 5}-{"0" * 16}.json'
        path.write_text('{"ip": 1' + '0' * 5000 + '}')
        self.submit()
        outcomes = [o['outcome'] for o in self.processor().run()['outcomes']]
        self.assertEqual(outcomes, ['invalid', 'not-blocked'])
        self.assertEqual(list(Path(self.cfg.spool_dir).glob('*.json')), [])

    def test_unusable_spool_alerts_gabriel_once(self):
        Path(self.cfg.spool_dir).rmdir()
        self.processor().run()
        self.clock[0] += 600
        self.processor().run()
        self.assertEqual([m['Subject'] for m in self.sys.mail],
                         ['[WhitelistMyIP.com] request spool unavailable; requests are not processed'])

    def test_refused_form_host_triggers_one_alert(self):
        line = '{ip} - - [19/Nov/2026:14:20:00 -0800] "POST /version-checker/whitelist_ip.php HTTP/1.1" {status} 9 "-" "curl"\n'
        (self.sys.etc / 'domlog').write_text(line.format(ip='198.54.116.2', status=200)
                                             + line.format(ip='45.11.22.33', status=403) * 3
                                             + line.format(ip='198.54.117.9', status=403))
        self.sys.rdns['198.54.117.9'] = 'server99-7.web-hosting.com.'
        self.processor().run()
        self.processor().run()
        alerts = [m for m in self.sys.mail if 'form host is being refused' in m['Subject']]
        self.assertEqual(len(alerts), 1)
        body = alerts[0].get_content()
        self.assertIn('198.54.117.9', body)
        self.assertNotIn('45.11.22.33', body, 'random scanners are not the form host')

    def test_dry_run_changes_nothing(self):
        self.sys.add_tracking(CLIENT)
        _, path = self.submit()
        files = (self.sys.allow_file, self.sys.deny_file, self.sys.tracking_file, self.sys.wp_file, self.sys.tempallow_file)
        before = {p: p.read_text() for p in files}
        self.processor().run(dry_run=True)
        self.assertTrue(path.exists())
        self.assertEqual({p: p.read_text() for p in files}, before)
        self.assertEqual((self.sys.mail, self.sys.wakes), ([], []))
        self.assertFalse((Path(self.cfg.state_dir) / 'requests.jsonl').exists())

    def test_a_second_run_waits_for_the_lock(self):
        self.submit()
        state = Path(self.cfg.state_dir)
        state.mkdir(mode=0o700, exist_ok=True)
        with open(state / '.lock', 'w') as held:
            fcntl.flock(held, fcntl.LOCK_EX)
            summary = self.processor().run()
        self.assertTrue(summary['busy'])
        self.assertEqual(self.sys.calls, [])
        self.assertEqual(len(list(Path(self.cfg.spool_dir).glob('*.json'))), 1)


class RemoteScriptTests(unittest.TestCase):
    """Run the real dc2-5 bash script against stub binaries and sandbox files."""

    def setUp(self):
        self.root = scratch('whitelistmyip-remote-')
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.log = self.root / 'commands.log'
        stub = ('#!/bin/bash\nname=$(basename "$0")\nprintf "%s\\n" "$name $*" >> "$STUB_LOG"\n'
                'case "$name $1" in\n'
                '  "ipset test") grep -qxF "$3" "$IPSET_FILE"; exit ;;\n'
                '  "apachectl -t") exit "${CONFIGTEST_RC:-0}" ;;\n'
                '  "geoiplookup "*) echo "GeoIP Country Edition: ${GEO_COUNTRY:-US}, Somewhere"; exit 0 ;;\n'
                'esac\n'
                '[ "$name" = csf_ban_wp_login_attackers ] && [ -n "${SWALLOW:-}" ] && cat > /dev/null\n'
                'exit 0\n')
        for name in ('csf', 'ipset', 'apachectl', 'geoiplookup', 'csf_ban_wp_login_attackers'):
            (self.bin / name).write_text(stub)
            (self.bin / name).chmod(0o755)
        self.files = {}
        for key in ('CSF_DENY', 'CSF_ALLOW', 'TEMPBAN', 'TEMPALLOW', 'TRACKING', 'WP_LOGIN', 'IPSET_FILE'):
            self.files[key] = self.root / key.lower()
            self.files[key].write_text('')

    def tearDown(self):
        subprocess.run(['rm', '-rf', str(self.root)], check=False)

    def run_script(self, *args, rc=0, **env):
        environ = dict(PATH=f'{self.bin}:/usr/bin:/bin', STUB_LOG=str(self.log),
                       BAN_TOOL=str(self.bin / 'csf_ban_wp_login_attackers'), BLOCKLIST_GLOB=str(self.root / 'csf.block.*'),
                       **{k: str(v) for k, v in self.files.items()}, **env)
        proc = subprocess.run(['bash', '-s', '--', *args], input=mod.REMOTE_SCRIPT, capture_output=True,
                              text=True, env=environ, timeout=30)
        self.assertEqual(proc.returncode, rc, proc.stderr)
        return mod.parse_remote(proc.stdout)

    def logged(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def mutations(self):
        return [l for l in self.logged() if l.startswith(('csf -', 'csf_ban', 'apachectl graceful'))]

    def test_check_reports_evidence_without_mutating(self):
        self.files['CSF_DENY'].write_text(f'{CLIENT} # lfd: (cpanel) Failed cPanel login\n1.2.0.0/16 # Sweep\n')
        self.files['IPSET_FILE'].write_text(f'{CLIENT}\n')
        self.files['TRACKING'].write_text(f'{CLIENT} # [2026-10-24] [Violations: 5, AH01797]\n')
        self.files['TEMPBAN'].write_text(f'1795000000|{CLIENT}||in|3600|(cpanel) temp\n')
        self.files['TEMPALLOW'].write_text(f'1795000000|{CLIENT}|443|in|3600|x\n')
        (self.root / 'csf.block.SPAMDROP').write_text(f'{CLIENT}\n')
        ev = mod.normalize_remote(self.run_script('check', CLIENT)['evidence'])
        self.assertTrue(ev['deny'] and ev['ipset_live'] and ev['tracking'] and ev['temp'])
        self.assertIn('Failed cPanel login', ev['deny_reason'])
        self.assertTrue(ev['deny_range'].startswith('1.2.0.0/16'))
        self.assertEqual((ev['temp_detail'], ev['web_allow'], ev['blocklists']), ('(cpanel) temp', ['443'], ['csf.block.SPAMDROP']))
        self.assertFalse(ev['allow'] or ev['wp_needed'])
        self.assertEqual(self.mutations(), [])

    def test_apply_clears_bans_adds_web_allows_and_skips_wp_login_for_us(self):
        self.files['CSF_DENY'].write_text(f'{CLIENT} # lfd block\n')
        self.files['IPSET_FILE'].write_text(f'{CLIENT}\n')
        self.files['TEMPBAN'].write_text(f'1795000000|{CLIENT}||in|3600|(cpanel) temp\n')
        result = self.run_script('apply', CLIENT, 'WhitelistMyIP.com request for Pat')
        logged = self.logged()
        for line in (f'csf -dr {CLIENT}', f'csf -trd {CLIENT}',
                     f'csf_ban_wp_login_attackers --unblacklist {CLIENT} WhitelistMyIP.com request for Pat',
                     f'csf -ta {CLIENT} 30d -p 80 -d in WhitelistMyIP.com request for Pat',
                     f'csf -ta {CLIENT} 30d -p 443 -d in WhitelistMyIP.com request for Pat'):
            self.assertIn(line, logged)
        self.assertFalse([l for l in logged if l.startswith('csf -a ')])
        self.assertNotIn('apachectl graceful', logged)
        self.assertIn('deny', result['verify'])

    def test_apply_adds_the_wp_login_exception_outside_the_us_and_rolls_back_on_bad_config(self):
        self.files['WP_LOGIN'].write_text('Allow from 203.0.113.9')  # no trailing newline
        result = self.run_script('wp-only', CLIENT, 'x', GEO_COUNTRY='CA')
        self.assertEqual(self.files['WP_LOGIN'].read_text(), f'Allow from 203.0.113.9\nAllow from {CLIENT}\n')
        self.assertEqual(result['actions']['wp-login-allow'], 'ok')
        self.assertEqual([l for l in self.mutations() if l.startswith('csf')], [])
        self.files['WP_LOGIN'].write_text('Allow from 203.0.113.9\n')
        result = self.run_script('wp-only', OTHER, 'x', GEO_COUNTRY='CA', CONFIGTEST_RC='1')
        self.assertEqual(self.files['WP_LOGIN'].read_text(), 'Allow from 203.0.113.9\n')
        self.assertTrue(result['actions']['wp-login-allow'].startswith('rolled-back'))

    def test_existing_allow_means_no_ban_changes(self):
        self.files['CSF_ALLOW'].write_text(f'{CLIENT} # manual\n')
        self.files['IPSET_FILE'].write_text(f'{CLIENT}\n')
        self.run_script('apply', CLIENT, 'x')
        self.assertEqual(self.mutations(), [])

    def test_a_command_that_reads_stdin_cannot_swallow_the_script(self):
        self.files['IPSET_FILE'].write_text(f'{CLIENT}\n')
        result = self.run_script('apply', CLIENT, 'x', SWALLOW='1')
        self.assertIn(f'csf -ta {CLIENT} 30d -p 443 -d in x', self.logged())
        self.assertIsNotNone(mod.normalize_remote(result['verify']))

    def test_remote_side_rejects_injection_even_if_the_caller_did_not(self):
        for ip in ('1.2.3.4;id', '2a00::1%eth0', ''):
            self.assertEqual(self.run_script('apply', ip, 'x', rc=2)['error'], 'invalid ip')
        self.assertEqual(self.run_script('rm', CLIENT, 'x', rc=2)['error'], 'invalid mode')
        self.assertEqual(self.mutations(), [])
        self.files['TEMPBAN'].write_text(f'1795000000|{CLIENT}||in|3600|(cpanel) temp\n')
        self.run_script('apply', CLIENT, 'bad; comment $(id)')
        self.assertIn(f'csf -ta {CLIENT} 30d -p 80 -d in WhitelistMyIP.com request', self.logged())


if __name__ == '__main__':
    unittest.main()
