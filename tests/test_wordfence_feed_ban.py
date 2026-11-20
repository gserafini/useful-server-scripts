"""Unit tests for wordfence_feed_ban.py. Uses only documentation addresses and example domains."""
import importlib.util
import ipaddress
import json
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'wordfence_feed_ban.py'
spec = importlib.util.spec_from_file_location('wordfence_feed_ban', SCRIPT)
wfb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wfb)


def feed(*rows):
    return json.dumps(list(rows)).encode()


def row(ip, block_type='brute', count=3):
    return {'IP': ip, 'blockCount': count, 'blockType': block_type,
            'countryCode': 'ZZ', 'countryName': 'Nowhere', 'unixday': 20000}


class ReadSites(unittest.TestCase):
    def test_comments_blank_lines_duplicates_and_trailing_slash(self):
        text = '# fleet sites\n\nhttps://example.com/\nhttps://example.com\nhttps://www.example.org  # owner site\n'
        self.assertEqual(wfb.read_sites(text), ['https://example.com', 'https://www.example.org'])

    def test_rejects_plain_http_and_paths(self):
        for bad in ['http://example.com', 'https://example.com/blog', 'example.com', 'https://exa mple.com']:
            with self.subTest(bad=bad):
                with self.assertRaises(wfb.ConfigError):
                    wfb.read_sites(bad + '\n')

    def test_empty_config_is_an_error(self):
        with self.assertRaises(wfb.ConfigError):
            wfb.read_sites('# nothing\n')


class ParseFeed(unittest.TestCase):
    def test_valid_rows_and_counted_skips(self):
        rows, stats = wfb.parse_feed(feed(row('203.0.113.7'), row('2001:db8::1'), row('10.1.2.3'),
                                          row('not-an-ip'), {'blockType': 'brute'}),
                                     allow_documentation=True)
        self.assertEqual([r['ip'] for r in rows], ['203.0.113.7'])
        self.assertEqual(stats, {'rows': 5, 'ipv4': 1, 'ipv6': 1, 'nonGlobal': 1, 'invalid': 2})

    def test_documentation_ranges_are_rejected_outside_tests(self):
        rows, stats = wfb.parse_feed(feed(row('198.51.100.9')))
        self.assertEqual(rows, [])
        self.assertEqual(stats['nonGlobal'], 1)

    def test_block_type_is_sanitized(self):
        rows, _ = wfb.parse_feed(feed(row('203.0.113.8', block_type='brute; rm -rf /')), allow_documentation=True)
        self.assertEqual(rows[0]['type'], 'other')

    def test_empty_body_means_no_recent_blocks(self):
        # The helper plugin answers HTTP 200 with an empty body when nothing was blocked.
        for raw in [b'', b'  \n']:
            with self.subTest(raw=raw):
                self.assertEqual(wfb.parse_feed(raw), ([], {'rows': 0, 'ipv4': 0, 'ipv6': 0, 'nonGlobal': 0, 'invalid': 0}))

    def test_non_list_json_and_oversize_are_feed_errors(self):
        for raw in [b'{"error":"nope"}', b'<html>login</html>']:
            with self.subTest(raw=raw):
                with self.assertRaises(wfb.FeedError):
                    wfb.parse_feed(raw)
        with self.assertRaises(wfb.FeedError):
            wfb.parse_feed(b'[' + b' ' * (wfb.MAX_FEED_BYTES + 1) + b']')


class Plan(unittest.TestCase):
    def setUp(self):
        self.feeds = {
            'https://example.com': [{'ip': '203.0.113.1', 'type': 'brute', 'count': 5},
                                    {'ip': '203.0.113.2', 'type': 'waf', 'count': 1},
                                    {'ip': '203.0.113.3', 'type': 'brute', 'count': 2}],
            'https://example.org': [{'ip': '203.0.113.1', 'type': 'brute', 'count': 2},
                                    {'ip': '203.0.113.4', 'type': 'brute', 'count': 1},
                                    {'ip': '203.0.113.5', 'type': 'brute', 'count': 9}],
        }

    def test_exact_membership_protection_and_grouping(self):
        protected = [ipaddress.ip_network('203.0.113.4/32')]
        result = wfb.plan(self.feeds, live={'203.0.113.3'}, protected=protected,
                          own={'203.0.113.5'}, cap=100)
        self.assertEqual(result['groups'], {'brute': ['203.0.113.1'], 'waf': ['203.0.113.2']})
        self.assertEqual(result['skipped'], {'live': 1, 'protected': 1, 'own': 1})
        self.assertEqual(result['deferred'], 0)
        self.assertEqual(result['unique'], 5)

    def test_substring_is_not_membership(self):
        result = wfb.plan({'https://example.com': [{'ip': '203.0.113.1', 'type': 'brute', 'count': 1}]},
                          live={'203.0.113.10', '203.0.113.100'}, protected=[], own=set(), cap=10)
        self.assertEqual(result['groups'], {'brute': ['203.0.113.1']})

    def test_cloudflare_ranges_are_always_protected(self):
        cf = str(next(ipaddress.ip_network(wfb.CLOUDFLARE_IPV4[0]).hosts()))
        result = wfb.plan({'https://example.com': [{'ip': cf, 'type': 'brute', 'count': 50}]},
                          live=set(), protected=[], own=set(), cap=10)
        self.assertEqual(result['groups'], {})
        self.assertEqual(result['skipped']['protected'], 1)

    def test_cap_keeps_strongest_evidence_and_defers_rest(self):
        result = wfb.plan(self.feeds, live=set(), protected=[], own=set(), cap=2)
        selected = sorted(ip for ips in result['groups'].values() for ip in ips)
        self.assertEqual(selected, ['203.0.113.1', '203.0.113.5'])
        self.assertEqual(result['deferred'], 3)


class Parsers(unittest.TestCase):
    def test_ipset_save_members_exact(self):
        text = ('create high_volume_bans hash:ip family inet hashsize 1024 maxelem 250000\n'
                'add high_volume_bans 203.0.113.10\nadd other_set 203.0.113.11\nadd high_volume_bans 203.0.113.12\n')
        self.assertEqual(wfb.parse_ipset_save(text), {'203.0.113.10', '203.0.113.12'})

    def test_protected_export_accepts_hosts_and_cidrs(self):
        nets = wfb.parse_networks('203.0.113.1\n198.51.100.0/24\n# comment\n\n192.0.2.7/31\n')
        self.assertEqual([str(n) for n in nets], ['203.0.113.1/32', '198.51.100.0/24', '192.0.2.6/31'])

    def test_protected_export_rejects_garbage(self):
        with self.assertRaises(ValueError):
            wfb.parse_networks('203.0.113.1\nnot a network\n')

    def test_own_addresses_from_ip_addr(self):
        text = ('1: lo    inet 127.0.0.1/8 scope host lo\n'
                '2: eth0    inet 203.0.113.20/24 brd 203.0.113.255 scope global eth0\n')
        self.assertEqual(wfb.parse_own_addresses(text), {'127.0.0.1', '203.0.113.20'})


class Apply(unittest.TestCase):
    def test_one_batch_per_type_with_stdin_and_reason(self):
        calls = []

        class Done:
            returncode = 0
            stdout = 'Blacklist batch complete: 2 unique IPs; 2 succeeded, 0 failed.\n'
            stderr = ''

        def runner(argv, **kwargs):
            calls.append((argv, kwargs.get('input')))
            return Done()

        results = wfb.apply({'brute': ['203.0.113.1', '203.0.113.2']}, helper='/bin/helper',
                            runner=runner, today='2026-11-19')
        self.assertEqual(calls[0][0][:3], ['/bin/helper', '--blacklist-file', '-'])
        self.assertIn('Wordfence', calls[0][0][3])
        self.assertIn('brute', calls[0][0][3])
        self.assertEqual(calls[0][1], '203.0.113.1\n203.0.113.2\n')
        self.assertEqual(results, [{'type': 'brute', 'inputs': 2, 'exit': 0, 'succeeded': 2, 'failed': 0}])

    def test_missing_summary_line_counts_as_failure(self):
        class Odd:
            returncode = 0
            stdout = 'something else\n'
            stderr = ''

        results = wfb.apply({'waf': ['203.0.113.9']}, helper='/bin/helper',
                            runner=lambda argv, **kw: Odd(), today='2026-11-19')
        self.assertEqual(results[0]['failed'], 1)
        self.assertIsNone(results[0]['succeeded'])

    def test_dry_run_never_calls_helper(self):
        results = wfb.apply({'brute': ['203.0.113.1']}, helper='/bin/helper',
                            runner=lambda *a, **k: self.fail('helper called'), dry_run=True, today='2026-11-19')
        self.assertEqual(results, [{'type': 'brute', 'inputs': 1, 'exit': None, 'succeeded': 0, 'failed': 0, 'dryRun': True}])


if __name__ == '__main__':
    unittest.main(verbosity=2)
