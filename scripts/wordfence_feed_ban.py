#!/usr/bin/env python3
"""Ban IPv4 sources reported by Wordfence blocked-IP feeds through the tracked ban helper.

Each configured WordPress site runs the "WordFence Get Blocked IPs" helper plugin, which
answers SITE/?get_wordfence_blocked_ips=true&format=json with recent Wordfence blocks.
This script collects those feeds, keeps only valid global IPv4 sources, removes addresses
that are already banned, protected by local CSF allow/ignore policy, Cloudflare, or owned
by this host, and passes the rest to `csf_ban_wp_login_attackers --blacklist-file -`.
That helper inserts into the kernel ipset `high_volume_bans` and keeps the persistent
tracking file, so these bans never consume CSF's capped csf.deny slots.

Configuration: one https:// site base URL per line in /etc/wordfence-feed-ban.conf
(see config/wordfence-feed-ban.conf.example). This repository is public: never commit
the real site list.

Exit codes: 0 all sites and batches succeeded; 1 partial failure (some site or batch
failed, valid work was still applied); 2 configuration error; 3 no feed could be read;
4 ban/policy state could not be read (nothing applied); 5 another run holds the lock.
"""
import argparse
import datetime
import fcntl
import ipaddress
import json
import os
import re
import ssl
import subprocess
import sys
import time
import urllib.request

DEFAULT_CONFIG = '/etc/wordfence-feed-ban.conf'
DEFAULT_HELPER = '/usr/local/useful-server-scripts/scripts/csf_ban_wp_login_attackers'
DEFAULT_STATE_DIR = '/var/lib/wordfence-feed-ban'
RUN_LOCK = '/var/run/wordfence-feed-ban.lock'
TRACKING_LOCK = '/var/lock/csf-ban-tracking.lock'
MAX_FEED_BYTES = 5 * 1024 * 1024
USER_AGENT = 'wordfence-feed-ban/1.0'
SET_NAME = 'high_volume_bans'

# Cloudflare edge ranges (https://www.cloudflare.com/ips-v4/). A misconfigured site behind
# Cloudflare can report edge addresses as attackers; banning them would cut off every
# proxied site on the server, so they are never banned regardless of feed content.
CLOUDFLARE_IPV4 = [
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
    '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
    '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
]
_CLOUDFLARE = [ipaddress.ip_network(n) for n in CLOUDFLARE_IPV4]
_DOCUMENTATION = [ipaddress.ip_network(n) for n in ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24')]
_SITE_RE = re.compile(r'https://([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+)/?')
_TYPE_RE = re.compile(r'[a-z0-9_-]{1,24}')
_SUMMARY_RE = re.compile(r'Blacklist batch complete: (\d+) unique IPs?; (\d+) succeeded, (\d+) failed\.')


class ConfigError(Exception):
    pass


class FeedError(Exception):
    pass


def read_sites(text):
    """Return normalized https://host site bases from the config text."""
    sites = []
    for number, line in enumerate(text.splitlines(), 1):
        value = line.split('#', 1)[0].strip()
        if not value:
            continue
        match = _SITE_RE.fullmatch(value)
        if not match:
            raise ConfigError('line %d: expected https://host with no path, got %r' % (number, value))
        site = 'https://' + match.group(1).lower()
        if site not in sites:
            sites.append(site)
    if not sites:
        raise ConfigError('no sites configured')
    return sites


def feed_url(site, maxdays, limit):
    return '%s/?get_wordfence_blocked_ips=true&format=json&maxdays=%d&limit=%d' % (site, maxdays, limit)


def parse_feed(raw, allow_documentation=False):
    """Validate one feed body. Return (rows, stats); rows hold ip/type/count."""
    if len(raw) > MAX_FEED_BYTES:
        raise FeedError('feed larger than %d bytes' % MAX_FEED_BYTES)
    if not raw.strip():
        # The helper plugin answers HTTP 200 with an empty body when nothing was blocked.
        return [], {'rows': 0, 'ipv4': 0, 'ipv6': 0, 'nonGlobal': 0, 'invalid': 0}
    try:
        data = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, ValueError) as exc:
        raise FeedError('feed is not JSON: %s' % str(exc)[:80])
    if not isinstance(data, list):
        raise FeedError('feed JSON is %s, expected a list' % type(data).__name__)
    rows = []
    stats = {'rows': len(data), 'ipv4': 0, 'ipv6': 0, 'nonGlobal': 0, 'invalid': 0}
    for item in data:
        ip = item.get('IP') if isinstance(item, dict) else None
        try:
            address = ipaddress.ip_address(ip) if isinstance(ip, str) else None
        except ValueError:
            address = None
        if address is None:
            stats['invalid'] += 1
            continue
        if address.version == 6:
            stats['ipv6'] += 1
            continue
        documentation = any(address in net for net in _DOCUMENTATION)
        if not address.is_global and not (allow_documentation and documentation):
            stats['nonGlobal'] += 1
            continue
        block_type = item.get('blockType')
        block_type = block_type if isinstance(block_type, str) and _TYPE_RE.fullmatch(block_type) else 'other'
        count = item.get('blockCount')
        count = count if isinstance(count, int) and not isinstance(count, bool) and count >= 0 else 0
        rows.append({'ip': str(address), 'type': block_type, 'count': count})
        stats['ipv4'] += 1
    return rows, stats


def parse_ipset_save(text, set_name=SET_NAME):
    members = set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[0] == 'add' and fields[1] == set_name:
            members.add(fields[2])
    return members


def parse_networks(text):
    """Parse one IPv4 address or CIDR per line; raise ValueError on anything else."""
    networks = []
    for line in text.splitlines():
        value = line.strip()
        if not value or value.startswith('#'):
            continue
        networks.append(ipaddress.ip_network(value, strict=False))
    return networks


def parse_own_addresses(text):
    """Extract IPv4 addresses from `ip -o -4 addr show` output."""
    return set(re.findall(r'\binet (\d{1,3}(?:\.\d{1,3}){3})/', text))


def plan(feeds, live, protected, own, cap):
    """Merge feeds per IP and choose what to ban, strongest evidence first."""
    merged = {}
    for rows in feeds.values():
        for row in rows:
            entry = merged.setdefault(row['ip'], {'total': 0, 'types': {}})
            entry['total'] += row['count']
            entry['types'][row['type']] = entry['types'].get(row['type'], 0) + max(row['count'], 1)
    networks = list(protected) + _CLOUDFLARE
    skipped = {'live': 0, 'protected': 0, 'own': 0}
    eligible = []
    for ip, entry in merged.items():
        address = ipaddress.ip_address(ip)
        if ip in own:
            skipped['own'] += 1
        elif any(address in net for net in networks):
            skipped['protected'] += 1
        elif ip in live:
            skipped['live'] += 1
        else:
            block_type = sorted(entry['types'].items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
            eligible.append((entry['total'], address, block_type))
    eligible.sort(key=lambda item: (-item[0], int(item[1])))
    chosen = eligible[:cap]
    groups = {}
    for _total, address, block_type in sorted(chosen, key=lambda item: int(item[1])):
        groups.setdefault(block_type, []).append(str(address))
    return {'unique': len(merged), 'eligible': len(eligible), 'groups': groups,
            'skipped': skipped, 'deferred': len(eligible) - len(chosen)}


def apply(groups, helper, runner=subprocess.run, dry_run=False, today=None, timeout=900):
    """Run one guarded helper batch per block type; never retry a failed batch."""
    today = today or datetime.date.today().isoformat()
    results = []
    for block_type in sorted(groups):
        ips = groups[block_type]
        if dry_run:
            results.append({'type': block_type, 'inputs': len(ips), 'exit': None,
                            'succeeded': 0, 'failed': 0, 'dryRun': True})
            continue
        reason = 'Wordfence feed %s: %s block reported by a fleet site' % (today, block_type)
        proc = runner([helper, '--blacklist-file', '-', reason], input='\n'.join(ips) + '\n',
                      capture_output=True, text=True, timeout=timeout)
        summary = _SUMMARY_RE.search(proc.stdout or '')
        succeeded = int(summary.group(2)) if summary else None
        failed = int(summary.group(3)) if summary else len(ips)
        results.append({'type': block_type, 'inputs': len(ips), 'exit': proc.returncode,
                        'succeeded': succeeded, 'failed': failed})
    return results


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


def _fetch(site, maxdays, limit, timeout):
    request = urllib.request.Request(feed_url(site, maxdays, limit), headers={'User-Agent': USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout, context=ssl.create_default_context()) as response:
        if response.status != 200:
            raise FeedError('HTTP %d' % response.status)
        return response.read(MAX_FEED_BYTES + 1)


def _run(argv, timeout=60):
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError('%s exited %d: %s' % (argv[0], proc.returncode, proc.stderr.strip()[:200]))
    return proc.stdout


def _write_state(state_dir, state):
    os.makedirs(state_dir, mode=0o700, exist_ok=True)
    path = os.path.join(state_dir, 'last-run.json')
    temporary = path + '.tmp'
    with open(temporary, 'w') as handle:
        json.dump(state, handle, indent=2, sort_keys=True)
        handle.write('\n')
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _locked_runner(lock_path, wait_seconds):
    """Serialize helper batches with the existing tracking-writer cron lock."""
    def runner(argv, **kwargs):
        with open(lock_path, 'a') as lock:
            deadline = time.monotonic() + wait_seconds
            while True:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError('tracking lock %s busy for %ds' % (lock_path, wait_seconds))
                    time.sleep(2)
            return subprocess.run(argv, **kwargs)
    return runner


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--config', default=DEFAULT_CONFIG)
    parser.add_argument('--helper', default=DEFAULT_HELPER)
    parser.add_argument('--state-dir', default=DEFAULT_STATE_DIR)
    parser.add_argument('--maxdays', type=int, default=7, help='feed window in days (default 7)')
    parser.add_argument('--limit', type=int, default=10000, help='rows requested per site (default 10000)')
    parser.add_argument('--cap', type=int, default=2000, help='maximum new bans per run (default 2000)')
    parser.add_argument('--timeout', type=int, default=30, help='seconds per feed request (default 30)')
    parser.add_argument('--dry-run', action='store_true', help='plan only; never call the ban helper')
    args = parser.parse_args(argv)

    lock = open(RUN_LOCK, 'a')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print(json.dumps({'at': _now(), 'result': 'skipped', 'reason': 'another run holds ' + RUN_LOCK}))
        return 5

    state = {'startedUTC': _now(), 'dryRun': args.dry_run, 'sites': [], 'maxdays': args.maxdays,
             'limit': args.limit, 'cap': args.cap}
    try:
        with open(args.config) as handle:
            sites = read_sites(handle.read())
    except (OSError, ConfigError) as exc:
        state.update(result='config-error', error=str(exc), endedUTC=_now())
        _write_state(args.state_dir, state)
        print(json.dumps({'at': state['endedUTC'], 'result': 'config-error', 'error': str(exc)}))
        return 2

    feeds = {}
    for site in sites:
        entry = {'site': site, 'ok': False}
        try:
            rows, stats = parse_feed(_fetch(site, args.maxdays, args.limit, args.timeout))
            feeds[site] = rows
            entry.update(ok=True, stats=stats)
        except Exception as exc:  # one failed site never blocks the others
            entry['error'] = ('%s: %s' % (type(exc).__name__, exc))[:200]
        state['sites'].append(entry)
    if not feeds:
        state.update(result='no-feeds', endedUTC=_now())
        _write_state(args.state_dir, state)
        print(json.dumps({'at': state['endedUTC'], 'result': 'no-feeds', 'sites': len(sites)}))
        return 3

    try:
        live = parse_ipset_save(_run(['ipset', 'save', SET_NAME]))
        protected = parse_networks(_run([args.helper, '--export-protected-ipv4'], timeout=120))
        own = parse_own_addresses(_run(['ip', '-o', '-4', 'addr', 'show']))
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
        state.update(result='state-error', error=str(exc)[:300], endedUTC=_now())
        _write_state(args.state_dir, state)
        print(json.dumps({'at': state['endedUTC'], 'result': 'state-error', 'error': str(exc)[:300]}))
        return 4
    if not protected:
        state.update(result='state-error', error='empty protected policy export', endedUTC=_now())
        _write_state(args.state_dir, state)
        print(json.dumps({'at': state['endedUTC'], 'result': 'state-error', 'error': 'empty protected policy export'}))
        return 4

    decision = plan(feeds, live, protected, own, args.cap)
    try:
        results = apply(decision['groups'], args.helper, runner=_locked_runner(TRACKING_LOCK, 300),
                        dry_run=args.dry_run)
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        results = [{'error': str(exc)[:300]}]
    batch_ok = all(r.get('exit') in (0, None) and r.get('failed') == 0 for r in results)
    sites_ok = all(entry['ok'] for entry in state['sites'])
    state.update(endedUTC=_now(), liveBefore=len(live), protectedNetworks=len(protected),
                 plan={k: v for k, v in decision.items() if k != 'groups'},
                 planned={k: len(v) for k, v in decision['groups'].items()}, results=results,
                 result='ok' if batch_ok and sites_ok else 'partial')
    _write_state(args.state_dir, state)
    print(json.dumps({'at': state['endedUTC'], 'result': state['result'], 'dryRun': args.dry_run,
                      'sitesOk': sum(e['ok'] for e in state['sites']), 'sites': len(sites),
                      'unique': decision['unique'], 'skipped': decision['skipped'],
                      'planned': state['planned'], 'deferred': decision['deferred'],
                      'banned': sum(r.get('succeeded') or 0 for r in results),
                      'failed': sum(r.get('failed') or 0 for r in results)}, sort_keys=True))
    return 0 if state['result'] == 'ok' else 1


if __name__ == '__main__':
    sys.exit(main())
