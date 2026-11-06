#!/usr/bin/python3.12
"""Rotate the PHP-FPM pool error logs in /home/USER/logs (server_ops M127).

Why: cPanel points each FPM pool's php_admin_value[error_log] at
/home/USER/logs/POOL.php.error.log, and nothing rotated those files. On
2026-11-06 cstulsa's had grown to 4.9 GB of warnings since 2024-10-31.

How: build a logrotate config from the installed pool configs, with one stanza
per account, then run logrotate with its own state file. Each stanza runs as
the account (su USER GROUP), renames the log and recreates it empty with the
same owner and mode (create). The previous generation is compressed one cycle
later (delaycompress). The PHP critical-error monitor follows a renamed log by
inode: findRotated() in server-watchdog-php-core.js reads the old generation's
unread tail from POOL.php.error.log-* before moving to the new file. So
rename-and-create loses no lines. copytruncate would (the collector records a
truncation gap), so it is never used.

Only paths directly inside the account's own /home/USER/logs, named
*.php.error.log and owned by the account, are included; anything else is
skipped and logged. Nested CGI error_log files inside web roots are out of
scope: a renamed copy no longer matches Apache's ^error_log$ deny and would be
downloadable.

Policy: weekly, or sooner once a log passes --maxsize (the job runs daily).
Keep --rotate generations, named -YYYYMMDD-EPOCH so they sort and never
collide.

Scheduled daily at 03:23 by /etc/cron.d/php-pool-logrotate; one JSON line per run
in /var/log/php-pool-logrotate.log. Pause with touch /etc/php-pool-logrotate.disable.

Usage: php_pool_logrotate.py [--dry-run] [--generate-only] [--only PATH ...]
         [--conf FILE] [--state FILE] [--log FILE] [--disable-file FILE]
"""
import argparse
import glob
import grp
import json
import os
import pwd
import re
import stat
import subprocess
import sys
import tempfile
import time

POOL_GLOB = '/opt/cpanel/ea-php*/root/etc/php-fpm.d/*.conf'
LOG_NAME = re.compile(r'^[A-Za-z0-9._-]+\.php\.error\.log$')
USER_RE = re.compile(r'^\s*user\s*=\s*"?([A-Za-z0-9_.-]+)"?\s*$', re.M)
LOG_RE = re.compile(r'^\s*php_admin_value\[error_log\]\s*=\s*(\S+)\s*$', re.M)


def parse_pool(text):
    """Return (user, error_log) from one pool config, or None."""
    user, log = USER_RE.search(text), LOG_RE.search(text)
    if not user or not log:
        return None
    return user.group(1), log.group(1).strip('"\'')


def account(name):
    """Look up the account the pool runs as: name, uid, gid, group, home."""
    pw = pwd.getpwnam(name)
    return {'name': name, 'uid': pw.pw_uid, 'gid': pw.pw_gid,
            'group': grp.getgrgid(pw.pw_gid).gr_name, 'home': pw.pw_dir}


def reject_reason(acct, log):
    """Return why a pool log must not be rotated as this account, or None if it is safe."""
    if not log.startswith('/') or os.path.normpath(log) != log:
        return 'path is not absolute and normalized'
    logs_dir = os.path.join(acct['home'], 'logs')
    if os.path.dirname(log) != logs_dir:
        return 'not directly inside the account logs directory'
    if not LOG_NAME.match(os.path.basename(log)):
        return 'file name is not *.php.error.log'
    try:
        d = os.lstat(logs_dir)
    except FileNotFoundError:
        return 'logs directory missing'
    if not stat.S_ISDIR(d.st_mode):
        return 'logs directory is a symlink or not a directory'
    if d.st_uid != acct['uid']:
        return 'logs directory not owned by the account'
    if d.st_mode & 0o022:
        return 'logs directory is group or world writable'
    try:
        f = os.lstat(log)
    except FileNotFoundError:
        return None  # missingok: PHP creates it on the first error
    if not stat.S_ISREG(f.st_mode):
        return 'log is a symlink or not a regular file'
    if f.st_uid != acct['uid']:
        return 'log not owned by the account'
    if f.st_nlink != 1:
        return 'log is hard-linked'
    return None


def plan(pool_glob=POOL_GLOB, lookup=account, only=None):
    """Collect pool logs per account, with skipped entries and their reasons."""
    by_user, skipped, seen = {}, [], set()
    for conf in sorted(glob.glob(pool_glob)):
        try:
            with open(conf, encoding='utf-8', errors='replace') as fh:
                parsed = parse_pool(fh.read())
        except OSError as err:
            skipped.append({'conf': conf, 'reason': f'unreadable: {err.strerror}'})
            continue
        if not parsed:
            continue
        user, log = parsed
        if log in seen or (only and log not in only):
            continue
        seen.add(log)
        try:
            acct = lookup(user)
        except KeyError:
            skipped.append({'conf': conf, 'log': log, 'reason': f'unknown user {user}'})
            continue
        reason = reject_reason(acct, log)
        if reason:
            skipped.append({'conf': conf, 'log': log, 'reason': reason})
            continue
        by_user.setdefault(user, {'acct': acct, 'logs': []})['logs'].append(log)
    return by_user, skipped


def render(by_user, rotate=12, maxsize='50M'):
    """Render the logrotate config: one stanza per account, which rotates as that account."""
    out = ['# Generated by useful-server-scripts/scripts/php_pool_logrotate.py (server_ops M127).',
           '# Do not edit: the daily job rewrites this file from the installed PHP-FPM pool configs.',
           '']
    for user in sorted(by_user):
        acct = by_user[user]['acct']
        out.append(' '.join(sorted(by_user[user]['logs'])) + ' {')
        out += [f'    su {acct["name"]} {acct["group"]}',
                '    weekly',
                f'    maxsize {maxsize}',
                f'    rotate {rotate}',
                '    dateext',
                '    dateformat -%Y%m%d-%s',
                '    compress',
                '    delaycompress',
                '    missingok',
                '    notifempty',
                '    create',
                '    nomail',
                '}', '']
    return '\n'.join(out)


def write_checked(path, text, logrotate):
    """Write the config only if logrotate accepts it, so a bad render never replaces a good file."""
    os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.php-pool-logs.', dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, 'w') as fh:
            fh.write(text)
        os.chmod(tmp, 0o644)
        with tempfile.TemporaryDirectory() as scratch:
            check = subprocess.run([logrotate, '-d', '-s', os.path.join(scratch, 'state'), tmp],
                                   capture_output=True, text=True)
        errors = [l for l in check.stderr.splitlines() if l.startswith('error:')]
        if check.returncode != 0 or errors:
            raise RuntimeError('logrotate rejected the generated config: ' + '; '.join(errors[:3] or [check.stderr.strip()[:300]]))
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--pool-glob', default=POOL_GLOB)
    ap.add_argument('--conf', default='/etc/logrotate-php-pool/php-pool-logs.conf')
    ap.add_argument('--state', default='/var/lib/logrotate/php-pool-logs.status')
    ap.add_argument('--log', default='/var/log/php-pool-logrotate.log')
    ap.add_argument('--disable-file', default='/etc/php-pool-logrotate.disable')
    ap.add_argument('--logrotate', default='/usr/sbin/logrotate')
    ap.add_argument('--rotate', type=int, default=12)
    ap.add_argument('--maxsize', default='50M')
    ap.add_argument('--only', action='append', help='limit to this exact log path (repeatable), for staged rollout')
    ap.add_argument('--generate-only', action='store_true', help='write the config but do not rotate')
    ap.add_argument('--dry-run', action='store_true', help='print what logrotate would do; change nothing')
    ap.add_argument('--force', action='store_true', help='pass -f to logrotate (tests only)')
    args = ap.parse_args()

    record = {'at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
    if os.path.exists(args.disable_file):
        record['disabled'] = args.disable_file
        print(json.dumps(record))
        return 0
    by_user, skipped = plan(args.pool_glob, only=set(args.only) if args.only else None)
    text = render(by_user, args.rotate, args.maxsize)
    record.update(accounts=len(by_user), logs=sum(len(v['logs']) for v in by_user.values()),
                  skipped=len(skipped), skippedSample=skipped[:5])
    conf = args.conf
    if args.dry_run:
        conf = os.path.join(tempfile.mkdtemp(prefix='php-pool-logrotate-'), 'php-pool-logs.conf')
    write_checked(conf, text, args.logrotate)
    if args.generate_only:
        record['generated'] = conf
    else:
        cmd = ['/usr/bin/nice', '-n', '19', '/usr/bin/ionice', '-c3', args.logrotate, '-s', args.state]
        cmd += ['-d'] if args.dry_run else []
        cmd += ['-f'] if args.force else []
        run = subprocess.run(cmd + [conf], capture_output=True, text=True)
        record.update(exit=run.returncode, errors=[l for l in run.stderr.splitlines() if l.startswith('error:')][:10])
        if args.dry_run:
            rotating = re.findall(r'^\s*log needs rotating', run.stderr, re.M)
            record['wouldRotate'] = len(rotating)
            sys.stderr.write(run.stderr)
    line = json.dumps(record)
    print(line)
    if not args.dry_run and args.log:
        with open(args.log, 'a') as fh:
            fh.write(line + '\n')
    return 1 if record.get('exit') or record.get('errors') else 0


if __name__ == '__main__':
    sys.exit(main())
