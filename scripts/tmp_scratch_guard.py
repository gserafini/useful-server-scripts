#!/usr/bin/python3.12
"""Close group/other access on stale root-owned scratch at the top level of /tmp.

Why (server_ops B1929/B1930): root agent sessions write scratch (mail threads,
exports, uploads) to /tmp with mode 0644/0755. No PHP pool is chrooted and none
sets open_basedir, so any hosted account's PHP could read it. This guard closes
that exposure for anything older than --min-age; it never deletes or reads files.

Selection (top-level entries only; a closed directory protects its subtree):
  - owned by root, regular file or directory (symlinks, sockets, fifos skipped)
  - has any group/other permission bit
  - mtime older than --min-age seconds (default 3600)
  - not a sticky directory, not a system socket directory, not systemd-private-*
  - not held open, or used as cwd/root, by any process
Action: chmod to (mode & 0o7700). Each change is logged with the old mode, so
it can be reversed with chmod. Pause by creating the --disable-file.

Usage: tmp_scratch_guard.py [--root /tmp] [--min-age 3600] [--dry-run]
         [--log /var/log/tmp-scratch-guard.log] [--disable-file /etc/tmp-scratch-guard.disable]

Installed on dc3-1 as /etc/cron.d/tmp-scratch-guard, every 10 minutes:
  */10 * * * * root /usr/bin/python3.12 -I <repo>/scripts/tmp_scratch_guard.py --min-age 3600
Tests: TMPDIR=/root/.cache python3.12 tests/test_tmp_scratch_guard.py
"""
import argparse
import os
import stat
import sys
import time

SYSTEM_NAMES = {'.X11-unix', '.ICE-unix', '.font-unix', '.XIM-unix', '.Test-unix'}


def in_use_names(root):
    """Top-level names under root that any process holds open or uses as cwd/root."""
    prefix = root.rstrip('/') + '/'
    names = set()
    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue
        links = [f'/proc/{pid}/cwd', f'/proc/{pid}/root']
        try:
            links += [f'/proc/{pid}/fd/{fd}' for fd in os.listdir(f'/proc/{pid}/fd')]
        except OSError:
            pass
        for link in links:
            try:
                target = os.readlink(link)
            except OSError:
                continue
            if target.startswith(prefix):
                names.add(target[len(prefix):].split('/', 1)[0])
    return names


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--root', default='/tmp')
    ap.add_argument('--min-age', type=int, default=3600)
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--log', default='/var/log/tmp-scratch-guard.log')
    ap.add_argument('--disable-file', default='/etc/tmp-scratch-guard.disable')
    a = ap.parse_args()
    if os.path.exists(a.disable_file):
        print(f'disabled by {a.disable_file}; no changes')
        return 0
    now = time.time()
    busy = in_use_names(a.root)
    changes = []
    with os.scandir(a.root) as it:
        for entry in it:
            name = entry.name
            if name in SYSTEM_NAMES or name.startswith('systemd-private-') or name in busy:
                continue
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            mode = stat.S_IMODE(st.st_mode)
            if st.st_uid != 0 or not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
                continue
            if stat.S_ISDIR(st.st_mode) and mode & stat.S_ISVTX:
                continue
            if mode & 0o077 == 0 or now - st.st_mtime < a.min_age:
                continue
            changes.append((name, mode, mode & 0o7700))
    if a.dry_run:
        for name, old, new in changes:
            print(f'would chmod {oct(old)} -> {oct(new)} {name}')
        print(f'dry-run: {len(changes)} candidates')
        return 0
    done = 0
    stamp = time.strftime('%Y-%m-%dT%H:%M:%S%z')
    with open(a.log, 'a') as log:
        for name, old, new in changes:
            path = os.path.join(a.root, name)
            try:
                st = os.lstat(path)  # re-check identity immediately before the change
                if st.st_uid != 0 or stat.S_ISLNK(st.st_mode) or stat.S_IMODE(st.st_mode) != old:
                    continue
                os.chmod(path, new)
            except OSError:
                continue
            log.write(f'{stamp}\t{oct(old)}\t{oct(new)}\t{name}\n')
            done += 1
    if a.log != '/dev/null':
        os.chmod(a.log, 0o600)
    print(f'changed {done} of {len(changes)} candidates')
    return 0


if __name__ == '__main__':
    sys.exit(main())
