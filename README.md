Gabriel's Useful Server Scripts
=====================

Useful scripts for server administration.  You will most likely need root access to install
these.


Installation
-----
1. ``$ git clone https://github.com/gserafini/useful-server-scripts.git``
2. ``$ cd useful-server-scripts/``
3. ``$ for f in `ls scripts/` ; do sudo ln -s $PWD/scripts/$f /usr/local/bin/$f ; done``

### svn\_add\_remove
Run this script in a directory you are managing using svn. It will ask you if you would like
to svn add new files and svn remove missing files.  It is particularly useful if a 
WordPress installation has been automatically upgraded and files have been added / removed
that you would like to then check in.

csf_ban_wp_login_attackers — Command-line options
-----------------------------------------------

This repository includes the `csf_ban_wp_login_attackers` script (under `scripts/`). It is a log-scanning, high-volume IP banning helper which uses `ipset` and integrates with CSF (via `/etc/csf/csfpost.sh`).

Usage examples
--------------

- Initialize the IPSET table and CSF integration (run once as root):

```bash
sudo ./scripts/csf_ban_wp_login_attackers --init
```

- Add a single IP to the ban list manually (and optionally add a message):

```bash
sudo ./scripts/csf_ban_wp_login_attackers --blacklist 1.2.3.4 "Brute force wp-login"
# or
sudo ./scripts/csf_ban_wp_login_attackers --block 1.2.3.4
```

- Whitelist an IP (adds to /etc/csf/csf.allow and removes from ipset):

```bash
sudo ./scripts/csf_ban_wp_login_attackers --whitelist 1.2.3.4 "Trusted admin"
# or
sudo ./scripts/csf_ban_wp_login_attackers --unblock 1.2.3.4
```

- Clear all ipset bans (DANGEROUS — interactive confirmation required):

```bash
sudo ./scripts/csf_ban_wp_login_attackers --clear
```

Abuse evidence/reporting options
--------------------------------

These flags assemble log evidence suitable for manual abuse reporting. They are read-only and do not change firewall state.

- `--abuse-report <IP> [MIN_HITS]` (alias `--abuse`)
	- Scans configured logs for the given IP, filters lines by the script's built-in `keywords` list, and writes matched evidence to temporary files in `/tmp`.
	- If `MIN_HITS` is provided, the report is generated only when the number of keyword-matched lines is >= MIN_HITS; otherwise the script uses a default of 100 (or the value set via `--abuse-min`).

- `--abuse-min <N>`
	- Sets the default minimum hits for reports when a `MIN_HITS` value is not supplied directly to `--abuse-report`.

- `--abuse-days <N>`
	- Best-effort: attempts to restrict search to entries in the last N days. This is approximate and depends on your log timestamps; use with care.

- `--abuse-since <STRING>` and `--abuse-until <STRING>`
	- Simple substring filters applied to log lines (useful when logs include ISO dates or common formats such as `2025-10-01` or `Oct/01/2025`). These are conservative text matches, not strict date parsers.

- `--abuse-email`
	- When present, the script will attempt a minimal `whois` lookup to find an abuse contact and will print a draft abuse email (To:, Subject:, body with sample evidence). This is a convenience to help craft provider reports — always manually verify the contact and evidence before sending.

Notes and examples
------------------

- Generate a standard report for `1.2.3.4` (default threshold 100):

```bash
sudo ./scripts/csf_ban_wp_login_attackers --abuse 1.2.3.4
```

- Generate a report for the last 7 days and produce a draft email:

```bash
sudo ./scripts/csf_ban_wp_login_attackers --abuse-days 7 --abuse-email --abuse 1.2.3.4
```

- Generate a report with a lower threshold of 50 hits:

```bash
sudo ./scripts/csf_ban_wp_login_attackers --abuse-min 50 --abuse 1.2.3.4
```

Implementation notes
--------------------

- The report functions are intentionally non-destructive. They read logs, write evidence files to `/tmp`, and print summary/sample output for copy/paste.
- Date-range handling is best-effort; for production accuracy provide explicit date parsing rules or examples of your log timestamp format and I can refine the filter.
- The `--abuse-email` whois-based lookup is heuristic and may not always find a provider contact; it is primarily a convenience for assembling a draft.

```