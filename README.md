# Useful Server Scripts

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Bash](https://img.shields.io/badge/bash-4.0+-green.svg)](https://www.gnu.org/software/bash/)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://www.linux.org/)
[![Security](https://img.shields.io/badge/security-firewall-red.svg)](scripts/csf_ban_wp_login_attackers)
[![CSF Compatible](https://img.shields.io/badge/CSF-compatible-orange.svg)](https://configserver.com/cp/csf.html)
[![Maintenance](https://img.shields.io/badge/maintained-yes-brightgreen.svg)](https://github.com/gserafini/useful-server-scripts/commits/master)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](#contributing)

A collection of battle-tested bash scripts for Linux server administration, with a focus on security hardening, WordPress management, and cPanel/WHM server maintenance.

**Author**: Gabriel Serafini ([gserafini@gmail.com](mailto:gserafini@gmail.com))

## Table of Contents

- [Overview](#overview)
- [Security Warning](#security-warning)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Scripts](#scripts)
  - [csf_ban_wp_login_attackers](#csf_ban_wp_login_attackers)
  - [svn_add_remove](#svn_add_remove)
  - [get_nameservers.sh](#get_nameserverssh)
  - [ban_ips.sh](#ban_ipssh)
  - [fix_permissions](#fix_permissions)
  - [Other Utility Scripts](#other-utility-scripts)
- [License](#license)
- [Contributing](#contributing)

## Overview

This repository provides production-ready scripts for system administrators managing:

- **WordPress Servers**: Automated security monitoring and IP blocking
- **cPanel/WHM Environments**: Domain management and account maintenance
- **SVN-Managed Sites**: Version control workflow automation
- **General Server Security**: Rootkit scanning, permission fixes, process management

These scripts are designed to be installed system-wide and run with root privileges, typically via cron jobs or manual administrative tasks.

## Security Warning

**⚠️ CRITICAL: These scripts modify production firewall rules and system configurations.**

- All scripts require **root/sudo privileges**
- Scripts modify **live firewall rules** and can affect server connectivity
- Always test in a VM or staging environment first
- Review all scripts before running them on production systems
- Keep backups of firewall configurations before making changes
- The `--init` and `--clear` operations for csf_ban_wp_login_attackers are particularly sensitive

**Use at your own risk. Always understand what a script does before executing it.**

## Requirements

### Core Dependencies

- Linux server (tested on RHEL/CentOS and Debian/Ubuntu)
- Bash 4.0 or higher
- Root access

### Script-Specific Dependencies

| Script | Dependencies |
|--------|-------------|
| csf_ban_wp_login_attackers | `ipset`, `iptables`, `csf`, `whois`, `conntrack-tools` (optional), Apache logs |
| get_nameservers.sh | `dig`, `whois`, `/etc/userdomains` (cPanel) |
| ban_ips.sh | `csf`, `geoiplookup` |
| svn_add_remove | `svn` (Subversion) |
| commit_htaccess_files.sh | `svn`, `/etc/trueuserowners` (cPanel) |
| chkrootkit_output_clean | `chkrootkit` |

**Installing conntrack-tools** (recommended for csf_ban_wp_login_attackers):

```bash
# RHEL/CentOS
sudo yum install -y conntrack-tools ipset

# Debian/Ubuntu
sudo apt-get install -y conntrack ipset
```

## Installation

Clone the repository and symlink scripts to `/usr/local/bin/`:

```bash
git clone https://github.com/gserafini/useful-server-scripts.git
cd useful-server-scripts/
for f in `ls scripts/` ; do sudo ln -s $PWD/scripts/$f /usr/local/bin/$f ; done
```

This makes all scripts available system-wide as commands (e.g., `sudo csf_ban_wp_login_attackers --init`).

## Quick Start

### For WordPress Security (csf_ban_wp_login_attackers)

1. **Install dependencies**:

   ```bash
   sudo yum install -y ipset conntrack-tools  # or apt-get on Debian/Ubuntu
   ```

2. **Initialize the system** (one-time setup):

   ```bash
   sudo csf_ban_wp_login_attackers --init
   ```

3. **Test a manual ban**:

   ```bash
   sudo csf_ban_wp_login_attackers --blacklist 1.2.3.4 "Test ban"
   ```

4. **Set up automated scanning** (add to root's crontab):

   ```bash
   # Run every 5 minutes
   */5 * * * * /usr/local/bin/csf_ban_wp_login_attackers
   ```

5. **Generate abuse reports**:

   ```bash
   sudo csf_ban_wp_login_attackers --abuse 1.2.3.4
   ```

### For SVN WordPress Management

In a WordPress directory managed by SVN:

```bash
svn_add_remove
```

Follow the interactive prompts to schedule additions/deletions.

### For cPanel Domain Information

```bash
# Human-readable output
get_nameservers.sh

# TSV format for spreadsheets
get_nameservers.sh --csv
```

## Scripts

### csf_ban_wp_login_attackers

**Primary script**: High-performance IP banning system using IPSET and CSF firewall integration.

**Purpose**: Automatically scan Apache logs for malicious activity (wp-login brute force, shell probes, ModSecurity violations) and ban offending IPs at the kernel level using IPSET.

**Key Features**:

- Handles 50,000+ bans efficiently using IPSET
- Integrates with CSF firewall via `/etc/csf/csfpost.sh`
- Terminates existing connections when banning (requires conntrack-tools)
- Generates abuse evidence reports with WHOIS integration
- Supports manual whitelist/blacklist management
- Rotatable ban list with permanent ban threshold

#### Setup & Configuration

**One-time initialization** (creates IPSET table and firewall rules):

```bash
sudo csf_ban_wp_login_attackers --init
```

This creates:

- IPSET table named `high_volume_bans`
- iptables DROP rule in `/etc/csf/csfpost.sh`
- Tracking file at `/etc/csf/ipset_tracking_high_volume_bans.log`

#### Daily Operations

**Manual IP management**:

```bash
# Ban an IP
sudo csf_ban_wp_login_attackers --blacklist 1.2.3.4 "Brute force wp-login"
# Alias: --block

# Whitelist an IP (adds to /etc/csf/csf.allow)
sudo csf_ban_wp_login_attackers --whitelist 1.2.3.4 "Trusted admin"
# Alias: --unblock

# Clear all bans (DANGEROUS - requires confirmation)
sudo csf_ban_wp_login_attackers --clear
```

**Automated scanning** (default mode, no flags):

```bash
sudo csf_ban_wp_login_attackers
```

Scans default log paths and bans IPs matching keyword patterns. Add to cron:

```bash
*/5 * * * * /usr/local/bin/csf_ban_wp_login_attackers
```

**Custom log paths**:

```bash
sudo csf_ban_wp_login_attackers --logs "/var/log/apache2/access.log /var/log/nginx/access.log"
```

#### Abuse Reporting (Read-Only)

These commands generate evidence for reporting abuse to ISPs. They don't modify firewall state.

**Basic report** (default threshold: 100 keyword matches):

```bash
sudo csf_ban_wp_login_attackers --abuse 1.2.3.4
```

**Report with email draft** (includes WHOIS abuse contact lookup):

```bash
sudo csf_ban_wp_login_attackers --abuse-email --abuse 1.2.3.4
```

**Time-limited report** (last 7 days):

```bash
sudo csf_ban_wp_login_attackers --abuse-days 7 --abuse 1.2.3.4
```

**Custom threshold** (50 hits instead of 100):

```bash
sudo csf_ban_wp_login_attackers --abuse-min 50 --abuse 1.2.3.4
```

**Date range filtering**:

```bash
sudo csf_ban_wp_login_attackers --abuse-since "2025-10-01" --abuse-until "2025-10-15" --abuse 1.2.3.4
```

**Raw log search** (grep wrapper):

```bash
sudo csf_ban_wp_login_attackers --raw-grep '1.2.3.4'
# Alias: --raw-search
```

#### All Command-Line Options

| Flag | Description |
|------|-------------|
| `--init` | Initialize IPSET table and CSF integration (one-time setup) |
| `--blacklist IP [MSG]` | Manually ban an IP (alias: `--block`) |
| `--whitelist IP [MSG]` | Remove IP from bans and add to CSF allow list (alias: `--unblock`) |
| `--clear` | Flush all bans from IPSET and tracking file (DANGEROUS) |
| `--logs "PATH1 PATH2"` | Override default log paths to scan |
| `--abuse IP [MIN_HITS]` | Generate abuse report (alias: `--abuse-report`) |
| `--abuse-min N` | Set default minimum hits for abuse reports |
| `--abuse-days N` | Restrict search to last N days (best-effort) |
| `--abuse-since STRING` | Filter logs by start date substring |
| `--abuse-until STRING` | Filter logs by end date substring |
| `--abuse-email` | Include WHOIS lookup and draft email in report |
| `--raw-grep STRING` | Search all logs for string (alias: `--raw-search`) |

#### Configuration Variables (in script)

Edit these at the top of the script if needed:

- `IP_SET_NAME`: IPSET table name (default: `high_volume_bans`)
- `MAX_BANS`: Maximum IPs in IPSET (default: 50,000)
- `MAX_PERMANENT_BANS`: Max permanent bans (default: 5,000)
- `MAX_VIOLATION_COUNT`: Threshold for permanent bans (default: 20 hits)
- `DEFAULT_LOG_PATHS`: Apache log locations to scan

#### Implementation Notes

- Reports are **non-destructive** - they read logs and write evidence to `/tmp`
- Date-range handling is **best-effort** based on log timestamp formats
- WHOIS abuse contact lookup is **heuristic** - always verify before emailing
- Requires **CSF installed** and configured before `--init`
- **conntrack-tools** optional but recommended for immediate session termination

---

### svn_add_remove

**Purpose**: Interactive SVN workflow helper for WordPress sites.

**Use Case**: After WordPress auto-updates, quickly schedule new/modified/removed files for SVN commit.

**What it does**:

1. Runs `svn status` to find unknown (`?`) and missing (`!`) files
2. Excludes cache files and error logs
3. Prompts to schedule additions and deletions
4. Handles replaced resources (`~`)
5. Fixes file ownership when run as root

**Usage**:

```bash
cd /path/to/wordpress
svn_add_remove
```

Follow interactive prompts to review and schedule changes.

**Requirements**: Subversion (`svn`)

---

### get_nameservers.sh

**Purpose**: Extract domain information for all accounts on a cPanel/WHM server.

**What it does**:

- Reads `/etc/userdomains` (cPanel's domain-to-user mapping)
- Filters for top-level domains (excludes subdomains)
- Queries DNS for A records using `dig`
- Performs WHOIS lookups for registrar and nameservers
- Groups output by cPanel user

**Usage**:

```bash
# Human-readable grouped output
get_nameservers.sh

# TSV format (tab-separated for spreadsheets)
get_nameservers.sh --csv
```

**Output includes**:

- Domain name
- IP address(es)
- Registrar
- Nameservers

**Requirements**: `dig`, `whois`, cPanel environment (`/etc/userdomains`)

---

### ban_ips.sh

**Purpose**: Bulk ban IPs from copy-pasted lists using CSF.

**What it does**:

1. Accepts multi-line input (paste IPs, press Enter, then Ctrl+D)
2. Extracts IPs using regex (handles various formats)
3. Performs GeoIP lookup for each IP
4. Bans via CSF with geographic metadata

**Usage**:

```bash
ban_ips.sh
# Paste IPs (one per line or mixed text)
# Press Ctrl+D to process
```

**Requirements**: `csf`, `geoiplookup`

---

### fix_permissions

**Purpose**: Recursively fix file and directory permissions for web files.

**What it does**:

- Sets files (`.php`, `.js`, `.png`, `.jpg`, `.jpeg`, `.txt`, `.css`) to `644`
- Sets directories to `755`
- Defaults to current directory or accepts path argument

**Usage**:

```bash
# Fix current directory
fix_permissions

# Fix specific path
fix_permissions /home/user/public_html
```

**Use Case**: After manual file uploads or ownership issues.

---

### Other Utility Scripts

#### commit_htaccess_files.sh

Auto-commits modified `.htaccess` files across all cPanel accounts to SVN, then fixes ownership.

**Requirements**: `svn`, cPanel environment (`/etc/trueuserowners`)

```bash
sudo commit_htaccess_files.sh
```

---

#### chkrootkit_output_clean

Runs `chkrootkit -q` and filters known false positives (e.g., cPanel's port 465).

**Requirements**: `chkrootkit` installed at `/usr/local/src/chkrootkit`

```bash
chkrootkit_output_clean
```

---

#### kill_long_php.sh

Kills all PHP processes running longer than 1 hour.

**Usage**:

```bash
sudo kill_long_php.sh
```

**Use Case**: Terminate runaway PHP scripts consuming resources.

---

#### inotify_watch_for_csf_whitelist_additions.sh

Monitors a file using `inotify` and adds IPs to CSF whitelist when detected.

---

#### inotify_watch_for_csf_whitelist_requests.sh

Monitors for whitelist requests and processes them.

---

#### restart_sshd.sh

Simple wrapper to restart SSH daemon.

---

#### rm_old_logs

Removes old log files (implementation TBD - check script for details).

---

#### ssh_count.sh

Counts active SSH connections.

---

## License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

Copyright (c) 2014 Gabriel Serafini

## Contributing

Contributions are welcome! Please:

1. **Test thoroughly** in a VM/staging environment
2. **Document changes** in commit messages
3. **Follow existing code style** (bash best practices, shellcheck compliance)
4. **Add usage examples** for new scripts or flags
5. **Update README.md** if adding new scripts or features

**Bug Reports**: Open an issue with reproduction steps and environment details.

**Security Issues**: Email [gserafini@gmail.com](mailto:gserafini@gmail.com) directly for security vulnerabilities.

---

**Repository**: [https://github.com/gserafini/useful-server-scripts](https://github.com/gserafini/useful-server-scripts)

**Built with assistance from**: Gemini Advanced (for csf_ban_wp_login_attackers and get_nameservers.sh)
