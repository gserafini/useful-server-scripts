# CLAUDE.md

---

**📦 This project uses [Agent Success Pack](https://github.com/gserafini/agent-success-pack)**

A framework for structured, AI-optimized project management. Key docs:
- **[PROGRESS.md](PROGRESS.md)** - Current status & session notes
- **[IMPLEMENTATION_CHECKLIST.md](IMPLEMENTATION_CHECKLIST.md)** - Phase breakdown
- **[ARCHITECTURE_DECISIONS.md](ARCHITECTURE_DECISIONS.md)** - Technical decisions (ADRs)

**At session start**: Read PROGRESS.md to understand current state.

---

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository contains a collection of bash scripts for Linux server administration, primarily focused on security hardening, WordPress management, and cPanel/WHM server maintenance. All scripts are designed to run with root privileges on production servers.

**Author**: Gabriel Serafini (gserafini@gmail.com)
**Repository**: https://github.com/gserafini/useful-server-scripts

## Installation

Scripts are installed by symlinking from the `scripts/` directory to `/usr/local/bin/`:

```bash
for f in `ls scripts/` ; do sudo ln -s $PWD/scripts/$f /usr/local/bin/$f ; done
```

This makes all scripts available system-wide as commands.

## Main Script: csf_ban_wp_login_attackers

The primary script in this repository is [scripts/csf_ban_wp_login_attackers](scripts/csf_ban_wp_login_attackers), a high-performance IP banning system that:

- Scans web server logs for malicious activity patterns
- Uses IPSET for kernel-level IP blocking (handles 50k+ bans efficiently)
- Integrates with CSF firewall via `/etc/csf/csfpost.sh`
- Provides abuse evidence reporting features
- Terminates existing connections using conntrack when available

### Architecture of csf_ban_wp_login_attackers

The script is organized into distinct functional areas:

1. **Configuration Section** (lines 66-93): Global variables including paths, thresholds, and temporary file creation
2. **Utility Functions** (lines 95-150): IP validation, path detection, setup verification
3. **Core Operations** (lines 151-419): Blacklist/whitelist/init/clear actions
4. **Log Scanning & Ban Logic** (lines 420-784): Main scanning loop, keyword matching, IP aggregation
5. **Abuse Reporting** (lines 785-1054): Evidence collection, WHOIS lookups, email draft generation
6. **Top Offenders Analysis** (lines 1055+): Statistical reporting
7. **Main Execution Logic** (bottom of file): Command-line argument parsing and dispatch

### Key Functions

- `validate_ip()`: IP address format validation
- `get_iptables_path()`: Locate iptables binary
- `is_setup_complete()`: Verify IPSET and CSF integration
- `perform_blacklist()`: Manually ban an IP
- `perform_whitelist()`: Remove IP from ban list and add to CSF allow list
- `perform_init()`: Initialize IPSET table and add firewall rules
- `perform_clear()`: Flush all bans (requires confirmation)
- `assemble_abuse_report()`: Generate abuse evidence for reporting to providers
- `provider_abuse_contact()`: WHOIS lookup for abuse contacts

### Common Usage Patterns

**Initial Setup** (run once):
```bash
sudo ./scripts/csf_ban_wp_login_attackers --init
```

**Manual IP Operations**:
```bash
sudo ./scripts/csf_ban_wp_login_attackers --blacklist 1.2.3.4 "Reason here"
sudo ./scripts/csf_ban_wp_login_attackers --whitelist 1.2.3.4 "Trusted admin"
```

**Abuse Reporting** (read-only operations):
```bash
sudo ./scripts/csf_ban_wp_login_attackers --abuse 1.2.3.4
sudo ./scripts/csf_ban_wp_login_attackers --abuse-days 7 --abuse-email --abuse 1.2.3.4
sudo ./scripts/csf_ban_wp_login_attackers --raw-grep '1.2.3.4'
```

**Automated Scanning** (typically via cron):
```bash
sudo ./scripts/csf_ban_wp_login_attackers
```

## Other Notable Scripts

### svn_add_remove
Interactive script for WordPress SVN management. Prompts to schedule additions/deletions for files detected by `svn status`. Handles permission cleanup when run as root.

### get_nameservers.sh
Queries cPanel's `/etc/userdomains` file to retrieve domain information (IPs, registrars, nameservers). Supports both human-readable and TSV output formats.

```bash
./scripts/get_nameservers.sh            # Human-readable
./scripts/get_nameservers.sh --csv      # TSV output
```

### ban_ips.sh
Bulk IP banning utility that reads IPs from stdin (one per line or mixed text), extracts IPs via regex, performs GeoIP lookup, and bans via CSF.

### fix_permissions
Recursively fixes file/directory permissions for web files. Defaults to current directory or accepts path argument.

```bash
./scripts/fix_permissions /path/to/website
```

## Development Guidelines

### Testing Scripts

**CRITICAL**: These scripts modify production firewall rules and system configurations. Testing should be done:

1. **In VM/Container**: Test major changes in isolated environments first
2. **With --init Dry-Run**: Review generated rules before applying
3. **With Test IPs**: Use known test IPs for blacklist/whitelist operations
4. **Check Dependencies**: Verify `ipset`, `iptables`, `csf`, `conntrack-tools` availability

### Code Patterns

**Variable Assignments**: The codebase uses command substitution with temporary variables to avoid shellcheck warnings:
```bash
# Preferred pattern
local path_cmd
path_cmd=$(command -v iptables 2>/dev/null || echo '/usr/sbin/iptables')
path=${path_cmd}
```

**Temporary Files**: Scripts create temp files at start and should clean them up:
```bash
TEMP_FILE=$(mktemp)
# ... use temp file ...
rm "$TEMP_FILE"  # Cleanup at end
```

**Input Validation**: Always validate IPs and user inputs:
```bash
if ! validate_ip "$ip"; then
    echo "Error: Invalid IP format"
    exit 1
fi
```

### Modifying csf_ban_wp_login_attackers

When adding new features:

1. **Configuration Variables**: Add at top (lines 66-93)
2. **Helper Functions**: Add after existing utility functions (after line 150)
3. **Command-Line Flags**: Add to argument parsing section at bottom
4. **Keywords**: Malicious patterns are in `keywords` array (around line 500-600)
5. **Log Paths**: Default logs in `DEFAULT_LOG_PATHS` variable (line 76)

### Dependencies

**Required for full functionality**:
- `ipset`: IP set management
- `iptables`: Firewall rules
- `csf`: ConfigServer Security & Firewall
- `conntrack-tools`: Connection termination (optional but recommended)
- `whois`: Abuse contact lookup
- `geoiplookup`: Geographic IP information (for ban_ips.sh)
- `dig`: DNS queries (for get_nameservers.sh)

**Server Environment**:
- Linux with root access
- cPanel/WHM (for get_nameservers.sh)
- Apache with standard log locations (for csf_ban_wp_login_attackers)

## Testing Commands

There are no automated tests in this repository. Manual testing workflow:

1. **Syntax Check**: `bash -n scripts/<script_name>`
2. **Setup Verification**: `sudo ./scripts/csf_ban_wp_login_attackers --init` (review output, don't apply on dev machines)
3. **Read-Only Operations**: Test `--abuse`, `--raw-grep` flags safely
4. **Manual Review**: Always review changes to `/etc/csf/` files before CSF reload

## File Structure

```
.
├── scripts/                          # All executable scripts
│   ├── csf_ban_wp_login_attackers   # Main IP banning system (1731 lines)
│   ├── svn_add_remove               # SVN workflow automation
│   ├── get_nameservers.sh           # Domain information queries
│   ├── ban_ips.sh                   # Bulk IP banning helper
│   ├── fix_permissions              # Permission management
│   └── [other utility scripts]
├── README.md                         # User documentation
└── LICENSE                           # MIT License
```

## Important Notes

- **Root Required**: All scripts require root/sudo privileges
- **Production Impact**: Scripts modify live firewall rules and system state
- **CSF Integration**: The main script depends on CSF being installed and configured
- **Log Paths**: Default log paths assume cPanel/Apache; customize via `--logs` flag if different
- **Backup First**: Always have firewall rule backups before running `--init` or `--clear`
