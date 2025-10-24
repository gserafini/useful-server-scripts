# Repository Maintenance Checklist

Maintenance and enhancement tracking for Useful Server Scripts collection.

## Legend

- ✅ Complete
- 🚧 In Progress
- ⏳ Blocked/Deferred
- ❌ Not Started

---

## Documentation

**Goal**: Maintain comprehensive documentation for all scripts.

- [x] Create CLAUDE.md for AI assistance
- [x] Comprehensive README.md overhaul
- [x] Document all 13 scripts
- [x] Add security warnings
- [x] Add installation instructions
- [x] Add Quick Start guide
- [ ] Add man pages for major scripts
- [ ] Create usage examples wiki
- [ ] Document cron job setup examples

**Status**: Documentation foundation complete, advanced docs pending

---

## Code Quality & Testing

**Goal**: Improve reliability and maintainability of bash scripts.

### Shell Script Best Practices

- [ ] Run shellcheck on all scripts
- [ ] Fix shellcheck warnings/errors
- [ ] Add consistent error handling (set -euo pipefail where appropriate)
- [ ] Standardize function documentation format
- [ ] Add usage/help output to all scripts

### Testing

- [ ] Create basic bash unit tests (using bats-core or similar)
- [ ] Add integration tests for csf_ban_wp_login_attackers
- [ ] Test scripts on both RHEL/CentOS and Debian/Ubuntu
- [ ] Create test fixtures for log parsing
- [ ] Document test environment setup

**Status**: Not started - testing infrastructure needed

---

## csf_ban_wp_login_attackers Enhancements

**Goal**: Improve the flagship IP banning script.

### Features

- [ ] Add support for nginx logs
- [ ] Add JSON output mode for reporting
- [ ] Implement IP reputation API integration (AbuseIPDB, etc.)
- [ ] Add GeoIP-based auto-blocking rules
- [ ] Support for fail2ban integration/comparison mode
- [ ] Add stats/dashboard output (top countries, attack patterns)
- [ ] Implement email notifications for critical events

### Performance

- [ ] Benchmark log parsing performance on large files
- [ ] Optimize grep patterns for speed
- [ ] Add parallel log processing option
- [ ] Implement incremental log scanning (track last position)

### Reliability

- [ ] Add comprehensive error handling
- [ ] Implement backup/restore for IPSET tables
- [ ] Add dry-run mode for testing
- [ ] Validate all IP addresses before adding to IPSET
- [ ] Add recovery mode if IPSET gets corrupted

**Status**: Feature-rich but room for improvements

---

## New Script Ideas

**Goal**: Add new useful server administration scripts.

### Security & Monitoring

- [ ] WordPress security scanner (file integrity checks)
- [ ] Log anomaly detector (ML-based or pattern-based)
- [ ] SSL certificate expiration monitor
- [ ] Suspicious process detector
- [ ] Disk usage alerter with cleanup suggestions

### WordPress Management

- [ ] WordPress core/plugin/theme update checker
- [ ] Database optimization scheduler
- [ ] Backup verification script
- [ ] Plugin security vulnerability scanner
- [ ] Mass WordPress configuration tool

### cPanel/WHM Utilities

- [ ] Account resource usage reporter
- [ ] Email queue analyzer
- [ ] Backup verification tool
- [ ] DNS propagation checker
- [ ] SSL installation automator

### General System Administration

- [ ] Automated security audit script
- [ ] System health dashboard generator
- [ ] Log rotation configuration checker
- [ ] Service dependency mapper
- [ ] Configuration drift detector

**Status**: Ideas collection - prioritization needed

---

## Repository Infrastructure

**Goal**: Improve development workflow and collaboration.

- [x] MIT License in place
- [x] Contributing guidelines in README
- [ ] Add GitHub Actions for shellcheck
- [ ] Create issue templates
- [ ] Add pull request template
- [ ] Set up automated testing on PR
- [ ] Add CHANGELOG.md
- [ ] Create releases/tags for stable versions
- [ ] Add CODE_OF_CONDUCT.md
- [ ] Set up GitHub Discussions for Q&A

**Status**: Basic infrastructure complete

---

## Platform Support

**Goal**: Ensure compatibility across common server environments.

### Operating Systems

- [x] RHEL/CentOS tested
- [ ] AlmaLinux tested
- [ ] Rocky Linux tested
- [ ] Debian tested
- [ ] Ubuntu LTS tested
- [ ] Amazon Linux 2 tested

### Control Panels

- [x] cPanel/WHM (primary target)
- [ ] Plesk compatibility layer
- [ ] DirectAdmin compatibility
- [ ] Standalone (no control panel) mode

**Status**: cPanel-focused, expansion possible

---

## Security Hardening

**Goal**: Ensure scripts follow security best practices.

- [ ] Audit all scripts for shell injection vulnerabilities
- [ ] Review privilege requirements (minimize root operations)
- [ ] Add input validation for all user inputs
- [ ] Implement secure temporary file handling
- [ ] Add signature verification for updates
- [ ] Security audit by external reviewer
- [ ] Add SAST (static analysis) in CI/CD

**Status**: Production-tested but formal audit pending

---

## Community & Outreach

**Goal**: Grow user base and contributor community.

- [ ] Write blog post about csf_ban_wp_login_attackers
- [ ] Create demo video/screencast
- [ ] Submit to Awesome Sysadmin lists
- [ ] Cross-post to /r/sysadmin
- [ ] Present at local sysadmin meetups
- [ ] Create Twitter/X account for updates
- [ ] Answer questions on ServerFault/StackOverflow

**Status**: Not started - repository is working tool, not marketed

---

## Migration & Modernization

**Goal**: Consider modern alternatives while maintaining bash compatibility.

### Long-term Considerations

- [ ] Evaluate Python rewrite for complex scripts (csf_ban_wp_login_attackers)
- [ ] Consider containerization (Docker) for portable testing
- [ ] Evaluate cloud-native alternatives (AWS WAF, Cloudflare)
- [ ] Research eBPF-based alternatives to IPSET
- [ ] Consider systemd integration for service scripts

**Status**: Deferred - bash scripts work well for target use cases

---

## Current Priority Focus

1. **Immediate**: Run shellcheck and fix critical issues
2. **Short-term**: Add basic tests for csf_ban_wp_login_attackers
3. **Medium-term**: Create usage examples wiki
4. **Long-term**: Evaluate new script additions based on user feedback

---

**Last Updated**: 2025-10-23
**Maintainer**: Gabriel Serafini ([gserafini@gmail.com](mailto:gserafini@gmail.com))
**Repository**: [https://github.com/gserafini/useful-server-scripts](https://github.com/gserafini/useful-server-scripts)
