#!/bin/bash
# Isolated fixtures: never source the script or invoke firewall commands.
set -euo pipefail
SCRIPT="${SCRIPT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/scripts/csf_ban_wp_login_attackers}"
grep -q '^perform_export_protected_ipv4()' "$SCRIPT" || { echo 'FAIL: missing read-only policy export'; exit 1; }
grep -q -- '--export-protected-ipv4' "$SCRIPT"
eval "$(sed -n '/^build_protected_ipv4_file() {/,/^}/p' "$SCRIPT")"
eval "$(sed -n '/^perform_export_protected_ipv4() {/,/^}/p' "$SCRIPT")"
sandbox=$(mktemp -d)
trap 'rm -rf "$sandbox"' EXIT
export TMPDIR="$sandbox"
CSF_ALLOW_FILE="$sandbox/allow"
CSF_IGNORE_FILE="$sandbox/ignore"
printf 'Include %s\ntcp|in|d=22|s=198.51.100.0/24\n' "$sandbox/nested" > "$CSF_ALLOW_FILE"
printf '192.0.2.7\n' > "$sandbox/nested"
printf '203.0.113.19\n' > "$CSF_IGNORE_FILE"
ip() { printf '%s\n' '2: eth0 inet 10.20.30.40/24 scope global eth0'; }
iptables() { echo 'FAIL: firewall mutation attempted' >&2; return 1; }
ipset() { echo 'FAIL: firewall mutation attempted' >&2; return 1; }
csf() { echo 'FAIL: firewall mutation attempted' >&2; return 1; }
before=$(sha256sum "$CSF_ALLOW_FILE" "$CSF_IGNORE_FILE" "$sandbox/nested")
actual=$(perform_export_protected_ipv4)
expected=$(printf '%s\n' 127.0.0.1 10.20.30.40 192.0.2.7 198.51.100.0/24 203.0.113.19 | sort -u)
[ "$actual" = "$expected" ]
[ "$before" = "$(sha256sum "$CSF_ALLOW_FILE" "$CSF_IGNORE_FILE" "$sandbox/nested")" ]
[ "$(find "$sandbox" -type f | wc -l)" -eq 3 ]
printf 'Include %s\n' "$sandbox/missing" > "$CSF_IGNORE_FILE"
if actual=$(perform_export_protected_ipv4 2>/dev/null); then echo 'FAIL: unreadable Include accepted'; exit 1; fi
[ -z "$actual" ]
[ "$(find "$sandbox" -type f | wc -l)" -eq 3 ]
echo 'PASS: read-only policy export uses complete canonical resolver, emits no partial policy and cleans temporary files'
