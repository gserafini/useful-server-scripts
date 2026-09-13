#!/bin/bash
set -euo pipefail

SCRIPT="/usr/local/useful-server-scripts/scripts/csf_ban_wp_login_attackers"

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

grep -q '^perform_unblacklist()' "$SCRIPT" || fail "missing perform_unblacklist helper"
grep -q -- '--unblacklist <IP>' "$SCRIPT" || fail "help output missing --unblacklist"

validate_block=$(sed -n '/^validate_ip() {/,/^}/p' "$SCRIPT")
unblacklist_block=$(sed -n '/^perform_unblacklist() {/,/^}/p' "$SCRIPT")
eval "$validate_block"
eval "$unblacklist_block"

sandbox=$(mktemp -d)
trap 'rm -rf "$sandbox"' EXIT
IP_TRACKING_FILE="$sandbox/tracking.log"
CSF_ALLOW_FILE="$sandbox/csf.allow"
CSF_DENY_FILE="$sandbox/csf.deny"
IP_SET_NAME="test_bans"
calls="$sandbox/calls.log"

cat > "$IP_TRACKING_FILE" <<'EOF'
203.0.113.10 # first target entry
198.51.100.20 # retained entry
203.0.113.10 # duplicate target entry
EOF
printf '%s\n' '192.0.2.5 # trusted admin' > "$CSF_ALLOW_FILE"
: > "$CSF_DENY_FILE"

ensure_setup() { :; }
report_ban_counts() { :; }
ipset() {
    printf '%s\n' "$*" >> "$calls"
    return 0
}

perform_unblacklist "203.0.113.10" "false positive"

[ "$(awk '$1=="203.0.113.10" {n++} END{print n+0}' "$IP_TRACKING_FILE")" -eq 0 ] || fail "target remained in tracking"
[ "$(awk '$1=="198.51.100.20" {n++} END{print n+0}' "$IP_TRACKING_FILE")" -eq 1 ] || fail "unrelated tracking entry was removed"
grep -Fqx '192.0.2.5 # trusted admin' "$CSF_ALLOW_FILE" || fail "CSF allow file changed"
grep -Fqx 'del test_bans 203.0.113.10' "$calls" || fail "live ipset entry was not removed"

before=$(sha256sum "$IP_TRACKING_FILE" | awk '{print $1}')
set +e
perform_unblacklist "999.0.0.1" "invalid" >/dev/null 2>&1
status=$?
set -e
[ "$status" -ne 0 ] || fail "invalid IP unexpectedly succeeded"
after=$(sha256sum "$IP_TRACKING_FILE" | awk '{print $1}')
[ "$before" = "$after" ] || fail "invalid IP mutated tracking"

echo "PASS: --unblacklist removes tracked/live deny coverage without creating a CSF allow entry"
