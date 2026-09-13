#!/bin/bash
set -euo pipefail

SCRIPT="/usr/local/useful-server-scripts/scripts/csf_ban_wp_login_attackers"

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

grep -q '^perform_check_ip()' "$SCRIPT" || fail "missing perform_check_ip helper"
grep -q -- '--check-ip <IP>' "$SCRIPT" || fail "help output missing --check-ip"
grep -q 'check-ip:' "$SCRIPT" || fail "getopt parser missing --check-ip"

validate_block=$(sed -n '/^validate_ip() {/,/^}/p' "$SCRIPT")
check_block=$(sed -n '/^perform_check_ip() {/,/^}/p' "$SCRIPT")
eval "$validate_block"
eval "$check_block"

sandbox=$(mktemp -d)
trap 'rm -rf "$sandbox"' EXIT
IP_TRACKING_FILE="$sandbox/tracking.log"
CSF_ALLOW_FILE="$sandbox/csf.allow"
CSF_DENY_FILE="$sandbox/csf.deny"
IP_SET_NAME="test_bans"

cat > "$IP_TRACKING_FILE" <<'EOF'
203.0.113.10 # first target entry
198.51.100.20 # retained entry
203.0.113.10 # duplicate target entry
EOF
cat > "$CSF_DENY_FILE" <<'EOF'
203.0.113.10 # exact deny
203.0.113.0/24 # parent deny
EOF
printf '%s\n' '192.0.2.5 # trusted admin' > "$CSF_ALLOW_FILE"

ipset() {
    [ "$1" = "test" ] && [ "$2" = "test_bans" ] && [ "$3" = "203.0.113.10" ]
}

before=$(sha256sum "$IP_TRACKING_FILE" "$CSF_DENY_FILE" "$CSF_ALLOW_FILE")
output=$(perform_check_ip "203.0.113.10")
after=$(sha256sum "$IP_TRACKING_FILE" "$CSF_DENY_FILE" "$CSF_ALLOW_FILE")

[ "$before" = "$after" ] || fail "read-only check mutated policy files"
grep -Fqx 'IP: 203.0.113.10' <<< "$output" || fail "IP missing from output"
grep -Fqx 'Live ipset test_bans: present' <<< "$output" || fail "live presence missing from output"
grep -Fqx 'Tracking entries: 2' <<< "$output" || fail "tracking count is wrong"
grep -Fqx 'CSF deny exact entries: 1' <<< "$output" || fail "exact deny count is wrong"
grep -Fqx 'CSF deny parent /24 entries: 1' <<< "$output" || fail "parent deny count is wrong"
grep -Fqx 'CSF allow exact entries: 0' <<< "$output" || fail "allow count is wrong"

set +e
perform_check_ip "999.0.0.1" >/dev/null 2>&1
status=$?
set -e
[ "$status" -ne 0 ] || fail "invalid IP unexpectedly succeeded"

echo "PASS: --check-ip reports live and persistent coverage without mutation"
