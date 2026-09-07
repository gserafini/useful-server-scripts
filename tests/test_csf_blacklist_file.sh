#!/bin/bash
set -euo pipefail

SCRIPT="/usr/local/useful-server-scripts/scripts/csf_ban_wp_login_attackers"

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

grep -q '^perform_blacklist_file()' "$SCRIPT" || fail "missing perform_blacklist_file helper"
grep -q -- 'blacklist-file:' "$SCRIPT" || fail "argument parser missing --blacklist-file"
grep -q -- '--blacklist-file <FILE|->' "$SCRIPT" || fail "help output missing --blacklist-file"

validate_block=$(sed -n '/^validate_ip() {/,/^}/p' "$SCRIPT")
batch_block=$(sed -n '/^perform_blacklist_file() {/,/^}/p' "$SCRIPT")
eval "$validate_block"
eval "$batch_block"

validate_ip "203.0.113.5" || fail "valid IPv4 address was rejected"
if validate_ip "999.0.0.1"; then
    fail "out-of-range IPv4 address was accepted"
fi

sandbox=$(mktemp -d)
trap 'rm -rf "$sandbox"' EXIT
calls="$sandbox/calls.log"

perform_blacklist() {
    printf '%s\t%s\n' "$1" "$2" >> "$calls"
    [ "$1" != "203.0.113.99" ]
}

cat > "$sandbox/valid.txt" <<'EOF'
# synchronized crawler fleet
203.0.113.10
198.51.100.20 # evidence source two

203.0.113.10
EOF

valid_output=$(perform_blacklist_file "$sandbox/valid.txt" "batch regression")
[ "$(wc -l < "$calls")" -eq 2 ] || fail "batch did not deduplicate input"
grep -Fqx $'203.0.113.10\tbatch regression' "$calls" || fail "first IP or message was not preserved"
grep -Fqx $'198.51.100.20\tbatch regression' "$calls" || fail "second IP or message was not preserved"
printf '%s\n' "$valid_output" | grep -q '2 succeeded, 0 failed' || fail "success summary is incorrect"

: > "$calls"
cat > "$sandbox/invalid.txt" <<'EOF'
203.0.113.10
999.0.0.1
EOF

set +e
invalid_output=$(perform_blacklist_file "$sandbox/invalid.txt" "must preflight" 2>&1)
invalid_status=$?
set -e
[ "$invalid_status" -ne 0 ] || fail "invalid batch unexpectedly succeeded"
[ ! -s "$calls" ] || fail "invalid batch mutated firewall state before preflight completed"
printf '%s\n' "$invalid_output" | grep -q 'line 2' || fail "invalid batch did not report its source line"

: > "$calls"
cat > "$sandbox/partial.txt" <<'EOF'
203.0.113.10
203.0.113.99
198.51.100.20
EOF

set +e
partial_output=$(perform_blacklist_file "$sandbox/partial.txt" "continue regression" 2>&1)
partial_status=$?
set -e
[ "$partial_status" -ne 0 ] || fail "partial batch failure returned success"
[ "$(wc -l < "$calls")" -eq 3 ] || fail "batch stopped instead of processing every preflighted IP"
printf '%s\n' "$partial_output" | grep -q '2 succeeded, 1 failed' || fail "partial-failure summary is incorrect"

echo "PASS: --blacklist-file validates, deduplicates, and processes complete batches"
