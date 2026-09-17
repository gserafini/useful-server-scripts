#!/bin/bash
set -euo pipefail

SCRIPT="/usr/local/useful-server-scripts/scripts/csf_ban_wp_login_attackers"

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

grep -q '^keyword_rule_pattern()' "$SCRIPT" || fail "missing multiword keyword parser"
grep -q '^build_unique_log_file_list()' "$SCRIPT" || fail "missing hard-link-aware log inventory"
grep -q '^scan_log_file_list_for_keyword()' "$SCRIPT" || fail "missing unique log scanner"
grep -q '^reconcile_protected_bans()' "$SCRIPT" || fail "missing allowlist reconciliation helper"
grep -q -- '--reconcile-allowlist' "$SCRIPT" || fail "missing explicit allowlist reconciliation command"

keyword_block=$(sed -n '/^keyword_rule_pattern() {/,/^}/p' "$SCRIPT")
inventory_block=$(sed -n '/^build_unique_log_file_list() {/,/^}/p' "$SCRIPT")
scan_block=$(sed -n '/^scan_log_file_list_for_keyword() {/,/^}/p' "$SCRIPT")
protected_block=$(sed -n '/^build_protected_ipv4_file() {/,/^}/p' "$SCRIPT")
reconcile_block=$(sed -n '/^reconcile_protected_bans() {/,/^}/p' "$SCRIPT")

eval "$keyword_block"
eval "$inventory_block"
eval "$scan_block"
eval "$protected_block"
eval "$reconcile_block"

[ "$(keyword_rule_pattern '1 union select')" = 'union select' ] ||
    fail "multiword signature was truncated"

sandbox=$(mktemp -d)
trap 'rm -rf "$sandbox"' EXIT
mkdir -p "$sandbox/logs/account"

cat > "$sandbox/logs/site-ssl_log" <<'EOF'
73.25.161.125 - - [15/Sep/2026:16:42:27 -0700] "GET /wp-content/plugins/jetpack/jetpack_vendor/automattic/jetpack-forms/dist/contact-form/css/grunion.css HTTP/2" 200 5050
198.51.100.44 - - [15/Sep/2026:16:43:00 -0700] ModSecurity decoded payload: 1 union select password
EOF
ln "$sandbox/logs/site-ssl_log" "$sandbox/logs/account/site-ssl_log"

LOG_PATHS="$sandbox/logs"
log_inventory="$sandbox/log-inventory.txt"
build_unique_log_file_list "$log_inventory"

[ "$(wc -l < "$log_inventory")" -eq 1 ] ||
    fail "hard-linked cPanel logs were inventoried more than once"

scan_output=$(scan_log_file_list_for_keyword 'union select' "$log_inventory")
if grep -q '73\.25\.161\.125' <<< "$scan_output"; then
    fail "Jetpack grunion.css falsely matched the union-select signature"
fi
[ "$(grep -c '198\.51\.100\.44' <<< "$scan_output")" -eq 1 ] ||
    fail "real union-select request was not matched exactly once"

IP_TRACKING_FILE="$sandbox/tracking.log"
CSF_ALLOW_FILE="$sandbox/csf.allow"
CSF_IGNORE_FILE="$sandbox/csf.ignore"
IP_SET_NAME="test_bans"
calls="$sandbox/ipset-calls.log"

cat > "$IP_TRACKING_FILE" <<'EOF'
73.25.161.125 # first false-positive entry
198.51.100.20 # retained malicious entry
73.25.161.125 # duplicate false-positive entry
192.0.2.10 # ignored monitoring source
10.20.30.40 # stale local self-ban
EOF
printf '%s\n' '73.25.161.125 # Pam via WhiteListMyIP' > "$CSF_ALLOW_FILE"
printf '%s\n' '192.0.2.10 # trusted monitoring' > "$CSF_IGNORE_FILE"

ip() {
    printf '%s\n' '2: eth0    inet 10.20.30.40/24 brd 10.20.30.255 scope global eth0'
}

ipset() {
    printf '%s\n' "$*" >> "$calls"
    return 0
}

reconcile_output=$(reconcile_protected_bans)

[ "$(awk '$1=="73.25.161.125" {n++} END{print n+0}' "$IP_TRACKING_FILE")" -eq 0 ] ||
    fail "allowlisted IP remained in tracking"
[ "$(awk '$1=="192.0.2.10" {n++} END{print n+0}' "$IP_TRACKING_FILE")" -eq 0 ] ||
    fail "ignored IP remained in tracking"
[ "$(awk '$1=="10.20.30.40" {n++} END{print n+0}' "$IP_TRACKING_FILE")" -eq 0 ] ||
    fail "local IP remained in tracking"
[ "$(awk '$1=="198.51.100.20" {n++} END{print n+0}' "$IP_TRACKING_FILE")" -eq 1 ] ||
    fail "unrelated tracked ban was removed"
grep -Fqx 'del test_bans 73.25.161.125 -exist' "$calls" ||
    fail "allowlisted IP was not removed from the live set"
grep -Fqx 'del test_bans 192.0.2.10 -exist' "$calls" ||
    fail "ignored IP was not removed from the live set"
grep -Fqx 'del test_bans 10.20.30.40 -exist' "$calls" ||
    fail "local IP was not removed from the live set"
grep -q 'Removed 4 protected tracking entries' <<< "$reconcile_output" ||
    fail "reconciliation summary did not report every removed entry"

echo "PASS: multiword signatures, hard-linked logs, and allowlist reconciliation prevent false-positive bans"
