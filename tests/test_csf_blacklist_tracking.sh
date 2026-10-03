#!/bin/bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
script="${1:-$repo_root/scripts/csf_ban_wp_login_attackers}"
sandbox=$(mktemp -d)
trap 'rm -rf "$sandbox"' EXIT

fail() { echo "FAIL: $1" >&2; exit 1; }
eval "$(sed -n '/^validate_ip() {/,/^}/p' "$script")"
eval "$(sed -n '/^perform_blacklist() {/,/^}/p' "$script")"

IP_SET_NAME=high_volume_bans
IP_TRACKING_FILE="$sandbox/tracking.log"
protected=no
ensure_setup() { :; }
ensure_live_ipset_capacity() { :; }
build_protected_ipv4_file() { : > "$1"; }
ipv4_matches_policy_file() { [ "$protected" = yes ]; }
ipset() {
    [ "$1" = test ] || fail "repair must preserve existing live coverage without re-adding it"
    return 0
}
terminate_live_sessions_for_ip() { printf '%s\n' "$1" >> "$sandbox/teardown.log"; }
report_ban_counts() { :; }

# A deliberately re-applied live ban must become persistent without any
# firewall removal or insertion, and a second call must preserve its reason.
: > "$IP_TRACKING_FILE"
perform_blacklist 203.0.113.8 "confirmed scanner persistence repair" > "$sandbox/output"
[ "$(awk '$1 == "203.0.113.8" {n++} END {print n+0}' "$IP_TRACKING_FILE")" -eq 1 ] || fail "existing-live ban still has no persistent tracking record"
grep -Fq 'confirmed scanner persistence repair' "$IP_TRACKING_FILE" || fail "repair lost the supplied reason"
cp "$IP_TRACKING_FILE" "$sandbox/expected.log"
perform_blacklist 203.0.113.8 "second request must not overwrite original reason" > "$sandbox/output"
cmp "$IP_TRACKING_FILE" "$sandbox/expected.log" || fail "repeat blacklist duplicated or rewrote existing tracking"
[ "$(wc -l < "$sandbox/teardown.log")" -eq 2 ] || fail "existing sessions were not torn down on both calls"

# Trust policy remains authoritative even when the address is already live.
protected=yes
: > "$IP_TRACKING_FILE"
set +e
perform_blacklist 203.0.113.8 "protected address" > "$sandbox/output" 2>&1
protected_status=$?
set -e
[ "$protected_status" -eq 3 ] || fail "protected live address was accepted"
[ ! -s "$IP_TRACKING_FILE" ] || fail "protected live address was made persistent"

# Persistence failures must never be reported as successful containment.
protected=no
IP_TRACKING_FILE="$sandbox"
set +e
perform_blacklist 203.0.113.8 "write failure" > "$sandbox/output" 2>&1
write_status=$?
set -e
[ "$write_status" -ne 0 ] || fail "tracking write failure returned success"
grep -Fq 'tracking' "$sandbox/output" || fail "tracking failure omitted a useful error"

echo "PASS: existing live bans repair persistence idempotently, preserve trust, and report write failures"
