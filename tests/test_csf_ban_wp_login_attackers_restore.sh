#!/bin/bash
set -euo pipefail

SCRIPT="/usr/local/useful-server-scripts/scripts/csf_ban_wp_login_attackers"

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

grep -q '^repopulate_ipset_from_tracking_file()' "$SCRIPT" || fail "missing repopulate_ipset_from_tracking_file helper"

grep -q '^CSF_REBUILD_LINE=' "$SCRIPT" || fail "missing persistent CSF rebuild hook command"
setup_block=$(sed -n '/^is_setup_complete() {/,/^}/p' "$SCRIPT")
printf '%s\n' "$setup_block" | grep -q 'CSF_REBUILD_LINE' || fail "setup check does not require the rebuild hook"

repopulate_block=$(sed -n '/^repopulate_ipset_from_tracking_file() {/,/^}/p' "$SCRIPT")
printf '%s\n' "$repopulate_block" | grep -q 'ip -4 -o addr show' || fail "rebuild does not discover local addresses"
printf '%s\n' "$repopulate_block" | grep -q 'ipset restore' || fail "rebuild does not use atomic bulk restore"
printf '%s\n' "$repopulate_block" | grep -q 'protected' || fail "rebuild does not skip local addresses"

sandbox=$(mktemp -d)
trap 'rm -rf "$sandbox"' EXIT
cat > "$sandbox/tracking.log" <<'EOF'
203.0.113.10 # malicious source
10.20.30.40 # stale local self-ban
203.0.113.10 # duplicate source
999.0.0.1 # malformed source
EOF

IP_SET_NAME="high_volume_bans"
IP_TRACKING_FILE="$sandbox/tracking.log"
MAX_BANS=250000

ip() {
    printf '%s\n' '2: eth0    inet 10.20.30.40/24 brd 10.20.30.255 scope global eth0'
}

ipset() {
    printf '%s\n' "$*" >> "$sandbox/ipset-calls.log"
    case "$1" in
        list|del)
            return 0
            ;;
        restore)
            cat > "$sandbox/restore-input.log"
            return 0
            ;;
    esac
    return 1
}

eval "$repopulate_block"
rebuild_output=$(repopulate_ipset_from_tracking_file)

verify_rebuild_preserves_caller_ip() {
    local ip="198.51.100.42"
    repopulate_ipset_from_tracking_file >/dev/null
    [ "$ip" = "198.51.100.42" ]
}

verify_rebuild_preserves_caller_ip || fail "rebuild clobbered the caller's local IP variable"

grep -q '^add high_volume_bans 203\.0\.113\.10 -exist$' "$sandbox/restore-input.log" || fail "bulk restore omitted valid tracked IP"
if grep -q '10\.20\.30\.40' "$sandbox/restore-input.log"; then
    fail "bulk restore included assigned local IP"
fi
[ "$(grep -c '203\.0\.113\.10' "$sandbox/restore-input.log")" -eq 1 ] || fail "bulk restore did not deduplicate tracked IPs"
grep -q '^del high_volume_bans 10\.20\.30\.40 -exist$' "$sandbox/ipset-calls.log" || fail "rebuild did not remove stale live self-ban"
printf '%s\n' "$rebuild_output" | grep -q 'Skipped 1 malformed tracking entries' || fail "rebuild did not report malformed entry"
printf '%s\n' "$rebuild_output" | grep -q 'Skipped and removed 1 assigned local-address entries' || fail "rebuild did not report local self-ban"

unset -f ip ipset
rm -rf "$sandbox"
trap - EXIT

whitelist_block=$(sed -n '/^perform_whitelist() {/,/^}/p' "$SCRIPT")
printf '%s\n' "$whitelist_block" | grep -q '/usr/sbin/csf -r' || fail "whitelist block missing csf reload"
printf '%s\n' "$whitelist_block" | grep -q 'repopulate_ipset_from_tracking_file' || fail "whitelist block does not repopulate live ipset after csf reload"

init_block=$(sed -n '/^perform_init() {/,/^}/p' "$SCRIPT")
printf '%s\n' "$init_block" | grep -q '/usr/sbin/csf -r' || fail "init block missing csf reload"
printf '%s\n' "$init_block" | grep -q 'repopulate_ipset_from_tracking_file' || fail "init block does not repopulate live ipset after csf reload"
printf '%s\n' "$init_block" | grep -q 'CSF_REBUILD_LINE' || fail "init block does not persist the rebuild hook"

grep -q -- '--rebuild-live-set' "$SCRIPT" || fail "help/argument parser missing --rebuild-live-set"

grep -q -- '--whitelist-local-addresses' "$SCRIPT" || fail "help/argument parser missing --whitelist-local-addresses"
grep -q '^perform_whitelist_local_addresses()' "$SCRIPT" || fail "missing perform_whitelist_local_addresses helper"
local_whitelist_block=$(sed -n '/^perform_whitelist_local_addresses() {/,/^}/p' "$SCRIPT")
printf '%s\n' "$local_whitelist_block" | grep -q '/usr/sbin/csf -r' || fail "local-address whitelist does not reload CSF"
printf '%s\n' "$local_whitelist_block" | grep -q 'repopulate_ipset_from_tracking_file' || fail "local-address whitelist does not rebuild the live ipset"
printf '%s\n' "$local_whitelist_block" | grep -q 'ip -4 -o addr show' || fail "local-address whitelist does not discover assigned IPv4 addresses"

grep -q '^MAX_BANS=250000$' "$SCRIPT" || fail "MAX_BANS must provide headroom for the tracked ban corpus"
grep -q '^resize_live_ipset()' "$SCRIPT" || fail "missing atomic resize_live_ipset helper"
grep -q '^ensure_live_ipset_capacity()' "$SCRIPT" || fail "missing ensure_live_ipset_capacity helper"
grep -q -- 'resize-live-set:' "$SCRIPT" || fail "argument parser missing --resize-live-set"

resize_block=$(sed -n '/^resize_live_ipset() {/,/^}/p' "$SCRIPT")
printf '%s\n' "$resize_block" | grep -q 'ipset swap' || fail "resize helper does not atomically swap the live set"
printf '%s\n' "$resize_block" | grep -q 'update_persistent_ipset_capacity' || fail "resize helper does not persist the new capacity"

persistence_block=$(sed -n '/^update_persistent_ipset_capacity() {/,/^}/p' "$SCRIPT")
printf '%s\n' "$persistence_block" | grep -q 'CSF_POST_FILE' || fail "capacity persistence helper does not update CSF recreation state"

blacklist_block=$(sed -n '/^perform_blacklist() {/,/^}/p' "$SCRIPT")
printf '%s\n' "$blacklist_block" | grep -q 'ensure_live_ipset_capacity' || fail "blacklist does not repair undersized live sets"

rebuild_block=$(sed -n '/^perform_rebuild_live_set() {/,/^}/p' "$SCRIPT")
printf '%s\n' "$rebuild_block" | grep -q 'ensure_live_ipset_capacity' || fail "rebuild does not repair undersized live sets"

echo "PASS: csf_ban_wp_login_attackers restores and resizes the live ipset"
