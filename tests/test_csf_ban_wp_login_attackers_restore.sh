#!/bin/bash
set -euo pipefail

SCRIPT="/usr/local/useful-server-scripts/scripts/csf_ban_wp_login_attackers"

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

grep -q '^repopulate_ipset_from_tracking_file()' "$SCRIPT" || fail "missing repopulate_ipset_from_tracking_file helper"

whitelist_block=$(sed -n '/^perform_whitelist() {/,/^}/p' "$SCRIPT")
printf '%s\n' "$whitelist_block" | grep -q '/usr/sbin/csf -r' || fail "whitelist block missing csf reload"
printf '%s\n' "$whitelist_block" | grep -q 'repopulate_ipset_from_tracking_file' || fail "whitelist block does not repopulate live ipset after csf reload"

init_block=$(sed -n '/^perform_init() {/,/^}/p' "$SCRIPT")
printf '%s\n' "$init_block" | grep -q '/usr/sbin/csf -r' || fail "init block missing csf reload"
printf '%s\n' "$init_block" | grep -q 'repopulate_ipset_from_tracking_file' || fail "init block does not repopulate live ipset after csf reload"

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
