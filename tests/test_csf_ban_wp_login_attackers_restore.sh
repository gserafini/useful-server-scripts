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

echo "PASS: csf_ban_wp_login_attackers restores live ipset after csf reload"
