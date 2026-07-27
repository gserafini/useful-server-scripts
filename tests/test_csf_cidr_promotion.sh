#!/bin/bash
set -euo pipefail

SCRIPT="/usr/local/useful-server-scripts/scripts/csf_ban_wp_login_attackers"

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

for function_name in \
    validate_ipv4_24_cidr \
    get_csf_deny_limit \
    count_active_csf_deny_entries \
    list_covered_csf_children \
    rollback_csf_cidr_promotion \
    perform_promote_cidr
do
    grep -q "^${function_name}()" "$SCRIPT" || fail "missing ${function_name} helper"
done

grep -q -- 'promote-cidr:' "$SCRIPT" || fail "argument parser missing --promote-cidr"
grep -q -- '--promote-cidr <CIDR>' "$SCRIPT" || fail "help output missing --promote-cidr"

function_blocks=""
for function_name in \
    validate_ipv4_24_cidr \
    get_csf_deny_limit \
    count_active_csf_deny_entries \
    list_covered_csf_children \
    rollback_csf_cidr_promotion \
    perform_promote_cidr
do
    function_blocks+=$'\n'
    function_blocks+="$(sed -n "/^${function_name}() {/,/^}/p" "$SCRIPT")"
done

sandbox=$(mktemp -d)
trap 'rm -rf "$sandbox"' EXIT

CSF_DENY_FILE="$sandbox/csf.deny"
CSF_CONF_FILE="$sandbox/csf.conf"
CSF_TEMPIP_FILE="$sandbox/csf.tempip"
CSF_BIN="csf"
CSF_CHAIN_DENY_SET="chain_DENY"
CSF_PROMOTE_LOCK_FILE="$sandbox/promote.lock"
EVENT_LOG="$sandbox/events.log"
LIVE_SET="$sandbox/live-set"

cat > "$CSF_CONF_FILE" <<'EOF'
DENY_IP_LIMIT = "3"
EOF

csf() {
    printf 'csf %s\n' "$*" >> "$EVENT_LOG"

    case "$1" in
        -r)
            awk '$0 !~ /^[[:space:]]*(#|$)/ { print $1 }' "$CSF_DENY_FILE" > "$LIVE_SET"
            return 0
            ;;
        -dr|-d)
            fail "atomic promotion delegated a policy mutation to csf $1"
            ;;
    esac

    return 1
}

ipset() {
    printf 'ipset %s\n' "$*" >> "$EVENT_LOG"

    case "$1" in
        add)
            grep -Fqx "$3" "$LIVE_SET" 2>/dev/null || printf '%s\n' "$3" >> "$LIVE_SET"
            return 0
            ;;
        test)
            grep -Fqx "$3" "$LIVE_SET"
            return
            ;;
        del)
            if [ "${IPSET_STUB_FAIL_CHILD_DEL:-0}" -eq 1 ] && [[ "$3" != */24 ]]; then
                return 1
            fi
            awk -v target="$3" '$1 != target { print }' "$LIVE_SET" > "$LIVE_SET.tmp"
            mv "$LIVE_SET.tmp" "$LIVE_SET"
            return 0
            ;;
    esac

    return 1
}

eval "$function_blocks"

validate_ipv4_24_cidr "203.0.113.0/24" || fail "valid canonical /24 was rejected"
if validate_ipv4_24_cidr "203.0.113.1/24"; then
    fail "non-canonical /24 was accepted"
fi
if validate_ipv4_24_cidr "203.0.999.0/24"; then
    fail "out-of-range IPv4 octet was accepted"
fi

cat > "$CSF_DENY_FILE" <<'EOF'
# policy comment

Include /etc/csf/csf.deny.d/external
192.0.2.8 # protected do not delete
198.51.100.9 # one evictable entry
EOF
[ "$(count_active_csf_deny_entries)" -eq 1 ] ||
    fail "capacity accounting does not match CSF's DENY_IP_LIMIT behavior"

cat > "$CSF_DENY_FILE" <<'EOF'
203.0.113.10 # first child
203.0.113.55 # second child
198.51.100.9 # unrelated ban
EOF
cat > "$CSF_TEMPIP_FILE" <<'EOF'
203.0.113.10|1|123456|first child
203.0.113.55|0|123457|covered temporary history
198.51.100.9|1|123458|unrelated history
EOF
: > "$EVENT_LOG"
: > "$LIVE_SET"

promotion_output=$(perform_promote_cidr "203.0.113.0/24" "test campaign")

[ "$(grep -v '^ipset test ' "$EVENT_LOG" | sed -n '1p')" = "ipset add chain_DENY 203.0.113.0/24 -exist" ] ||
    fail "live parent coverage was not the first firewall mutation"
grep -q '^ipset del chain_DENY 203\.0\.113\.10 -exist$' "$EVENT_LOG" || fail "first covered live child was not removed"
grep -q '^ipset del chain_DENY 203\.0\.113\.55 -exist$' "$EVENT_LOG" || fail "second covered live child was not removed"
if grep -qE '^csf -(dr|d) ' "$EVENT_LOG"; then
    fail "promotion used non-atomic sequential CSF mutations"
fi
grep -q '^203\.0\.113\.0/24 ' "$CSF_DENY_FILE" || fail "parent CIDR missing from final policy"
if grep -q '^203\.0\.113\.[0-9]\+ ' "$CSF_DENY_FILE"; then
    fail "covered child entries remain in final policy"
fi
grep -q '^198\.51\.100\.9 ' "$CSF_DENY_FILE" || fail "unrelated deny entry was lost"
if grep -q '^203\.0\.113\.' "$CSF_TEMPIP_FILE"; then
    fail "covered LF_PERMBLOCK history remains in csf.tempip"
fi
grep -q '^198\.51\.100\.9|' "$CSF_TEMPIP_FILE" || fail "unrelated csf.tempip entry was lost"
printf '%s\n' "$promotion_output" | grep -q 'removed 2 covered child bans' ||
    fail "promotion summary omitted the removed child count"
printf '%s\n' "$promotion_output" | grep -q '1 slot of headroom' ||
    fail "promotion summary omitted final headroom"

cat > "$CSF_DENY_FILE" <<'EOF'
203.0.113.10 # first ban
198.51.100.9 # second ban
192.0.2.9 # third ban
EOF
: > "$EVENT_LOG"
: > "$LIVE_SET"

set +e
capacity_output=$(perform_promote_cidr "198.18.0.0/24" "no child headroom" 2>&1)
capacity_status=$?
set -e

[ "$capacity_status" -ne 0 ] || fail "over-capacity promotion unexpectedly succeeded"
[ ! -s "$EVENT_LOG" ] || fail "over-capacity refusal mutated firewall state"
printf '%s\n' "$capacity_output" | grep -q 'would exceed DENY_IP_LIMIT' ||
    fail "capacity refusal omitted the exact reason"

cat > "$CSF_DENY_FILE" <<'EOF'
203.0.113.10 # first child
203.0.113.55 # second child
198.51.100.9 # unrelated ban
EOF
cat > "$CSF_TEMPIP_FILE" <<'EOF'
203.0.113.10|1|123456|first child
203.0.113.55|0|123457|covered temporary history
198.51.100.9|1|123458|unrelated history
EOF
cp "$CSF_DENY_FILE" "$sandbox/original.deny"
cp "$CSF_TEMPIP_FILE" "$sandbox/original.tempip"
: > "$EVENT_LOG"
: > "$LIVE_SET"
IPSET_STUB_FAIL_CHILD_DEL=1

set +e
rollback_output=$(perform_promote_cidr "203.0.113.0/24" "forced failure" 2>&1)
rollback_status=$?
set -e
unset IPSET_STUB_FAIL_CHILD_DEL

[ "$rollback_status" -ne 0 ] || fail "failed parent persistence unexpectedly succeeded"
cmp -s "$sandbox/original.deny" "$CSF_DENY_FILE" || fail "rollback did not restore the exact deny file"
cmp -s "$sandbox/original.tempip" "$CSF_TEMPIP_FILE" || fail "rollback did not restore the exact csf.tempip file"
grep -q '^csf -r$' "$EVENT_LOG" || fail "rollback did not rebuild CSF from the restored policy"
printf '%s\n' "$rollback_output" | grep -q 'restored the original CSF deny policy' ||
    fail "rollback did not report restoration"

echo "PASS: atomic CSF CIDR promotion preserves coverage, capacity, and rollback"
