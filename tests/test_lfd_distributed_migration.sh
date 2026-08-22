#!/bin/bash
set -euo pipefail

SCRIPT="/usr/local/useful-server-scripts/scripts/csf_ban_wp_login_attackers"
SYSTEM_AWK=$(command -v awk)

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

for function_name in \
    validate_ip \
    get_csf_deny_limit \
    count_active_csf_deny_entries \
    collect_lfd_distributed_ips \
    rollback_lfd_distributed_migration \
    perform_migrate_lfd_distributed
do
    grep -q "^${function_name}()" "$SCRIPT" || fail "missing ${function_name} helper"
done

grep -q -- 'migrate-lfd-distributed' "$SCRIPT" || fail "argument parser missing --migrate-lfd-distributed"
grep -q -- '--migrate-lfd-distributed' "$SCRIPT" || fail "help output missing --migrate-lfd-distributed"

function_blocks=""
for function_name in \
    validate_ip \
    get_csf_deny_limit \
    count_active_csf_deny_entries \
    collect_lfd_distributed_ips \
    rollback_lfd_distributed_migration \
    perform_migrate_lfd_distributed
do
    function_blocks+=$'\n'
    function_blocks+="$(sed -n "/^${function_name}() {/,/^}/p" "$SCRIPT")"
done

sandbox=$(mktemp -d)
trap 'rm -rf "$sandbox"' EXIT

LFD_LOG_FILE="$sandbox/lfd.log"
LFD_MIGRATE_TAIL_LINES=5000
IP_SET_NAME="high_volume_bans"
IP_TRACKING_FILE="$sandbox/tracking.log"
CSF_DENY_FILE="$sandbox/csf.deny"
CSF_CONF_FILE="$sandbox/csf.conf"
CSF_TEMPIP_FILE="$sandbox/csf.tempip"
CSF_BIN="csf"
CSF_CHAIN_DENY_SET="chain_DENY"
CSF_PROMOTE_LOCK_FILE="$sandbox/policy.lock"
EVENT_LOG="$sandbox/events.log"
HIGH_SET="$sandbox/high-set"
CHAIN_SET="$sandbox/chain-set"

cat > "$CSF_CONF_FILE" <<'EOF'
DENY_IP_LIMIT = "10"
EOF

csf() {
    printf 'csf %s\n' "$*" >> "$EVENT_LOG"
    case "$1" in
        -r)
            awk '$0 !~ /^[[:space:]]*(#|$)/ { print $1 }' "$CSF_DENY_FILE" > "$CHAIN_SET"
            return 0
            ;;
        -dr|-d)
            fail "migration delegated a policy mutation to csf $1"
            ;;
    esac
    return 1
}

ipset() {
    local set_file
    printf 'ipset %s\n' "$*" >> "$EVENT_LOG"
    case "$2" in
        "$IP_SET_NAME") set_file="$HIGH_SET" ;;
        "$CSF_CHAIN_DENY_SET") set_file="$CHAIN_SET" ;;
        *) return 1 ;;
    esac

    case "$1" in
        add)
            grep -Fqx "$3" "$set_file" 2>/dev/null || printf '%s\n' "$3" >> "$set_file"
            return 0
            ;;
        test)
            grep -Fqx "$3" "$set_file"
            return
            ;;
        del)
            if [ "${IPSET_STUB_FAIL_CHILD_DEL:-0}" -eq 1 ] && [ "$2" = "$CSF_CHAIN_DENY_SET" ]; then
                return 1
            fi
            awk -v target="$3" '$1 != target { print }' "$set_file" > "$set_file.tmp"
            mv "$set_file.tmp" "$set_file"
            return 0
            ;;
    esac
    return 1
}

eval "$function_blocks"

# dc2-5 runs GNU awk 3.1.7, where interval quantifiers are disabled by
# default. Exercise the collector with those legacy matching semantics.
awk() {
    if [[ "$*" == *"*Blocked in csf* [LF_DISTATTACK]"* ]]; then
        command "$SYSTEM_AWK" --traditional "$@"
    else
        command "$SYSTEM_AWK" "$@"
    fi
}

: > "$CSF_DENY_FILE"
: > "$CSF_TEMPIP_FILE"
: > "$IP_TRACKING_FILE"
: > "$EVENT_LOG"
: > "$HIGH_SET"
: > "$CHAIN_SET"
set +e
missing_log_output=$(perform_migrate_lfd_distributed 2>&1)
missing_log_status=$?
set -e
[ "$missing_log_status" -ne 0 ] || fail "migration succeeded with an unreadable LFD log"
printf '%s\n' "$missing_log_output" | grep -q 'Cannot read LFD log' ||
    fail "unreadable-log failure omitted the exact cause"

cat > "$LFD_LOG_FILE" <<'EOF'
Aug 22 06:00:00 host lfd[100]: 203.0.113.10 (US/Example/-) has 10 failures *Blocked in csf* [LF_DISTATTACK]
Aug 22 06:00:01 host lfd[101]: 203.0.113.55 (US/Example/-) has 10 failures *Blocked in csf* [LF_DISTATTACK]
Aug 22 06:00:02 host lfd[102]: 203.0.113.10 (US/Example/-) has 10 failures *Blocked in csf* [LF_DISTATTACK]
Aug 22 06:00:03 host lfd[103]: 203.0.113.99 (US/Example/-) has 10 failures *Blocked in csf* [LF_DISTATTACK]
Aug 22 06:00:04 host lfd[104]: 198.51.100.77 (US/Example/-) has 10 failures *Blocked in csf* [LF_SSHD]
EOF

mapfile -t collected < <(collect_lfd_distributed_ips)
[ "${#collected[@]}" -eq 3 ] || fail "collector did not return three unique LF_DISTATTACK sources"
[ "${collected[0]}" = "203.0.113.10" ] || fail "collector did not preserve first-seen order"
[ "${collected[1]}" = "203.0.113.55" ] || fail "collector returned the wrong second source"
[ "${collected[2]}" = "203.0.113.99" ] || fail "collector returned the wrong third source"

cat > "$CSF_DENY_FILE" <<'EOF'
# policy comment
Include /etc/csf/csf.deny.d/external
203.0.113.10 # distributed auth block
203.0.113.10 # duplicate distributed auth block
203.0.113.55 # distributed auth block
203.0.113.99 # protected do not delete
198.51.100.9 # unrelated ban
192.0.2.0/24 # unrelated range
EOF
cat > "$CSF_TEMPIP_FILE" <<'EOF'
203.0.113.10|1|123456|distributed auth
203.0.113.55|1|123457|distributed auth
203.0.113.99|1|123458|protected history
198.51.100.9|1|123459|unrelated history
EOF
cat > "$IP_TRACKING_FILE" <<'EOF'
203.0.113.10 # [2026-08-22 05:59:00] already tracked
EOF
: > "$EVENT_LOG"
: > "$HIGH_SET"
printf '%s\n' 203.0.113.10 203.0.113.55 203.0.113.99 198.51.100.9 192.0.2.0/24 > "$CHAIN_SET"

migration_output=$(perform_migrate_lfd_distributed)

for ip in 203.0.113.10 203.0.113.55 203.0.113.99; do
    grep -Fqx "$ip" "$HIGH_SET" || fail "$ip was not covered by high_volume_bans"
    [ "$(awk -v target="$ip" '$1 == target { count++ } END { print count + 0 }' "$IP_TRACKING_FILE")" -eq 1 ] ||
        fail "$ip was not recorded exactly once in tracking"
done

first_high_add=$(grep -n '^ipset add high_volume_bans 203\.0\.113\.10 -exist$' "$EVENT_LOG" | cut -d: -f1)
first_chain_del=$(grep -n '^ipset del chain_DENY 203\.0\.113\.10 -exist$' "$EVENT_LOG" | cut -d: -f1)
[ -n "$first_high_add" ] && [ -n "$first_chain_del" ] && [ "$first_high_add" -lt "$first_chain_del" ] ||
    fail "high-volume coverage was not installed before CSF coverage was removed"

if grep -qE '^203\.0\.113\.(10|55)[[:space:]]' "$CSF_DENY_FILE"; then
    fail "migrated LF_DISTATTACK entries remain in csf.deny"
fi
if grep -qE '^203\.0\.113\.(10|55)\|' "$CSF_TEMPIP_FILE"; then
    fail "migrated LF_DISTATTACK entries remain in csf.tempip"
fi
grep -q '^203\.0\.113\.99 .*do not delete' "$CSF_DENY_FILE" || fail "protected deny was removed"
grep -q '^203\.0\.113\.99|' "$CSF_TEMPIP_FILE" || fail "protected permanent history was removed"
grep -q '^198\.51\.100\.9 ' "$CSF_DENY_FILE" || fail "unrelated deny was removed"
grep -q '^192\.0\.2\.0/24 ' "$CSF_DENY_FILE" || fail "unrelated CIDR was removed"
grep -q '^Include ' "$CSF_DENY_FILE" || fail "include directive was removed"
grep -q '^198\.51\.100\.9|' "$CSF_TEMPIP_FILE" || fail "unrelated permanent history was removed"

if grep -Fqx '203.0.113.10' "$CHAIN_SET" || grep -Fqx '203.0.113.55' "$CHAIN_SET"; then
    fail "migrated exact entries remain in live chain_DENY"
fi
grep -Fqx '203.0.113.99' "$CHAIN_SET" || fail "protected live deny was removed"
printf '%s\n' "$migration_output" | grep -q 'migrated 3 unique LF_DISTATTACK sources' ||
    fail "migration summary omitted candidate count"
printf '%s\n' "$migration_output" | grep -q 'removed 3 evictable CSF entries' ||
    fail "migration summary omitted removal count"

tracking_before=$(sha256sum "$IP_TRACKING_FILE" | awk '{print $1}')
policy_before=$(sha256sum "$CSF_DENY_FILE" | awk '{print $1}')
perform_migrate_lfd_distributed >/dev/null
[ "$tracking_before" = "$(sha256sum "$IP_TRACKING_FILE" | awk '{print $1}')" ] || fail "second migration duplicated tracking entries"
[ "$policy_before" = "$(sha256sum "$CSF_DENY_FILE" | awk '{print $1}')" ] || fail "second migration changed an idempotent policy"

cat > "$CSF_DENY_FILE" <<'EOF'
203.0.113.10 # distributed auth block
203.0.113.55 # distributed auth block
198.51.100.9 # unrelated ban
EOF
cat > "$CSF_TEMPIP_FILE" <<'EOF'
203.0.113.10|1|123456|distributed auth
203.0.113.55|1|123457|distributed auth
198.51.100.9|1|123459|unrelated history
EOF
cp "$CSF_DENY_FILE" "$sandbox/original.deny"
cp "$CSF_TEMPIP_FILE" "$sandbox/original.tempip"
printf '%s\n' 203.0.113.10 203.0.113.55 198.51.100.9 > "$CHAIN_SET"
: > "$EVENT_LOG"
IPSET_STUB_FAIL_CHILD_DEL=1

set +e
rollback_output=$(perform_migrate_lfd_distributed 2>&1)
rollback_status=$?
set -e
unset IPSET_STUB_FAIL_CHILD_DEL

[ "$rollback_status" -ne 0 ] || fail "forced live-policy failure unexpectedly succeeded"
cmp -s "$sandbox/original.deny" "$CSF_DENY_FILE" || fail "rollback did not restore exact csf.deny"
cmp -s "$sandbox/original.tempip" "$CSF_TEMPIP_FILE" || fail "rollback did not restore exact csf.tempip"
grep -q '^csf -r$' "$EVENT_LOG" || fail "rollback did not rebuild CSF from restored policy"
printf '%s\n' "$rollback_output" | grep -q 'restored the original CSF deny policy' ||
    fail "rollback did not report restoration"

echo "PASS: LF_DISTATTACK migration preserves coverage and CSF policy integrity"
