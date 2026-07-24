#!/bin/bash
set -euo pipefail

SCRIPT="/usr/local/useful-server-scripts/scripts/modsecurity_persistent_blacklist"

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

[ -f "$SCRIPT" ] || fail "missing ModSecurity persistent blacklist adapter"

# shellcheck source=/dev/null
source "$SCRIPT"

sandbox=$(mktemp -d "$PWD/tests/.tmp.modsec-blacklist.XXXXXX")
trap 'rm -rf "$sandbox"' EXIT

cat > "$sandbox/fake-ban-script" <<'EOF'
#!/bin/bash
printf '%s\n' "$*" >> "$MODSEC_TEST_CALLS"
EOF
chmod +x "$sandbox/fake-ban-script"

cat > "$sandbox/fake-sudo" <<'EOF'
#!/bin/bash
exec "$@"
EOF
chmod +x "$sandbox/fake-sudo"

BAN_SCRIPT="$sandbox/fake-ban-script"
SUDO_BIN="$sandbox/fake-sudo"
MODSEC_TEST_CALLS="$sandbox/calls.log"
export MODSEC_TEST_CALLS

unset REMOTE_ADDR
if run_modsecurity_blacklist >"$sandbox/missing.out" 2>&1; then
    fail "missing REMOTE_ADDR was accepted"
fi
grep -q 'REMOTE_ADDR is missing or invalid' "$sandbox/missing.out" ||
    fail "missing REMOTE_ADDR did not report the exact remedy"

REMOTE_ADDR='%{REMOTE_ADDR}'
if run_modsecurity_blacklist >"$sandbox/literal.out" 2>&1; then
    fail "literal ModSecurity macro was accepted as an IP"
fi

REMOTE_ADDR='999.1.2.3'
if run_modsecurity_blacklist >"$sandbox/range.out" 2>&1; then
    fail "out-of-range IPv4 address was accepted"
fi

REMOTE_ADDR='203.0.113.55'
run_modsecurity_blacklist >"$sandbox/success.out"
grep -q '^--blacklist 203\.0\.113\.55 ModSecurity automatic persistent ban$' "$MODSEC_TEST_CALLS" ||
    fail "valid REMOTE_ADDR was not passed to the blacklist CLI"

# Holding the adapter lock must make a concurrent invocation a cheap no-op.
exec 8<"$BAN_SCRIPT"
flock -n 8
before_count=$(wc -l < "$MODSEC_TEST_CALLS")
run_modsecurity_blacklist >"$sandbox/locked.out"
after_count=$(wc -l < "$MODSEC_TEST_CALLS")
[ "$before_count" -eq "$after_count" ] || fail "lock contention invoked the blacklist CLI"
grep -q 'another persistent ban is already running' "$sandbox/locked.out" ||
    fail "lock contention was not reported"

echo "PASS: ModSecurity adapter validates and serializes persistent bans"
