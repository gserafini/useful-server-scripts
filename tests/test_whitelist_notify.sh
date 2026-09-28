#!/bin/bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SCRIPT="$ROOT/scripts/whitelist_notify.sh"

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

[ -x "$SCRIPT" ] || fail "missing executable whitelist_notify.sh"

# /tmp is mounted noexec on cPanel hosts, so command mocks must live on the
# repository filesystem in order to exercise the script's real exec paths.
sandbox=$(mktemp -d "$ROOT/.test-whitelist-notify.XXXXXX")
trap 'rm -rf "$sandbox"' EXIT
mkdir -p "$sandbox/bin" "$sandbox/csf"

cat > "$sandbox/csf/csf.deny" <<'EOF'
198.51.100.40 # unrelated deny
EOF

cat > "$sandbox/csf/tracking.log" <<'EOF'
203.0.113.22 # [2026-09-01 12:00:00] csf_ban_wp_login_attackers inserted IP to ipset [Violations: 5, Apache missing-script probe]
EOF

cat > "$sandbox/bin/ipset" <<'EOF'
#!/bin/bash
[ "$1" = "test" ] && [ "$2" = "high_volume_bans" ] && [ "$3" = "203.0.113.22" ]
EOF

cat > "$sandbox/bin/ssh" <<'EOF'
#!/bin/bash
cat <<'REMOTE'
CSF deny: not found
high_volume_bans live: yes
high_volume_bans tracking: [2026-09-01 12:00:00] remote tracked reason
external blocklists: none
REMOTE
EOF

cat > "$sandbox/bin/geoiplookup" <<'EOF'
#!/bin/bash
echo 'GeoIP Country Edition: US, United States'
EOF

cat > "$sandbox/bin/mail" <<'EOF'
#!/bin/bash
cat > "$MAIL_CAPTURE"
printf '%s\n' "$*" > "$MAIL_ARGS_CAPTURE"
EOF

chmod +x "$sandbox/bin/ipset" "$sandbox/bin/ssh" "$sandbox/bin/geoiplookup" "$sandbox/bin/mail"

export MAIL_CAPTURE="$sandbox/mail-body.txt"
export MAIL_ARGS_CAPTURE="$sandbox/mail-args.txt"

CSF_DENY_FILE="$sandbox/csf/csf.deny" \
IP_TRACKING_FILE="$sandbox/csf/tracking.log" \
CSF_BLOCKLIST_GLOB="$sandbox/csf/csf.block.*" \
IPSET_BIN="$sandbox/bin/ipset" \
SSH_BIN="$sandbox/bin/ssh" \
GEOIP_BIN="$sandbox/bin/geoiplookup" \
MAIL_BIN="$sandbox/bin/mail" \
MAIL_TO="owner@example.com" \
"$SCRIPT" "203.0.113.22" "Test Client" "client@example.com" "example.com"

grep -Fq 'high_volume_bans live: yes' "$MAIL_CAPTURE" ||
    fail "live high-volume membership was not reported"
grep -Fq 'Apache missing-script probe' "$MAIL_CAPTURE" ||
    fail "local tracked ban reason was not preserved"
grep -Fq 'remote tracked reason' "$MAIL_CAPTURE" ||
    fail "remote tracked ban reason was not preserved"
grep -Fq 'example.com' "$MAIL_CAPTURE" ||
    fail "request context was not included"

if CSF_DENY_FILE="$sandbox/csf/csf.deny" \
    IP_TRACKING_FILE="$sandbox/csf/tracking.log" \
    IPSET_BIN="$sandbox/bin/ipset" \
    SSH_BIN="$sandbox/bin/ssh" \
    GEOIP_BIN="$sandbox/bin/geoiplookup" \
    MAIL_BIN="$sandbox/bin/mail" \
    "$SCRIPT" "999.1.1.1" "Test" "client@example.com" "example.com" >/dev/null 2>&1; then
    fail "invalid IPv4 address was accepted"
fi

echo "PASS: whitelist notification preserves local and remote high-volume ban evidence"
