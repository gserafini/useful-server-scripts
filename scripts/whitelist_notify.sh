#!/bin/bash
set -u

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

CSF_DENY_FILE="${CSF_DENY_FILE:-/etc/csf/csf.deny}"
IP_TRACKING_FILE="${IP_TRACKING_FILE:-/etc/csf/ipset_tracking_high_volume_bans.log}"
CSF_BLOCKLIST_GLOB="${CSF_BLOCKLIST_GLOB:-/var/lib/csf/csf.block.*}"
IP_SET_NAME="${IP_SET_NAME:-high_volume_bans}"
IPSET_BIN="${IPSET_BIN:-ipset}"
SSH_BIN="${SSH_BIN:-ssh}"
GEOIP_BIN="${GEOIP_BIN:-geoiplookup}"
MAIL_BIN="${MAIL_BIN:-/bin/mail}"
MAIL_TO="${MAIL_TO:-gserafini@gmail.com}"
REMOTE_TARGET="${REMOTE_TARGET:-root@dc3-1.serafinihosting.com}"
REMOTE_PORT="${REMOTE_PORT:-22022}"
WAKE_SSH_BIN="${WAKE_SSH_BIN:-$SSH_BIN}"
WAKE_TARGET="${WAKE_TARGET:-$REMOTE_TARGET}"
WAKE_PORT="${WAKE_PORT:-$REMOTE_PORT}"
WAKE_CHAT_ID="${WAKE_CHAT_ID:--5190961854}"
WAKE_DELAY="${WAKE_DELAY:-10s}"
WAKE_STATE_DIR="${WAKE_STATE_DIR:-/var/run/whitelist-notify}"
WAKE_DEDUPE_SECONDS="${WAKE_DEDUPE_SECONDS:-600}"
WAKE_ENABLED="${WAKE_ENABLED:-1}"
FLOCK_BIN="${FLOCK_BIN:-flock}"

validate_ipv4() {
    local ip=$1
    local IFS='.'
    local octets=()
    local octet

    [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
    read -r -a octets <<< "$ip"
    [ "${#octets[@]}" -eq 4 ] || return 1
    for octet in "${octets[@]}"; do
        [ "$((10#$octet))" -le 255 ] || return 1
    done
}

sanitize_line() {
    printf '%s' "$1" | tr '\r\n' '  '
}

exact_reason() {
    local file=$1
    local ip=$2

    awk -v target="$ip" '
        $1 == target {
            line = $0
            sub(/^[^#]*#[[:space:]]*/, "", line)
            print line
            exit
        }
    ' "$file" 2>/dev/null
}

queue_claudegram_wake() {
    local message=$1
    local encoded
    local lock_file
    local now
    local previous=0
    local state_file
    local state_tmp

    [ "$WAKE_ENABLED" = "1" ] || return 0

    if ! [[ $WAKE_CHAT_ID =~ ^-?[0-9]+$ ]]; then
        echo "Warning: Invalid ClaudeGram wake chat ID: $WAKE_CHAT_ID" >&2
        return 1
    fi
    if ! [[ $WAKE_DELAY =~ ^[0-9]+[smhd]$ ]]; then
        echo "Warning: Invalid ClaudeGram wake delay: $WAKE_DELAY" >&2
        return 1
    fi
    if ! [[ $WAKE_DEDUPE_SECONDS =~ ^[0-9]+$ ]]; then
        echo "Warning: Invalid wake dedupe interval: $WAKE_DEDUPE_SECONDS" >&2
        return 1
    fi
    if ! mkdir -p "$WAKE_STATE_DIR"; then
        echo "Warning: Could not create wake state directory: $WAKE_STATE_DIR" >&2
        return 1
    fi

    lock_file="$WAKE_STATE_DIR/.lock"
    exec 9>"$lock_file" || {
        echo "Warning: Could not open wake lock: $lock_file" >&2
        return 1
    }
    if command -v "$FLOCK_BIN" >/dev/null 2>&1; then
        "$FLOCK_BIN" -x 9 || {
            echo "Warning: Could not acquire wake lock: $lock_file" >&2
            return 1
        }
    fi

    state_file="$WAKE_STATE_DIR/$IP"
    now=$(date +%s)
    if [ -f "$state_file" ]; then
        read -r previous < "$state_file" || previous=0
    fi
    if [[ $previous =~ ^[0-9]+$ ]] &&
        [ "$WAKE_DEDUPE_SECONDS" -gt 0 ] &&
        [ "$((now - previous))" -lt "$WAKE_DEDUPE_SECONDS" ]; then
        echo "ClaudeGram wake suppressed for duplicate whitelist request: $IP" >&2
        return 0
    fi

    encoded=$(printf '%s' "$message" | base64 | tr -d '\n')
    if ! "$WAKE_SSH_BIN" -p "$WAKE_PORT" "$WAKE_TARGET" bash -s -- \
        "$encoded" "$WAKE_CHAT_ID" "$WAKE_DELAY" <<'REMOTE_WAKE'
set -euo pipefail

encoded=$1
chat_id=$2
delay=$3
pending_dir=/root/claudegram/pending
filename="whitelist-$(date +%s)-$$.json"
temp_path="$pending_dir/.${filename}.tmp"
final_path="$pending_dir/$filename"
node_bin=$(command -v node)

mkdir -p "$pending_dir"
WAKE_MESSAGE_B64="$encoded" WAKE_CHAT_ID="$chat_id" WAKE_DELAY="$delay" \
    "$node_bin" - "$temp_path" "$final_path" <<'NODE'
const fs = require('fs');
const tempPath = process.argv[2];
const finalPath = process.argv[3];
const payload = {
  chatId: process.env.WAKE_CHAT_ID,
  delay: process.env.WAKE_DELAY,
  message: Buffer.from(process.env.WAKE_MESSAGE_B64, 'base64').toString('utf8'),
};
fs.writeFileSync(tempPath, JSON.stringify(payload, null, 2), { mode: 0o600 });
fs.renameSync(tempPath, finalPath);
NODE
REMOTE_WAKE
    then
        echo "Warning: Could not queue ClaudeGram whitelist investigation for $IP" >&2
        return 1
    fi

    state_tmp="${state_file}.tmp.$$"
    if printf '%s\n' "$now" > "$state_tmp"; then
        mv -f "$state_tmp" "$state_file"
    else
        rm -f "$state_tmp"
        echo "Warning: ClaudeGram wake queued but dedupe state could not be saved for $IP" >&2
    fi
}

IP="${1:-}"
NAME=$(sanitize_line "${2:-Unknown}")
EMAIL=$(sanitize_line "${3:-Unknown}")
WEBSITE=$(sanitize_line "${4:-Unknown}")

if ! validate_ipv4 "$IP"; then
    echo "Error: Invalid IPv4 address: $IP" >&2
    exit 2
fi

LOCAL_CSF_REASON=$(exact_reason "$CSF_DENY_FILE" "$IP")
LOCAL_TRACKING_REASON=$(exact_reason "$IP_TRACKING_FILE" "$IP")
LOCAL_HIGH_VOLUME_LIVE="no"
if command -v "$IPSET_BIN" >/dev/null 2>&1 &&
    "$IPSET_BIN" test "$IP_SET_NAME" "$IP" >/dev/null 2>&1; then
    LOCAL_HIGH_VOLUME_LIVE="yes"
fi

LOCAL_BLOCKLISTS=""
shopt -s nullglob
for list in $CSF_BLOCKLIST_GLOB; do
    if [ -f "$list" ] && awk -v target="$IP" '$1 == target { found=1; exit } END { exit !found }' "$list"; then
        if [ -n "$LOCAL_BLOCKLISTS" ]; then
            LOCAL_BLOCKLISTS="$LOCAL_BLOCKLISTS, "
        fi
        LOCAL_BLOCKLISTS="${LOCAL_BLOCKLISTS}$(basename "$list")"
    fi
done
shopt -u nullglob

REMOTE_EVIDENCE=""
if ! REMOTE_EVIDENCE=$("$SSH_BIN" -p "$REMOTE_PORT" "$REMOTE_TARGET" bash -s -- "$IP" <<'REMOTE'
IP="$1"

exact_reason() {
    awk -v target="$2" '
        $1 == target {
            line = $0
            sub(/^[^#]*#[[:space:]]*/, "", line)
            print line
            exit
        }
    ' "$1" 2>/dev/null
}

deny_reason=$(exact_reason /etc/csf/csf.deny "$IP")
tracking_reason=$(exact_reason /etc/csf/ipset_tracking_high_volume_bans.log "$IP")
high_volume_live="no"
if command -v ipset >/dev/null 2>&1 && ipset test high_volume_bans "$IP" >/dev/null 2>&1; then
    high_volume_live="yes"
fi

blocklists=""
for list in /var/lib/csf/csf.block.*; do
    [ -f "$list" ] || continue
    if awk -v target="$IP" '$1 == target { found=1; exit } END { exit !found }' "$list"; then
        [ -z "$blocklists" ] || blocklists="$blocklists, "
        blocklists="${blocklists}$(basename "$list")"
    fi
done

printf 'CSF deny: %s\n' "${deny_reason:-not found}"
printf 'high_volume_bans live: %s\n' "$high_volume_live"
printf 'high_volume_bans tracking: %s\n' "${tracking_reason:-not found}"
printf 'external blocklists: %s\n' "${blocklists:-none}"
REMOTE
); then
    REMOTE_EVIDENCE="remote evidence unavailable"
fi

GEOIP="Unknown"
if command -v "$GEOIP_BIN" >/dev/null 2>&1; then
    GEOIP=$("$GEOIP_BIN" "$IP" 2>/dev/null | sed 's/GeoIP Country Edition: //' | head -1)
    GEOIP=${GEOIP:-Unknown}
fi

MAIL_STATUS=0
{
    printf 'WhitelistMyIP.com Request\n'
    printf '============================\n\n'
    printf 'Name: %s\n' "$NAME"
    printf 'Email: %s\n' "$EMAIL"
    printf 'Website: %s\n' "$WEBSITE"
    printf 'IP: %s\n' "$IP"
    printf 'GeoIP: %s\n\n' "$GEOIP"
    printf 'BLOCK EVIDENCE CAPTURED AT REQUEST TIME\n'
    printf '%s\n' '---------------------------------------'
    printf 'dc2-5 CSF deny: %s\n' "${LOCAL_CSF_REASON:-not found}"
    printf 'dc2-5 high_volume_bans live: %s\n' "$LOCAL_HIGH_VOLUME_LIVE"
    printf 'dc2-5 high_volume_bans tracking: %s\n' "${LOCAL_TRACKING_REASON:-not found}"
    printf 'dc2-5 external blocklists: %s\n' "${LOCAL_BLOCKLISTS:-none}"
    printf '%s\n' "$REMOTE_EVIDENCE"
    printf '%s\n\n' '---------------------------------------'
    printf 'IP has been allowlisted on both servers.\n'
} | "$MAIL_BIN" -s "[WhitelistMyIP.com] $IP unblocked for $NAME" "$MAIL_TO" || MAIL_STATUS=$?

WAKE_MESSAGE=$(printf '%s\n' \
    '[WhitelistMyIP client request]' \
    "Client: $NAME" \
    "Website: $WEBSITE" \
    "IP: $IP" \
    "GeoIP: $GEOIP" \
    '' \
    'Block evidence captured before allowlist reconciliation:' \
    "dc2-5 CSF deny: ${LOCAL_CSF_REASON:-not found}" \
    "dc2-5 high_volume_bans live: $LOCAL_HIGH_VOLUME_LIVE" \
    "dc2-5 high_volume_bans tracking: ${LOCAL_TRACKING_REASON:-not found}" \
    "dc2-5 external blocklists: ${LOCAL_BLOCKLISTS:-none}" \
    "$REMOTE_EVIDENCE" \
    '' \
    'Investigate why this IP was blocked. Correlate the preserved reason with bounded current or rotated logs on the correct origin. Classify hostile activity versus a false positive. If it is a false positive, fix the underlying detector safely and verify the regression. Confirm the IP is allowlisted on both servers, absent from deny sets, and that the client site is healthy. Reply in this ops chat with a concise evidence-backed report. Do not expose the client email address or secret query parameters.')

WAKE_STATUS=0
queue_claudegram_wake "$WAKE_MESSAGE" || WAKE_STATUS=$?

if [ "$MAIL_STATUS" -ne 0 ] && [ "$WAKE_STATUS" -ne 0 ]; then
    echo "Error: Both email and ClaudeGram whitelist notifications failed for $IP" >&2
    exit 1
fi

exit 0
