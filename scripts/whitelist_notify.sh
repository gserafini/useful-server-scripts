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
} | "$MAIL_BIN" -s "[WhitelistMyIP.com] $IP unblocked for $NAME" "$MAIL_TO"
