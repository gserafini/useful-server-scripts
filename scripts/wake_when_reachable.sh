#!/bin/bash
# wake_when_reachable.sh - queue one ClaudeGram wake the first time an SSH target answers.
#
# Meant for a silent ClaudeGram scheduler job: while the target is down it prints one
# status line and exits 0. When a non-interactive SSH probe succeeds, it writes a wake
# request to the ClaudeGram pending queue once and records that in a state file, so the
# job can keep running without repeating the wake.
#
# Usage:
#   wake_when_reachable.sh --target user@host --key mbp-node --chat-id -1003657418886 --message "what to do"
#
# Environment overrides (tests): WWR_STATE_DIR, WWR_PENDING_DIR, WWR_WAKE_DELAY, WWR_CONNECT_TIMEOUT
set -uo pipefail

STATE_DIR="${WWR_STATE_DIR:-/root/claudegram/state/wake-when-reachable}"
PENDING_DIR="${WWR_PENDING_DIR:-/root/claudegram/pending}"
WAKE_DELAY="${WWR_WAKE_DELAY:-15s}"
CONNECT_TIMEOUT="${WWR_CONNECT_TIMEOUT:-8}"
TARGET=""
KEY=""
CHAT_ID=""
MESSAGE=""

usage() {
    echo "Usage: $(basename "$0") --target user@host --key NAME --chat-id <telegram chat id> --message TEXT" >&2
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --target) TARGET="${2:-}"; shift 2 ;;
        --key) KEY="${2:-}"; shift 2 ;;
        --chat-id) CHAT_ID="${2:-}"; shift 2 ;;
        --message) MESSAGE="${2:-}"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "Unknown argument: $1" >&2; usage ;;
    esac
done

[[ "$TARGET" =~ ^[A-Za-z0-9._-]+@[A-Za-z0-9.:-]+$ ]] || { echo "Invalid or missing --target" >&2; usage; }
[[ "$KEY" =~ ^[A-Za-z0-9._-]+$ && "$KEY" != .* ]] || { echo "Invalid or missing --key" >&2; usage; }
[[ "$CHAT_ID" =~ ^-?[0-9]+$ ]] || { echo "Invalid or missing --chat-id" >&2; usage; }
[ -n "$MESSAGE" ] || { echo "Missing --message" >&2; usage; }

STATE_FILE="$STATE_DIR/$KEY.queued"
if [ -f "$STATE_FILE" ]; then
    echo "$KEY: already queued ($(head -1 "$STATE_FILE"))"
    exit 0
fi

if ! ssh -o BatchMode=yes -o ConnectTimeout="$CONNECT_TIMEOUT" -o StrictHostKeyChecking=yes "$TARGET" true >/dev/null 2>&1; then
    echo "$KEY: $TARGET not reachable yet ($(date -Iseconds))"
    exit 0
fi

mkdir -p "$PENDING_DIR" "$STATE_DIR" || exit 1
TMP=$(mktemp "$PENDING_DIR/.wwr-XXXXXX") || exit 1
if ! TARGET="$TARGET" CHAT_ID="$CHAT_ID" MESSAGE="$MESSAGE" WAKE_DELAY="$WAKE_DELAY" node -e '
        const e = process.env;
        process.stdout.write(JSON.stringify({
            chatId: e.CHAT_ID,
            delay: e.WAKE_DELAY,
            message: `${e.TARGET} is reachable again over SSH.\n\n${e.MESSAGE}`,
            delivery: "wake",
        }, null, 2));' > "$TMP"; then
    rm -f "$TMP"
    echo "Failed to build wake request" >&2
    exit 1
fi
chmod 600 "$TMP"
mv "$TMP" "$PENDING_DIR/wake-when-reachable-$KEY-$(date +%s).json" || { rm -f "$TMP"; exit 1; }
printf '%s | %s reachable\n' "$(date -Iseconds)" "$TARGET" > "$STATE_FILE"
echo "$KEY: $TARGET reachable; queued wake for chat $CHAT_ID"
