#!/bin/bash
# kernel_fix_watch.sh - queue one ClaudeGram wake when a fix for a kernel CVE lands on this host.
#
# Fix sources checked, in order:
#   1. KernelCare live patches already applied (kcarectl --patch-info lists the CVE)
#   2. Distro errata that name the CVE (dnf updateinfo list --all --cve CVE)
#
# Prints one status line and exits 0 when nothing changed, so it can run as a
# silent ClaudeGram scheduler job. When a fix is found it writes a wake request
# to the ClaudeGram pending queue once, and records that in a state file.
#
# Usage:
#   kernel_fix_watch.sh --cve CVE-2026-98432 --chat-id -1003657418886 [--note "next step"]
#
# Environment overrides (tests): KFW_STATE_DIR, KFW_PENDING_DIR, KFW_WAKE_DELAY
set -uo pipefail

STATE_DIR="${KFW_STATE_DIR:-/root/claudegram/state/kernel-fix-watch}"
PENDING_DIR="${KFW_PENDING_DIR:-/root/claudegram/pending}"
WAKE_DELAY="${KFW_WAKE_DELAY:-15s}"
CVE=""
CHAT_ID=""
NOTE=""

usage() {
    echo "Usage: $(basename "$0") --cve CVE-YYYY-NNNN --chat-id <telegram chat id> [--note TEXT]" >&2
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --cve) CVE="${2:-}"; shift 2 ;;
        --chat-id) CHAT_ID="${2:-}"; shift 2 ;;
        --note) NOTE="${2:-}"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "Unknown argument: $1" >&2; usage ;;
    esac
done

[[ "$CVE" =~ ^CVE-[0-9]{4}-[0-9]{4,}$ ]] || { echo "Invalid or missing --cve" >&2; usage; }
[[ "$CHAT_ID" =~ ^-?[0-9]+$ ]] || { echo "Invalid or missing --chat-id" >&2; usage; }

STATE_FILE="$STATE_DIR/$CVE.notified"
if [ -f "$STATE_FILE" ]; then
    echo "$CVE: already notified ($(head -1 "$STATE_FILE"))"
    exit 0
fi

FOUND=""
CHECK_ERRORS=""
# Capture each tool's full output before matching: piping into grep -q lets grep
# exit early, the writer dies of SIGPIPE, and pipefail turns a match into a miss.
if command -v kcarectl >/dev/null 2>&1; then
    KC_OUT=$(kcarectl --patch-info 2>/dev/null)
    KC_RC=$?
    if [ "$KC_RC" -ne 0 ]; then
        CHECK_ERRORS="${CHECK_ERRORS}kcarectl --patch-info exited $KC_RC; "
    elif grep -qE "^kpatch-cve:.*(^|[^0-9A-Za-z-])${CVE}([^0-9]|$)" <<< "$KC_OUT"; then
        FOUND="KernelCare live patch applied: kcarectl --patch-info lists $CVE"
    fi
fi

if [ -z "$FOUND" ] && command -v dnf >/dev/null 2>&1; then
    DNF_OUT=$(dnf -q updateinfo list --all --cve "$CVE" 2>/dev/null)
    DNF_RC=$?
    if [ "$DNF_RC" -ne 0 ]; then
        CHECK_ERRORS="${CHECK_ERRORS}dnf updateinfo exited $DNF_RC; "
    else
        ADVISORIES=$(grep -oE '\b[A-Z]{2,5}-[0-9]{4}:[0-9]+\b' <<< "$DNF_OUT" | sort -u | tr '\n' ' ')
        ADVISORIES="${ADVISORIES% }"
        if [ -n "$ADVISORIES" ]; then
            FOUND="Distro errata available: $ADVISORIES (dnf updateinfo list --all --cve $CVE)"
        fi
    fi
fi

if [ -z "$FOUND" ]; then
    if [ -n "$CHECK_ERRORS" ]; then
        echo "$CVE: no fix found, but a check could not run on $(hostname -s): ${CHECK_ERRORS% }" >&2
        exit 3
    fi
    echo "$CVE: no fix yet on $(hostname -s) (KernelCare and dnf errata checked $(date -Iseconds))"
    exit 0
fi

mkdir -p "$PENDING_DIR" "$STATE_DIR" || exit 1
TMP=$(mktemp "$PENDING_DIR/.kfw-XXXXXX") || exit 1
if ! CVE="$CVE" CHAT_ID="$CHAT_ID" FOUND="$FOUND" NOTE="$NOTE" WAKE_DELAY="$WAKE_DELAY" \
    HOST="$(hostname -s)" KERNEL="$(uname -r)" node -e '
        const e = process.env;
        const lines = [
            `Kernel fix watch: a fix for ${e.CVE} is now available on ${e.HOST}.`,
            "",
            `Evidence: ${e.FOUND}`,
            `Running kernel: ${e.KERNEL}`,
            "",
            "Verify the fix directly, update the pm item, tell Gabriel in one short message, and remove this watcher job.",
        ];
        if (e.NOTE) lines.push(`Follow-up: ${e.NOTE}`);
        process.stdout.write(JSON.stringify({
            chatId: e.CHAT_ID, delay: e.WAKE_DELAY, message: lines.join("\n"), delivery: "wake",
        }, null, 2));' > "$TMP"; then
    rm -f "$TMP"
    echo "Failed to build wake request" >&2
    exit 1
fi
chmod 600 "$TMP"
mv "$TMP" "$PENDING_DIR/kernel-fix-$CVE-$(date +%s).json" || { rm -f "$TMP"; exit 1; }
printf '%s | %s\n' "$(date -Iseconds)" "$FOUND" > "$STATE_FILE"
echo "$CVE: FOUND ($FOUND); queued wake for chat $CHAT_ID"
