#!/bin/bash
# Regression tests for scripts/wake_when_reachable.sh. ssh is stubbed through PATH.
set -uo pipefail

SCRIPT="${SCRIPT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/scripts/wake_when_reachable.sh}"
# cPanel securetmp mounts /tmp noexec, so the PATH stub must live inside the checkout.
WORK=$(mktemp -d "$(dirname "${BASH_SOURCE[0]}")/.tmp.wake-when-reachable.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin"
cat > "$WORK/bin/ssh" <<'STUB'
#!/bin/sh
echo "$*" >> "$WWR_TEST_SSH_LOG"
[ -n "${WWR_TEST_UP:-}" ] && exit 0
exit 255
STUB
chmod +x "$WORK/bin/ssh"

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); echo "ok - $1"; }
not_ok() { FAIL=$((FAIL + 1)); echo "not ok - $1"; }
reset_case() { rm -rf "$WORK/state" "$WORK/pending"; : > "$WORK/ssh.log"; }
run_watch() {
    PATH="$WORK/bin:$PATH" WWR_STATE_DIR="$WORK/state" WWR_PENDING_DIR="$WORK/pending" WWR_TEST_SSH_LOG="$WORK/ssh.log" \
        bash "$SCRIPT" "$@"
}
pending_count() { find "$WORK/pending" -maxdepth 1 -name '*.json' 2>/dev/null | wc -l; }
ARGS=(--target gserafini@100.72.66.60 --key mbp-node --chat-id -1003657418886 --message 'MacBook Pro is back: run the approved Node update')

# 1. Host down: quiet success, nothing queued, no state.
reset_case
out=$(run_watch "${ARGS[@]}"); rc=$?
[ "$rc" -eq 0 ] && ok "down: exit 0" || not_ok "down: exit 0 (got $rc)"
echo "$out" | grep -q 'not reachable' && ok "down: says not reachable" || not_ok "down: says not reachable ($out)"
[ "$(pending_count)" -eq 0 ] && [ ! -e "$WORK/state/mbp-node.queued" ] && ok "down: nothing queued" || not_ok "down: nothing queued"
grep -q 'BatchMode=yes' "$WORK/ssh.log" && grep -q 'ConnectTimeout=' "$WORK/ssh.log" && ok "down: probe is non-interactive with a timeout" || not_ok "down: probe flags ($(cat "$WORK/ssh.log"))"

# 2. Host up: one wake with the message and chat, state recorded, file mode 600.
reset_case
WWR_TEST_UP=1 run_watch "${ARGS[@]}" >/dev/null; rc=$?
f=$(find "$WORK/pending" -maxdepth 1 -name '*.json' | head -1)
[ "$rc" -eq 0 ] && [ "$(pending_count)" -eq 1 ] && ok "up: one wake queued" || not_ok "up: one wake queued (rc $rc, $(pending_count))"
if [ -n "$f" ] && node -e '
    const j = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
    process.exit(j.chatId === "-1003657418886" && j.delivery === "wake" && /approved Node update/.test(j.message) && /100\.72\.66\.60/.test(j.message) ? 0 : 1);' "$f"; then
    ok "up: wake JSON fields"
else
    not_ok "up: wake JSON fields"
fi
[ -n "$f" ] && [ "$(stat -c '%a' "$f")" = "600" ] && ok "up: wake file mode 600" || not_ok "up: wake file mode 600"
[ -f "$WORK/state/mbp-node.queued" ] && ok "up: state recorded" || not_ok "up: state recorded"

# 3. Already queued: no probe, no second wake.
: > "$WORK/ssh.log"
out=$(WWR_TEST_UP=1 run_watch "${ARGS[@]}"); rc=$?
[ "$rc" -eq 0 ] && [ "$(pending_count)" -eq 1 ] && [ ! -s "$WORK/ssh.log" ] && ok "rerun: no probe, no duplicate" || not_ok "rerun: no probe, no duplicate"
echo "$out" | grep -q 'already queued' && ok "rerun: says already queued" || not_ok "rerun: says already queued ($out)"

# 4. Bad arguments fail with exit 2 and never probe.
reset_case
run_watch --target 'gserafini@100.72.66.60; rm -rf /' --key mbp-node --chat-id -1003657418886 --message x >/dev/null 2>&1; rc=$?
[ "$rc" -eq 2 ] && [ ! -s "$WORK/ssh.log" ] && ok "bad target rejected" || not_ok "bad target rejected (got $rc)"
run_watch --target gserafini@100.72.66.60 --key '../evil' --chat-id -1003657418886 --message x >/dev/null 2>&1; rc=$?
[ "$rc" -eq 2 ] && ok "bad key rejected" || not_ok "bad key rejected (got $rc)"
run_watch --target gserafini@100.72.66.60 --key mbp-node --chat-id -1003657418886 >/dev/null 2>&1; rc=$?
[ "$rc" -eq 2 ] && ok "missing message rejected" || not_ok "missing message rejected (got $rc)"

echo "# pass $PASS fail $FAIL"
[ "$FAIL" -eq 0 ]
