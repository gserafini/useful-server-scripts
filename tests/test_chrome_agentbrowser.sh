#!/bin/bash
# Tests for scripts/chrome-agentbrowser.sh (server_ops B1926). Run as root.
set -euo pipefail

SCRIPT="${SCRIPT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/scripts/chrome-agentbrowser.sh}"

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

[ "$(id -u)" -eq 0 ] || fail "run as root"
id agentbrowser >/dev/null 2>&1 || fail "agentbrowser user missing"

# The stub stands in for Chrome. It must be executable by agentbrowser, and /tmp is
# mounted noexec, so it lives in agentbrowser's home.
WORK=$(mktemp -d /var/lib/agentbrowser/tmp/test-chrome-agentbrowser.XXXXXX)
PROFILE=""
cleanup() { rm -rf "$WORK" ${PROFILE:+"$PROFILE"}; }
trap cleanup EXIT
chmod 755 "$WORK"
cat > "$WORK/chrome" <<'STUB'
#!/bin/bash
echo "uid=$(id -un)"
echo "home=${HOME:-}"
echo "tmpdir=${TMPDIR:-}"
echo "dbus=${DBUS_SESSION_BUS_ADDRESS:-unset}"
echo "secret=${CHROME_AGENTBROWSER_TEST_SECRET:-unset}"
for arg in "$@"; do
    echo "arg=$arg"
    case "$arg" in
        --user-data-dir=*) touch "${arg#--user-data-dir=}/written" && echo "profile=writable" ;;
    esac
done
if { true >&3; } 2>/dev/null; then echo "pipe-fd-ok" >&3; fi
STUB
chmod 755 "$WORK/chrome"

run() { CHROME_AGENTBROWSER_EXEC="$WORK/chrome" "$SCRIPT" "$@"; }

# 1. Root callers run Chrome as agentbrowser with a clean environment.
out=$(CHROME_AGENTBROWSER_TEST_SECRET=root-only DBUS_SESSION_BUS_ADDRESS=disabled: run --headless=new)
grep -qx 'uid=agentbrowser' <<<"$out" || fail "Chrome did not run as agentbrowser: $out"
grep -qx 'home=/var/lib/agentbrowser' <<<"$out" || fail "HOME not set to agentbrowser's home"
grep -qx 'tmpdir=/var/lib/agentbrowser/tmp' <<<"$out" || fail "TMPDIR not private"
grep -qx 'secret=unset' <<<"$out" || fail "root environment leaked into Chrome"
grep -qx 'dbus=disabled:' <<<"$out" || fail "DBUS_SESSION_BUS_ADDRESS was not passed through"

# 2. Sandbox-off flags are dropped; other flags pass through unchanged.
out=$(run --no-sandbox --disable-setuid-sandbox --headless=new --remote-debugging-pipe)
grep -q -- 'arg=--no-sandbox' <<<"$out" && fail "--no-sandbox reached Chrome"
grep -q -- 'arg=--disable-setuid-sandbox' <<<"$out" && fail "--disable-setuid-sandbox reached Chrome"
grep -qx -- 'arg=--remote-debugging-pipe' <<<"$out" || fail "ordinary flags must pass through"

# 3. The library's root-created temp profile is handed to agentbrowser.
PROFILE=$(mktemp -d /tmp/playwright_chromiumdev_profile-XXXXXX)
out=$(run "--user-data-dir=$PROFILE")
grep -qx 'profile=writable' <<<"$out" || fail "temp profile not writable by agentbrowser: $out"
[ "$(stat -c %U "$PROFILE")" = agentbrowser ] || fail "temp profile not owned by agentbrowser"
rm -rf "$PROFILE"; PROFILE=""

# 3b. Lighthouse's chrome-launcher names its temp profile /tmp/lighthouse.XXXXXX.
PROFILE=$(mktemp -d /tmp/lighthouse.XXXXXX)
out=$(run "--user-data-dir=$PROFILE")
grep -qx 'profile=writable' <<<"$out" || fail "chrome-launcher temp profile not handed to agentbrowser: $out"
rm -rf "$PROFILE"; PROFILE=""

# 4. Any other root-owned profile is refused with the remedy.
set +e
err=$(run "--user-data-dir=$WORK/../" 2>&1 >/dev/null); rc=$?
err2=$(run "--user-data-dir=/root" 2>&1 >/dev/null); rc2=$?
set -e
[ "$rc2" -eq 64 ] || fail "a root-owned profile outside the library temp pattern was accepted (rc=$rc2)"
grep -q 'agentbrowser does not own it' <<<"$err2" || fail "refusal must explain the remedy: $err2"
[ "$rc" -eq 0 ] || fail "a profile agentbrowser owns must be accepted (rc=$rc): $err"

# 5. The library's pipe file descriptors survive the privilege drop.
PIPE_OUT="$WORK/fd3"
run --remote-debugging-pipe 3>"$PIPE_OUT" >/dev/null
grep -qx 'pipe-fd-ok' "$PIPE_OUT" || fail "fd 3 (remote-debugging-pipe) did not reach Chrome"

# 6. Non-root callers get Chrome directly, arguments untouched.
out=$(setpriv --reuid=agentbrowser --regid=agentbrowser --init-groups \
    env CHROME_AGENTBROWSER_EXEC="$WORK/chrome" "$SCRIPT" --no-sandbox)
grep -qx 'uid=agentbrowser' <<<"$out" || fail "non-root passthrough changed user"
grep -qx -- 'arg=--no-sandbox' <<<"$out" || fail "non-root passthrough must not rewrite arguments"

echo "PASS: chrome-agentbrowser"
