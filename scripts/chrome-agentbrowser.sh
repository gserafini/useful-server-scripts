#!/bin/bash
# Google Chrome for root-run automation, run as the unprivileged agentbrowser user so
# Chrome's sandbox stays on (server_ops B1926).
#
# Root-run Puppeteer or Playwright scripts set their executablePath to
# /usr/local/bin/chrome-agentbrowser. Chrome cannot be sandboxed as root, so this:
# - drops --no-sandbox and --disable-setuid-sandbox (the sandbox works for agentbrowser);
# - hands the library's per-launch temp profile (/tmp/puppeteer_dev_chrome_profile-* or
#   /tmp/playwright_chromiumdev_profile-*, created by root) to agentbrowser, and refuses
#   any other profile agentbrowser does not own;
# - execs Chrome through setpriv with no capabilities, no way to regain privileges and a
#   clean environment, keeping the pipe file descriptors that --remote-debugging-pipe uses.
#   Prefer the pipe transport (Puppeteer: pipe: true; Playwright's default): a debugging
#   port on 127.0.0.1 can be driven by any local user.
#
# Chrome then reads and writes only what agentbrowser can: send downloads to a directory it
# owns (for example under /var/lib/agentbrowser/downloads) and serve local pages over HTTP.
# Non-root callers get plain Chrome, which already runs sandboxed.
set -euo pipefail

CHROME="${CHROME_AGENTBROWSER_EXEC:-/opt/google/chrome/chrome}"
BROWSER_USER=agentbrowser
BROWSER_HOME=/var/lib/agentbrowser

if [ "$(id -u)" -ne 0 ]; then
    exec "$CHROME" "$@"
fi

hand_over_profile() {
    local dir="$1"
    if [[ "$dir" =~ ^/tmp/(puppeteer_dev_chrome_profile-|playwright_chromiumdev_profile-)[A-Za-z0-9]+$ ]] \
        && [ -d "$dir" ] && [ ! -L "$dir" ] && [ "$(stat -c %u "$dir")" = 0 ]; then
        chown -R -h -P "$BROWSER_USER:$BROWSER_USER" "$dir"
        return 0
    fi
    if [ -d "$dir" ] && [ "$(stat -c %U "$dir")" = "$BROWSER_USER" ]; then
        return 0
    fi
    echo "chrome-agentbrowser: refusing --user-data-dir=$dir: agentbrowser does not own it." \
        "Let the library create its temp profile, or use a directory under $BROWSER_HOME owned by agentbrowser." >&2
    exit 64
}

args=()
for arg in "$@"; do
    case "$arg" in
        --no-sandbox | --disable-setuid-sandbox) continue ;;
        --user-data-dir=*) hand_over_profile "${arg#--user-data-dir=}" ;;
    esac
    args+=("$arg")
done

env_args=("HOME=$BROWSER_HOME" "TMPDIR=$BROWSER_HOME/tmp" "PATH=/usr/bin:/bin" "LANG=${LANG:-C.UTF-8}")
# Settings the automation libraries rely on; never credentials.
for name in DBUS_SESSION_BUS_ADDRESS TZ FONTCONFIG_PATH; do
    if [ -n "${!name:-}" ]; then
        env_args+=("$name=${!name}")
    fi
done

exec /usr/bin/setpriv --reuid="$BROWSER_USER" --regid="$BROWSER_USER" --init-groups \
    --inh-caps=-all --no-new-privs \
    /usr/bin/env -i "${env_args[@]}" "$CHROME" "${args[@]}"
