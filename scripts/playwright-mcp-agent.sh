#!/bin/bash
# Playwright MCP server for agent sessions (server_ops B221).
#
# Root agent sessions spawn this over stdio. It drops to the unprivileged agentbrowser
# user before Node starts, so Google Chrome runs with its sandbox on (no --no-sandbox),
# without root's environment, and without any way to regain privileges. setpriv keeps
# the stdio pipes, so the MCP protocol is unaffected. The browser is the RPM-managed
# Google Chrome at /opt/google/chrome (channel "chrome"); the server is the pinned
# shared install in /opt/node/global. Extra MCP flags (for example --caps pdf) pass through.
#
# The browser can read only what agentbrowser can read: open local files over HTTP or a
# webspace URL rather than file:// paths under /root.
set -euo pipefail

MCP_CLI=/opt/node/global/lib/node_modules/@playwright/mcp/cli.js
NODE=/opt/node/24/bin/node
SAFE_PATH=/opt/node/24/bin:/usr/bin:/bin

# Playwright MCP derives a fixed /tmp/pw-<hash> path for its browser socket, so callers that
# share /tmp collide (EACCES). Each identity gets a private TMPDIR instead.
if [ "$(id -u)" -eq 0 ]; then
  exec /usr/bin/setpriv --reuid=agentbrowser --regid=agentbrowser --init-groups \
    --inh-caps=-all --no-new-privs \
    /usr/bin/env -i HOME=/var/lib/agentbrowser TMPDIR=/var/lib/agentbrowser/tmp \
    PATH="$SAFE_PATH" LANG=C.UTF-8 \
    "$NODE" "$MCP_CLI" --headless --isolated --browser chrome --sandbox \
    --output-dir /var/lib/agentbrowser/mcp-output "$@"
fi

# Non-root callers (ClaudeGram tenant runtime users) are already unprivileged, and Chrome
# sandboxes itself for them. Run as the caller with a clean environment.
CALLER_HOME="${HOME:-/tmp}"
CALLER_TMP="$CALLER_HOME/.cache/playwright-mcp/tmp"
mkdir -p -m 700 "$CALLER_TMP"
exec /usr/bin/env -i HOME="$CALLER_HOME" TMPDIR="$CALLER_TMP" PATH="$SAFE_PATH" LANG=C.UTF-8 \
  "$NODE" "$MCP_CLI" --headless --isolated --browser chrome --sandbox "$@"
