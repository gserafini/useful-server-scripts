#!/bin/bash
# Regression guard for scripts/playwright-mcp-agent.sh (server_ops B221): agent sessions
# must get sandboxed Chrome, never root Chrome with --no-sandbox.
set -euo pipefail
SCRIPT="${SCRIPT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/scripts/playwright-mcp-agent.sh}"
fail() { echo "FAIL: $1" >&2; exit 1; }
bash -n "$SCRIPT" || fail "syntax"
# Check code only; the header comment explains why --no-sandbox is never used.
CODE=$(grep -v '^[[:space:]]*#' "$SCRIPT")
grep -q -- '--reuid=agentbrowser' <<<"$CODE" || fail "root sessions must drop to agentbrowser"
grep -q -- '--no-new-privs' <<<"$CODE" || fail "privilege drop must forbid regaining privileges"
grep -q -- '--inh-caps=-all' <<<"$CODE" || fail "inherited capabilities must be cleared"
[ "$(grep -c -- '--sandbox' <<<"$CODE")" -ge 2 ] || fail "both root and non-root paths must pass --sandbox"
grep -q -- '--no-sandbox' <<<"$CODE" && fail "--no-sandbox must never be passed"
grep -q 'env -i' <<<"$CODE" || fail "root environment must not leak into the MCP server"
grep -q 'TMPDIR=' <<<"$CODE" || fail "each identity needs a private TMPDIR"
echo "PASS: playwright-mcp-agent"
