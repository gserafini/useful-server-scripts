#!/bin/bash
# Regression tests for scripts/kernel_fix_watch.sh. kcarectl and dnf are stubbed through PATH.
set -uo pipefail

SCRIPT="${SCRIPT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/scripts/kernel_fix_watch.sh}"
# cPanel securetmp mounts /tmp noexec, so the PATH stubs must live inside the checkout.
WORK=$(mktemp -d "$(dirname "${BASH_SOURCE[0]}")/.tmp.kernel-fix-watch.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin"

cat > "$WORK/bin/kcarectl" <<'STUB'
#!/bin/sh
[ -n "${KFW_TEST_KCARE_FAIL:-}" ] && exit 1
# exec, so an early-closing reader gives this process SIGPIPE like the real tool.
[ "$1" = "--patch-info" ] && exec cat "$KFW_TEST_KCARE"
exit 0
STUB
cat > "$WORK/bin/dnf" <<'STUB'
#!/bin/sh
cat "$KFW_TEST_DNF" 2>/dev/null
exit 0
STUB
chmod +x "$WORK/bin/kcarectl" "$WORK/bin/dnf"

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); echo "ok - $1"; }
not_ok() { FAIL=$((FAIL + 1)); echo "not ok - $1"; }

reset_case() {
    rm -rf "$WORK/state" "$WORK/pending"
    : > "$WORK/kcare.txt"
    : > "$WORK/dnf.txt"
}

run_check() {
    PATH="$WORK/bin:$PATH" KFW_STATE_DIR="$WORK/state" KFW_PENDING_DIR="$WORK/pending" \
        KFW_TEST_KCARE="$WORK/kcare.txt" KFW_TEST_DNF="$WORK/dnf.txt" \
        bash "$SCRIPT" "$@"
}

pending_count() { find "$WORK/pending" -maxdepth 1 -name '*.json' 2>/dev/null | wc -l; }
first_pending() { find "$WORK/pending" -maxdepth 1 -name '*.json' 2>/dev/null | head -1; }

# 1. No fix anywhere: quiet success, nothing queued.
reset_case
printf 'kpatch-cve: CVE-2026-11111\n' > "$WORK/kcare.txt"
out=$(run_check --cve CVE-2026-98432 --chat-id -1003657418886); rc=$?
[ "$rc" -eq 0 ] && ok "no fix: exit 0" || not_ok "no fix: exit 0 (got $rc)"
echo "$out" | grep -q 'no fix yet' && ok "no fix: reports no fix yet" || not_ok "no fix: reports no fix yet ($out)"
[ "$(pending_count)" -eq 0 ] && ok "no fix: nothing queued" || not_ok "no fix: nothing queued"

# 2. KernelCare lists the CVE: one wake queued with the right fields, state recorded.
reset_case
printf 'kpatch-name: x.patch\nkpatch-cve: CVE-2026-98432\n' > "$WORK/kcare.txt"
run_check --cve CVE-2026-98432 --chat-id -1003657418886 --note 'Decide on the ipopt_guard stopgap' >/dev/null; rc=$?
[ "$rc" -eq 0 ] && ok "kcare fix: exit 0" || not_ok "kcare fix: exit 0 (got $rc)"
[ "$(pending_count)" -eq 1 ] && ok "kcare fix: one wake queued" || not_ok "kcare fix: one wake queued ($(pending_count))"
f=$(first_pending)
if [ -n "$f" ] && node -e '
    const j = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
    const good = j.chatId === "-1003657418886" && j.delivery === "wake" && Boolean(j.delay) &&
        /CVE-2026-98432/.test(j.message) && /KernelCare/.test(j.message) && /ipopt_guard/.test(j.message);
    process.exit(good ? 0 : 1);' "$f"; then
    ok "kcare fix: wake JSON fields"
else
    not_ok "kcare fix: wake JSON fields"
fi
[ -n "$f" ] && [ "$(stat -c '%a' "$f")" = "600" ] && ok "kcare fix: wake file mode 600" || not_ok "kcare fix: wake file mode 600"
[ -f "$WORK/state/CVE-2026-98432.notified" ] && ok "kcare fix: state recorded" || not_ok "kcare fix: state recorded"
[ -z "$(find "$WORK/pending" -maxdepth 1 -name '.kfw-*' 2>/dev/null)" ] && ok "kcare fix: no temp file left" || not_ok "kcare fix: no temp file left"

# 3. Already notified: no second wake.
out=$(run_check --cve CVE-2026-98432 --chat-id -1003657418886); rc=$?
[ "$rc" -eq 0 ] && [ "$(pending_count)" -eq 1 ] && ok "rerun: no duplicate wake" || not_ok "rerun: no duplicate wake"
echo "$out" | grep -q 'already notified' && ok "rerun: says already notified" || not_ok "rerun: says already notified ($out)"

# 4. Distro errata lists the CVE (no live patch): wake names the advisory.
reset_case
printf 'ALSA-2026:99999 Important/Sec. kernel-4.18.0-553.190.1.el8_10.x86_64\n' > "$WORK/dnf.txt"
run_check --cve CVE-2026-98432 --chat-id -1003657418886 >/dev/null; rc=$?
f=$(first_pending)
if [ "$rc" -eq 0 ] && [ -n "$f" ] && grep -q 'ALSA-2026:99999' "$f"; then
    ok "errata fix: wake names advisory"
else
    not_ok "errata fix: wake names advisory"
fi

# 5. A longer CVE ID that merely starts with ours must not match.
reset_case
printf 'kpatch-cve: CVE-2026-984321\n' > "$WORK/kcare.txt"
run_check --cve CVE-2026-98432 --chat-id -1003657418886 >/dev/null
[ "$(pending_count)" -eq 0 ] && ok "exact match: longer ID ignored" || not_ok "exact match: longer ID ignored"

# 6. A check that cannot run is a visible failure, not a silent "no fix yet".
reset_case
out=$(KFW_TEST_KCARE_FAIL=1 run_check --cve CVE-2026-98432 --chat-id -1003657418886 2>&1); rc=$?
[ "$rc" -eq 3 ] && ok "failed check: exit 3" || not_ok "failed check: exit 3 (got $rc)"
echo "$out" | grep -q 'kcarectl' && ok "failed check: names kcarectl" || not_ok "failed check: names kcarectl ($out)"
[ "$(pending_count)" -eq 0 ] && ok "failed check: nothing queued" || not_ok "failed check: nothing queued"

# 7. Large KernelCare output with an early match still counts (no SIGPIPE false negative).
reset_case
{ printf 'kpatch-cve: CVE-2026-98432\n'; for i in $(seq 1 20000); do printf 'kpatch-cve: CVE-2025-%05d\n' "$i"; done; } > "$WORK/kcare.txt"
run_check --cve CVE-2026-98432 --chat-id -1003657418886 >/dev/null; rc=$?
[ "$rc" -eq 0 ] && [ "$(pending_count)" -eq 1 ] && ok "large output: early match found" || not_ok "large output: early match found (rc $rc, $(pending_count) queued)"

# 8. Bad arguments fail with exit 2.
run_check --cve 'CVE-2026-98432; rm -rf /' --chat-id -1003657418886 >/dev/null 2>&1; rc=$?
[ "$rc" -eq 2 ] && ok "bad CVE rejected" || not_ok "bad CVE rejected (got $rc)"
run_check --cve CVE-2026-98432 >/dev/null 2>&1; rc=$?
[ "$rc" -eq 2 ] && ok "missing chat rejected" || not_ok "missing chat rejected (got $rc)"

echo "# pass $PASS fail $FAIL"
[ "$FAIL" -eq 0 ]
