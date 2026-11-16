#!/bin/bash
set -euo pipefail

SCRIPT="${SCRIPT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/scripts/csf_ban_wp_login_attackers}"
fail() { echo "FAIL: $1" >&2; exit 1; }

# Evaluate only trusted declarations and pure log helpers, never the live CLI.
eval "$(sed -n '/^declare -A keywords$/,/^)/p' "$SCRIPT")"
eval "$(sed -n '/^keyword_rule_pattern() {/,/^}/p' "$SCRIPT")"
eval "$(sed -n '/^scan_log_file_list_for_keyword() {/,/^}/p' "$SCRIPT")"
eval "$(sed -n '/^extract_source_ipv4_from_matched_log_lines() {/,/^}/p' "$SCRIPT")"
rule=''
for key in "${!keywords[@]}"; do
    if [ "${keywords[$key]}" = 'tried to access wp-login' ]; then rule="$key"; fi
done
[ -n "$rule" ] || fail 'missing actual login-volume detector'
[ "${rule%% *}" = 100 ] || fail 'login-volume threshold changed'
pattern=$(keyword_rule_pattern "$rule")

sandbox=$(mktemp -d)
trap 'rm -rf "$sandbox"' EXIT
log="$sandbox/access_log"
for ((i=0; i<113; i++)); do
    printf '%s\n' '198.51.100.40 - - [16/Nov/2026:12:00:00 -0800] "POST /wp-admin/admin-ajax.php HTTP/2" 403 12 "https://example.test/wp-login.php?redirect_to=%2Fwp-admin%2F" "Browser"'
done > "$log"
cat >> "$log" <<'EOF'
198.51.100.41 - - [16/Nov/2026:12:00:01 -0800] "GET /style.css HTTP/2" 200 12 "-" "Browser wp-login/1.0"
198.51.100.42 - - [16/Nov/2026:12:00:02 -0800] "GET /page?next=/wp-login.php HTTP/2" 200 12 "-" "Browser"
198.51.100.50 - - [16/Nov/2026:12:00:03 -0800] "GET /wp-login.php HTTP/2" 200 12 "-" "Browser"
198.51.100.51 - - [16/Nov/2026:12:00:04 -0800] "POST /network/wp-login.php?redirect_to=%2Fwp-admin%2F HTTP/1.1" 302 12 "-" "Browser"
198.51.100.52 - - [16/Nov/2026:12:00:05 -0800] "HEAD /wp-login HTTP/1.1" 200 0 "-" "Browser"
198.51.100.53 - - [16/Nov/2026:12:00:06 -0800] "GET /wp-login.php/ HTTP/1.1" 404 12 "-" "Browser"
198.51.100.54 - - [16/Nov/2026:12:00:07 -0800] "GET /wp-login.css HTTP/1.1" 200 12 "-" "Browser"
198.51.100.55 - - [16/Nov/2026:12:00:08 -0800] "GET /notwp-login.php HTTP/1.1" 200 12 "-" "Browser"
198.51.100.56 - - [16/Nov/2026:12:00:09 -0800] "GET https://example.test/wp-login.php HTTP/1.1" 200 12 "-" "Browser"
198.51.100.57 - - [16/Nov/2026:12:00:10 -0800] "PROPFIND /wp-login.php HTTP/1.1" 405 12 "-" "Browser"
EOF
printf '%s\n' "$log" > "$sandbox/inventory"
ips=$(scan_log_file_list_for_keyword "$pattern" "$sandbox/inventory" | extract_source_ipv4_from_matched_log_lines | sort)
if grep -q '^198\.51\.100\.40$' <<< "$ips"; then
    fail 'ordinary admin-ajax requests with a login referrer count toward the login ban'
fi
expected=$'198.51.100.50\n198.51.100.51\n198.51.100.52\n198.51.100.53\n198.51.100.56\n198.51.100.57'
[ "$ips" = "$expected" ] || fail 'actual login routes or query/referrer/UA boundaries were misclassified'

for ((i=0; i<100; i++)); do
    printf '%s\n' '198.51.100.60 - - [16/Nov/2026:12:00:11 -0800] "POST /wp-login.php HTTP/2" 200 12 "-" "Browser"'
done > "$log"
count=$(scan_log_file_list_for_keyword "$pattern" "$sandbox/inventory" | extract_source_ipv4_from_matched_log_lines | grep -c '^198\.51\.100\.60$')
[ "$count" -eq 100 ] || fail 'real repeated login requests no longer reach the existing threshold'
echo 'PASS: login bans count the requested login path, excluding heartbeat referrers, query values and user agents; real threshold retained'
