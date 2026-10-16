#!/bin/bash
# Extract only the policy builder: never source or execute firewall operations.
set -euo pipefail
SCRIPT="${SCRIPT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/scripts/csf_ban_wp_login_attackers}"
sandbox=$(mktemp -d)
trap 'rm -rf "$sandbox"' EXIT
eval "$(sed -n '/^build_protected_ipv4_file() {/,/^}/p' "$SCRIPT")"
ip() { printf '%s\n' '2: eth0 inet 10.20.30.40/24 scope global eth0'; }
CSF_ALLOW_FILE="$sandbox/csf.allow"
CSF_IGNORE_FILE="$sandbox/csf.ignore"
output="$sandbox/policy"
passed=0 failed=0
check() {
    if "$@"; then
        passed=$((passed + 1))
    else
        printf 'FAIL: %s\n' "$name" >&2
        failed=$((failed + 1))
    fi
}
reset_policy() { : > "$CSF_ALLOW_FILE"; : > "$CSF_IGNORE_FILE"; : > "$output"; }
expect_policy() {
    local expected="$sandbox/expected"
    printf '%s\n' 127.0.0.1 10.20.30.40 "$@" | sort -u > "$expected"
    build_protected_ipv4_file "$output" 2> "$sandbox/error" && cmp -s "$expected" "$output"
}
expect_failure() {
    local status=0
    printf 'existing sentinel\n' > "$output"
    build_protected_ipv4_file "$output" 2> "$sandbox/error" || status=$?
    [ "$status" -ne 0 ] && [ "$(cat "$output")" = 'existing sentinel' ] || return 1
    : > "$output"
    status=0
    build_protected_ipv4_file "$output" 2> "$sandbox/error" || status=$?
    [ "$status" -ne 0 ] && [ ! -s "$output" ] || return 1
    rm -f "$output"
    status=0
    build_protected_ipv4_file "$output" 2> "$sandbox/error" || status=$?
    [ "$status" -ne 0 ] && [ ! -e "$output" ]
}
reset_policy
printf '%s\n' '192.0.2.7 # exact' '198.51.100.0/024' > "$CSF_ALLOW_FILE"
printf '%s\n' '203.0.113.0/0' '198.51.100.0/024' > "$CSF_IGNORE_FILE"
name='existing exact/CIDR, /0 and dedup'; check expect_policy 192.0.2.7 198.51.100.0/24 203.0.113.0/0

reset_policy
mkdir -p "$sandbox/includes/nested"
printf 'Include %s\nInclude %s\n' "$sandbox/includes/first" "$sandbox/includes/first" > "$CSF_ALLOW_FILE"
printf '192.0.2.11\nInclude nested/second\n' > "$sandbox/includes/first"
printf '198.51.100.0/24\nInclude ../../third\n' > "$sandbox/includes/nested/second"
printf '203.0.113.19\n' > "$sandbox/third"
name='absolute, relative nested Includes and duplicate inclusion'; check expect_policy 192.0.2.11 198.51.100.0/24 203.0.113.19

reset_policy
printf 'Include %s\n' "$sandbox/third" > "$CSF_IGNORE_FILE"
name='Include from ignore root'; check expect_policy 203.0.113.19

reset_policy
cat > "$CSF_ALLOW_FILE" <<'RULES'
tcp|in|d=3306|s=192.0.2.11
tcp|out|d=22|d=198.51.100.0/24
s=203.0.113.12|d=80
d=203.0.113.13|s=25|u=99
s=192.0.2.0/0|d=25
RULES
name='numeric s=/d= operands in every field'; check expect_policy 192.0.2.11 198.51.100.0/24 203.0.113.12 203.0.113.13 192.0.2.0/0

reset_policy
printf 's=192.0.2.21\nd=198.51.100.0/24\n' > "$CSF_ALLOW_FILE"
name='standalone s=/d= operands conservatively protected'; check expect_policy 192.0.2.21 198.51.100.0/24

reset_policy
printf 's=192.0.2.21/33\n' > "$CSF_ALLOW_FILE"
name='malformed standalone operand fails without partial output'; check expect_failure

reset_policy
literal_dollar='$(touch${IFS}policy-evaluated)'
literal_backtick='`touch${IFS}backtick-evaluated`'
printf 'Include %s/%s\nInclude %s/%s\n' "$sandbox" "$literal_dollar" "$sandbox" "$literal_backtick" > "$CSF_ALLOW_FILE"
printf '192.0.2.22\n' > "$sandbox/$literal_dollar"
printf '198.51.100.22\n' > "$sandbox/$literal_backtick"
expect_literal_paths() {
    (cd "$sandbox" && expect_policy 192.0.2.22 198.51.100.22) &&
        [ ! -e "$sandbox/policy-evaluated" ] && [ ! -e "$sandbox/backtick-evaluated" ]
}
name='literal Include paths never execute dollar or backtick substitutions'; check expect_literal_paths

reset_policy
cat > "$CSF_ALLOW_FILE" <<'RULES'
# Include /does/not/exist
 # s=192.0.2.100
192.0.2.7 # 203.0.113.99 d=198.51.100.99
tcp|in|d=25|s=443
s=1_65535|d=22,80,443|u=198.51.100.66|g=203.0.113.66
u=192.0.2.77|d=80
s=ping|d=80
RULES
name='comments, numeric ports, ranges, lists and IP-looking owner fields ignored'; check expect_policy 192.0.2.7

reset_policy
cat > "$CSF_ALLOW_FILE" <<'RULES'
2001:db8::1
::ffff:192.0.2.99/128
tcp|in|d=22|s=::ffff:192.0.2.88
tcp|out|d=::/0|s=80
trusted.example.test
s=trusted.example.test|d=80
198.51.example.test
RULES
name='IPv6 and hostnames ignored without DNS'; check expect_policy

for bad in '999.1.2.3' '192.0.2.1/33' '192.0.2.1/-1' '192.0.2.1/nope' '192.0.2.1/' '192.0.2.1/24/4' 'tcp|in|s=999.1.2.3|d=80' 'd=192.0.2.1/33|s=25' '192.0.2' '192/24' 's=192/24|d=80'; do
    reset_policy
    printf '203.0.113.7\n%s\n' "$bad" > "$CSF_ALLOW_FILE"
    name="invalid numeric policy fails without partial output: $bad"; check expect_failure
done

reset_policy
printf '192.0.2.1\nInclude %s\n' "$sandbox/missing" > "$CSF_ALLOW_FILE"
name='missing include fails without partial output'; check expect_failure

reset_policy
rm "$CSF_IGNORE_FILE"
name='missing root fails without partial output'; check expect_failure

reset_policy
printf 'Include %s\n' "$sandbox" > "$CSF_ALLOW_FILE"
name='directory include fails without partial output'; check expect_failure

reset_policy
printf '192.0.2.1\nInclude %s\n' "$sandbox/includes/first" > "$CSF_ALLOW_FILE"
printf 'Include ../csf.allow\n' > "$sandbox/includes/first"
name='recursive include cycle fails without partial output'; check expect_failure

reset_policy
ln -s "$CSF_ALLOW_FILE" "$sandbox/alias"
printf 'Include %s\n' "$sandbox/alias" > "$CSF_ALLOW_FILE"
name='symlink include cycle fails without partial output'; check expect_failure

reset_policy
printf 'Include %s # invalid CSF include comment\n' "$sandbox/third" > "$CSF_ALLOW_FILE"
name='documented invalid Include trailing comment rejected'; check expect_failure

reset_policy
printf 'Include\n' > "$CSF_ALLOW_FILE"
name='empty Include rejected'; check expect_failure

reset_policy
printf 'Include %s\n' "$sandbox/unreadable" > "$CSF_ALLOW_FILE"
printf '192.0.2.17\n' > "$sandbox/unreadable"
chmod 000 "$sandbox/unreadable"
expect_unreadable_failure() {
    if [ "$(id -u)" -eq 0 ]; then
        # Root bypasses chmod; verify the actual unreadable-file path as nobody.
        command -v su >/dev/null || return 1
        local unprivileged_command
        chmod 755 "$sandbox"
        mkdir -m 777 "$sandbox/unprivileged"
        sed -n '/^build_protected_ipv4_file() {/,/^}/p' "$SCRIPT" > "$sandbox/builder.sh"
        chmod 644 "$sandbox/builder.sh"
        # Legacy dc2-5 runuser has no -u option; su -s/-c works on both hosts.
        # Bash printf %q quotes every argument before su starts its command shell.
        printf -v unprivileged_command '%q ' bash -c '
            source "$1"
            CSF_ALLOW_FILE="$2" CSF_IGNORE_FILE="$3"
            ip() { echo "2: eth0 inet 10.20.30.40/24 scope global eth0"; }
            printf "sentinel\n" > "$4"
            if build_protected_ipv4_file "$4"; then exit 1; fi
            [ "$(cat "$4")" = sentinel ]
        ' _ "$sandbox/builder.sh" "$CSF_ALLOW_FILE" "$CSF_IGNORE_FILE" "$sandbox/unprivileged/output"
        su -s /bin/bash nobody -c "$unprivileged_command" 2> "$sandbox/error"
    else
        expect_failure
    fi
}
name='unreadable Include rejected without partial output'; check expect_unreadable_failure
chmod 600 "$sandbox/unreadable"

reset_policy
mkdir "$sandbox/output-directory"
expect_directory_failure() {
    if build_protected_ipv4_file "$sandbox/output-directory" 2> "$sandbox/error"; then return 1; fi
    [ -z "$(ls -A "$sandbox/output-directory")" ]
}
name='directory destination rejected without inserting a file'; check expect_directory_failure

printf 'target sentinel\n' > "$sandbox/output-target"
ln -s "$sandbox/output-target" "$sandbox/output-link"
expect_symlink_failure() {
    if build_protected_ipv4_file "$sandbox/output-link" 2> "$sandbox/error"; then return 1; fi
    [ -L "$sandbox/output-link" ] && [ "$(cat "$sandbox/output-target")" = 'target sentinel' ]
}
name='symlink destination rejected without replacing link or modifying target'; check expect_symlink_failure

printf 'Protected-policy cases: %s passed, %s failed\n' "$passed" "$failed"
[ "$failed" -eq 0 ]
