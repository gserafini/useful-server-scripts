# Test-only extracted file I/O primitives; caller supplies its private tracker.
for fixture_function in tracking_initialize tracking_record_failure tracking_lock tracking_snapshot tracking_publish tracking_discard; do
    eval "$(sed -n "/^${fixture_function}() {/,/^}/p" "${SCRIPT:-$script}")"
done
unset fixture_function

# Legacy functions contain explicit /tmp templates. Keep extracted tests entirely
# inside the caller's private fixture root, including on a production host.
: "${TMPDIR:?Set TMPDIR to a new private fixture directory before this test}"
mktemp() {
    local fixture_arg
    local fixture_args=()
    for fixture_arg in "$@"; do
        case "$fixture_arg" in /tmp/*) fixture_arg="$TMPDIR/${fixture_arg##*/}";; esac
        fixture_args+=("$fixture_arg")
    done
    command mktemp "${fixture_args[@]}"
}
