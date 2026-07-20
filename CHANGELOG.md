# Changelog

## 2026-07-20

- Preserve caller-local IP variables while rebuilding `high_volume_bans`, so whitelist/unblock completion output retains the target IP.

## 2026-07-17

- Persist `high_volume_bans` across CSF rebuilds by replaying its tracking file from `csfpost.sh`.
- Bulk-restore tracked bans, deduplicate entries, and exclude assigned local IPv4 addresses from replay.
- Add safe live-set resizing and local-address cleanup commands with regression coverage.
