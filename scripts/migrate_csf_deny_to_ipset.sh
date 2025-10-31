#!/bin/bash
# migrate_csf_deny_to_ipset.sh
#
# Migrates all IPs from /etc/csf/csf.deny to IPSET using csf_ban_wp_login_attackers
# Simply extracts IP and reason, then feeds to the ban script which handles everything else
#
# Usage: sudo ./migrate_csf_deny_to_ipset.sh
#
# Author: Gabriel Serafini <gserafini@gmail.com>

CSF_DENY_FILE="/etc/csf/csf.deny"
BAN_SCRIPT="/usr/local/bin/csf_ban_wp_login_attackers"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root"
   exit 1
fi

# Check if files exist
if [[ ! -f "$CSF_DENY_FILE" ]]; then
    echo "Error: $CSF_DENY_FILE not found"
    exit 1
fi

if [[ ! -x "$BAN_SCRIPT" ]]; then
    echo "Error: $BAN_SCRIPT not found or not executable"
    exit 1
fi

echo "Migrating IPs from csf.deny to IPSET..."
echo ""

# Count IPs
total=$(grep -cE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$CSF_DENY_FILE" || echo 0)
echo "Found $total IPs to migrate"
echo ""

if [[ $total -eq 0 ]]; then
    echo "No IPs to migrate"
    exit 0
fi

# Process each line
count=0
while IFS= read -r line; do
    # Skip empty lines and pure comment lines
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^[[:space:]]*# ]] && continue

    # Extract IP and reason (everything after #)
    if [[ "$line" =~ ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)[[:space:]]*(#[[:space:]]*(.*))?$ ]]; then
        ip="${BASH_REMATCH[1]}"
        reason="${BASH_REMATCH[3]}"

        # Use original reason or default
        [[ -z "$reason" ]] && reason="Migrated from csf.deny"

        ((count++))
        echo "[$count/$total] $ip"

        # Call ban script - it handles everything (dupes, IPSET, etc)
        "$BAN_SCRIPT" --blacklist "$ip" "$reason" > /dev/null 2>&1
    fi
done < "$CSF_DENY_FILE"

echo ""
echo "Migration complete! Processed $count IPs"
echo ""
echo "Next: Backup and clear csf.deny:"
echo "  cp $CSF_DENY_FILE ${CSF_DENY_FILE}.backup"
echo "  echo '# Migrated to IPSET' > $CSF_DENY_FILE"
