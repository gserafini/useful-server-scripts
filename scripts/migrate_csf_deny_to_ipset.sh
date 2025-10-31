#!/bin/bash
# migrate_csf_deny_to_ipset.sh
#
# Migrates all IPs from /etc/csf/csf.deny to IPSET using csf_ban_wp_login_attackers
#
# Usage: sudo ./migrate_csf_deny_to_ipset.sh [--dry-run] [--force]
#   --dry-run: Preview migration without making changes
#   --force:   Skip confirmation prompt (useful for automated runs)
#
# Author: Gabriel Serafini <gserafini@gmail.com>

set -euo pipefail

CSF_DENY_FILE="/etc/csf/csf.deny"
BAN_SCRIPT="/usr/local/bin/csf_ban_wp_login_attackers"
IP_SET_NAME="high_volume_bans"  # Must match csf_ban_wp_login_attackers
DRY_RUN=0
FORCE=0

# Check for flags
for arg in "$@"; do
    case "$arg" in
        --dry-run)
            DRY_RUN=1
            echo "DRY RUN MODE - No IPs will be added to IPSET"
            echo ""
            ;;
        --force)
            FORCE=1
            ;;
    esac
done

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root (use sudo)"
   exit 1
fi

# Check if csf.deny exists
if [[ ! -f "$CSF_DENY_FILE" ]]; then
    echo "Error: $CSF_DENY_FILE not found"
    exit 1
fi

# Check if ban script exists
if [[ ! -x "$BAN_SCRIPT" ]]; then
    echo "Error: $BAN_SCRIPT not found or not executable"
    exit 1
fi

echo "Starting migration from csf.deny to IPSET..."
echo "(csf_ban_wp_login_attackers will handle IPSET initialization and duplicate checking)"
echo ""

# Count total IPs to migrate
total_ips=$(grep -cE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$CSF_DENY_FILE" || echo 0)
echo "Found $total_ips IPs in $CSF_DENY_FILE"
echo ""

if [[ $total_ips -eq 0 ]]; then
    echo "No IPs to migrate"
    exit 0
fi

# Ask for confirmation unless dry-run or --force
if [[ $DRY_RUN -eq 0 ]] && [[ $FORCE -eq 0 ]]; then
    REPLY=""  # Initialize to avoid unset variable error
    read -p "Proceed with migration? This will add $total_ips IPs to IPSET. [y/N] " -n 1 -r || true
    echo
    if [[ ! "${REPLY:-}" =~ ^[Yy]$ ]]; then
        echo "Migration cancelled"
        exit 0
    fi
    echo ""
elif [[ $FORCE -eq 1 ]]; then
    echo "FORCE mode enabled - proceeding without confirmation"
    echo ""
fi

# Counters
added=0
skipped=0
errors=0
counter=0

# Process each line in csf.deny
while IFS= read -r line; do
    # Skip empty lines and comments
    if [[ -z "$line" ]] || [[ "$line" =~ ^[[:space:]]*# ]]; then
        continue
    fi

    # Extract IP and reason
    if [[ "$line" =~ ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)[[:space:]]*(#.*)?$ ]]; then
        ip="${BASH_REMATCH[1]}"
        reason="${BASH_REMATCH[2]}"

        # Clean up reason (remove leading # and whitespace)
        reason=$(echo "$reason" | sed 's/^#[[:space:]]*//')

        # Use default reason if empty
        if [[ -z "$reason" ]]; then
            reason="Migrated from csf.deny"
        fi

        ((counter++))

        # Show progress every 100 IPs
        if (( counter % 100 == 0 )); then
            echo "Progress: $counter/$total_ips IPs processed (added: $added, skipped: $skipped, errors: $errors)"
        fi

        # Check if IP is already in IPSET
        if ipset test "$IP_SET_NAME" "$ip" &>/dev/null; then
            ((skipped++))
            echo "[$counter/$total_ips] Skipped $ip (already in IPSET)"
            continue
        fi

        if [[ $DRY_RUN -eq 1 ]]; then
            echo "[DRY RUN] Would ban: $ip - $reason"
            ((added++))
        else
            # Add to IPSET using ban script
            echo "[$counter/$total_ips] Adding $ip..."
            if output=$("$BAN_SCRIPT" --blacklist "$ip" "$reason" 2>&1); then
                ((added++))
                echo "  ✓ Added successfully"
            else
                echo "  ✗ Error: $output"
                ((errors++))
            fi
        fi
    fi
done < "$CSF_DENY_FILE"

echo ""
echo "Migration complete!"
echo "===================="
echo "Total IPs processed: $counter"
echo "Added to IPSET: $added"
echo "Skipped (already in IPSET): $skipped"
echo "Errors: $errors"
echo ""

if [[ $DRY_RUN -eq 0 ]]; then
    echo "Next step: Review the migration, then run the following to empty csf.deny:"
    echo "  sudo cp $CSF_DENY_FILE ${CSF_DENY_FILE}.backup"
    echo "  sudo echo '# Migrated to IPSET - see csf_ban_wp_login_attackers' | sudo tee $CSF_DENY_FILE"
    echo ""
    echo "Or use the companion script to automatically backup and clear csf.deny"
fi
