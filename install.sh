#!/bin/bash
# Installation script for useful-server-scripts
# Symlinks all scripts from scripts/ directory to /usr/local/bin/
#
# Usage: sudo ./install.sh

# Note: We don't use 'set -e' here because we want to continue
# processing all scripts even if individual operations fail.
# Errors are handled explicitly throughout the script.

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (use sudo)"
    echo "Usage: sudo ./install.sh"
    exit 1
fi

# Get the absolute path to the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS_PATH="$SCRIPT_DIR/scripts"
INSTALL_DIR="/usr/local/bin"

echo "====================================================================="
echo "Useful Server Scripts - Installation"
echo "====================================================================="
echo ""
echo "This will create symlinks in $INSTALL_DIR for all scripts in:"
echo "  $SCRIPTS_PATH"
echo ""

# Check if scripts directory exists
if [ ! -d "$SCRIPTS_PATH" ]; then
    echo "Error: Scripts directory not found at $SCRIPTS_PATH"
    exit 1
fi

# Check if /usr/local/bin exists
if [ ! -d "$INSTALL_DIR" ]; then
    echo "Error: $INSTALL_DIR does not exist"
    exit 1
fi

# Count scripts to install
SCRIPT_COUNT=$(find "$SCRIPTS_PATH" -maxdepth 1 -type f | wc -l)
if [ "$SCRIPT_COUNT" -eq 0 ]; then
    echo "Error: No scripts found in $SCRIPTS_PATH"
    exit 1
fi

echo "Found $SCRIPT_COUNT script(s) to install."
echo ""
echo "The following symlinks will be created:"
echo ""

# List scripts that will be installed
for script in "$SCRIPTS_PATH"/*; do
    if [ -f "$script" ]; then
        script_name=$(basename "$script")
        echo "  $INSTALL_DIR/$script_name -> $script"
    fi
done

echo ""
read -r -p "Proceed with installation? (yes/no): " response

if [[ ! "$response" =~ ^[Yy][Ee][Ss]$ ]]; then
    echo "Installation cancelled."
    exit 0
fi

echo ""
echo "Installing scripts..."
echo ""

INSTALLED=0
SKIPPED=0
UPDATED=0

for script in "$SCRIPTS_PATH"/*; do
    if [ -f "$script" ]; then
        script_name=$(basename "$script")
        target="$INSTALL_DIR/$script_name"

        # Check if symlink already exists
        if [ -L "$target" ]; then
            # Symlink exists - check if it points to the right place
            current_target=$(readlink "$target")
            if [ "$current_target" = "$script" ]; then
                echo "✓ $script_name (already installed)"
                ((SKIPPED++))
            else
                echo "⚠ $script_name (updating symlink)"
                echo "  Old: $current_target"
                echo "  New: $script"
                ERROR_MSG=$(rm "$target" && ln -s "$script" "$target" 2>&1)
                if [ $? -eq 0 ]; then
                    echo "  ✓ Updated successfully"
                    ((UPDATED++))
                else
                    echo "  ✗ Failed to update"
                    echo "  Error: ${ERROR_MSG:-Unknown error}"
                    ((SKIPPED++))
                fi
            fi
        elif [ -e "$target" ]; then
            # File exists but is not a symlink
            echo "✗ $script_name (file exists but is not a symlink)"
            echo "  A file already exists at $target"
            echo "  Please remove or rename it manually to install this script."
            ((SKIPPED++))
        else
            # Create new symlink
            ERROR_MSG=$(ln -s "$script" "$target" 2>&1)
            if [ $? -eq 0 ]; then
                echo "✓ $script_name (installed)"
                ((INSTALLED++))
            else
                echo "✗ $script_name (FAILED to create symlink)"
                echo "  Target: $target"
                echo "  Error: ${ERROR_MSG:-Unknown error}"
                echo "  Tip: Make sure you're running with sudo and $INSTALL_DIR is writable"
                ((SKIPPED++))
            fi
        fi
    fi
done

echo ""
echo "====================================================================="
echo "Installation Summary"
echo "====================================================================="
echo ""
echo "  Newly installed: $INSTALLED"
echo "  Already installed: $SKIPPED"
echo "  Updated: $UPDATED"
echo ""

if [ $INSTALLED -gt 0 ] || [ $UPDATED -gt 0 ]; then
    echo "✅ Installation successful!"
else
    echo "✅ All scripts were already installed."
fi

echo ""
echo "Scripts are now available system-wide."
echo ""
echo "Next steps:"
echo "  1. Initialize the IP banning system:"
echo "     csf_ban_wp_login_attackers --init"
echo ""
echo "  2. (Optional) Set up ModSecurity instant banning:"
echo "     csf_ban_wp_login_attackers --install-mod-security-triggers"
echo ""
echo "  3. Add to cron for automated scanning (every 5 minutes):"
echo "     echo '*/5 * * * * /usr/local/bin/csf_ban_wp_login_attackers' | crontab -"
echo ""
echo "====================================================================="
