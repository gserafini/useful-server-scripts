#!/bin/bash

# This script iterates through the domains listed in /etc/userdomains,
# filters for top-level domains, and retrieves their IP addresses, registrars, and nameservers.
# It outputs the data in a human-readable, grouped format, with all domains listed under
# a single user heading. Users are now sorted alphabetically, and domains are sorted alphabetically
# within each user's group.

# --- User-Defined Configuration ---
# Set the path to the userdomains file.
USERDOMAINS_FILE="/etc/userdomains"

# --- Script Logic ---

# Check for the --csv or --tsv flag to determine the output format.
output_tsv=false
if [[ "$1" == "--csv" || "$1" == "--tsv" ]]; then
    output_tsv=true
fi

# Check if the userdomains file exists.
if [ ! -f "$USERDOMAINS_FILE" ]; then
    echo "Error: The file $USERDOMS_FILE was not found."
    echo "This script must be run on a WHM-powered server."
    exit 1
fi

echo "Running this script on $HOSTNAME"
echo "Retrieving domain information from $USERDOMS_FILE..."
echo "Please wait, this may take a while depending on the number of domains."
echo "Script build using Google Gemini"
echo "https://gemini.google.com/app/e37a8e86a2cef5e2"

# This variable is used to track the current user and group domains for human-readable output.
current_user=""

# Create a temporary file to store the filtered list of top-level domains.
TEMP_DOMAINS_FILE=$(mktemp)

# Step 1: Safely filter and extract valid top-level domains from the userdomains file.
# This ensures that no corrupted data from whois can interfere with the main loop.
while IFS= read -r line; do
    if [[ "$line" =~ ":" ]]; then
        domain=$(echo "$line" | cut -d':' -f1 | sed 's/^[ \t]*//;s/[ \t]*$//')
        user=$(echo "$line" | cut -d':' -f2 | sed 's/^[ \t]*//;s/[ \t]*$//')
        
        dot_count=$(echo "$domain" | grep -o '\.' | wc -l)
        if [ "$dot_count" -eq 1 ]; then
            echo "$user:$domain" >> "$TEMP_DOMAINS_FILE"
        fi
    fi
done < "$USERDOMAINS_FILE"

# Process the file line by line to gather all domain and user information.
# The `sort -t':' -k1,1 -k2,2` command now sorts the input by user first, then by domain.
sort -t':' -k1,1 -k2,2 "$TEMP_DOMAINS_FILE" | while IFS= read -r line; do
    # Correctly extract the user and domain from the sorted temp file.
    user=$(echo "$line" | cut -d':' -f1 | sed 's/^[ \t]*//;s/[ \t]*$//')
    domain=$(echo "$line" | cut -d':' -f2 | sed 's/^[ \t]*//;s/[ \t]*$//')

    # Use 'dig' to get the A record (IP address) for the domain.
    ip_addresses=$(dig +short A "$domain" @8.8.8.8 | tr '\n' ',' | sed 's/,$//')
    if [ -z "$ip_addresses" ]; then
        ip_addresses="Not found"
    fi

    # Use 'whois' to get nameserver and registrar information.
    whois_output=$(whois "$domain" 2>/dev/null)

    # Initialize variables to hold the parsed data.
    registrar="Not found"
    nameservers=()
    
    # This is the core parsing logic that you confirmed is correct.
    while IFS= read -r whois_line; do
        if [[ "$whois_line" =~ ^[[:space:]]*(Registrar:[[:space:]]*)(.*)$ ]]; then
            registrar="${BASH_REMATCH[2]}"
        fi
        
        if [[ "$whois_line" =~ ^[[:space:]]*(Name[[:space:]]Server:[[:space:]]*)(.*)$ ]]; then
            ns_name="${BASH_REMATCH[2]}"
            nameservers+=("$ns_name")
        fi
    done <<< "$whois_output"
    
    # Check the output flag to determine the formatting.
    if [ "$output_tsv" == true ]; then
        # Explicitly assign nameservers to variables for fixed-column TSV output.
        nameserver1=""
        nameserver2=""
        if [ ${#nameservers[@]} -gt 0 ]; then
            nameserver1="${nameservers[0]}"
        fi
        if [ ${#nameservers[@]} -gt 1 ]; then
            nameserver2="${nameservers[1]}"
        fi
        
        # Use printf to format each column explicitly to prevent data merging.
        printf "%s\t%s\t%s\t%s\t%s\t%s\n" "$user" "$domain" "$ip_addresses" "$registrar" "$nameserver1" "$nameserver2"
    else
        # Check if the user has changed. If so, print the new user heading.
        if [[ "$user" != "$current_user" ]]; then
            current_user="$user"
            echo "---------------------------------------------------------------------"
            echo "### User: $user ###"
            echo "" # Add a line break after the user's name.
        fi

        # Output the domain information, correctly indented.
        echo "    Domain: $domain"
        echo "    IP Address: $ip_addresses"
        echo "    Registrar: $registrar"
        
        if [ ${#nameservers[@]} -eq 0 ]; then
            echo "    Nameserver(s): Not found"
        else
            for ns in "${nameservers[@]}"; do
                echo "    Nameserver: $ns"
            done
        fi
        echo "" # Add a blank line between domains.
    fi
done

# Clean up the temporary file.
rm "$TEMP_DOMAINS_FILE"

echo "Script complete."

