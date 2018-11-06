#!/bin/bash
# Script to bulk ban bad IPs that are copy/pasted

printf "Give me some IPs to ban using CSF!  Use ctrl-d to cancel, or new line to process.  \n"

ip_list=$(sed '/^$/q')

echo "Processing..."

echo "$ip_list" | while read -r line;
do
  ip="$(grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' <<< "$line")"
  if [[ ! -z $ip ]]
    then
      geoip=`geoiplookup $ip`
      echo "Found IP $ip"
      echo "$geoip"
      echo "Banning IP..."
      csf -d $ip "Bulk banning IPs found by WordFence ($(tr '\n' ' ' <<< $geoip))"
  fi
done

echo "Done!"


