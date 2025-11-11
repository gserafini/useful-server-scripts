<?php
// 1. Get list of all IPs we want to deny
// 2. Check to see if they're already in csf.deny (it's expensive to try to deny each IP individually and let csf check it)
// 3. Add IPs to deny file

echo "Getting IPs to ban from WordFence...\n";

$sites = array();
$sites[] = "https://sharethepractice.org/";
$sites[] = "https://serafinistudios.com/";
$sites[] = "https://www.asaentertainment.com/";
$sites[] = "https://gabrielserafini.com/";
//$sites[] = "https://christiansciencenursing.org/";
$sites[] = "https://firstchurchstl.com/";
$sites[] = "https://offyonder.com/";
#$sites[] = "https://www.ssicinnercircle.com/";
#$sites[] = "https://ssiconline.com/";
$sites[] = "https://interprosepr.com";

$ips_to_ban = array();

// Add args to $_GET
if($argc>1)
  parse_str(implode('&',array_slice($argv, 1)), $_GET);

$maxdays = $_GET['maxdays'] ?? 30;
$limit = $_GET['limit'] ?? 20;
$format = $_GET['format'] ?? 'json';

$params = "?get_wordfence_blocked_ips=true&format=$format&maxdays=$maxdays&limit=$limit";

$csf_deny_file = '/etc/csf/csf.deny';
$csf_ignore_file = '/etc/csf/csf.ignore';
$csf_allow_file = '/etc/csf/csf.allow';
$ban_script = '/usr/local/bin/csf_ban_wp_login_attackers';

// Check existing IPs in CSF files and IPSET
$csf_deny_file_contents = file_get_contents($csf_deny_file);
echo "Lines in $csf_deny_file: " . count( explode(PHP_EOL,$csf_deny_file_contents)). "\n";

$csf_ignore_file_contents = file_get_contents($csf_ignore_file);
echo "Lines in $csf_ignore_file: " . count( explode(PHP_EOL,$csf_ignore_file_contents)). "\n";

$csf_allow_file_contents = file_get_contents($csf_allow_file);
echo "Lines in $csf_allow_file: " . count( explode(PHP_EOL,$csf_allow_file_contents)). "\n";

// Get IPs already in IPSET (using high_volume_bans set name)
$ipset_ips = shell_exec('ipset list high_volume_bans 2>/dev/null | grep -E "^[0-9]" || echo ""');
echo "IPs in IPSET: " . count( explode(PHP_EOL, trim($ipset_ips))). "\n";

echo "\n";

$existing_ips = $csf_ignore_file_contents.$csf_allow_file_contents.$csf_deny_file_contents.$ipset_ips;

foreach ($sites as $site) {
	$url = $site . $params;
	echo "Getting IPs from: $url\n";
	$raw_ips = file_get_contents($url);
	if ($raw_ips) {
		$site_ips = json_decode($raw_ips);
		//print_r($site_ips);
		if ($site_ips) {
			foreach ($site_ips as $details) {
				if (!isset($ips_to_ban[$details->IP]) && isset($details->IP)) {
					$details->site = $site;
					$ips_to_ban[$details->IP] = $details;
				}
			}
		}
	}
}
echo "\n";
echo "Found total of " . count($ips_to_ban) . " IPs to check! \n";

$ips_added = 0;

foreach ($ips_to_ban as $IP => $details) {
	//echo "Checking $IP\n";
	if (strpos($existing_ips, $IP) === false) {
		// Build reason string for ban
		$reason = "WordFence: {$details->blockCount} blocks for {$details->blockType} on {$details->site} ({$details->countryCode} {$details->countryName})";

		echo "Banning $IP: $reason\n";

		// Call csf_ban_wp_login_attackers to add to IPSET
		$cmd = escapeshellcmd($ban_script) . ' --blacklist ' . escapeshellarg($IP) . ' ' . escapeshellarg($reason) . ' 2>&1';
		$output = shell_exec($cmd);

		if ($output) {
			echo "  Output: " . trim($output) . "\n";
		}

		$ips_added++;
	}
	else {
		unset($ips_to_ban[$IP]);
	}
}

if ($ips_added > 0) {
	echo "\nSuccessfully added $ips_added IPs to IPSET via csf_ban_wp_login_attackers\n";
}
else {
	echo "\nNo new IPs to add - all IPs already banned in CSF or IPSET.\n";
}

echo "Done!\n";


