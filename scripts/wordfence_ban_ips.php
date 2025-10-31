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

$csf_deny_file_for_dashboard = '/home/serafini/public_html/version-checker/csf_deny.txt';

$csf_deny_file_contents = file_get_contents($csf_deny_file);
echo "Lines in $csf_deny_file: " . count( explode(PHP_EOL,$csf_deny_file_contents)). "\n";

$csf_ignore_file_contents = file_get_contents($csf_ignore_file);
echo "Lines in $csf_ignore_file: " . count( explode(PHP_EOL,$csf_ignore_file_contents)). "\n";

$csf_allow_file_contents = file_get_contents($csf_allow_file);
echo "Lines in $csf_allow_file: " . count( explode(PHP_EOL,$csf_allow_file_contents)). "\n";

echo "\n";

$existing_ips = $csf_ignore_file_contents.$csf_allow_file_contents.$csf_deny_file_contents;

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

$lines_to_insert = '';

foreach ($ips_to_ban as $IP => $details) {
	//echo "Checking $IP\n";
	if (strpos($existing_ips, $IP) === false) {
		$do_not_delete_limit = 10;
		$do_not_delete = '';
		if ($details->blockCount > $do_not_delete_limit) {
			$do_not_delete = " [More than $do_not_delete_limit blocks, do not delete ] ";
		}
		$lines_to_insert .= "$IP # Bulk banning IPs (/root/wordfence_ban_ips.php) WordFence blocked " . $details->blockCount . " times for " . $details->blockType . " on " . $details->site . $do_not_delete . " (" . $details->countryCode . " " . $details->countryName . ") - " . date("D M j G:i:s Y") . "\n";
	}
	else {
		unset($ips_to_ban[$IP]);
	}
}


if (count($ips_to_ban) > 0) {
	echo count($ips_to_ban) . " IPs not found in csf.deny\n";
	echo "Writing ips to $csf_deny_file\n";
	echo $lines_to_insert . "\n";
	$csf_deny_file_contents .= $lines_to_insert;

	// Let's let CSF worry about the additional lines being added the next time an address is added through another process.
	file_put_contents($csf_deny_file, $csf_deny_file_contents);
	file_put_contents($csf_deny_file_for_dashboard, $csf_deny_file_contents);
	chown($csf_deny_file_for_dashboard, 'serafini');
}
else {
	echo "No IPs found to add, all have already been added to $csf_deny_file.\n";
}

echo "Addedd " . count($ips_to_ban) . " IPs to $csf_deny_file\n";
echo "Done!\n";


