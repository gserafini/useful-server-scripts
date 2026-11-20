<?php
// Ban Wordfence-reported attackers through the tracked csf_ban_wp_login_attackers helper
// (kernel ipset high_volume_bans plus persistent tracking). Legacy PHP runner for hosts
// without Python 3; scripts/wordfence_feed_ban.py is the maintained implementation.
//
// Sites: /etc/wordfence-feed-ban.conf, one https:// base per line (see
// config/wordfence-feed-ban/wordfence-feed-ban.conf.example). This repository is public:
// never commit real site names.
//
// Usage: php wordfence_ban_ips.php [limit=N] [maxdays=N] [dryrun=1] [config=PATH]
// Prints nothing when nothing changed, so `| mail -E ...` only mails real bans or errors.
// Exit codes: 0 ok, 1 some feed failed, 2 configuration error, 4 CSF policy unreadable.

$lock_file = fopen('/var/run/wordfence_ban_ips.lock', 'c');
if ($lock_file === false) {
	fwrite(STDERR, "Unable to open lock file /var/run/wordfence_ban_ips.lock\n");
	exit(1);
}
if (!flock($lock_file, LOCK_EX | LOCK_NB)) {
	exit(0); // a previous run is still working; stay silent
}
ftruncate($lock_file, 0);
fwrite($lock_file, getmypid() . PHP_EOL);
register_shutdown_function(function () use ($lock_file) {
	flock($lock_file, LOCK_UN);
	fclose($lock_file);
});

if ($argc > 1) {
	parse_str(implode('&', array_slice($argv, 1)), $_GET);
}
$maxdays = max(1, (int) ($_GET['maxdays'] ?? 30));
$limit = max(1, (int) ($_GET['limit'] ?? 20));
$dryrun = !empty($_GET['dryrun']);
$config_file = $_GET['config'] ?? '/etc/wordfence-feed-ban.conf';
$ban_script = '/usr/local/bin/csf_ban_wp_login_attackers';

// 1. Site list from local configuration.
$lines = @file($config_file, FILE_IGNORE_NEW_LINES);
if ($lines === false) {
	echo "ERROR: cannot read $config_file\n";
	exit(2);
}
$sites = array();
foreach ($lines as $n => $line) {
	$value = trim(preg_replace('/#.*/', '', $line));
	if ($value === '') {
		continue;
	}
	if (!preg_match('#^https://[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+/?$#', $value)) {
		echo "ERROR: $config_file line " . ($n + 1) . ": expected https://host with no path\n";
		exit(2);
	}
	$sites[rtrim(strtolower($value), '/')] = true;
}
if (!$sites) {
	echo "ERROR: no sites in $config_file\n";
	exit(2);
}

// 2. Exact membership set: every IPv4 already in CSF allow/ignore/deny or the live ipset.
//    (The old strpos() test treated 1.2.3.4 as present when 11.2.3.45 was listed.)
$existing = array();
foreach (array('/etc/csf/csf.ignore', '/etc/csf/csf.allow', '/etc/csf/csf.deny') as $policy) {
	$text = @file_get_contents($policy);
	if ($text === false) {
		echo "ERROR: cannot read $policy\n";
		exit(4);
	}
	if (preg_match_all('/(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])/', $text, $m)) {
		foreach ($m[1] as $ip) {
			$existing[$ip] = true;
		}
	}
}
$live = (string) shell_exec('ipset save high_volume_bans 2>/dev/null');
if (preg_match_all('/^add high_volume_bans (\S+)/m', $live, $m)) {
	foreach ($m[1] as $ip) {
		$existing[$ip] = true;
	}
}

// 3. Collect new, valid, public IPv4 sources from every feed.
$errors = array();
$candidates = array();
$context = stream_context_create(array(
	'http' => array('timeout' => 30, 'user_agent' => 'wordfence-feed-ban/1.0'),
	'ssl' => array('verify_peer' => true, 'verify_peer_name' => true),
));
foreach (array_keys($sites) as $site) {
	$url = $site . "/?get_wordfence_blocked_ips=true&format=json&maxdays=$maxdays&limit=$limit";
	$raw = @file_get_contents($url, false, $context);
	if ($raw === false) {
		$errors[] = "$site: feed request failed";
		continue;
	}
	if (trim($raw) === '') {
		continue; // the helper plugin returns an empty body when nothing was blocked
	}
	$rows = json_decode($raw);
	if (!is_array($rows)) {
		$errors[] = "$site: feed did not return a JSON list";
		continue;
	}
	foreach ($rows as $row) {
		$ip = (is_object($row) && isset($row->IP) && is_string($row->IP)) ? $row->IP : '';
		if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
			continue;
		}
		if (isset($existing[$ip]) || isset($candidates[$ip])) {
			continue;
		}
		$type = (isset($row->blockType) && preg_match('/^[a-z0-9_-]{1,24}$/', (string) $row->blockType)) ? $row->blockType : 'other';
		$count = isset($row->blockCount) ? (int) $row->blockCount : 0;
		$candidates[$ip] = "WordFence: $count $type blocks on $site";
	}
}

// 4. Ban through the tracked helper; it re-checks protected policy for every address.
$added = 0;
foreach ($candidates as $ip => $reason) {
	if ($dryrun) {
		echo "DRYRUN would ban $ip: $reason\n";
		continue;
	}
	$output = shell_exec(escapeshellcmd($ban_script) . ' --blacklist ' . escapeshellarg($ip) . ' ' . escapeshellarg($reason) . ' 2>&1');
	echo "Banned $ip: $reason\n";
	if ($output) {
		echo '  ' . str_replace("\n", "\n  ", trim($output)) . "\n";
	}
	$added++;
}
foreach ($errors as $error) {
	echo "ERROR: $error\n";
}
if ($added > 0) {
	echo "Added $added IPs via csf_ban_wp_login_attackers.\n";
}
exit($errors ? 1 : 0);
