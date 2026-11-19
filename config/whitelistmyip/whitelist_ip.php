<?php
/*
 * WhitelistMyIP.com intake endpoint (server_ops B2003).
 *
 * Source of truth: useful-server-scripts/config/whitelistmyip/whitelist_ip.php
 * Deployed to:     /home/serafini/public_html/version-checker/whitelist_ip.php (owner serafini)
 *
 * The whitelistmyip.com backend (Namecheap server182.web-hosting.com) calls this with
 * ip, name, email and website_url, and expects {"success": true|false}.
 * This file only validates the request and writes one JSON file into
 * /home/serafini/whitelistmyip-spool/. Root's whitelistmyip_process.py, started
 * by systemd when a file appears, does the firewall work. Nothing here runs a
 * command or writes anything a shell will read.
 */
declare(strict_types=1);

// 198.54.114.2 is server182's own address, which its outbound calls use (seen 2026-11-19);
// 198.54.116.2 is the whitelistmyip.com site address on the same server.
const ALLOWED_CALLERS = ['198.54.114.2', '198.54.116.2'];
const MAX_PENDING = 50;
const MAX_RECORD_BYTES = 8000;

header('Content-Type: application/json');
header('Cache-Control: no-store');
header('X-Robots-Tag: noindex');

function respond(bool $success, int $status = 200): never
{
    http_response_code($status);
    echo json_encode(['success' => $success]);
    exit;
}

/* One printable line: control, format and line-separator characters become spaces. */
function clean_field(mixed $value, int $max): string
{
    if (!is_string($value)) {
        return '';
    }
    $value = preg_replace('/[\p{C}\p{Zl}\p{Zp}]+/u', ' ', $value);
    if ($value === null) {
        return ''; // not valid UTF-8
    }
    $value = trim((string) preg_replace('/\s+/u', ' ', $value));
    return preg_match('/^.{0,' . $max . '}/us', $value, $match) ? rtrim($match[0]) : '';
}

$caller = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
if (!in_array($caller, ALLOWED_CALLERS, true)) {
    respond(false, 403);
}

$ip = is_string($_REQUEST['ip'] ?? null) ? trim($_REQUEST['ip']) : '';
$ip_flags = FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
    | (defined('FILTER_FLAG_GLOBAL_RANGE') ? FILTER_FLAG_GLOBAL_RANGE : 0);
if (filter_var($ip, FILTER_VALIDATE_IP, $ip_flags) === false) {
    respond(false);
}

$email = is_string($_REQUEST['email'] ?? null) ? trim($_REQUEST['email']) : '';
if (strlen($email) > 254 || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
    respond(false);
}

$spool = dirname(__DIR__, 2) . '/whitelistmyip-spool';
if (!is_dir($spool) || is_link($spool)) {
    error_log('whitelist_ip.php: request spool ' . $spool . ' is missing');
    respond(false, 503);
}

$pending = glob($spool . '/*.json', GLOB_NOSORT);
if ($pending !== false && count($pending) >= MAX_PENDING) {
    error_log('whitelist_ip.php: request spool is full; is whitelistmyip-process.path running?');
    respond(false, 503);
}

$record = [
    'version' => 1,
    'received_at' => gmdate('c'),
    'ip' => $ip,
    'name' => clean_field($_REQUEST['name'] ?? '', 100),
    'email' => $email,
    'website' => clean_field($_REQUEST['website_url'] ?? '', 255),
    'caller' => $caller,
];
$json = json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
if ($json === false || strlen($json) > MAX_RECORD_BYTES) {
    respond(false);
}

$id = time() . '-' . bin2hex(random_bytes(8));
$tmp = $spool . '/.tmp-' . $id;
$final = $spool . '/' . $id . '.json';

$previous = umask(0077);
$handle = @fopen($tmp, 'x');
umask($previous);
if ($handle === false) {
    error_log('whitelist_ip.php: cannot create ' . $tmp);
    respond(false, 503);
}
$written = fwrite($handle, $json) === strlen($json);
$closed = fclose($handle);
if (!$written || !$closed || !rename($tmp, $final)) {
    @unlink($tmp);
    error_log('whitelist_ip.php: cannot queue request ' . $id);
    respond(false, 503);
}

respond(true);
