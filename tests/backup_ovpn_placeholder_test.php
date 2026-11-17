<?php
// A fresh installation starts only TeleMT; OpenVPN is not initialised and its
// directory holds just the repository placeholder config/openvpn/.gitkeep.
// The exporter took that file for an OpenVPN snapshot, validation then
// demanded ca.crt/server.crt/server.key/server.conf and every backup failed
// ("Required files are missing from the snapshot") until OpenVPN was enabled.
require_once __DIR__ . '/../app/bot.php';
require __DIR__ . '/../app/i18n.php';

class OvpnPlaceholderBot extends Bot
{
    public function __construct(public string $root, array $strings) { $this->i18n = $strings; $this->language = 'en'; }
    public function ovpnPaths() { return ['pki' => "$this->root/pki", 'srv' => "$this->root/server.conf"] + parent::ovpnPaths(); }
}
$failed = 0; $count = 0;
$check = static function (bool $ok, string $what) use (&$failed, &$count) { $count++; if (!$ok) { $failed++; echo "FAIL: $what\n"; } };
$root = sys_get_temp_dir() . '/vpnbot-ovpn-placeholder-' . bin2hex(random_bytes(4));
mkdir($root, 0700);
try {
    touch("$root/.gitkeep");
    $b = new OvpnPlaceholderBot($root, $i);
    $files = $b->exportOvpnPki(true);
    $check($files === null, 'not initialised OpenVPN (only .gitkeep) is not exported');
    try { $b->validateBackup(['pac' => [], 'ovpn' => $files]); $ok = true; } catch (Throwable $e) { $ok = false; }
    $check($ok, 'a backup of a fresh installation passes validation');

    // An initialised PKI is exported as before, without the placeholder.
    foreach (['pki/ca.crt', 'pki/issued/server.crt', 'pki/private/server.key', 'server.conf'] as $name) {
        @mkdir(dirname("$root/$name"), 0700, true); file_put_contents("$root/$name", "x\n");
    }
    $files = $b->exportOvpnPki(true);
    $check(is_array($files) && isset($files['server.conf'], $files['pki/ca.crt']), 'initialised OpenVPN is exported');
    $check(is_array($files) && !isset($files['.gitkeep']), 'the placeholder is not part of the snapshot');
    // A damaged PKI (core file missing) is still refused.
    unlink("$root/pki/ca.crt");
    try { $b->decodeBackupTree($b->exportOvpnPki(true), $root, Bot::OVPN_SNAPSHOT_CORE); $refused = false; } catch (InvalidArgumentException $e) { $refused = true; }
    $check($refused, 'an incomplete PKI is still refused');
} finally {
    exec('rm -rf ' . escapeshellarg($root));
}
echo "backup_ovpn_placeholder_test: " . ($count - $failed) . "/$count\n";
exit($failed ? 1 : 0);
