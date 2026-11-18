<?php
// Restoring a backup with OpenVPN files while the OpenVPN module is disabled
// (now, or by the module states of that backup) tried to restart OpenVPN in a
// container that is not running: "OpenVPN was not started: client isolation
// could not be applied. Retry the restart." although nothing had failed.
require_once __DIR__ . '/../app/bot.php';

class OvpnRestoreBot extends Bot
{
    public bool $enabled = false; public int $restarts = 0;
    public function __construct() {}
    public function protocolModuleEnabled(string $key, ?array $pac = null): bool { return $key === 'ovpn' ? $this->enabled : true; }
    public function restartOvpn() { $this->restarts++; return true; }
}
$failed = 0; $count = 0;
$check = static function (bool $ok, string $what) use (&$failed, &$count) { $count++; if (!$ok) { $failed++; echo "FAIL: $what\n"; } };
$b = new OvpnRestoreBot();
$check(method_exists($b, 'restartOvpnIfEnabled'), 'restore restarts OpenVPN through the module check');
if (method_exists($b, 'restartOvpnIfEnabled')) {
    $b->enabled = false; $b->restartOvpnIfEnabled();
    $check($b->restarts === 0, 'disabled OpenVPN: no restart, no false "not started" message');
    $b->enabled = true; $b->restartOvpnIfEnabled();
    $check($b->restarts === 1, 'enabled OpenVPN: restarted as before');
}
$source = file_get_contents(__DIR__ . '/../app/bot.php');
$block = substr($source, strpos($source, "\$out[] = 'update openvpn';"), 2500);
$check(substr_count($block, '$this->restartOvpn();') === 0 && substr_count($block, '$this->restartOvpnIfEnabled();') === 2,
    'both restarts of the restore OpenVPN section check the module');
echo "ovpn_restore_disabled_test: " . ($count - $failed) . "/$count\n";
exit($failed ? 1 : 0);
