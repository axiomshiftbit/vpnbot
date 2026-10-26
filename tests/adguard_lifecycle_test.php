<?php
require_once __DIR__ . '/../app/bot.php';

class AdguardLifecycleBot extends Bot
{
    public bool $enabled = true;
    public bool $fail = false;
    public array $calls = [];
    public function __construct() {}
    public function protocolModuleEnabled(string $service): bool { return $this->enabled; }
    public function getPacConf() { return ['adpswd' => 'synthetic-password']; }
    public function setPacConf(array $conf) { return true; }
    public function nginxGetTypeCert() { return false; }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
    {
        $this->calls[] = [$cmd, $service, $wait];
        if ($this->fail) return '';
        return str_ends_with($cmd, ' -- start') ? 'VPNBOT_AD_STARTED' : 'VPNBOT_AD_STOPPED';
    }
}
function adLifecycleCheck(bool $ok, string $why): void
{
    if (!$ok) throw new RuntimeException($why);
}
$bot = new AdguardLifecycleBot();
adLifecycleCheck($bot->stopAd() === '' && $bot->startAd() === '', 'Successful control changed its return value');
foreach ($bot->calls as [$cmd, $service, $wait]) {
    adLifecycleCheck($service === 'ad' && $wait === true, 'AdGuard lifecycle must finish before returning');
    adLifecycleCheck(str_starts_with($cmd, 'sh -c ' . escapeshellarg(file_get_contents(__DIR__ . '/../app/adguard_control.sh'))), 'Control script must travel as one quoted argument');
}
$bot->enabled = false;
$bot->stopAd(); $bot->startAd();
adLifecycleCheck(count($bot->calls) === 2, 'Disabled module attempted SSH');
$bot->enabled = true; $bot->fail = true;
foreach (['startAd', 'stopAd'] as $method) {
    $thrown = false;
    try { $bot->$method(); } catch (RuntimeException $e) { $thrown = true; }
    adLifecycleCheck($thrown, 'Failed lifecycle operation was treated as success');
}
$path = tempnam(sys_get_temp_dir(), 'adguard-lifecycle-');
try {
    $bot->adguard = $path;
    file_put_contents($path, "users: []\ndns: {ratelimit: 500}\n");
    $before = file_get_contents($path);
    $bot->calls = [];
    try { $bot->adguardSync(); } catch (RuntimeException $e) {}
    adLifecycleCheck(file_get_contents($path) === $before, 'Config changed before a confirmed shutdown');
    adLifecycleCheck(count($bot->calls) === 1 && str_ends_with($bot->calls[0][0], ' -- stop'), 'Failed shutdown attempted a second start');
} finally { unlink($path); }
echo "adguard_lifecycle_test OK\n";
