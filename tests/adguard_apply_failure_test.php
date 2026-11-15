<?php
require_once __DIR__ . '/../app/bot.php';
class AdguardApplyFixture extends Bot {
    public bool $readable = true, $transportFailure = false;
    public int $writes = 0, $commands = 0;
    public function __construct() { $this->input = []; $this->language = 'ru'; }
    public function getPacConf() { return ['domain'=>'vpn.example','adpswd'=>'synthetic-password']; }
    public function setPacConf(array $conf) { return true; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
    public function protocolModuleEnabled(string $module): bool { return true; }
    public function nginxGetTypeCert() { return 'letsencrypt'; }
    public function adguardConf(): ?array { return $this->readable ? ['dns'=>[], 'tls'=>['enabled'=>false]] : null; }
    public function adguardWrite(array $c): bool { $this->writes++; return true; }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') {
        $this->commands++; $this->sshFailed = $this->transportFailure;
        return str_ends_with($cmd,'-- start') ? 'VPNBOT_AD_STARTED' : 'VPNBOT_AD_STOPPED';
    }
}
$failed = 0;
foreach (['unreadable','transport','healthy'] as $case) {
    $b = new AdguardApplyFixture(); $b->readable = $case !== 'unreadable'; $b->transportFailure = $case === 'transport';
    $thrown = false;
    try { $b->adguardSync(); } catch (RuntimeException $error) { $thrown = true; }
    $ok = $thrown === ($case !== 'healthy') && $b->writes === ($case === 'healthy' ? 1 : 0);
    if ($case === 'unreadable') $ok = $ok && $b->commands === 0;
    if (!$ok) { $failed++; echo "FAIL: $case\n"; }
}
echo "adguard_apply_failure_test: 3 checks, $failed failed\n";
exit($failed ? 1 : 0);
