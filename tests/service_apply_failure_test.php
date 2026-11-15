<?php
// Real file writes; the SSH boundary models transport/process/readiness errors.
$root = sys_get_temp_dir() . '/vpnbot-service-apply-' . bin2hex(random_bytes(6)); mkdir($root, 0700);
$source = str_replace(['__DIR__', '/config/Caddyfile'], [var_export(dirname(__DIR__) . '/app', true), "$root/Caddyfile"], file_get_contents(__DIR__ . '/../app/bot.php'));
file_put_contents("$root/bot.php", $source); require "$root/bot.php";
class ServiceApplyFixture extends Bot {
    public string $failure = '';
    public bool $running = true;
    public array $commands = [];
    public function __construct(public string $root) { $this->input = []; $this->language = 'ru'; }
    public function getPacConf() { return ['domain'=>'vpn.example', 'naive'=>['user'=>'audit','pass'=>'synthetic-next']]; }
    public function getHashSubdomain($subdomain) { return 'audit'; }
    public function protocolModuleEnabled(string $module): bool { return true; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
    public function ttPaths() { return ['dir'=>$this->root,'cred'=>"$this->root/credentials.toml",'hosts'=>"$this->root/hosts.toml",'vpn'=>"$this->root/vpn.toml",'rules'=>"$this->root/rules.toml",'log'=>"$this->root/log"]; }
    public function ttBlockers() { return []; }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') {
        $this->commands[] = $cmd; $this->sshFailed = $this->failure === 'transport';
        if ($this->sshFailed) return '';
        if (str_contains($cmd, 'caddy validate')) return $this->failure === 'invalid' ? '' : (str_contains($cmd,'VPNBOT_NAIVE_VALID') ? 'VPNBOT_NAIVE_VALID' : 'Valid configuration');
        if (str_contains($cmd,'pkill') || str_contains($cmd,'service_supervisor.sh stop')) {
            if ($this->failure === 'stop') return '';
            $this->running = false;
            return str_contains($cmd,'service_supervisor.sh') ? 'VPNBOT_SERVICE_STOPPED:trusttunnel' : 'VPNBOT_TT_STOPPED';
        }
        if ($this->failure === 'start') { $this->running = false; return ''; }
        $this->running = true;
        return str_contains($cmd,'service_supervisor.sh') ? 'VPNBOT_SERVICE_READY:' . ($service === 'np' ? 'naive' : 'trusttunnel') : '';
    }
}
$failures = []; $checks = 0;
$check = static function($ok, $name) use (&$failures,&$checks) { $checks++; if (!$ok) $failures[] = $name; };
try {
    foreach (['invalid','transport','start',''] as $failure) {
        $b = new ServiceApplyFixture($root); $b->failure = $failure;
        $old = "forward_proxy {\n basic_auth audit synthetic-old\n}\n";
        file_put_contents("$root/Caddyfile", $old);
        $result = $b->restartNaive();
        $check($result === ($failure === ''), 'Naive reports ' . ($failure ?: 'success'));
        if (in_array($failure,['invalid','transport'],true)) {
            $check($b->running && file_get_contents("$root/Caddyfile") === $old, 'Naive preserves running config before valid candidate: '.$failure);
            $check(!array_filter($b->commands,fn($cmd)=>str_contains($cmd,'pkill') || str_contains($cmd,'service_supervisor.sh')), 'Naive does not stop before validation: '.$failure);
        }
        $check(!glob("$root/Caddyfile.pending-*"), 'Naive removes staging file');
    }
    touch("$root/vpn.toml"); touch("$root/rules.toml");
    foreach (['transport','start',''] as $failure) {
        $b = new ServiceApplyFixture($root); $b->failure = $failure;
        $b->writeTtCredentials(['audit'=>'synthetic-old']);
        $failed = false;
        try { (new ReflectionMethod(Bot::class,'ttUsersUpdate'))->invoke($b, static function(&$users) { $users['audit']='synthetic-next'; }); }
        catch (RuntimeException $error) { $failed = true; }
        $check($failed === ($failure !== ''), 'TrustTunnel reports application error: '.($failure ?: 'success'));
        $check($b->getClientsTt()['audit'] === 'synthetic-next', 'TrustTunnel retains desired credentials for retry');
    }
    $b = new ServiceApplyFixture($root); $b->failure='stop'; $b->writeTtCredentials([]);
    $check($b->restartTt() === false, 'TrustTunnel empty restore requires confirmed stop');
} finally { foreach(glob("$root/*") as $path) unlink($path); rmdir($root); }
foreach($failures as $failure) echo "FAIL: $failure\n";
echo 'service_apply_failure_test: '.$checks.' checks, '.count($failures)." failed\n";
exit($failures ? 1 : 0);
