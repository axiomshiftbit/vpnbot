<?php
// Application lifecycle contract; SSH and transport storage are deterministic
// adapters. Real process/port recovery is checked by service_lifecycle.py.
require_once (getenv('VPNBOT_TEST_SOURCE') ?: dirname(__DIR__)) . '/app/bot.php';
class SsTransportLifecycleBot extends Bot {
    public array $cloakState = ['Enabled' => 1, 'PrivateKey' => 'synthetic', 'PublicKey' => 'synthetic', 'UID' => 'synthetic'];
    public array $tlsState = ['Enabled' => 0];
    public array $controls = [];
    public bool $applyOk = false;
    public int $menus = 0;
    public int $lockAcquisitions = 0;
    public function __construct() {
        $this->language = 'ru'; $this->ip = '192.0.2.1';
        $directory = sys_get_temp_dir() . '/ss-transport-' . bin2hex(random_bytes(6));
        mkdir($directory, 0700); $this->pac = "$directory/pac.json";
        $this->managedNodeRoot = "$directory/nodes";
        file_put_contents("$directory/ssserver.json", '{}');
        register_shutdown_function(static function () use ($directory) {
            foreach (['ssserver.json', 'stlsserver.json'] as $name) if (is_file("$directory/$name")) unlink("$directory/$name");
            rmdir($directory);
        });
    }
    public function getPacConf() { return ['domain' => 'fixture.example']; }
    public function getCloakConfig() { return $this->cloakState; }
    public function setCloakConfig(array $c) { $this->cloakState = $c; }
    public function getStlsConfig() { return $this->tlsState; }
    public function setStlsConfig(array $c) { $this->tlsState = $c; }
    public function ensureCloakIdentity() { return $this->cloakState; }
    public function getSSConfig() { return []; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) {
        return parent::withLock($name, function () use ($name, $fn) {
            if ($name === 'shadowsocks') $this->lockAcquisitions++;
            return $fn();
        }, $timeout, $busy);
    }
    public function controlContainerService(string $container, string $service, string $action): bool {
        $this->controls[] = [$container, $service, $action]; return $this->applyOk;
    }
    public function protocolModuleEnabled(string $service): bool { return true; }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') { return ''; }
    public function menu($type = false, $arg = false, $return = false) { $this->menus++; }
    public function restoreTransport() { return (new ReflectionMethod(Bot::class, 'restoreBackupExtraServices'))->invoke($this, ['stlsserver.json' => base64_encode(json_encode($this->tlsState))]); }
}
$checks = 0; $failures = [];
$check = function ($ok, $name) use (&$checks, &$failures) { $checks++; if (!$ok) $failures[] = $name; };
$attempt = static function ($fn) { try { $fn(); return false; } catch (RuntimeException $e) { return true; } };
$b = new SsTransportLifecycleBot(); $before = $b->cloakState;
$check($attempt(fn() => $b->cloak()), 'failed Cloak stop is reported');
$check($b->cloakState === $before && $b->menus === 0, 'failed stop preserves enabled state and does not show success');
$check($b->lockAcquisitions === 1, 'Cloak stop owns transport lock');
$b = new SsTransportLifecycleBot(); $before = $b->cloakState;
$check($attempt(fn() => $b->regenCloakKeys()), 'failed stop blocks key regeneration');
$check($b->cloakState === $before, 'old identity untouched until confirmed stop');
$b = new SsTransportLifecycleBot(); $b->cloakState['Enabled'] = 0; $b->tlsState['Enabled'] = 1;
$check($attempt(fn() => $b->simpleTls()), 'failed simple-tls stop is reported');
$check($b->tlsState['Enabled'] === 1 && $b->menus === 0, 'failed simple-tls stop does not publish off');
$b = new SsTransportLifecycleBot(); $b->cloakState['Enabled'] = 0;
$check($attempt(fn() => $b->simpleTls()), 'failed simple-tls start is reported');
$check($b->controls === [['ss','simple-tls','restart']] && $b->menus === 0, 'single supervisor restart owns enable');
$b = new SsTransportLifecycleBot(); $b->applyOk = true;
$b->cloak();
$check($b->cloakState['Enabled'] === 0 && $b->controls === [['ss','ck-server','stop']], 'confirmed Cloak off');
$b = new SsTransportLifecycleBot(); $b->cloakState['Enabled'] = 0; $b->applyOk = true;
$b->simpleTls(); $b->simpleTls();
$check($b->tlsState['Enabled'] === 0 && $b->controls === [['ss','simple-tls','restart'],['ss','simple-tls','stop']], 'confirmed simple-tls on and off');
$check($b->lockAcquisitions === 2, 'simple-tls toggle reuses nested transport lock');
$b = new SsTransportLifecycleBot(); $b->tlsState['Enabled'] = 1;
$check(in_array('simple-tls', $b->restoreTransport(), true), 'backup does not accept failed transport apply');
$b->applyOk = true;
$check($b->restoreTransport() === [], 'backup accepts confirmed transport apply');
echo json_encode(['checks' => $checks, 'failures' => $failures]), "\n";
exit($failures ? 1 : 0);
