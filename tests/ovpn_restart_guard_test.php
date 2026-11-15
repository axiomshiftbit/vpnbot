<?php
// Только синтетический server.conf и SSH-mocks, без настоящих PKI/демонов.
require_once __DIR__ . '/../app/bot.php';

function expectOvpnGuard(bool $ok, string $message): void {
    if (!$ok) throw new RuntimeException($message);
}

$dir = sys_get_temp_dir() . '/ovpn-guard-' . bin2hex(random_bytes(6));
mkdir($dir, 0700);
$bot = new class($dir) extends Bot {
    public array $commands = [];
    public bool $guardOk = true;
    public bool $transportOk = true;
    public bool $pkiReady = true;
    private string $dir;
    public function __construct($dir) { $this->dir = $dir; $this->input = []; }
    public function ovpnPaths() { return ['srv' => $this->dir . '/server.conf']; }
    public function ovpnPkiMissing() { return $this->pkiReady ? [] : ['synthetic']; }
    public function migrateOvpnServerConf() { return ''; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') {
        $this->commands[] = $cmd;
        $this->sshFailed = !$this->transportOk;
        return str_contains($cmd, '/ovpn_firewall.sh') && $this->guardOk ? 'VPNBOT_OVPN_GUARD_OK' : '';
    }
    public function menu($type = false, $arg = false, $return = false) { return null; }
};
try {
    foreach ([[false, true], [true, false]] as [$guard, $transport]) {
        $bot->commands = []; $bot->guardOk = $guard; $bot->transportOk = $transport;
        expectOvpnGuard($bot->restartOvpn() === false, 'failed guard/transport must report failure');
        expectOvpnGuard(count($bot->commands) === 1, 'failed guard must not start daemon');
    }
    $bot->commands = []; $bot->guardOk = $bot->transportOk = true;
    expectOvpnGuard($bot->restartOvpn() === true, 'successful guard permits start');
    expectOvpnGuard(count($bot->commands) === 2, 'stop/guard precedes one start');
    expectOvpnGuard(strpos($bot->commands[0], 'pkill') < strpos($bot->commands[0], '/ovpn_firewall.sh'), 'stop precedes guard');
    expectOvpnGuard(str_starts_with($bot->commands[1], 'openvpn --config '), 'daemon starts only after guard marker');
    $bot->commands = []; $bot->pkiReady = false;
    expectOvpnGuard($bot->restartOvpn() === false && count($bot->commands) === 1, 'incomplete PKI remains stopped');
    $bot->pkiReady = true;

    $path = $dir . '/server.conf';
    foreach (["client-to-client\n", " --client-to-client # legacy\n"] as $legacy) {
        file_put_contents($path, "dev tun\n" . $legacy . "#ovpn-isolation\n#ovpn-isolation\n");
        expectOvpnGuard(!$bot->isOvpnIsolated(), 'legacy active directive outside markers is visible');
        $bot->toggleOvpnIsolation();
        expectOvpnGuard($bot->isOvpnIsolated(), 'isolation toggle removes legacy active directive');
        $bot->toggleOvpnIsolation();
        expectOvpnGuard(!$bot->isOvpnIsolated(), 'allow toggle inserts active directive');
    }
    file_put_contents($path, "dev tun\n# client-to-client\n;client-to-client\n#ovpn-isolation\n#ovpn-isolation\n");
    expectOvpnGuard($bot->isOvpnIsolated(), 'commented directives do not enable interclient traffic');
    echo "ovpn restart guard: PASS\n";
} finally {
    @unlink($dir . '/server.conf');
    rmdir($dir);
}
