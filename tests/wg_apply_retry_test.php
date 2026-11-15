<?php
// Настоящие файлы, atomic writes, flock и аварийный subprocess. Только SSH/WG
// backend подменён детерминированным адаптером; native-туннель здесь не заявлен.
$source = getenv('VPNBOT_TEST_SOURCE') ?: dirname(__DIR__);
require_once $source . '/app/bot.php';
class WgApplyFixture extends Bot {
    public string $root;
    public string $fault = '';
    public bool $saveFails = false, $intentFails = false, $crashBeforeClientCommit = false;
    public int $notifications = 0;
    public bool $amnezia = false, $pauseRead = false;
    public function __construct(string $root) {
        $this->root = $root; $this->clients = "$root/clients.json"; $this->clients1 = "$root/clients1.json";
        $this->xrayConf = "$root/xray.json"; $this->pac = "$root/pac.json"; $this->language = 'ru'; $this->ip = '127.0.0.1';
        $this->input = ['chat' => 1, 'message_id' => 1, 'callback_id' => 'synthetic'];
    }
    public function getPacConf() { return array_replace(self::PAC_DEFAULTS, ['domain' => '', 'wg_instance' => 0, 'amnezia' => $this->amnezia, 'wg1_amnezia' => $this->amnezia]); }
    public function getPorts() { return ['wg' => ['port' => 51820], 'wg1' => ['port' => 51821]]; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) {
        $f = fopen("$this->root/lock-$name", 'c'); if (!$f || !flock($f, LOCK_EX)) return $busy;
        try { return $fn(); } finally { flock($f, LOCK_UN); fclose($f); }
    }
    public function readClients(): array {
        $clients = parent::readClients();
        if ($this->pauseRead) {
            $this->pauseRead = false; touch("$this->root/first-read"); $until = microtime(true) + 3;
            while (!is_file("$this->root/second-start") && microtime(true) < $until) usleep(1000);
            if (!is_file("$this->root/second-start")) throw new RuntimeException('second writer not ready');
            usleep(150000);
        }
        return $clients;
    }
    public function saveClients(array $clients) {
        if ($this->crashBeforeClientCommit) exit(87);
        if ($this->saveFails) return false;
        return parent::saveClients($clients);
    }
    public function writePrivateKey(string $path, string $data): bool {
        if ($this->intentFails && str_ends_with($path, '.wg-apply.pending.json')) return false;
        return parent::writePrivateKey($path, $data);
    }
    public function menu($type = false, $arg = false, $return = false) {}
    public function wgConfUnavailable(string $why): void {}
    public function answer($callback_id, $textNotify = false, $notify = false) { $this->notifications++; }
    public function restartXray($config, $norestart = false) { return $this->writeXrayJson(json_encode($config)); }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') {
        $this->sshFailed = false;
        $path = $this->root . '/' . ($service === 'wg1' ? 'wg1' : 'wg0') . '.conf';
        $runtime = "$this->root/runtime-$service.json";
        if ($cmd === 'cat /etc/wireguard/wg0.conf') return (string) file_get_contents($path);
        if (str_contains($cmd, 'while [ $i -lt')) return str_repeat('N', 43) . '= ' . str_repeat('P', 43) . "=\n" . str_repeat('M', 43) . '= ' . str_repeat('Q', 43) . "=\n";
        if (str_contains($cmd, 'base64 -d >')) {
            $this->tick($service);
            if ($this->fault === 'write') { $this->sshFailed = true; return ''; }
            if (!preg_match("~echo '([A-Za-z0-9+/=]+)'~", $cmd, $m)) throw new RuntimeException('fixture command');
            file_put_contents($path, base64_decode($m[1], true)); return '';
        }
        if (str_contains($cmd, '-quick down')) { file_put_contents($runtime, '[]'); return ''; }
        if (str_contains($cmd, '-quick up')) {
            $this->tick($service);
            if ($this->fault === 'up') return '';
            preg_match_all('~^PublicKey\s*=\s*(.+)$~m', (string) file_get_contents($path), $m);
            file_put_contents($runtime, json_encode($m[1])); return 'VPNBOT_WG_READY';
        }
        if (str_contains($cmd, ' show wg0 peers')) {
            if ($this->fault === 'verify') { $this->sshFailed = true; return ''; }
            $keys = json_decode((string) file_get_contents($runtime), true);
            if ($this->fault === 'extra-peer') $keys[] = str_repeat('Z', 43) . '=';
            return implode("\n", $keys) . "\nVPNBOT_WG_PEERS_READY\n";
        }
        throw new RuntimeException('unexpected fixture SSH');
    }
    private function tick(string $service): void {
        $file = "$this->root/calls-$service"; file_put_contents($file, (string) ((is_file($file) ? (int) file_get_contents($file) : 0) + 1));
    }
}
if (($argv[1] ?? '') === 'race-worker') {
    $b = new WgApplyFixture($argv[2]);
    if ($argv[3] === 'first') { $b->pauseRead = true; $b->dnsPeer(1, 0); }
    else { touch($argv[2] . '/second-start'); $b->changeClientMTU('1380', 1, 0); }
    exit(0);
}
if (($argv[1] ?? '') === 'crash-worker') {
    $b = new WgApplyFixture($argv[2]); $b->crashBeforeClientCommit = true; $b->switchClient(0); exit(1);
}
$root = sys_get_temp_dir() . '/wg-apply-' . bin2hex(random_bytes(6)); mkdir($root, 0700);
$failures = []; $checks = 0;
$check = static function (bool $ok, string $label) use (&$failures, &$checks) { $checks++; if (!$ok) $failures[] = $label; };
$keyA = str_repeat('A', 43) . '='; $keyB = str_repeat('B', 43) . '=';
$clients = [['interface' => ['PrivateKey' => 'synthetic-private-a', 'Address' => '10.8.0.2/32', '## time' => '2000-01-01'], 'peers' => [['PublicKey' => 'synthetic-server']]],
            ['interface' => ['PrivateKey' => 'synthetic-private-b', 'Address' => '10.8.0.3/32'], 'peers' => [['PublicKey' => 'synthetic-server']]]];
$server = ['interface' => ['Address' => '10.8.0.1/24', 'PrivateKey' => 'synthetic-server-private'], 'peers' => [
    ['PublicKey' => $keyA, 'AllowedIPs' => '10.8.0.2/32'], ['PublicKey' => $keyB, 'AllowedIPs' => '10.8.0.3/32']]];
$seed = static function () use ($root, $clients, $server, $keyA, $keyB): WgApplyFixture {
    foreach (glob("$root/*") as $p) unlink($p);
    $b = new WgApplyFixture($root); file_put_contents("$root/clients.json", json_encode($clients)); file_put_contents("$root/clients1.json", '[]');
    file_put_contents("$root/wg0.conf", $b->createConfig($server)); file_put_contents("$root/wg1.conf", $b->createConfig(['interface' => $server['interface'], 'peers' => []]));
    file_put_contents("$root/runtime-wg.json", json_encode([$keyA, $keyB])); file_put_contents("$root/runtime-wg1.json", '[]');
    file_put_contents("$root/xray.json", json_encode(['inbounds' => [['settings' => ['clients' => [['id' => 'synthetic', 'awg' => 'synthetic-private-a']]]]]]));
    return $b;
};
$pending = static fn() => is_file("$root/clients.json.wg-apply.pending.json");
$runtime = static fn() => json_decode((string) file_get_contents("$root/runtime-wg.json"), true);
try {
    $b = $seed(); $b->shutdownClient();
    $check(!in_array($keyA, $runtime(), true) && in_array($keyB, $runtime(), true) && !empty($b->readClients()[0]['# off']), 'healthy expiry positive control');
    foreach (['write', 'up', 'verify', 'extra-peer'] as $fault) {
        $b = $seed(); $b->fault = $fault; $b->shutdownClient();
        $check(empty($b->readClients()[0]['# off']) && isset($b->readClients()[0]['interface']['## time']), "$fault: unconfirmed expiry retains client identity and retry input");
        $check($pending(), "$fault: durable intent retained");
        if ($pending()) $check((fileperms("$root/clients.json.wg-apply.pending.json") & 0777) === 0600, "$fault: private intent permissions");
        $b->fault = ''; $b->shutdownClient();
        $check(!$pending() && !in_array($keyA, $runtime(), true) && in_array($keyB, $runtime(), true) && !empty($b->readClients()[0]['# off']), "$fault: later cron completes revoke");
    }
    $b = $seed(); $b->fault = 'write'; $b->deletePeer(0, 0, false);
    $check(count($b->readClients()) === 2 && $pending(), 'failed delete preserves identity and intent');
    $before = (string) file_get_contents("$root/clients.json"); $denied = false;
    try { $b->dnsPeer(1, 0); } catch (RuntimeException $expected) { $denied = true; }
    $check($denied && file_get_contents("$root/clients.json") === $before, 'new RMW blocked while prior apply is pending');
    $b->fault = ''; $b->shutdownClient();
    $check(count($b->readClients()) === 1 && $b->readClients()[0]['interface']['Address'] === '10.8.0.3/32' && !in_array($keyA, $runtime(), true), 'cron finishes delete without touching neighbour');
    $b = $seed(); $b->saveFails = true; $b->switchClient(0);
    $check($pending() && empty($b->readClients()[0]['# off']) && !in_array($keyA, $runtime(), true), 'file commit failure retains already-enforced revoke intent');
    $b->saveFails = false; $b->shutdownClient(); $check(!$pending() && !empty($b->readClients()[0]['# off']), 'retry finishes failed client commit');
    $b = $seed(); $b->intentFails = true; $b->switchClient(0);
    $check($runtime() === [$keyA, $keyB] && empty($b->readClients()[0]['# off']), 'failed intent publication never changes runtime or client state');
    $b = $seed();
    $child = proc_open([PHP_BINARY, __FILE__, 'crash-worker', $root], [0 => ['file', '/dev/null', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
    $check(proc_close($child) === 87 && $pending(), 'crash after native apply keeps durable intent');
    (new WgApplyFixture($root))->shutdownClient();
    $check(!$pending() && !empty($b->readClients()[0]['# off']) && !in_array($keyA, $runtime(), true), 'next process completes interrupted revoke');
    $b = $seed(); $b->fault = 'write';
    try { $b->rotateAllPeerKeys(0, true); } catch (RuntimeException $expected) {}
    $check($b->notifications === 0 && $b->readClients()[0]['interface']['PrivateKey'] === 'synthetic-private-a' && $pending(), 'failed rotation has no success notification or new profile publication');
    $b->fault = '';
    if (method_exists($b, 'retryWireguardApply')) $b->retryWireguardApply();
    $check(!$pending() && !in_array($keyA, $runtime(), true) && $b->readClients()[0]['interface']['PrivateKey'] === str_repeat('N', 43) . '=', 'rotation retry publishes verified new keys');
    $check(($b->getXray()['inbounds'][0]['settings']['clients'][0]['awg'] ?? '') === str_repeat('N', 43) . '=', 'rotation retry remaps Xray after WG lock release');
    foreach ([false, true] as $amnezia) foreach ([0, 1] as $instance) {
        $b = $seed(); $b->amnezia = $amnezia;
        if ($instance === 1) {
            file_put_contents("$root/clients1.json", json_encode($clients)); file_put_contents("$root/clients.json", '[]');
            file_put_contents("$root/wg1.conf", $b->createConfig($server)); file_put_contents("$root/runtime-wg1.json", json_encode([$keyA, $keyB]));
        }
        $b->fault = 'write'; $b->shutdownClient(); $b->wg = $instance;
        $check(empty($b->readClients()[0]['# off']), 'WG/AWG instance retains unconfirmed expiry');
        $b->fault = ''; $b->shutdownClient(); $b->wg = $instance;
        $check(!empty($b->readClients()[0]['# off']), 'WG/AWG instance retry positive control');
    }
    $b = $seed(); $descriptors = [0 => ['file', '/dev/null', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']];
    $first = proc_open([PHP_BINARY, __FILE__, 'race-worker', $root, 'first'], $descriptors, $pipes);
    $until = microtime(true) + 3; while (!is_file("$root/first-read") && microtime(true) < $until) usleep(1000);
    $second = proc_open([PHP_BINARY, __FILE__, 'race-worker', $root, 'second'], $descriptors, $pipes);
    $firstExit = proc_close($first); $secondExit = proc_close($second); $client = $b->readClients()[1];
    $check($firstExit === 0 && $secondExit === 0 && ($client['interface']['DNS'] ?? '') === '10.10.0.5'
        && (string) ($client['interface']['MTU'] ?? '') === '1380', 'two real WG writers preserve DNS and MTU updates');
    $b = $seed(); $b->fault = 'write'; $b->switchClient(0); $b->wg = 1;
    $check(!method_exists($b, 'hasWireguardPending') || !$b->hasWireguardPending(), 'second instance has independent pending state');
    $check(method_exists($b, 'withWireguardUpdate') && $b->withWireguardUpdate(static fn() => true) === true, 'second instance is not blocked by first pending');
} finally {
    foreach (glob("$root/*") as $p) unlink($p); rmdir($root);
}
foreach ($failures as $label) echo "FAIL: $label\n";
echo 'wg_apply_retry_test: ', count($failures), " failure(s), $checks checks\n";
exit($failures ? 1 : 0);
