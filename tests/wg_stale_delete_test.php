<?php
// C-01 (сверочный аудит): кнопка удаления клиента WireGuard адресовала его
// номером, а после удаления другого клиента список перенумеровывается.
// Устаревшая кнопка удаляла соседа. Теперь кнопка несёт метку клиента, и
// удаление выполняется только при совпадении. Настоящие файлы и блокировки,
// SSH/WG подменён тем же адаптером, что в wg_apply_retry_test.php.
$source = getenv('VPNBOT_TEST_SOURCE') ?: dirname(__DIR__);
require_once $source . '/app/bot.php';
class WgStaleFixture extends Bot {
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
$root = sys_get_temp_dir() . '/wg-stale-' . bin2hex(random_bytes(6)); mkdir($root, 0700);
$failed = 0; $count = 0;
$check = static function (bool $ok, string $what) use (&$failed, &$count) { $count++; if (!$ok) { $failed++; echo "FAIL: $what\n"; } };
$keys = ['A' => str_repeat('A', 43) . '=', 'B' => str_repeat('B', 43) . '=', 'C' => str_repeat('C', 43) . '='];
$clients = []; $peers = [];
foreach (['A' => 2, 'B' => 3, 'C' => 4] as $name => $ip) {
    $clients[] = ['interface' => ['PrivateKey' => "synthetic-private-$name", 'Address' => "10.8.0.$ip/32", '## name' => $name], 'peers' => [['PublicKey' => 'synthetic-server']]];
    $peers[] = ['PublicKey' => $keys[$name], 'AllowedIPs' => "10.8.0.$ip/32"];
}
$server = ['interface' => ['Address' => '10.8.0.1/24', 'PrivateKey' => 'synthetic-server-private'], 'peers' => $peers];
$b = new WgStaleFixture($root);
file_put_contents("$root/clients.json", json_encode($clients)); file_put_contents("$root/clients1.json", '[]');
file_put_contents("$root/wg0.conf", $b->createConfig($server)); file_put_contents("$root/wg1.conf", $b->createConfig(['interface' => $server['interface'], 'peers' => []]));
file_put_contents("$root/runtime-wg.json", json_encode(array_values($keys))); file_put_contents("$root/runtime-wg1.json", '[]');
file_put_contents("$root/xray.json", json_encode(['inbounds' => [['settings' => ['clients' => []]]]]));
$addresses = static fn() => array_map(static fn($c) => $c['interface']['Address'], $b->readClients());
try {
    // Меню клиента B показало кнопку удаления с его номером (1) и меткой.
    $tokenB = method_exists($b, 'wgClientToken') ? $b->wgClientToken($b->readClients()[1]) : 'deadbeef';
    $b->deletePeer(0, 0, false);                        // администратор удаляет A
    $check($addresses() === ['10.8.0.3/32', '10.8.0.4/32'], 'A удалён, B и C на местах 0 и 1');
    $b->deletePeer(1, 0, false, $tokenB);              // устаревшая кнопка B (номер 1 теперь у C)
    $check(in_array('10.8.0.4/32', $addresses(), true), 'устаревшая кнопка не удаляет соседа C');
    $check(in_array('10.8.0.3/32', $addresses(), true), 'B не удалён по чужому номеру');
    // Кнопка из свежего меню удаляет именно своего клиента.
    $tokenC = method_exists($b, 'wgClientToken') ? $b->wgClientToken($b->readClients()[1]) : null;
    $b->deletePeer(1, 0, false, $tokenC);
    $check($addresses() === ['10.8.0.3/32'], 'свежая кнопка удаляет своего клиента');
    // Маршрут кнопки требует метку: старые кнопки без неё не удаляют никого.
    $bot = file_get_contents($source . '/app/bot.php');
    $check(str_contains($bot, '"/delete {$client}_{$page}_" . $this->wgClientToken($clients[$client])'), 'кнопка меню несёт метку клиента');
    $check(str_contains($bot, "case preg_match('~^/delete (?P<client>\\d+)_(?P<page>-?\\d+)_(?P<tok>[a-f0-9]{8})$~'")
        && str_contains($bot, "case preg_match('~^/delete \\d+(?:_-?\\d+)?$~', \$this->input['callback']):"), 'кнопка без метки не маршрутизируется в удаление');
} finally {
    exec('rm -rf ' . escapeshellarg($root));
}
echo "wg_stale_delete_test: " . ($count - $failed) . "/$count\n";
exit($failed ? 1 : 0);
