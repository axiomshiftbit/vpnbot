<?php
// Реальные proc_open/flock, только синтетические временные файлы; без pcntl.
function lockTestWait(string $path, float $seconds = 5): bool {
    $until = microtime(true) + $seconds;
    do { clearstatcache(true, $path); if (is_file($path)) return true; usleep(10000); } while (microtime(true) < $until);
    return false;
}
function lockTestRemove(string $path): void {
    if (is_dir($path) && !is_link($path)) { foreach (scandir($path) as $name) if ($name !== '.' && $name !== '..') lockTestRemove("$path/$name"); rmdir($path); }
    elseif (file_exists($path) || is_link($path)) unlink($path);
}
$worker = ($argv[1] ?? '') === '--worker';
$root = $worker ? $argv[2] : sys_get_temp_dir() . '/backup-domain-locks-' . bin2hex(random_bytes(6));
if (!$worker) {
    foreach (['app', 'config/ipsec', 'logs'] as $dir) mkdir("$root/$dir", 0700, true);
    foreach (glob(__DIR__ . '/../app/*.php') as $path) {
        if (in_array(basename($path), ['config.php', 'debug.php'], true) || is_link($path)) continue;
        file_put_contents("$root/app/" . basename($path), str_replace(['/logs/', '/config/'], ["$root/logs/", "$root/config/"], file_get_contents($path)));
    }
}
require "$root/app/bot.php";
require "$root/app/i18n.php";
class BackupDomainLockFixture extends Bot {
    private bool $hooked = false;
    public array $starts = [];
    public array $restartOutcomes = [];
    public array $pacWriteFaults = [];
    public bool $trackPacWrites = false;
    public int $pacWrites = 0;
    public function __construct(public string $dir, public string $testRoot, array $strings) {
        $this->pac = "$dir/pac.json"; $this->clients = "$dir/clients.json"; $this->clients1 = "$dir/clients1.json";
        $this->update = "$dir/backup.json"; $this->managedNodeRoot = "$dir/nodes";
        $this->htpasswd = "$dir/webapp/.htpasswd"; $this->telemtDecoyDir = "$dir/decoy"; $this->backupWarpRoot = "$dir/warp";
        $this->protocolModulesFile = "$dir/modules.json"; $this->language = 'ru'; $this->i18n = $strings;
        $this->input = ['chat' => 1, 'message_id' => 1]; $this->ip = '192.0.2.1';
    }
    public function setPacConf(array $conf) {
        if ($this->trackPacWrites) $this->pacWrites++;
        $fault = array_shift($this->pacWriteFaults);
        if ($fault === 'before-false') return false;
        if ($fault === 'before-throw') throw new RuntimeException('synthetic before rename');
        $result = parent::setPacConf($conf);
        if ($fault === 'after-false') return false;
        if ($fault === 'after-throw') throw new RuntimeException('synthetic after rename');
        return $result;
    }
    public function managedNodeBackupRefresh(): void {
        // Refresh обязан вызываться ДО файловых locks: иначе helper с EX зависнет.
        foreach (array_keys($this->managedNodes()) as $id) {
            $path = "$this->managedNodeRoot/.lock-$id";
            if (!is_file($path)) continue;
            $lock = fopen($path, 'c'); $ok = flock($lock, LOCK_SH | LOCK_NB); fclose($lock);
            if (!$ok && is_file("$this->dir/require-refresh-free")) throw new RuntimeException('refresh under file lock');
        }
    }
    public function ipsecPaths() { return ['conf' => "$this->testRoot/config/ipsec"]; }
    public function restartIpsec() { return $this->withLock('ipsec-users', static fn() => true, 1, false); }
    public function protocolModulesSnapshot(): ?array {
        if (!$this->hooked && is_file("$this->dir/hook-enabled")) {
            $this->hooked = true; touch("$this->dir/preflight-passed");
            if (!lockTestWait("$this->dir/continue")) throw new RuntimeException('hook timeout');
        }
        return parent::protocolModulesSnapshot();
    }
    public function waitProtocolModulesApplied(?array $before, int $timeout = 150): bool { return true; }
    public function telemtQuotaRestore(?array $state, array $conf): void {
        $this->pacConfUpdate(function (&$current) use ($conf) { $current = $this->preserveBackupSettings($conf, $current); });
    }
    public function getPorts() { return ['wg' => ['port' => 51820], 'wg1' => ['port' => 51821]]; }
    public function restartNaive() { return true; }
    public function pacUpdate($import = '') {}
    public function dnsttStart() { return true; }
    public function setUpstreamDomainOcserv($domain) {}
    public function setUpstreamDomainNaive($domain) {}
    public function cloakNginx() { return true; }
    public function verifyBackupServices(array $json): array { return []; }
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML') {}
    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false) {}
    public function restartWG($body, $switch = false) {
        $mode = $this->getInstanceWG() === 'wg1' ? 'wg1_amnezia' : 'amnezia';
        $this->starts[] = ['mode' => !empty($this->getPacConf()[$mode]), 'switch' => (bool) $switch];
        return array_shift($this->restartOutcomes) ?? true;
    }
    public function iptablesWG() { $this->sshFailed = false; }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') { throw new RuntimeException('unexpected RPC'); }
}
if ($worker) {
    $dir = $argv[3]; $action = $argv[4]; $bot = new BackupDomainLockFixture($dir, $root, $i);
    ini_set('error_log', "$dir/errors.log"); touch("$dir/started");
    try {
        $payload = is_file("$dir/payload.json") ? json_decode(file_get_contents("$dir/payload.json"), true) : [];
        $result = match ($action) {
            'node-export' => ['files' => $bot->backupExtraFiles()],
            'node-import' => (function () use ($bot, $payload) { $bot->restoreBackupExtraFiles($payload); return ['ok' => true]; })(),
            'ipsec-export' => ['files' => $bot->exportIpsecPki()],
            'ipsec-import' => ['ok' => $bot->importIpsecPki($payload), 'released' => $bot->restartIpsec()],
            'restore' => ['ok' => $bot->importFile($bot->update)],
        };
    } catch (Throwable $error) { $result = ['error' => get_class($error)]; }
    file_put_contents("$dir/result.json", json_encode($result)); exit;
}
$rows = []; $processes = [];
$check = static function (bool $ok, string $name) use (&$rows): void { $rows[] = ['name' => $name, 'pass' => $ok]; };
$new = static function (string $name) use ($root, $i): array {
    $dir = "$root/$name"; mkdir($dir, 0700); $bot = new BackupDomainLockFixture($dir, $root, $i);
    $bot->setPacConf(['language' => 'ru', 'limitpage' => 5, 'amnezia' => 0, 'wg1_amnezia' => 0]);
    file_put_contents($bot->protocolModulesFile, json_encode(array_fill_keys(array_keys(ProtocolModules::DEFAULTS), false)));
    return [$dir, $bot];
};
$start = static function (string $dir, string $action) use ($root, &$processes): void {
    $process = proc_open([PHP_BINARY, __FILE__, '--worker', $root, $dir, $action], [0 => ['file', '/dev/null', 'r'], 1 => ['file', "$dir/stdout", 'w'], 2 => ['file', "$dir/stderr", 'w']], $pipes);
    if (!is_resource($process)) throw new RuntimeException('proc_open failed');
    $processes[] = $process;
    if (!lockTestWait("$dir/started")) throw new RuntimeException('worker did not start');
};
$result = static function (string $dir): array {
    if (!lockTestWait("$dir/result.json")) throw new RuntimeException('worker did not finish');
    return json_decode(file_get_contents("$dir/result.json"), true);
};
$hold = static function (string $path, int $mode = LOCK_EX) {
    if (!is_dir(dirname($path))) mkdir(dirname($path), 0700, true);
    $lock = fopen($path, 'c'); if (!flock($lock, $mode)) throw new RuntimeException('flock failed'); return $lock;
};
$free = static function (string $path): bool {
    $lock = fopen($path, 'c'); $ok = flock($lock, LOCK_EX | LOCK_NB); fclose($lock); return $ok;
};
$nodeFiles = static function (string $generation): array {
    return ['key' => "synthetic-$generation", 'key.pub' => "synthetic-$generation", 'endpoint.json' => json_encode(['generation' => $generation]), 'snapshot.json' => json_encode(['generation' => $generation])];
};
try {
    foreach (['active', 'retired'] as $kind) {
        [$dir, $bot] = $new("node-export-$kind"); $id = $kind === 'active' ? 'aabbccdd' : str_repeat('a', 32);
        $rel = $kind === 'active' ? $id : "retired/$id"; $node = "$bot->managedNodeRoot/$rel"; mkdir($node, 0700, true);
        if ($kind === 'active') $bot->setPacConf($bot->getPacConf() + ['managed_nodes' => [$id => ['connected' => true]]]);
        $old = $kind === 'active' ? $nodeFiles('old') : ['key' => 'old', 'key.pub' => 'old'];
        $newFiles = $kind === 'active' ? $nodeFiles('new') : ['key' => 'new', 'key.pub' => 'new'];
        foreach ($old as $name => $body) file_put_contents("$node/$name", $body);
        $lockPath = "$bot->managedNodeRoot/" . ($kind === 'active' ? ".lock-$id" : '.retired.lock');
        $lock = $hold($lockPath); file_put_contents("$node/key", $newFiles['key']);
        $start($dir, 'node-export'); usleep(200000); $blocked = !is_file("$dir/result.json");
        foreach ($newFiles as $name => $body) file_put_contents("$node/$name", $body);
        flock($lock, LOCK_UN); fclose($lock); $actual = $result($dir);
        $expected = []; foreach ($newFiles as $name => $body) $expected["nodes/$rel/$name"] = base64_encode($body);
        $check($blocked && ($actual['files'] ?? null) === $expected, "node $kind export waits for complete generation");

        [$dir, $bot] = $new("node-import-$kind"); $node = "$bot->managedNodeRoot/$rel"; mkdir($node, 0700, true);
        foreach ($old as $name => $body) file_put_contents("$node/$name", $body);
        file_put_contents("$dir/payload.json", json_encode($expected));
        $lock = $hold("$bot->managedNodeRoot/" . ($kind === 'active' ? ".lock-$id" : '.retired.lock'), LOCK_SH);
        $start($dir, 'node-import'); usleep(200000);
        $untouched = !is_file("$dir/result.json") && file_get_contents("$node/key") === $old['key'];
        flock($lock, LOCK_UN); fclose($lock); $actual = $result($dir);
        $check($untouched && !empty($actual['ok']) && file_get_contents("$node/key.pub") === $newFiles['key.pub'], "node $kind restore waits for readers");
    }
    [$dir, $bot] = $new('node-shared-reader'); $id = 'aabbccdd'; mkdir("$bot->managedNodeRoot/$id", 0700, true);
    $bot->setPacConf($bot->getPacConf() + ['managed_nodes' => [$id => ['connected' => true]]]);
    foreach ($nodeFiles('shared') as $name => $body) file_put_contents("$bot->managedNodeRoot/$id/$name", $body);
    $lock = $hold("$bot->managedNodeRoot/.lock-$id", LOCK_SH); $start($dir, 'node-export');
    $check(lockTestWait("$dir/result.json", 1) && isset($result($dir)['files']), 'node export uses shared locks');
    flock($lock, LOCK_UN); fclose($lock);

    [$dir, $bot] = $new('node-lock-order'); mkdir($bot->managedNodeRoot, 0700, true);
    $files = []; foreach (['ffffffff', '00000000'] as $id) foreach ($nodeFiles('ordered') as $name => $body) $files["nodes/$id/$name"] = base64_encode($body);
    file_put_contents("$dir/payload.json", json_encode($files));
    $lock = $hold("$bot->managedNodeRoot/.lock-ffffffff"); $start($dir, 'node-import'); usleep(200000);
    $check(!$free("$bot->managedNodeRoot/.lock-00000000"), 'node IDs acquired in sorted order');
    flock($lock, LOCK_UN); fclose($lock); $result($dir);
    $check($free("$bot->managedNodeRoot/.lock-00000000") && $free("$bot->managedNodeRoot/.retired.lock"), 'node restore releases stable lock files');

    foreach (['export', 'import'] as $action) {
        [$dir, $bot] = $new("ipsec-$action"); $path = $bot->ipsecPaths()['conf'];
        $old = ['psk' => 'old', 'chap-secrets' => 'old', 'users_ikev2.json' => '{"generation":"old"}'];
        $next = ['psk' => 'new', 'chap-secrets' => 'new', 'users_ikev2.json' => '{"generation":"new"}'];
        foreach ($old as $name => $body) file_put_contents("$path/$name", $body);
        file_put_contents("$dir/payload.json", json_encode(array_map('base64_encode', $next)));
        $lock = $hold("$root/logs/.lock.ipsec-users");
        if ($action === 'export') file_put_contents("$path/psk", 'new');
        $start($dir, "ipsec-$action"); usleep(200000); $blocked = !is_file("$dir/result.json");
        if ($action === 'export') foreach ($next as $name => $body) file_put_contents("$path/$name", $body);
        else $blocked = $blocked && file_get_contents("$path/psk") === 'old';
        flock($lock, LOCK_UN); fclose($lock); $actual = $result($dir);
        $valid = $action === 'export' ? ($actual['files'] ?? null) == array_map('base64_encode', $next) : !empty($actual['ok']) && !empty($actual['released']) && file_get_contents("$path/chap-secrets") === 'new';
        $check($blocked && $valid && $free("$root/logs/.lock.ipsec-users"), "IPsec $action serializes files and releases before restart");
    }
    foreach ([0, 1] as $instance) {
        [$dir, $bot] = $new("wg-pending-$instance"); $mode = $instance ? 'wg1_amnezia' : 'amnezia';
        $clients = $instance ? $bot->clients1 : $bot->clients;
        file_put_contents($clients . '.wg-apply.pending.json', '{}');
        $beforePac = file_get_contents($bot->pac); $beforeModules = file_get_contents($bot->protocolModulesFile);
        file_put_contents($bot->update, json_encode(['pac' => array_replace($bot->getPacConf(), [$mode => 1])]));
        $start($dir, 'restore'); $actual = $result($dir);
        $check(($actual['ok'] ?? null) === false && file_get_contents($bot->pac) === $beforePac && file_get_contents($bot->protocolModulesFile) === $beforeModules, "WG $instance pending rejects restore before PAC/modules");

        [$dir, $bot] = $new("wg-race-$instance"); $clients = $instance ? $bot->clients1 : $bot->clients;
        file_put_contents($clients, '[]'); file_put_contents("$dir/wg$instance.conf", 'old-server'); touch("$dir/hook-enabled");
        $incoming = ['pac' => array_replace($bot->getPacConf(), [$mode => 1]), $instance ? 'wg1' : 'wg' => ['server' => ['interface' => ['Address' => '10.0.0.1/24', 'ListenPort' => 51820]], 'clients' => []]];
        file_put_contents($bot->update, json_encode($incoming)); $start($dir, 'restore');
        if (!lockTestWait("$dir/preflight-passed")) throw new RuntimeException('preflight hook not reached');
        $lock = $hold("$root/logs/.lock.wireguard-" . ($instance ? 'wg1' : 'wg'));
        file_put_contents($clients . '.wg-apply.pending.json', '{}'); flock($lock, LOCK_UN); fclose($lock); touch("$dir/continue");
        $actual = $result($dir);
        $check(($actual['ok'] ?? null) === false && empty($bot->getPacConf()[$mode]) && file_get_contents("$dir/wg$instance.conf") === 'old-server', "WG $instance pending created after preflight preserves mode and config");
    }
    [$dir, $bot] = $new('wg-mode-without-server'); $before = file_get_contents($bot->pac);
    file_put_contents($bot->update, json_encode(['pac' => array_replace($bot->getPacConf(), ['amnezia' => 1])]));
    $start($dir, 'restore'); $actual = $result($dir);
    $check(($actual['ok'] ?? null) === false && file_get_contents($bot->pac) === $before, 'PAC-only mode switch requires matching WG server');
    foreach ([0, 1] as $instance) {
        [$dir, $bot] = $new("wg-success-$instance"); $mode = $instance ? 'wg1_amnezia' : 'amnezia';
        $clients = $instance ? $bot->clients1 : $bot->clients; file_put_contents($clients, '[]'); file_put_contents("$dir/wg$instance.conf", 'old-server');
        file_put_contents($bot->update, json_encode(['pac' => array_replace($bot->getPacConf(), [$mode => 1]), $instance ? 'wg1' : 'wg' => ['server' => ['interface' => ['Address' => '10.0.0.1/24', 'ListenPort' => 51820]], 'clients' => []]]));
        $start($dir, 'restore'); $actual = $result($dir);
        $check(($actual['ok'] ?? null) === true && !empty($bot->getPacConf()[$mode]), "WG $instance successful restore publishes requested mode");
    }
    foreach ([0, 1] as $instance) {
        [$dir, $bot] = $new("wg-mode-rollback-$instance"); $mode = $instance ? 'wg1_amnezia' : 'amnezia';
        $bot->wg = $instance; $clients = $instance ? $bot->clients1 : $bot->clients;
        file_put_contents($clients, '[]'); file_put_contents("$dir/wg$instance.conf", 'old-server');
        $bot->restartOutcomes = [false, true];
        $method = new ReflectionMethod(Bot::class, 'restoreBackupWireGuard');
        $actual = $method->invoke($bot, ['server' => ['interface' => ['Address' => '10.0.0.1/24', 'ListenPort' => 51820]], 'clients' => []], 0, true);
        $check($actual === false && empty($bot->getPacConf()[$mode]) && file_get_contents("$dir/wg$instance.conf") === 'old-server'
            && $bot->starts === [['mode' => true, 'switch' => true], ['mode' => false, 'switch' => true]], "WG $instance failed new-mode apply restores old mode before restart");
    }
    $faultCases = [
        'publish-before-false' => [['before-false'], false, 1],
        'publish-after-false' => [['after-false'], false, 2],
        'publish-before-throw' => [['before-throw'], false, 1],
        'publish-after-throw' => [['after-throw'], false, 2],
        'rollback-before-false' => [['after-false', 'before-false'], true, 2],
        'rollback-after-false' => [['after-false', 'after-false'], false, 2],
        'rollback-before-throw' => [['after-throw', 'before-throw'], true, 2],
        'rollback-after-throw' => [['after-throw', 'after-throw'], false, 2],
    ];
    foreach ([0, 1] as $instance) foreach ([false, true] as $oldMode) foreach ($faultCases as $name => [$faults, $expectPartial, $writes]) {
        [$dir, $bot] = $new("wg-mode-fault-$instance-" . (int) $oldMode . "-$name");
        $mode = $instance ? 'wg1_amnezia' : 'amnezia'; $bot->wg = $instance;
        $bot->setPacConf(array_replace($bot->getPacConf(), [$mode => (int) $oldMode, 'unrelated' => 'preserve']));
        $clients = $instance ? $bot->clients1 : $bot->clients;
        file_put_contents($clients, '[]'); file_put_contents("$dir/wg$instance.conf", 'old-server');
        $clientInode = fileinode($clients); $serverInode = fileinode("$dir/wg$instance.conf");
        $bot->pacWriteFaults = $faults; $bot->trackPacWrites = true; $partial = false; $unexpected = false;
        try {
            $method = new ReflectionMethod(Bot::class, 'restoreBackupWireGuard');
            $actual = $method->invoke($bot, ['server' => ['interface' => ['Address' => '10.0.0.1/24', 'ListenPort' => 51820]], 'clients' => []], 0, !$oldMode);
        } catch (Throwable $error) {
            $actual = false; $partial = $error->getCode() === Bot::BACKUP_PARTIAL; $unexpected = !$partial;
        }
        clearstatcache();
        $check(!$unexpected && $actual === false && $partial === $expectPartial && $bot->pacWrites === $writes
            && !empty($bot->getPacConf()[$mode]) === ($expectPartial ? !$oldMode : $oldMode)
            && $bot->getPacConf()['unrelated'] === 'preserve' && $bot->starts === []
            && file_get_contents($clients) === '[]' && fileinode($clients) === $clientInode
            && file_get_contents("$dir/wg$instance.conf") === 'old-server' && fileinode("$dir/wg$instance.conf") === $serverInode
            && $free("$root/logs/.lock.pac") && $free("$root/logs/.lock.wireguard-" . ($instance ? 'wg1' : 'wg')),
            "WG $instance mode " . (int) $oldMode . " $name distinguishes published state and true rollback failure");
    }
    [$dir, $bot] = $new('node-lock-exception'); $id = 'aabbccdd'; mkdir("$bot->managedNodeRoot/$id", 0700, true);
    $bot->setPacConf($bot->getPacConf() + ['managed_nodes' => [$id => ['connected' => true]]]);
    foreach (['key', 'key.pub'] as $name) file_put_contents("$bot->managedNodeRoot/$id/$name", 'synthetic');
    $failed = false;
    try { $bot->backupExtraFiles(); } catch (Throwable $error) { $failed = true; }
    $check($failed && is_file("$bot->managedNodeRoot/.lock-$id") && $free("$bot->managedNodeRoot/.lock-$id")
        && is_file("$bot->managedNodeRoot/.retired.lock") && $free("$bot->managedNodeRoot/.retired.lock"), 'node exception releases locks without unlinking stable inodes');
    echo json_encode(['checks' => $rows, 'passed' => count(array_filter($rows, static fn($row) => $row['pass'])), 'total' => count($rows)], JSON_UNESCAPED_SLASHES) . "\n";
} finally {
    foreach ($processes as $process) { $status = proc_get_status($process); if ($status['running']) proc_terminate($process); proc_close($process); }
    lockTestRemove($root);
}
exit(count(array_filter($rows, static fn($row) => !$row['pass'])) ? 1 : 0);
