<?php
// Synthetic storage and real process/flock boundaries; no running VPN service.
require_once __DIR__ . '/../app/bot.php';

class IntegrityStatsBot extends Bot
{
    public string $fault = '';
    public bool $rejectRestore = false;
    public int $restarts = 0;
    public string $testRoot;
    public function __construct(string $root)
    {
        $this->testRoot = $root;
        $this->xrayConf = $root . '/xray.json'; $this->pac = $root . '/pac.json';
        $this->protocolRoot = $root . '/protocols'; $this->protocolModulesFile = $root . '/modules.json';
        $this->language = 'en'; $this->input = ['chat' => 1, 'message_id' => 1];
    }
    public function writePrivateKey(string $path, string $data): bool
    {
        if ($path === $this->testRoot . '/xray.stats' && $this->fault !== '') {
            $fault = $this->fault; $this->fault = '';
            if ($fault === 'after') parent::writePrivateKey($path, $data);
            return false;
        }
        return parent::writePrivateKey($path, $data);
    }
    // Unit storage adapter: real flock and timeout, rooted in this fixture.
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null)
    {
        $lock = fopen($this->testRoot . '/.lock.' . $name, 'c');
        if ($lock === false) return $busy;
        try {
            if ($timeout > 0) {
                $deadline = microtime(true) + $timeout;
                while (!flock($lock, LOCK_EX | LOCK_NB)) {
                    if (microtime(true) >= $deadline) return $busy;
                    usleep(200000);
                }
            } elseif (!flock($lock, LOCK_EX)) return $busy;
            return $fn();
        } finally { flock($lock, LOCK_UN); fclose($lock); }
    }
    public function restartXray($config, $norestart = false)
    {
        return $this->withXrayApplyLock(function () use ($config) {
            $this->restarts++;
            $this->collectSession();
            return file_put_contents($this->xrayConf, json_encode($config)) !== false;
        });
    }
    protected function restoreBackupXrayLocked(array $config): bool { return !$this->rejectRestore && $this->restartXray($config); }
    public function getPacConf() { return ['language' => 'en'] + self::PAC_DEFAULTS; }
    public function exitNodes(?array $pac = null): array { return []; }
    public function xrayStatCounters(): ?array { return ['inbound>>>main>>>traffic>>>downlink' => 20]; }
    public function notifyAdmins(string $text): void {}
    public function adguardXrayClients() {}
    public function deleteHwidUser($id) {}
    public function deleteWarpClient($email) {}
    protected function userXrLocked($i) {}
    public function xray($page = 0) {}
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML') {}
    public function menu($type = false, $arg = false, $return = false) {}
    public function pacUpdate($import = '') {}
    public function protocolModuleEnabled(string $service): bool { return true; }
}

function integrityClients(bool $blocked = false): array
{
    $limited = ['id' => '00000000-0000-4000-8000-000000000001', 'email' => 'limited', 'traffic' => 80];
    if ($blocked) { $limited['off'] = $limited['id']; $limited['id'] = '00000000-0000-4000-8000-000000000003'; $limited['traffic_off'] = 1; }
    return [$limited, ['id' => '00000000-0000-4000-8000-000000000002', 'email' => 'unlimited']];
}
function integrityConfig(array $clients): array { return ['inbounds' => [['tag' => 'main', 'settings' => ['clients' => $clients]]]]; }
function integrityStats(): array
{
    $row = ['global' => ['download' => 60, 'upload' => 10], 'session' => ['download' => 20, 'upload' => 10]];
    return $row + ['users' => [$row]];
}
function integrityCheck(bool $ok, string $label): void
{
    global $checks; $checks[] = ['test' => $label, 'ok' => $ok];
}
function integrityThrows(callable $fn): bool { try { $fn(); return false; } catch (Throwable $e) { return true; } }
function integritySeed(IntegrityStatsBot $bot, bool $blocked = false): void
{
    file_put_contents($bot->xrayConf, json_encode(integrityConfig(integrityClients($blocked))));
    $bot->fault = ''; $bot->setXrayStats(integrityStats()); $bot->restarts = 0;
}
function integrityWait(string $file): void
{
    for ($i = 0; $i < 300 && !is_file($file); $i++) usleep(10000);
    if (!is_file($file)) throw new RuntimeException('Worker barrier timed out');
}

$worker = ($argv[1] ?? '') === 'worker';
$root = $worker ? ($argv[2] ?? '') : sys_get_temp_dir() . '/vpnbot-xray-integrity-' . bin2hex(random_bytes(12));
if (!$worker && !mkdir($root, 0700)) throw new RuntimeException('Cannot create fixture directory');
if (!is_dir($root) || is_link($root) || realpath($root) !== $root || (fileperms($root) & 0777) !== 0700) throw new RuntimeException('Invalid fixture directory');
$bot = new IntegrityStatsBot($root);
if ($worker) {
    $operation = $argv[3]; $done = $root . '/done-' . $operation;
    file_put_contents($done . '.started', 'ready');
    try {
        if ($operation === 'set') $bot->setXrayStats([]);
        elseif ($operation === 'get') $bot->getXrayStats();
        elseif ($operation === 'collect') $bot->collectSession();
        elseif ($operation === 'reset') $bot->resetXrStats(true);
        elseif ($operation === 'revoke') $bot->delxr(1, false);
        elseif ($operation === 'restore') {
            $method = new ReflectionMethod(Bot::class, 'restoreBackupXraySnapshot');
            if (!$method->invoke($bot, integrityConfig(integrityClients()), integrityStats())) exit(2);
        }
        file_put_contents($done, 'done'); exit(0);
    } catch (Throwable $e) { exit(3); }
}

$checks = []; $process = null; $lock = null;
try {
    integrityCheck((fileperms($root) & 0777) === 0700, 'fixture root is private');
    @unlink($root . '/xray.stats'); @unlink($root . '/xray.stats.initialized');
    file_put_contents($bot->xrayConf, json_encode(integrityConfig([])));
    integrityCheck(!integrityThrows(fn() => $bot->getXrayStats()), 'fresh empty installation bootstraps');
    integritySeed($bot);
    integrityCheck($bot->xrUserTraffic($bot->getXrayStats(), 0) === 100, 'global plus session preserves all directions');
    foreach (['missing', 'truncated', 'empty', 'object', 'negative', 'string', 'missing-direction', 'wrong-users'] as $fault) {
        integritySeed($bot); $stats = integrityStats();
        if ($fault === 'missing') unlink($root . '/xray.stats');
        elseif ($fault === 'truncated') file_put_contents($root . '/xray.stats', '{');
        elseif ($fault === 'empty') file_put_contents($root . '/xray.stats', '[]');
        elseif ($fault === 'object') file_put_contents($root . '/xray.stats', '{}');
        else {
            if ($fault === 'negative') $stats['users'][0]['global']['download'] = -100;
            if ($fault === 'string') $stats['users'][0]['global']['download'] = '100';
            if ($fault === 'missing-direction') unset($stats['users'][0]['global']['download']);
            if ($fault === 'wrong-users') $stats['users'] = false;
            $stats['_schema'] = 1; file_put_contents($root . '/xray.stats', json_encode($stats));
        }
        integrityCheck(integrityThrows(fn() => $bot->getXrayStats()), "$fault ledger is unknown");
        $digest = is_file($root . '/xray.stats') ? hash_file('sha256', $root . '/xray.stats') : null;
        $bot->time_xray_stats = 0; $bot->xrayStatsUser();
        integrityCheck((is_file($root . '/xray.stats') ? hash_file('sha256', $root . '/xray.stats') : null) === $digest, "$fault collector cannot invent a new period");
    }
    integritySeed($bot); unlink($root . '/xray.stats'); unlink($root . '/xray.stats.initialized');
    integrityCheck(integrityThrows(fn() => $bot->getXrayStats()), 'missing legacy ledger with existing users is unknown');
    file_put_contents($root . '/xray.stats', '[]');
    integrityCheck(!integrityThrows(fn() => $bot->getXrayStats()), 'legacy confirmed empty reset migrates');
    $bot->setXrayStats([]);
    integrityCheck($bot->xrUserTraffic($bot->getXrayStats(), 0) === 0, 'explicit empty reset is readable');
    unlink($root . '/xray.stats'); file_put_contents($bot->xrayConf, json_encode(integrityConfig([])));
    integrityCheck(integrityThrows(fn() => $bot->getXrayStats()), 'initialized empty installation cannot silently bootstrap again');
    foreach (['before', 'after'] as $fault) {
        integritySeed($bot, true); $bot->fault = $fault;
        $rejected = integrityThrows(fn() => $bot->resetXrStats(true));
        integrityCheck($rejected && $bot->restarts === 0 && !empty($bot->getXray()['inbounds'][0]['settings']['clients'][0]['off']), "reset $fault rename failure cannot reenable");
        integrityCheck(integrityThrows(fn() => $bot->getXrayStats()), "reset $fault rename leaves unconfirmed ledger unknown");
        integritySeed($bot, true); $bot->fault = $fault;
        $rejected = integrityThrows(fn() => $bot->resetXrUser(0));
        integrityCheck($rejected && $bot->restarts === 0 && !empty($bot->getXray()['inbounds'][0]['settings']['clients'][0]['off']), "user reset $fault rename failure cannot reenable");
    }
    integritySeed($bot, true); file_put_contents($root . '/xray.stats', '{');
    integrityCheck(!integrityThrows(fn() => $bot->resetXrStats(true)) && empty($bot->getXray()['inbounds'][0]['settings']['clients'][0]['off'])
        && $bot->xrUserTraffic($bot->getXrayStats(), 0) === 0, 'confirmed full reset recovers unknown ledger');
    integritySeed($bot); file_put_contents($root . '/xray.stats', '{'); $bot->checkTrafficLimits();
    $clients = $bot->getXray()['inbounds'][0]['settings']['clients'];
    integrityCheck(!empty($clients[0]['off']) && !empty($clients[0]['traffic_usage_unavailable']) && empty($clients[1]['off']), 'unknown ledger closes limited client only');
    integrityCheck(file_get_contents($root . '/xray.stats') === '{', 'revoke restart preserves corrupted ledger');
    integrityCheck($bot->delxr(1, false) === true && count($bot->getXray()['inbounds'][0]['settings']['clients']) === 1
        && file_get_contents($root . '/xray.stats') === '{', 'independent unlimited deletion remains available');

    integritySeed($bot);
    integrityCheck(integrityThrows(fn() => $bot->validateBackup(['xraystats' => ['users' => [['global' => ['download' => -1, 'upload' => 0]]]]])), 'backup invalid counters rejected at preflight');
    integrityCheck(!integrityThrows(fn() => $bot->validateBackup(['xraystats' => []])), 'legacy empty backup accepted');
    $bot->setXrayStats(['users' => [['global' => ['upload' => 10, 'download' => 60]]]]);
    integrityCheck($bot->xrUserTraffic($bot->getXrayStats(), 0) === 70, 'legacy global-only backup retains its counters');
    $incomplete = $bot->getXrayStats(); $incomplete['_schema'] = 1; unset($incomplete['users'][0]['session']);
    file_put_contents($root . '/xray.stats', json_encode($incomplete));
    integrityCheck(integrityThrows(fn() => $bot->getXrayStats()), 'versioned ledger cannot lose a whole counter group');
    if (method_exists(Bot::class, 'restoreBackupXraySnapshot')) {
        $restore = new ReflectionMethod(Bot::class, 'restoreBackupXraySnapshot');
        file_put_contents($root . '/xray.stats', '{');
        integrityCheck($restore->invoke($bot, integrityConfig(integrityClients()), integrityStats())
            && $bot->xrUserTraffic($bot->getXrayStats(), 0) === 100, 'backup restores confirmed counters from unknown state');
        integritySeed($bot); $bot->rejectRestore = true;
        integrityCheck(!$restore->invoke($bot, integrityConfig(integrityClients()), [])
            && $bot->xrUserTraffic($bot->getXrayStats(), 0) === 100, 'failed Xray restore rolls ledger back');
        $bot->rejectRestore = false;
        integrityCheck($restore->invoke($bot, integrityConfig(integrityClients()), null)
            && integrityThrows(fn() => $bot->getXrayStats()), 'config-only restore cannot authorize mismatched counters');
    } else integrityCheck(false, 'backup config and ledger share one operation');

    // Real flock contention, using proc_open because CI PHP has no pcntl.
    foreach (['set' => 'xray-stats', 'get' => 'xray-stats', 'collect' => 'xray-stats', 'reset' => 'xray', 'revoke' => 'xray', 'restore' => 'xray'] as $operation => $lockName) {
        integritySeed($bot, $operation === 'reset');
        $done = $root . '/done-' . $operation; @unlink($done); @unlink($done . '.started');
        $lock = fopen($root . '/.lock.' . $lockName, 'c'); flock($lock, LOCK_EX);
        $process = proc_open([PHP_BINARY, __FILE__, 'worker', $root, $operation], [0 => ['file', '/dev/null', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
        integrityWait($done . '.started'); usleep(250000); $waited = !is_file($done);
        flock($lock, LOCK_UN); fclose($lock); $lock = null;
        $status = proc_close($process); $process = null;
        integrityCheck($waited && $status === 0 && is_file($done), "$operation waits for its stable domain lock");
        @unlink($done); @unlink($done . '.started');
    }

    integritySeed($bot); $bot->setXrayStats([]);
    $store = $bot->protocolStore('anytls');
    $store->configure(['host' => 'vpn.example.test', 'sni' => 'vpn.example.test'], true);
    $bot->syncXrayProtocolUsers();
    $rows = [];
    foreach ($store->read()['users'] as $id => $user) $rows[$id] = ['upload' => 0, 'download' => 0, 'reset' => $user['reset']];
    @mkdir($store->directory() . '/runtime', 0700, true);
    ManagedProtocol::writeJson($store->directory() . '/runtime/usage.json', ['users' => $rows]);
    $bot->syncXrayProtocolUsers();
    $enabled = array_filter($store->read()['users'], fn($u) => $u['enabled']);
    integrityCheck(count($enabled) === 2, 'managed shared users start with confirmed zero counters');
    file_put_contents($root . '/xray.stats', '{');
    $config = $bot->getXray(); $config['inbounds'][0]['settings']['clients'][1]['off'] = $config['inbounds'][0]['settings']['clients'][1]['id'];
    $config['inbounds'][0]['settings']['clients'][1]['id'] = Bot::xrayUuid();
    file_put_contents($bot->xrayConf, json_encode($config));
    $bot->syncXrayProtocolUsers();
    $users = array_values($store->read()['users']);
    integrityCheck(count($users) === 2 && !array_filter($users, fn($u) => $u['enabled']), 'unknown Xray ledger closes managed quota and preserves unlimited revoke');
    integrityCheck(count(array_filter($users, fn($u) => $u['quota'] === 1)) === 1, 'managed unknown quota uses a positive denied sentinel');
    integrityCheck(!integrityThrows(fn() => $bot->xraySubscriptionMetadata(integrityClients()[1], 1)), 'unlimited metadata survives unavailable Xray counters');
    integrityCheck(integrityThrows(fn() => $bot->xraySubscriptionMetadata(integrityClients()[0], 0)), 'limited metadata cannot advertise unknown counters as zero');
} catch (Throwable $error) {
    integrityCheck(false, 'unexpected fixture failure: ' . get_class($error) . ' line ' . $error->getLine());
} finally {
    if (is_resource($lock)) { flock($lock, LOCK_UN); fclose($lock); }
    if (is_resource($process)) { proc_terminate($process); proc_close($process); }
    $entries = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($entries as $entry) {
        if ($entry->isDir() && !$entry->isLink()) rmdir($entry->getPathname());
        else unlink($entry->getPathname());
    }
    rmdir($root);
}
integrityCheck(!is_dir($root), 'parent removes its fixture root');
$passed = count(array_filter($checks, fn($r) => $r['ok']));
echo json_encode(['suite' => 'xray_stats_integrity', 'passed' => $passed, 'total' => count($checks), 'checks' => $checks], JSON_UNESCAPED_SLASHES) . "\n";
exit($passed === count($checks) ? 0 : 1);
