<?php
// Actual config/ledger/store files and process locks. The restart boundary
// deliberately publishes a config before returning false; no native core claim.
require_once __DIR__ . '/../app/bot.php';

class GenerationStatsBot extends Bot
{
    public string $phase = 'ok';
    public string $testRoot;
    public function __construct(string $root)
    {
        $this->testRoot = $root;
        $this->xrayConf = $root . '/xray.json'; $this->pac = $root . '/pac.json';
        $this->protocolRoot = $root . '/protocols'; $this->protocolModulesFile = $root . '/modules.json';
        $this->language = 'en';
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
            if ($this->phase === 'before') return false;
            if ($this->phase === 'pause') {
                file_put_contents($this->testRoot . '/paused', 'ready');
                generationWait($this->testRoot . '/release');
            }
            $config['inbounds'][0]['settings']['clients'] = array_values($config['inbounds'][0]['settings']['clients']);
            if (!$this->writeXrayJson(json_encode($config))) return false;
            $this->collectSession();
            if ($this->phase === 'unreadable') file_put_contents($this->xrayConf, '{');
            if ($this->phase === 'throw') throw new RuntimeException('Injected post-publication failure');
            return !in_array($this->phase, ['after', 'unreadable'], true);
        });
    }
    protected function restoreBackupXrayLocked(array $config): bool { return $this->restartXray($config); }
    public function getPacConf() { return ['language' => 'en'] + self::PAC_DEFAULTS; }
    public function protocolModuleEnabled(string $service): bool { return true; }
    public function deleteHwidUser($id) {}
    public function deleteWarpClient($email) {}
    public function adguardXrayClients() {}
    protected function userXrLocked($i) {}
    public function xray($page = 0) {}
}
function generationRow(int $n): array { return ['global' => ['upload' => 0, 'download' => $n], 'session' => ['upload' => 0, 'download' => 0]]; }
function generationConfig(): array
{
    $clients = [];
    foreach (['A', 'B', 'C'] as $index => $name) $clients[] = ['id' => sprintf('00000000-0000-4000-8000-%012d', $index + 1), 'email' => $name, 'traffic' => 50];
    return ['inbounds' => [['tag' => 'main', 'settings' => ['clients' => $clients]]]];
}
function generationSeed(GenerationStatsBot $bot, bool $sparse = false): void
{
    $bot->phase = 'ok'; file_put_contents($bot->xrayConf, json_encode(generationConfig()));
    $rows = [generationRow(100), generationRow(200), generationRow(300)];
    if ($sparse) unset($rows[1]);
    $bot->setXrayStats(['users' => $rows]);
}
function generationCheck(bool $ok, string $label): void { global $checks; $checks[] = ['test' => $label, 'ok' => $ok]; }
function generationUnknown(GenerationStatsBot $bot): bool { try { $bot->getXrayStats(); return false; } catch (Throwable $e) { return true; } }
function generationWait(string $file): void
{
    $deadline = microtime(true) + 8;
    while (!is_file($file) && microtime(true) < $deadline) usleep(10000);
    if (!is_file($file)) throw new RuntimeException('Worker barrier timed out');
}
function generationWorker(string $root, string $action)
{
    @unlink($root . '/' . $action . '-started'); @unlink($root . '/' . $action . '-done');
    return proc_open([PHP_BINARY, __FILE__, 'worker', $root, $action], [0 => ['file', '/dev/null', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
}
function generationManaged(GenerationStatsBot $bot, ?int $used): ManagedProtocol
{
    $store = $bot->protocolStore('anytls'); $store->configure(['host' => 'vpn.example.test', 'sni' => 'vpn.example.test'], true);
    $bot->syncXrayProtocolUsers(); @mkdir($store->directory() . '/runtime', 0700, true);
    if ($used === null) { @unlink($store->directory() . '/runtime/usage.json'); return $store; }
    $rows = [];
    foreach ($store->read()['users'] as $id => $user) $rows[$id] = ['upload' => 0, 'download' => $user['name'] === 'A' ? $used : 0, 'reset' => $user['reset']];
    ManagedProtocol::writeJson($store->directory() . '/runtime/usage.json', ['users' => $rows]);
    $bot->syncXrayProtocolUsers(); return $store;
}

$worker = ($argv[1] ?? '') === 'worker';
$root = $worker ? ($argv[2] ?? '') : sys_get_temp_dir() . '/vpnbot-xray-generation-' . bin2hex(random_bytes(12));
if (!$worker && !mkdir($root, 0700)) throw new RuntimeException('Cannot create fixture directory');
if (!is_dir($root) || is_link($root) || realpath($root) !== $root || (fileperms($root) & 0777) !== 0700) throw new RuntimeException('Invalid fixture directory');
$bot = new GenerationStatsBot($root);
if ($worker) {
    $action = $argv[3]; file_put_contents($root . '/' . $action . '-started', 'ready');
    try {
        if ($action === 'delete') { $bot->phase = 'pause'; if (!$bot->delxr(0, false)) exit(2); }
        elseif ($action === 'sync') $bot->syncXrayProtocolUsers();
        elseif ($action === 'publish') {
            $config = $bot->getXray(); $config['probe'] = true;
            if (!$bot->writeXrayJson(json_encode($config))) exit(2);
        }
        file_put_contents($root . '/' . $action . '-done', 'done'); exit(0);
    } catch (Throwable $e) { exit(3); }
}

$checks = []; $children = []; $lock = null;
try {
    generationCheck((fileperms($root) & 0777) === 0700, 'fixture root is private');
    generationSeed($bot, true);
    generationCheck($bot->delxr(0, false) === true, 'sparse deletion is applied');
    $stats = $bot->getXrayStats();
    generationCheck($bot->xrUserTraffic($stats, 0) === 0 && $bot->xrUserTraffic($stats, 1) === 300, 'reset B stays zero and C retains 300 after deleting A');
    foreach (['before', 'after', 'unreadable', 'throw'] as $phase) {
        generationSeed($bot); $bot->phase = $phase; $result = null; $thrown = false;
        try { $result = $bot->delxr(0, false); } catch (Throwable $e) { $thrown = true; }
        generationCheck($phase === 'throw' ? $thrown : $result === false, "$phase failure cannot report deletion success");
        if ($phase === 'before') {
            $stats = $bot->getXrayStats();
            generationCheck($bot->xrUserTraffic($stats, 0) === 100 && $bot->xrUserTraffic($stats, 1) === 200, 'unchanged config permits exact old ledger rollback');
        } else generationCheck(generationUnknown($bot), "$phase published config cannot receive the old indexed ledger");
    }
    foreach (['before', 'after'] as $phase) {
        generationSeed($bot); $bot->phase = $phase; $target = generationConfig(); array_shift($target['inbounds'][0]['settings']['clients']);
        $restore = new ReflectionMethod(Bot::class, 'restoreBackupXraySnapshot');
        generationCheck(!$restore->invoke($bot, $target, ['users' => [generationRow(200), generationRow(300)]]), "backup $phase failure is visible");
        generationCheck($phase === 'before' ? $bot->xrUserTraffic($bot->getXrayStats(), 0) === 100 : generationUnknown($bot), "backup $phase ledger matches the surviving generation or is unknown");
    }
    foreach (['unknown' => null, 'exhausted' => 5000, 'available' => 0] as $case => $usage) {
        generationSeed($bot); $config = $bot->getXray();
        $config['inbounds'][0]['settings']['clients'][0]['off'] = $config['inbounds'][0]['settings']['clients'][0]['id'];
        $config['inbounds'][0]['settings']['clients'][0]['id'] = Bot::xrayUuid();
        $config['inbounds'][0]['settings']['clients'][0]['traffic_off'] = 1;
        file_put_contents($bot->xrayConf, json_encode($config)); generationManaged($bot, $usage);
        $bot->saveTrafficXr('0.000001', 0);
        $disabled = !empty($bot->getXray()['inbounds'][0]['settings']['clients'][0]['off']);
        generationCheck($disabled === ($case !== 'available'), "$case shared usage governs quota reenable");
    }

    // Pause delete AFTER reindexing the ledger, BEFORE publishing new clients.
    // A real independent sync worker must wait outside xray-sync, not observe
    // exhausted A with newly reindexed zero usage from B.
    generationSeed($bot); $bot->setXrayStats(['users' => [generationRow(100), generationRow(0), generationRow(0)]]);
    $store = generationManaged($bot, 0);
    @unlink($root . '/paused'); @unlink($root . '/release');
    $children['delete'] = generationWorker($root, 'delete'); generationWait($root . '/paused');
    $children['sync'] = generationWorker($root, 'sync'); generationWait($root . '/sync-started'); usleep(300000);
    $a = array_values(array_filter($store->read()['users'], fn($u) => $u['name'] === 'A'));
    generationCheck(!is_file($root . '/sync-done') && count($a) === 1 && !$a[0]['enabled'], 'managed sync cannot enable exhausted A during a mixed generation');
    file_put_contents($root . '/release', 'go');
    $deleteCode = proc_close($children['delete']); unset($children['delete']);
    $syncCode = proc_close($children['sync']); unset($children['sync']);
    generationCheck($deleteCode === 0 && $syncCode === 0 && !array_filter($store->read()['users'], fn($u) => $u['name'] === 'A'), 'ordered delete and sync complete without deadlock or stale resurrection');

    $lock = fopen($bot->xrayConf . '.apply.lock', 'c'); flock($lock, LOCK_EX);
    $before = hash_file('sha256', $bot->xrayConf); $children['publish'] = generationWorker($root, 'publish');
    generationWait($root . '/publish-started'); usleep(300000);
    generationCheck(!is_file($root . '/publish-done') && hash_file('sha256', $bot->xrayConf) === $before, 'direct writeXrayJson cannot publish before acquiring apply');
    flock($lock, LOCK_UN); fclose($lock); $lock = null;
    $publishCode = proc_close($children['publish']); unset($children['publish']);
    generationCheck($publishCode === 0 && ($bot->getXray()['probe'] ?? null) === true, 'direct publication completes after apply unlock');
} catch (Throwable $e) { generationCheck(false, 'fixture failure: ' . get_class($e) . ' line ' . $e->getLine()); }
finally {
    file_put_contents($root . '/release', 'go');
    if (is_resource($lock)) { flock($lock, LOCK_UN); fclose($lock); }
    foreach ($children as $child) { proc_terminate($child); proc_close($child); }
    $entries = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($entries as $entry) {
        if ($entry->isDir() && !$entry->isLink()) rmdir($entry->getPathname());
        else unlink($entry->getPathname());
    }
    rmdir($root);
}
generationCheck(!is_dir($root), 'parent removes its fixture root');
$passed = count(array_filter($checks, fn($r) => $r['ok']));
echo json_encode(['suite' => 'xray_stats_generation', 'passed' => $passed, 'total' => count($checks), 'checks' => $checks]) . "\n";
exit($passed === count($checks) ? 0 : 1);
