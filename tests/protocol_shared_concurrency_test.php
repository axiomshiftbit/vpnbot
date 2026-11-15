<?php
require_once __DIR__ . '/../app/bot.php';

if (!function_exists('pcntl_fork')) { echo "protocol_shared_concurrency_test: SKIP (pcntl)\n"; exit; }

class ConcurrentSharedBot extends Bot {
    public string $fixture;
    public bool $slow = false;
    public function __construct(string $root) {
        $this->fixture = $root;
        $this->protocolRoot = "$root/protocols";
        $this->protocolModulesFile = "$root/modules.json";
        $this->xrayConf = "$root/xray.json";
    }
    public function getXray() {
        $config = ManagedProtocol::readJson($this->fixture . '/xray.json');
        if ($this->slow) {
            touch($this->fixture . '/old-read');
            // Let the newer synchronization finish first if it can overtake us.
            // With serialization it waits, and this bounded barrier releases us.
            $deadline = microtime(true) + 1;
            while (!is_file($this->fixture . '/new-done') && microtime(true) < $deadline) usleep(10000);
        }
        return $config;
    }
    public function getXrayStats() { return []; }
}

function concurrentCheck(bool $ok, string $message): void { if (!$ok) throw new RuntimeException($message); }
function concurrentWorker(ConcurrentSharedBot $bot, bool $slow): int {
    $pid = pcntl_fork();
    if ($pid === -1) throw new RuntimeException('Не удалось запустить параллельную синхронизацию');
    if ($pid === 0) {
        try {
            $bot->slow = $slow;
            $bot->syncXrayProtocolUsers();
            if (!$slow) touch($bot->fixture . '/new-done');
            exit(0);
        } catch (Throwable $e) { fwrite(STDERR, "Ошибка параллельной синхронизации\n"); exit(1); }
    }
    return $pid;
}

$root = sys_get_temp_dir() . '/vpnbot-concurrent-shared-' . bin2hex(random_bytes(6)); mkdir($root, 0700);
$children = []; $failures = [];
try {
    foreach (['disable', 'delete', 'rotate'] as $operation) {
        $dir = "$root/$operation"; mkdir($dir, 0700);
        $bot = new ConcurrentSharedBot($dir);
        $modules = new ProtocolModules($bot->protocolModulesFile);
        foreach (array_keys(ManagedProtocol::NAMES) as $protocol) {
            $bot->protocolStore($protocol)->configure(['host' => 'vpn.example.test', 'sni' => in_array($protocol, ['mieru', 'snolc'], true) ? '' : 'vpn.example.test'], true);
            $modules->set($protocol, true);
        }
        $client = ['id' => Bot::xrayUuid(), 'subtoken' => bin2hex(random_bytes(16)), 'email' => 'Concurrent fixture'];
        $config = ['inbounds' => [['settings' => ['clients' => [$client]]]]];
        ManagedProtocol::writeJson("$dir/xray.json", $config);
        $bot->syncXrayProtocolUsers();
        $children[] = concurrentWorker($bot, true);
        $deadline = microtime(true) + 5;
        while (!is_file("$dir/old-read") && microtime(true) < $deadline) usleep(10000);
        concurrentCheck(is_file("$dir/old-read"), 'Первый процесс не прочитал исходное состояние');
        if ($operation === 'disable') $client['off'] = $client['id'];
        if ($operation === 'rotate') $client['id'] = Bot::xrayUuid();
        $config['inbounds'][0]['settings']['clients'] = $operation === 'delete' ? [] : [$client];
        ManagedProtocol::writeJson("$dir/xray.json", $config);
        $children[] = concurrentWorker($bot, false);
        foreach ($children as $pid) {
            pcntl_waitpid($pid, $status);
            concurrentCheck(pcntl_wifexited($status) && pcntl_wexitstatus($status) === 0, 'Процесс синхронизации завершился с ошибкой');
        }
        $children = [];
        foreach (array_keys(ManagedProtocol::NAMES) as $protocol) {
            $users = $bot->protocolStore($protocol)->read()['users'];
            $user = reset($users);
            $ok = match ($operation) {
                'disable' => count($users) === 1 && !$user['enabled'],
                'delete' => count($users) === 0,
                'rotate' => count($users) === 1 && $user['xray_credential'] === ManagedProtocol::xrayCredential($client),
            };
            if (!$ok) $failures[] = "$operation/$protocol";
        }
    }
    concurrentCheck(!$failures, 'Устаревшая синхронизация отменила изменения: ' . implode(', ', $failures));
    echo "protocol_shared_concurrency_test: OK (12 проверок)\n";
} finally {
    foreach ($children as $pid) pcntl_waitpid($pid, $status);
    $remove = static function ($path) use (&$remove) {
        if (is_dir($path)) { foreach (scandir($path) as $file) if ($file !== '.' && $file !== '..') $remove("$path/$file"); rmdir($path); }
        else unlink($path);
    };
    $remove($root);
}
