<?php

// Хранилище SQLite (app/BotStore.php): устройства HWID и журнал подключений.
//
// Главное — равенство: те же операции через JSON (прежний путь, образ без
// pdo_sqlite) и через SQLite дают одинаковые данные, включая пределы журнала
// (30 дней, 50 назначений, 50 адресов, 200 клиентов). Плюс однократный перенос
// JSON, права файла, гонка регистраций, отказ базы без тихого перехода на JSON.

require_once __DIR__ . '/../app/bot.php';

if (!extension_loaded('pdo_sqlite')) {
    echo "store_test SKIP: нет pdo_sqlite (в CI и образе php он есть)\n";
    exit(0);
}

set_error_handler(static function ($level, $message, $file, $line) {
    if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line);
    return false;
});

$checks = 0;
function stCheck(bool $ok, string $label): void
{
    global $checks;
    if (!$ok) throw new RuntimeException($label);
    $checks++;
}

class StoreBot extends Bot
{
    public bool $json = false;
    public function __construct(string $root) { $this->hwid = "$root/hwid.json"; }
    public function store(): ?PDO { return $this->json ? null : parent::store(); }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
}

function stRoot(): string
{
    $root = sys_get_temp_dir() . '/vpnbot-store-' . bin2hex(random_bytes(6));
    mkdir($root, 0700);
    return $root;
}
function stClean(string $root): void
{
    foreach (glob("$root/{,.}*", GLOB_BRACE) ?: [] as $f) if (is_file($f)) unlink($f);
    rmdir($root);
}
// Порядок ключей у JSON и SQLite совпадать не обязан: сравниваем содержимое.
function stSort(array $a): array
{
    ksort($a);
    foreach ($a as &$v) if (is_array($v)) $v = stSort($v);
    return $a;
}

// ── 1. Открытие, права, перенос JSON ────────────────────────────────────────
$root = stRoot();
try {
    $now = time();
    file_put_contents("$root/hwid.json", json_encode(['u1' => ['devA' => ['time' => 1, 'user_agent' => 'Happ']]]));
    file_put_contents("$root/connlog.json", json_encode(['alice' => ['last' => $now, 'ips' => ['198.51.100.1' => ['first' => $now - 5, 'last' => $now, 'count' => 3, 'dst' => ['example.com:443' => ['first' => $now - 5, 'last' => $now, 'count' => 2]]]]]]));
    $b = new StoreBot($root);
    stCheck($b->store() instanceof PDO, 'база открыта');
    stCheck((fileperms("$root/vpnbot.sqlite") & 0777) === 0600, 'файл базы только для владельца');
    stCheck(strtolower((string) $b->store()->query('PRAGMA journal_mode')->fetchColumn()) === 'wal', 'режим WAL');
    stCheck($b->getHwidStorage() === ['u1' => ['devA' => ['time' => 1, 'user_agent' => 'Happ']]], 'HWID перенесён из JSON');
    stCheck($b->getConnLog()['alice']['ips']['198.51.100.1']['dst']['example.com:443']['count'] === 2, 'журнал подключений перенесён');
    file_put_contents("$root/hwid.json", json_encode(['u9' => ['devZ' => []]]));
    $again = new StoreBot($root);
    stCheck(array_keys($again->getHwidStorage()) === ['u1'], 'перенос однократный: JSON после переноса не читается');
    stCheck(json_decode(file_get_contents("$root/hwid.json"), true) === ['u9' => ['devZ' => []]], 'JSON-файл не удаляется (откат на образ без SQLite)');
} finally {
    stClean($root);
}

// ── 2. HWID: те же операции через JSON и SQLite ─────────────────────────────
$results = [];
foreach (['json', 'sqlite'] as $mode) {
    $root = stRoot();
    try {
        $b = new StoreBot($root);
        $b->json = $mode === 'json';
        $log = [];
        $log[] = $b->hwidRegister('u1', 'devA', 1, ['time' => 1]);
        $log[] = $b->hwidRegister('u1', 'devB', 1, ['time' => 2]);
        $log[] = $b->hwidRegister('u1', 'devA', 1, ['time' => 3]);
        $log[] = $b->hwidRegister('u2', 'devA', 2, ['time' => 4]);
        $log[] = $b->hwidRegister('u2', 'devC', 2, ['time' => 5]);
        $log[] = $b->hwidRegister('u2', 'devD', 2, ['time' => 6]);
        $b->setHwidDevice('u3', 'devE', ['time' => 7, 'device_os' => 'Android']);
        $b->deleteHwidDevice('u2', 'devA');
        $log[] = $b->getHwidDevicesByUser('u2');
        $log[] = $b->getHwidDevicesByUser('nobody');
        $b->deleteHwidUser('u3');
        $log[] = $b->hwidUpdate(function (array &$storage) { $storage['u4']['devF'] = ['time' => 8]; return 'ok'; });
        $log[] = $b->getHwidStorage();
        $b->setHwidStorage(['u5' => ['devG' => ['time' => 9]]]);
        $log[] = $b->getHwidStorage();
        $results[$mode] = $log;
    } finally {
        stClean($root);
    }
}
stCheck($results['json'] === $results['sqlite'], 'HWID: JSON и SQLite дают одинаковые ответы и данные');
stCheck($results['sqlite'][0] === true && $results['sqlite'][1] === false && $results['sqlite'][2] === true, 'HWID: лимит 1 — второе устройство отклонено, повтор первого принят');
stCheck($results['sqlite'][6] === ['devC' => ['time' => 5]], 'HWID: удаление одного устройства');

// Порядок устройств сохраняется при обновлении сведений (как у JSON).
$root = stRoot();
try {
    $b = new StoreBot($root);
    $b->hwidRegister('u', 'first', 5, ['time' => 1]);
    $b->hwidRegister('u', 'second', 5, ['time' => 2]);
    $b->hwidRegister('u', 'first', 5, ['time' => 3]);
    stCheck(array_keys($b->getHwidDevicesByUser('u')) === ['first', 'second'], 'HWID: обновление не меняет порядок');
    stCheck($b->getHwidDevicesByUser('u')['first'] === ['time' => 3], 'HWID: сведения обновлены');
    // Ненадёжный ввод: имя устройства и сведения с битым UTF-8 не роняют запись.
    stCheck($b->hwidRegister('u', "x'); DROP TABLE hwid;--", 5, ['user_agent' => "bad\xff"]) && count($b->getHwidDevicesByUser('u')) === 3, 'HWID: параметры запроса, не склейка SQL');
} finally {
    stClean($root);
}

// Гонка: параллельные процессы регистрируют разные устройства при лимите 2.
if (function_exists('pcntl_fork')) {
    $root = stRoot();
    try {
        (new StoreBot($root))->store();
        $children = [];
        for ($n = 0; $n < 8; $n++) {
            $pid = pcntl_fork();
            if ($pid === 0) {
                $child = new StoreBot($root);
                exit($child->hwidRegister('race', "dev$n", 2, ['time' => $n]) ? 0 : 10);
            }
            $children[] = $pid;
        }
        $accepted = 0;
        foreach ($children as $pid) {
            pcntl_waitpid($pid, $status);
            stCheck(pcntl_wifexited($status) && in_array(pcntl_wexitstatus($status), [0, 10], true), 'гонка: процесс завершился штатно');
            if (pcntl_wexitstatus($status) === 0) $accepted++;
        }
        stCheck($accepted === 2 && count((new StoreBot($root))->getHwidDevicesByUser('race')) === 2, 'гонка: из 8 одновременных устройств принято ровно 2');
    } finally {
        stClean($root);
    }
}

// ── 3. Журнал подключений: равенство и пределы ──────────────────────────────
$now = time();
$events = [];
for ($i = 0; $i < 60; $i++) $events[] = ['email' => 'alice', 'ip' => '198.51.100.1', 'dst' => "host$i.test:443", 'ts' => $now - 100 + $i];
for ($i = 0; $i < 5; $i++) $events[] = ['email' => 'alice', 'ip' => '198.51.100.1', 'dst' => 'host59.test:443', 'ts' => $now];
for ($i = 0; $i < 55; $i++) $events[] = ['email' => 'bob', 'ip' => "198.51.100.$i", 'dst' => null, 'ts' => $now - 60 + $i];
for ($i = 0; $i < 205; $i++) $events[] = ['email' => "user$i", 'ip' => '203.0.113.1', 'dst' => 'x.test:80', 'ts' => $now - 1000 + $i];
$events[] = ['email' => 'old', 'ip' => '203.0.113.9', 'dst' => 'y.test:80', 'ts' => $now - 2592000 - 10];
$logs = [];
foreach (['json', 'sqlite'] as $mode) {
    $root = stRoot();
    try {
        $b = new StoreBot($root);
        $b->json = $mode === 'json';
        foreach (array_chunk($events, 37) as $chunk) $b->recordConnLog($chunk);
        $logs[$mode] = stSort($b->getConnLog());
        $b->setConnLog([]);
        $logs[$mode . '-cleared'] = $b->getConnLog();
    } finally {
        stClean($root);
    }
}
stCheck($logs['json'] === $logs['sqlite'], 'журнал: JSON и SQLite совпадают после пределов');
$alice = $logs['sqlite']['alice']['ips']['198.51.100.1'] ?? [];
stCheck(count($alice['dst'] ?? []) === 50 && ($alice['dst']['host59.test:443']['count'] ?? 0) === 6 && $alice['count'] === 65, 'журнал: 50 назначений, счётчики');
stCheck(count($logs['sqlite']['bob']['ips'] ?? []) === 50, 'журнал: 50 адресов на клиента');
stCheck(count($logs['sqlite']) === 200 && !isset($logs['sqlite']['old']), 'журнал: 200 клиентов, старше 30 дней — удалены');
stCheck($logs['json-cleared'] === [] && $logs['sqlite-cleared'] === [], 'журнал: очистка');

// ── 4. Отказ базы: без тихого перехода на JSON ──────────────────────────────
$root = stRoot();
try {
    file_put_contents("$root/vpnbot.sqlite", str_repeat("not a database\n", 100));
    $b = new StoreBot($root);
    $failed = 0;
    for ($n = 0; $n < 2; $n++) {
        try { $b->getHwidStorage(); } catch (RuntimeException $e) { $failed++; }
    }
    stCheck($failed === 2, 'повреждённая база: ошибка видна, без тихого JSON, повтор не закеширован');
    // Выдача подписки при сбое хранилища не падает (лимит мягкий, как раньше).
    $_SERVER['HTTP_X_HWID'] = 'devA';
    $sub = new class($root) extends StoreBot {
        public function getPacConf() { return ['hwid_limit_enabled' => 1, 'hwid_device_count' => 1]; }
    };
    file_put_contents("$root/vpnbot.sqlite", 'broken');
    stCheck(@$sub->processHwidRequest(['id' => 'u1']) === true, 'сбой хранилища: подписка выдаётся, ошибка в журнале');
} finally {
    stClean($root);
}

echo "store_test OK ($checks проверок)\n";
