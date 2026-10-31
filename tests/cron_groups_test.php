<?php

// Периодика в двух процессах: access (сроки, лимиты, учёт, онлайн — только
// локальные операции) и maintenance (сетевые и медленные проверки), чтобы
// проба узлов или загрузка .dat не задерживали отключение по сроку и лимиту.
//  1. разбиение: группы не пересекаются, вместе — прежний список, сетевых
//     шагов в access нет;
//  2. надзор: cron.php (access) поднимает упавший maintenance;
//  3. шаги access, меняющие xray.json, идут под блокировкой xray (параллельно
//     с maintenance и обработчиками Telegram), уведомление — вне блокировки.

require_once __DIR__ . '/../app/bot.php';

set_error_handler(static function ($level, $message, $file, $line) {
    if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line);
    return false;
});

$checks = 0;
function cgCheck(bool $ok, string $label): void
{
    global $checks;
    if (!$ok) throw new RuntimeException($label);
    $checks++;
}

// ── 1. Разбиение ────────────────────────────────────────────────────────────
$source = (string) file_get_contents(__DIR__ . '/../app/bot.php');
$cron = substr($source, strpos($source, 'public function cron('), 4000);
preg_match('~\$steps = \[(.*?)\];~s', $cron, $m);
preg_match_all("~^\s*'([A-Za-z0-9_]+)',\s*$~m", $m[1], $all);
$all = $all[1];
$access = Bot::CRON_ACCESS;
cgCheck(count($all) >= 30 && !array_diff($access, $all), 'шаги access — из общего списка');
cgCheck(count($access) === count(array_unique($access)), 'шаги access без повторов');
$maintenance = array_values(array_diff($all, $access));
cgCheck(count($access) + count($maintenance) === count($all), 'группы не пересекаются и покрывают все шаги');
foreach (['shutdownClient', 'shutdownClientXr', 'xrayStatsUser', 'checkTrafficLimits', 'checkAccessPolicies', 'trackOnline'] as $step) {
    cgCheck(in_array($step, $access, true), "критичный шаг в access: $step");
}
foreach (['checkExitNodes', 'refreshExtSubCache', 'checkDatUpdates', 'checkVersion', 'checkBackup', 'checkRealityMask', 'checkRelayHealth', 'warmGeoCache', 'checkCert', 'checkXrayCore'] as $step) {
    cgCheck(in_array($step, $maintenance, true), "медленный шаг в maintenance: $step");
}
cgCheck(array_search('xrayStatsUser', $access, true) < array_search('checkTrafficLimits', $access, true), 'учёт трафика перед проверкой лимитов');

class CronBot extends Bot
{
    public array $ran = [], $locks = [], $sent = [];
    public int $passes = 0;
    public array $xr = [];
    public bool $restartOk = true;
    public function __construct() { $this->cronPeriod = 0; }
    protected function cronContinue(): bool { return $this->passes++ < 3; }
    public function __call($name, $args) { $this->ran[] = $name; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { $this->locks[] = [$name, $timeout]; return $fn(); }
    public function getXray() { return $this->xr; }
    public function getXrayStats() { return ['users' => [['global' => ['download' => 2000, 'upload' => 0]]]]; }
    public function xrayProtocolUsage(array $client): array { return []; }
    public function restartXray($c, $norestart = false) { $this->locks[] = ['restartXray', count($this->locks)]; $this->xr = $c; return $this->restartOk; }
    public function saveXray(array $c): void { $this->locks[] = ['saveXray', 0]; }
    public function notifyAdmins(string $text): void { $this->sent[] = $text; }
    public function switchXr($i, $nm = 0, $time = false) { $this->locks[] = ['switchXr', $i]; }
    public function ensureSubTokens(array &$xr): bool { return true; }
}
try {
    (new CronBot())->cron('bogus');
    cgCheck(false, 'неизвестная группа отклонена');
} catch (InvalidArgumentException $e) {
    cgCheck(true, 'неизвестная группа отклонена');
}

// ── 2. Надзор за maintenance ────────────────────────────────────────────────
$dir = sys_get_temp_dir() . '/vpnbot-cron-' . bin2hex(random_bytes(6));
mkdir($dir, 0700);
try {
    $script = "$dir/maintenance.php";
    // Дочерний процесс пишет свою группу и сразу «падает».
    file_put_contents($script, '<?php file_put_contents(__DIR__ . "/runs", ($argv[1] ?? "-") . "\n", FILE_APPEND); exit(1);');
    // Шаги access подменены: проверяется только порядок работы цикла.
    $access = new class extends CronBot {
        public function shutdownClient() { $this->ran[] = 'shutdownClient'; usleep(300000); }
        public function shutdownClientXr() { $this->ran[] = 'shutdownClientXr'; }
        public function checkResetXrayStats() { $this->ran[] = 'checkResetXrayStats'; }
        public function xrayStatsUser() { $this->ran[] = 'xrayStatsUser'; }
        public function checkTrafficLimits() { $this->ran[] = 'checkTrafficLimits'; }
        public function syncXrayProtocolUsers(): void { $this->ran[] = 'syncXrayProtocolUsers'; }
        public function checkAccessPolicies(?int $now = null): void { $this->ran[] = 'checkAccessPolicies'; }
        public function trackOnline(): array { $this->ran[] = 'trackOnline'; return []; }
        public function trackWgOnline(): void { $this->ran[] = 'trackWgOnline'; }
        public function trackTelemtOnline(bool $force = false): bool { $this->ran[] = 'trackTelemtOnline'; return true; }
        public function trackOvpnTraffic(): void { $this->ran[] = 'trackOvpnTraffic'; }
    };
    $access->cron('access', $script);
    $runs = file("$dir/runs", FILE_IGNORE_NEW_LINES) ?: [];
    cgCheck(count($runs) === 3 && array_unique($runs) === ['maintenance'], 'упавший maintenance поднимается на каждом проходе: ' . json_encode($runs));
    cgCheck(count(array_filter($access->ran, fn($s) => $s === 'shutdownClient')) === 3, 'access выполняет свои шаги каждый проход');
    cgCheck(array_unique($access->ran) === Bot::CRON_ACCESS, 'access выполняет ровно свои шаги по порядку');
} finally {
    @unlink("$dir/runs");
    @unlink("$dir/maintenance.php");
    rmdir($dir);
}

// ── 3. Блокировка xray в шагах access ───────────────────────────────────────
$b = new CronBot();
$b->xr = ['inbounds' => [['settings' => ['clients' => [['email' => 'alice', 'id' => 'a', 'traffic' => 1000]]]]]];
$b->checkTrafficLimits();
cgCheck($b->locks[0] === ['xray', 30] && $b->locks[1][0] === 'restartXray', 'лимит трафика: изменение и перезапуск под блокировкой xray (ожидание до 30 с)');
cgCheck(($b->xr['inbounds'][0]['settings']['clients'][0]['traffic_off'] ?? 0) === 1 && count($b->sent) === 1 && str_contains($b->sent[0], 'alice'), 'лимит трафика: клиент отключён, одно уведомление после блокировки');
$b = new CronBot();
$b->restartOk = false;
$b->xr = ['inbounds' => [['settings' => ['clients' => [['email' => 'alice', 'id' => 'a', 'traffic' => 1000]]]]]];
$b->checkTrafficLimits();
cgCheck($b->sent === [], 'ядро не приняло конфиг — уведомления «отключены» нет');
$b = new CronBot();
$b->xr = ['inbounds' => [['settings' => ['clients' => [['email' => 'bob', 'id' => 'b', 'time' => time() - 5]]]]]];
$b->shutdownClientXr();
cgCheck($b->locks === [['xray', 30], ['switchXr', 0]], 'истёкший срок: отключение под блокировкой xray');
$b = new CronBot();
$b->xr = ['inbounds' => [['settings' => ['clients' => []]]]];
$b->backfillSubTokens();
cgCheck($b->locks === [['xray', 30], ['saveXray', 0]], 'токены подписок: запись под блокировкой xray');

echo "cron_groups_test OK ($checks проверок)\n";
