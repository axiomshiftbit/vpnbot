<?php

// Menu → статус сервера: разбор /proc/meminfo и df, формат uptime, состав меню.

require_once __DIR__ . '/../app/bot.php';

function statusAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

class ServerStatusTestBot extends Bot
{
    public string $text = '';
    public array $buttons = [];
    public array $disks = [];

    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML')
    {
        $this->text = $text;
        $this->buttons = is_array($button) ? $button : [];
    }

    public function cpuUsage()
    {
        return 7;
    }

    // Свои числа вместо памяти машины, на которой идёт тест: под нагрузкой
    // сборки она бывает занята на 90 % и больше.
    public function memInfo(?string $meminfo = null)
    {
        return $meminfo === null ? [4 << 30, 16 << 30, 1 << 30, 4 << 30] : parent::memInfo($meminfo);
    }

    public function diskUsage(string $path): array
    {
        $this->disks[] = $path;
        return [30 << 30, 100 << 30, 65 << 30, 32];
    }
}

$bot = (new ReflectionClass(ServerStatusTestBot::class))->newInstanceWithoutConstructor();

// Память: занято = всего − MemAvailable (кеш занятым не считается), swap отдельно.
$meminfo = "MemTotal:       16000000 kB\nMemFree:          500000 kB\nMemAvailable:   12000000 kB\n"
    . "Buffers:          100000 kB\nCached:          9000000 kB\nSwapCached:            0 kB\n"
    . "SwapTotal:       4000000 kB\nSwapFree:        3000000 kB\n";
statusAssert($bot->memInfo($meminfo) === [4000000 * 1024, 16000000 * 1024, 1000000 * 1024, 4000000 * 1024], 'meminfo mismatch');
// Старое ядро без MemAvailable: свободное + буферы + кеш.
$old = "MemTotal: 1000 kB\nMemFree: 100 kB\nBuffers: 50 kB\nCached: 250 kB\n";
statusAssert($bot->memInfo($old) === [600 * 1024, 1000 * 1024, 0, 0], 'meminfo fallback mismatch');
statusAssert($bot->memInfo('') === [0, 0, 0, 0], 'empty meminfo must not fail');

// df: занятое берётся из своего столбца, а не как «всего минус доступно».
$df = Bot::parseDfLine('/dev/mapper/ubuntu--vg-ubuntu--lv 101589168 29032096 67351284      31% /');
statusAssert($df === [29032096 * 1024, 101589168 * 1024, 67351284 * 1024], 'df line mismatch');
statusAssert(Bot::parseDfLine('overlay 20466256 20466256 0 100% /') === [20466256 * 1024, 20466256 * 1024, 0], 'full disk mismatch');
statusAssert(Bot::parseDfLine('Filesystem 1024-blocks Used Available Capacity Mounted on') === null, 'df header parsed as data');
statusAssert(Bot::parseDfLine('') === null, 'empty df output parsed');

// Настоящая файловая система: числа согласованы, процент как у df.
$plain = (new ReflectionClass(Bot::class))->newInstanceWithoutConstructor();
[$used, $total, $avail, $percent] = $plain->diskUsage(sys_get_temp_dir());
statusAssert($total > 0 && $used >= 0 && $avail >= 0 && $used + $avail <= $total, 'disk numbers are inconsistent');
statusAssert($percent === (int) ceil($used / max(1, $used + $avail) * 100) && $percent <= 100, 'disk percent mismatch');
statusAssert($plain->diskUsage('/no/such/path/for/vpnbot')[1] === 0, 'missing path must give zeros');

statusAssert(Bot::fmtUptime(59) === '0m' && Bot::fmtUptime(1957) === '32m' && Bot::fmtUptime(3600) === '1h 0m'
    && Bot::fmtUptime(86400 * 45 + 3 * 3600 + 12 * 60 + 5) === '45d 3h 12m' && Bot::fmtUptime(86400 * 400) === '400d 0h 0m'
    && Bot::fmtUptime(-5) === '0m', 'uptime format mismatch');

statusAssert($plain->cpuCores() >= 1, 'cpu cores mismatch');
$cpu = $plain->cpuUsage();
statusAssert(is_int($cpu) && $cpu >= 0 && $cpu <= 100, 'cpu usage out of range');

$bot->language = 'en';
$bot->i18n = ['server status' => ['en' => 'server status'], 'refresh' => ['en' => 'refresh'], 'back' => ['en' => 'back']];
$bot->input = ['chat' => 1, 'message_id' => 2];
$bot->serverStatus();
foreach (['status time', 'status uptime', 'status kernel', '▓░░░░░░░░░ 7%', 'status load',
    'status used: 30.0 GB status of 100.0 GB', 'status free: 65.0 GB', '▓▓▓░░░░░░░ 32%',
    'status used: 4.0 GB status of 16.0 GB', 'status free: 12.0 GB', 'status swap: 1.0 GB status of 4.0 GB (25%)'] as $want) {
    statusAssert(str_contains($bot->text, $want), "status line missing: $want\n" . $bot->text);
}
statusAssert($bot->disks[0] === '/', 'root filesystem was not measured');
statusAssert(str_contains(json_encode($bot->buttons), '/status'), 'refresh button is missing');
statusAssert(substr_count($bot->text, '<code>') === substr_count($bot->text, '</code>')
    && substr_count($bot->text, '<b>') === substr_count($bot->text, '</b>'), 'markup is unbalanced');
statusAssert(!str_contains($bot->text, '⚠️') || sys_getloadavg()[0] > $plain->cpuCores(), 'warning shown without a reason');

statusAssert(Bot::usageBar(0) === '░░░░░░░░░░' && Bot::usageBar(100) === '▓▓▓▓▓▓▓▓▓▓' && Bot::usageBar(250) === '▓▓▓▓▓▓▓▓▓▓'
    && Bot::usageBar(-3) === '░░░░░░░░░░' && Bot::usageBar(55) === '▓▓▓▓▓▓░░░░', 'usage bar mismatch');
$block = $bot->usageBlock('Disk', 95 << 30, 100 << 30, 5 << 30, 95);
statusAssert(str_contains($block[0], '⚠️') && $block[3] === 'status free: 5.0 GB', 'near-full resource is not flagged');

statusAssert(str_contains($bot->text, 'status alerts hint'), 'alerts hint is missing');

// ── Загрузка процессора между двумя снимками ────────────────────────────────
statusAssert(Bot::cpuPercent([100, 1000], [150, 1500]) === 90 && Bot::cpuPercent([100, 1000], [600, 1500]) === 0
    && Bot::cpuPercent([100, 1000], [100, 1500]) === 100, 'cpu percent mismatch');
statusAssert(Bot::cpuPercent([100, 1000], [100, 1000]) === null && Bot::cpuPercent([900, 9000], [10, 100]) === null,
    'stalled or reset counters must give no sample');

// ── Оповещение о диске: порог 90 %, напоминание раз в сутки, отбой ниже 85 % ─
$pac = sys_get_temp_dir() . '/vpnbot-status-' . getmypid() . '.json';
try {
    $bot->pac = $pac;
    file_put_contents($pac, json_encode(['domain' => 'example.test']));
    $disk = fn(int $percent) => ['status disk' => [$percent << 30, 100 << 30, (100 - $percent) << 30, $percent]];
    $t = 1800000000;
    statusAssert($bot->diskAlertStep($disk(89), $t) === [], 'alert below the threshold');
    $first = $bot->diskAlertStep($disk(90), $t);
    statusAssert(count($first) === 1 && str_contains($first[0], '90%') && str_contains($first[0], 'status free 10.0 GB'), 'no alert at 90%: ' . json_encode($first));
    statusAssert($bot->diskAlertStep($disk(95), $t + 3600) === [], 'alert repeated within a day');
    statusAssert($bot->diskAlertStep($disk(87), $t + 7200) === [], 'hysteresis band must stay silent');
    statusAssert(count($bot->diskAlertStep($disk(96), $t + 86400)) === 1, 'daily reminder is missing');
    $clear = $bot->diskAlertStep($disk(60), $t + 90000);
    statusAssert(count($clear) === 1 && str_contains($clear[0], '✅'), 'recovery was not reported');
    $saved = json_decode(file_get_contents($pac), true);
    statusAssert(!isset($saved['disk_alert']) && ($saved['domain'] ?? '') === 'example.test', 'alert state was not cleared or settings were lost');
    statusAssert($bot->diskAlertStep($disk(60), $t + 90300) === [], 'recovery reported twice');
    statusAssert(count($bot->diskAlertStep($disk(91), $t + 90600)) === 1, 'new episode did not alert');
    statusAssert($bot->diskAlertStep(['status disk' => [0, 0, 0, 0]], $t + 91000) === [], 'unmeasured disk must be skipped');
    $two = $bot->diskAlertStep($disk(91) + ['status data disk' => [99 << 30, 100 << 30, 1 << 30, 99]], $t + 91200);
    statusAssert(count($two) === 1 && str_contains($two[0], 'status data disk'), 'second filesystem is not tracked separately');
} finally {
    @unlink($pac);
}

// ── Оповещение о процессоре: час на 90 % и выше ─────────────────────────────
$cpu = (new ReflectionClass(Bot::class))->newInstanceWithoutConstructor();
$t = 1800000000;
$events = [];
for ($i = 0; $i < 54; $i++) {
    $events[] = $cpu->cpuAlertStep(97, $t + $i * 60);
}
statusAssert(array_filter($events) === [], 'cpu alert before a full hour of samples');
statusAssert($cpu->cpuAlertStep(97, $t + 55 * 60) === ['high', 97], 'no cpu alert after an hour at 97%');
statusAssert($cpu->cpuAlertStep(99, $t + 56 * 60) === null, 'cpu alert repeated');
// Короткий провал тревогу не снимает; десять минут ниже 80 % — снимают.
statusAssert($cpu->cpuAlertStep(10, $t + 57 * 60) === null, 'single dip cleared the alert');
$ok = null;
for ($i = 58; $i < 75 && $ok === null; $i++) {
    $ok = $cpu->cpuAlertStep(15, $t + $i * 60);
}
statusAssert(is_array($ok) && $ok[0] === 'ok' && $ok[1] < 80, 'cpu recovery was not reported');
// Час с редкими всплесками тревогу не даёт.
$calm = (new ReflectionClass(Bot::class))->newInstanceWithoutConstructor();
for ($i = 0; $i < 70; $i++) {
    statusAssert($calm->cpuAlertStep($i % 3 === 0 ? 100 : 60, $t + $i * 60) === null, 'bursty load raised an alert');
}
// Замеры с дырой (cron стоял) за час не считаются.
$gap = (new ReflectionClass(Bot::class))->newInstanceWithoutConstructor();
for ($i = 0; $i < 20; $i++) {
    $gap->cpuAlertStep(100, $t + $i * 60);
}
statusAssert($gap->cpuAlertStep(100, $t + 3400) === null, 'sparse samples raised an alert');

echo "server_status_test OK\n";
