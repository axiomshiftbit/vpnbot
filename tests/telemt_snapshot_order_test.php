<?php
// AUX-01: два процесса (меню и cron) опрашивают одно поколение ядра TeleMT.
// Снимок, полученный раньше, но записанный позже, не должен считаться сбросом
// счётчика и завышать накопленный трафик. API ядра подменён снимками.
require_once __DIR__ . '/../app/bot.php';
set_error_handler(static function ($level, $message, $file, $line) { if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line); return true; });

class TelemtOrderBot extends Bot
{
    public array $conf = ['telemt_users' => ['alice' => 'abababababababababababababababab']];
    public array $snapshots = [];      // очередь ответов API
    public ?TelemtOrderBot $racer = null;
    public function __construct(public string $root) { $this->language = 'ru'; $this->input = []; }
    public function getPacConf() { return $this->conf; }
    public function protocolModuleEnabled(string $module): bool { return true; }
    public function telemtServiceRunning(): bool { return true; }
    public function telemtActivityPath(): string { return "$this->root/activity.json"; }
    // Межпроцессная блокировка в одном процессе теста: занятый замок ставит
    // второй «процесс» в очередь, он выполнится после освобождения (как flock).
    public static bool $held = false;
    public static array $waiting = [];
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) {
        if (self::$held) { self::$waiting[] = $fn; return true; }
        self::$held = true;
        try { $result = $fn(); } finally { self::$held = false; }
        while ($next = array_shift(self::$waiting)) $this->withLock($name, $next);
        return $result;
    }
    public function telemtApiFetch(array $paths): array {
        $octets = array_shift($this->snapshots);
        // Пока этот ответ «в пути», другой процесс успевает опросить ядро и записать.
        if ($this->racer) { $racer = $this->racer; $this->racer = null; $racer->trackTelemtOnline(true); }
        return ['/v1/users' => [['username' => 'alice', 'current_connections' => 1, 'active_unique_ips_list' => [],
            'recent_unique_ips_list' => [], 'total_octets' => $octets]],
            '/v1/system/info' => ['process_started_at_epoch_secs' => 1700000000], '/v1/stats/users/quota' => ['users' => []]];
    }
}

$root = sys_get_temp_dir() . '/vpnbot-telemt-order-' . bin2hex(random_bytes(6));
mkdir($root, 0700);
$failed = 0; $count = 0;
$check = static function (bool $ok, string $what) use (&$failed, &$count) { $count++; if (!$ok) { $failed++; echo "FAIL: $what\n"; } };
try {
    $menu = new TelemtOrderBot($root); $cron = new TelemtOrderBot($root);
    $menu->snapshots = [0]; $menu->trackTelemtOnline(true);          // начало учёта
    // Меню получает 100 и задерживается; cron тем временем получает 150 и сохраняет.
    $menu->snapshots = [100]; $cron->snapshots = [150]; $menu->racer = $cron;
    $menu->trackTelemtOnline(true);
    $bytes = (int) ($menu->getTelemtActivity()['users']['alice']['bytes'] ?? -1);
    $check($bytes === 150, "устаревший снимок не завышает трафик (ожидалось 150, получено $bytes)");
    // Следующий настоящий снимок прибавляет только прирост.
    $cron->snapshots = [180]; $cron->trackTelemtOnline(true);
    $bytes = (int) ($cron->getTelemtActivity()['users']['alice']['bytes'] ?? -1);
    $check($bytes === 180, "дальше считается только прирост (ожидалось 180, получено $bytes)");
} finally {
    exec('rm -rf ' . escapeshellarg($root));
}
echo "telemt_snapshot_order_test: " . ($count - $failed) . "/$count\n";
exit($failed ? 1 : 0);
