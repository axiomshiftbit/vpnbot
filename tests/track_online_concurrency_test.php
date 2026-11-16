<?php
// CORE-03 (аудит A): меню и cron одновременно вызывают trackOnline(). Строки
// журнала Xray между общим offset и концом файла должны учитываться ровно один
// раз. Журнал и состояние синтетические, второй «процесс» запускается, пока
// первый ещё не сохранил offset.
require_once __DIR__ . '/../app/bot.php';
set_error_handler(static function ($level, $message, $file, $line) { if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line); return true; });

class OnlineRaceBot extends Bot
{
    public static array $state = [], $recorded = [];
    public static bool $held = false;
    public static array $waiting = [];
    public ?OnlineRaceBot $racer = null;
    public function __construct(string $log) { $this->xrayLog = $log; $this->language = 'ru'; $this->input = []; }
    public function getOnlineState(): array { return self::$state; }
    public function setOnlineState($s) { self::$state = $s; return true; }
    public function xrayOnlineIps(): ?array { return []; }
    public function recordConnLog(array $events) {
        // Другой процесс читает тот же хвост журнала, пока этот ещё не записал offset.
        if ($this->racer) { $racer = $this->racer; $this->racer = null; $racer->trackOnline(); }
        foreach ($events as $e) self::$recorded[] = $e['email'] . '@' . $e['ip'];
    }
    // flock в одном процессе: занятый замок ставит второй вызов в очередь.
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) {
        if (self::$held) { self::$waiting[] = $fn; return $busy; }
        self::$held = true;
        try { $result = $fn(); } finally { self::$held = false; }
        while ($next = array_shift(self::$waiting)) $this->withLock($name, $next);
        return $result;
    }
}

$log = sys_get_temp_dir() . '/vpnbot-online-race-' . bin2hex(random_bytes(6)) . '.log';
$failed = 0; $count = 0;
$check = static function (bool $ok, string $what) use (&$failed, &$count) { $count++; if (!$ok) { $failed++; echo "FAIL: $what\n"; } };
try {
    file_put_contents($log, '');
    $menu = new OnlineRaceBot($log); $cron = new OnlineRaceBot($log);
    $menu->trackOnline();   // начальный offset — конец пустого журнала
    file_put_contents($log, "2026/11/16 10:00:00 from 203.0.113.7:5000 accepted tcp:example.com:443 [in >> out] email: alice\n"
        . "2026/11/16 10:00:01 from 203.0.113.8:5001 accepted tcp:example.org:443 [in >> out] email: bob\n", FILE_APPEND);
    $menu->racer = $cron;
    $menu->trackOnline();
    sort(OnlineRaceBot::$recorded);
    $check(OnlineRaceBot::$recorded === ['alice@203.0.113.7', 'bob@203.0.113.8'], 'каждая строка журнала учтена один раз: ' . implode(',', OnlineRaceBot::$recorded));
    $check(isset(OnlineRaceBot::$state['seen']['alice'], OnlineRaceBot::$state['seen']['bob']), 'онлайн-состояние содержит обоих клиентов');
} finally {
    @unlink($log);
}
echo "track_online_concurrency_test: " . ($count - $failed) . "/$count\n";
exit($failed ? 1 : 0);
