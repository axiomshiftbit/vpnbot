<?php
// Реальные файлы и flock в двух процессах; внешние протоколы и Telegram исключены.
$source = getenv('VPNBOT_TEST_SOURCE') ?: dirname(__DIR__);
require_once $source . '/app/bot.php';
class PacRaceBot extends Bot {
    public string $dir;
    public bool $pauseRead = false;
    public function __construct(string $dir) { $this->dir = $dir; $this->pac = "$dir/pac.json"; $this->language = 'ru'; }
    public function getPacConf() {
        $conf = parent::getPacConf();
        if ($this->pauseRead) {
            $this->pauseRead = false;
            touch($this->dir . '/read');
            $until = microtime(true) + 3;
            while (!is_file($this->dir . '/second') && microtime(true) < $until) usleep(1000);
            if (!is_file($this->dir . '/second')) throw new RuntimeException('second writer not ready');
            usleep(150000);
        }
        return $conf;
    }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) {
        $lock = fopen($this->dir . '/lock-' . $name, 'c');
        if (!$lock || !flock($lock, LOCK_EX)) return $busy;
        try { return $fn(); } finally { flock($lock, LOCK_UN); fclose($lock); }
    }
    public function menu($type = false, $arg = false, $return = false) {}
    public function xray($page = 0) {}
}
if (($argv[1] ?? '') === 'worker') {
    $bot = new PacRaceBot($argv[2]);
    if ($argv[4] === 'first') $bot->pauseRead = true;
    else touch($argv[2] . '/second');
    $method = $argv[3];
    $method === 'setLang' ? $bot->setLang('en') : $bot->$method(1);
    exit(0);
}
$dir = sys_get_temp_dir() . '/pac-writer-race-' . bin2hex(random_bytes(8)); mkdir($dir, 0700);
$failed = 0;
try {
    foreach (['selectWG', 'listXr'] as $method) {
        foreach (['read', 'second'] as $flag) @unlink("$dir/$flag");
        $bot = new PacRaceBot($dir); $bot->setPacConf(['language' => 'ru', 'wg_instance' => 0, 'keep' => ['synthetic' => true]]);
        $descriptors = [0 => ['file', '/dev/null', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']];
        $first = proc_open([PHP_BINARY, __FILE__, 'worker', $dir, $method, 'first'], $descriptors, $pipes);
        $until = microtime(true) + 3;
        while (!is_file("$dir/read") && microtime(true) < $until) usleep(1000);
        if (!is_file("$dir/read")) throw new RuntimeException('first writer not ready');
        $second = proc_open([PHP_BINARY, __FILE__, 'worker', $dir, 'setLang', 'second'], $descriptors, $pipes);
        $a = proc_close($first); $b = proc_close($second);
        $conf = $bot->getPacConf(); $key = $method === 'selectWG' ? 'wg_instance' : 'xtlslist';
        $ok = $a === 0 && $b === 0 && ($conf['language'] ?? '') === 'en'
            && ($conf[$key] ?? null) === 1 && ($conf['keep']['synthetic'] ?? false);
        if (!$ok) { $failed++; echo "FAIL: $method preserves simultaneous unrelated update\n"; }
        // Положительный контроль: два обычных последовательных изменения тоже сохраняются.
        $bot->setLang('ru'); $bot->$method(0); $conf = $bot->getPacConf();
        if (($conf['language'] ?? '') !== 'ru' || ($conf[$key] ?? null) !== 0) { $failed++; echo "FAIL: sequential control\n"; }
    }
} finally {
    foreach (glob("$dir/*") as $path) unlink($path); rmdir($dir);
}
echo "pac_writer_race_test: $failed failure(s)\n";
exit($failed ? 1 : 0);
