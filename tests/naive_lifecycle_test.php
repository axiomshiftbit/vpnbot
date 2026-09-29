<?php
require_once __DIR__ . '/../app/bot.php';

class NaiveLifecycleBot extends Bot
{
    public bool $slow = false;
    public bool $failWrite = false;
    public int $restarts = 0;
    public function __construct(public string $root) { $this->pac = "$root/pac.json"; }
    public function getPacConf() {
        $conf = parent::getPacConf();
        if ($this->slow) {
            touch("$this->root/old-read");
            $deadline = microtime(true) + 1;
            while (!is_file("$this->root/new-done") && microtime(true) < $deadline) usleep(10000);
        }
        return $conf;
    }
    public function setPacConf(array $conf) { return !$this->failWrite && parent::setPacConf($conf); }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) {
        $lock = fopen("$this->root/$name.lock", 'c'); flock($lock, LOCK_EX);
        try { return $fn(); } finally { flock($lock, LOCK_UN); fclose($lock); }
    }
    public function restartNaive() { $this->restarts++; }
    public function menu($type = false, $arg = false, $return = false) {}
}

$root = sys_get_temp_dir() . '/vpnbot-naive-lifecycle-' . bin2hex(random_bytes(6)); mkdir($root, 0700);
$failures = []; $children = [];
$check = static function ($ok, $name) use (&$failures) { if (!$ok) $failures[] = $name; };
try {
    $bot = new NaiveLifecycleBot($root);
    $bot->setPacConf(['domain' => 'vpn.example.test', 'naive' => ['user' => 'before', 'pass' => 'before']]);
    if (function_exists('pcntl_fork')) {
        $pid = pcntl_fork();
        if ($pid === 0) { $bot->slow = true; $bot->chnplogin('after'); exit(0); }
        $children[] = $pid;
        $deadline = microtime(true) + 5;
        while (!is_file("$root/old-read") && microtime(true) < $deadline) usleep(10000);
        $check(is_file("$root/old-read"), 'Первое изменение прочитало исходный конфиг');
        $bot->chnppass('new-password'); touch("$root/new-done");
        pcntl_waitpid($pid, $status); $children = [];
        $check(pcntl_wifexited($status) && pcntl_wexitstatus($status) === 0, 'Параллельное изменение завершилось');
        $check($bot->getPacConf()['naive'] === ['user' => 'after', 'pass' => 'new-password'],
            'Одновременная смена логина не возвращает старый пароль');
    }
    $before = file_get_contents($bot->pac); $bot->failWrite = true; $bot->restarts = 0;
    foreach (['chnplogin', 'chnppass'] as $method) {
        $rejected = false;
        try { $bot->$method('not-saved'); } catch (RuntimeException $e) { $rejected = true; }
        $check($rejected, "$method сообщает отказ записи");
    }
    $check($bot->restarts === 0 && file_get_contents($bot->pac) === $before,
        'Ошибка сохранения не перезапускает сервис');
} finally {
    foreach ($children as $pid) pcntl_waitpid($pid, $status);
    foreach (glob("$root/*") as $file) unlink($file);
    rmdir($root);
}
foreach ($failures as $failure) echo "FAIL: $failure\n";
if ($failures) exit(1);
echo "naive_lifecycle_test OK\n";
