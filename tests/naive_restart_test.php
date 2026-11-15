<?php
$root = sys_get_temp_dir() . '/vpnbot-naive-restart-' . bin2hex(random_bytes(6)); mkdir($root, 0700);
// Изолируем абсолютный путь Caddyfile, выполняя штатный код генератора.
$source = file_get_contents(__DIR__ . '/../app/bot.php');
$source = str_replace(['__DIR__', '/config/Caddyfile'], [var_export(dirname(__DIR__) . '/app', true), "$root/Caddyfile"], $source);
file_put_contents("$root/bot.php", $source);
require "$root/bot.php";

class NaiveRestartBot extends Bot
{
    public bool $failWrite = false;
    public bool $slow = false;
    public array $commands = [];
    public function __construct(public string $root) { $this->pac = "$root/pac.json"; }
    public function getPacConf() {
        $conf = parent::getPacConf();
        if ($this->slow) { touch("$this->root/old-read"); usleep(300000); }
        return $conf;
    }
    public function getHashSubdomain($type) { return 'naive'; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) {
        $lock = fopen("$this->root/$name.lock", 'c'); flock($lock, LOCK_EX);
        try { return $fn(); } finally { flock($lock, LOCK_UN); fclose($lock); }
    }
    public function writePrivateKey(string $path, string $data): bool {
        return !$this->failWrite && parent::writePrivateKey($path, $data);
    }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') {
        $this->commands[] = $cmd;
        if (str_contains($cmd, 'service_supervisor.sh restart naive')) {
            copy("$this->root/Caddyfile", "$this->root/active");
            return 'VPNBOT_SERVICE_READY:naive';
        }
        return str_starts_with($cmd, 'caddy validate') ? 'VPNBOT_NAIVE_VALID' : '';
    }
    public function menu($type = false, $arg = false, $return = false) {}
}

$failures = []; $children = [];
$check = static function ($ok, $name) use (&$failures) { if (!$ok) $failures[] = $name; };
try {
    $b = new NaiveRestartBot($root);
    file_put_contents("$root/Caddyfile", "forward_proxy {\n    basic_auth before before\n}\n");
    $b->setPacConf(['domain' => 'vpn.example.test', 'naive' => ['user' => 'before', 'pass' => 'current']]);
    $b->restartNaive();
    $check(is_file("$root/active"), 'Действующие реквизиты запускают Caddy');
    $check(str_contains(file_get_contents("$root/active"), 'basic_auth before current'),
        'Отступ пробелами не мешает отзыву старого пароля');
    $check((fileperms("$root/Caddyfile") & 0777) === 0600, 'Конфиг с паролем доступен только владельцу');
    $before = file_get_contents("$root/Caddyfile"); $b->commands = []; $b->failWrite = true;
    $rejected = false;
    try { $b->restartNaive(); } catch (RuntimeException $e) { $rejected = true; }
    $check($rejected && !$b->commands && file_get_contents("$root/Caddyfile") === $before,
        'Ошибка записи сохраняет конфиг и работающий процесс');
    $b->failWrite = false;
    if (function_exists('pcntl_fork')) {
        $pid = pcntl_fork();
        if ($pid === 0) { $b->slow = true; $b->restartNaive(); exit(0); }
        $children[] = $pid;
        $deadline = microtime(true) + 5;
        while (!is_file("$root/old-read") && microtime(true) < $deadline) usleep(10000);
        $b->chnppass('latest'); pcntl_waitpid($pid, $status); $children = [];
        $check(str_contains(file_get_contents("$root/active"), 'basic_auth before latest'),
            'Старый restart не восстанавливает отозванный пароль');
    }
    $b->setPacConf(['domain' => 'vpn.example.test', 'naive' => ['user' => 'CHANGEME', 'pass' => 'CHANGEME']]);
    $b->commands = []; $b->restartNaive();
    $check(!array_filter($b->commands, static fn($cmd) => str_starts_with($cmd, 'caddy run')),
        'Плейсхолдер не запускает сервис с общеизвестным паролем');
    $b->setPacConf(['domain' => 'vpn.example.test', 'naive' => ['user' => 'before', 'pass' => 'latest']]);
    file_put_contents("$root/Caddyfile", "forward_proxy {\n    hide_ip\n}\n"); $b->commands = [];
    $check($b->restartNaive() === false && !$b->commands,
        'Конфиг без basic_auth не запускается как открытый прокси');
} finally {
    foreach ($children as $pid) pcntl_waitpid($pid, $status);
    foreach (glob("$root/*") as $file) unlink($file);
    rmdir($root);
}
foreach ($failures as $failure) echo "FAIL: $failure\n";
if ($failures) exit(1);
echo "naive_restart_test OK\n";
