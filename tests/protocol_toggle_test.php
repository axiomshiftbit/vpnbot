<?php
require_once __DIR__ . '/../app/bot.php';
set_error_handler(static function ($level, $message, $file, $line) {
    if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line);
    return true;
});
if (!function_exists('pcntl_fork')) { echo "protocol_toggle_test: SKIP (pcntl)\n"; exit; }

class ToggleFixtureBot extends Bot {
    public string $fixture;
    public bool $slow = false;
    public function __construct(string $root) {
        $this->fixture = $root; $this->protocolRoot = "$root/protocols";
        $this->protocolModulesFile = "$root/modules.json"; $this->admin = true;
    }
    public function protocolModulesMenu(): void {}
    public function protocolMenu(string $protocol, string $id = '', int $page = 0): void {}
    public function protocolError(string $message, string $back = '/protocolModules', string $retry = ''): void { throw new RuntimeException($message); }
    public function syncManagedUpstreams(): void {}
    public function syncXrayProtocolUsers(): void {}
    public function getPacConf() { return self::PAC_DEFAULTS; }
    public function prepareProtocolSelfHost(): void {
        if (!$this->slow) return;
        touch($this->fixture . '/old-read');
        $deadline = microtime(true) + 1;
        while (!is_file($this->fixture . '/new-done') && microtime(true) < $deadline) usleep(10000);
    }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) {
        $lock = fopen($this->fixture . "/$name.lock", 'c'); flock($lock, LOCK_EX);
        try { return $fn(); } finally { flock($lock, LOCK_UN); fclose($lock); }
    }
}
function toggleCheck(bool $ok, string $message): void { if (!$ok) throw new RuntimeException($message); }
$root = sys_get_temp_dir() . '/vpnbot-toggle-' . bin2hex(random_bytes(6)); mkdir($root, 0700);
$children = []; $errors = [];
try {
    $bot = new ToggleFixtureBot($root);
    $modules = new ProtocolModules($bot->protocolModulesFile); $modules->set('oc', true);
    $lock = fopen($bot->protocolModulesFile . '.lock', 'c'); flock($lock, LOCK_EX);
    for ($n = 0; $n < 2; $n++) {
        $pid = pcntl_fork(); toggleCheck($pid !== -1, 'fork failed');
        if ($pid === 0) { fclose($lock); $bot->protocolModulesToggle('oc'); exit; }
        $children[] = $pid;
    }
    // Both workers must reach the locked write before releasing the parent.
    $deadline = microtime(true) + 5;
    do {
        $waiting = count(array_filter($children, static fn($pid) => str_contains((string) @file_get_contents("/proc/$pid/wchan"), 'lock')));
        if ($waiting === 2) break;
        usleep(10000);
    } while (microtime(true) < $deadline);
    flock($lock, LOCK_UN); fclose($lock);
    foreach ($children as $pid) { pcntl_waitpid($pid, $status); toggleCheck(pcntl_wexitstatus($status) === 0, 'toggle worker failed'); } $children = [];
    if (!$modules->enabled('oc')) $errors[] = 'Два одновременных переключения OpenConnect потеряли одно нажатие';

    $bot->protocolStore('anytls')->configure(['host'=>'vpn.example.test','sni'=>'vpn.example.test','self_hosted'=>true], false);
    $pid = pcntl_fork(); toggleCheck($pid !== -1, 'fork failed');
    if ($pid === 0) { $bot->slow = true; $bot->protocolCommand('anytls', 'toggle'); exit; }
    $children[] = $pid;
    $deadline = microtime(true) + 5;
    while (!is_file("$root/old-read") && microtime(true) < $deadline) usleep(10000);
    toggleCheck(is_file("$root/old-read"), 'Первое нажатие не началось');
    $bot->protocolCommand('anytls', 'toggle'); touch("$root/new-done");
    pcntl_waitpid($pid, $status); $children = [];
    if ($bot->protocolStore('anytls')->read()['enabled'] || $modules->enabled('anytls')) $errors[] = 'Два переключения AnyTLS потеряли одно нажатие';
    // Desired state must roll back when the separate container-state write fails.
    $modulePath = $bot->protocolModulesFile;
    $bot->protocolModulesFile = "$root/missing/modules.json";
    try { $bot->protocolCommand('anytls', 'toggle'); $errors[] = 'Ошибка записи модуля не сообщена'; }
    catch (RuntimeException $e) {}
    if ($bot->protocolStore('anytls')->read()['enabled']) $errors[] = 'Неудачное включение оставило противоречивое desired state';
    $bot->protocolModulesFile = $modulePath;
    toggleCheck(!$errors, implode('; ', $errors));
    echo "protocol_toggle_test: OK\n";
} finally {
    foreach ($children as $pid) pcntl_waitpid($pid, $status);
    $remove = static function ($path) use (&$remove) {
        if (is_dir($path)) { foreach (scandir($path) as $file) if ($file !== '.' && $file !== '..') $remove("$path/$file"); rmdir($path); }
        else unlink($path);
    }; $remove($root);
}
