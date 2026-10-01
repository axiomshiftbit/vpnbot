<?php
require_once __DIR__ . '/../app/bot.php';
set_error_handler(static function ($level, $message, $file, $line) {
    if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line);
    return true;
});

class TelemtLifecycleBot extends Bot {
    public string $fixture;
    public bool $slow = false;
    public bool $failState = false;
    public function __construct(string $root) {
        $this->fixture = $root; $this->pac = "$root/pac.json"; $this->ip = '203.0.113.10'; $this->key = 'fixture';
        $this->protocolModulesFile = "$root/modules.json"; $this->admin = true;
    }
    public function getPacConf() {
        $conf = parent::getPacConf();
        if ($this->slow) {
            touch($this->fixture . '/old-read');
            $deadline = microtime(true) + 1;
            while (!is_file($this->fixture . '/new-done') && microtime(true) < $deadline) usleep(10000);
        }
        return $conf;
    }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) {
        $lock = fopen($this->fixture . "/$name.lock", 'c'); flock($lock, LOCK_EX);
        try { return $fn(); } finally { flock($lock, LOCK_UN); fclose($lock); }
    }
    public function telemtWriteToml(string $toml): void { file_put_contents($this->fixture . '/active.toml', $toml); }
    public function telemtWriteServiceState(bool $enabled): void {
        if ($this->failState) throw new RuntimeException('Ошибка записи состояния');
        file_put_contents($this->fixture . '/service-enabled', $enabled ? "1\n" : "0\n");
    }
    public function telemtUsers($relay = '', int $page = 0) {}
    public function telemtWebRefresh(bool $was): void {}
    public function cloakNginx() {}
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') { return str_contains($cmd, 'telemt_state.py') ? 'TELEMT_STATE_OK' : ''; }
}

class TelemtWriteGuardBot extends TelemtLifecycleBot {
    public bool $failWrite = false;
    public bool $failSettings = false;
    public int $sshCalls = 0;
    public function telemtWriteToml(string $toml): void { Bot::telemtWriteToml($toml); }
    public function writePrivateKey(string $path, string $data): bool {
        return !$this->failWrite && parent::writePrivateKey($this->fixture . '/written.toml', $data);
    }
    public function setPacConf(array $conf) {
        if ($this->failSettings) return false;
        return file_put_contents($this->pac, json_encode($conf)) !== false;
    }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') { $this->sshCalls++; return parent::ssh($cmd, $service, $wait, $log); }
}

$root = sys_get_temp_dir() . '/vpnbot-telemt-lifecycle-' . bin2hex(random_bytes(6)); mkdir($root, 0700);
$failures = []; $children = [];
$check = static function (bool $ok, string $name) use (&$failures): void { if (!$ok) $failures[] = $name; };
try {
    $bot = new TelemtLifecycleBot($root);
    $conf = ['telemt_users' => ['alice' => str_repeat('ab', 16)], 'telemt_user_enabled' => ['alice' => 0], 'telemt_web' => 0];
    $bot->setPacConf($conf);
    $bot->telemtUserAdd('alice');
    $check($bot->getPacConf()['telemt_users'] === $conf['telemt_users'], 'Повторное добавление не меняет секрет');
    $check($bot->getPacConf()['telemt_user_enabled'] === $conf['telemt_user_enabled'], 'Повторное добавление сохраняет отключение');

    $bot->ip = '2001:db8::1';
    $web = $conf + ['domain' => 'vpn.example.test', 'letsencrypt' => 'letsencrypt']; $web['telemt_web'] = 1;
    $check(str_contains($bot->telemtToml($web), 'public_addr = "[2001:db8::1]:443"'), 'IPv6 WEB содержит скобки');
    foreach (['0.0.0.0', '::', '0:0:0:0:0:0:0:0'] as $address) {
        $bot->ip = $address;
        $check(in_array('telemt web need ip', $bot->telemtWebBlockers($web), true), 'WEB отклоняет неопределённый адрес ' . $address);
    }

    if (function_exists('pcntl_fork')) {
        $bot->ip = '203.0.113.10'; unset($conf['telemt_user_enabled']); $bot->setPacConf($conf);
        $pid = pcntl_fork();
        if ($pid === 0) { $bot->slow = true; $bot->restartTelemt(); exit(0); }
        $children[] = $pid;
        $deadline = microtime(true) + 5;
        while (!is_file("$root/old-read") && microtime(true) < $deadline) usleep(10000);
        $check(is_file("$root/old-read"), 'Начат старый перезапуск');
        $bot->telemtToggleUser('alice'); touch("$root/new-done");
        pcntl_waitpid($pid, $status); $children = [];
        $check(pcntl_wifexited($status) && pcntl_wexitstatus($status) === 0, 'Перезапуск завершился');
        $check(str_contains(file_get_contents("$root/active.toml"), '"alice" = false'), 'Старый перезапуск не отменяет отключение пользователя');
    }
    $guard = new TelemtWriteGuardBot($root);
    $guard->telemtWriteToml('old configuration');
    $check((fileperms("$root/written.toml") & 0777) === 0600, 'Секреты TOML доступны только владельцу');
    $guard->failWrite = true;
    try { $guard->restartTelemt(); $check(false, 'Ошибка TOML должна отменять перезапуск'); } catch (RuntimeException $e) {}
    $check($guard->sshCalls === 0 && file_get_contents("$root/written.toml") === 'old configuration', 'Ошибка записи сохраняет работающий процесс и конфиг');
    $before = file_get_contents($guard->pac); $guard->failSettings = true;
    try { $guard->telemtToggleUser('alice'); $check(false, 'Ошибка pac.json должна отменять переключение'); } catch (RuntimeException $e) {}
    $check($guard->sshCalls === 0 && file_get_contents($guard->pac) === $before, 'Неудачное сохранение не меняет доступ');

    $modules = new ProtocolModules($bot->protocolModulesFile);
    $conf = ['telemt_users' => ['alice' => str_repeat('ab', 16)], 'telemt_user_enabled' => ['alice' => 0],
        'telemt_web' => 1, 'domain' => 'vpn.example.test', 'letsencrypt' => 'letsencrypt'];
    $bot->setPacConf($conf);
    // Настройки и доступы должны пережить выключение целого сервиса.
    $saved = file_get_contents($bot->pac);
    $bot->toggleTelemtService();
    $check(!$modules->enabled('telemt'), 'Модуль TeleMT выключен');
    $check(file_get_contents("$root/service-enabled") === "0\n", 'Контейнер получает запрет запуска');
    $check(!$bot->telemtWebEnabled($conf), 'WEB закрывается вместе с модулем');
    $check($bot->linkTelemt('alice') === '' && $bot->linkTelemtWeb('alice') === '', 'Отключённый сервис не выдаёт ссылки');
    $active = file_get_contents("$root/active.toml");
    $bot->restartTelemt();
    $check(file_get_contents("$root/active.toml") === $active, 'Фоновый рестарт не меняет отключённый сервис');
    $check(file_get_contents($bot->pac) === $saved, 'Выключение сохраняет пользователей и WEB-настройки');
    // WEB-decoy не относится к этой проверке, сохраняем WEB выключенным до включения.
    $bot->telemtConfUpdate(static function (&$c) { $c['telemt_web'] = 0; });
    $saved = file_get_contents($bot->pac);
    $bot->toggleTelemtService();
    $check($modules->enabled('telemt') && file_get_contents("$root/service-enabled") === "1\n", 'Повторное включение разрешает запуск');
    $check(file_get_contents($bot->pac) === $saved, 'Включение не меняет секреты и запрет пользователя');
    $check(str_contains(file_get_contents("$root/active.toml"), '"alice" = false'), 'После включения индивидуальный запрет сохранён');
    $bot->admin = false; $bot->toggleTelemtService();
    $check($modules->enabled('telemt'), 'Неадминистратор не выключает модуль'); $bot->admin = true;
    $guard->failWrite = true; $guard->failSettings = false;
    $modules->set('telemt', false);
    try { $guard->toggleTelemtService(); $check(false, 'Ошибка TOML должна отменять включение модуля'); } catch (RuntimeException $e) {}
    $check(!$modules->enabled('telemt') && file_get_contents("$root/service-enabled") === "0\n", 'Ошибка включения возвращает отключённое состояние');
    $guard->failWrite = false; $modules->set('telemt', true); $guard->telemtWriteServiceState(true);
    $guard->sshCalls = 0; $guard->failState = true;
    try { $guard->toggleTelemtService(); $check(false, 'Ошибка флага должна отменять выключение'); } catch (RuntimeException $e) {}
    $check($modules->enabled('telemt') && file_get_contents("$root/service-enabled") === "1\n" && $guard->sshCalls === 0,
        'Ошибка сохранения флага не останавливает работающий сервис');
    if ($failures) throw new RuntimeException(implode('; ', $failures));
    echo "telemt_lifecycle_test: OK\n";
} finally {
    foreach ($children as $pid) pcntl_waitpid($pid, $status);
    foreach (glob("$root/*") as $path) unlink($path);
    rmdir($root);
}
