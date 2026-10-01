<?php
require_once __DIR__ . '/../app/bot.php';
require_once __DIR__ . '/managed_protocol_fixture.php';

class ProtocolDisableBot extends Bot
{
    public function __construct(string $root) {
        $this->protocolRoot = "$root/protocols";
        $this->protocolModulesFile = "$root/modules.json";
        $this->admin = true;
    }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) {
        $lock = fopen(dirname($this->protocolModulesFile) . "/$name.lock", 'c');
        flock($lock, LOCK_EX);
        try { return $fn(); } finally { flock($lock, LOCK_UN); fclose($lock); }
    }
    public function getPacConf() { return self::PAC_DEFAULTS; }
    public function protocolModulesMenu(): void {}
    public function protocolMenu(string $protocol, string $id = '', int $page = 0): void {}
    public function syncManagedUpstreams(): void {}
    public function syncXrayProtocolUsers(): void {}
    public function protocolError(string $message, string $back, string $retry = ''): void { throw new RuntimeException($message); }
}

$root = sys_get_temp_dir() . '/vpnbot-disable-' . bin2hex(random_bytes(6)); mkdir($root, 0700);
$checks = 0;
$check = static function (bool $ok, string $message) use (&$checks): void {
    $checks++;
    if (!$ok) throw new RuntimeException($message);
};
try {
    $bot = new ProtocolDisableBot($root);
    $modules = new ProtocolModules($bot->protocolModulesFile);
    foreach (ProtocolModules::DEFAULTS as $protocol => $_) {
        // TeleMT's process/WEB/rollback path has its own lifecycle tests.
        if ($protocol === 'telemt' || isset(ManagedProtocol::NAMES[$protocol])) continue;
        $before = $modules->read();
        $bot->protocolModulesToggle($protocol);
        $check($modules->read() === array_replace($before, [$protocol => !$before[$protocol]]),
            "$protocol: переключатель меняет только выбранный модуль");
        $bot->protocolModulesToggle($protocol);
        $check($modules->read() === $before, "$protocol: повторное включение сохраняет остальные настройки");
        $bot->admin = false; $bot->protocolModulesToggle($protocol); $bot->admin = true;
        $check($modules->read() === $before, "$protocol: посторонний пользователь не меняет состояние");
    }
    foreach (ManagedProtocol::NAMES as $protocol => $_) {
        $store = $bot->protocolStore($protocol);
        $store->configure(['host' => 'vpn.example.test', 'sni' => in_array($protocol, ['mieru', 'snolc'], true) ? '' : 'vpn.example.test'], true);
        $modules->set($protocol, true);
        $active = managedProtocolFixtureUser($store, 'Активный');
        $disabled = managedProtocolFixtureUser($store, 'Отключённый');
        $store->user($disabled, ['enabled' => false, 'expires' => time() - 1, 'quota' => 1024]);
        $before = $store->read();
        $bot->protocolCommand($protocol, 'toggle');
        $check(!$modules->enabled($protocol) && !$store->read()['enabled'], "$protocol: оба состояния выключены");
        $check($store->read()['users'] === $before['users'] && $store->read()['settings'] === $before['settings'],
            "$protocol: пароли, токены, запреты, сроки и лимиты сохранены");
        $denied = false;
        try { $store->profile($active, array_key_first($store->formats())); } catch (RuntimeException $e) { $denied = true; }
        $check($denied, "$protocol: отключённый сервис не выдаёт профиль");
        $bot->protocolCommand($protocol, 'toggle');
        $check($modules->enabled($protocol) && $store->read()['enabled'], "$protocol: сервис включается повторно");
        $check($store->read()['users'] === $before['users'] && !$store->allowed($store->read()['users'][$disabled], $disabled),
            "$protocol: включение не снимает запрет отдельного пользователя");
        $before = $store->read();
        $bot->admin = false; $bot->protocolCommand($protocol, 'toggle'); $bot->admin = true;
        $check($store->read() === $before && $modules->enabled($protocol), "$protocol: переключение доступно только администратору");
    }
    echo "protocol_disable_test: $checks OK\n";
} finally {
    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($files as $file) $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
    rmdir($root);
}
