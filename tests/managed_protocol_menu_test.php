<?php
require_once __DIR__ . '/../app/bot.php';

function protocolMenuAssert(bool $ok, string $message): void
{
    if (!$ok) throw new RuntimeException($message);
}

class ProtocolMenuBot extends Bot
{
    public function __construct() { $this->admin = true; $this->ip = '192.0.2.1'; }
    public function getPacConf() { return self::PAC_DEFAULTS; }
    public function getHashBot($notset = false) { return 'fixture'; }
    public function i18n(string $menu): string { return $menu; }
    public function menuVersions(): array { return []; }
    public function menuStatusAge() { return 0; }
    public function ipsecPorts() { return ['ike' => 500, 'natt' => 4500]; }
    public function serviceStatuses($force = false)
    {
        return ['st' => array_fill_keys(['wg', 'wg1', 'xray', 'naive', 'oc', 'hy', 'tt', 'ovpn',
            'l2tp', 'ikev2', 'ad', 'ss', 'dnstt', 'telemt', 'warp', 'cron'], true)];
    }
    public function getPorts()
    {
        return array_fill_keys(['wg', 'wg1', 'hy', 'ad', 'ss', 'dnstt', 'telemt'], ['enable' => true, 'port' => 12345]);
    }
}

$root = sys_get_temp_dir() . '/vpnbot-protocol-menu-' . bin2hex(random_bytes(6));
mkdir($root, 0700);
$oldPath = getenv('PATH');
file_put_contents("$root/git", "#!/bin/sh\ncase \"\$*\" in\n  *rev-list*) echo 0;;\n  *--abbrev-ref*) echo dev;;\n  *--short*) echo fixture;;\nesac\n");
chmod("$root/git", 0700);
putenv("PATH=$root:$oldPath");
try {
    $bot = new ProtocolMenuBot();
    $bot->protocolRoot = "$root/protocols";
    $bot->protocolModulesFile = "$root/protocol-services.json";
    $bot->upstreamFile = "$root/upstream.conf";
    $modules = new ProtocolModules($bot->protocolModulesFile);
    $stores = []; $bindings = [];
    foreach (ManagedProtocol::NAMES as $key => $label) {
        $stores[$key] = $store = $bot->protocolStore($key);
        $store->configure(['host' => 'vpn.example.test', 'sni' => "$key.example.test"]);
        $bindings[$key] = $store->read()['settings']['port'];
    }
    file_put_contents($bot->upstreamFile, "anytls.example.test anytls_bridge;\n");
    ManagedProtocol::writeJson("$root/protocol-services.status.json", ['bindings' => $bindings]);
    [$text, $buttons] = $bot->menu(false, false, true);
    protocolMenuAssert(!str_contains(json_encode($buttons), '/protocol '), 'Сохранение адреса не включает протокол и его кнопку');

    foreach ($stores as $key => $store) {
        $store->configure([], true);
        $modules->set($key, true);
        ManagedProtocol::writeJson($store->directory() . '/runtime/status.json', [
            'running' => true, 'phase' => 'running', 'time' => time(), 'revision' => $store->read()['revision'],
        ]);
    }
    [$text, $buttons] = $bot->menu(false, false, true);
    $callbacks = array_column(array_merge(...$buttons), 'callback_data');
    foreach (ManagedProtocol::NAMES as $key => $label) {
        protocolMenuAssert(count(array_keys($callbacks, "/protocol $key", true)) === 1, "$label: одна кнопка в главном меню");
        protocolMenuAssert(str_contains($text, 'on ' . $label), "$label: свежий применённый статус отображается");
    }
    protocolMenuAssert(in_array('/xray', $callbacks, true) && in_array('/menu oc', $callbacks, true), 'Прежние кнопки сохранены');

    $modules->set('mieru', false);
    [$text, $buttons] = $bot->menu(false, false, true);
    protocolMenuAssert(!str_contains(json_encode($buttons), '/protocol mieru') && !str_contains($text, 'Mieru'), 'Отключённый модуль скрыт');
    $modules->set('mieru', true);
    $stores['mieru']->configure([], false);
    [$text, $buttons] = $bot->menu(false, false, true);
    protocolMenuAssert(!str_contains(json_encode($buttons), '/protocol mieru'), 'Выключенное состояние не выдаётся за активный сервис');

    $path = $stores['tuic']->directory() . '/runtime/status.json';
    $status = ManagedProtocol::readJson($path); $status['time'] = time() - 60;
    ManagedProtocol::writeJson($path, $status);
    [$text, $buttons] = $bot->menu(false, false, true);
    protocolMenuAssert(str_contains($text, 'off TUIC v5') && str_contains(json_encode($buttons), '/protocol tuic'), 'Устаревший статус не зелёный; карточка доступна');
    $status['time'] = time(); $status['revision']--;
    ManagedProtocol::writeJson($path, $status);
    [$text] = $bot->menu(false, false, true);
    protocolMenuAssert(str_contains($text, 'off TUIC v5'), 'Неприменённая ревизия не выдаётся за готовую');
    file_put_contents($bot->upstreamFile, "# pending\n");
    [$text] = $bot->menu(false, false, true);
    protocolMenuAssert(str_contains($text, 'off AnyTLS'), 'Неприменённый SNI-маршрут не выдаётся за готовый');
    file_put_contents($stores['shadowtls']->directory() . '/desired.json', '{broken');
    [$text, $buttons] = $bot->menu(false, false, true);
    protocolMenuAssert(str_contains($text, 'ShadowTLS v3 + SS') && str_contains($text, 'ошибка состояния'), 'Ошибка нового состояния видна без поломки главного меню');
    protocolMenuAssert(str_contains(json_encode($buttons), '/protocol shadowtls'), 'Карточка неисправного протокола доступна');
    ManagedProtocol::writeJson($stores['shadowtls']->directory() . '/desired.json', ['schema' => 0]);
    [$text, $buttons] = $bot->menu(false, false, true);
    protocolMenuAssert(str_contains($text, 'ошибка состояния') && str_contains(json_encode($buttons), '/protocol shadowtls'), 'Повреждённая структура состояния не ломает главное меню');
    echo "managed_protocol_menu_test: OK\n";
} finally {
    putenv("PATH=$oldPath");
    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($files as $file) $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
    rmdir($root);
}
