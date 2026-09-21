<?php
require_once __DIR__ . '/../app/bot.php';

function protocolMenuAssert(bool $ok, string $message): void
{
    if (!$ok) throw new RuntimeException($message);
}

class ProtocolMenuBot extends Bot
{
    public array $conf = [];
    public function __construct() { $this->admin = true; $this->ip = '192.0.2.1'; }
    public function getPacConf() { return $this->conf + self::PAC_DEFAULTS; }
    public function getHashBot($notset = false) { return 'fixture'; }
    public function getHashSubdomain($subdomain) { return $subdomain . '-fixture'; }
    public function expireCert() { return 1800000000; }
    public function domainsCert() { return [$this->conf['domain'] ?? '']; }
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
        protocolMenuAssert(str_contains($text, 'on ' . $label . '  on ' . $bindings[$key]), "$label: отдельный индикатор применённого порта");
    }
    protocolMenuAssert(in_array('/xray', $callbacks, true) && in_array('/menu oc', $callbacks, true), 'Прежние кнопки сохранены');

    $enabledModules = $modules->read();
    foreach ([['oc'], ['oc', 'tt'], ['hy'], ['ss', 'dnstt'], ['ovpn', 'ipsec', 'anytls'], ['oc', 'ovpn', 'tt', 'ipsec', 'hy', 'ss', 'dnstt', 'anytls', 'mieru', 'tuic', 'shadowtls']] as $disabled) {
        $modules->setMany(array_replace($enabledModules, array_fill_keys($disabled, false)));
        [, $rows] = $bot->menu(false, false, true);
        $actual = array_column(array_merge(...$rows), 'callback_data');
        foreach ($rows as $index => $row) {
            protocolMenuAssert(count($row) === 2 || ($index === array_key_last($rows) && count($row) === 1), 'После выключения модулей одиночная кнопка только в последней строке');
        }
        protocolMenuAssert(array_slice($actual, -2) === ['/menu config', '/refreshMain'], 'Настройки и статус остаются в конце меню');
        protocolMenuAssert(count($actual) === count(array_unique($actual)), 'Кнопки не дублируются при перегруппировке');
        protocolMenuAssert(in_array('/xray', $actual, true) && in_array('/changeWG 0', $actual, true), 'Действующие службы остаются доступны');
        foreach (['oc', 'ovpn', 'tt', 'hy', 'ss', 'l2tp', 'ikev2'] as $key) {
            protocolMenuAssert(in_array("/menu $key", $actual, true) === $modules->enabled($key), "$key: выключенные службы не возвращаются при перегруппировке");
        }
        protocolMenuAssert(in_array('/dnstt', $actual, true) === $modules->enabled('dnstt'), 'DNSTT: выключенная служба скрыта');
        foreach (ManagedProtocol::NAMES as $key => $label) {
            protocolMenuAssert(in_array("/protocol $key", $actual, true) === $modules->enabled($key), "$key: новые службы учитывают выключатель");
        }
    }
    $modules->setMany($enabledModules);

    foreach (['mieru', 'shadowtls'] as $key) {
        $pending = $bindings; $pending[$key]++;
        ManagedProtocol::writeJson("$root/protocol-services.status.json", ['bindings' => $pending]);
        [$text] = $bot->menu(false, false, true);
        protocolMenuAssert(str_contains($text, 'off ' . ManagedProtocol::NAMES[$key] . '  off ' . $bindings[$key]), "$key: неприменённый порт красный");
    }
    ManagedProtocol::writeJson("$root/protocol-services.status.json", ['bindings' => $bindings]);

    $bot->conf = ['domain' => 'site.example.test'];
    $stores['anytls']->configure(['host' => 'at.site.example.test', 'sni' => 'at.site.example.test', 'cover_host' => 'site.example.test']);
    $stores['shadowtls']->configure(['host' => 'vpn.site.example.test', 'sni' => 'external.example.test']);
    [$text] = $bot->menu(false, false, true);
    protocolMenuAssert(str_contains($text, 'Domains:') && str_contains($text, 'AnyTLS: <code>at.site.example.test</code>'), 'Domains показывает полный поддомен AnyTLS');
    protocolMenuAssert(str_contains($text, 'AnyTLS сайт прикрытия: <code>site.example.test</code>'), 'Domains отличает сайт AnyTLS от адреса подключения');
    protocolMenuAssert(str_contains($text, 'ShadowTLS: <code>vpn.site.example.test</code>')
        && str_contains($text, 'ShadowTLS сайт прикрытия (SNI): <code>external.example.test</code>'), 'Domains показывает адрес и фактический сайт ShadowTLS');
    protocolMenuAssert(in_array('at.site.example.test', $bot->managedCertificateNames(), true)
        && !in_array('external.example.test', $bot->managedCertificateNames(), true), 'SSL включает поддомен AnyTLS, но не чужой сайт ShadowTLS');
    $stores['anytls']->configure(['host' => 'vpn.example.test', 'sni' => 'anytls.example.test', 'cover_host' => '']);

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
