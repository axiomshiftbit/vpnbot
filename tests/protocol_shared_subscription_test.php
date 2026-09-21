<?php
require_once __DIR__ . '/managed_protocol_fixture.php';
require_once __DIR__ . '/../app/bot.php';
require_once __DIR__ . '/../app/i18n.php';

class SharedProtocolBot extends Bot {
    public array $xr = []; public array $conf = []; public array $stats = []; public array $templates = [];
    public string $primaryError = '';
    public function __construct() { $this->ip = '192.0.2.1'; $this->language = 'ru'; }
    public function getXray() { return $this->xr; }
    public function getPacConf() { return $this->conf + self::PAC_DEFAULTS; }
    public function getXrayStats() { return $this->stats; }
    public function getHashBot($notset = false) { return 'fixture'; }
    public function subDomain(array $pac): string { return 'vpn.example.test'; }
    public function nginxGetTypeCert() { return false; }
    public function flagName(string $name, string|array $hosts, bool $cacheOnly = true): string { return $name; }
    public function subscriptionCompatibilityError(array $xr, array $pac, string $type): string { return $this->primaryError; }
    public function smuxActive(?array $p = null): bool { return false; }
    public function subTemplate(string $template, string $type, array $pac) { return $this->templates[$type]; }
    public function warpClientProfile($email) { return ['server' => '192.0.2.2', 'private-key' => base64_encode(str_repeat('a', 32)), 'public-key' => base64_encode(str_repeat('b', 32)), 'ip' => '172.16.0.2']; }
}
$checks = 0;
function sharedCheck(bool $ok, string $label): void { global $checks; $checks++; if (!$ok) throw new RuntimeException($label); }
function sharedUser(ManagedProtocol $store, array $client): array {
    foreach ($store->read()['users'] as $id => $user) if (($user['xray_source'] ?? '') === ManagedProtocol::xraySource($client)) return [$id, $user];
    throw new RuntimeException('Связанный пользователь отсутствует');
}
function sharedProfile(SharedProtocolBot $bot, string $format): array {
    $_GET = ['s' => $bot->xr['inbounds'][0]['settings']['clients'][0]['subtoken'], 't' => $format];
    $body = $bot->subscription(true);
    return $format === 'cl' ? yaml_parse($body) : json_decode($body, true, 512, JSON_THROW_ON_ERROR);
}
$root = sys_get_temp_dir() . '/vpnbot-shared-' . bin2hex(random_bytes(6)); mkdir($root, 0700);
set_error_handler(static function ($level, $message, $file, $line) {
    if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line);
    return false;
});
try {
    $bot = new SharedProtocolBot(); $bot->protocolRoot = "$root/protocols"; $bot->protocolModulesFile = "$root/modules.json";
    $bot->upstreamFile = "$root/upstream.conf"; file_put_contents($bot->upstreamFile, "vpn.example.test anytls_bridge;\n");
    $bot->conf = array_fill_keys(['includelist', 'blocklist', 'warplist', 'processlist', 'packagelist', 'subnetlist', 'rulessetlist'], []) + ['domain' => 'vpn.example.test', 'outbound' => 'proxy', 'transport' => 'Reality', 'xray' => rtrim(strtr(base64_encode(str_repeat('p', 32)), '+/', '-_'), '=')];
    $client = ['id' => Bot::xrayUuid(), 'subtoken' => bin2hex(random_bytes(16)), 'email' => 'Одинаковое имя', 'time' => 0, 'traffic' => 0];
    $other = array_replace($client, ['id' => Bot::xrayUuid(), 'subtoken' => bin2hex(random_bytes(16))]);
    sharedCheck(ManagedProtocol::xrayCredential($client + ['off'=>false]) !== ManagedProtocol::xrayCredential($other + ['off'=>false]), 'Пустой старый флаг off не скрывает ротацию UUID');
    $bot->xr = ['inbounds' => [['settings' => ['clients' => [$client, $other]], 'streamSettings' => ['realitySettings' => ['serverNames' => ['example.com'], 'shortIds' => ['abcd']]]]]];
    $modules = new ProtocolModules($bot->protocolModulesFile); $legacy = [];
    foreach (ManagedProtocol::NAMES as $protocol => $_) {
        $store = $bot->protocolStore($protocol);
        $store->configure(['host' => 'vpn.example.test', 'sni' => $protocol === 'mieru' ? '' : 'vpn.example.test'], true);
        $legacy[$protocol] = managedProtocolFixtureUser($store, 'Старый отдельный доступ'); $modules->set($protocol, true);
    }
    $bot->syncXrayProtocolUsers();
    $bindings = [];
    foreach (array_keys(ManagedProtocol::NAMES) as $protocol) $bindings[$protocol] = $bot->protocolStore($protocol)->read()['settings']['port'];
    ManagedProtocol::writeJson("$root/protocol-services.status.json", ['bindings'=>$bindings]);
    $secrets = [];
    foreach (ManagedProtocol::NAMES as $protocol => $_) {
        $store = $bot->protocolStore($protocol); $state = $store->read();
        sharedCheck(count($state['users']) === 3 && isset($state['users'][$legacy[$protocol]]), 'Старый доступ сохранён, одинаковые имена не объединяются');
        [$uid, $user] = sharedUser($store, $client); $secrets[] = $user['password'];
        sharedCheck($user['enabled'] && $user['quota'] === null && $user['expires'] === null, 'Права общего пользователя синхронизированы');
        $bot->syncXrayProtocolUsers(); sharedCheck($store->read()['revision'] === $state['revision'], 'Повторная синхронизация не пишет ревизию и не перезапускает ядро');
    }
    sharedCheck(count(array_unique($secrets)) === 4 && !in_array($client['id'], $secrets, true), 'У каждого протокола отдельный секрет');
    foreach (['clash', 'sing'] as $kind) $bot->templates[$kind] = json_decode(file_get_contents(__DIR__ . '/../config/' . $kind . '.json'), true);
    $plain = [];
    foreach (array_keys(ManagedProtocol::NAMES) as $protocol) $modules->set($protocol, false);
    $plain['cl'] = sharedProfile($bot, 'cl'); $plain['si'] = sharedProfile($bot, 'si');
    foreach (array_keys(ManagedProtocol::NAMES) as $protocol) $modules->set($protocol, true);
    $mihomo = sharedProfile($bot, 'cl'); $sing = sharedProfile($bot, 'si');
    sharedCheck($mihomo === sharedProfile($bot, 'clj'), 'Полная общая подписка YAML и JSON семантически идентична');
    $_GET = ['s'=>$client['subtoken'], 't'=>'clj'];
    sharedCheck(yaml_parse($bot->subscription(true)) === $mihomo, 'JSON со ссылками и Unicode также понимает YAML-парсер Mihomo');
    foreach (['cl' => $mihomo, 'si' => $sing] as $type => $config) {
        foreach (['dns', 'rules', 'rule-providers', 'route', 'inbounds', 'tun'] as $field) {
            sharedCheck(($plain[$type][$field] ?? null) === ($config[$field] ?? null), "$type сохраняет $field шаблона");
        }
        $key = $type === 'cl' ? 'proxies' : 'outbounds'; $tag = $type === 'cl' ? 'name' : 'tag';
        $names = array_merge(array_column($config[$key], $tag), array_column($config['proxy-groups'] ?? [], 'name'));
        sharedCheck(count($names) === count(array_unique($names)), 'Имена узлов и групп уникальны');
        sharedCheck(count(array_filter($config[$key], fn($p) => ($p['type'] ?? '') === 'vless')) === 1, 'VLESS остаётся доступным');
        sharedCheck(count(array_filter($config[$key], fn($p) => ($p['type'] ?? '') === 'mieru')) === ($type === 'cl' ? 1 : 0), 'Mieru добавляется только в Mihomo');
        foreach (['anytls', 'tuic', 'ss'] as $protocol) {
            $wanted = $type === 'si' && $protocol === 'ss' ? 'shadowsocks' : $protocol;
            sharedCheck(count(array_filter($config[$key], fn($p) => ($p['type'] ?? '') === $wanted)) === 1, 'Поддерживаемый протокол добавлен один раз');
        }
    }
    sharedCheck($sing['outbounds'][0]['default'] === 'proxy · VLESS', 'Прежнее подключение остаётся выбранным по умолчанию');
    $chain = $plain['si']; $chain['outbounds'][] = ['type' => 'socks', 'tag' => 'warp', 'server' => '10.10.0.13', 'server_port' => 1080, 'detour' => 'proxy'];
    $bot->appendXrayProtocols($chain, $client, 'si', 0);
    sharedCheck($chain['outbounds'][2]['detour'] === 'proxy · VLESS', 'Цепочка WARP сохраняет исходный транспорт');
    $collision = $plain['cl']; $collision['proxies'][] = ['name' => 'AnyTLS', 'type' => 'direct'];
    $bot->appendXrayProtocols($collision, $client, 'cl', 0);
    sharedCheck(in_array('AnyTLS 2', array_column($collision['proxies'], 'name'), true), 'Существующий тег AnyTLS не перезаписывается');
    $chainClash = $plain['cl'];
    $chainClash['proxies'][] = ['name' => 'warp', 'type' => 'socks5', 'server' => '10.10.0.13', 'port' => 1080, 'dialer-proxy' => 'warp-dialer'];
    $chainClash['proxy-groups'][] = ['name' => 'warp-dialer', 'type' => 'select', 'proxies' => ['proxy'], 'include-all' => true, 'exclude-filter' => 'warp'];
    $bot->appendXrayProtocols($chainClash, $client, 'cl', 0);
    $group = $chainClash['proxy-groups'][1];
    sharedCheck($group['proxies'] === ['proxy · VLESS'] && preg_match('~' . $group['exclude-filter'] . '~', 'AnyTLS') === 1, 'WARP dialer не подхватывает новые протоколы через include-all');
    sharedCheck(preg_match('~' . $group['exclude-filter'] . '~', 'proxy · VLESS') === 0, 'WARP сохраняет доступный VLESS');
    $pending = $bot->protocolStore('tuic'); $oldPort = $pending->read()['settings']['port']; $pending->configure(['port'=>25443]);
    sharedCheck(!in_array('tuic', array_column(sharedProfile($bot, 'cl')['proxies'], 'type'), true), 'Не применённый внешний порт не попадает в общую подписку');
    $pending->configure(['port'=>$oldPort]);
    sharedCheck($sing['experimental']['clash_api']['external_controller'] === '127.0.0.1:9090', 'Выбор протокола доступен через локальный API sing-box');
    $bot->conf['transport'] = 'xhttp';
    $compatible = sharedProfile($bot, 'si');
    sharedCheck(!in_array('vless', array_column($compatible['outbounds'], 'type'), true), 'Обычный sing-box получает совместимые новые узлы без XHTTP');
    sharedCheck($compatible['outbounds'][0]['default'] === 'AnyTLS', 'При неподдерживаемом VLESS выбран первый совместимый протокол');
    $dependent = $plain['si'];
    $dependent['outbounds'][] = ['tag'=>'warp','type'=>'socks','server'=>'10.10.0.13','server_port'=>1080,'detour'=>'proxy'];
    $before = $dependent;
    sharedCheck(!$bot->appendXrayProtocols($dependent, $client, 'si', 0, null, false) && $dependent === $before, 'Цепочка не переводится на другой транспорт без совместимого VLESS');
    $bot->conf['transport'] = 'Reality';
    $bot->primaryError = 'reality singbox mlkem';
    sharedCheck(!in_array('vless', array_column(sharedProfile($bot, 'si')['outbounds'], 'type'), true), 'Новый REALITY не мешает выдать совместимую подписку новых протоколов');
    foreach (array_keys(ManagedProtocol::NAMES) as $protocol) $modules->set($protocol, false);
    $_GET = ['s'=>$client['subtoken'],'t'=>'si'];
    sharedCheck($bot->subscription(true) === '', 'Без совместимого узла ошибка VLESS не подавляется');
    foreach (array_keys(ManagedProtocol::NAMES) as $protocol) $modules->set($protocol, true);
    $bot->primaryError = '';
    foreach (['missing', '', ['bad']] as $badRelay) {
        $_GET = ['s'=>$client['subtoken'],'t'=>'clj','relay'=>$badRelay];
        sharedCheck($bot->subscription(true) === '', 'Неверный relay не заменяется прямым подключением');
    }
    $relay = $plain['si']; $bot->appendXrayProtocols($relay, $client, 'si', 0, ['tuic_address' => 'relay.example.test', 'tuic_port' => 33333]);
    $relayed = array_values(array_filter($relay['outbounds'], fn($n) => $n['type'] === 'tuic'));
    sharedCheck(count($relayed) === 1 && $relayed[0]['server'] === 'relay.example.test' && $relayed[0]['server_port'] === 33333, 'Relay использует отдельные настройки протокола');
    sharedCheck(!in_array('anytls', array_column($relay['outbounds'], 'type'), true), 'Протокол без relay не раскрывает прямой маршрут');
    $store = $bot->protocolStore('anytls'); [$uid, $user] = sharedUser($store, $client);
    $store->configureOption('client.fingerprint', 'firefox');
    $config = sharedProfile($bot, 'cl');
    sharedCheck(array_values(array_filter($config['proxies'], fn($p) => $p['type'] === 'anytls'))[0]['client-fingerprint'] === 'firefox', 'Дополнительные настройки попадают в общую подписку');
    $store->configureOption('client.udp', false);
    sharedCheck($store->read()['config']['route']['rules'][0] === ['network'=>'udp','action'=>'reject'], 'UDP выключается только на сервере AnyTLS, общий маршрут других протоколов не блокируется');
    sharedCheck(sharedProfile($bot, 'si')['route'] === $plain['si']['route'], 'Запрет UDP AnyTLS сохраняет DNS и правила общего профиля');
    $store->configureOption('client.udp', null);
    $bot->xr['inbounds'][0]['settings']['clients'][0]['managed_protocols']['anytls'] = false;
    $bot->syncXrayProtocolUsers();
    sharedCheck(!sharedUser($store, $client)[1]['enabled'], 'Персональный выключатель отзывает соединение');
    sharedCheck(!in_array('anytls', array_column(sharedProfile($bot, 'cl')['proxies'], 'type'), true), 'Отключённый протокол отсутствует в подписке');
    $bot->xr['inbounds'][0]['settings']['clients'][0]['managed_protocols']['anytls'] = true;
    $bot->xr['inbounds'][0]['settings']['clients'][0]['off'] = $client['id'];
    $bot->xr['inbounds'][0]['settings']['clients'][0]['id'] = Bot::xrayUuid();
    $bot->syncXrayProtocolUsers();
    foreach (array_keys(ManagedProtocol::NAMES) as $p) sharedCheck(!sharedUser($bot->protocolStore($p), $client)[1]['enabled'], 'Общий выключатель закрывает все протоколы');
    sharedCheck(sharedUser($store, $client)[1]['password'] === $user['password'], 'Обычное выключение не меняет действительный секрет');
    $bot->xr['inbounds'][0]['settings']['clients'][0] = $client;
    $bot->xr['inbounds'][0]['settings']['clients'][0]['protocol_source'] = ManagedProtocol::xraySource($client);
    $bot->xr['inbounds'][0]['settings']['clients'][0]['subtoken'] = bin2hex(random_bytes(16));
    $bot->syncXrayProtocolUsers();
    sharedCheck(sharedUser($store, $client)[1]['password'] === $user['password'], 'Ротация ссылки сохраняет VPN-секрет и счётчики');
    $bot->xr['inbounds'][0]['settings']['clients'][0]['id'] = Bot::xrayUuid();
    $bot->syncXrayProtocolUsers();
    sharedCheck(sharedUser($store, $client)[1]['password'] !== $user['password'], 'Ротация clientID отзывает связанные секреты');
    $bot->xr['inbounds'][0]['settings']['clients'][0]['traffic'] = 1000;
    $bot->stats = ['users' => [0 => ['session' => ['upload' => 100, 'download' => 100]]]];
    foreach (array_keys(ManagedProtocol::NAMES) as $p) {
        $s = $bot->protocolStore($p); [$id, $u] = sharedUser($s, $client);
        ManagedProtocol::writeJson($s->directory() . '/runtime/usage.json', ['users' => [$id => ['upload' => 50, 'download' => 50, 'reset' => $u['reset']]]]);
    }
    $bot->syncXrayProtocolUsers();
    foreach (array_keys(ManagedProtocol::NAMES) as $p) sharedCheck(sharedUser($bot->protocolStore($p), $client)[1]['quota'] === 500, 'Общий остаток 400, локальный счётчик 100: квота 500');
    $bot->stats['users'][0]['session']['upload'] = 600; $bot->syncXrayProtocolUsers();
    foreach (array_keys(ManagedProtocol::NAMES) as $p) sharedCheck(!sharedUser($bot->protocolStore($p), $client)[1]['enabled'], 'Исчерпанный общий лимит закрывает каждый протокол');
    $bot->resetXrayProtocolUsage($client); $bot->stats = []; $bot->syncXrayProtocolUsers();
    sharedCheck(array_sum($bot->xrayProtocolUsage($client)) === 0, 'Старые счётчики не возвращаются после сброса');
    foreach (array_keys(ManagedProtocol::NAMES) as $p) sharedCheck(sharedUser($bot->protocolStore($p), $client)[1]['enabled'], 'Сброс общей квоты восстанавливает доступ');
    $bot->xr['inbounds'][0]['settings']['clients'] = [$other]; $bot->syncXrayProtocolUsers();
    foreach (array_keys(ManagedProtocol::NAMES) as $p) sharedCheck(count($bot->protocolStore($p)->read()['users']) === 2, 'Удаление общего пользователя удаляет только его связанные доступы');
    echo "protocol_shared_subscription_test: OK ($checks проверок)\n";
} finally {
    restore_error_handler();
    $remove = static function ($path) use (&$remove) { if (is_dir($path)) { foreach (scandir($path) as $f) if ($f !== '.' && $f !== '..') $remove("$path/$f"); rmdir($path); } else unlink($path); };
    $remove($root);
}
