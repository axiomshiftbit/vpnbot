<?php
require_once __DIR__ . '/../app/bot.php';
require_once __DIR__ . '/managed_protocol_fixture.php';

class MasqueTestBot extends Bot
{
    public array $screens = [], $conf = [], $prompts = [], $answers = [];
    public function __construct(string $root) {
        $this->admin = true; $this->language = 'ru';
        $this->protocolRoot = "$root/protocols"; $this->protocolModulesFile = "$root/modules.json";
        $this->input = ['chat' => 1, 'message_id' => 1, 'callback_id' => 'test', 'username' => 'test'];
    }
    public function getPacConf() { return $this->conf; }
    public function getDomain($sub = true, $var = '') { return 'vpn.example.test'; }
    public function getHashBot($notset = false) { return 'fixture'; }
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML') { $this->screens[] = [$text, $button]; }
    public function answer($id, $text = '', $alert = false) { $this->answers[] = $text; }
    public function syncManagedUpstreams(): void {}
    public function syncXrayProtocolUsers(): void {}
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
    public function subSecurityHeaders(): void {}
    public function subRateLimit($key, $bucket = '') {}
    public function processHwidRequest(array $token, bool $htmlPreview = false): bool { return true; }
    public function protocolError(string $message, string $back, string $retry = ''): void { throw new RuntimeException($message); }
}

$root = sys_get_temp_dir() . '/vpnbot-masque-' . bin2hex(random_bytes(6)); mkdir($root, 0700);
$checks = 0;
function masqueCheck(bool $ok, string $message): void { global $checks; $checks++; if (!$ok) throw new RuntimeException($message); }
function masqueReject(callable $call): void {
    try { $call(); } catch (InvalidArgumentException | RuntimeException $e) { masqueCheck(true, 'отказ'); return; }
    throw new RuntimeException('Неверное значение было принято');
}
ob_start();
try {
    $bot = new MasqueTestBot($root); $store = $bot->protocolStore('masque'); $modules = new ProtocolModules($bot->protocolModulesFile);
    masqueCheck(!$store->read()['enabled'] && !$modules->enabled('masque'), 'Выключен по умолчанию');
    masqueReject(fn() => $store->configure([], true));
    $store->configure(['host' => 'vpn.example.test', 'sni' => 'vpn.example.test'], true); $modules->set('masque', true);
    $id = managedProtocolFixtureUser($store, 'Клиент <&>'); $state = $store->read();
    masqueCheck($state['settings']['port'] === 24449 && $state['settings']['listen_port'] === 24449, 'Отдельный порт');
    masqueCheck(array_keys($store->formats()) === ['native'] && array_keys($bot->connectionFormats('masque')) === ['native'], 'Только нативный профиль');
    $profile = $store->profile($id, 'native'); $node = $profile['outbounds'][0];
    masqueCheck($node['protocol'] === 'masque' && $node['streamSettings']['tlsSettings']['alpn'] === ['h3'], 'CONNECT-IP поверх H3');
    masqueCheck(!isset($node['streamSettings']['tlsSettings']['allowInsecure']), 'Проверка TLS обязательна');
    masqueCheck($node['streamSettings']['masqueSettings'] === ['user' => $id, 'pass' => $state['users'][$id]['password']], 'Личные учётные данные');
    masqueCheck(!str_contains(json_encode($profile), $state['users'][$id]['token']), 'Токен подписки не служит паролем');
    $relay = $store->profile($id, 'native', endpoint: ['host' => '2001:db8::7', 'port' => 10443]);
    masqueCheck($relay['outbounds'][0]['settings']['address'] === '2001:db8::7' && $relay['outbounds'][0]['settings']['port'] === 10443
        && $relay['outbounds'][0]['streamSettings'] === $node['streamSettings'], 'Relay сохраняет SNI, TLS и пароль');
    foreach (['singbox', 'mihomo', 'uri'] as $format) masqueReject(fn() => $store->profile($id, $format));
    masqueReject(fn() => $store->connectionUri($id));
    foreach ([['listen_port' => 24448], ['port' => 443], ['options' => ['client' => ['http' => 'h1']]],
        ['options' => ['noise' => ['packets' => [['type' => 'exp', 'packet' => '<r 65535>', 'delay' => '0']]]]],
        ['options' => ['noise' => ['reset' => '0']]], ['options' => ['singbox' => ['tls' => []]]]] as $bad) {
        $before = file_get_contents($store->directory() . '/desired.json');
        masqueReject(fn() => $store->configure($bad));
        masqueCheck(file_get_contents($store->directory() . '/desired.json') === $before, 'Ошибка не меняет сохранённое состояние');
    }
    $store->configureOption('noise.enabled', true); $state = $store->read();
    $serverNoise = $state['config']['inbounds'][0]['streamSettings']['finalmask']['udp'];
    masqueCheck($serverNoise === $store->profile($id, 'native')['outbounds'][0]['streamSettings']['finalmask']['udp'], 'Сервер и H3-клиент получают одинаковые маски');
    masqueCheck($serverNoise[0]['settings']['noise'][0]['type'] === 'exp', 'Динамический шаблон по умолчанию');
    $store->configureOption('client.http', 'h2');
    $h2 = $store->profile($id, 'native')['outbounds'][0]['streamSettings'];
    masqueCheck($h2['tlsSettings']['alpn'] === ['h2'] && !isset($h2['finalmask']), 'H2 не получает неработающую UDP-маску');
    $store->configureOption('noise.enabled', false);
    masqueCheck(!isset($store->read()['config']['inbounds'][0]['streamSettings']['finalmask']), 'Выключение удаляет маску');
    $config = $store->read()['config'];
    masqueCheck($config['inbounds'][1]['listen'] === '127.0.0.1' && $config['api']['services'] === ['StatsService'], 'API закрыт на loopback');
    masqueCheck($config['policy']['levels'][0]['statsUserUplink'] && $config['policy']['levels'][0]['statsUserDownlink'], 'Индивидуальные счётчики');
    $blocked = $config['routing']['rules'][1]['ip'];
    foreach (['10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', 'fc00::/7', '::1/128'] as $ip) masqueCheck(in_array($ip, $blocked, true), 'ACL: ' . $ip);
    $bot->protocolCommand('masque'); [$text, $buttons] = end($bot->screens);
    masqueCheck(str_contains($text, 'HTTP/3') && str_contains($text, '26.9.30'), 'Меню объясняет совместимость');
    masqueCheck(str_contains(json_encode($buttons), '/po masque'), 'Настройки доступны');
    foreach (['client', 'client.http', 'noise', 'noise.enabled', 'noise.reset', 'noise.packets'] as $path) {
        $bot->protocolOptions('masque', path: $path); [$text, $buttons] = end($bot->screens);
        masqueCheck(mb_strlen(strip_tags($text)) < 4096, 'Настройки помещаются в Telegram');
        foreach ($buttons as $row) foreach ($row as $button) masqueCheck(strlen($button['callback_data']) <= 64, 'Размер callback');
    }
    $before = $store->read(); $bot->protocolCommand('masque', 'toggle');
    masqueCheck(!$store->read()['enabled'] && !$modules->enabled('masque') && $store->read()['users'] === $before['users'], 'Отключение сохраняет пользователей');
    $bot->protocolCommand('masque', 'toggle');
    $state = $store->read();
    ManagedProtocol::writeJson("$root/protocol-services.status.json", ['bindings' => ['masque' => 24449]]);
    ManagedProtocol::writeJson($store->directory() . '/runtime/status.json', ['running' => true, 'time' => time(), 'revision' => $state['revision']]);
    $response = function ($token) use ($bot) { http_response_code(200); ob_start(); $bot->protocolMachine('masque', $token, 'native'); return [http_response_code(), ob_get_clean()]; };
    [$code, $body] = $response($state['users'][$id]['token']);
    masqueCheck($code === 200 && json_decode($body, true)['outbounds'][0]['protocol'] === 'masque', 'HTTP-выдача профиля');
    [$code, $body] = $response(str_repeat('0', 64)); masqueCheck($code === 404 && $body === '', 'Неверный токен');
    $store->user($id, ['enabled' => false]);
    [$code, $body] = $response($state['users'][$id]['token']); masqueCheck($code === 404 && $body === '', 'Отозванный доступ закрывает выдачу');
    $store->user($id, ['enabled' => true, 'expires' => time() - 1]); masqueReject(fn() => $store->profile($id, 'native'));
    $store->user($id, ['expires' => null, 'quota' => 10]); $u = $store->read()['users'][$id];
    ManagedProtocol::writeJson($store->directory() . '/runtime/usage.json', ['users' => [$id => ['reset' => $u['reset'], 'upload' => 5, 'download' => 5]]]);
    masqueReject(fn() => $store->profile($id, 'native'));
    $store->user($id, [], 'reset'); masqueCheck($store->profile($id, 'native')['outbounds'][0]['protocol'] === 'masque', 'Сброс квоты');
    $snapshot = $store->snapshot(); $store->user($id, [], 'rotate');
    masqueCheck($store->read()['users'][$id]['password'] !== $snapshot['state']['users'][$id]['password'], 'Ротация пароля');
    $store->restore($snapshot); masqueCheck($store->read()['users'] === $snapshot['state']['users'], 'Восстановление доступа из backup');
    ob_end_clean(); echo "masque_test: $checks OK\n";
} finally {
    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($files as $file) $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
    rmdir($root);
}
