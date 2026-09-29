<?php
require_once __DIR__ . '/../app/bot.php';
require_once __DIR__ . '/../app/i18n.php';

class ConnectionExportTransport {
    public array $messages = [1 => ['text' => 'Menu']];
    public int $next = 100;
    public function call($method, $data, $json = 0) {
        $id = $data['message_id'] ?? ++$this->next;
        if ($method === 'deleteMessage') unset($this->messages[$id]);
        elseif (in_array($method, ['sendMessage', 'sendDocument', 'editMessageText'], true)) $this->messages[$id] = $data;
        return ['ok' => true, 'result' => ['message_id' => $id, 'chat' => ['id' => 1]]];
    }
}
class ConnectionExportBot extends Bot {
    public array $xr = []; public array $conf = []; public array $templates = []; public array $stats = [];
    public bool $permit = true;
    public function __construct(array $i) { $this->i18n = $i; $this->language = 'ru'; $this->ip = '192.0.2.1'; $this->transport = new ConnectionExportTransport(); }
    public function auth() { $this->admin = $this->permit; }
    public function getPacConf() { return $this->conf + self::PAC_DEFAULTS; }
    public function getXray() { return $this->xr; }
    public function getXrayStats() { return $this->stats; }
    public function getDomain($cdn = false) { return 'vpn.example.test'; }
    public function getHashBot($notset = false) { return 'fixture'; }
    public function subDomain(array $pac): string { return 'vpn.example.test'; }
    public function nginxGetTypeCert() { return false; }
    public function flagName(string $name, string|array $hosts, bool $cacheOnly = true): string { return $name; }
    public function smuxActive(?array $p = null): bool { return false; }
    public function realityRequiresMlkem(): bool { return false; }
    public function subTemplate(string $template, string $type, array $pac) { return $this->templates[$type]; }
    public function warpClientProfile($email) { throw new RuntimeException('Экспорт не должен регистрировать посторонний WARP'); }
    public function userXr($index) { $this->update(1, 1, "User $index"); }
    public function xray($page = 0) { $this->update(1, 1, 'Users'); }
}
$checks = 0;
function connectionCheck(bool $ok, string $label): void { global $checks; $checks++; if (!$ok) throw new RuntimeException($label); }
function connectionDenied(callable $fn, string $label): void {
    try { $fn(); } catch (RuntimeException | InvalidArgumentException $e) { connectionCheck(true, $label); return; }
    connectionCheck(false, $label);
}
function connectionClick(ConnectionExportBot $bot, string $callback): array {
    $bot->input(['callback_query' => ['id' => 'fixture', 'from' => ['id' => 90123, 'username' => 'fixture'],
        'message' => ['message_id' => 1, 'chat' => ['id' => 1]], 'data' => $callback]]);
    $screen = $bot->transport->messages[1];
    connectionCheck($bot->messageTextLength($screen['text']) <= 4096, 'Экран помещается в Telegram');
    foreach (connectionButtons($screen) as $button) connectionCheck(strlen($button['callback_data']) <= 64, 'Callback помещается в Telegram');
    return $screen;
}
function connectionButtons(array $screen): array { return array_merge(...(json_decode($screen['reply_markup'] ?? '{}', true)['inline_keyboard'] ?? [[]])); }
function connectionBack(array $screen): string { $buttons = connectionButtons($screen); return end($buttons)['callback_data']; }
$root = sys_get_temp_dir() . '/vpnbot-exports-' . bin2hex(random_bytes(6)); mkdir($root, 0700); mkdir("$root/sessions", 0700);
session_save_path("$root/sessions"); ob_start();
set_error_handler(static function ($level, $message, $file, $line) { if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line); return false; });
try {
    $bot = new ConnectionExportBot($i); $bot->protocolRoot = "$root/protocols"; $bot->protocolModulesFile = "$root/modules.json";
    $bot->upstreamFile = "$root/upstream.conf"; file_put_contents($bot->upstreamFile, "vpn.example.test anytls_bridge;\n");
    $bot->conf = array_fill_keys(['includelist', 'blocklist', 'warplist', 'processlist', 'packagelist', 'subnetlist', 'rulessetlist'], [])
        + ['domain' => 'vpn.example.test', 'outbound' => 'proxy', 'transport' => 'Websocket', 'xray' => rtrim(strtr(base64_encode(str_repeat('p', 32)), '+/', '-_'), '=')];
    $client = ['id' => Bot::xrayUuid(), 'subtoken' => bin2hex(random_bytes(16)), 'email' => 'Клиент <& #> /?', 'time' => 0, 'traffic' => 0];
    $bot->xr = ['inbounds' => [['protocol' => 'vless', 'settings' => ['decryption' => 'none', 'clients' => [$client]],
        'streamSettings' => ['realitySettings' => ['serverNames' => ['example.com'], 'shortIds' => ['abcd']]]]]];
    foreach (['clash', 'sing', 'v2ray'] as $kind) $bot->templates[$kind] = json_decode(file_get_contents(__DIR__ . '/../config/' . $kind . '.json'), true);
    $modules = new ProtocolModules($bot->protocolModulesFile); $bindings = [];
    foreach (ManagedProtocol::NAMES as $p => $_) {
        $store = $bot->protocolStore($p); $store->configure(['host' => 'vpn.example.test', 'sni' => in_array($p, ['mieru', 'snolc'], true) ? '' : 'vpn.example.test'], true);
        $modules->set($p, true); $bindings[$p] = $store->read()['settings']['port'];
        if ($p === 'snolc') {
            if (!is_dir($store->directory() . '/runtime')) mkdir($store->directory() . '/runtime', 0700, true);
            file_put_contents($store->directory() . '/runtime/client-patches.zip', 'synthetic client bundle');
        }
    }
    ManagedProtocol::writeJson("$root/protocol-services.status.json", ['bindings' => $bindings]);
    $source = ManagedProtocol::xraySource($client); $prefix = "/xc $source";
    $bot->syncXrayProtocolUsers(); $profiles = [];
    foreach (['vless' => 'VLESS'] + ManagedProtocol::NAMES as $p => $_) {
        foreach ($bot->connectionFormats($p) as $format => $_) {
            $value = $bot->connectionExport($source, $p, $format); $profiles[$p][$format] = $value;
            if ($p === 'snolc') { connectionCheck(is_string($value) && str_starts_with($value, 'PK'), 'snolc выдаёт настоящий ZIP'); continue; }
            if (in_array($format, ['uri', 'sr'], true)) continue;
            $key = in_array($format, ['cl', 'clj'], true) ? 'proxies' : 'outbounds';
            connectionCheck(array_keys($value) === [$key], "$p/$format: только подключение");
            connectionCheck(count($value[$key]) === ($p === 'shadowtls' && $format === 'si' ? 2 : 1), "$p/$format: все необходимые звенья");
            connectionCheck(!str_contains(json_encode($value), 'domain_resolver'), 'Нет ссылки на DNS из полного профиля');
        }
        if ($p !== 'snolc') connectionCheck($profiles[$p]['cl'] === $profiles[$p]['clj'], 'YAML и JSON Mihomo идентичны');
    }
    $shadow = $profiles['shadowtls']['si']['outbounds'];
    connectionCheck($shadow[0]['detour'] === $shadow[1]['tag'] && str_contains($shadow[0]['password'], ':'), 'Цепочка ShadowTLS и ключи SS2022 сохранены');
    foreach (['vless' => 'vless', 'anytls' => 'anytls', 'tuic' => 'tuic', 'mieru' => 'mierus'] as $p => $scheme) {
        $uri = parse_url($profiles[$p]['uri']);
        parse_str($uri['query'] ?? '', $query);
        connectionCheck($uri['scheme'] === $scheme && ($p === 'mieru' ? $query['profile'] : rawurldecode($uri['fragment'])) === $client['email'], "$p: схема и имя URI");
        connectionCheck(!str_contains($profiles[$p]['uri'], $client['subtoken']), 'URI не путает пароль с токеном подписки');
    }
    foreach (array_diff_key(ManagedProtocol::NAMES, ['snolc' => true]) as $p => $_) {
        $text = $profiles[$p]['sr']; $node = $profiles[$p]['cl']['proxies'][0];
        connectionCheck(str_contains($text, $node['password']) && str_contains($text, (string)$node['port']), 'Памятка Shadowrocket содержит действительные параметры');
    }
    connectionCheck(str_contains($profiles['shadowtls']['sr'], $profiles['shadowtls']['cl']['proxies'][0]['plugin-opts']['password']), 'Отдельный пароль ShadowTLS в памятке');
    connectionDenied(fn() => $bot->connectionExport($source, 'shadowtls', 'uri'), 'Нет неполной ShadowTLS URI');
    connectionDenied(fn() => $bot->connectionExport($source, 'mieru', 'si'), 'Нет неподдерживаемого Mieru sing-box');
    foreach (['anytls', 'tuic', 'mieru'] as $p) {
        $store = $bot->protocolStore($p); $state = $store->read(); $id = array_key_first($state['users']);
        $state['settings']['host'] = '2001:db8::1'; $state['users'][$id]['password'] = 'p@:/#%?+';
        $uri = parse_url($store->connectionUri($id, $state));
        connectionCheck($uri['host'] === '[2001:db8::1]' && rawurldecode($uri[$p === 'anytls' ? 'user' : 'pass']) === 'p@:/#%?+', 'IPv6 и символы пароля URI не искажаются');
    }
    $bot->protocolStore('anytls')->configureOption('client.fingerprint', 'firefox');
    connectionCheck($bot->connectionExport($source, 'anytls', 'cl')['proxies'][0]['client-fingerprint'] === 'firefox', 'Fingerprint сохранён');
    connectionCheck(str_contains($bot->connectionExport($source, 'anytls', 'sr'), 'firefox'), 'Fingerprint доступен для ручного ввода Shadowrocket');
    connectionCheck(str_starts_with($bot->connectionExport($source, 'anytls', 'uri'), 'anytls://'), 'Базовая ссылка доступна отдельно от расширенных параметров');
    $bot->protocolStore('tuic')->configureOption('client.heartbeat', '20s');
    connectionCheck($bot->connectionExport($source, 'tuic', 'si')['outbounds'][0]['heartbeat'] === '20s', 'Расширенные настройки TUIC сохранены');
    $bot->protocolStore('shadowtls')->configureOption('multiplex.enabled', true);
    connectionCheck($bot->connectionExport($source, 'shadowtls', 'si')['outbounds'][0]['multiplex']['enabled'], 'ShadowTLS mux сохранён');
    foreach (['Reality', 'Websocket', 'xhttp', 'trojan-grpc'] as $transport) {
        $bot->conf['transport'] = $transport;
        foreach (array_intersect(array_keys($bot->connectionFormats('vless')), ['cl', 'si', 's']) as $format) {
            $config = $bot->connectionExport($source, 'vless', $format);
            connectionCheck(count($config[$format === 'cl' ? 'proxies' : 'outbounds']) === 1, "$transport/$format: только VLESS/Trojan");
        }
        connectionCheck(str_starts_with($bot->connectionExport($source, 'vless', 'uri'), $transport === 'trojan-grpc' ? 'trojan://' : 'vless://'), 'Родная схема транспорта');
        if ($transport === 'xhttp') connectionDenied(fn() => $bot->connectionExport($source, 'vless', 'si'), 'Неподдерживаемый XHTTP не заменяется другим узлом');
    }
    $bot->conf['transport'] = 'Websocket';
    $original = $bot->templates;
    $bot->templates['clash']['proxies'][] = ['name' => 'unused-warp', 'type' => 'wireguard', 'private-key' => '~warp_private_key~'];
    $bot->connectionExport($source, 'vless', 'cl');
    connectionCheck(true, 'Посторонний WARP не создаёт аккаунт при выгрузке узла');
    $bot->templates = $original;
    $bot->conf['dpi']['fragment'] = ['enabled' => true, 'packets' => 'tlshello', 'length' => '100-200', 'interval' => '10-20'];
    $fragment = $bot->connectionExport($source, 'vless', 's')['outbounds'];
    connectionCheck(count($fragment) === 2 && $fragment[0]['streamSettings']['sockopt']['dialerProxy'] === $fragment[1]['tag'], 'Xray DPI сохраняет требуемый freedom dialer');
    unset($bot->conf['dpi']);
    $beforeGet = $_GET = ['unrelated' => 'keep']; $beforeToken = $bot->subToken = ['r' => 'do-not-use'];
    $bot->connectionExport($source, 'vless', 'cl');
    connectionCheck($_GET === $beforeGet && $bot->subToken === $beforeToken, 'Контекст подписки восстановлен');
    $bot->templates['clash'] = ['proxies' => [['name' => 'missing']]];
    connectionDenied(fn() => $bot->connectionExport($source, 'vless', 'cl'), 'Отсутствующий узел шаблона отклонён');
    connectionCheck($_GET === $beforeGet && $bot->subToken === $beforeToken, 'Контекст восстановлен после отказа'); $bot->templates = $original; $bot->subToken = [];
    foreach ([['tag' => 'a', 'detour' => 'a'], ['tag' => 'a', 'detour' => 'missing']] as $bad) connectionDenied(fn() => Bot::connectionNodes(['outbounds' => [$bad]], 'si'), 'Нет циклических или отсутствующих зависимостей');
    $screen = connectionClick($bot, $prefix);
    connectionCheck(connectionBack($screen) === '/userXr 0', 'Корень экспорта возвращает в своего пользователя');
    foreach (['vless' => 'VLESS'] + ManagedProtocol::NAMES as $p => $_) {
        $screen = connectionClick($bot, "$prefix $p");
        connectionCheck(connectionBack($screen) === $prefix && !str_contains($screen['text'], '❌'), 'Карточка возвращается в выбор протокола');
        foreach (array_keys($bot->connectionFormats($p)) as $format) {
            for ($repeat = 0; $repeat < 2; $repeat++) {
                connectionClick($bot, "$prefix $p $format");
                $files = array_values(array_filter($bot->transport->messages, fn($v) => isset($v['document'])));
                connectionCheck(count($files) === 1 && count($bot->transport->messages) === 2, 'Остаются меню и ровно один файл');
                $file = $files[0]['document'];
                connectionCheck(!str_contains($file->postname, '/') && !str_contains($file->postname, '?'), 'Имя файла безопасно');
                if ($p === 'snolc') { connectionCheck($file->mime === 'application/zip' && str_starts_with($file->data, 'PK'), 'Нативный ZIP отправлен без изменения байтов'); }
                elseif (!in_array($format, ['uri', 'sr'], true)) {
                    $parsed = $format === 'cl' ? yaml_parse($file->data) : json_decode($file->data, true, 512, JSON_THROW_ON_ERROR);
                    connectionCheck($parsed === $bot->connectionExport($source, $p, $format), 'Файл действительно содержит выбранный формат');
                }
            }
        }
        if (!in_array($p, ['vless', 'snolc'], true)) {
            $screen = connectionClick($bot, "$prefix $p ios");
            connectionCheck(connectionBack($screen) === "$prefix $p" && str_contains($screen['text'], 'Shadowrocket'), 'Shadowrocket: правильный возврат и пояснение');
            connectionClick($bot, connectionBack($screen));
        }
        connectionClick($bot, $prefix);
        connectionCheck(count($bot->transport->messages) === 1, 'Выход убирает выгрузки');
    }
    $bot->xr['inbounds'][0]['settings']['clients'][0]['managed_protocols']['anytls'] = false;
    connectionDenied(fn() => $bot->connectionExport($source, 'anytls', 'cl'), 'Персональный запрет протокола');
    $bot->xr['inbounds'][0]['settings']['clients'][0] = $client;
    foreach (['off' => $client['id'], 'time' => time() - 1, 'traffic' => 1] as $field => $value) {
        $bot->xr['inbounds'][0]['settings']['clients'][0][$field] = $value;
        $bot->stats = ['users' => [0 => ['session' => ['upload' => 2, 'download' => 0]]]];
        foreach (['vless', 'anytls', 'mieru', 'tuic', 'shadowtls'] as $p) connectionDenied(fn() => $bot->connectionExport($source, $p, 'cl'), 'Общие ограничения не обходятся экспортом');
        $bot->xr['inbounds'][0]['settings']['clients'][0] = $client;
    }
    $modules->set('tuic', false);
    connectionDenied(fn() => $bot->connectionExport($source, 'tuic', 'cl'), 'Выключенный сервис не экспортируется'); $modules->set('tuic', true);
    $bot->protocolStore('tuic')->configure(['port' => 25555]);
    connectionDenied(fn() => $bot->connectionExport($source, 'tuic', 'cl'), 'Не применённый порт не выдаётся');
    array_unshift($bot->xr['inbounds'][0]['settings']['clients'], array_replace($client, ['id' => Bot::xrayUuid(), 'subtoken' => bin2hex(random_bytes(16))]));
    $screen = connectionClick($bot, $prefix);
    connectionCheck(connectionBack($screen) === '/userXr 1', 'Старый callback следует за пользователем после изменения индекса');
    $bot->permit = false; $before = $bot->transport->messages;
    connectionClick($bot, "$prefix anytls uri"); connectionCheck($before === $bot->transport->messages, 'Чужой пользователь не получает секреты'); $bot->permit = true;
    $bot->xr['inbounds'][0]['settings']['clients'] = [];
    $screen = connectionClick($bot, "$prefix anytls");
    connectionCheck(str_contains($screen['text'], 'удалён') && connectionBack($screen) === '/xray', 'Удалённый пользователь даёт чистую ошибку с возвратом');
    echo "connection_export_test: OK ($checks проверок)\n";
} finally {
    restore_error_handler(); if (session_status() === PHP_SESSION_ACTIVE) session_write_close(); ob_end_flush();
    $remove = static function ($path) use (&$remove) { if (is_dir($path)) { foreach (scandir($path) as $f) if ($f !== '.' && $f !== '..') $remove("$path/$f"); rmdir($path); } else unlink($path); }; $remove($root);
}
