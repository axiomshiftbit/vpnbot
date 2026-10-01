<?php
require_once __DIR__ . '/managed_protocol_fixture.php';
require_once __DIR__ . '/../app/bot.php';
require_once __DIR__ . '/../app/i18n.php';

$checks = 0;
function relayCheck(bool $ok, string $label): void {
    global $checks;
    if (!$ok) throw new RuntimeException($label);
    $checks++;
}
class ManagedRelayTransport {
    public array $calls = [];
    public function call($method, $data, $json = 0) {
        $this->calls[] = [$method, $data];
        return ['ok' => true, 'result' => ['message_id' => count($this->calls), 'chat' => ['id' => 1]]];
    }
}
class ManagedRelayBot extends Bot {
    public array $conf = ['relays' => []];
    public array $prompts = [];
    public array $qr = [];
    public function __construct(array $translations) {
        $this->admin = true; $this->i18n = $translations; $this->language = 'ru'; $this->ip = '192.0.2.1';
        $this->input = ['chat' => 1, 'message_id' => 1, 'username' => 'fixture', 'message' => '', 'reply' => false];
        $this->transport = new ManagedRelayTransport();
    }
    public function getPacConf() { return $this->conf + self::PAC_DEFAULTS; }
    public function setPacConf(array $conf) { $this->conf = $conf; return true; }
    public function getDomain($cdn = false) { return 'origin.example.test'; }
    public function getHashBot($notset = false) { return 'fixture'; }
    public function getWgMsg() { return null; }
    protected function sessionApply(callable $fn) { $fn(); }
    public function readRelayHealth(): array { return []; }
    public function stashReply($r, array $state) { $this->prompts[] = $state; }
    public function sendQr($name, $code, $title = false) { $this->qr[] = $code; }
    public function subSecurityHeaders() {}
    public function subRateLimit($sid, $scope = '') {}
    public function processHwidRequest(array $client, bool $htmlPreview = false) { return true; }
}
function relayScreen(ManagedRelayBot $bot): array {
    [, $data] = end($bot->transport->calls);
    $buttons = json_decode($data['reply_markup'] ?? '{}', true)['inline_keyboard'] ?? [];
    relayCheck($bot->messageTextLength($data['text'] ?? '') <= 4096, 'Лимит текста Telegram');
    foreach ($buttons as $row) foreach ($row as $button) relayCheck(strlen($button['callback_data'] ?? '') <= 64, 'Лимит callback Telegram');
    return [$data['text'] ?? '', $buttons];
}
function relayClick(ManagedRelayBot $bot, string $callback): void {
    $bot->input['callback'] = $callback; $bot->action(); $bot->input['callback'] = false;
}
function relayResponse(ManagedRelayBot $bot, string $protocol, string $token, string $format, array $query): array {
    $_GET = $query; http_response_code(200); ob_start();
    $bot->protocolMachine($protocol, $token, $format);
    return [http_response_code(), ob_get_clean()];
}
$root = sys_get_temp_dir() . '/vpnbot-relay-' . bin2hex(random_bytes(6));
mkdir($root, 0700); ob_start();
set_error_handler(static function ($level, $message, $file, $line) {
    if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line);
    return false;
});
try {
    $bot = new ManagedRelayBot($i);
    $bot->protocolRoot = "$root/protocols"; $bot->protocolModulesFile = "$root/modules.json"; $bot->upstreamFile = "$root/upstream.conf";
    $modules = new ProtocolModules($bot->protocolModulesFile);
    $name = 'relay.with.dots-' . str_repeat('r', 16);
    $bot->conf['relays'][$name] = ['address' => 'legacy.example.test', 'portmap' => [443 => 444], 'hy_port' => 1234];
    $key = substr(hash('sha256', $name), 0, 16);
    foreach (array_diff_key(ManagedProtocol::NAMES, ['snolc' => true, 'masque' => true]) as $protocol => $label) {
        $store = $bot->protocolStore($protocol);
        $store->configure(['host' => 'origin.example.test', 'sni' => $protocol . '.example.test'], true);
        $id = managedProtocolFixtureUser($store, 'Пользователь < &'); $modules->set($protocol, true);
        $before = $store->read();
        relayClick($bot, "/prset $protocol $name");
        $prompt = end($bot->prompts);
        relayCheck($prompt['callback'] === 'protocolRelayReply' && $prompt['args'] === [$protocol, $name], 'Реальный диспетчер ввода relay');
        $bot->protocolRelayReply('relay.example.test 10443', $protocol, $name);
        [$text, $buttons] = relayScreen($bot);
        relayCheck(str_contains(json_encode($buttons), "/prset $protocol"), 'Настройка доступна из карточки relay');
        relayCheck($bot->conf['relays'][$name]['hy_port'] === 1234, 'Настройки прежних протоколов сохранены');
        foreach (['198.51.100.7', 'relay.example.test', '2001:db8::7'] as $host) {
            $endpoint = ['host' => $host, 'port' => 10443];
            foreach ($store->formats() as $format => $_) {
                $result = $store->profile($id, $format, endpoint: $endpoint);
                if ($format === 'mihomo') {
                    $proxy = $result['proxies'][0];
                    relayCheck($proxy['server'] === $host && $proxy['port'] === 10443, "$protocol: endpoint YAML");
                    $direct = $store->profile($id, $format); $result['proxies'][0]['server'] = $direct['proxies'][0]['server'];
                    $result['proxies'][0]['port'] = $direct['proxies'][0]['port'];
                    relayCheck($result === $direct, "$protocol: SNI, TLS, ключи и правила YAML сохранены");
                } elseif (str_starts_with($format, 'singbox')) {
                    foreach ($result['outbounds'] as $out) relayCheck($out['server'] === $host && $out['server_port'] === 10443, "$protocol: endpoint sing-box, включая detour");
                    $direct = $store->profile($id, $format);
                    foreach ($result['outbounds'] as $n => &$out) { $out['server'] = $direct['outbounds'][$n]['server']; $out['server_port'] = $direct['outbounds'][$n]['server_port']; } unset($out);
                    relayCheck($result === $direct, "$protocol: остальные настройки sing-box сохранены");
                } elseif ($format === 'native') {
                    $server = $result['profiles'][0]['servers'][0];
                    relayCheck(($server['ipAddress'] ?? $server['domainName']) === $host && $server['portBindings'][0]['port'] === 10443, 'Endpoint нативного Mieru');
                } elseif ($format === 'native-uri') {
                    $raw = base64_decode(substr($result, 8), true);
                    relayCheck(str_contains($raw, $host) && !str_contains($raw, 'origin.example.test'), 'Endpoint mieru://');
                } else {
                    relayCheck(trim(parse_url($result, PHP_URL_HOST), '[]') === $host, 'Хост URI, включая IPv6');
                    parse_str(parse_url($result, PHP_URL_QUERY), $query);
                    relayCheck((parse_url($result, PHP_URL_PORT) ?? (int) $query['port']) === 10443, 'Внешний порт URI');
                    if ($protocol === 'anytls') relayCheck($query['sni'] === 'anytls.example.test' && $query['insecure'] === '0', 'AnyTLS relay сохраняет проверяемый SNI');
                }
            }
        }
        foreach ([[], ['host' => 'bad/path', 'port' => 443], ['host' => "bad\nhost", 'port' => 443], ['host' => 'ok.test', 'port' => 0], ['host' => 'ok.test', 'port' => 65536], ['host' => 'ok.test', 'port' => '443'], ['host' => 'ok.test', 'port' => 443, 'sni' => 'evil.test']] as $endpoint) {
            try { $store->profile($id, 'mihomo', endpoint: $endpoint); throw new LogicException('Принят неверный endpoint'); } catch (InvalidArgumentException $e) { $checks++; }
        }
        relayCheck($store->read() === $before, 'Экспорт relay не меняет состояние сервера');
        $saved = $bot->conf;
        foreach (['host.test 0', 'host.test 999999', 'https://relay.test 443', '<b> 443', 'ok.test 443 extra'] as $bad) {
            $bot->protocolRelayReply($bad, $protocol, $name); relayCheck($bot->conf === $saved, 'Ошибка ввода сохраняет прежний relay');
        }
        relayClick($bot, "/protocol $protocol relays $id"); [$text, $buttons] = relayScreen($bot);
        relayCheck(str_contains(json_encode($buttons), "/pr $protocol $id $key"), 'Выбор relay через диспетчер');
        relayClick($bot, "/pr $protocol $id $key"); [$text, $buttons] = relayScreen($bot);
        relayCheck(str_contains($text, '?relay=' . $name), 'Ссылка подписки содержит имя relay');
        relayClick($bot, "/pr $protocol $id $key yaml"); [$text] = relayScreen($bot);
        relayCheck(str_contains($text, 'relay.example.test') && str_contains($text, '10443'), 'Копируемый YAML использует relay');
        relayClick($bot, "/pr $protocol $id $key mihomo");
        [$method, $data] = end($bot->transport->calls);
        relayCheck($method === 'sendDocument' && str_contains($data['document']->data, 'relay.example.test'), 'Файл через relay');
        if (isset($store->formats()['uri'])) { relayClick($bot, "/pr $protocol $id $key qr"); relayCheck(str_contains(end($bot->qr), 'relay.example.test'), 'QR через relay'); }
        file_put_contents($bot->upstreamFile, "anytls.example.test anytls_bridge;\n");
        ManagedProtocol::writeJson("$root/protocol-services.status.json", ['bindings' => [$protocol => $before['settings']['port']]]);
        ManagedProtocol::writeJson($store->directory() . '/runtime/status.json', ['running' => true, 'phase' => 'running', 'time' => time(), 'revision' => $before['revision']]);
        $token = $before['users'][$id]['token'];
        [$code, $body] = relayResponse($bot, $protocol, $token, 'mihomo', ['relay' => $name]);
        relayCheck($code === 200 && yaml_parse($body)['proxies'][0]['server'] === 'relay.example.test', 'Действующая HTTP-подписка relay');
        foreach ([['relay' => 'missing'], ['relay' => []], ['relay' => ''], ['relay' => '../bad']] as $query) {
            [$code, $body] = relayResponse($bot, $protocol, $token, 'mihomo', $query);
            relayCheck($code === 404 && $body === '', 'Неверный relay не раскрывает прямой профиль');
        }
        $store->user($id, ['enabled' => false]);
        [$code, $body] = relayResponse($bot, $protocol, $token, 'mihomo', ['relay' => $name]);
        relayCheck($code === 404 && $body === '', 'Отзыв доступа закрывает relay-подписку');
        $store->user($id, ['enabled' => true]); $modules->set($protocol, false);
        [$code, $body] = relayResponse($bot, $protocol, $token, 'mihomo', ['relay' => $name]);
        relayCheck($code === 404 && $body === '', 'Выключатель контейнера закрывает relay-подписку');
        $modules->set($protocol, true);
        $bot->protocolRelayReply('0', $protocol, $name);
        relayClick($bot, "/pr $protocol $id $key"); [$text] = relayScreen($bot);
        relayCheck(str_contains($text, 'Relay удалён'), 'Старый callback после отключения не ведёт на origin');
        $bot->admin = false; $saved = $bot->conf; $calls = count($bot->transport->calls);
        relayClick($bot, "/prset $protocol $name"); $bot->protocolRelayReply('evil.test 443', $protocol, $name); relayClick($bot, "/pr $protocol $id page");
        relayCheck($bot->conf === $saved && count($bot->transport->calls) === $calls, 'Управление relay доступно только администратору');
        $bot->admin = true;
    }
    ob_end_clean(); echo "managed_protocol_relay_test: OK ($checks проверок)\n";
} finally {
    restore_error_handler(); $_GET = [];
    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($files as $file) $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
    rmdir($root);
}
