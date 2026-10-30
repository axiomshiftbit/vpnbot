<?php
require_once __DIR__ . '/managed_protocol_fixture.php';
require_once __DIR__ . '/../app/bot.php';
require_once __DIR__ . '/../app/i18n.php';

$checks = 0; $fixtures = []; $screens = [];
function optCheck(bool $ok, string $name): void {
    global $checks;
    if (!$ok) throw new RuntimeException($name);
    $checks++;
}
class OptionsTransport {
    public array $calls = [];
    public function call($method, $data, $json = 0) {
        $this->calls[] = [$method, $data];
        return ['ok' => true, 'result' => ['message_id' => count($this->calls), 'chat' => ['id' => 1]]];
    }
}
class OptionsBot extends Bot {
    public array $conf = [];
    public array $prompts = [];
    public function __construct(array $i) {
        $this->admin = true; $this->i18n = $i; $this->language = 'ru'; $this->ip = '192.0.2.1';
        $this->input = ['chat' => 1, 'message_id' => 1, 'message' => '', 'reply' => false, 'username' => 'fixture'];
        $this->transport = new OptionsTransport();
    }
    public function getPacConf() { return $this->conf + self::PAC_DEFAULTS; }
    public function getDomain($cdn = false) { return 'vpn.example.test'; }
    public function getHashBot($notset = false) { return 'fixture'; }
    public function getWgMsg() { return null; }
    protected function sessionApply(callable $fn) { $fn(); }
    public function stashReply($r, array $state) { $this->prompts[] = $state; }
}
class NavigationBot extends OptionsBot {
    public function stashReply($r, array $state) { Bot::stashReply($r, $state); }
    protected function sessionApply(callable $fn) { $fn(); }
    public function menu($type = false, $arg = false, $return = false) {
        $this->send($this->input['chat'], 'Главное меню');
    }
}
function optClick(OptionsBot $bot, string $callback): array {
    if (preg_match('~^/po (\w+) (\w+)(?: ([\w.-]+))?(?: ([0-9]+))?$~D', $callback, $m)) {
        $callback = ProtocolOptions::callback($m[1], $m[2], $m[3] ?? '', isset($m[4]) ? (int) $m[4] : null);
    }
    $before = count($bot->transport->calls);
    $bot->input['callback'] = $callback; $bot->action(); $bot->input['callback'] = false;
    optCheck(count($bot->transport->calls) > $before, "Диспетчер ответил: $callback");
    if (preg_match('~^/!?po \w+(?: (show|pick|reset)(?: |$)|$)~', $callback)) {
        foreach (array_slice($bot->transport->calls, $before) as [$method]) optCheck($method !== 'sendMessage', 'Навигация параметров не создаёт сообщений');
    }
    [, $data] = end($bot->transport->calls);
    $buttons = json_decode($data['reply_markup'] ?? '{}', true)['inline_keyboard'] ?? [];
    optCheck($bot->messageTextLength($data['text'] ?? '') <= 4096, "Длина сообщения: $callback");
    foreach ($buttons as $row) {
        optCheck(count($row) <= 2, 'Не более двух кнопок в строке');
        foreach ($row as $b) optCheck(strlen($b['callback_data'] ?? '') <= 64 && $b['text'] !== '', "Кнопки: $callback");
    }
    return ['text' => $data['text'] ?? '', 'buttons' => $buttons];
}
function optSample(array $rule, string $protocol, string $path): mixed {
    return match ($rule[0]) {
        'int' => str_ends_with($path, '.maxLen') ? 12 : max($rule[1], min(1400, $rule[2])),
        'duration' => max($rule[1], 1000) . 'ms',
        'text' => 'fixture < &',
        'bool' => true, 'enum' => $rule[1][0],
        'ip' => '1.1.1.1', 'hostname' => 'cover.example.test',
        'list' => [str_ends_with($path, '.alpn') ? ($protocol === 'tuic' ? 'h3' : 'http/1.1') : optSample($rule[1], $protocol, $path)],
        'pin' => base64_encode(str_repeat('a', 32)),
        'hex' => '010203040506', 'rotation' => 'LOW_ENTROPY_MASK_ROTATE_LEFT_15',
        'hosts' => ['target.example.test' => '11.77.0.2'],
        'padding' => ['stop=2', '0=30-30', '1=100-400'],
        default => throw new LogicException('Unknown fixture rule'),
    };
}
function optWalk(OptionsBot $bot, ManagedProtocol $store, string $id, string $path = ''): void {
    global $fixtures, $screens;
    $protocol = $store->protocol; $rule = ProtocolOptions::definition($protocol, $path);
    $screen = optClick($bot, rtrim("/po $protocol show $path"));
    if ($path === '' || !str_contains($path, '.')) $screens["$protocol-$path"] = $screen;
    if ($rule[0] === 'object') {
        foreach ($rule[1] as $field => $child) optWalk($bot, $store, $id, $path === '' ? $field : "$path.$field");
        return;
    }
    $values = $rule[0] === 'enum' ? $rule[1] : ($rule[0] === 'bool' ? [false, true] : [optSample($rule, $protocol, $path)]);
    foreach ($values as $index => $value) {
        $store->configureOption('', null);
        if (str_ends_with($path, '.spoof_method')) $store->configureOption('singbox.tls.spoof', 'cover.example.test');
        if ($value === 'NONCE_TYPE_FIXED') $store->configureOption(substr($path, 0, -4) . 'customHexStrings', ['010203040506']);
        if ($rule[0] === 'enum' || $rule[0] === 'bool') optClick($bot, "/po $protocol pick $path $index");
        else {
            optClick($bot, "/po $protocol edit $path");
            $prompt = end($bot->prompts);
            optCheck($prompt['callback'] === 'protocolOptionReply' && $prompt['args'] === [$protocol, $path], 'Reply привязан к параметру');
            $input = is_string($value) ? $value : json_encode($value, JSON_UNESCAPED_UNICODE);
            $bot->protocolOptionReply($input, $protocol, $path);
        }
        $state = $store->read();
        optCheck(ProtocolOptions::at($state['settings']['options'], $path) === $value, "$protocol: сохранено $path");
        $profiles = [];
        foreach ($store->formats($state) as $format => $_) {
            $profiles[$format] = $store->profile($id, $format, $state);
            if ($format === 'mihomo') optCheck(empty($profiles[$format]['allow-lan']), 'Mihomo закрыт от LAN');
        }
        $fixtures[] = ['protocol' => $protocol, 'path' => $path, 'value' => $value, 'state' => $state, 'profiles' => $profiles];
        $old = file_get_contents($store->directory() . '/desired.json');
        try { $store->configureOption($path, new stdClass()); throw new LogicException('Invalid accepted'); }
        catch (InvalidArgumentException $e) {}
        optCheck(file_get_contents($store->directory() . '/desired.json') === $old, 'Неверный тип не изменяет ревизию или файл');
        $invalids = match ($rule[0]) {
            'int' => [$rule[1] - 1, $rule[2] + 1, (string) $value],
            'enum' => ['__unknown__'], 'bool' => [1, 'true'],
            'duration' => ['-1s', '99999999h', "1s\n", '1'],
            'hostname' => ['https://invalid.test/', '127.0.0.1', "../invalid"],
            'ip' => ['1.2.3.999', 'invalid.test'],
            'list' => [array_fill(0, $rule[2] + 1, $value[0]), ['unknown' => true]],
            'pin' => [base64_encode('short')], 'hex' => ['0x12', 'xyz'],
            'text' => ["bad\nvalue"], 'padding' => [['stop=999', '0=1-2'], ['stop=2', '0=99999-99999']],
            'hosts' => [['invalid.test' => '127.999.0.1']], 'rotation' => ['LOW_ENTROPY_MASK_ROTATE_RIGHT_16'],
        };
        foreach ($invalids as $invalid) {
            try { $store->configureOption($path, $invalid); throw new LogicException("Неверное значение принято: $path"); }
            catch (InvalidArgumentException $e) {}
            optCheck(file_get_contents($store->directory() . '/desired.json') === $old, "$path: пределы и формат ввода");
        }
        optClick($bot, "/po $protocol reset $path");
        optCheck(ProtocolOptions::at($store->read()['settings']['options'], $path) === null, 'Сброс параметра');
    }
}
$root = sys_get_temp_dir() . '/vpnbot-options-' . bin2hex(random_bytes(6)); mkdir($root, 0700);
set_error_handler(static function($level, $message, $file, $line) {
    if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line);
    return false;
});
try {
    $bot = new OptionsBot($i); $bot->protocolRoot = "$root/protocols";
    $bot->protocolModulesFile = "$root/modules.json"; $bot->upstreamFile = "$root/upstream.conf";
    $modules = new ProtocolModules($bot->protocolModulesFile);
    foreach (ManagedProtocol::NAMES as $protocol => $_) {
        if ($protocol === 'snolc') {
            optCheck(ProtocolOptions::groups($protocol) === [] && ProtocolOptions::schema($protocol) === [], 'snolc не предлагает настройки чужих ядер');
            continue;
        }
        $store = $bot->protocolStore($protocol); $store->configure(['host' => 'vpn.example.test', 'sni' => 'vpn.example.test'], true);
        $id = managedProtocolFixtureUser($store, 'Fixture < &'); $modules->set($protocol, true);
        $baseline = $store->read()['config'];
        if ($protocol === 'mieru') {
            $path = 'server.advancedSettings.tcpIdleTimeout';
            $profile = $store->profile($id, 'native');
            optCheck(!isset($baseline['advancedSettings']['tcpIdleTimeout']), 'Mieru: тайм-аут по умолчанию выключен');
            $store->configureOption($path, '15m');
            optCheck($store->read()['config']['advancedSettings']['tcpIdleTimeout'] === '15m', 'Mieru: тайм-аут передаётся ядру');
            optCheck($store->profile($id, 'native') === $profile, 'Mieru: серверный тайм-аут не меняет профиль клиента');
            $snapshot = $store->snapshot();
            $store->configureOption($path, null);
            optCheck(!isset($store->read()['config']['advancedSettings']['tcpIdleTimeout']), 'Mieru: сброс выключает тайм-аут');
            $store->restore($snapshot);
            optCheck($store->read()['config']['advancedSettings']['tcpIdleTimeout'] === '15m', 'Mieru: бэкап восстанавливает тайм-аут');
            $store->configureOption($path, null);
        }
        if ($protocol === 'masque') continue; // Native MASQUE schema and exports: masque_test.php.
        $conflicts = match ($protocol) {
            'anytls' => [
                ['server' => ['tls' => ['min_version' => '1.3']], 'singbox' => ['tls' => ['max_version' => '1.2']]],
                ['server' => ['tls' => ['alpn' => ['http/1.1']]], 'client' => ['alpn' => ['h2']]],
                ['client' => ['idle_session_timeout' => '1500ms']],
            ],
            'tuic' => [
                ['client' => ['alpn' => []]],
                ['server' => ['tls' => ['min_version' => '1.2']]],
                ['server' => ['stream_receive_window' => 32768, 'connection_receive_window' => 16384]],
            ],
            'mieru' => [
                ['server' => ['advancedSettings' => ['tcpIdleTimeout' => '0s']]],
                ['server' => ['advancedSettings' => ['tcpIdleTimeout' => '59s']]],
                ['server' => ['advancedSettings' => ['tcpIdleTimeout' => '25h']]],
                ['server' => ['trafficPattern' => ['nonce' => ['maxLen' => 6]]]],
                ['client' => ['trafficPattern' => ['nonce' => ['minLen' => 12, 'maxLen' => 6]]]],
                ['native' => ['socks5Port' => 1081]],
            ],
            'shadowtls' => [
                ['multiplex' => ['min_streams' => 2, 'max_streams' => 4]],
                ['singbox' => ['tls' => ['spoof_method' => 'wrong-sequence']]],
                ['singbox' => ['tls' => ['max_version' => '1.2']]],
            ],
        };
        foreach ($conflicts as $options) {
            $before = file_get_contents($store->directory() . '/desired.json');
            try { $store->configure(['options' => $options]); throw new LogicException('Несовместимые настройки приняты'); }
            catch (InvalidArgumentException $e) {}
            optCheck(file_get_contents($store->directory() . '/desired.json') === $before, "$protocol: несовместимые параметры не меняют рабочее состояние");
        }
        optWalk($bot, $store, $id);
        if ($protocol === 'shadowtls') {
            $store->configureOption('multiplex.enabled', true);
            optCheck($store->profile($id, 'mihomo')['proxies'][0]['smux']['protocol'] === 'smux'
                && $store->profile($id, 'singbox')['outbounds'][0]['multiplex']['protocol'] === 'smux', 'Включение мультиплексирования по умолчанию выбирает smux в обоих клиентах');
        }
        $store->configureOption('', null);
        optCheck($store->read()['config'] === $baseline, "$protocol: сброс восстанавливает базовый конфиг");
        foreach (['server.users', 'server.listen', 'singbox.tls.insecure', 'singbox.tls.key_path', 'unknown', 'server..tls'] as $path) {
            $before = $store->read(); $bot->protocolOptionReply('true', $protocol, $path);
            optCheck($store->read() === $before, 'Чужие структурные поля запрещены');
        }
        $sub = optClick($bot, "/ps $protocol $id"); $screens["$protocol-subscription"] = $sub;
        optCheck(str_contains($sub['text'], '/mihomo'), 'Ссылка подписки Mihomo');
        $provider = optClick($bot, "/ps $protocol $id direct provider");
        preg_match('~<pre><code class="language-yaml">(.*?)</code></pre>~s', $provider['text'], $m);
        $parsed = yaml_parse(html_entity_decode($m[1], ENT_QUOTES | ENT_HTML5, 'UTF-8'));
        optCheck($parsed['proxy-providers']["$protocol-$id"]['interval'] === 3600, 'Provider обновляется');
        optCheck($parsed['proxy-groups'][0]['use'] === ["$protocol-$id"], 'Группа ссылается на provider');
        $back = end($sub['buttons'])[0]['callback_data'];
        optCheck(!str_contains(optClick($bot, $back)['text'], 'Неизвестное'), 'Назад из подписок');
        $nav = new NavigationBot($i);
        $nav->protocolRoot = $bot->protocolRoot; $nav->protocolModulesFile = $bot->protocolModulesFile; $nav->upstreamFile = $bot->upstreamFile;
        foreach (['/!protocol' => '/menu', '/protocol' => '/protocolModules'] as $entry => $back) {
            $screen = optClick($nav, "$entry $protocol");
            optCheck(end($screen['buttons'])[0]['callback_data'] === $back, "$protocol: возврат в точку входа");
            $prefix = $entry === '/!protocol' ? '/!' : '/';
            $subscreen = optClick($nav, $prefix . "ps $protocol $id");
            optCheck(end($subscreen['buttons'])[0]['callback_data'] === $prefix . "protocol $protocol user $id", 'Подписки сохраняют контекст');
            $options = optClick($nav, $prefix . "po $protocol");
            optCheck(end($options['buttons'])[0]['callback_data'] === "$entry $protocol", 'Настройки сохраняют контекст');
            $screen = optClick($nav, end($options['buttons'])[0]['callback_data']);
            optCheck(end($screen['buttons'])[0]['callback_data'] === $back, 'Вложенный переход не меняет точку входа');
        }
        $prompt = optClick($nav, "/!protocol $protocol name $id");
        $replyId = count($nav->transport->calls);
        optCheck(!empty($_SESSION['reply'][$nav->input['chat'] . ':' . $replyId]['protocol_main']), 'ForceReply сохраняет точку входа');
        $nav->input['reply'] = $replyId; $nav->input['message'] = 'После ответа'; $nav->input['message_id'] = 999;
        $nav->reply();
        [, $data] = end($nav->transport->calls);
        $buttons = json_decode($data['reply_markup'], true)['inline_keyboard'];
        optCheck(end($buttons)[0]['callback_data'] === "/!protocol $protocol", 'Возврат после ForceReply');
        optCheck(!$nav->protocolReturnMain, 'Контекст не остаётся для следующего обновления');
        optCheck(optClick($nav, '/menu')['text'] === 'Главное меню', 'Реальный callback возвращает в главное меню');
        $store->user($id, ['enabled' => false]);
        optCheck(!str_contains(optClick($bot, "/ps $protocol $id")['text'], $store->read()['users'][$id]['token']), 'Закрытая подписка не раскрывает URL');
        $before = $store->read(); $calls = count($bot->transport->calls); $bot->admin = false;
        foreach (["/po $protocol reset", "/ps $protocol $id"] as $callback) { $bot->input['callback'] = $callback; $bot->action(); }
        optCheck($store->read() === $before && count($bot->transport->calls) === $calls, 'Посторонний callback не имеет доступа');
        $bot->admin = true;
    }
    if ($output = getenv('VPNBOT_OPTIONS_FIXTURES')) {
        file_put_contents($output, json_encode($fixtures, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
        chmod($output, 0600);
        file_put_contents($output . '.screens.json', json_encode($screens, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR));
        chmod($output . '.screens.json', 0600);
    }
    echo "protocol_options_test: OK ($checks проверок, " . count($fixtures) . " вариантов)\n";
} finally {
    restore_error_handler();
    $remove = static function($path) use (&$remove) {
        if (is_dir($path)) { foreach (scandir($path) as $f) if ($f !== '.' && $f !== '..') $remove("$path/$f"); rmdir($path); }
        else unlink($path);
    };
    $remove($root);
}
