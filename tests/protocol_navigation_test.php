<?php
require_once __DIR__ . '/managed_protocol_fixture.php';
require_once __DIR__ . '/../app/bot.php';
require_once __DIR__ . '/../app/i18n.php';

// Keep a real message ledger: a successful send is not an edit of the menu.
class ProtocolChatTransport {
    public array $messages = [1 => ['text' => 'Menu']];
    public array $calls = [];
    public int $next = 100;
    public function call($method, $data, $json = 0) {
        $this->calls[] = [$method, $data];
        $id = $data['message_id'] ?? ++$this->next;
        if ($method === 'deleteMessage') unset($this->messages[$id]);
        elseif (in_array($method, ['sendMessage', 'sendDocument', 'sendPhoto', 'editMessageText'], true)) {
            if ($method === 'editMessageText' && !isset($this->messages[$id])) throw new RuntimeException('Edit of a missing message');
            $this->messages[$id] = $data;
        }
        return ['ok' => true, 'result' => ['message_id' => $id, 'chat' => ['id' => 1]]];
    }
}
class ProtocolChatBot extends Bot {
    public array $conf = [];
    public array $xr = ['inbounds'=>[['settings'=>['clients'=>[]]]]];
    public bool $qrFallback = false;
    public function __construct(array $i) {
        $this->i18n = $i; $this->language = 'ru'; $this->ip = '192.0.2.1';
        $this->transport = new ProtocolChatTransport();
    }
    public function auth() { $this->admin = true; }
    public function getPacConf() { return $this->conf + self::PAC_DEFAULTS; }
    public function getXray() { return $this->xr; }
    public function getXrayStats() { return []; }
    public function xrayConfUpdate(callable $fn, $norestart = false) { $fn($this->xr); }
    public function setPacConf(array $conf) { $this->conf = $conf; return true; }
    public function getDomain($cdn = false) { return 'vpn.example.test'; }
    public function getHashBot($notset = false) { return 'fixture'; }
    public function getWgMsg() { return null; }
    public function readRelayHealth(): array { return []; }
    public function getSSConfig() { return []; }
    public function getCloakConfig() { return []; }
    public function getStlsConfig() { return []; }
    public function getPorts() { return array_fill_keys(['wg', 'wg1', 'telemt', 'ss', 'hy'], ['enable' => true, 'port' => 24440]); }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') { return ''; }
    public function nginxGetTypeCert() { return false; }
    public function subscription($return = false) { return $_GET['t'] === 'cl' ? "proxies: []\n" : '{"outbounds":[]}'; }
    // Exercise the real output tracking without requiring qrencode or /logs in CI.
    public function sendQr($name, $code, $title = false) {
        if ($this->qrFallback) return parent::sendQr($name, str_repeat('a', self::QR_MAX_BYTES + 1), $title);
        return $this->sendPhoto($this->input['chat'], 'fixture-photo', $name);
    }
    public function upload($name, $code, $chat = false) {
        return $this->sendFile($chat ?: $this->input['chat'], new CURLStringFile($code, $name));
    }
    public function menu($type = false, $arg = false, $return = false) {
        $this->update(1, $this->input['message_id'], $type === 'config' ? 'Settings' : 'Menu');
    }
}
$checks = 0;
function chatCheck(bool $ok, string $label): void {
    global $checks;
    if (!$ok) throw new RuntimeException($label);
    $checks++;
}
function chatClick(ProtocolChatBot $bot, string $callback, int $menu = 1): array {
    $bot->input(['callback_query' => ['id' => 'fixture', 'from' => ['id' => 90123, 'username' => 'fixture'],
        'message' => ['message_id' => $menu, 'chat' => ['id' => 1]], 'data' => $callback]]);
    $screen = $bot->transport->messages[$menu];
    chatCheck($bot->messageTextLength($screen['text'] ?? '') <= 4096, 'Экран помещается в Telegram');
    foreach (chatButtons($screen) as $button) chatCheck(strlen($button['callback_data'] ?? '') <= 64, 'Callback помещается в Telegram');
    return $screen;
}
function chatReply(ProtocolChatBot $bot, string $text): array {
    $prompts = array_filter($bot->transport->messages, static fn($v) => !empty(json_decode($v['reply_markup'] ?? '{}', true)['force_reply']));
    chatCheck(count($prompts) === 1, 'В чате один запрос ввода');
    $id = ++$bot->transport->next;
    $bot->transport->messages[$id] = ['text' => $text];
    $bot->input(['message' => ['message_id' => $id, 'chat' => ['id' => 1], 'from' => ['id' => 90123, 'username' => 'fixture'],
        'text' => $text, 'reply_to_message' => ['message_id' => array_key_first($prompts)]]]);
    chatCheck(count($bot->transport->messages) === 1, 'Ввод и запрос удалены, остаётся одно меню');
    return $bot->transport->messages[1];
}
function chatButtons(array $screen): array {
    return array_merge(...(json_decode($screen['reply_markup'] ?? '{}', true)['inline_keyboard'] ?? [[]]));
}
function chatBack(array $screen): string {
    $buttons = chatButtons($screen);
    return end($buttons)['callback_data'];
}
$root = sys_get_temp_dir() . '/vpnbot-chat-' . bin2hex(random_bytes(6));
mkdir($root, 0700); mkdir($root . '/sessions', 0700);
session_save_path($root . '/sessions');
ob_start();
set_error_handler(static function ($level, $message, $file, $line) {
    if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line);
    return false;
});
try {
    $bot = new ProtocolChatBot($i); $bot->protocolRoot = $root . '/protocols';
    $bot->protocolModulesFile = $root . '/modules.json'; $bot->upstreamFile = $root . '/upstream.conf';
    foreach (array_diff_key(ManagedProtocol::NAMES, ['snolc' => true]) as $protocol => $name) {
        $store = $bot->protocolStore($protocol);
        $store->configure(['host' => 'vpn.example.test', 'sni' => in_array($protocol, ['mieru', 'snolc'], true) ? '' : 'vpn.example.test']);
        $id = managedProtocolFixtureUser($store, 'Навигация');
        $store->configure([], true); (new ProtocolModules($bot->protocolModulesFile))->set($protocol, true);
        if ($protocol === 'masque') {
            $screen = chatClick($bot, '/protocolModules');
            $callbacks = array_column(chatButtons($screen), 'callback_data');
            chatCheck(!in_array('/protocolModules masque', $callbacks, true) && count(array_keys($callbacks, '/protocol masque', true)) === 1,
                'MASQUE: единая кнопка открывает настройки как у остальных управляемых протоколов');
            $rows = json_decode($screen['reply_markup'], true)['inline_keyboard'];
            $row = array_values(array_filter($rows, static fn($row) => in_array('/protocol masque', array_column($row, 'callback_data'), true)))[0];
            chatCheck(count($row) === 1 && str_contains($row[0]['text'], 'MASQUE'), 'MASQUE: название протокола занимает всю строку');
            foreach ([true, false, true] as $enabled) {
                $before = $store->snapshot();
                $settingsBefore = file_get_contents($bot->protocolModulesFile);
                $screen = chatClick($bot, '/protocol masque');
                chatCheck($store->snapshot() === $before && file_get_contents($bot->protocolModulesFile) === $settingsBefore,
                    'MASQUE: открытие настроек не переключает сервис и не меняет доступы');
                chatCheck(in_array('/protocol masque toggle', array_column(chatButtons($screen), 'callback_data'), true),
                    'MASQUE: выключатель доступен внутри настроек');
                chatCheck(chatBack($screen) === '/protocolModules', 'MASQUE: возврат из настроек ведёт в общий список');
                if ($enabled) {
                    $screen = chatClick($bot, '/protocol masque toggle');
                    chatCheck(!$store->read()['enabled'] && !(new ProtocolModules($bot->protocolModulesFile))->enabled('masque'),
                        'MASQUE: выключатель в настройках отключает оба состояния');
                } else {
                    $screen = chatClick($bot, '/protocol masque toggle');
                    chatCheck($store->read()['enabled'] && (new ProtocolModules($bot->protocolModulesFile))->enabled('masque'),
                        'MASQUE: выключатель в настройках включает оба состояния');
                }
                chatCheck($store->read()['users'] === $before['state']['users'] && $store->read()['settings'] === $before['state']['settings'],
                    'MASQUE: выключатель сохраняет пользователей и настройки');
                chatCheck(chatBack($screen) === '/protocolModules' && count($bot->transport->messages) === 1,
                    'MASQUE: переключение сохраняет карточку без новых сообщений');
                $screen = chatClick($bot, chatBack($screen));
                $buttons = array_column(chatButtons($screen), 'text', 'callback_data');
                chatCheck(str_starts_with($buttons['/protocol masque'], $enabled ? '🔴' : '🟢'), 'MASQUE: цвет в общем списке отражает состояние');
            }
            chatClick($bot, '/protocol masque toggle');
            // Старое сообщение в чате может содержать прежнюю кнопку выключателя.
            foreach ([false, true] as $enabled) {
                $screen = chatClick($bot, '/protocolModules masque');
                chatCheck($store->read()['enabled'] === $enabled && (new ProtocolModules($bot->protocolModulesFile))->enabled('masque') === $enabled,
                    'MASQUE: реальный callback переключает оба состояния');
                $buttons = array_column(chatButtons($screen), 'text', 'callback_data');
                chatCheck(str_starts_with($buttons['/protocol masque'], $enabled ? '🟢' : '🔴'), 'MASQUE: цвет отражает новое состояние');
                chatCheck(chatBack($screen) === '/menu config' && count($bot->transport->messages) === 1,
                    'MASQUE: переключение остаётся в общем списке без новых сообщений');
                $detail = chatClick($bot, '/protocol masque');
                chatCheck(chatBack($detail) === '/protocolModules', 'MASQUE: настройки доступны при любом состоянии и возвращают в список');
            }
        }
        chatClick($bot, "/!protocol $protocol");
        for ($repeat = 0; $repeat < 3; $repeat++) {
            $screen = chatClick($bot, "/!po $protocol");
            chatCheck(count($bot->transport->messages) === 1, "$protocol: дополнительные настройки редактируют одно меню");
            chatClick($bot, chatBack($screen));
        }
        $walk = function (string $path = '') use (&$walk, $bot, $protocol): void {
            $rule = ProtocolOptions::definition($protocol, $path);
            $screen = chatClick($bot, '/!' . substr(ProtocolOptions::callback($protocol, 'show', $path), 1));
            chatCheck(count($bot->transport->messages) === 1, "$protocol/$path: один экран");
            if ($path !== '') chatCheck(ProtocolOptions::hint($protocol, $path) !== '', "$protocol/$path: есть объяснение функции");
            if ($rule[0] === 'object') foreach ($rule[1] as $key => $_) $walk($path === '' ? $key : "$path.$key");
            else {
                chatClick($bot, chatBack($screen));
                chatCheck(count($bot->transport->messages) === 1, 'Назад не оставляет дочерний экран');
            }
        };
        $walk();
        if (in_array($protocol, ['anytls', 'shadowtls'], true)) {
            foreach (ProtocolOptions::FINGERPRINTS as $n => $value) {
                $screen = chatClick($bot, "/!pf $protocol pick $n");
                chatCheck(chatBack($screen) === "/!protocol $protocol", 'Быстрый fingerprint возвращается прямо в протокол');
                chatCheck($store->read()['settings']['options']['client']['fingerprint'] === $value, 'Fingerprint применяется');
            }
            chatClick($bot, "/!pf $protocol reset");
            $screen = chatClick($bot, "/!po $protocol show client.fingerprint");
            chatCheck(chatBack($screen) === "/!po $protocol show client", 'Вложенный fingerprint возвращается в группу');
        }
        $path = $protocol === 'masque' ? 'noise.reset' : ($protocol === 'mieru' ? 'server.mtu' : 'singbox.connect_timeout');
        chatClick($bot, "/!po $protocol edit $path");
        $screen = chatReply($bot, 'неверно');
        chatCheck(str_contains($screen['text'], '❌'), 'Ошибка ввода видна в текущем меню');
        chatClick($bot, chatButtons($screen)[0]['callback_data']);
        $screen = chatReply($bot, $protocol === 'masque' ? '60-120' : ($protocol === 'mieru' ? '1400' : '10s'));
        chatCheck(!str_contains($screen['text'], '❌'), 'Повторный ввод сохраняется');
        chatClick($bot, "/!po $protocol reset");
        foreach (["name $id" => 'Новое имя', "quota $id" => '0.5', "expires $id" => '2026-12-01 12:00'] as $action => $value) {
            chatClick($bot, "/!protocol $protocol $action"); chatReply($bot, $value);
        }
        $store->user($id, ['quota' => null, 'expires' => null]);
        foreach (['/protocol' => '/protocolModules', '/!protocol' => '/menu'] as $entry => $rootBack) {
            $prefix = $entry === '/!protocol' ? '/!' : '/';
            chatClick($bot, "$entry $protocol");
            $rootRelay = chatClick($bot, $prefix . "prmanage $protocol");
            chatCheck(chatBack($rootRelay) === "$entry $protocol", 'Relay сервиса возвращает в сервис, а не VLESS');
            chatClick($bot, chatBack($rootRelay));
            chatClick($bot, "$entry $protocol user $id");
            $list = chatClick($bot, "$entry $protocol relays $id");
            $manage = array_values(array_filter(chatButtons($list), static fn($b) => str_contains($b['callback_data'], 'prmanage')))[0];
            $screen = chatClick($bot, $manage['callback_data']);
            chatCheck(chatBack($screen) === $prefix . "pr $protocol $id page", 'Общий relay возвращается в исходный протокол');
            chatClick($bot, '/relayAdd'); chatReply($bot, 'relay-' . $protocol);
            chatClick($bot, "/prset $protocol relay-$protocol"); $screen = chatReply($bot, 'неверно');
            chatClick($bot, chatButtons($screen)[0]['callback_data']); chatReply($bot, 'relay.example.test 10443');
            $screen = chatClick($bot, '/relayMenu');
            chatCheck(chatBack($screen) === $prefix . "pr $protocol $id page", 'Контекст relay сохранён после ответа');
            chatClick($bot, chatBack($screen));
            $key = substr(hash('sha256', 'relay-' . $protocol), 0, 16);
            $screen = chatClick($bot, $prefix . "pr $protocol $id $key");
            foreach ($protocol === 'masque' ? [''] : ['', 'provider'] as $action) {
                chatClick($bot, rtrim($prefix . "ps $protocol $id $key $action"));
                chatCheck(count($bot->transport->messages) === 1, 'Подписка и provider редактируют меню');
            }
            if ($protocol !== 'masque') chatClick($bot, $prefix . "pr $protocol $id $key yaml");
            $exportFormat = $protocol === 'masque' ? 'native' : 'mihomo';
            chatClick($bot, $prefix . "pr $protocol $id $key $exportFormat");
            chatCheck(count($bot->transport->messages) === 2, 'Выгрузка: меню и один файл');
            chatClick($bot, $prefix . "pr $protocol $id $key $exportFormat");
            chatCheck(count($bot->transport->messages) === 2, 'Повторная выгрузка убирает предыдущий файл');
            chatClick($bot, "$entry $protocol");
            chatCheck(count($bot->transport->messages) === 1, 'Выход удаляет временную выгрузку');
            chatCheck(chatBack($bot->transport->messages[1]) === $rootBack, 'Возврат на исходный уровень');
            foreach (isset($store->formats()['uri']) ? [false, false, true] : [] as $fallback) {
                $bot->qrFallback = $fallback;
                chatClick($bot, $prefix . "pr $protocol $id $key qr");
                chatCheck(count($bot->transport->messages) === ($fallback ? 3 : 2), "$protocol: QR заменяет прошлую выгрузку; длинный QR даёт файл и пояснение (" . count($bot->transport->messages) . ')');
            }
            $bot->qrFallback = false;
            chatClick($bot, "$entry $protocol");
            chatCheck(count($bot->transport->messages) === 1, 'Выход удаляет QR, запасной файл и пояснение');
        }
        chatClick($bot, "/!po $protocol edit $path");
        chatClick($bot, '/menu');
        chatCheck(count($bot->transport->messages) === 1, 'Уход в другое меню отменяет ввод');
        $before = $store->read()['settings'];
        chatClick($bot, "/protocolPort $protocol");
        if ($protocol === 'anytls') {
            chatCheck(count($bot->transport->messages) === 1 && str_contains($bot->transport->messages[1]['text'], 'SNI'), 'AnyTLS объясняет общий порт без запроса ввода');
        } else {
            $screen = chatReply($bot, '443'); chatCheck(str_contains($screen['text'], '❌'), 'Неверный порт отклонён');
            chatClick($bot, "/protocolPort $protocol"); chatReply($bot, '25445');
            $after = $store->read()['settings'];
            chatCheck($after['port'] === 25445 && array_diff_key($after, ['port' => true]) === array_diff_key($before, ['port' => true]), 'Меняется только внешний порт');
            chatCheck(chatBack($bot->transport->messages[1]) === '/menu config', 'После порта открывается Settings → Ports');
        }
        chatClick($bot, '/ports');
    }
    $client = ['id'=>Bot::xrayUuid(),'subtoken'=>bin2hex(random_bytes(16)),'email'=>'Общий пользователь'];
    $bot->conf['transport'] = 'Websocket';
    $bot->xr['inbounds'][0]['settings']['clients'] = [$client]; $bot->syncXrayProtocolUsers();
    foreach (['cl' => '_mihomo.yaml', 'clj' => '_mihomo.json', 'si' => '_singbox.json', 's' => '_v2ray.json'] as $format => $suffix) {
        chatClick($bot, "/dw 0 $format");
        $files = array_values(array_filter($bot->transport->messages, static fn($message) => isset($message['document'])));
        chatCheck(count($files) === 1 && count($bot->transport->messages) === 2, 'Скачивание общего профиля через callback заменяет предыдущий файл');
        chatCheck($files[0]['document']->postname === $client['email'] . $suffix, 'Callback отдаёт файл запрошенного формата');
        chatCheck($_GET['s'] === $client['subtoken'], 'Callback использует токен общей подписки');
    }
    chatClick($bot, '/menu');
    chatCheck(count($bot->transport->messages) === 1, 'Уход из карточки убирает файл общей подписки');
    $source = ManagedProtocol::xraySource($client);
    foreach (array_keys(ManagedProtocol::NAMES) as $protocol) {
        foreach ([false, true] as $enabled) {
            $screen = chatClick($bot, "/xp $source $protocol");
            chatCheck(count($bot->transport->messages) === 1, 'Переключатель общей подписки не создаёт сообщение');
            chatCheck($bot->xr['inbounds'][0]['settings']['clients'][0]['managed_protocols'][$protocol] === $enabled, 'Личный переключатель сохранён');
            chatCheck(chatBack($screen) === '/userXr 0', 'Назад открывает карточку общего пользователя');
        }
    }
    array_unshift($bot->xr['inbounds'][0]['settings']['clients'], ['id'=>Bot::xrayUuid(),'email'=>'Другой']);
    chatCheck(chatBack(chatClick($bot, "/xp $source")) === '/userXr 1', 'Стабильный callback находит пользователя после переиндексации');
    $bot->xr['inbounds'][0]['settings']['clients'] = [];
    $screen=chatClick($bot, "/xp $source anytls");
    chatCheck(str_contains($screen['text'], 'удалён') && chatBack($screen) === '/xray', 'Старая кнопка удалённого пользователя не меняет чужой доступ');
    ob_end_clean(); echo "protocol_navigation_test: OK ($checks проверок)\n";
} finally {
    restore_error_handler();
    if (session_status() === PHP_SESSION_ACTIVE) session_write_close();
    $remove = static function ($path) use (&$remove) {
        if (is_dir($path)) { foreach (scandir($path) as $f) if ($f !== '.' && $f !== '..') $remove("$path/$f"); rmdir($path); }
        else unlink($path);
    };
    $remove($root);
}
