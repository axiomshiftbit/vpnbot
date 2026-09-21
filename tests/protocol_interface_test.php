<?php
require_once __DIR__ . '/../app/bot.php';
require_once __DIR__ . '/../app/i18n.php';
require_once __DIR__ . '/../app/panel/Panel.php';

$checks = 0;
function uiCheck(bool $ok, string $name): void {
    global $checks;
    if (!$ok) throw new RuntimeException($name);
    $checks++;
}
class ProtocolInterfaceTransport {
    public array $calls = [];
    public function call($method, $data, $json = 0) {
        $this->calls[] = [$method, $data];
        return ['ok' => true, 'result' => ['message_id' => count($this->calls), 'chat' => ['id' => 1]]];
    }
}
class ProtocolInterfaceBot extends Bot {
    public function __construct(array $translations) {
        $this->admin = true; $this->i18n = $translations; $this->language = 'ru';
        $this->ip = '192.0.2.1'; $this->transport = new ProtocolInterfaceTransport();
        $this->input = ['chat' => 1, 'message_id' => 1];
    }
    public function getDomain($cdn = false) { return 'vpn.example.test'; }
    public function getHashBot($notset = false) { return 'fixture'; }
    public function getPacConf() { return self::PAC_DEFAULTS; }
    public function stashReply($r, array $state) { $_SESSION['reply'][$r['result']['message_id']] = $state; }
}
function uiLast(ProtocolInterfaceBot $bot): array {
    [$method, $data] = end($bot->transport->calls);
    $markup = json_decode($data['reply_markup'] ?? '{}', true);
    if (isset($markup['input_field_placeholder'])) uiCheck(mb_strlen($markup['input_field_placeholder']) <= 64, 'Placeholder Telegram не длиннее 64 символов');
    $buttons = $markup['inline_keyboard'] ?? [];
    uiCheck($bot->messageTextLength($data['text'] ?? '') <= 4096, 'Сообщение укладывается в лимит Telegram');
    foreach ($buttons as $row) foreach ($row as $button) {
        uiCheck(strlen($button['callback_data'] ?? '') <= 64, 'Callback укладывается в 64 байта');
        uiCheck(($button['text'] ?? '') !== '', 'Кнопка подписана');
    }
    return [$data['text'] ?? '', $buttons, $data, $method];
}
function uiCallbacks(array $buttons): array { return array_column($buttons ? array_merge(...$buttons) : [], 'callback_data'); }

$root = sys_get_temp_dir() . '/vpnbot-interface-' . bin2hex(random_bytes(6));
mkdir($root, 0700); $screens = [];
set_error_handler(function ($level, $message, $file, $line) {
    if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line);
    return false;
});
try {
    $bot = new ProtocolInterfaceBot($i);
    $bot->protocolRoot = "$root/protocols"; $bot->protocolModulesFile = "$root/protocol-services.json";
    $bot->upstreamFile = "$root/no-live-upstream.conf";
    $modules = new ProtocolModules($bot->protocolModulesFile);
    $bot->protocolModulesMenu(); [$text, $buttons] = uiLast($bot);
    foreach (ManagedProtocol::NAMES as $key => $label) uiCheck(in_array("/protocol $key", uiCallbacks($buttons), true), "$key: настройка доступна до включения");
    foreach (ManagedProtocol::NAMES as $key => $label) {
        $store = $bot->protocolStore($key);
        $bot->protocolCommand($key); [$text, $buttons] = uiLast($bot);
        uiCheck(str_contains(json_encode($buttons, JSON_UNESCAPED_UNICODE), 'Включить сервис'), "$key: выключенный сервис");
        $bot->protocolCommand($key, 'settings'); [, , $prompt] = uiLast($bot);
        uiCheck(json_decode($prompt['reply_markup'], true)['force_reply'] === true, "$key: ввод параметров через ответ");
        $settings = $key === 'mieru' ? 'vpn.example.test 24445 TCP' : "vpn.example.test $key.example.test " . $store->defaults()['settings']['port'];
        $bot->protocolReply($settings, $key, 'settings');
        uiCheck(!$store->read()['enabled'], "$key: сохранение параметров не активирует контейнер");
        $bot->protocolCommand($key, 'toggle');
        uiCheck($store->read()['enabled'] && $modules->enabled($key), "$key: включение синхронизирует модуль");
        ManagedProtocol::writeJson($store->directory() . '/runtime/status.json', [
            'running' => false, 'phase' => 'idle', 'time' => time(), 'revision' => $store->read()['revision'],
        ]);
        $bot->protocolCommand($key); [$text] = uiLast($bot);
        uiCheck(str_contains($text, 'ожидает активного доступа'), "$key: пустой сервис ожидает доступа");
        foreach (['name', 'expires', 'quota'] as $field) {
            $bot->protocolCommand($key, $field); uiLast($bot);
        }
        if ($key === 'mieru') { $bot->protocolCommand($key, 'rolling'); uiLast($bot); }
        $bot->protocolCommand($key, 'add'); [, , $prompt] = uiLast($bot);
        uiCheck(str_contains($prompt['text'], 'Название доступа'), "$key: подсказка создания");
        $bot->protocolReply('Тест < & 🇷🇺', $key, 'add');
        $id = array_key_first($store->read()['users']);
        [$text, $buttons] = uiLast($bot);
        uiCheck(str_contains($text, 'Тест &lt; &amp; 🇷🇺'), "$key: HTML имени экранирован");
        foreach ($store->formats() as $format => $_) {
            uiCheck(in_array("/protocol $key export $id $format", uiCallbacks($buttons), true), "$key: кнопка $format");
            $bot->protocolCommand($key, 'export', $id, $format);
            [$method, $data] = end($bot->transport->calls);
            uiCheck($method === 'sendDocument' && $data['document'] instanceof CURLStringFile, "$key: экспорт создаёт вложение");
            uiCheck(str_contains($data['document']->postname, "$key-$format"), "$key: расширение экспорта");
        }
        $bot->protocolCommand($key, 'user-toggle', $id); [$text, $buttons] = uiLast($bot);
        uiCheck(str_contains($text, '🔴') && !str_contains(implode(' ', uiCallbacks($buttons)), ' export '), "$key: отключённый доступ без экспорта");
        $bot->protocolCommand($key, 'user-toggle', $id);
        $bot->protocolReply('0.5', $key, 'quota', $id); [$text] = uiLast($bot);
        uiCheck(str_contains($text, '0.500 ГиБ'), "$key: дробный лимит отображается");
        $before = $store->read();
        $bot->protocolReply('-1', $key, 'quota', $id); [$text] = uiLast($bot);
        uiCheck(str_contains($text, 'Не удалось сохранить') && $store->read() === $before, "$key: ошибка ввода без изменения доступа");
        $bot->protocolReply('2020-01-01 12:00', $key, 'expires', $id); [$text, $buttons] = uiLast($bot);
        uiCheck(str_contains($text, '2020-01-01 12:00') && !str_contains(implode(' ', uiCallbacks($buttons)), ' export '), "$key: просроченный доступ без экспорта");
        $bot->protocolReply('0', $key, 'expires', $id);
        $bot->protocolReply('Новое имя', $key, 'name', $id); [$text] = uiLast($bot);
        uiCheck(str_contains($text, 'Новое имя'), "$key: переименование");
        $bot->protocolCommand($key, 'rotate', $id);
        uiCheck($store->read()['users'][$id]['token'] !== $before['users'][$id]['token'], "$key: новая подписка после ротации");
        $bot->protocolCommand($key, 'reset', $id);
        if ($key === 'mieru') {
            $bot->protocolReply('30 10240', $key, 'rolling', $id); [$text] = uiLast($bot);
            uiCheck(str_contains($text, '30 дн.: 10240 МиБ'), 'Mieru: периодическая квота видна');
        }
        $bot->protocolCommand($key, 'user', $id); [$text, $buttons] = uiLast($bot);
        $screens[$key . '-user'] = ['text' => $text, 'buttons' => $buttons];
        for ($n = 0; $n < 21; $n++) $store->add(str_repeat('Имя ', 24) . $n);
        $bot->protocolCommand($key, 'page', '0'); [, $buttons] = uiLast($bot);
        uiCheck(in_array("/protocol $key page 1", uiCallbacks($buttons), true), "$key: следующая страница");
        $bot->protocolCommand($key, 'page', '999'); [$text, $buttons] = uiLast($bot);
        uiCheck(in_array("/protocol $key page 0", uiCallbacks($buttons), true), "$key: граница пагинации");
        if (in_array($key, ['tuic', 'shadowtls'], true)) {
            $bot->protocolCommand($key, 'udp-mode'); [$text, $buttons] = uiLast($bot);
            uiCheck($key === 'tuic' ? str_contains(json_encode($buttons), 'quic') : str_contains($text, 'UoT v2'), "$key: переключение UDP отображается");
        }
        if ($key === 'tuic') {
            $bot->protocolCommand($key, 'congestion'); [, $buttons] = uiLast($bot);
            uiCheck(str_contains(json_encode($buttons), 'new_reno'), 'TUIC: смена congestion');
        }
        $screens[$key] = ['text' => $text, 'buttons' => $buttons];
        $count = count($store->read()['users']);
        $bot->protocolCommand($key, 'toggle');
        uiCheck(!$modules->enabled($key) && count($store->read()['users']) === $count, "$key: отключение сохраняет доступы");
        $bot->protocolCommand($key, 'delete', $id);
        uiCheck(!isset($store->read()['users'][$id]), "$key: удаление возвращает в список");
    }
    $bot->admin = false; $count = count($bot->transport->calls);
    $bot->protocolCommand('mieru', 'toggle'); $bot->protocolReply('Чужой', 'mieru', 'add'); $bot->protocolModulesToggle('oc');
    uiCheck(count($bot->transport->calls) === $count, 'Неадминистратор не выполняет действия');
    if ($out = getenv('VPNBOT_UI_SNAPSHOTS')) file_put_contents($out, json_encode($screens, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));
    echo "protocol_interface_test: OK ($checks проверок)\n";
} finally {
    restore_error_handler();
    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($files as $file) $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
    rmdir($root);
}
