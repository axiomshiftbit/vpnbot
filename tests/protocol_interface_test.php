<?php
require_once __DIR__ . '/managed_protocol_fixture.php';
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
    public function getXray() { return ['inbounds' => [['settings' => ['clients' => []]]]]; }
    public function xray($page = 0) { $this->update(1, 1, 'Пользователи VLESS'); }
    public function getDomain($cdn = false) { return 'vpn.example.test'; }
    public function getHashBot($notset = false) { return 'fixture'; }
    public function getWgMsg() { return null; }
    public function getPorts() { return array_fill_keys(['wg', 'wg1', 'telemt', 'hy', 'ss', 'oc', 'tt', 'ovpn'], ['enable' => true, 'port' => 24443]); }
    public function getSSConfig() { return []; }
    public function getCloakConfig() { return []; }
    public function getStlsConfig() { return []; }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') { return str_contains($cmd, 'telemt_state.py') ? 'TELEMT_STATE_OK' : ''; }
    public function telemtWriteServiceState(bool $enabled): void {}
    public function telemtWriteToml(string $toml): void {}
    protected function sessionApply(callable $fn) { $fn(); }
    public function getPacConf() { return self::PAC_DEFAULTS; }
    public function stashReply($r, array $state) { $_SESSION['reply'][$r['result']['message_id']] = $state + ['chat' => $this->input['chat']]; }
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
function snolcDeniedUi(callable $call, string $name): void
{
    try { $call(); } catch (RuntimeException | InvalidArgumentException $e) { uiCheck(true, $name); return; }
    uiCheck(false, $name);
}
try {
    $bot = new ProtocolInterfaceBot($i);
    $bot->protocolRoot = "$root/protocols"; $bot->protocolModulesFile = "$root/protocol-services.json";
    $bot->upstreamFile = "$root/no-live-upstream.conf";
    $modules = new ProtocolModules($bot->protocolModulesFile);
    $bot->protocolModulesMenu(); [$text, $buttons] = uiLast($bot);
    foreach (array_diff_key(ManagedProtocol::NAMES, ['snolc' => true, 'masque' => true]) as $key => $label) uiCheck(in_array("/protocol $key", uiCallbacks($buttons), true), "$key: настройка доступна до включения");
    // Нажимаем реальные callback из меню через общий диспетчер. Прямой вызов
    // protocolModulesToggle не обнаруживал отсутствующий маршрут TrustTunnel.
    $callbacks = uiCallbacks($buttons);
    $bot->input += ['message' => '', 'reply' => false];
    foreach (ProtocolModules::LABELS as $key => $label) {
        if (isset(ManagedProtocol::NAMES[$key])) continue;
        uiCheck(in_array("/protocolModules $key", $callbacks, true), "$label: кнопка выключателя присутствует");
        $before = $modules->read();
        $bot->input['callback'] = "/protocolModules $key";
        $bot->action();
        uiCheck($modules->read() === array_replace($before, [$key => false]), "$label: callback выключает только выбранный модуль");
        [, $changedButtons] = uiLast($bot);
        uiCheck(in_array('🔴 ' . $label, array_column(array_merge(...$changedButtons), 'text'), true), "$label: кнопка показывает отключение");
        $bot->action();
        uiCheck($modules->read() === $before, "$label: повторное нажатие включает модуль");
        $bot->admin = false; $calls = count($bot->transport->calls);
        $bot->action();
        uiCheck($modules->read() === $before && count($bot->transport->calls) === $calls, "$label: чужое нажатие ничего не меняет");
        $bot->admin = true;
    }
    foreach (['/protocolModules unknown', '/protocolModules tt extra', "/protocolModules tt\n", '/protocolModules tt;id'] as $callback) {
        $before = $modules->read(); $calls = count($bot->transport->calls);
        $bot->input['callback'] = $callback; $bot->action();
        uiCheck($modules->read() === $before && count($bot->transport->calls) === $calls, 'Неверный callback не меняет модули');
    }
    $bot->input['callback'] = false;
    foreach (array_diff_key(ManagedProtocol::NAMES, ['snolc' => true, 'masque' => true]) as $key => $label) {
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
        $bot->protocolModulesMenu(); [, $moduleButtons] = uiLast($bot);
        $flat = array_merge(...$moduleButtons);
        $index = array_search("/protocol $key", array_column($flat, 'callback_data'), true);
        uiCheck($index !== false && $flat[$index]['text'] === '🟢 ' . $label, "$key: зелёный кружок в настройках протоколов");
        $modules->set($key, false); $bot->protocolModulesMenu(); [, $moduleButtons] = uiLast($bot);
        $flat = array_merge(...$moduleButtons);
        $index = array_search("/protocol $key", array_column($flat, 'callback_data'), true);
        uiCheck($index !== false && $flat[$index]['text'] === '🔴 ' . $label, "$key: красный кружок в настройках протоколов");
        $modules->set($key, true);
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
        uiCheck(str_contains($prompt['text'], 'Пользователи VLESS'), "$key: создание переведено в общий список");
        $id = managedProtocolFixtureUser($store, 'Тест < & 🇷🇺');
        $bot->protocolMenu($key, $id);
        [$text, $buttons] = uiLast($bot);
        uiCheck(str_contains($text, 'Тест &lt; &amp; 🇷🇺'), "$key: HTML имени экранирован");
        foreach ($store->formats() as $format => $_) {
            uiCheck(in_array("/protocol $key export $id $format", uiCallbacks($buttons), true), "$key: кнопка $format");
            $bot->protocolCommand($key, 'export', $id, $format);
            [$method, $data] = end($bot->transport->calls);
            uiCheck($method === 'sendDocument' && $data['document'] instanceof CURLStringFile, "$key: экспорт создаёт вложение");
            uiCheck(str_contains($data['document']->postname, "$key-$format"), "$key: расширение экспорта");
            if ($format === 'mihomo') {
                uiCheck($data['document']->postname === "$key-mihomo.yaml" && $data['document']->mime === 'application/yaml', "$key: YAML-файл и MIME");
                uiCheck(yaml_parse($data['document']->data) === $store->profile($id, 'mihomo'), "$key: YAML сохраняет типы, секреты и все параметры профиля");
            }
        }
        $yamlCallback = "/protocol $key yaml $id";
        uiCheck(in_array($yamlCallback, uiCallbacks($buttons), true), "$key: кнопка копирования YAML");
        $bot->input['callback'] = $yamlCallback; $bot->action(); $bot->input['callback'] = false;
        [$yamlText, $yamlButtons] = uiLast($bot);
        uiCheck(preg_match('~<pre><code class="language-yaml">(.*?)</code></pre>~s', $yamlText, $match) === 1, "$key: callback выдаёт копируемый YAML");
        $snippet = html_entity_decode($match[1], ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $expected = $store->profile($id, 'mihomo')['proxies']; $expected[0]['name'] = "$key-$id";
        uiCheck(yaml_parse("proxies:\n" . $snippet)['proxies'] === $expected, "$key: блок вставляется в proxies без потери обоих слоёв и параметров");
        // Признак начала документа YAML — «---» в начале строки. Поиск по всему
        // тексту срабатывал и на случайном ключе пользователя (base64url
        // содержит «-»): раз в несколько сотен прогонов тест падал без причины.
        uiCheck(preg_match('~^---~m', $snippet) !== 1 && !str_contains($snippet, 'mixed-port:'), "$key: блок не заменяет настройки роутера");
        $screens[$key . '-yaml'] = ['text' => $yamlText, 'buttons' => $yamlButtons];
        $deniedYaml = function () use ($bot, $key, $id, $store): void {
            $bot->input['callback'] = "/protocol $key yaml $id"; $bot->action(); $bot->input['callback'] = false;
            [$text] = uiLast($bot);
            uiCheck(str_contains($text, 'Доступ отключён, истёк или исчерпан') && !str_contains($text, '<pre>'), "$key: устаревшая кнопка YAML не раскрывает закрытый доступ");
            try { $store->profileDocument($id, 'mihomo'); throw new LogicException('Закрытый доступ экспортирован'); }
            catch (RuntimeException $e) { uiCheck($e->getMessage() === 'Доступ отключён, истёк или исчерпан', "$key: YAML-файл закрытого доступа недоступен"); }
        };
        $bot->protocolCommand($key, 'user-toggle', $id); [$text, $buttons] = uiLast($bot);
        uiCheck(str_contains($text, '🔴') && !str_contains(implode(' ', uiCallbacks($buttons)), ' export '), "$key: отключённый доступ без экспорта");
        $deniedYaml();
        $bot->protocolCommand($key, 'user-toggle', $id);
        $bot->protocolReply('0.5', $key, 'quota', $id);
        $bot->accessEditFinish($_SESSION['access_review'][$bot->input['chat']]['token'], true); [$text] = uiLast($bot);
        uiCheck(str_contains($text, '0.500 ГиБ'), "$key: дробный лимит отображается");
        $before = $store->read();
        $bot->protocolReply('-1', $key, 'quota', $id); [$text] = uiLast($bot);
        uiCheck(str_contains($text, 'Не удалось сохранить') && $store->read() === $before, "$key: ошибка ввода без изменения доступа");
        $bot->protocolReply('2020-01-01 12:00', $key, 'expires', $id);
        $bot->accessEditFinish($_SESSION['access_review'][$bot->input['chat']]['token'], true); [$text, $buttons] = uiLast($bot);
        uiCheck(str_contains($text, '2020-01-01 12:00') && !str_contains(implode(' ', uiCallbacks($buttons)), ' export '), "$key: просроченный доступ без экспорта");
        $deniedYaml();
        $bot->protocolReply('0', $key, 'expires', $id);
        $bot->accessEditFinish($_SESSION['access_review'][$bot->input['chat']]['token'], true);
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
        for ($n = 0; $n < 21; $n++) managedProtocolFixtureUser($store, str_repeat('Имя ', 24) . $n);
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
        $deniedYaml();
        $bot->protocolCommand($key, 'delete', $id);
        uiCheck(!isset($store->read()['users'][$id]), "$key: удаление возвращает в список");
    }
    $snolc = $bot->protocolStore('snolc');
    $bot->protocolReply('vpn.example.test 24448', 'snolc', 'settings');
    uiCheck($snolc->read()['settings']['host'] === 'vpn.example.test', 'snolc: адрес без SNI сохраняется');
    $seed = $snolc->read()['settings']['server_seed'];
    $bot->protocolPortReply('24449', 'snolc');
    uiCheck($snolc->read()['settings']['port'] === 24449 && $snolc->read()['settings']['listen_port'] === 24448,
        'snolc: Ports меняет только внешний TCP-порт');
    uiCheck($snolc->read()['settings']['server_seed'] === $seed, 'snolc: Ports сохраняет ключи сервера');
    $bot->protocolPortReply('22', 'snolc');
    uiCheck($snolc->read()['settings']['port'] === 24449, 'snolc: Ports отклоняет служебный порт');
    $bot->protocolPortReply('24448', 'snolc');
    $bot->input['callback'] = '/protocol snolc toggle'; $bot->action(); $bot->input['callback'] = false;
    uiCheck($modules->enabled('snolc') && $snolc->read()['enabled'], 'snolc: callback включает контейнерный модуль');
    $id = managedProtocolFixtureUser($snolc, 'Нативный клиент');
    $bot->protocolCommand('snolc'); [$text, $buttons] = uiLast($bot);
    $callbacks = uiCallbacks($buttons);
    uiCheck(!in_array('/po snolc', $callbacks, true) && !in_array('/protocol snolc egress', $callbacks, true), 'snolc: нет неподдерживаемых настроек');
    uiCheck(str_contains($text, 'SSH + Noise') && str_contains($text, 'Linux x86_64'), 'snolc: клиент и режим указаны');
    $bot->protocolCommand('snolc', 'user', $id); [$text, $buttons] = uiLast($bot);
    uiCheck(in_array("/protocol snolc export $id native", uiCallbacks($buttons), true), 'snolc: нативный архив доступен');
    uiCheck(!in_array("/protocol snolc yaml $id", uiCallbacks($buttons), true), 'snolc: нет ложного Mihomo YAML');
    $bot->input['callback'] = "/protocol snolc export $id native"; $bot->action(); $bot->input['callback'] = false;
    [, , $file, $method] = uiLast($bot);
    uiCheck($method === 'sendDocument' && $file['document']->mime === 'application/zip' && str_starts_with($file['document']->data, 'PK'), 'snolc: кнопка отправляет полноценный ZIP');
    $bot->protocolRelay('snolc', $id); [$text] = uiLast($bot);
    uiCheck(!str_contains($text, '❌'), 'snolc: меню relay проверяет нативный доступ');
    $bot->protocolSubscriptions('snolc', $id); [$text, $buttons] = uiLast($bot);
    uiCheck(str_contains($text, '/native') && !str_contains(json_encode($buttons), 'provider'), 'snolc: HTTP-архив без ложного provider');
    $before = $snolc->read();
    $bot->protocolCommand('snolc', 'toggle');
    uiCheck(!$modules->enabled('snolc') && !$snolc->read()['enabled'], 'snolc: выключение снимает оба флага — контейнер и протокол');
    uiCheck($snolc->read()['users'] === $before['users'] && $snolc->read()['settings'] === $before['settings'], 'snolc: выключение сохраняет всех пользователей и ключи');
    $bot->protocolCommand('snolc'); [$text, $buttons] = uiLast($bot);
    uiCheck(str_contains(json_encode($buttons, JSON_UNESCAPED_UNICODE), 'Включить сервис'), 'snolc: карточка выключенного сервиса предлагает включение');
    snolcDeniedUi(fn() => $snolc->profileDocument($id, 'native'), 'snolc: выключенный сервис не выдаёт ZIP');
    // Кнопка из старого сообщения (/protocolModules snolc) не переключает управляемый протокол.
    $bot->input['callback'] = '/protocolModules snolc'; $bot->action(); $bot->input['callback'] = false;
    uiCheck(!$modules->enabled('snolc') && !$snolc->read()['enabled'], 'snolc: устаревшая кнопка списка модулей ничего не меняет');
    $bot->protocolCommand('snolc', 'toggle');
    uiCheck($modules->enabled('snolc') && $snolc->read()['enabled'], 'snolc: включение ставит оба флага');
    uiCheck($snolc->read()['settings'] === $before['settings'] && $snolc->read()['users'] === $before['users'], 'snolc: включение сохраняет ключи сервера и пользователей');
    uiCheck($snolc->profileDocument($id, 'native')['extension'] === 'zip', 'snolc: после включения ZIP снова выдаётся');
    // Настройки модулей не записались: флаг протокола возвращается, состояния не расходятся.
    $file = $bot->protocolModulesFile; $bot->protocolModulesFile = "$root/absent-directory/modules.json";
    $bot->protocolCommand('snolc', 'toggle');
    $bot->protocolModulesFile = $file;
    uiCheck($modules->enabled('snolc') && $snolc->read()['enabled'], 'snolc: сбой записи модулей откатывает флаг протокола');
    $bot->admin = false; $before = $snolc->read();
    $bot->protocolCommand('snolc', 'toggle');
    uiCheck($snolc->read() === $before, 'snolc: неадминистратор не меняет модуль');
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
