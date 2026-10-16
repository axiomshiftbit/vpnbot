<?php

require_once __DIR__ . '/../app/bot.php';
require_once __DIR__ . '/../app/i18n.php';

// Тестовые данные генерируются в памяти; конструктор, SSH и рабочие файлы
// бота не вызываются. Сетевую совместимость проверяет отдельный стенд ядрами.
class VlessEncryptionTestBot extends Bot
{
    public array $p = [];
    public array $x = [];
    public string $generated = '';
    public bool $valid = true;
    public bool $saveOk = true;
    public bool $restartOk = true;
    public int $restarts = 0;
    public int $generations = 0;
    public array $templates = [];
    public array $probe = ['ok' => true, 'active' => 'origin', 'running' => 'origin', 'version' => 'Xray 26.7.28'];

    public function __construct()
    {
        $this->ip = '127.0.0.1';
        $this->language = 'ru';
        $this->p = self::PAC_DEFAULTS + [
            'transport' => 'Websocket', 'outbound' => 'proxy', 'domain' => 'example.test',
            'includelist' => [], 'blocklist' => [], 'warplist' => [], 'processlist' => [],
            'packagelist' => [], 'subnetlist' => [], 'fingerprint' => 'firefox',
            'xray' => rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '='),
            'reality' => ['domain' => 'example.test', 'shortId' => 'ab'],
        ];
        $this->x = ['inbounds' => [[
            'protocol' => 'vless', 'tag' => 'vless', 'port' => 443,
            'settings' => ['decryption' => 'none', 'clients' => [[
                'id' => '11111111-2222-4333-8444-555555555555', 'email' => 'test', 'subtoken' => 'test-sub',
            ]]],
            'streamSettings' => ['network' => 'ws', 'wsSettings' => ['path' => '/wstest']],
        ]], 'outbounds' => [['protocol' => 'freedom', 'tag' => 'direct']], 'routing' => ['rules' => []]];
    }

    public function getPacConf() { return $this->p; }
    public function setPacConf(array $conf) { if (!$this->saveOk) { return false; } $this->p = $conf; return true; }
    public function getXray() { return $this->x; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
    {
        if ($cmd !== 'xray vlessenc') { throw new RuntimeException('Unexpected SSH command in test'); }
        $this->generations++;
        return $this->generated;
    }
    public function validateXrayConfig(array $config, string $binary = 'xray'): bool { return $this->valid; }
    public function restartXray($c, $norestart = false)
    {
        if (!$this->restartOk) { return false; }
        if (!VlessEncryption::applyServer($c, $this->p)) { return false; }
        $this->x = $c;
        $this->restarts++;
        return true;
    }
    public function xrayCoreProbe(bool $fresh = false): array { return $this->probe; }
    public function getDomain($cdn = false) { return 'example.test'; }
    public function getHashBot($notset = false) { return 'test'; }
    public function nginxGetTypeCert() { return 'test'; }
    public function flagName(string $name, string|array $hosts, bool $cacheOnly = true): string { return $name; }
    public function fingerprint() { return 'firefox'; }
    public function subTemplate(string $template, string $type, array $pac)
    {
        if (isset($this->templates[$type])) { return $this->templates[$type]; }
        return match ($type) {
            'v2ray' => ['outbounds' => [['tag' => '~outbound~', 'protocol' => 'vless', 'settings' => ['vnext' => [['port' => 443]]]]]],
            'clash' => ['proxies' => [['name' => '~outbound~', 'type' => 'vless', 'port' => 443, 'tls' => true, 'udp' => true]]],
            'sing' => ['outbounds' => [['tag' => '~outbound~', 'type' => 'vless', 'server' => '~domain~', 'server_port' => 443,
                'tls' => ['enabled' => true, 'utls' => ['enabled' => true, 'fingerprint' => 'chrome'], 'reality' => ['enabled' => true]],
                'packet_encoding' => 'xudp']], 'route' => []],
        };
    }
}

$veChecks = 0;
function veAssert(bool $value, string $message): void
{
    global $veChecks;
    $veChecks++;
    if (!$value) { throw new RuntimeException($message); }
}
function veOutput(): string
{
    $out = "Choose one Authentication to use, do not mix them.\n\n";
    foreach (VlessEncryption::KEY_BYTES as $auth => [$server, $client]) {
        $label = $auth === 'x25519' ? 'X25519, not Post-Quantum' : 'ML-KEM-768, Post-Quantum';
        $key = fn($size) => rtrim(strtr(base64_encode(random_bytes($size)), '+/', '-_'), '=');
        $out .= "Authentication: $label\n\"decryption\": \"mlkem768x25519plus.native.600s.{$key($server)}\"\n"
            . "\"encryption\": \"mlkem768x25519plus.native.0rtt.{$key($client)}\"\n\n";
    }
    return $out;
}

$output = veOutput();
$pairs = VlessEncryption::parseOutput($output);
veAssert(array_keys($pairs) === ['x25519', 'mlkem768'], 'Обе пары генератора распознаны отдельно');
veAssert(VlessEncryption::parseOutput(str_replace("\n", "\r\n", $output)) === $pairs, 'CRLF поддерживается');
veAssert(VlessEncryption::parseOutput('unknown command') === [], 'Ошибка CLI не является ключами');

class VlessMenuTestBot extends VlessEncryptionTestBot
{
    public array $buttons = [];
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML')
    {
        $this->buttons = $button;
    }
    public function answer($callback_id, $textNotify = false, $notify = false) {}
}
$menu = new VlessMenuTestBot();
$menu->i18n = $i;
$menu->input = ['chat' => 1, 'message_id' => 1, 'callback_id' => 'test'];
$menu->generated = $output;
$menu->vlessEncryptionMenu();
veAssert(str_contains($menu->buttons[0][0]['text'], '🔴'), 'Отключённое шифрование отмечено красным');
foreach (['x25519', 'mlkem768'] as $auth) {
    foreach (VlessEncryption::MODES as $mode) {
        $menu->setVlessEncryption($auth, $mode);
        veAssert(str_contains($menu->buttons[0][0]['text'], '🟢'), 'Включённое шифрование отмечено зелёным');
        $menu->vlessEncryptionMenu();
        veAssert(str_contains($menu->buttons[0][0]['text'], '🟢'), 'Повторное открытие сохраняет зелёный индикатор');
        veAssert($menu->buttons[0][0]['callback_data'] === '/vlessEncryptionSet off native', 'Индикатор сохраняет действие отключения');
        $menu->setVlessEncryption('off', 'native');
        veAssert(str_contains($menu->buttons[0][0]['text'], '🔴'), 'Отключение возвращает красный индикатор');
    }
}
$menu->restartOk = false;
$menu->setVlessEncryption('mlkem768', 'native');
veAssert(str_contains($menu->buttons[0][0]['text'], '🔴'), 'Отказ включения не даёт ложный зелёный индикатор');

class VlessProbeTestBot extends Bot
{
    public string $reply = '';
    public string $command = '';
    public function __construct() {}
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
    {
        $this->command = $cmd;
        $this->sshFailed = false;
        return $this->reply;
    }
}
$probeBot = new VlessProbeTestBot();
$probeBot->reply = "1|/usr/bin/xray-smux|cubic|/usr/bin/xray-smux|Xray 26.9.9\nREALITY_BUILD=v0.0.0-20260322125925-9234c772ba8f";
$probe = $probeBot->xrayCoreProbe();
veAssert($probe['version'] === 'Xray 26.9.9' && $probe['active'] === 'fork', 'Build info не портит версию и выбор ядра');
veAssert(!$probeBot->realityRequiresMlkem(), 'Поздний релиз форка со старым REALITY не блокирует sing-box');
$probeBot->reply = str_replace('20260322125925-9234c772ba8f', '20260908062103-8cdf7bf9c7f0', $probeBot->reply);
$probeBot->xrayCoreProbe(true);
veAssert($probeBot->realityRequiresMlkem(), 'Новая зависимость форка включает ограничение sing-box');
$proc = proc_open(['/bin/sh', '-n', '-c', $probeBot->command], [0 => ['file', '/dev/null', 'r'],
    1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
veAssert(proc_close($proc) === 0, 'Команда диагностики синтаксически корректна');

foreach ($pairs as $auth => $settings) {
    foreach (VlessEncryption::MODES as $mode) {
        $bot = new VlessEncryptionTestBot();
        $bot->generated = $output;
        veAssert($bot->applyVlessEncryption($auth, $mode) === '', 'Пресет применяется');
        $pair = VlessEncryption::pair($bot->p['vless_encryption']);
        veAssert($bot->x['inbounds'][0]['settings']['decryption'] === $pair['decryption'], 'Сервер получает decryption');
        veAssert(str_contains($pair['encryption'], ".$mode.0rtt."), 'Режим клиента совпадает с сервером');
        veAssert(!isset($bot->x['inbounds'][0]['settings']['clients'][0]['encryption']), 'Шифрование не попало в inbound client');
        $uri = $bot->linkXray(0);
        parse_str(parse_url($uri, PHP_URL_QUERY), $query);
        veAssert($query['encryption'] === $pair['encryption'], 'URI содержит клиентскую часть');
        $relay = $bot->relayVlessLink($uri, ['address' => 'relay.test', 'port' => 8443]);
        parse_str(parse_url($relay, PHP_URL_QUERY), $relayQuery);
        veAssert($relayQuery['encryption'] === $pair['encryption'], 'Relay сохраняет шифрование');
        foreach (['Websocket', 'xhttp', 'Reality'] as $transport) {
            $bot->p['transport'] = $transport;
            $bot->x['inbounds'][0]['streamSettings']['realitySettings'] = ['serverNames' => ['example.test'], 'shortIds' => ['ab']];
            foreach (['s', 'cl'] as $format) {
                if ($format === 'cl' && !function_exists('yaml_emit')) { continue; }
                $_GET = ['s' => 'test-sub', 't' => $format];
                $body = $bot->subscription(true);
                $config = $format === 'cl' ? yaml_parse($body) : json_decode($body, true);
                $value = $format === 'cl' ? $config['proxies'][0]['encryption'] : $config['outbounds'][0]['settings']['vnext'][0]['users'][0]['encryption'];
                veAssert($value === $pair['encryption'], 'Подписка передаёт Encryption во всех VLESS транспортах');
                $private = explode('.', $pair['decryption']);
                veAssert(!str_contains($body, end($private)), 'Серверный секрет не попадает в подписку');
                if ($transport === 'Reality' && $format === 'cl') {
                    veAssert($config['proxies'][0]['reality-opts']['support-x25519mlkem768'] === true, 'mihomo REALITY включает MLKEM');
                    // Отпечаток выбирает администратор; бот его не подменяет (предупреждает в меню).
                    veAssert($config['proxies'][0]['client-fingerprint'] === $bot->normalizeFingerprint($bot->fingerprint(), 'mihomo'),
                        'mihomo REALITY получает выбранный отпечаток');
                }
            }
        }
        $_GET = ['s' => 'test-sub', 't' => 'si'];
        veAssert($bot->subscription(true) === '', 'Несовместимый sing-box не получает конфиг');
        veAssert($bot->linkXray(0, 2) === '', 'Несовместимый sing-box не получает ссылку импорта');
        $saved = $bot->p['vless_encryption'];
        veAssert($bot->applyVlessEncryption('off', 'native') === '', 'Выключение работает');
        veAssert($bot->x['inbounds'][0]['settings']['decryption'] === 'none', 'Сервер возвращается к none');
        veAssert($bot->subscription(true) !== '', 'После выключения sing-box снова доступен на старом REALITY');
        veAssert($bot->applyVlessEncryption($auth, $mode) === '', 'Повторное включение работает');
        veAssert($bot->p['vless_encryption'] === $saved && $bot->generations === 1, 'Ключи не ротируются при выключении/включении');
        veAssert($bot->applyVlessEncryption($auth, 'random') === '' && $bot->generations === 1, 'Смена режима сохраняет ключи');
        $bot->generated = veOutput();
        veAssert($bot->applyVlessEncryption($auth, $mode, true) === '' && $bot->generations === 2, 'Явная ротация генерирует новую пару');
        veAssert($bot->p['vless_encryption']['encryption'] !== $saved['encryption'], 'Ротация меняет клиентский параметр');
    }
}

foreach (['generated', 'valid', 'saveOk', 'restartOk'] as $failure) {
    $bot = new VlessEncryptionTestBot();
    $bot->generated = $output;
    $bot->$failure = $failure === 'generated' ? 'broken output' : false;
    $before = [$bot->p, $bot->x];
    veAssert($bot->applyVlessEncryption('x25519', 'native') !== '', 'Ошибка не скрывается');
    veAssert([$bot->p, $bot->x] === $before && $bot->restarts === 0, 'Ошибка сохраняет настройки и сервер');
}
$bot = new VlessEncryptionTestBot();
$bot->generated = $output;
$bot->x['inbounds'][0]['settings']['fallbacks'] = [['dest' => 80]];
veAssert($bot->applyVlessEncryption('x25519', 'native') !== '', 'Fallback несовместим с Encryption');
veAssert($bot->restarts === 0, 'При конфликте fallback сервер не перезапускается');
unset($bot->x['inbounds'][0]['settings']['fallbacks']);
$bot->applyVlessEncryption('x25519', 'native');
$bad = $bot->p;
$bad['vless_encryption']['encryption'] .= '=';
veAssert(VlessEncryption::pair($bad['vless_encryption']) === null, 'Неканоничный base64 отвергается');
veAssert(!VlessEncryption::applyServer($bot->x, $bad), 'Повреждённые настройки не выключают шифрование');
veAssert(VlessEncryption::client($bot->x, $bad) === null, 'Повреждённые настройки не дают plaintext-профиль');
$bad = $bot->p;
$bad['vless_encryption']['encryption'] = $pairs['mlkem768']['encryption'];
veAssert(VlessEncryption::pair($bad['vless_encryption']) === null, 'Смешивание семейств ключей отвергается');
$bot->x['inbounds'][0]['settings']['decryption'] = 'none';
veAssert(VlessEncryption::client($bot->x, $bot->p) === null, 'Сервер и настройки не совпали — экспорт запрещён');
$bot->x['inbounds'][0]['protocol'] = 'trojan';
veAssert(VlessEncryption::applyServer($bot->x, $bot->p), 'Trojan не зависит от Encryption');
veAssert(!isset($bot->x['inbounds'][0]['settings']['decryption']), 'Trojan не получает decryption');
veAssert(VlessEncryption::client($bot->x, $bot->p) === 'none', 'В клиенте Trojan нет Encryption');
veAssert($bot->applyVlessEncryption('x25519', 'native') === 'vless encryption transport', 'Включение на Trojan отвергается');
$bot->x['inbounds'][0]['protocol'] = 'vless';
veAssert(VlessEncryption::applyServer($bot->x, $bot->p), 'Возврат на VLESS восстанавливает Encryption');
veAssert(VlessEncryption::client($bot->x, $bot->p) !== null, 'Возврат транспорта сохраняет согласованную пару');

$bot = new VlessEncryptionTestBot();
$bot->p['transport'] = 'Reality';
$bot->probe['version'] = 'Xray 26.9.9';
veAssert($bot->subscriptionCompatibilityError($bot->x, $bot->p, 'si') === 'reality singbox mlkem', 'sing-box с новым REALITY отклоняется даже без Encryption');
$bot->probe['version'] = 'Xray 26.9.5-0936';
veAssert($bot->subscriptionCompatibilityError($bot->x, $bot->p, 'si') === '', 'Старое ядро сохраняет поддержку sing-box');
$bot->probe['ok'] = false;
$bot->probe['version'] = 'Xray 26.9.9';
veAssert(!$bot->realityRequiresMlkem(), 'Неизвестность не выдаётся за подтверждённую несовместимость');
$bot->probe['ok'] = true;
$bot->probe['running'] = 'fork';
veAssert(!$bot->realityRequiresMlkem(), 'Версия симлинка не подменяет другой работающий бинарь');
$bot->probe['active'] = 'fork';
$bot->p['xray_core'] = 'fork';
veAssert(!$bot->realityRequiresMlkem(), 'Одна дата выпуска форка не доказывает обновление REALITY');
$bot->probe['reality'] = 'v0.0.0-20260908062103-8cdf7bf9c7f0';
veAssert($bot->realityRequiresMlkem(), 'Обновлённый форк получает те же требования REALITY');
veAssert($bot->subscriptionCompatibilityError($bot->x, $bot->p, 'si') === 'reality singbox mlkem', 'sing-box защищён и после обновления форка');
$_GET = ['s' => 'test-sub', 't' => 'cl'];
$profile = yaml_parse($bot->subscription(true));
veAssert($profile['proxies'][0]['reality-opts']['support-x25519mlkem768'] === true, 'Новый REALITY не ограничен upstream-ядром');
// Форк 26.10.5: та же версия зависимости, но REALITY из дерева форка снова
// принимает ClientHello без гибридной группы.
$bot->probe['version'] = 'Xray 26.10.5-1858';
$bot->probe['reality_local'] = true;
veAssert(!$bot->realityRequiresMlkem(), 'REALITY из дерева форка не блокирует sing-box');
veAssert($bot->subscriptionCompatibilityError($bot->x, $bot->p, 'si') === '', 'Подписка sing-box выдаётся на форке с собственным REALITY');
$bot->probe['reality_local'] = false;
$bot->probe['version'] = 'Xray 26.9.5-0936';
veAssert($bot->realityRequiresMlkem(), 'Backport REALITY определяется по зависимости, а не имени релиза');
$bot->probe['reality'] = 'v0.0.0-20260322125925-9234c772ba8f';
veAssert(!$bot->realityRequiresMlkem(), 'Текущий форк не объявляется новым REALITY');
$bot->p['transport'] = 'Websocket';
$bot->generated = $output;
veAssert($bot->applyVlessEncryption('x25519', 'native') === '', 'Форк использует тот же генератор и проверку Encryption');
$bot->applyVlessEncryption('off', 'native');
veAssert($bot->applyVlessEncryption('x25519', 'native', true) === 'vless encryption unavailable', 'Старая кнопка ротации не включает отключённое шифрование');

// Пустые списки в полном шаблоне не должны ломать разбор конфигурации Xray.
$bot = new VlessEncryptionTestBot();
$template = $bot->subTemplate('', 'v2ray', []);
$template['routing']['rules'] = [
    ['type' => 'field', 'outboundTag' => 'proxy', 'domain' => []],
    ['type' => 'field', 'outboundTag' => 'proxy', 'ip' => []],
    ['type' => 'field', 'outboundTag' => 'proxy', 'domain' => [], 'port' => '443'],
    ['type' => 'field', 'outboundTag' => 'proxy', 'protocol' => ['bittorrent']],
];
$bot->templates['v2ray'] = $template;
$_GET = ['s' => 'test-sub', 't' => 's'];
$profile = json_decode($bot->subscription(true), true);
veAssert(count($profile['routing']['rules']) === 2, 'Правила без условий удаляются');
veAssert($profile['routing']['rules'][0]['port'] === '443', 'Условие port при пустом domain сохраняется');
veAssert($profile['routing']['rules'][1]['protocol'] === ['bittorrent'], 'Другие условия маршрутизации сохраняются');
$_GET['t'] = 'cl';
$profile = yaml_parse($bot->subscription(true));
veAssert($profile['proxies'][0]['client-fingerprint'] === 'firefox', 'WebSocket получает fingerprint на уровне прокси');

// Ограничение применяется и к ссылке импорта sing-box из другого формата.
$bot->generated = $output;
$bot->applyVlessEncryption('x25519', 'native');
foreach (['si', 'k', 'h', 'w'] as $deepLink) {
    $_GET = ['s' => 'test-sub', 't' => 's', 'r' => $deepLink];
    veAssert($bot->subscription(true) === '', 'Несовместимый deep-link блокируется до редиректа');
}

// Реальная запись pac.json сохраняет закрытые права независимо от umask.
$diskBot = (new ReflectionClass(Bot::class))->newInstanceWithoutConstructor();
$dir = sys_get_temp_dir() . '/vpnbot-encryption-' . bin2hex(random_bytes(8));
mkdir($dir, 0700);
$diskBot->pac = "$dir/pac.json";
$mask = umask(0022);
try {
    veAssert($diskBot->setPacConf(['vless_encryption' => $pairs['x25519']]), 'PAC записан');
    veAssert((fileperms($diskBot->pac) & 0777) === 0600, 'PAC с ключами доступен только владельцу');
    chmod($diskBot->pac, 0644);
    veAssert($diskBot->setPacConf(['vless_encryption' => $pairs['mlkem768']]), 'PAC перезаписан атомарно');
    clearstatcache(true, $diskBot->pac);
    veAssert((fileperms($diskBot->pac) & 0777) === 0600, 'Замена старого PAC исправляет его права');
} finally {
    @unlink($diskBot->pac);
    rmdir($dir);
    umask($mask);
}
$_GET = [];
echo "vless_encryption_test OK ($veChecks checks)\n";
