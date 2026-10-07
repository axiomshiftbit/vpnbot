<?php

// Свой сайт-приманка WEB-режима telemt (web.vhosts.decoy = http_upstream,
// имена хостов — с telemt 3.5.14).
//
// Здесь две цены ошибки, и обе выше обычной:
//   * невалидный адрес telemt не пропускает, а отказывается грузить конфиг
//     целиком — вместе с обычным MTProto. Неразрешимое имя хоста даёт то же
//     самое уже после старта процесса;
//   * запросы без секрета уходят на указанный адрес с ПУБЛИЧНОГО хоста. Адрес
//     панели, unit, Docker API, loopback контейнера или метаданных облака
//     превращает приманку в открытую дверь во внутреннюю сеть.

require_once __DIR__ . '/../app/bot.php';
require __DIR__ . '/../app/i18n.php';

$checks = 0;
function wdAssert(bool $ok, string $message): void
{
    global $checks;
    $checks++;
    if (!$ok) {
        throw new RuntimeException('telemt_web_decoy_test: ' . $message);
    }
}

class TelemtDecoyTestBot extends Bot
{
    public array  $pacFake  = [];
    public string $ver      = '3.5.14';
    public ?array $probe    = ['addresses' => ['192.168.7.10'], 'status' => 200, 'location' => ''];
    public int    $probes   = 0;
    public int    $restarts = 0;
    public bool   $revert   = false;
    public array  $screens  = [];
    public array  $prompts  = [];

    public function getPacConf() { return $this->pacFake; }
    public function setPacConf(array $conf) { $this->pacFake = $conf; return true; }
    public function getPorts() { return ['telemt' => ['port' => 8443, 'enable' => 1]]; }
    public function telemtVersion(): string { return $this->ver; }
    public function telemtWebDecoyProbe(array $decoy): ?array { $this->probes++; return $this->probe; }
    public function restartTelemt()
    {
        $this->restarts++;
        if ($this->revert) {
            unset($this->pacFake['telemt_web_decoy']);
        }
    }
    public function update($chat, $message, $text, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false)
    {
        $this->screens[] = ['text' => $text, 'buttons' => $button];
    }
    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false)
    {
        $this->prompts[] = $text;
        return ['result' => ['message_id' => 77]];
    }
    public function stashReply($r, array $state) { $this->prompts[] = $state; }
}

$mk = static function (array $extra = [], string $class = TelemtDecoyTestBot::class) use ($i) {
    $b = (new ReflectionClass($class))->newInstanceWithoutConstructor();
    $b->i18n = $i;
    $b->key = 'test-bot-key';
    $b->ip = '203.0.113.10';
    $b->language = 'ru';
    $b->input = ['chat' => 1, 'message_id' => 2, 'callback_id' => 3, 'username' => 'admin'];
    $b->pacFake = $extra + [
        'domain'        => 'vpn.example',
        'letsencrypt'   => 'letsencrypt',
        'telemt_web'    => 1,
        'telemt_domain' => 'www.google.com',
        'telemt_users'  => ['bob' => 'aabbccddeeff00112233445566778899'],
    ];
    return $b;
};

// ── 1. Какие адреса вообще допустимы ────────────────────────────────────────
$accepted = [
    'http://10.10.0.1:8081'      => ['http://10.10.0.1:8081', false, 8081],
    'http://10.10.0.1'           => ['http://10.10.0.1', false, 80],
    ' http://192.168.1.10:3000/ ' => ['http://192.168.1.10:3000', false, 3000],
    'http://172.17.0.1:81'       => ['http://172.17.0.1:81', false, 81],
    'http://10.200.3.4:9000'     => ['http://10.200.3.4:9000', false, 9000],
    'http://[FD00:0:0::1]:8000'  => ['http://[fd00::1]:8000', false, 8000],
    'http://site.lan'            => ['http://site.lan', true, 80],
    'http://My_Site:8000'        => ['http://my_site:8000', true, 8000],
];
foreach ($accepted as $value => [$origin, $name, $port]) {
    $r = Bot::telemtWebDecoyParse($value);
    wdAssert(($r['origin'] ?? null) === $origin && $r['name'] === $name && $r['port'] === $port,
        "принят «{$value}»: " . json_encode($r));
}
$refused = [
    'telemt web decoy bad url' => ['', 'site.lan', 'https://10.0.0.1', 'ftp://10.0.0.1', 'http://user@10.0.0.1',
        'http://u:p@10.0.0.1', 'http://10.0.0.1/path', 'http://10.0.0.1?x=1', 'http://10.0.0.1#f', 'http://10.0.0.1:0',
        'http://10.0.0.1:70000', 'http://ex ample', "http://10.0.0.1\nx", 'http://-bad.lan', 'http://bad-.lan',
        'http://xn--e1afmkfd.lan', 'http://[fd00::zz]:81',
        // URL-парсер ядра читает всё это как IPv4 — адреса, которые проверка
        // «на глаз» приняла бы за имена или за другие числа.
        'http://10.1', 'http://2130706433', 'http://0x7f.0.0.1', 'http://010.0.0.1', 'http://a.123', 'http://ok.0x1f',
        'http://1.2.3.4.5'],
    'telemt web decoy own port' => ['http://192.168.1.10:8080', 'http://site.lan:8080', 'http://[fd00::1]:8080'],
    'telemt web decoy not private' => [
        // собственные сервисы сборки
        'http://10.10.0.7:8090', 'http://10.10.0.5', 'http://10.10.0.8:2375', 'http://10.10.0.20:9091',
        'http://10.10.1.2', 'http://10.10.255.254',
        // loopback контейнера telemt, link-local (метаданные облака), публичные
        'http://127.0.0.1:9091', 'http://127.1.2.3', 'http://169.254.169.254', 'http://8.8.8.8', 'http://172.32.0.1',
        'http://192.169.0.1', 'http://100.64.0.1', 'http://0.0.0.0:81',
        'http://[::1]:81', 'http://[fe80::1]:81', 'http://[::ffff:10.0.0.1]:81', 'http://[2001:db8::1]:81'],
];
foreach ($refused as $error => $values) {
    foreach ($values as $value) {
        wdAssert(Bot::telemtWebDecoyParse($value) === ['error' => $error], "отклонён «{$value}» как $error: "
            . json_encode(Bot::telemtWebDecoyParse($value)));
    }
}
// Каждый статический адрес сервисов из docker-compose обязан отклоняться: новый
// сервис с адресом вне DOCKER_NET сломает этот тест, а не безопасность молча.
preg_match_all('~ipv4_address:\s*(\S+)~', (string) file_get_contents(__DIR__ . '/../docker-compose.yml'), $compose);
wdAssert(count($compose[1]) > 20, 'адреса сервисов прочитаны из docker-compose.yml');
foreach (array_unique($compose[1]) as $address) {
    wdAssert(!Bot::telemtWebDecoyAddressOk($address), "адрес сервиса сборки $address не может быть приманкой");
}
wdAssert(Bot::telemtWebDecoyAddressOk(Bot::TELEMT_WEB_DECOY_GATEWAY), 'шлюз docker-сети (хост) разрешён');
wdAssert(!Bot::telemtWebDecoyAddressOk('not-an-ip') && !Bot::telemtWebDecoyAddressOk(''), 'не адрес — не приватный адрес');

// ── 2. Конфигурация telemt ──────────────────────────────────────────────────
$b = $mk();
$toml = $b->telemtToml($b->pacFake);
wdAssert(str_contains($toml, "[web.vhosts.decoy]\nmode = \"static_directory\"\ndirectory = \"/telemt/decoy\"\nindex = \"index.html\"\n"),
    'по умолчанию — встроенная страница');
wdAssert(!str_contains($toml, 'http_upstream') && !str_contains($toml, '[web.timeouts]') && !str_contains($toml, 'resolve'),
    'без настройки новых ключей нет');

$b = $mk(['telemt_web_decoy' => 'http://10.10.0.1:8081']);
$toml = $b->telemtToml($b->pacFake);
wdAssert(str_contains($toml, "[web.vhosts.decoy]\nmode = \"http_upstream\"\nupstream = \"http://10.10.0.1:8081\"\n\n[[web.vhosts.profiles]]"),
    'IP-адрес: http_upstream без resolve');
wdAssert(!str_contains($toml, 'static_directory') && !str_contains($toml, 'resolve') && !str_contains($toml, '[web.timeouts]'),
    'IP-адресу разрешение имён не нужно');

$b = $mk(['telemt_web_decoy' => 'http://site.lan:8000']);
$toml = $b->telemtToml($b->pacFake);
wdAssert(str_contains($toml, "mode = \"http_upstream\"\nupstream = \"http://site.lan:8000\"\nresolve = \"startup\"\n"),
    'имя хоста: resolve = "startup"');
wdAssert(str_contains($toml, "[web.timeouts]\ndecoy_resolve_secs = " . Bot::TELEMT_WEB_DECOY_RESOLVE_SECS . "\n\n[[web.vhosts]]\n"),
    'срок разрешения имени задан перед vhost');
wdAssert(strpos($toml, '[web.limits]') < strpos($toml, '[web.timeouts]')
    && strpos($toml, '[web.timeouts]') < strpos($toml, '[[web.vhosts]]'), 'таблицы [web] идут до массива vhosts');

foreach (['http://10.10.0.7:8090', 'http://127.0.0.1:9091', 'garbage', ['http://10.10.0.1'], 5] as $garbage) {
    $b = $mk(['telemt_web_decoy' => $garbage]);
    wdAssert($b->telemtWebDecoyOf($b->pacFake) === null && str_contains($b->telemtToml($b->pacFake), 'static_directory'),
        'недопустимое значение из pac.json или бэкапа — встроенная страница: ' . json_encode($garbage));
}
$b = $mk(['telemt_web_decoy' => 'http://10.10.0.1:8081', 'telemt_web' => 0]);
wdAssert(!str_contains($b->telemtToml($b->pacFake), 'http_upstream'), 'без WEB секции приманки нет вовсе');

// ── 3. Сохранение: проверки до записи ───────────────────────────────────────
$apply = static function (string $value, array $setup = []) use ($mk): array {
    $b = $mk();
    foreach ($setup as $key => $v) {
        $b->$key = $v;
    }
    $error = $b->telemtWebDecoyApply($value);
    return [$error, $b];
};
[$error, $b] = $apply('http://192.168.7.10:81');
wdAssert($error === '' && $b->pacFake['telemt_web_decoy'] === 'http://192.168.7.10:81' && $b->restarts === 1 && $b->probes === 1,
    'рабочий адрес сохранён, активный WEB перезапущен один раз');
wdAssert($b->telemtWebDecoyApply('http://192.168.7.10:81/') === '' && $b->restarts === 1, 'то же значение повторно — без перезапуска');
wdAssert($b->telemtWebDecoyApply('') === '' && !isset($b->pacFake['telemt_web_decoy']) && $b->restarts === 2 && $b->probes === 2,
    'возврат к встроенной странице не требует проверки адреса');
wdAssert($b->telemtWebDecoyApply('') === '' && $b->restarts === 2, 'повторный сброс ничего не делает');

[$error, $b] = $apply('http://8.8.8.8');
wdAssert($error === 'telemt web decoy not private' && $b->probes === 0 && $b->restarts === 0 && !isset($b->pacFake['telemt_web_decoy']),
    'недопустимый адрес отклонён до обращения к контейнеру');
[$error, $b] = $apply('http://site.lan', ['ver' => '3.5.13']);
wdAssert($error === 'telemt web decoy need version' && $b->probes === 0 && !isset($b->pacFake['telemt_web_decoy']),
    'имя хоста на образе старше 3.5.14 не принимается');
[$error, $b] = $apply('http://192.168.7.10:81', ['ver' => '3.5.13']);
wdAssert($error === '' && isset($b->pacFake['telemt_web_decoy']), 'IP-адрес от версии 3.5.14 не зависит');
$webHost = $mk()->telemtWebHost($mk()->pacFake);
wdAssert($webHost !== '' && str_ends_with($webHost, '.vpn.example'), 'у тестового бота есть WEB-хост');
$failures = [
    'telemt web decoy unchecked'   => null,
    'telemt web decoy unresolved'  => ['addresses' => [], 'status' => 0, 'location' => ''],
    'telemt web decoy no answer'   => ['addresses' => ['192.168.7.10'], 'status' => 0, 'location' => ''],
    'telemt web decoy redirect'    => ['addresses' => ['192.168.7.10'], 'status' => 301, 'location' => 'https://' . strtoupper($webHost) . '/'],
];
foreach ($failures as $expected => $probe) {
    [$error, $b] = $apply('http://site.lan:81', ['probe' => $probe]);
    wdAssert($error === $expected && !isset($b->pacFake['telemt_web_decoy']) && $b->restarts === 0, "отказ: $expected ($error)");
}
// Имя, которое в контейнере telemt ведёт в сеть сборки, на loopback или наружу.
foreach ([['10.10.0.7'], ['127.0.0.1'], ['192.168.7.10', '10.10.0.5'], ['192.168.7.10', '93.184.216.34'], ['::1'], [5]] as $addresses) {
    [$error, $b] = $apply('http://site.lan:81', ['probe' => ['addresses' => $addresses, 'status' => 200, 'location' => '']]);
    wdAssert($error === 'telemt web decoy not private' && !isset($b->pacFake['telemt_web_decoy']),
        'имя с недопустимым адресом отклонено: ' . json_encode($addresses));
}
[$error, $b] = $apply('http://site.lan:81', ['probe' => ['addresses' => ['192.168.7.10'], 'status' => 302, 'location' => 'https://other.example/x']]);
wdAssert($error === '' && isset($b->pacFake['telemt_web_decoy']), 'перенаправление на другой хост петлёй не считается');
[$error, $b] = $apply('http://site.lan:81', ['probe' => ['addresses' => ['192.168.7.10'], 'status' => 404, 'location' => '']]);
wdAssert($error === '', 'любой ответ HTTP, включая 404, означает живой сайт');

$b = $mk(['telemt_web' => 0]);
wdAssert($b->telemtWebDecoyApply('http://192.168.7.10:81') === '' && $b->restarts === 0 && isset($b->pacFake['telemt_web_decoy']),
    'при выключенном WEB настройка сохраняется без перезапуска');
[$error, $b] = $apply('http://192.168.7.10:81', ['revert' => true]);
wdAssert($error === 'telemt web decoy reverted' && !isset($b->pacFake['telemt_web_decoy']),
    'если telemt с адресом не поднялся и настройку сняла лестница откатов — об этом сказано');

// ── 4. Меню ─────────────────────────────────────────────────────────────────
$b = $mk();
$b->telemtWebDecoyMenu();
$screen = end($b->screens);
wdAssert(str_contains($screen['text'], 'decoy: встроенная страница'), 'меню показывает встроенную страницу');
wdAssert(array_column(array_merge(...$screen['buttons']), 'callback_data') === ['/telemtWebDecoy ask', '/telemtWebDecoy reset', '/telemtWeb'],
    'кнопки подменю');
wdAssert(str_starts_with($screen['buttons'][1][0]['text'], '✅ '), 'действующий выбор отмечен');
$b->telemtWebDecoyMenu('ask');
wdAssert(($b->prompts[1]['callback'] ?? '') === 'telemtWebDecoySet' && str_contains($b->prompts[0], 'http://10.10.0.1:8081'),
    'запрос адреса ждёт ответа и показывает пример');
$b->telemtWebDecoySet('http://192.168.7.10:81');
$screen = end($b->screens);
wdAssert(str_contains($screen['text'], '<code>http://192.168.7.10:81</code>') && str_contains($screen['text'], 'ℹ Сайт-приманка изменён.')
    && !str_starts_with($screen['buttons'][1][0]['text'], '✅ '), 'после ввода меню показывает новый адрес');
$b->telemtWebDecoySet('http://10.10.0.7:8090');
$screen = end($b->screens);
wdAssert(str_contains($screen['text'], '⚠ Адрес не принят') && str_contains($screen['text'], '<code>http://192.168.7.10:81</code>'),
    'отказ показан, прежний адрес остался');
$b->telemtWebDecoyMenu('reset');
$screen = end($b->screens);
wdAssert(str_contains($screen['text'], 'decoy: встроенная страница') && str_contains($screen['text'], 'ℹ Сайт-приманка изменён.'),
    'сброс возвращает встроенную страницу');
foreach (['telemt web decoy', 'telemt web decoy builtin', 'telemt web decoy ask', 'telemt web decoy setup', 'telemt web decoy changed',
    'telemt web decoy bad url', 'telemt web decoy own port', 'telemt web decoy not private', 'telemt web decoy need version',
    'telemt web decoy unchecked', 'telemt web decoy unresolved', 'telemt web decoy no answer', 'telemt web decoy redirect',
    'telemt web decoy reverted'] as $key) {
    foreach (['ru', 'en'] as $language) {
        $b->language = $language;
        wdAssert($b->i18n($key) !== $key && $b->i18n($key) !== '', "есть текст «{$key}» ($language)");
    }
}
$source = (string) file_get_contents(__DIR__ . '/../app/bot.php');
wdAssert(preg_match('~case preg_match\(\'\~\^/telemtWebDecoy\(\?: \(ask\|reset\)\)\?\$\~\'.*?\n\s*\$this->telemtWebDecoyMenu\(\$m\[1\] \?\? \'\'\);~', $source) === 1,
    'кнопки подменю зарегистрированы в маршрутизаторе');

// ── 5. Лестница откатов при запуске ─────────────────────────────────────────
// telemt с недоступной приманкой не стартует вовсе; встроенная страница
// возвращается ПЕРВОЙ ступенью — до снятия подбора carrier и самого WEB.
class TelemtDecoyHealBot extends TelemtDecoyTestBot
{
    public array $sshCalls = [];
    public array $tomls = [];
    public array $alive = [];       // ответы проб по порядку; дальше — последний
    public int $nginxReloads = 0;

    public function restartTelemt() { return Bot::restartTelemt(); }
    public function telemtWriteServiceState(bool $enabled): void {}
    public function telemtWriteToml(string $toml): void { $this->tomls[] = $toml; }
    public function telemtWebDecoy(): void {}
    public function cloakNginx() { $this->nginxReloads++; return true; }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
    {
        $this->sshFailed = false;
        $this->sshCalls[] = $cmd;
        if (str_contains($cmd, 'telemt_state.py')) {
            return 'TELEMT_STATE_OK';
        }
        if (str_contains($cmd, 'pgrep -x telemt')) {
            $answer = count($this->alive) > 1 ? array_shift($this->alive) : $this->alive[0];
            return $answer ? '250' : '';
        }
        return '';
    }
}
$heal = static function (array $alive, array $extra) use ($mk): TelemtDecoyHealBot {
    $h = $mk($extra, TelemtDecoyHealBot::class);
    $h->alive = $alive;
    $h->restartTelemt();
    return $h;
};
$runs = static fn(TelemtDecoyHealBot $h): int => count(array_filter($h->sshCalls, static fn($c) => str_starts_with($c, 'telemt run')));
$waits = static fn(TelemtDecoyHealBot $h): int => count(array_filter($h->sshCalls,
    static fn($c) => $c === 'sleep ' . (Bot::TELEMT_WEB_DECOY_RESOLVE_SECS + 1) . '; pgrep -x telemt'));

$h = $heal([false, true], ['telemt_web_decoy' => 'http://192.168.7.10:81', 'telemt_web_negotiation' => 'https']);
wdAssert(!isset($h->pacFake['telemt_web_decoy']) && !empty($h->pacFake['telemt_web']), 'не поднялся с адресом: приманка сброшена, WEB остался');
wdAssert(count($h->tomls) === 2 && str_contains($h->tomls[0], 'http_upstream') && str_contains($h->tomls[1], 'static_directory')
    && str_contains($h->tomls[1], '[web]'), 'второй конфиг — со встроенной страницей и по-прежнему с WEB');
wdAssert(($h->pacFake['telemt_web_negotiation'] ?? '') === 'https' && str_contains($h->tomls[1], 'carriers = '),
    'подбор carrier при этом не тронут');
wdAssert($runs($h) === 2 && $h->nginxReloads === 0 && $waits($h) === 0, 'один повторный запуск, nginx не трогаем');

$h = $heal([true], ['telemt_web_decoy' => 'http://192.168.7.10:81']);
wdAssert(isset($h->pacFake['telemt_web_decoy']) && count($h->tomls) === 1 && $runs($h) === 1 && $waits($h) === 0,
    'рабочий адрес остаётся, лишних проб для IP нет');

// Имя хоста: процесс жив, пока ждёт DNS, и гибнет после. Первая проба этого
// не видит — нужна вторая, позже срока разрешения имени.
$h = $heal([true, false, true], ['telemt_web_decoy' => 'http://site.lan:81']);
wdAssert($waits($h) === 1 && !isset($h->pacFake['telemt_web_decoy']) && !empty($h->pacFake['telemt_web']) && $runs($h) === 2,
    'имя не разрешилось после старта процесса: отказ замечен, возвращена встроенная страница');
$h = $heal([true], ['telemt_web_decoy' => 'http://site.lan:81']);
wdAssert($waits($h) === 1 && isset($h->pacFake['telemt_web_decoy']) && $runs($h) === 1, 'имя разрешилось: настройка остаётся');
$h = $heal([true], ['telemt_web_decoy' => 'http://site.lan:81', 'telemt_web' => 0]);
wdAssert($waits($h) === 0, 'без WEB дополнительной пробы нет');

// Причина не в приманке: дальше работают прежние ступени, вплоть до снятия WEB.
$h = $heal([false], ['telemt_web_decoy' => 'http://192.168.7.10:81', 'telemt_web_negotiation' => 'https']);
wdAssert(!isset($h->pacFake['telemt_web_decoy']) && ($h->pacFake['telemt_web_negotiation'] ?? '') === 'off'
    && empty($h->pacFake['telemt_web']) && $runs($h) === 4 && $h->nginxReloads === 1,
    'telemt не поднимается ни в каком виде: сняты приманка, подбор и WEB, по ступени за запуск');

// ── 6. Проверка адреса: настоящая команда против настоящего HTTP-сервера ────
class TelemtDecoyProbeBot extends Bot
{
    public function __construct() {}
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
    {
        $this->sshFailed = false;
        return (string) shell_exec($cmd . ' 2>/dev/null');
    }
}
$python = trim((string) shell_exec('command -v python3'));
if ($python === '') {
    echo "telemt_web_decoy_test: python3 нет, проверка команды пропущена\n";
} else {
    // Сервер отвечает только на тот Host, который отправит telemt: authority
    // из адреса приманки, а не публичное имя WEB-хоста.
    $server = <<<'PY'
import http.server,sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.headers.get('Host') != '127.0.0.1:%d' % self.server.server_address[1]: self.send_response(400)
        elif sys.argv[1]: self.send_response(301); self.send_header('Location', sys.argv[1])
        else: self.send_response(200)
        self.end_headers()
    def log_message(self, *a): pass
s=http.server.HTTPServer(('127.0.0.1',0),H); print(s.server_address[1],flush=True); s.serve_forever()
PY;
    $probeBot = new TelemtDecoyProbeBot();
    foreach (['' => 200, 'https://web.vpn.example/x' => 301] as $location => $status) {
        $process = proc_open([$python, '-c', $server, $location], [1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
        $port = (int) trim((string) fgets($pipes[1]));
        try {
            $result = $probeBot->telemtWebDecoyProbe(['origin' => "http://127.0.0.1:$port", 'host' => '127.0.0.1', 'port' => $port, 'name' => false]);
            wdAssert($port > 0 && $result === ['addresses' => ['127.0.0.1'], 'status' => $status, 'location' => $location],
                'проба видит адрес, код ответа и перенаправление: ' . json_encode($result));
        } finally {
            proc_terminate($process);
            proc_close($process);
        }
    }
    $result = $probeBot->telemtWebDecoyProbe(['origin' => 'http://nonexistent.invalid:81', 'host' => 'nonexistent.invalid', 'port' => 81, 'name' => true]);
    wdAssert($result === ['addresses' => [], 'status' => 0, 'location' => ''], 'неразрешимое имя — пустой список адресов: ' . json_encode($result));
    $result = $probeBot->telemtWebDecoyProbe(['origin' => 'http://127.0.0.1:1', 'host' => '127.0.0.1', 'port' => 1, 'name' => false]);
    wdAssert($result === ['addresses' => ['127.0.0.1'], 'status' => 0, 'location' => ''], 'закрытый порт — адрес есть, ответа нет');
    $result = $probeBot->telemtWebDecoyProbe(['origin' => "http://x:81", 'host' => "x'; echo pwned; '", 'port' => 81, 'name' => true]);
    wdAssert($result === ['addresses' => [], 'status' => 0, 'location' => ''], 'аргументы команды экранированы');
}

echo "telemt_web_decoy_test OK ($checks проверок)\n";
