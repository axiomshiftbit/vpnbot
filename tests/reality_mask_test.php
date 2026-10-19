<?php

// Проверка сайта-маски REALITY. Xray 26.10.17+ отвергает всех клиентов, если
// маска отвечает без ALPN (и без подтверждения SNI): бот должен это увидеть
// и предупредить, а для старых ядер — предупредить заранее. Вывод openssl
// ниже снят командой Bot::realityMaskCommand() с настоящих масок; поведение
// ядра на тех же масках проверяет reality_mask_core_test.php.

require_once __DIR__ . '/../app/bot.php';

$checks = 0;
function rmkAssert(bool $ok, string $message): void
{
    global $checks;
    $checks++;
    if (!$ok) {
        throw new RuntimeException('reality_mask_test: ' . $message);
    }
}

class RealityMaskTestBot extends Bot
{
    protected const REALITY_MASK_FILE = '/tmp/vpnbot-reality-mask-test.json';
    public array $p = ['transport' => 'Reality'];
    public array $x = [];
    public array $probe = [];
    public array $outputs = [];
    public array $commands = [];
    public array $answers = [];
    public int $menus = 0;
    public function __construct() { $this->input = ['callback_id' => 1, 'chat' => 1, 'message_id' => 1]; $this->language = 'ru'; }
    public function getPacConf() { return $this->p; }
    public function getXray() { return $this->x; }
    public function xrayCoreProbe(bool $fresh = false): array { return $this->probe; }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
    {
        $this->commands[] = [$cmd, $service];
        $this->sshFailed = $this->outputs === [];
        return array_shift($this->outputs) ?? '';
    }
    public function answer($callback_id, $textNotify = false, $notify = false) { $this->answers[] = $textNotify; }
    public function xray($page = 0) { $this->menus++; }
    public function i18n(string $key): string { return $key . ($key === 'reality mask fail' ? ' %s %s' : ' %s'); }
    public static function file(): string { return static::REALITY_MASK_FILE; }
}

function rmkXray(string $dest, string $sni): array
{
    return ['inbounds' => [['streamSettings' => ['security' => 'reality', 'realitySettings' => [
        'dest' => $dest, 'serverNames' => [$sni], 'privateKey' => 'k', 'shortIds' => ['']]]]]];
}

function rmkRecords(string ...$headers): string
{
    $out = '';
    foreach ($headers as $h) {
        $out .= "<<< TLS 1.2, RecordHeader [length 0005]\n    $h\n--\n";
    }
    return $out;
}

$tls13 = "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\nProtocol: TLSv1.3\n--\n";
$hello = ['16 03 03 04 ba', '14 03 03 00 01'];
$tail  = ['17 03 03 03 3b', '17 03 03 01 19', '17 03 03 00 45'];
$out = [
    'h2'      => rmkRecords(...array_merge($hello, ['17 03 03 00 20'], $tail)) . $tls13 . "ALPN protocol: h2\nEarly data was not sent\n",
    'empty'   => rmkRecords(...array_merge($hello, ['17 03 03 00 17'], $tail)) . $tls13 . "No ALPN negotiated\nEarly data was not sent\n--\n" . rmkRecords('17 03 03 00 fa'),
    'sniack'  => rmkRecords(...array_merge($hello, ['17 03 03 00 1b'], $tail)) . $tls13 . "No ALPN negotiated\nEarly data was not sent\n",
    // Весь ответ одной записью (как у www.google.com).
    'joined'  => rmkRecords(...array_merge($hello, ['17 03 03 0a 51'])) . $tls13 . "No ALPN negotiated\n",
    'tls12'   => rmkRecords('16 03 03 00 4a', '16 03 03 03 27', '14 03 03 00 01', '16 03 03 00 28')
        . "New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384\nProtocol: TLSv1.2\n--\nALPN protocol: h2\n",
    'refused' => "4067EB1A1A700000:error:8000006F:system library:BIO_connect:Connection refused:../crypto/bio/bio_sock2.c:183:calling connect()\nconnect:errno=111\n",
    'dns'     => "40478637CE740000:error:10080002:BIO routines:BIO_lookup_ex:system lib:../crypto/bio/bio_addr.c:767:Name or service not known\nconnect:errno=0\n",
    'none'    => "New, (NONE), Cipher is (NONE)\n",
];

// ── Разбор вывода ────────────────────────────────────────────────────────────
foreach ([
    'h2'      => ['ok', 'h2', 32, ''],
    'empty'   => ['short', '', 23, ''],
    'sniack'  => ['ok', '', 27, ''],
    'joined'  => ['ok', '', 0xa51, ''],
    'tls12'   => ['tls12', 'h2', 0, 'TLSv1.2'],
    'refused' => ['fail', '', 0, 'connection refused'],
    'dns'     => ['fail', '', 0, 'DNS'],
    'none'    => ['fail', '', 0, 'TLS handshake'],
    ''        => ['fail', '', 0, 'timeout'],
] as $name => [$status, $alpn, $record, $reason]) {
    $v = Bot::realityMaskVerdict($out[$name] ?? '');
    rmkAssert($v === ['status' => $status, 'reason' => $reason, 'alpn' => $alpn, 'record' => $record],
        "разбор «{$name}»: " . json_encode($v));
}
rmkAssert(Bot::REALITY_MASK_MIN_RECORD === 27, 'граница — запись REALITY с подтверждением SNI');

// ── Команда: адрес и SNI экранированы, ALPN как у браузера ───────────────────
$cmd = Bot::realityMaskCommand('www.example.com:443', 'www.example.com');
rmkAssert(str_contains($cmd, "-connect 'www.example.com:443' -servername 'www.example.com' -alpn h2,http/1.1 -msg"), 'команда пробы: ' . $cmd);
rmkAssert(str_starts_with($cmd, 'timeout '), 'проба ограничена по времени');

// ── Адрес маски из конфига ───────────────────────────────────────────────────
$bot = new RealityMaskTestBot();
foreach ([
    [rmkXray('www.example.com:443', 'www.example.com'), ['www.example.com:443', 'www.example.com']],
    [rmkXray('10.10.1.2:443', 'vpn.example.org'), ['10.10.1.2:443', 'vpn.example.org']],
    [['inbounds' => [['streamSettings' => ['realitySettings' => ['target' => 'a.example.com:8443', 'serverNames' => ['a.example.com']]]]]], ['a.example.com:8443', 'a.example.com']],
    [rmkXray('443', 'www.example.com'), ['', '']],
    [rmkXray('/run/mask.sock', 'www.example.com'), ['', '']],
    [rmkXray("x.example.com:443' ; id", 'x.example.com'), ['', '']],
    [rmkXray('www.example.com:443', ''), ['', '']],
    [[], ['', '']],
] as [$x, $expected]) {
    rmkAssert($bot->realityMaskTarget($x) === $expected, 'адрес маски ' . json_encode($x));
}

// ── Правило ядра ─────────────────────────────────────────────────────────────
$probe = static fn(array $p): array => $p + ['ok' => true, 'running' => '', 'active' => 'origin', 'reality' => '', 'reality_local' => false, 'version' => ''];
foreach ([
    [['reality' => 'v0.0.0-20261014101318-83f621788ca8'], true, '26.10.17'],
    [['reality' => 'v0.0.0-20260921001439-3c98159aaaaa'], true, 'первый коммит с подтверждением SNI'],
    [['reality' => 'v0.0.0-20260908062103-8cdf7bf9c7f0'], false, '26.10.10'],
    [['active' => 'fork', 'reality' => 'v0.0.0-20260908062103-8cdf7bf9c7f0', 'reality_local' => true], false, 'форк 26.10.13 со своей копией'],
    [['version' => 'Xray 26.10.17 (Xray, Penetrates Everything.)'], true, 'без build info, 26.10.17'],
    [['version' => 'Xray 26.10.10 (Xray, Penetrates Everything.)'], false, 'без build info, 26.10.10'],
    [['active' => 'fork', 'version' => 'Xray 26.10.20-2400'], false, 'неизвестный форк без build info'],
    [['ok' => false, 'reality' => 'v0.0.0-20261014101318-83f621788ca8'], false, 'ядро не ответило'],
    [['running' => 'fork', 'reality' => 'v0.0.0-20261014101318-83f621788ca8'], false, 'симлинк и процесс расходятся'],
] as [$p, $expected, $label]) {
    $bot->probe = $probe($p);
    rmkAssert($bot->realityAcksServerName() === $expected, "правило ядра: $label");
}

// ── Кеш, срок и повторная проверка ───────────────────────────────────────────
$file = RealityMaskTestBot::file();
@unlink($file);
try {
    $bot->x = rmkXray('www.example.com:443', 'www.example.com');
    rmkAssert($bot->realityMaskCached() === null, 'без файла результата нет');

    $bot->outputs = [$out['empty']];
    $r = $bot->realityMaskCheck();
    rmkAssert(($r['status'] ?? '') === 'short' && $r['target'] === 'www.example.com:443' && $r['sni'] === 'www.example.com', 'первая проверка');
    rmkAssert($bot->commands[0][1] === 'xr', 'проба идёт из контейнера xr');
    rmkAssert($bot->commands[0][0] === Bot::realityMaskCommand('www.example.com:443', 'www.example.com'), 'проба той же командой');
    rmkAssert(($bot->realityMaskCached()['status'] ?? '') === 'short', 'результат сохранён');

    $bot->commands = [];
    rmkAssert(($bot->realityMaskCheck()['status'] ?? '') === 'short' && $bot->commands === [], 'свежий результат без новой пробы');
    $bot->outputs = [$out['h2']];
    rmkAssert(($bot->realityMaskCheck(true)['status'] ?? '') === 'ok' && count($bot->commands) === 1, 'кнопка проверяет заново');

    // Устаревший устойчивый результат — через 6 часов, сбой — через 10 минут.
    $age = static function (int $seconds) use ($file): void {
        $c = json_decode((string) file_get_contents($file), true);
        $c['ts'] = time() - $seconds;
        file_put_contents($file, json_encode($c));
    };
    $bot->commands = [];
    $age(Bot::REALITY_MASK_TTL - 60);
    $bot->realityMaskCheck();
    rmkAssert($bot->commands === [], 'результат «ok» держится 6 часов');
    $age(Bot::REALITY_MASK_TTL + 1);
    $bot->outputs = [$out['refused']];
    rmkAssert(($bot->realityMaskCheck()['status'] ?? '') === 'fail' && count($bot->commands) === 1, 'через 6 часов — новая проба');
    $age(Bot::REALITY_MASK_RETRY + 1);
    $bot->outputs = [$out['h2']];
    rmkAssert(($bot->realityMaskCheck()['status'] ?? '') === 'ok' && count($bot->commands) === 2, 'после сбоя — повтор через 10 минут');

    // Другая маска — старый результат не годится.
    $bot->x = rmkXray('www.example.org:443', 'www.example.org');
    rmkAssert($bot->realityMaskCached() === null, 'результат другой маски не показывается');

    // Отказ ssh — не вердикт о маске: без предупреждения, повтор скоро.
    $bot->outputs = [];
    $r = $bot->realityMaskCheck();
    rmkAssert(($r['status'] ?? '') === 'error' && $bot->realityMaskWarnings($r) === [], 'отказ ssh без предупреждения');

    // Cron проверяет только при REALITY.
    $bot->commands = [];
    $bot->p = ['transport' => 'ws'];
    $age(Bot::REALITY_MASK_TTL + 1);
    $bot->checkRealityMask();
    rmkAssert($bot->commands === [], 'без REALITY маску не проверяем');
    $bot->p = ['transport' => 'Reality'];
    $bot->outputs = [$out['h2']];
    $bot->checkRealityMask();
    rmkAssert(count($bot->commands) === 1, 'cron проверяет маску REALITY');

    // ── Предупреждения ──────────────────────────────────────────────────────
    $mask = static fn(string $status, string $reason = '') => ['status' => $status, 'reason' => $reason, 'alpn' => '', 'record' => 0, 'sni' => 'www.example.org'];
    $bot->probe = $probe(['reality' => 'v0.0.0-20261014101318-83f621788ca8']);
    rmkAssert($bot->realityMaskWarnings($mask('short')) === ['reality mask short now www.example.org'], 'ядро 26.10.17: клиенты отвергаются сейчас');
    $bot->probe = $probe(['reality' => 'v0.0.0-20260908062103-8cdf7bf9c7f0']);
    rmkAssert($bot->realityMaskWarnings($mask('short')) === ['reality mask short www.example.org'], 'старое ядро: предупреждение на будущее');
    rmkAssert($bot->realityMaskWarnings($mask('tls12')) === ['reality mask tls12 www.example.org'], 'без TLS 1.3');
    rmkAssert($bot->realityMaskWarnings($mask('fail', 'DNS')) === ['reality mask fail www.example.org DNS'], 'маска недоступна');
    rmkAssert($bot->realityMaskWarnings($mask('ok')) === [], 'хорошая маска без предупреждений');

    // ── Кнопка «проверить» ──────────────────────────────────────────────────
    $bot->outputs = [$out['h2']];
    $bot->checkFakeDomain();
    rmkAssert(end($bot->answers) === '✅ TLS 1.3, ALPN h2' && $bot->menus === 1, 'кнопка: маска в порядке');
    $bot->outputs = [$out['empty']];
    $bot->checkFakeDomain();
    rmkAssert(str_starts_with((string) end($bot->answers), '⚠ reality mask short') && mb_strlen((string) end($bot->answers)) <= 200, 'кнопка: предупреждение');
    $bot->outputs = [];
    $bot->checkFakeDomain();
    rmkAssert(end($bot->answers) === 'fake domain: ? (ssh)', 'кнопка: контейнер не ответил');
} finally {
    @unlink($file);
}

// ── Меню Xray и проводка ─────────────────────────────────────────────────────
$src = file_get_contents(__DIR__ . '/../app/bot.php');
rmkAssert(str_contains($src, "case preg_match('~^/checkFakeDomain$~'"), 'кнопка подключена');
rmkAssert(preg_match("~'checkXrayCore',\s*'checkRealityMask',~", $src) === 1, 'шаг cron');
$fake = substr($src, strpos($src, 'public function setFakeDomain('), 2400);
rmkAssert(str_contains($fake, '$this->realityMaskCheck(true);'), 'смена маски сразу её проверяет');
require __DIR__ . '/../app/i18n.php';
$i18n = $i;
foreach (['check fake domain', 'reality mask short', 'reality mask short now', 'reality mask tls12', 'reality mask fail'] as $key) {
    rmkAssert(!empty($i18n[$key]['ru']) && !empty($i18n[$key]['en']), "строка $key");
    $n = substr_count($i18n[$key]['ru'], '%s');
    rmkAssert($n === substr_count($i18n[$key]['en'], '%s'), "подстановки $key совпадают");
}

echo "reality_mask_test OK ($checks)\n";
