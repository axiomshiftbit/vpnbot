<?php

// Явный порт relay (telemt 'port', hysteria 'hy_port', naive 'np_port') и
// relay для naiveproxy. Проверяется то, что ломается молча:
//  - relayPortInput(): поле не имеет «ошибочного» состояния — мусор и порт вне
//    1..65535 обязаны трактоваться как очистка, иначе в ссылку уедет строка
//    вроде «abc» или «70000» и клиент просто не подключится;
//  - relayPort(): приоритет port > portmap > порт origin. Перепутанный
//    приоритет = молчаливое игнорирование только что заданного порта;
//  - linkHysteria(): явный hy_port схлопывает диапазон port hopping (relay
//    слушает один UDP-порт), а без него работает старый путь через hy_portmap;
//  - linkNaive(): порт дописывается ТОЛЬКО когда задан (иначе клиент должен
//    идти на 443 по умолчанию), userinfo по-прежнему percent-encoded.

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function rpAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

// ── 1. relayPortInput ───────────────────────────────────────────────────────
$accept = [
    '8443'  => '8443',
    '443'   => '443',
    '1'     => '1',
    '65535' => '65535',
    ' 443 ' => '443',   // trim, как во всех relay-сеттерах
    '0443'  => '443',   // ведущий ноль нормализуется через (int)
];
foreach ($accept as $in => $out) {
    rpAssert(Bot::relayPortInput($in) === $out,
        'должно приниматься как ' . var_export($out, true) . ': ' . var_export($in, true));
}

// Всё остальное — очистка (у поля нет состояния «ошибка ввода»).
$clear = ['', '0', '00', 'abc', '70000', '65536', '-1', '44 3', '443:8443', '8.8.8.8', null, '1e3'];
foreach ($clear as $in) {
    rpAssert(Bot::relayPortInput($in) === '', 'должно очищать: ' . var_export($in, true));
}
// Сентинел очистки общий с адресами — '0' обязан ловиться и там, и тут.
rpAssert(Bot::relayClearInput('0') === true, "'0' — сентинел очистки");
rpAssert(Bot::relayClearInput('0.0.0.0') === false, 'адрес 0.0.0.0 сентинелом не считается');

// ── 2. relayPort: приоритет port > portmap > origin ─────────────────────────
rpAssert(Bot::relayPort(null, 443) === '443', 'без relay порт origin не трогается');
rpAssert(Bot::relayPort([], 443) === '443', 'пустой relay — порт origin');
rpAssert(Bot::relayPort(['portmap' => ['443' => '8443']], 443) === '8443', 'portmap применяется');
rpAssert(Bot::relayPort(['portmap' => ['80' => '8080']], 443) === '443', 'portmap мимо — порт origin');
rpAssert(Bot::relayPort(['port' => '9443', 'portmap' => ['443' => '8443']], 443) === '9443',
    'явный port перебивает portmap');
// Пустой/невалидный port не должен «съедать» portmap.
rpAssert(Bot::relayPort(['port' => '', 'portmap' => ['443' => '8443']], 443) === '8443',
    'пустой port — откат на portmap');
rpAssert(Bot::relayPort(['port' => 'abc', 'portmap' => ['443' => '8443']], 443) === '8443',
    'мусорный port — откат на portmap');
// Каналы независимы: hy_port не должен влиять на telemt/np и наоборот.
$multi = [
    'port'     => '1000',
    'hy_port'  => '2000',
    'np_port'  => '3000',
    'portmap'  => ['443' => '1443'],
];
rpAssert(Bot::relayPort($multi, 443) === '1000', "канал '' берёт port");
rpAssert(Bot::relayPort($multi, 443, 'hy_') === '2000', "канал hy_ берёт hy_port");
rpAssert(Bot::relayPort($multi, 443, 'np_') === '3000', "канал np_ берёт np_port");
rpAssert(Bot::relayPort($multi, 443, 'awg_') === '443', 'канал awg_ пуст — порт origin');
// Порт origin приходит и int, и строкой (getPorts даёт int) — ключи portmap строковые.
rpAssert(Bot::relayPort(['portmap' => ['51820' => '443']], 51820) === '443', 'int-порт находит строковый ключ');

// ── 3. Hysteria: hy_port схлопывает диапазон hopping ────────────────────────
// Ровно та же формула, что в linkHysteria().
$hySpec = function ($portSpec, array $relay): string {
    $map = $relay['hy_portmap'] ?? [];
    return ($fixed = Bot::relayPortInput($relay['hy_port'] ?? '')) !== ''
        ? $fixed
        : implode(',', array_map(
            fn($t) => preg_match('~^\d+$~', $t) ? (string) ($map[$t] ?? $t) : $t,
            preg_split('~,~', (string) $portSpec, -1, PREG_SPLIT_NO_EMPTY),
        ));
};

rpAssert($hySpec('36712', ['hy_portmap' => ['36712' => '443']]) === '443',
    'без hy_port работает старый путь через hy_portmap');
rpAssert($hySpec('20000-50000', ['hy_portmap' => ['36712' => '443']]) === '20000-50000',
    'диапазон hopping через карту не мапится (регрессия прежнего поведения)');
rpAssert($hySpec('20000-50000', ['hy_port' => '8443']) === '8443',
    'явный hy_port схлопывает диапазон hopping в один порт');
rpAssert($hySpec('36712,20000-50000', ['hy_port' => '8443']) === '8443',
    'мультипорт тоже схлопывается');
rpAssert($hySpec('36712', ['hy_port' => '0', 'hy_portmap' => ['36712' => '443']]) === '443',
    'hy_port=0 (очистка) не ломает откат на карту');

// ── 4. Naive: ссылка с relay и без ──────────────────────────────────────────
// Схема из README naiveproxy; порт дописывается только когда задан.
$mkLink = function (string $u, string $p, string $host, string $port = ''): string {
    return 'https://' . rawurlencode($u) . ':' . rawurlencode($p)
        . "@$host" . ($port !== '' ? ":$port" : '');
};

rpAssert($mkLink('user', 'pass', 'np.example.com') === 'https://user:pass@np.example.com',
    'без relay порт не дописывается — клиент идёт на 443');
rpAssert($mkLink('user', 'pass', 'relay.example.com', Bot::relayPortInput('8443'))
    === 'https://user:pass@relay.example.com:8443', 'relay с портом');
rpAssert($mkLink('user', 'pass', 'relay.example.com', Bot::relayPortInput('0'))
    === 'https://user:pass@relay.example.com', 'очищенный np_port — порта в ссылке нет');
// Экранирование userinfo не должно потеряться при выносе ссылки в linkNaive().
rpAssert($mkLink('u', 'p@ss', 'h', '8443') === 'https://u:p%40ss@h:8443', '@ в пароле кодируется');
rpAssert($mkLink('u', 'a:b', 'h', '8443') === 'https://u:a%3Ab@h:8443',
    ': в пароле кодируется и не путается с портом');

// ── 5. TeleMT: порт в tg://proxy ────────────────────────────────────────────
$tg = fn(string $server, $port, string $secret) => 'tg://proxy?' . http_build_query([
    'server' => $server,
    'port'   => $port,
    'secret' => $secret,
], '', '&', PHP_QUERY_RFC3986);

$relay  = ['address' => 'relay.example.com', 'port' => '8443', 'portmap' => ['443' => '9443']];
$secret = 'eedeadbeef';
$link   = $tg($relay['address'], Bot::relayPort($relay, 443), $secret);
rpAssert(str_contains($link, 'port=8443'), 'явный порт telemt попадает в ссылку: ' . $link);
rpAssert(str_contains($link, 'server=relay.example.com'), 'сервер подменён на relay');
rpAssert(str_contains($link, "secret=$secret"), 'секрет и Fake-TLS домен не трогаются');

// ── 6. Имена relay в callback_data ──────────────────────────────────────────
// Новые колбэки принимают имя тем же классом символов, что и старые.
$cb = '~^/(?:setRelayHyPort|setRelayNpAddress|setRelayNpPort|setTelemtRelayPort|npRelaySub) (?P<a>[\w.\-]+)$~';
foreach (['my.relay-1', 'r_2', '10'] as $n) {
    rpAssert((bool) preg_match($cb, "/setRelayNpPort $n"), "имя relay принимается: $n");
}
rpAssert(!preg_match($cb, '/setRelayNpPort my relay'), 'пробел в имени не проходит');
// setRelayHyPort и setRelayHyPortMap — разные колбэки, якорь '$' обязателен.
rpAssert(!preg_match('~^/setRelayHyPort (?P<a>[\w.\-]+)$~', '/setRelayHyPortMap r'),
    '/setRelayHyPortMap не должен ловиться веткой /setRelayHyPort');
rpAssert(!preg_match('~^/setTelemtRelayPort (?P<a>[\w.\-]+)$~', '/setTelemtRelayPortMap r'),
    '/setTelemtRelayPortMap не должен ловиться веткой /setTelemtRelayPort');

echo $failed ? "\n$failed test(s) failed\n" : "OK\n";
exit($failed ? 1 : 0);
