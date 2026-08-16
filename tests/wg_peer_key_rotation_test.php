<?php

// Массовая ротация ключей клиентов WG/AWG (applyRotatedPeerKeys/
// remapVlessAwgLinks — чистые функции, ssh/сеть тут не нужны).
//
// Инварианты, нарушение которых стоит дорого и не видно глазом:
//  1. Сопоставление clients[] ↔ серверных peers[] — по адресу
//     (peerIndexByClient), а не по общему индексу: не тот клиент не должен
//     получить чужой публичный ключ на сервере.
//  2. Клиент без пира на сервере пропускается ЦЕЛИКОМ — его локальный
//     PrivateKey НЕ меняется тоже (иначе он указывал бы на пира, которого
//     на сервере нет вовсе — хуже, чем оставить как было).
//  3. Выключенный пир хранит поля с префиксом "# " (switchClient()) — новый
//     ключ обязан лечь под тем же префиксом, никогда не создавая рядом и
//     PublicKey, и # PublicKey (иначе createConfig() теряет заголовок
//     секции [Peer]/# [Peer]).
//  4. PresharedKey — только когда явно передан (amnezia); для обычного WG
//     поле нигде не создаётся, даже если что-то было раньше.
//  5. Ротация PrivateKey рвёт привязку к VLESS-клиенту (xray.json 'awg' —
//     сырое значение PrivateKey) — remapVlessAwgLinks() обязана её чинить.

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function wgkAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

// 44-символьный base64 с завершающим "=" — та же форма, что проверяет
// presharedKey() (^[A-Za-z0-9+/]{43}=$) для настоящих wg genkey/genpsk.
function fakeKey(string $seed): string
{
    return substr(str_pad($seed, 43, 'X'), 0, 43) . '=';
}

$bot = (new ReflectionClass(Bot::class))->newInstanceWithoutConstructor();

// ── формат сгенерированной пары (сверка с форматом presharedKey()) ─────────
$re = '~^[A-Za-z0-9+/]{43}=$~';
wgkAssert((bool) preg_match($re, fakeKey('priv0')), 'fakeKey() даёт форму настоящего wg-ключа');
wgkAssert(strlen(fakeKey('x')) === 44, 'длина ключа — 44 символа, как у genkey/genpsk');

// ── фикстуры: 2 обычных клиента + 1 выключенный + 1 сирота ─────────────────
function mkClients(): array
{
    return [
        0 => ['interface' => ['PrivateKey' => fakeKey('old0'), 'Address' => '10.0.1.2/32'],
              'peers'     => [['PublicKey' => 'server-pub', 'AllowedIPs' => '0.0.0.0/0', 'PersistentKeepalive' => 20]]],
        1 => ['interface' => ['PrivateKey' => fakeKey('old1'), 'Address' => '10.0.1.3/32'],
              'peers'     => [['PublicKey' => 'server-pub', 'AllowedIPs' => '0.0.0.0/0', 'PersistentKeepalive' => 20]]],
        2 => ['interface' => ['PrivateKey' => fakeKey('old2'), 'Address' => '10.0.1.4/32'], // выключен
              'peers'     => [['PublicKey' => 'server-pub', 'AllowedIPs' => '0.0.0.0/0', 'PersistentKeepalive' => 20]]],
        3 => ['interface' => ['PrivateKey' => fakeKey('old3'), 'Address' => '10.0.1.99/32'], // сирота — нет пира на сервере
              'peers'     => [['PublicKey' => 'server-pub', 'AllowedIPs' => '0.0.0.0/0', 'PersistentKeepalive' => 20]]],
    ];
}

function mkConf(): array
{
    return ['peers' => [
        ['PublicKey' => fakeKey('pub0'), 'AllowedIPs' => '10.0.1.2/32', '## name' => 'first'],
        ['PublicKey' => fakeKey('pub1'), 'AllowedIPs' => '10.0.1.3/32', '## name' => 'second'],
        ['# PublicKey' => fakeKey('pub2'), '# AllowedIPs' => '10.0.1.4/32', '# ## name' => 'third'], // выключен
        // 10.0.1.99/32 (клиент #3) на сервере отсутствует вовсе — сирота.
    ]];
}

function pairs(int $n): array
{
    $p = [];
    for ($i = 0; $i < $n; $i++) {
        $p[] = [fakeKey("new{$i}p"), fakeKey("new{$i}u")];
    }

    return $p;
}

// ── 1. счастливый путь, обычный WG (psk = null) ─────────────────────────────
$clients = mkClients();
$conf    = mkConf();
$r = $bot->applyRotatedPeerKeys($clients, $conf, pairs(4), null);
wgkAssert($r['rotated'] === 3, 'rotated=3 (клиент #3 — сирота, пира на сервере нет)');
wgkAssert($r['skipped'] === 1, 'skipped=1');
wgkAssert($r['clients'][0]['interface']['PrivateKey'] === fakeKey('new0p'), 'клиент #0: новый приватный ключ');
wgkAssert($r['conf']['peers'][0]['PublicKey'] === fakeKey('new0u'), 'сервер: новый публичный ключ пира #0');
wgkAssert(!isset($r['clients'][0]['peers'][0]['PresharedKey']), 'plain WG: PresharedKey не создаётся у клиента');
wgkAssert(!isset($r['conf']['peers'][0]['PresharedKey']), 'plain WG: PresharedKey не создаётся у серверного пира');

// ── 2. счастливый путь, AWG (psk задан) ─────────────────────────────────────
$clients2 = mkClients();
$conf2    = mkConf();
$psk      = fakeKey('newpsk');
$r2 = $bot->applyRotatedPeerKeys($clients2, $conf2, pairs(4), $psk);
wgkAssert($r2['clients'][0]['peers'][0]['PresharedKey'] === $psk, 'AWG: PresharedKey обновлён у клиента');
wgkAssert($r2['conf']['peers'][0]['PresharedKey'] === $psk, 'AWG: PresharedKey обновлён у серверного пира (включён)');

// ── 3. выключенный пир — новый ключ под "# PublicKey" ───────────────────────
wgkAssert(array_key_exists('# PublicKey', $r2['conf']['peers'][2]), 'выключенный пир остаётся выключенным (# PublicKey)');
wgkAssert($r2['conf']['peers'][2]['# PublicKey'] === fakeKey('new2u'), 'новый публичный ключ ушёл именно под # PublicKey');
wgkAssert(!array_key_exists('PublicKey', $r2['conf']['peers'][2]), 'рядом НЕ появился голый PublicKey');
wgkAssert($r2['conf']['peers'][2]['# PresharedKey'] === $psk, 'у выключенного пира PresharedKey тоже под префиксом #');
wgkAssert(!array_key_exists('PresharedKey', $r2['conf']['peers'][2]), 'и тут без голого PresharedKey рядом');

// ── 4. сирота — PrivateKey не меняется вовсе ────────────────────────────────
wgkAssert($r2['clients'][3]['interface']['PrivateKey'] === fakeKey('old3'), 'клиент-сирота: приватный ключ остался прежним');

// ── 5. psk=null — поле нигде не создаётся, даже если раньше не было ────────
$clientsNoPsk = mkClients();
$confNoPsk    = mkConf();
$r5 = $bot->applyRotatedPeerKeys($clientsNoPsk, $confNoPsk, pairs(4), null);
foreach ($r5['clients'] as $c) {
    wgkAssert(!isset($c['peers'][0]['PresharedKey']), 'psk=null: ни у одного клиента нет PresharedKey');
}
foreach ($r5['conf']['peers'] as $p) {
    wgkAssert(!isset($p['PresharedKey']) && !isset($p['# PresharedKey']), 'psk=null: ни у одного серверного пира нет PresharedKey');
}

// ── 6. независимость по клиентам в смешанном батче ──────────────────────────
// Сирота (#3) идёт ПОСЛЕ выключенного (#2) в исходном массиве — проверяем,
// что пропуск сироты не сбивает пары ключей для последующих клиентов (тут
// сирота последняя, так что даём тот же набор, но с сиротой в середине).
$mixed = [
    0 => mkClients()[0],
    1 => mkClients()[3], // сирота — вставлена в середину
    2 => mkClients()[1],
];
$confMixed = mkConf();
$r6 = $bot->applyRotatedPeerKeys($mixed, $confMixed, pairs(3), null);
wgkAssert($r6['rotated'] === 2 && $r6['skipped'] === 1, 'сирота в середине списка: rotated=2, skipped=1');
wgkAssert($r6['clients'][0]['interface']['PrivateKey'] === fakeKey('new0p'), 'клиент #0 (до сироты) получил свою пару');
wgkAssert($r6['clients'][1]['interface']['PrivateKey'] === fakeKey('old3'), 'сирота осталась нетронутой');
wgkAssert($r6['clients'][2]['interface']['PrivateKey'] === fakeKey('new2p'),
    'клиент ПОСЛЕ сироты получил СВОЮ пару (new2*), не пару сироты (new1*) — сирота не потребляет чужую пару');

// ── 7. remapVlessAwgLinks() ──────────────────────────────────────────────────
$oldToNew = ['OLD-PRIV-0' => 'NEW-PRIV-0', 'OLD-PRIV-1' => 'NEW-PRIV-1'];
$xr = ['inbounds' => [['settings' => ['clients' => [
    ['email' => 'a', 'awg' => 'OLD-PRIV-0'],
    ['email' => 'b'], // без vless-линка вовсе
    ['email' => 'c', 'awg' => 'OLD-PRIV-1'],
    ['email' => 'd', 'awg' => 'SOME-OTHER-UNRELATED-KEY'],
]]]]];
$xr2 = $bot->remapVlessAwgLinks($xr, $oldToNew);
wgkAssert($xr2['inbounds'][0]['settings']['clients'][0]['awg'] === 'NEW-PRIV-0', 'awg-ссылка клиента a переписана');
wgkAssert(!isset($xr2['inbounds'][0]['settings']['clients'][1]['awg']), 'клиент b без ссылки остался без неё');
wgkAssert($xr2['inbounds'][0]['settings']['clients'][2]['awg'] === 'NEW-PRIV-1', 'awg-ссылка клиента c переписана');
wgkAssert($xr2['inbounds'][0]['settings']['clients'][3]['awg'] === 'SOME-OTHER-UNRELATED-KEY',
    'несвязанная awg-ссылка клиента d не тронута');
// Пустая карта / отсутствие clients — не должно падать.
wgkAssert($bot->remapVlessAwgLinks($xr, []) === $xr, 'пустая карта — конфиг не меняется');
wgkAssert($bot->remapVlessAwgLinks(['inbounds' => [['settings' => []]]], $oldToNew) === ['inbounds' => [['settings' => []]]],
    'нет clients вовсе — не падает, конфиг как есть');

if ($failed) {
    echo "wg_peer_key_rotation_test FAILED: $failed\n";
    exit(1);
}
echo "wg_peer_key_rotation_test OK\n";
