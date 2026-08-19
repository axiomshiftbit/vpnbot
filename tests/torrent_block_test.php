<?php

// Блокировка торрентов для клиентов xray (routing protocol: bittorrent).
//
// Что здесь дорого сломать и глазом не видно:
//
//  1. Правило обязано стоять ВЫШЕ пользовательских маршрутов (warp/direct по
//     спискам) — xray берёт первое совпавшее, и правило в хвосте не сработает
//     ни разу, а меню будет показывать «включено».
//  2. И одновременно НИЖЕ гейтов ensureWgGuard() (DNS :53 → direct): порядок
//     задаётся тем, что ensureTorrentBlock() зовут ПЕРЕД ensureWgGuard().
//  3. inboundTag — только клиентские inbound'ы. Попади туда wg-in, и один
//     тумблер молча зарезал бы торренты WG/AWG-клиентам, у которых свой
//     (block_torrent.sh).
//  4. outboundTag: 'block' обязан существовать в outbounds — правило с
//     несуществующим тегом xray игнорирует, и трафик уходит НАРУЖУ.
//  5. Повторные вызовы не должны копить дубли: restartXray() зовёт
//     ensureTorrentBlock() на каждом рестарте.
//  6. Матчинг по protocol работает только при sniffing.enabled и
//     metadataOnly=false — иначе ядро не заполняет content.Protocol.
//  7. Полное покрытие (uTP, DHT, UDP-трекеры) есть только в форк-ядре с
//     v26.8.21 — пин в .env не должен уехать ниже.

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function tbAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

$bot = (new ReflectionClass(Bot::class))->newInstanceWithoutConstructor();

// Конфиг образца: клиентский inbound + служебные api/wg-in + пользовательское
// правило маршрутизации, которое обязано остаться ПОД правилом торрентов.
function tbXray(): array
{
    return [
        'inbounds' => [
            ['tag' => 'vless_tls', 'protocol' => 'vless', 'settings' => ['clients' => [['id' => 'x']]]],
            ['tag' => 'api',       'protocol' => 'dokodemo-door', 'settings' => ['address' => '127.0.0.1']],
            ['tag' => 'wg-in',     'protocol' => 'socks', 'settings' => ['auth' => 'noauth']],
        ],
        'outbounds' => [
            ['protocol' => 'freedom', 'tag' => 'direct'],
        ],
        'routing' => ['rules' => [
            ['type' => 'field', 'outboundTag' => 'warp', 'domain' => ['geosite:openai']],
        ]],
    ];
}

$ruleOf = function (array $c): ?array {
    foreach (($c['routing']['rules'] ?? []) as $r) {
        if ((array) ($r['protocol'] ?? []) === ['bittorrent']) {
            return $r;
        }
    }
    return null;
};

// ── выключено: правила нет, чужие правила целы ───────────────────────────────
$c = tbXray();
$bot->ensureTorrentBlock($c, []);
tbAssert($ruleOf($c) === null, 'тумблер выключен — правила bittorrent быть не должно');
tbAssert(count($c['routing']['rules']) === 1, 'выключенный тумблер не трогает чужие правила');

// ── включено: форма правила ──────────────────────────────────────────────────
$c = tbXray();
$bot->ensureTorrentBlock($c, ['xray_blocktorrent' => 1]);
$r = $ruleOf($c);
tbAssert($r !== null, 'тумблер включён — правило bittorrent обязано появиться');
tbAssert(($r['outboundTag'] ?? '') === 'block', 'правило ведёт в blackhole (block)');
tbAssert(($r['type'] ?? '') === 'field', 'type=field: других xray не понимает');
tbAssert(($c['routing']['rules'][0]['protocol'] ?? null) === ['bittorrent'],
    'правило стоит ПЕРВЫМ — иначе пользовательские маршруты совпадут раньше');
tbAssert(($r['inboundTag'] ?? []) === ['vless_tls'],
    'inboundTag — только клиентские inbound\'ы: ' . json_encode($r['inboundTag'] ?? []));
tbAssert(!in_array('wg-in', (array) ($r['inboundTag'] ?? []), true),
    'wg-in в inboundTag: тумблер xray зарезал бы торренты WG-клиентам');
tbAssert(!in_array('api', (array) ($r['inboundTag'] ?? []), true), 'api в inboundTag не место');

$hasBlock = false;
foreach ($c['outbounds'] as $o) {
    $hasBlock = $hasBlock || ($o['tag'] ?? '') === 'block';
}
tbAssert($hasBlock, 'blackhole-аутбаунд block дописан: правило с чужим тегом xray игнорирует');
// Чужие аутбаунды на месте.
tbAssert(($c['outbounds'][0]['tag'] ?? '') === 'direct', 'существующие outbounds не переписаны');

// ── идемпотентность: рестарты не копят дубли ─────────────────────────────────
for ($i = 0; $i < 3; $i++) {
    $bot->ensureTorrentBlock($c, ['xray_blocktorrent' => 1]);
}
$n = 0;
foreach ($c['routing']['rules'] as $rr) {
    $n += (int) ((array) ($rr['protocol'] ?? []) === ['bittorrent']);
}
tbAssert($n === 1, "правило bittorrent размножилось: $n копий");
$nb = 0;
foreach ($c['outbounds'] as $o) {
    $nb += (int) (($o['tag'] ?? '') === 'block');
}
tbAssert($nb === 1, "blackhole размножился: $nb копий");

// ── выключение снимает правило, даже если тег inbound'а сменился ─────────────
$c['routing']['rules'][0]['inboundTag'] = ['vless_ws'];   // как после changeTransport
$bot->ensureTorrentBlock($c, ['xray_blocktorrent' => 0]);
tbAssert($ruleOf($c) === null, 'выключение снимает правило по сигнатуре, а не по тегам');
tbAssert(count($c['routing']['rules']) === 1, 'чужое правило пережило снятие');

// ── порядок относительно гейтов wg (как в restartXray) ──────────────────────
$c = tbXray();
$bot->ensureTorrentBlock($c, ['xray_blocktorrent' => 1]);
$bot->ensureWgGuard($c);
$rules = $c['routing']['rules'];
$idxT = $idxDns = null;
foreach ($rules as $k => $rr) {
    if ((array) ($rr['protocol'] ?? []) === ['bittorrent']) {
        $idxT = $k;
    }
    if ((string) ($rr['port'] ?? '') === '53' && ($rr['outboundTag'] ?? '') === 'direct') {
        $idxDns = $k;
    }
}
tbAssert($idxT !== null && $idxDns !== null, 'после гейтов на месте оба правила');
tbAssert($idxDns < $idxT, 'DNS-гейт обязан стоять ВЫШЕ правила торрентов');
$idxUser = null;
foreach ($rules as $k => $rr) {
    if (($rr['outboundTag'] ?? '') === 'warp') {
        $idxUser = $k;
    }
}
tbAssert($idxT < $idxUser, 'правило торрентов обязано стоять ВЫШЕ пользовательских маршрутов');

// ── ensureTorrentBlock зовут раньше ensureWgGuard (порядок в restartXray) ────
$src = file_get_contents(__DIR__ . '/../app/bot.php');
$posT = strpos($src, '$this->ensureTorrentBlock($c, $pac);');
$posG = strpos($src, '$this->ensureWgGuard($c);');
tbAssert($posT !== false && $posG !== false && $posT < $posG,
    'в restartXray() ensureTorrentBlock обязан идти ДО ensureWgGuard');

// ── пригодность: без sniffing правило мертво ────────────────────────────────
// Настройка из pac главнее: она уедет в xray.json на ближайшем рестарте.
$xr = fn (?array $s) => ['inbounds' => [
    ['tag' => 'vless_tls', 'settings' => ['clients' => [['id' => 'x']]]] + ($s === null ? [] : ['sniffing' => $s]),
]];
tbAssert($bot->xrayTorrentReady(['sniffing' => ['enabled' => true]], $xr(['enabled' => false])),
    'sniffing включён в pac — правило рабочее (конфиг догонит на рестарте)');
tbAssert(!$bot->xrayTorrentReady(['sniffing' => ['enabled' => false]], $xr(['enabled' => true])),
    'sniffing выключен в pac — ядро не заполняет content.Protocol');
tbAssert(!$bot->xrayTorrentReady(['sniffing' => ['enabled' => true, 'metadataOnly' => true]], $xr(['enabled' => true])),
    'metadataOnly отключает разбор содержимого — протокол не определится');

// Ключа в pac нет вовсе — смотрим на фактический блок клиентского inbound'а,
// а НЕ на дефолт sniffingSettings(): иначе меню обещало бы работу фильтра на
// установке, где sniffing в xray.json не прописан.
tbAssert(!$bot->xrayTorrentReady([], $xr(null)),
    'sniffing нет ни в pac, ни в конфиге — фильтр обязан считаться неготовым');
tbAssert($bot->xrayTorrentReady([], $xr(['enabled' => true, 'destOverride' => ['http', 'tls', 'quic']])),
    'sniffing в конфиге включён — фильтр готов');
tbAssert(!$bot->xrayTorrentReady([], $xr(['enabled' => true, 'metadataOnly' => true])),
    'metadataOnly из конфига тоже обязан учитываться');
// Служебные inbound'ы не в счёт: sniffing wg-in ничего не говорит о клиентах.
tbAssert(!$bot->xrayTorrentReady([], ['inbounds' => [
    ['tag' => 'wg-in', 'sniffing' => ['enabled' => true]],
    ['tag' => 'vless_tls', 'settings' => ['clients' => [['id' => 'x']]]],
]]), 'sniffing на wg-in не делает фильтр готовым');

// ── нет тумблера в pac — нет и правила ──────────────────────────────────────
tbAssert(!$bot->xrayTorrentBlocked([]), 'свежая установка: торренты не режем');
tbAssert($bot->xrayTorrentBlocked(['xray_blocktorrent' => 1]), 'тумблер читается из pac');

// ── пин форк-ядра не ниже v26.8.21 ──────────────────────────────────────────
$env = (string) @file_get_contents(__DIR__ . '/../.env');
if (preg_match('~^XRAY_FORK_VERSION=v?(\d+)\.(\d+)\.(\d+)~m', $env, $m)) {
    $ver = sprintf('%04d%04d%04d', $m[1], $m[2], $m[3]);
    tbAssert($ver >= sprintf('%04d%04d%04d', 26, 8, 21),
        "XRAY_FORK_VERSION={$m[0]}: uTP/DHT/UDP-трекеры появились в v26.8.21");
} else {
    tbAssert(false, 'XRAY_FORK_VERSION в .env не найден');
}

if ($failed) {
    echo "torrent_block_test FAILED: $failed\n";
    exit(1);
}
echo "torrent_block_test OK\n";
