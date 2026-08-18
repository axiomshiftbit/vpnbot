<?php

// СРЕДНИЕ отчёта AUDIT-2026-08-18-05-vpn-configs.md.

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function vcAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

$json = static fn(string $p): array => json_decode((string) file_get_contents(__DIR__ . '/../' . $p), true) ?: [];
$text = static fn(string $p): string => (string) file_get_contents(__DIR__ . '/../' . $p);

// ── 1. Порядок правил: block раньше проксирования ───────────────────────────
// sing-box берёт ПЕРВОЕ совпавшее правило. Домен, попавший и в blocklist, и в
// includelist (типовой случай: рекламный поддомен внутри проксируемой зоны),
// в sing-box не блокировался, а проксировался — в mihomo и xray блокировался.
$sing  = $json('config/sing.json');
$names = [];
foreach ($sing['route']['rules'] as $r) {
    $names[] = ($r['createruleset'][0]['name'] ?? null) ?: ($r['outbound'] ?? $r['action'] ?? '');
}
$iBlock = array_search('block', $names, true);
vcAssert($iBlock !== false, 'block-ruleset на месте');
foreach (['direct', 'pac', 'subnet', 'package', 'process', 'warp'] as $after) {
    $i = array_search($after, $names, true);
    vcAssert($i === false || $iBlock < $i, "block стоит раньше «{$after}»");
}
// Хайджек DNS и sniff обязаны остаться выше блока.
vcAssert(array_search('hijack-dns', $names, true) < $iBlock, 'hijack-dns остался выше block');

// ── 2. Резолверы ────────────────────────────────────────────────────────────
$hy = $text('config/hysteria.yaml');
vcAssert(str_contains($hy, '10.10.0.5:53'),
    'hysteria резолвит через внутренний AdGuard, как остальные протоколы');
vcAssert(!preg_match('~addr: 1\.1\.1\.1:853~', $hy),
    'внешний резолвер Cloudflare убран: он получал полный DNS-профиль пользователей');

$ag = $text('config/AdGuardHome.yaml');
vcAssert(substr_count($ag, 'tls://') >= 2, 'апстримы AdGuard идут по DoT, а не открытым UDP/53');
vcAssert(!preg_match('~^\s+- 1\.1\.1\.1$~m', $ag), 'голых апстримов не осталось');

// ── 3. Бутстрап домена в clash-шаблонах ─────────────────────────────────────
// ~dns~ это https://<domain>/dns-query…, и чтобы им воспользоваться, mihomo
// сначала резолвит <domain> встроенным дефолтом (plain UDP) — маркер для DPI и
// точка для подмены. В sing-box-шаблонах это закрыто predefined-hosts.
foreach (['config/clash.json', 'templates/mihomo-warp.json'] as $p) {
    $c = $json($p);
    vcAssert(($c['dns']['hosts']['~domain~'] ?? '') === '~ip~',
        basename($p) . ': домен сервера резолвится из hosts, а не по сети');
}

// ── 4. Свой DoH замещает чужие резолверы ────────────────────────────────────
$src = (string) file_get_contents(__DIR__ . '/../app/bot.php');
$blk = substr($src, strpos($src, "if (isset(\$c['dns']['nameserver']))"), 2600);
vcAssert(str_contains($blk, "\$c['dns']['fallback']"),
    'прежние резолверы шаблона уезжают в fallback');
vcAssert(str_contains($blk, "\$c['dns']['nameserver'] = array_values(array_unique(\$own"),
    'в nameserver остаётся только свой DoH: mihomo опрашивает список параллельно и берёт первый ответ');

// ── 5. Права на конфиги с секретами ─────────────────────────────────────────
vcAssert(method_exists('Bot', 'chmodSecret'), 'есть общий хелпер прав на конфиги');
vcAssert(substr_count($src, 'chmodSecret(') >= 7,
    'права ставятся на xray.json, clients.json, ssserver.json, hysteria.yaml, ocserv.passwd');
// Окно в БАЙТАХ, комментарии кириллицей — по два байта на символ.
$wx = substr($src, strpos($src, 'public function writeXrayJson('), 4200);
vcAssert(str_contains($wx, 'chmodSecret($this->xrayConf)'),
    'xray.json (privateKey reality + все UUID) пишется с 0600');

// ── 6. Reality: подписи клиентов ────────────────────────────────────────────
$bot = (new ReflectionClass(Bot::class))->newInstanceWithoutConstructor();
$ids = $bot->realityShortIds('aabbccddeeff0011');
vcAssert(count($ids) >= 3, 'shortIds больше не единственный на всю установку: ' . count($ids));
vcAssert($ids[0] === 'aabbccddeeff0011', 'основной shortId остаётся первым');
foreach ($ids as $id) {
    vcAssert((bool) preg_match('~^[0-9a-f]{2,16}$~', $id) && strlen($id) % 2 === 0,
        "shortId валиден для xray (hex чётной длины ≤16): $id");
}
vcAssert(count(array_unique(array_map('strlen', $ids))) > 1, 'длины различаются');

$xr = ['inbounds' => [['streamSettings' => ['realitySettings' => ['shortIds' => $ids]]]]];
$got = [];
foreach (['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'] as $u) {
    $got[$u] = $bot->clientShortId($xr, "uuid-$u");
    vcAssert(in_array($got[$u], $ids, true), "клиенту выдан shortId из набора инбаунда ($u)");
}
vcAssert(count(array_unique($got)) > 1, 'разные клиенты получают разные shortId');
vcAssert($bot->clientShortId($xr, 'uuid-a') === $got['a'],
    'выдача детерминирована: иначе конфиг менялся бы на каждой выдаче подписки');
vcAssert($bot->clientShortId(['inbounds' => [[]]], 'uuid-a') === '',
    'конфиг без reality не роняет подстановку');

vcAssert(count(Bot::REALITY_FAKE_DOMAINS) > 1, 'дефолтный fake-домен выбирается из списка');
vcAssert(in_array($bot->defaultFakeDomain(), Bot::REALITY_FAKE_DOMAINS, true),
    'выбранный домен из списка');
vcAssert(!preg_match("~\\?: 'yandex\\.ru'~", $src),
    'захардкоженный yandex.ru как дефолт убран: узнаваемая подпись у каждой установки');

if ($failed) {
    echo "audit_vpn_configs_test FAILED ($failed)\n";
    exit(1);
}
echo "audit_vpn_configs_test OK\n";
