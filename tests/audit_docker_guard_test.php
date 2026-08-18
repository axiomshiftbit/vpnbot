<?php

// Гейт docker-сети (ensureWgGuard) после аудита 2026-08-18.
//
// До аудита правило `block 10.10.0.0/16` вешалось только на внутренние
// socks-inbound'ы (wg-in/socks-in), то есть закрывало боковое движение
// клиентам wg/awg и оставляло его открытым основному клиентскому inbound'у
// (vless/vmess/trojan). Любой обладатель подписки доходил до control API unit
// (10.10.0.7:8080, без аутентификации, приложения от root), до веб-панели и до
// sshd контейнеров. Здесь проверяется, что гейт покрывает ВСЕ inbound'ы
// конфига, кроме служебного 'api', и что старые узкие копии снимаются.

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function guardAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

$bot = (new ReflectionClass(Bot::class))->newInstanceWithoutConstructor();

// Конфиг «как на боевом хосте»: клиентский vless, внутренний socks для wg,
// служебный api и пользовательское правило маршрутизации.
$mk = static fn(array $tags, array $rules = []) => [
    'inbounds'  => array_map(static fn($t) => ['tag' => $t], $tags),
    'outbounds' => [['protocol' => 'freedom', 'tag' => 'direct']],
    'routing'   => ['rules' => $rules ?: [
        ['type' => 'field', 'outboundTag' => 'warp', 'domain' => ['example.com']],
    ]],
];

// ── 1. Клиентский inbound покрыт гейтом ─────────────────────────────────────
$c = $mk(['vless_tls', 'wg-in', 'api']);
$bot->ensureWgGuard($c);
$r = $c['routing']['rules'];

guardAssert(($r[0]['ip'] ?? null) === [Bot::INTERNAL_DNS] && ($r[0]['port'] ?? '') === '53'
    && ($r[0]['outboundTag'] ?? '') === 'direct',
    'первым идёт allow внутреннего DNS');
guardAssert(($r[1]['ip'] ?? null) === [Bot::DOCKER_NET] && ($r[1]['outboundTag'] ?? '') === 'block',
    'вторым — блок docker-сети');
guardAssert(in_array('vless_tls', $r[1]['inboundTag'] ?? [], true),
    'ГЛАВНОЕ: клиентский inbound vless_tls закрыт от docker-сети');
guardAssert(in_array('wg-in', $r[1]['inboundTag'] ?? [], true),
    'внутренний socks клиентов wg остался закрыт');
guardAssert(!in_array('api', $r[1]['inboundTag'] ?? [], true),
    'служебный api-inbound гейтом не трогается');
guardAssert(($r[0]['inboundTag'] ?? null) === ($r[1]['inboundTag'] ?? null),
    'allow и block навешаны на один и тот же набор тегов');
guardAssert(($r[2]['domain'] ?? null) === ['example.com'],
    'пользовательское правило сохранено и ушло вниз');
guardAssert(in_array('block', array_column($c['outbounds'], 'tag'), true),
    'blackhole-outbound добавлен: правило на несуществующий тег молча теряет смысл');

// ── 2. Идемпотентность ──────────────────────────────────────────────────────
$before = count($c['routing']['rules']);
$bot->ensureWgGuard($c);
guardAssert(count($c['routing']['rules']) === $before, 'повторный вызов не дублирует правила');
guardAssert(count(array_filter($c['outbounds'], static fn($o) => ($o['tag'] ?? '') === 'block')) === 1,
    'повторный вызов не дублирует outbound');

// ── 3. Старая узкая копия гейта снимается ───────────────────────────────────
// Ровно то, что лежит сейчас на боевых хостах: гейт только на wg-in.
$legacy = $mk(['vless_tls', 'wg-in'], [
    ['type' => 'field', 'inboundTag' => ['wg-in'], 'ip' => [Bot::INTERNAL_DNS],
        'port' => '53', 'outboundTag' => 'direct'],
    ['type' => 'field', 'inboundTag' => ['wg-in'], 'ip' => [Bot::DOCKER_NET],
        'outboundTag' => 'block'],
    ['type' => 'field', 'outboundTag' => 'warp', 'domain' => ['example.com']],
]);
$bot->ensureWgGuard($legacy);
$guards = array_values(array_filter($legacy['routing']['rules'],
    static fn($r) => ($r['ip'] ?? null) === [Bot::DOCKER_NET] || ($r['ip'] ?? null) === [Bot::INTERNAL_DNS]));
guardAssert(count($guards) === 2, 'старая узкая копия снята, а не оставлена дублем');
guardAssert(in_array('vless_tls', $guards[1]['inboundTag'] ?? [], true),
    'гейт перевыставлен на полный набор тегов');

// ── 4. Гейт восстанавливается после xrayUpdateRules ─────────────────────────
// Тот перезаписывает routing.rules целиком; гейт обязан снова оказаться первым.
$c['routing']['rules'] = [['type' => 'field', 'outboundTag' => 'warp', 'ip' => ['1.1.1.1']]];
$bot->ensureWgGuard($c);
guardAssert(($c['routing']['rules'][0]['ip'] ?? null) === [Bot::INTERNAL_DNS],
    'после перезаписи правил гейт снова впереди пользовательских');

// ── 5. Вырожденные конфиги ──────────────────────────────────────────────────
$empty = $mk([]);
$bot->ensureWgGuard($empty);
guardAssert(count($empty['routing']['rules']) === 1,
    'без inbound\'ов гейт не добавляется (правило на несуществующий тег бесполезно)');

$onlyApi = $mk(['api']);
$bot->ensureWgGuard($onlyApi);
guardAssert(count($onlyApi['routing']['rules']) === 1,
    'конфиг из одного служебного api-inbound гейта не получает');

$noTag = $mk([]);
$noTag['inbounds'] = [['protocol' => 'vless']]; // inbound без tag
$bot->ensureWgGuard($noTag);
guardAssert(count($noTag['routing']['rules']) === 1,
    'безымянный inbound не порождает правило с пустым inboundTag');

// ── 6. Чужие правила про ту же подсеть не съедаются ─────────────────────────
// Снятие старых копий опознаёт гейт по полной сигнатуре (ip + outboundTag),
// поэтому админское правило с другим назначением обязано уцелеть.
$custom = $mk(['vless_tls'], [
    ['type' => 'field', 'inboundTag' => ['vless_tls'], 'ip' => [Bot::DOCKER_NET], 'outboundTag' => 'warp'],
]);
$bot->ensureWgGuard($custom);
guardAssert((bool) array_filter($custom['routing']['rules'],
    static fn($r) => ($r['ip'] ?? null) === [Bot::DOCKER_NET] && ($r['outboundTag'] ?? '') === 'warp'),
    'пользовательское правило про docker-сеть с другим outbound сохранено');

if ($failed) {
    echo "audit_docker_guard_test FAILED ($failed)\n";
    exit(1);
}
echo "audit_docker_guard_test OK\n";
