<?php

// finalmask fragment/noise на серверном xray-инбаунде (streamSettings.finalmask).
//
// В отличие от SMUX это фича самого апстрима XTLS/Xray-core (форк Jolymmiles/
// Xray-core её лишь наследует, идя впереди апстрима) — поэтому единственный
// инвариант, специфичный именно для нашей интеграции, это ОТСУТСТВИЕ гейта по
// xrayCore(): в отличие от smux, вывод ensureFinalmaskInbound() не должен
// зависеть от того, форк сейчас активен или апстрим.
//
// Остальные проверки — прямые инварианты Build()-валидации ядра
// (infra/conf/transport_finalmask.go, FragmentMask/NoiseMask), нарушение
// которых стоит дорого и не видно глазом: xray просто не поднимется на
// старте, и ни один тест выше по цепочке этого не заметит.
//
//  1. packets: числовой диапазон не может начинаться с 0 ("0-3" отвергается).
//  2. noise item несёт РОВНО одно из rand+randRange либо type+packet — никогда
//     оба сразу (Build() отвергает item, где Packet непуст И Rand.To > 0).
//  3. randRange обязан укладываться в 0..255.
//  4. ensureFinalmaskInbound(): точная форма JSON (только 'tcp'/'udp', только
//     'type'/'settings' в каждом элементе, type — буквально 'fragment'/'noise') —
//     опечатка в имени ключа/типа молча ломает маску, а не роняет конфиг.
//  5. enabled=0 после включения — ключ finalmask пропадает целиком (self-healing,
//     тот же приём, что ensureSmuxInbound()).

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function fmAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

// Конструктор Bot тянет токен/окружение — не нужен: все методы finalmask
// принимают pac-конфиг аргументом и в файлы не ходят.
$bot = (new ReflectionClass(Bot::class))->newInstanceWithoutConstructor();

// ── дефолты ───────────────────────────────────────────────────────────────
$d = Bot::finalmaskDefaults();
fmAssert($d['enabled'] === 0, 'finalmask выключен по умолчанию');
fmAssert($d['fragment']['packets'] === 'tlshello', 'дефолтный packets — tlshello, не диапазон с 0');
fmAssert($d['fragment']['maxSplit'] === '', 'maxSplit пуст по умолчанию — без лимита ядра');

$s = $bot->finalmaskSettings(['finalmask' => ['enabled' => 1]]);
fmAssert($s['enabled'] === 1, 'finalmaskSettings() сохраняет заданное значение');
fmAssert($s['fragment']['packets'] === 'tlshello', 'finalmaskSettings() подставляет дефолты во вложенный fragment');
fmAssert($s['noise']['reset'] === '5-10', 'finalmaskSettings() подставляет дефолты во вложенный noise');

// ── packets: числовой диапазон не может начинаться с 0 ──────────────────────
$frag = $bot->finalmaskFragmentSettings(['packets' => '0-3', 'length' => '10-20', 'delay' => '5-10']);
fmAssert($frag['packets'] === '1-3', "packets='0-3' клэмпится в '1-3', а не уезжает как есть (было: {$frag['packets']})");

$frag2 = $bot->finalmaskFragmentSettings(['packets' => '0']);
fmAssert($frag2['packets'] === 'tlshello', "packets='0' откатывается на tlshello (было: {$frag2['packets']})");

$frag3 = $bot->finalmaskFragmentSettings(['packets' => '2-5']);
fmAssert($frag3['packets'] === '2-5', 'валидный диапазон (from>=1) проходит без изменений');

fmAssert(!isset($bot->finalmaskFragmentSettings(['packets' => 'tlshello'])['maxSplit']), 'пустой maxSplit не эмитится вовсе');
fmAssert($bot->finalmaskFragmentSettings(['maxSplit' => '4-8'])['maxSplit'] === '4-8', 'заданный maxSplit эмитится как есть');

// ── noise: item несёт ровно одно из rand+randRange либо type+packet ────────
$ns = $bot->finalmaskNoiseSettings([], [
    ['type' => 'rand', 'packet' => '10-20', 'delay' => '10-16'],
]);
$item = $ns['noise'][0];
fmAssert(isset($item['rand'], $item['randRange']) && !isset($item['packet'], $item['type']),
    'type=rand эмитит rand+randRange, без packet/type');
fmAssert($item['rand'] === '10-20', 'значение из packet переезжает в rand для типа rand');
fmAssert($item['randRange'] === '0-255', 'randRange фиксирован в допустимых границах 0..255');

$ns2 = $bot->finalmaskNoiseSettings([], [
    ['type' => 'hex', 'packet' => 'deadbeef', 'delay' => '10-16'],
]);
$item2 = $ns2['noise'][0];
fmAssert(isset($item2['type'], $item2['packet']) && !isset($item2['rand'], $item2['randRange']),
    'type=hex эмитит type+packet, без rand/randRange');

// str/hex/base64 без пакета ядро отвергает — пропускаем, как и applyDpiFragment().
$ns3 = $bot->finalmaskNoiseSettings([], [
    ['type' => 'hex', 'packet' => '', 'delay' => '10-16'],
]);
fmAssert(count($ns3['noise']) === 1 && $ns3['noise'][0]['rand'] === '10-20',
    'пустой packet у str/hex/base64 пропускается, список не остаётся пустым (фолбэк на rand)');

fmAssert($bot->finalmaskNoiseSettings(['reset' => '3-7'], [])['reset'] === '3-7', 'reset берётся из настроек как есть');
fmAssert($bot->finalmaskNoiseSettings([], [])['reset'] === '5-10', 'пустой reset — дефолт 5-10');

// ── ensureFinalmaskInbound(): точная форма JSON ──────────────────────────────
function fmXray(): array
{
    return ['inbounds' => [['streamSettings' => ['network' => 'ws']]]];
}

$pacBoth = [
    'finalmask' => [
        'enabled'  => 1,
        'fragment' => ['enabled' => 1, 'packets' => 'tlshello', 'length' => '100-200', 'delay' => '10-20'],
        'noise'    => ['enabled' => 1, 'reset' => '5-10', 'list' => [['type' => 'rand', 'packet' => '10-20', 'delay' => '10-16']]],
    ],
];
$c = fmXray();
$bot->ensureFinalmaskInbound($c, $pacBoth);
$fm = $c['inbounds'][0]['streamSettings']['finalmask'] ?? null;
fmAssert(is_array($fm), 'finalmask появляется в streamSettings при enabled+fragment+noise');
fmAssert(array_keys($fm) === ['tcp', 'udp'], 'ровно tcp и udp, в этом порядке, ничего лишнего');
fmAssert(array_keys($fm['tcp'][0]) === ['type', 'settings'], 'tcp[0] — ровно type+settings');
fmAssert($fm['tcp'][0]['type'] === 'fragment', "tcp[0].type буквально 'fragment' (было: {$fm['tcp'][0]['type']})");
fmAssert(array_keys($fm['udp'][0]) === ['type', 'settings'], 'udp[0] — ровно type+settings');
fmAssert($fm['udp'][0]['type'] === 'noise', "udp[0].type буквально 'noise' (было: {$fm['udp'][0]['type']})");

// Только fragment — udp не эмитится вовсе, не пустым массивом.
$pacFragOnly = $pacBoth;
$pacFragOnly['finalmask']['noise']['enabled'] = 0;
$c2 = fmXray();
$bot->ensureFinalmaskInbound($c2, $pacFragOnly);
fmAssert(array_keys($c2['inbounds'][0]['streamSettings']['finalmask']) === ['tcp'], 'только fragment включён — udp-ключа нет вовсе');

// ── enabled=0 → ключ пропадает целиком (self-healing) ────────────────────────
$pacOff = $pacBoth;
$pacOff['finalmask']['enabled'] = 0;
$c3 = fmXray();
$c3['inbounds'][0]['streamSettings']['finalmask'] = ['tcp' => [['type' => 'fragment', 'settings' => []]]]; // как будто уже было
$bot->ensureFinalmaskInbound($c3, $pacOff);
fmAssert(!isset($c3['inbounds'][0]['streamSettings']['finalmask']), 'enabled=0 убирает ключ finalmask целиком, даже если он уже был');

$pacNothing = ['finalmask' => ['enabled' => 1, 'fragment' => ['enabled' => 0], 'noise' => ['enabled' => 0]]];
$c4 = fmXray();
$bot->ensureFinalmaskInbound($c4, $pacNothing);
fmAssert(!isset($c4['inbounds'][0]['streamSettings']['finalmask']), 'enabled=1, но fragment и noise оба выключены — собирать нечего, ключа нет');

// ── регрессия: никакого гейта по xrayCore(), в отличие от SMUX ──────────────
$pacFork = $pacBoth;
$pacFork['xray_core'] = 'fork';
$pacOrigin = $pacBoth;
$pacOrigin['xray_core'] = 'origin';
$cFork = fmXray();
$cOrigin = fmXray();
$bot->ensureFinalmaskInbound($cFork, $pacFork);
$bot->ensureFinalmaskInbound($cOrigin, $pacOrigin);
fmAssert(
    $cFork['inbounds'][0]['streamSettings']['finalmask'] === $cOrigin['inbounds'][0]['streamSettings']['finalmask'],
    'вывод не зависит от xray_core (fork/origin дают одинаковый результат) — finalmask не форк-эксклюзив'
);

if ($failed) {
    echo "finalmask_test FAILED: $failed\n";
    exit(1);
}
echo "finalmask_test OK\n";
