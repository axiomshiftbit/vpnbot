<?php

// AmneziaWG 3.1: RandomTrailers/DisableCookies (amneziawg-tools >= v3.1.20260812,
// amneziawg-go >= v3.1.20260814 — до этого тега в go паника рантайма при включённом
// RandomTrailers, см. dockerfile/wireguard.dockerfile). Отдельный массив AWG_KEYS_31
// и отдельный порог версии awgSupports31() — старые tools 3.0.x отвергают ВЕСЬ
// wg0.conf на незнакомой строке («Line unrecognized»), значит срез 3.1 обязан быть
// независим от среза 3.0: поле одной эпохи не должно задевать поля другой.
// mihomo (>= v1.19.30) объявляет random-trailers/disable-cookies как bool, а не как
// строку/число (как остальные 3.0-поля) — отдельная проверка сериализации.

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function awg31Assert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

// awgToolsVersion()/getPacConf() подменены — остальное чистое, ssh не нужен.
class Awg31TestBot extends Bot
{
    public ?string $fakeToolsVer = null;
    public array $fakeConf = [];

    public function awgToolsVersion(bool $force = false): ?string
    {
        return $this->fakeToolsVer;
    }

    public function getPacConf()
    {
        return $this->fakeConf;
    }
}

$bot = (new ReflectionClass(Awg31TestBot::class))->newInstanceWithoutConstructor();

// ── 1. awgKeyNames(): AWG_KEYS_31 в default-объединении и в case 4 ──────────────
awg31Assert(
    array_values(Bot::AWG_KEYS_31) === Bot::awgKeyNames(4),
    'awgKeyNames(4) должен вернуть ровно AWG_KEYS_31'
);
foreach (Bot::AWG_KEYS_31 as $k) {
    awg31Assert(in_array($k, Bot::awgKeyNames(0), true), "awgKeyNames(0): нет $k из AWG_KEYS_31");
}
// Полнота: объединение всех версий-срезов должно давать ровно то же множество, что
// awgKeyNames(0) — если кто-то добавит AWG_KEYS_4 и забудет завести под него case/merge,
// эта проверка не поймает регресс сама по себе, но ловит обратную ошибку — забытый ключ
// в default при заведённом case.
$union = array_merge(Bot::AWG_KEYS_1, Bot::AWG_KEYS_2, Bot::AWG_KEYS_3, Bot::AWG_KEYS_31);
awg31Assert($union === Bot::awgKeyNames(0), 'awgKeyNames(0) разошёлся с ручным array_merge всех версий');

// ── 2. amneziaKeysUsable(): срез 3.1 независим от среза 3.0 ─────────────────────
$full = array_fill_keys(array_merge(Bot::AWG_KEYS_3, Bot::AWG_KEYS_31), 'x');
// S1..S4 нужны >= 12 для awgHeaderProtectionOk(), иначе HeaderProtectionKey срежется
// по другой причине и тест перестанет проверять то, что должен.
$full = array_merge($full, ['S1' => 20, 'S2' => 76, 'S3' => 48, 'S4' => 52]);

foreach ([[false, false], [false, true], [false, null], [true, false], [null, false]] as [$s3, $s31]) {
    $u = Bot::amneziaKeysUsable($full, $s3, $s31);
    foreach (Bot::AWG_KEYS_3 as $k) {
        $expect = $s3 !== false;
        awg31Assert(isset($u[$k]) === $expect, "usable(sup3=" . var_export($s3, true) . ", sup31=" . var_export($s31, true) . "): $k ожидался " . ($expect ? 'сохранён' : 'срезан'));
    }
    foreach (Bot::AWG_KEYS_31 as $k) {
        $expect = $s31 !== false;
        awg31Assert(isset($u[$k]) === $expect, "usable(sup3=" . var_export($s3, true) . ", sup31=" . var_export($s31, true) . "): $k ожидался " . ($expect ? 'сохранён' : 'срезан'));
    }
}
// Оба true/null — ничего не срезано.
foreach ([[true, true], [null, null], [true, null], [null, true]] as [$s3, $s31]) {
    $u = Bot::amneziaKeysUsable($full, $s3, $s31);
    foreach (array_merge(Bot::AWG_KEYS_3, Bot::AWG_KEYS_31) as $k) {
        awg31Assert(isset($u[$k]), "usable(sup3=" . var_export($s3, true) . ", sup31=" . var_export($s31, true) . "): $k не должен срезаться");
    }
}
// Обратная совместимость сигнатуры: третий параметр опционален, старый 2-арг вызов
// не должен резать AWG_KEYS_31.
$u = Bot::amneziaKeysUsable($full, true);
foreach (Bot::AWG_KEYS_31 as $k) {
    awg31Assert(isset($u[$k]), "usable(2 арг.): $k срезан без явного \$supports31 — сломана обратная совместимость");
}
awg31Assert(Bot::amneziaKeysUsable('nonsense', true, true) === [], 'usable: мусор на входе → []');

// ── 3. amneziaKeysReport(): поля 3.1 выводятся как есть, без маски ──────────────
$rep = Bot::amneziaKeysReport(['RandomTrailers' => 'on', 'DisableCookies' => 'off'], true, Bot::AWG_KEYS_31);
awg31Assert(strpos($rep, 'RandomTrailers: on') !== false, 'report: RandomTrailers потерялся');
awg31Assert(strpos($rep, 'DisableCookies: off') !== false, 'report: DisableCookies потерялся');

// ── 4. amneziaProtoVer(): поля 3.1 сами по себе не поднимают версию протокола ───
// Дизайн: RandomTrailers/DisableCookies — надстройка над шаблоном 3.0, а не признак
// версии протокола (та выводится только из AWG_KEYS_3, см. комментарий у функции).
awg31Assert(
    Bot::amneziaProtoVer(['I1' => '<t><r 100>', 'RandomTrailers' => 'on']) === 2,
    'amneziaProtoVer: RandomTrailers на 2.0-наборе не должен давать версию 3'
);
awg31Assert(
    Bot::amneziaProtoVer(array_merge($full, ['I1' => '<t><r 100>'])) === 3,
    'amneziaProtoVer: полный 3.0-набор + поля 3.1 всё ещё версия 3'
);

// ── 5. awgSupports31()/awgSupports31Cached(): порог версии 3.1 ──────────────────
foreach ([
    ['v3.0.20260805', false],
    ['v3.0.20260730', false],
    ['v3.1.20260812', true],
    ['v3.1.20260814', true],
    ['3.1.20260812', true],   // без ведущей "v"
] as [$ver, $expect]) {
    $bot->fakeToolsVer = $ver;
    awg31Assert($bot->awgSupports31() === $expect, "awgSupports31('$ver') должен быть " . var_export($expect, true));
    // awgSupports3() не должен ложно провалиться на 3.1-теге — тот же порог '>= 3.0'.
    awg31Assert($bot->awgSupports3() === true, "awgSupports3('$ver') должен остаться true на 3.1-теге");
}
$bot->fakeToolsVer = null;
awg31Assert($bot->awgSupports31() === null, 'awgSupports31(): контейнер не отвечает -> null, не false');

$bot->fakeConf = ['awg_tools_ver' => ['v' => 'v3.1.20260812']];
awg31Assert($bot->awgSupports31Cached() === true, 'awgSupports31Cached: кеш 3.1 должен дать true');
$bot->fakeConf = ['awg_tools_ver' => ['v' => 'v3.0.20260805']];
awg31Assert($bot->awgSupports31Cached() === false, 'awgSupports31Cached: кеш 3.0 должен дать false');
$bot->fakeConf = ['wg1_awg_tools_ver' => ['v' => 'v3.1.20260812']];
awg31Assert($bot->awgSupports31Cached('wg1_') === true, 'awgSupports31Cached: инстанс-префикс не читается');
$bot->fakeConf = [];
awg31Assert($bot->awgSupports31Cached() === null, 'awgSupports31Cached: пустой кеш -> null');

// ── 6. amneziaKeysForMihomo(): random-trailers/disable-cookies — bool, не строка ─
$mih = Bot::amneziaKeysForMihomo(array_merge($full, ['RandomTrailers' => 'on', 'DisableCookies' => 'off']), true);
awg31Assert(($mih['random-trailers'] ?? null) === true, 'mihomo: random-trailers должен быть bool(true) при on');
awg31Assert(is_bool($mih['random-trailers'] ?? null), 'mihomo: random-trailers должен быть именно bool, не строкой');
awg31Assert(!array_key_exists('disable-cookies', $mih), 'mihomo: disable-cookies при off не должен эмититься вовсе');

$mihBoth = Bot::amneziaKeysForMihomo(array_merge($full, ['RandomTrailers' => 'on', 'DisableCookies' => 'on']), true);
awg31Assert(($mihBoth['disable-cookies'] ?? null) === true, 'mihomo: disable-cookies должен быть bool(true) при on');

// Тумблер mihomo_awg3 выключен (awg3=false) — поля 3.1 не должны просочиться, как и 3.0.
$mihOff = Bot::amneziaKeysForMihomo(array_merge($full, ['RandomTrailers' => 'on', 'DisableCookies' => 'on']), false);
awg31Assert(!isset($mihOff['random-trailers']) && !isset($mihOff['disable-cookies']), 'mihomo: awg3=false должен гасить и поля 3.1');
awg31Assert(!isset($mihOff['version']), 'mihomo: awg3=false не должен объявлять version');

// Набор ещё 2.0 (нет AWG_KEYS_3), но RandomTrailers каким-то образом лежит в pac.json —
// без version:3 mihomo проигнорирует блок целиком, поэтому поле 3.1 тоже не должно уйти.
$mih2 = Bot::amneziaKeysForMihomo(['I1' => '<t><r 100>', 'RandomTrailers' => 'on'], true);
awg31Assert(!isset($mih2['random-trailers']), 'mihomo: RandomTrailers на 2.0-наборе не должен эмититься без version:3');

if ($failed) {
    echo "awg31_test FAILED ($failed)\n";
    exit(1);
}
echo "awg31_test OK\n";
