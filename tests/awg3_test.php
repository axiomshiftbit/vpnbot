<?php

// AmneziaWG 3.0: генератор наборов, валидатор диапазонов и инварианты, которые
// amneziawg-go/tools проверяют на своей стороне и при нарушении отвергают конфиг
// ЦЕЛИКОМ (интерфейс не поднимается):
//  - при непустом HeaderProtectionKey каждый из S1..S4 обязан быть >= 12;
//  - H1..H4 не должны пересекаться;
//  - range пишется как "N" или "LO-HI" при HI >= LO, без пробелов и "off".
// Плюс страховка от забытого ключа: всё, что генерируется, обязано быть
// перечислено в AWG_KEYS_*, иначе switchAmnezia() не вычистит его при смене
// версии и в wg0.conf останется хвост от прошлой конфигурации.

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function awgAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

// Подменяем только детект версии — остальное чистое, ssh/pac.json не нужны.
class Awg3TestBot extends Bot
{
    public $supports3 = true;

    public function awgSupports3(): ?bool
    {
        return $this->supports3;
    }

    public function amneziaKeys()
    {
        return $this->fakeKeys;
    }

    public array $fakeKeys = [];
}

$bot = (new ReflectionClass(Awg3TestBot::class))->newInstanceWithoutConstructor();

// ── 1. Генератор 3.0 ────────────────────────────────────────────────────────
foreach (['standard_3', 'aggressive_3', 'mobile_3'] as $tpl) {
    for ($i = 0; $i < 200; $i++) {
        $k = $bot->generateAmneziaKeys($tpl);

        foreach (Bot::AWG_KEYS_3 as $key) {
            awgAssert(isset($k[$key]), "$tpl: отсутствует $key");
        }
        foreach (['S1', 'S2', 'S3', 'S4'] as $s) {
            awgAssert((int) $k[$s] >= Bot::AWG_HPK_MIN_S, "$tpl: $s = {$k[$s]} < " . Bot::AWG_HPK_MIN_S);
        }
        awgAssert($k['S1'] !== $k['S2'], "$tpl: S1 === S2");
        awgAssert($k['S1'] + 56 !== $k['S2'], "$tpl: S1 + 56 === S2");
        awgAssert(Bot::awgHeaderProtectionOk($k), "$tpl: awgHeaderProtectionOk() === false");

        foreach (['ContentPaddingAddition', 'RekeyAfterTime', 'RekeyTimeout',
                  'RejectAfterTime', 'KeepaliveTimeout', 'MaxHandshakeAttempts'] as $key) {
            awgAssert(Bot::validateAwgRange((string) $k[$key]) === '', "$tpl: $key = {$k[$key]} не проходит validateAwgRange");
        }

        // Пир не должен отбрасывать сессию раньше, чем попробует рекей.
        [, $rekeyHi]   = Bot::awgRangeBounds((string) $k['RekeyAfterTime']);
        [$rejectLo, ]  = Bot::awgRangeBounds((string) $k['RejectAfterTime']);
        awgAssert($rejectLo > $rekeyHi, "$tpl: RejectAfterTime.lo ($rejectLo) <= RekeyAfterTime.hi ($rekeyHi)");

        $raw = base64_decode((string) $k['HeaderProtectionKey'], true);
        awgAssert($raw !== false && strlen($raw) === 32, "$tpl: HeaderProtectionKey не 32-байтный base64");

        awgAssert(Bot::amneziaProtoVer($k) === 3, "$tpl: amneziaProtoVer() !== 3");
    }
}

// ── 2. H1-H4: непересекающиеся диапазоны ────────────────────────────────────
foreach (['standard_2', 'aggressive_2', 'mobile_2', 'standard_3', 'aggressive_3', 'mobile_3'] as $tpl) {
    for ($i = 0; $i < 50; $i++) {
        $k = $bot->generateAmneziaKeys($tpl);
        $ranges = [];
        foreach (['H1', 'H2', 'H3', 'H4'] as $h) {
            awgAssert(preg_match('~^\d+-\d+$~', (string) $k[$h]) === 1, "$tpl: $h = {$k[$h]} не в формате MIN-MAX");
            [$lo, $hi] = Bot::awgRangeBounds((string) $k[$h]);
            awgAssert($lo < $hi, "$tpl: $h пустой диапазон");
            awgAssert($hi <= 0x7FFFFFFF, "$tpl: $h выходит за signed int32");
            $ranges[] = [$lo, $hi];
        }
        for ($a = 0; $a < 4; $a++) {
            for ($b = $a + 1; $b < 4; $b++) {
                $overlap = $ranges[$a][0] <= $ranges[$b][1] && $ranges[$b][0] <= $ranges[$a][1];
                awgAssert(!$overlap, "$tpl: H-диапазоны пересекаются");
            }
        }
    }
}

// ── 3. Полнота списков ключей ───────────────────────────────────────────────
foreach (array_keys(Bot::AMNEZIA_TEMPLATE_LABELS) as $tpl) {
    $unknown = array_diff(array_keys($bot->generateAmneziaKeys($tpl)), Bot::awgKeyNames());
    awgAssert($unknown === [], "$tpl: ключи вне AWG_KEYS_*: " . implode(',', $unknown));
}

// ── 4. validateAwgRange ─────────────────────────────────────────────────────
foreach (['0', '5', '65535', '10-40', '12-12'] as $ok) {
    awgAssert(Bot::validateAwgRange($ok) === '', "validateAwgRange('$ok') должен пройти");
}
foreach (['', 'off', 'abc', '40-10', '65536', '-5', '1-2-3', '10 - 40', '10-', ' 10'] as $bad) {
    awgAssert(Bot::validateAwgRange($bad) !== '', "validateAwgRange('$bad') должен упасть");
}
awgAssert(Bot::validateAwgRange('5', 10, 100) !== '', 'нижняя граница не проверяется');
awgAssert(Bot::validateAwgRange('10-200', 10, 100) !== '', 'верхняя граница не проверяется');
awgAssert(Bot::awgRangeBounds('12') === [12, 12], 'awgRangeBounds одиночного значения');
awgAssert(Bot::awgRangeBounds('10-40') === [10, 40], 'awgRangeBounds диапазона');

// ── 5. enforceHeaderProtection ──────────────────────────────────────────────
for ($i = 0; $i < 100; $i++) {
    $in  = ['S1' => 5, 'S2' => 61, 'S3' => 0, 'S4' => 0, 'HeaderProtectionKey' => 'x'];
    $out = Bot::enforceHeaderProtection($in);
    foreach (['S1', 'S2', 'S3', 'S4'] as $s) {
        awgAssert($out[$s] >= Bot::AWG_HPK_MIN_S, "enforceHeaderProtection: $s = {$out[$s]}");
    }
    awgAssert($out['S1'] !== $out['S2'], 'enforceHeaderProtection: S1 === S2');
    awgAssert($out['S1'] + 56 !== $out['S2'], 'enforceHeaderProtection: S1 + 56 === S2');
    awgAssert(Bot::awgHeaderProtectionOk($out), 'enforceHeaderProtection: инвариант не выполнен');
}

// ── 6. amneziaKeysForMihomo ─────────────────────────────────────────────────
$full = $bot->generateAmneziaKeys('standard_3');
$mih  = Bot::amneziaKeysForMihomo($full);
foreach (Bot::AWG_KEYS_3 as $k) {
    awgAssert(!isset($mih[$k]), "mihomo: 3.0-ключ $k просочился в amnezia-wg-option");
}
foreach (array_merge(Bot::AWG_KEYS_1, Bot::AWG_KEYS_2) as $k) {
    awgAssert(isset($mih[$k]), "mihomo: потерян ключ $k");
}
awgAssert(Bot::amneziaKeysForMihomo('') === [], 'mihomo: пустой вход должен дать []');

// ── 7. amneziaProtoVer ──────────────────────────────────────────────────────
awgAssert(Bot::amneziaProtoVer($bot->generateAmneziaKeys('classic_1')) === 1, 'classic_1 !== 1');
awgAssert(Bot::amneziaProtoVer($bot->generateAmneziaKeys('standard_2')) === 2, 'standard_2 !== 2');
awgAssert(Bot::amneziaProtoVer($bot->generateAmneziaKeys('mobile_3')) === 3, 'mobile_3 !== 3');
awgAssert(Bot::amneziaProtoVer([]) === 1, 'пустой набор !== 1');
awgAssert(Bot::amneziaProtoVer('nonsense') === 1, 'мусор на входе должен дать 1');

// ── 8. amneziaKeysEffective ─────────────────────────────────────────────────
$bot->fakeKeys  = $bot->generateAmneziaKeys('standard_3');
$bot->supports3 = false;
$eff = $bot->amneziaKeysEffective();
foreach (Bot::AWG_KEYS_3 as $k) {
    awgAssert(!isset($eff[$k]), "effective: при старых tools $k должен быть срезан");
}
awgAssert(isset($eff['I1']), 'effective: 2.0-поля не должны срезаться');

$bot->supports3 = null;
$eff = $bot->amneziaKeysEffective();
awgAssert(isset($eff['HeaderProtectionKey']), 'effective: при неизвестной версии срезать нельзя');

$bot->supports3 = true;
$bot->fakeKeys['S4'] = 5;   // ниже порога header protection
$eff = $bot->amneziaKeysEffective();
awgAssert(!isset($eff['HeaderProtectionKey']), 'effective: HPK при S4 < 12 должен быть срезан');
awgAssert(isset($eff['ContentPaddingAddition']), 'effective: остальные 3.0-поля срезать не нужно');

// ── 9. Обратная совместимость: 2.0/1.x без 3.0-полей ────────────────────────
foreach (['standard_2', 'aggressive_2', 'mobile_2', 'classic_1'] as $tpl) {
    $k = $bot->generateAmneziaKeys($tpl);
    foreach (Bot::AWG_KEYS_3 as $key) {
        awgAssert(!isset($k[$key]), "$tpl: не должен содержать $key");
    }
}

// ── 10. Списки шаблонов по версиям ──────────────────────────────────────────
foreach ([1, 2, 3] as $ver) {
    foreach (Bot::amneziaTemplateList($ver) as $tpl) {
        awgAssert(isset(Bot::AMNEZIA_TEMPLATE_LABELS[$tpl]), "нет метки для шаблона $tpl");
        awgAssert(isset(Bot::AMNEZIA_TEMPLATE_DESCS[$tpl]), "нет описания для шаблона $tpl");
        awgAssert(Bot::amneziaProtoVer($bot->generateAmneziaKeys($tpl)) === $ver, "$tpl не даёт версию $ver");
    }
}

// ── 11. Маскирование секрета в отчёте ───────────────────────────────────────
$rep = Bot::amneziaKeysReport(['HeaderProtectionKey' => 'SECRETVALUE', 'Jc' => 4]);
awgAssert(strpos($rep, 'SECRETVALUE') === false, 'report: ключ не замаскирован');
awgAssert(strpos($rep, 'Jc: 4') !== false, 'report: обычные поля потерялись');
$rep = Bot::amneziaKeysReport(['HeaderProtectionKey' => 'SECRETVALUE'], false);
awgAssert(strpos($rep, 'SECRETVALUE') !== false, 'report: без маски ключ должен быть виден');
$rep = Bot::amneziaKeysReport(['Jc' => 4, 'S1' => 20], true, ['S1']);
awgAssert($rep === 'S1: 20', 'report: фильтр $only не работает');

if ($failed) {
    echo "awg3_test FAILED ($failed)\n";
    exit(1);
}
echo "awg3_test OK\n";
