<?php

// CPS-пресеты I1-I5: разбор КАЖДОГО пресета как бинарного пакета.
//
// Зачем: два QUIC-пресета лежали в меню сломанными — они клали случайный байт
// на место поля Destination Connection ID Length, которому RFC 9000 §17.2
// разрешает значения только до 20. Проверить это было нечем: пресеты жили
// литералами внутри setAmneziaI1(), а validateCPSLine() смотрит лишь на
// синтаксис тегов и чётность hex, но не на смысл байтов.
//
// Здесь каждый пресет раскрывается в байты (теги <r N> и т.п. заменяются на N
// нулей — размер и смещения от этого не зависят) и разбирается по своему RFC.

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function t(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        echo "FAIL: $msg\n";
        $failed++;
    }
}

// Раскрывает CPS-строку в байты. Значения случайных тегов неважны — важны
// длина и позиции литералов, а именно на них держатся все поля длин.
function cpsBytes(string $cps): string
{
    return (string) preg_replace_callback(
        '~<b 0x([0-9a-fA-F]+)>|<(r|rc|rd) (\d+)>|<t>~',
        function ($m) {
            if (($m[1] ?? '') !== '') {
                return (string) hex2bin($m[1]);
            }
            return str_repeat("\x00", isset($m[3]) && $m[3] !== '' ? (int) $m[3] : 4);
        },
        $cps
    );
}

$bot = (new ReflectionClass(Bot::class))->newInstanceWithoutConstructor();

// ── Инварианты, обязательные для ВСЕХ пресетов ──────────────────────────────

$presets = $bot->cpsPresets();
t($presets !== [], 'список пресетов не пуст');
$total = 0;
foreach ($presets as $section => $items) {
    foreach ($items as $label => $cps) {
        $total++;
        $where = "[$section] $label";
        // 1. Собственная валидация бота обязана принимать всё, что бот же и
        //    предлагает нажать: иначе пресет невозможно применить.
        t($bot->validateCPSLine($cps) === '', "$where: validateCPSLine — " . $bot->validateCPSLine($cps));
        // 2. Чётность hex — единственное правило, ломающее разбор ВСЕГО
        //    конфига у клиента (obf_bytes.go: "odd amount of symbols").
        preg_match_all('~<b 0x([0-9a-fA-F]+)>~', $cps, $m);
        foreach ($m[1] as $hex) {
            t(strlen($hex) % 2 === 0, "$where: нечётный hex <b 0x$hex>");
        }
        // 3. Соседних <b> быть не должно — их обязан склеить cpsJoin().
        t(!preg_match('~<b 0x[0-9a-fA-F]+><b 0x~', $cps), "$where: несклеенные соседние <b>");
        // 4. Потолок 1000 у r/rc/rd (docs.amnezia.org, таблица Tag Types).
        preg_match_all('~<(?:r|rc|rd) (\d+)>~', $cps, $m);
        foreach ($m[1] as $n) {
            t((int) $n <= Bot::CPS_MAX_LEN, "$where: <r $n> превышает " . Bot::CPS_MAX_LEN);
        }
        // 5. Пустой пакет бессмысленен.
        t(strlen(cpsBytes($cps)) > 0, "$where: пустой пакет");
    }
}
t($total >= 14, "пресетов не меньше 14 (сейчас $total)");

// ── QUIC Initial без шифрования (RFC 9000 §17.2.2) ──────────────────────────

$p = cpsBytes($bot->cpsQUIC(1200));
t(strlen($p) === 1200, 'cpsQUIC(1200): ровно 1200 байт, ' . strlen($p));
t((ord($p[0]) & 0xf0) === 0xc0, 'cpsQUIC: long header + fixed bit + тип Initial');
t(substr($p, 1, 4) === "\x00\x00\x00\x01", 'cpsQUIC: версия 1');
$dcidLen = ord($p[5]);
// Ровно тот байт, на котором ломались прежние пресеты.
t($dcidLen > 0 && $dcidLen <= 20, "cpsQUIC: DCID Length=$dcidLen в пределах 1..20 (RFC 9000 §17.2)");
$scidLen = ord($p[6 + $dcidLen]);
t($scidLen > 0 && $scidLen <= 20, "cpsQUIC: SCID Length=$scidLen в пределах 1..20");
$off = 7 + $dcidLen + $scidLen;
t(ord($p[$off]) === 0, 'cpsQUIC: Token Length = 0 (клиент без Retry)');
$lenRaw = unpack('n', substr($p, $off + 1, 2))[1];
t(($lenRaw & 0xc000) === 0x4000, 'cpsQUIC: поле Length записано 2-байтной формой varint');
$pnOff = $off + 3;
t(
    ($lenRaw & 0x3fff) === strlen($p) - $pnOff,
    'cpsQUIC: Length совпадает с фактическим остатком пакета'
);
// Sample для header protection — 16 байт с pn_offset+4 (RFC 9001 §5.4.2).
t(strlen($p) - ($pnOff + 4) >= 16, 'cpsQUIC: тела хватает на sample header protection');
// Нижняя граница target.
$threw = false;
try {
    $bot->cpsQUIC(45);
} catch (InvalidArgumentException $e) {
    $threw = true;
}
t($threw, 'cpsQUIC: слишком маленький target отвергается');

// ── QUIC Initial с шифрованием (RFC 9001) ───────────────────────────────────
// Проверяем ровно так, как это делает Wireshark: ключи выводятся из DCID,
// секретов не нужно. Если пакет расшифровался и внутри лежит ClientHello —
// значит подделка настоящая, а не «похоже начинается».

$cps = $bot->cpsQUICInitial('www.cloudflare.com');
t((bool) preg_match('~^<b 0x[0-9a-f]+>$~', $cps), 'cpsQUICInitial: один статический литерал без тегов <r>');
$p = cpsBytes($cps);
t(strlen($p) === 1200, 'cpsQUICInitial: 1200 байт (RFC 9000 §14.1), ' . strlen($p));

$keysM = new ReflectionMethod(Bot::class, 'quicInitialKeys');
$keysM->setAccessible(true);
$dcidLen = ord($p[5]);
$dcid    = substr($p, 6, $dcidLen);
$scidLen = ord($p[6 + $dcidLen]);
$off     = 7 + $dcidLen + $scidLen;
$lenVal  = unpack('n', substr($p, $off + 1, 2))[1] & 0x3fff;
$pnOff   = $off + 3;
[$key, $iv, $hp] = $keysM->invoke(null, $dcid);

$mask  = openssl_encrypt(substr($p, $pnOff + 4, 16), 'aes-128-ecb', $hp, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
$first = ord($p[0]) ^ (ord($mask[0]) & 0x0f);
t((($first >> 2) & 0x03) === 0, 'cpsQUICInitial: reserved-биты после снятия HP равны 0 (RFC 9000 §17.2)');
$pnLen = ($first & 0x03) + 1;
$pn    = '';
for ($i = 0; $i < $pnLen; $i++) {
    $pn .= chr(ord($p[$pnOff + $i]) ^ ord($mask[1 + $i]));
}
$hdr    = substr($p, 0, $pnOff);
$hdr[0] = chr($first);
$hdr   .= $pn;
$ctAll  = substr($p, $pnOff + $pnLen);
$nonce  = $iv ^ (str_repeat("\x00", strlen($iv) - 4) . str_pad($pn, 4, "\x00", STR_PAD_LEFT));
$pt     = openssl_decrypt(substr($ctAll, 0, -16), 'aes-128-gcm', $key, OPENSSL_RAW_DATA, $nonce, substr($ctAll, -16), $hdr);
t($pt !== false, 'cpsQUICInitial: AES-128-GCM расшифровывается ключами из DCID');
if ($pt !== false) {
    t($lenVal === $pnLen + strlen($ctAll), 'cpsQUICInitial: Length = Packet Number + тело');
    t(ord($pt[0]) === 0x06, 'cpsQUICInitial: первый фрейм — CRYPTO (0x06)');
    $chLen = unpack('n', substr($pt, 2, 2))[1] & 0x3fff;
    $ch    = substr($pt, 4, $chLen);
    t(ord($ch[0]) === 0x01, 'cpsQUICInitial: внутри ClientHello (handshake type 1)');
    t(hexdec(bin2hex(substr($ch, 1, 3))) === strlen($ch) - 4, 'cpsQUICInitial: длина ClientHello сходится');
    t(substr($ch, 4, 2) === "\x03\x03", 'cpsQUICInitial: legacy_version 0x0303');
    // RFC 9001 §8.4: сервер ОБЯЗАН отбросить Initial с непустым session_id.
    t(ord($ch[38]) === 0, 'cpsQUICInitial: legacy_session_id пуст (RFC 9001 §8.4)');
    t(str_contains($ch, 'www.cloudflare.com'), 'cpsQUICInitial: SNI на месте');
    t(str_contains($ch, "\x02h3"), 'cpsQUICInitial: ALPN h3 на месте');
    t(trim(substr($pt, 4 + $chLen), "\x00") === '', 'cpsQUICInitial: хвост — только PADDING-фреймы (0x00)');
}
// Разные вызовы обязаны давать разные пакеты (DCID и key_share случайны),
// иначе ротация I1 не меняла бы ничего.
t($bot->cpsQUICInitial('www.google.com') !== $bot->cpsQUICInitial('www.google.com'), 'cpsQUICInitial: каждый вызов уникален');
$threw = false;
try {
    $bot->cpsQUICInitial('не хост');
} catch (InvalidArgumentException $e) {
    $threw = true;
}
t($threw, 'cpsQUICInitial: мусорный SNI отвергается');

// ── STUN Binding Request (RFC 5389) ─────────────────────────────────────────

$p = cpsBytes($bot->cpsSTUN());
t(unpack('n', substr($p, 0, 2))[1] === 0x0001, 'cpsSTUN: тип Binding Request');
t(substr($p, 4, 4) === hex2bin('2112a442'), 'cpsSTUN: magic cookie');
$msgLen = unpack('n', substr($p, 2, 2))[1];
t($msgLen === strlen($p) - 20, "cpsSTUN: Message Length=$msgLen = фактические " . (strlen($p) - 20) . ' байт атрибутов');
// Проход по TLV: прежняя версия сыпала сюда случайные байты, и разбор
// уезжал по мусорному смещению на первом же атрибуте.
$o     = 20;
$types = [];
while ($o + 4 <= strlen($p)) {
    $a       = unpack('ntype/nlen', substr($p, $o, 4));
    $types[] = $a['type'];
    $o      += 4 + $a['len'] + ((4 - $a['len'] % 4) % 4);
}
t($o === strlen($p), "cpsSTUN: TLV-проход заканчивается ровно на границе пакета ($o из " . strlen($p) . ')');
t(in_array(0x0006, $types, true), 'cpsSTUN: есть USERNAME');
t(in_array(0x0024, $types, true), 'cpsSTUN: есть PRIORITY');
t(end($types) === 0x0008, 'cpsSTUN: MESSAGE-INTEGRITY последний (RFC 5389 §15.4)');
// FINGERPRINT нельзя посчитать заранее — в сообщении есть теги <r>,
// раскрываемые клиентом при отправке; неверный лучше не слать вовсе.
t(!in_array(0x8028, $types, true), 'cpsSTUN: FINGERPRINT отсутствует намеренно');

// ── NTPv4 client request (RFC 5905 §7.3) ────────────────────────────────────

$p = cpsBytes($bot->cpsNTP());
t(strlen($p) === 48, 'cpsNTP: ровно 48 байт, ' . strlen($p));
t(ord($p[0]) === 0x23, 'cpsNTP: LI=0, VN=4, Mode=3 (client)');
t(substr($p, 4, 36) === str_repeat("\x00", 36), 'cpsNTP: заполнено только поле Transmit Timestamp');

// ── BitTorrent DHT (BEP 5) и uTP (BEP 29) ───────────────────────────────────

$p = cpsBytes($bot->cpsDHT());
t(strlen($p) === 56, 'cpsDHT ping: 56 байт, ' . strlen($p));
t($p[0] === 'd' && substr($p, -1) === 'e', 'cpsDHT ping: bencode-словарь');
t(str_contains($p, '1:q4:ping'), 'cpsDHT ping: запрос ping');
t(str_contains($p, '2:id20:'), 'cpsDHT ping: node id объявлен 20-байтным');

$p = cpsBytes($bot->cpsDHT(true));
t(strlen($p) === 92, 'cpsDHT find_node: 92 байта, ' . strlen($p));
t(str_contains($p, '1:q9:find_node'), 'cpsDHT find_node: запрос find_node');
t(str_contains($p, '6:target20:'), 'cpsDHT find_node: target объявлен 20-байтным');
// Ключи словаря bencode обязаны идти лексикографически.
t(strpos($p, '2:id') < strpos($p, '6:target'), 'cpsDHT: ключи "id" < "target" по порядку');

$p = cpsBytes($bot->cpsUTP());
t(strlen($p) === 20, 'cpsUTP: заголовок 20 байт, ' . strlen($p));
t(ord($p[0]) === 0x41, 'cpsUTP: type=ST_SYN(4), version=1');
t(ord($p[1]) === 0x00, 'cpsUTP: extension=0');

// ── cpsJoin ─────────────────────────────────────────────────────────────────

t($bot->cpsJoin('<b 0xaa><b 0xbb>') === '<b 0xaabb>', 'cpsJoin склеивает соседние литералы');
t($bot->cpsJoin('<b 0xaa><r 4><b 0xbb>') === '<b 0xaa><r 4><b 0xbb>', 'cpsJoin не трогает разделённые тегом');
t($bot->cpsJoin('<b 0xaa><b 0xbb><b 0xcc>') === '<b 0xaabbcc>', 'cpsJoin склеивает цепочку');

// ── Ранее сломанные пресеты не должны вернуться ─────────────────────────────
// Случайный байт на месте DCID Length: 236 значений из 256 вне лимита в 20.
$quic = $presets['QUIC (UDP/443)'] ?? [];
t($quic !== [], 'секция QUIC на месте (переименовали — поправьте и проверку ниже)');
foreach ($quic as $label => $cps) {
    t(
        !preg_match('~^<b 0x(?:c7|d1)00000001><r ~', $cps),
        // Фигурные скобки обязательны: PHP разрешает байты 0x80-0xFF в именах
        // переменных, и «$label»» разобралось бы как одно имя с хвостом.
        "QUIC-пресет «{$label}» снова кладёт <r> на место DCID Length"
    );
}

echo $failed ? "\n$failed FAILED\n" : "OK\n";
exit($failed ? 1 : 0);
