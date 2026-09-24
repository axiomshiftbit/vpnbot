<?php

// Мелочи выдачи подписок (аудит 2026-08-12, раздел МЕЛОЧЬ → «Xray / подписки»):
//  - ?s[]=1 / ?relay[]=1 доезжали до findClientBySid(string) и до
//    $pac['relays'][…] — TypeError и HTTP 500 вместо честного 404;
//  - #remark не кодировался: «#» в email обрывал имя узла и ломал подмену
//    имени в relaySwapLink;
//  - applyVmessExtRemark отдавал пустую vmess:// на невалидном UTF-8 из
//    чужой подписки;
//  - safeExtUrlIps не отбивал CGNAT (100.64/10) и NAT64 (64:ff9b::/96).

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function subMiscAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

class SubMiscTestBot extends Bot
{
    public array $pacFake = [];

    public function getPacConf()
    {
        return $this->pacFake;
    }

    public function flagName(string $name, array|string $hosts, bool $cacheOnly = true): string
    {
        return $name; // флаги требуют geoip-базы, к делу не относятся
    }
}

$bot = (new ReflectionClass(SubMiscTestBot::class))->newInstanceWithoutConstructor();

// ── 1. Параметры подписки приводятся к скалярам ─────────────────────────────
$_GET = ['s' => ['1'], 'relay' => ['x'], 'id' => 'ok', 't' => 'si'];
$bot->subToken = ['s' => ['1'], 'r' => 'name'];
$bot->normalizeSubGet();
subMiscAssert(!isset($_GET['s']), 'массив в ?s[] выброшен');
subMiscAssert(!isset($_GET['relay']), 'массив в ?relay[] выброшен');
subMiscAssert(($_GET['id'] ?? '') === 'ok', 'скалярные параметры не тронуты');
subMiscAssert(($_GET['t'] ?? '') === 'si', 'формат подписки на месте');
subMiscAssert(!isset($bot->subToken['s']), 'массив внутри токена выброшен');
subMiscAssert(($bot->subToken['r'] ?? '') === 'name', 'скаляр в токене не тронут');
// Ровно то, ради чего это делалось: сигнатура резолвера строгая.
$xr = ['inbounds' => [['settings' => ['clients' => [['id' => 'u', 'email' => 'a@x']]]]]];
subMiscAssert($bot->findClientBySid($xr, (string) ($_GET['s'] ?? '')) === null,
    'резолв по отсутствующему sid отдаёт null, а не TypeError');
$_GET = [];

// ── 2. #remark кодируется ───────────────────────────────────────────────────
$link = $bot->applyExtRemark('vless://uuid@host:443?type=tcp#old', 'a#b c');
subMiscAssert(str_ends_with($link, '#a%23b%20c'), "имя узла закодировано: $link");
subMiscAssert(substr_count($link, '#') === 1, "в ссылке ровно один #: $link");
// Именно из-за второго «#» ломалась подмена имени для relay (~#[^#]*$~).
$swapped = preg_replace('~#[^#]*$~', '#relay-name', $link);
subMiscAssert(str_ends_with($swapped, '#relay-name'), "подмена имени relay работает: $swapped");

// ── 3. vmess-ремарк на битом UTF-8 ──────────────────────────────────────────
$broken = 'vmess://' . base64_encode(json_encode(['ps' => 'x', 'add' => 'h']) );
$ok     = $bot->applyVmessExtRemark($broken, 'новое имя');
subMiscAssert(str_starts_with($ok, 'vmess://'), 'валидная ссылка переписывается');
$j = json_decode(base64_decode(substr($ok, strlen('vmess://'))), true);
subMiscAssert(($j['ps'] ?? '') === 'новое имя', 'имя подставлено: ' . json_encode($j, JSON_UNESCAPED_UNICODE));
// Невалидный UTF-8 внутри чужой подписки: json_encode вернёт false.
$bad     = 'vmess://' . base64_encode('{"ps":"x","add":"' . "\xB1\x31" . '"}');
$unchanged = $bot->applyVmessExtRemark($bad, 'имя');
subMiscAssert($unchanged === $bad, 'ссылка с битым UTF-8 остаётся как есть, а не превращается в «vmess://»');
subMiscAssert($unchanged !== 'vmess://', 'пустая vmess:// не отдаётся');

// ── 4. SSRF-guard: CGNAT и NAT64 ────────────────────────────────────────────
foreach (['100.64.0.1', '100.127.255.254', '64:ff9b::7f00:1', '64:ff9b:1::1'] as $ip) {
    subMiscAssert(Bot::isCarrierRange($ip) === true, "адрес $ip считается непубличным");
}
foreach (['8.8.8.8', '100.63.255.255', '100.128.0.0', '2001:db8::1', '1.1.1.1'] as $ip) {
    subMiscAssert(Bot::isCarrierRange($ip) === false, "адрес $ip остаётся публичным");
}
subMiscAssert(Bot::isCarrierRange('вообще не адрес') === false, 'мусор не роняет проверку');
// Классические обходы фильтр отбивал и раньше — проверяем, что не сломали.
subMiscAssert($bot->safeExtUrlIps('https://127.0.0.1/list') === [], 'loopback отбит');
subMiscAssert($bot->safeExtUrlIps('http://example.com/list') === [], 'только https');
subMiscAssert($bot->safeExtUrlIps('https://100.64.0.1/list') === [], 'CGNAT отбит');
subMiscAssert($bot->safeExtUrlIps('https://192.168.1.1/list') === [], 'приватный адрес отбит');
subMiscAssert($bot->safeExtUrlIps('https://[2606:4700:4700::1111]/list') === ['2606:4700:4700::1111'], 'Публичный IPv6 URL разрешён без DNS');
foreach (['::1', 'fc00::1', 'fe80::1', '::ffff:127.0.0.1', '::ffff:10.0.0.1', '::ffff:100.64.0.1', '64:ff9b::7f00:1'] as $ip) {
    subMiscAssert($bot->safeExtUrlIps("https://[$ip]/list") === [], 'Локальный или транслируемый IPv6 отбит');
}

if ($failed) {
    echo "audit_sub_misc_test FAILED: $failed\n";
    exit(1);
}
echo "audit_sub_misc_test OK\n";
