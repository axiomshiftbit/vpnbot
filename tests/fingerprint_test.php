<?php

// uTLS fingerprint. Инварианты проверены по исходникам ядер, а не по докам:
//
//  Xray-core transport/internet/tls/tls.go — PresetFingerprints:
//      chrome firefox safari ios android edge 360 qq random randomized
//      randomizednoalpn unsafe
//    GetFingerprint() возвращает nil для "unsafe", и КАЖДЫЙ диалер
//    (tcp/websocket/grpc/splithttp) в этом случае откатывается на tls.Client()
//    — то есть на стандартный Go-ClientHello без всякой маскировки.
//  Xray-core infra/conf/transport_security.go — для REALITY "unsafe" и
//    "hellogolang" отвергаются явно: `invalid "fingerprint"`, конфиг не грузится.
//  sing-box common/tls/utls_client.go — знает всё, кроме randomizednoalpn и
//    unsafe; на незнакомом имени возвращает ошибку (конфиг не запустится).
//  mihomo component/tls/utls.go — карта fingerprints[] БЕЗ randomized и
//    randomizednoalpn; GetFingerprint() на незнакомом имени пишет warning и
//    возвращает false → uTLS молча НЕ применяется (тот же Go-отпечаток).
//
// Отсюда главное правило: значение, доехавшее до клиента, обязано быть
// известно ЕГО ядру. Иначе маскировка либо ломает конфиг, либо тихо исчезает.

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function fpAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

// Наборы, поддерживаемые каждым ядром (снято с исходников, см. шапку).
$XRAY_PRESETS = [
    'chrome', 'firefox', 'safari', 'ios', 'android', 'edge', '360', 'qq',
    'random', 'randomized', 'randomizednoalpn', 'unsafe',
];
$SINGBOX = [
    'chrome', 'firefox', 'edge', 'safari', '360', 'qq', 'ios', 'android',
    'random', 'randomized',
];
$MIHOMO = [
    'chrome', 'firefox', 'safari', 'ios', 'android', 'edge', '360', 'qq',
    'random', 'chrome120', 'firefox120', 'safari16',
];

$bot = (new ReflectionClass(Bot::class))->newInstanceWithoutConstructor();

// Бот с подменённым pac.json — только для fingerprint().
function fpBot($value)
{
    return new class ($value) extends Bot {
        private $v;
        public function __construct($v)
        {
            $this->v = $v;
        }
        public function getPacConf(): array
        {
            return $this->v === null ? [] : ['fingerprint' => $this->v];
        }
    };
}

// ── 1. Список меню ─────────────────────────────────────────────────────────
$list = $bot->fingerprints();
foreach ($list as $fp) {
    fpAssert(in_array($fp, $XRAY_PRESETS, true), "«{$fp}» существует в PresetFingerprints Xray");
}
fpAssert(!in_array('unsafe', $list, true), '«unsafe» не предлагается: ломает Reality и снимает маскировку в TLS');
fpAssert(in_array('chrome', $list, true), 'chrome остаётся в списке как дефолт');
fpAssert(count($list) === count(array_unique($list)), 'в списке нет дублей');

// ── 2. Чтение значения: неизвестное/снятое → chrome ────────────────────────
fpAssert(fpBot('firefox')->fingerprint() === 'firefox', 'валидное значение читается как есть');
fpAssert(fpBot('unsafe')->fingerprint() === 'chrome', 'сохранённый ранее «unsafe» мигрирует в chrome');
fpAssert(fpBot('hellogolang')->fingerprint() === 'chrome', 'значение вне списка меню → chrome');
fpAssert(fpBot('')->fingerprint() === 'chrome', 'пустое значение → chrome');
fpAssert(fpBot(null)->fingerprint() === 'chrome', 'отсутствующий ключ → chrome');
fpAssert(fpBot('CHROME')->fingerprint() === 'chrome', 'регистр не совпал — не рискуем, отдаём chrome');

// ── 3. Нормализация под ядро: результат обязан быть известен ядру ──────────
foreach ($list as $fp) {
    $si = $bot->normalizeFingerprint($fp, 'singbox');
    $cl = $bot->normalizeFingerprint($fp, 'mihomo');
    $xr = $bot->normalizeFingerprint($fp, 'xray');
    fpAssert(in_array($si, $SINGBOX, true), "sing-box примет «{$fp}» → «{$si}»");
    fpAssert(in_array($cl, $MIHOMO, true), "mihomo примет «{$fp}» → «{$cl}»");
    fpAssert(in_array($xr, $XRAY_PRESETS, true), "xray примет «{$fp}» → «{$xr}»");
    fpAssert($xr === $fp, "для xray «{$fp}» не подменяется");
}

// Именно эти две подмены и защищают от тихой потери uTLS в mihomo.
fpAssert($bot->normalizeFingerprint('randomized', 'mihomo') === 'random', 'randomized → random для mihomo (иначе uTLS отключается молча)');
fpAssert($bot->normalizeFingerprint('randomizednoalpn', 'mihomo') === 'random', 'randomizednoalpn → random для mihomo');
fpAssert($bot->normalizeFingerprint('randomizednoalpn', 'singbox') === 'randomized', 'randomizednoalpn → randomized для sing-box');
fpAssert($bot->normalizeFingerprint('randomized', 'singbox') === 'randomized', 'randomized sing-box понимает сам');
fpAssert($bot->normalizeFingerprint('chrome', 'mihomo') === 'chrome', 'обычные значения не трогаем');

// ── 4. ALPN-совместимость ──────────────────────────────────────────────────
fpAssert($bot->fingerprintNoAlpn('randomizednoalpn'), 'randomizednoalpn помечен как без ALPN');
foreach (array_diff($list, ['randomizednoalpn']) as $fp) {
    fpAssert(!$bot->fingerprintNoAlpn($fp), "«{$fp}» отправляет ALPN");
}

// ── 5. Отпечаток не должен теряться ни в одном формате выдачи ──────────────
$src = file_get_contents(__DIR__ . '/../app/bot.php');
// Share-ссылки: fp обязателен во ВСЕХ четырёх транспортах, иначе клиент
// подставит своё умолчание и ClientHello разойдётся с остальными конфигами.
fpAssert(substr_count($src, '. "&fp=$fp') === 4, 'fp есть в share-ссылке каждого транспорта (reality/xhttp/trojan-grpc/ws)');
// Единая точка чтения: прямых обращений к pac['fingerprint'] мимо fingerprint()
// быть не должно — там и жила подстановка «unsafe» в конфиги.
fpAssert(
    !preg_match("~\\\$p(ac)?\\['fingerprint'\\]\\s*\\?:~", $src),
    'нет чтения pac[fingerprint] в обход fingerprint()'
);
foreach (['config/sing.json', 'config/clash.json', 'config/v2ray.json'] as $tpl) {
    $t = file_get_contents(__DIR__ . '/../' . $tpl);
    fpAssert(strpos($t, '~fingerprint~') !== false, "шаблон $tpl подставляет отпечаток");
}
// sing-box требует utls.enabled=true, иначе fingerprint игнорируется целиком.
$sing = json_decode(file_get_contents(__DIR__ . '/../config/sing.json'), true);
$found = false;
array_walk_recursive($sing, function ($v, $k) use (&$found) {
    if ($k === 'fingerprint' && $v === '~fingerprint~') {
        $found = true;
    }
});
fpAssert($found, 'sing.json несёт fingerprint внутри utls');
fpAssert(strpos(file_get_contents(__DIR__ . '/../config/sing.json'), '"enabled": true') !== false, 'utls в sing.json включён');

// ── REALITY: в профили уходит только отпечаток, который примет сервер ───────
// Сервер REALITY с Xray 26.9.8 отвергает ClientHello без X25519MLKEM768;
// из набора uTLS её несут chrome, firefox и safari (сверено на настоящем
// ядре — см. reality_fingerprint_core_test.php).
class FpRealityBot extends Bot
{
    public array $conf = [];
    public array $screen = ['', []];
    public function __construct() {}
    public function getPacConf() { return $this->conf; }
    public function setPacConf(array $conf) { $this->conf = $conf; return true; }
    public function i18n(string $menu): string { return $menu; }
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML') { $this->screen = [$text, is_array($button) ? $button : []]; }
}
$rb = new FpRealityBot();
$rb->input = ['chat' => 1, 'message_id' => 1];
fpAssert(Bot::REALITY_FINGERPRINTS === ['chrome', 'firefox', 'safari'], 'набор отпечатков REALITY изменён без сверки с ядром');
fpAssert(array_diff(Bot::REALITY_FINGERPRINTS, $rb->fingerprints()) === [], 'отпечаток REALITY отсутствует в меню');
foreach ($rb->fingerprints() as $fp) {
    $accepted = in_array($fp, Bot::REALITY_FINGERPRINTS, true);
    $rb->conf = ['transport' => 'Reality', 'fingerprint' => $fp];
    fpAssert($rb->fingerprintChosen() === $fp, "выбор $fp не сохраняется как выбранный");
    fpAssert($rb->fingerprint() === ($accepted ? $fp : 'chrome'), "REALITY: в профили уходит $fp → " . $rb->fingerprint());
    fpAssert($rb->fingerprintRejectedByReality() === !$accepted, "REALITY: пригодность $fp определена неверно");
    // Остальные транспорты — обычный TLS: сервер отпечаток не проверяет вовсе.
    foreach (['Websocket', 'xhttp', 'trojan-grpc', ''] as $transport) {
        $rb->conf = ['transport' => $transport, 'fingerprint' => $fp];
        fpAssert($rb->fingerprint() === $fp && !$rb->fingerprintRejectedByReality(), "$transport: отпечаток $fp подменён");
    }
}
$rb->conf = ['transport' => 'Reality', 'fingerprint' => 'ios'];
$rb->fingerprintMenu();
fpAssert(str_contains($rb->screen[0], 'fp reality warn') && str_contains($rb->screen[0], '<code>ios</code>'), 'меню не предупреждает о несовместимом отпечатке');
$labels = array_column(array_merge(...$rb->screen[1]), 'text');
fpAssert(count(preg_grep('~⚠~u', $labels)) === count($rb->fingerprints()) - 3 && !preg_grep('~^(Chrome|Firefox|Safari) .*⚠~u', $labels), 'несовместимые с REALITY отпечатки не помечены: ' . json_encode($labels, JSON_UNESCAPED_UNICODE));
$rb->conf = ['transport' => 'Reality', 'fingerprint' => 'firefox'];
$rb->fingerprintMenu();
fpAssert(!str_contains($rb->screen[0], 'fp reality warn'), 'предупреждение при совместимом отпечатке');
$rb->conf = ['transport' => 'Websocket', 'fingerprint' => 'ios'];
$rb->fingerprintMenu();
fpAssert(!str_contains($rb->screen[0], 'fp reality warn') && !preg_grep('~⚠~u', array_column(array_merge(...$rb->screen[1]), 'text')), 'предупреждение REALITY показано для обычного TLS');
// Перебор кнопкой идёт по выбранному значению, а не по подменённому: иначе с ios он застревал бы на firefox.
$rb->conf = ['transport' => 'Reality', 'fingerprint' => 'ios'];
$rb->changeFingerprint();
fpAssert($rb->conf['fingerprint'] === 'android', 'перебор отпечатков сбился: ' . $rb->conf['fingerprint']);
// Сервер отпечаток не хранит: это настройка клиента.
fpAssert(!str_contains((string) json_encode(json_decode((string) file_get_contents(__DIR__ . '/../config/xray.json'), true)), 'fingerprint'), 'в серверном шаблоне xray.json появился fingerprint');

if ($failed) {
    echo "$failed test(s) failed\n";
    exit(1);
}
echo "fingerprint: all checks passed\n";
