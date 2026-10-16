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
// Случайный набор расширений ClientHello срывал рукопожатие через раз даже с
// обычным TLS (замер на nginx стенда 2026-10-13): в меню этих значений нет,
// а сохранённое прежде читается как chrome.
fpAssert(!in_array('randomized', $list, true) && !in_array('randomizednoalpn', $list, true), 'нестабильные randomized-отпечатки убраны из меню');
fpAssert(fpBot('randomized')->fingerprint() === 'chrome' && fpBot('randomizednoalpn')->fingerprint() === 'chrome', 'сохранённый randomized читается как chrome');

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

// ── REALITY: выбор администратора не подменяется, бот предупреждает ─────────
// Сервер REALITY, требующий ML-KEM (апстрим 26.9.8+, форк с requireMlkem),
// отвергает ClientHello без X25519MLKEM768; из набора uTLS её несут chrome,
// firefox и safari (сверено на настоящих ядрах — reality_fingerprint_core_test.php
// и набор стенда reality_fingerprints). Старое ядро и форк без флага принимают
// любой образец с TLS 1.3; android и 360 без TLS 1.3 не принимает никто.
class FpRealityBot extends Bot
{
    public array $conf = [];
    public array $screen = ['', []];
    public array $popups = [];
    public bool $mlkem = true;
    public function __construct() {}
    public function getPacConf() { return $this->conf; }
    public function setPacConf(array $conf) { $this->conf = $conf; return true; }
    public function i18n(string $menu): string { return $menu; }
    public function realityRequiresMlkem(): bool { return $this->mlkem; }
    public function answer($callback_id, $textNotify = false, $notify = false) { $this->popups[] = $textNotify; }
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML') { $this->screen = [$text, is_array($button) ? $button : []]; }
}
$rb = new FpRealityBot();
$rb->input = ['chat' => 1, 'message_id' => 1, 'callback_id' => 7];
$buttons = fn() => array_filter(array_merge(...$rb->screen[1]), fn($b) => str_starts_with($b['callback_data'], '/changeFingerprint'));
$labels = fn() => array_values(array_map(fn($b) => strtolower(strtok($b['text'], ' ')), $buttons()));
$warned = fn() => array_values(array_map(fn($b) => strtolower(strtok($b['text'], ' ')), array_filter($buttons(), fn($b) => str_ends_with($b['text'], '⚠'))));
fpAssert(Bot::REALITY_FINGERPRINTS === ['chrome', 'firefox', 'safari'], 'набор отпечатков REALITY изменён без сверки с ядром');
fpAssert(array_diff(Bot::REALITY_FINGERPRINTS, $rb->fingerprints()) === [], 'отпечаток REALITY отсутствует в общем списке');
fpAssert(Bot::REALITY_NO_TLS13 === ['android', '360'], 'набор образцов без TLS 1.3 изменён без сверки');
foreach ([true, false] as $mlkem) {
    $rb->mlkem = $mlkem;
    foreach ($rb->fingerprints() as $fp) {
        $noTls13 = in_array($fp, Bot::REALITY_NO_TLS13, true);
        $carries = in_array($fp, Bot::REALITY_FINGERPRINTS, true);
        $rb->conf = ['transport' => 'Reality', 'fingerprint' => $fp];
        $tag = "$fp, ML-KEM " . ($mlkem ? 'да' : 'нет');
        fpAssert($rb->fingerprint() === $fp, "REALITY: выбор подменён ($tag) → " . $rb->fingerprint());
        fpAssert($rb->fingerprintRejectedByReality() === ($noTls13 || ($mlkem && !$carries)), "REALITY: пригодность определена неверно ($tag)");
        $w = $rb->fingerprintWarnings();
        fpAssert(in_array('fp reality no tls13', $w, true) === $noTls13, "предупреждение о TLS 1.3 ($tag)");
        fpAssert(in_array('fp reality mlkem', $w, true) === (!$noTls13 && $mlkem && !$carries && $fp !== 'random'), "предупреждение об ML-KEM ($tag)");
        fpAssert(in_array('fp reality mihomo', $w, true) === (!$noTls13 && $mlkem && $fp !== 'chrome'), "предупреждение о Mihomo ($tag)");
        // random стабилен на ядре без ML-KEM; с ML-KEM — отдельное предупреждение.
        fpAssert(in_array('fp reality random', $w, true) === ($fp === 'random' && $mlkem), "предупреждение о random ($tag)");
        // Остальные транспорты — обычный TLS: nginx принимает любой образец.
        foreach (['Websocket', 'xhttp', 'trojan-grpc', ''] as $transport) {
            $rb->conf = ['transport' => $transport, 'fingerprint' => $fp];
            fpAssert($rb->fingerprint() === $fp && !$rb->fingerprintRejectedByReality() && $rb->fingerprintWarnings() === [],
                "$transport: отпечаток $fp подменён или помечен");
        }
    }
}
// Меню при REALITY: весь список, ⚠ у несовместимых с текущим ядром, объяснение правила ядра.
$rb->mlkem = true;
$rb->conf = ['transport' => 'Reality', 'fingerprint' => 'ios'];
$rb->fingerprintMenu();
fpAssert($labels() === $rb->fingerprints(), 'кнопки меню при REALITY: ' . json_encode($labels()));
fpAssert($warned() === ['ios', 'android', 'edge', '360', 'qq', 'random'], 'пометки ⚠ при ядре с ML-KEM: ' . json_encode($warned()));
fpAssert(str_contains($rb->screen[0], 'fp reality mlkem') && str_contains($rb->screen[0], 'fp reality core mlkem') && str_contains($rb->screen[0], 'fp compat'),
    'меню не объясняет поведение при REALITY');
fpAssert(str_contains(json_encode($rb->screen[1], JSON_UNESCAPED_UNICODE), 'Ios on'), 'выбранный ios не отмечен');
$rb->mlkem = false;
$rb->fingerprintMenu();
fpAssert($warned() === ['android', '360'], 'пометки ⚠ при ядре без ML-KEM: ' . json_encode($warned()));
fpAssert(!str_contains($rb->screen[0], 'fp reality mlkem') && str_contains($rb->screen[0], 'fp reality core any'), 'ядро без ML-KEM: лишнее предупреждение');
// Обычный TLS: весь список, без пометок и примечаний REALITY.
$rb->conf = ['transport' => 'Websocket', 'fingerprint' => 'ios'];
$rb->fingerprintMenu();
fpAssert($labels() === $rb->fingerprints() && $warned() === [] && !str_contains($rb->screen[0], 'fp reality'), 'меню при обычном TLS: ' . json_encode($labels()));
fpAssert(str_contains($rb->screen[0], 'fp compat') && str_contains(json_encode($rb->screen[1], JSON_UNESCAPED_UNICODE), 'Ios on'), 'при обычном TLS выбранный ios не отмечен');
foreach (array_merge(...$rb->screen[1]) as $button) {
    fpAssert(strlen($button['callback_data']) <= 64, 'длинные данные кнопки');
}
// Выбор сохраняется как есть; несовместимый — со всплывающим предупреждением.
$rb->mlkem = true; $rb->popups = [];
$rb->conf = ['transport' => 'Reality', 'fingerprint' => 'chrome'];
$rb->changeFingerprint('ios');
fpAssert($rb->conf['fingerprint'] === 'ios', 'выбор при REALITY не сохранён: ' . $rb->conf['fingerprint']);
fpAssert(count($rb->popups) === 1 && str_contains((string) $rb->popups[0], 'fp reality mlkem'), 'нет всплывающего предупреждения о несовместимом выборе');
// Окно ответа Telegram — не больше 200 символов при любом сочетании и языке.
$realI18n = new class extends FpRealityBot { public function i18n(string $menu): string { return Bot::i18n($menu); } };
$realI18n->input = $rb->input;
$realI18n->i18n = (static function () { require __DIR__ . '/../app/i18n.php'; return $i; })();
$seenPopups = [];
foreach (['ru', 'en'] as $lang) {
    $realI18n->language = $lang;
    foreach ([true, false] as $mlkem) {
        $realI18n->mlkem = $mlkem;
        foreach ($realI18n->fingerprints() as $fp) {
            foreach (['Reality', 'xhttp', 'trojan-grpc'] as $transport) {
                $realI18n->conf = ['transport' => $transport, 'fingerprint' => 'chrome']; $realI18n->popups = [];
                $realI18n->changeFingerprint($fp);
                foreach ($realI18n->popups as $popup) {
                    fpAssert(mb_strlen((string) $popup) <= 200, "окно ответа длиннее 200 ($lang, $transport, $fp)");
                    $seenPopups[$lang][] = $popup;
                }
            }
        }
    }
}
fpAssert(count($seenPopups['ru'] ?? []) >= 5 && preg_match('~[а-я]~u', $seenPopups['ru'][0]) && !str_contains($seenPopups['en'][0] ?? '', 'fp reality'),
    'проверка длины прошла по настоящим текстам предупреждений');
$rb->popups = [];
$rb->changeFingerprint('chrome');
fpAssert($rb->conf['fingerprint'] === 'chrome' && $rb->popups === [], 'лишнее предупреждение при совместимом выборе');
$rb->changeFingerprint();
fpAssert($rb->conf['fingerprint'] === 'firefox', 'перебор идёт по всему списку: ' . $rb->conf['fingerprint']);
$rb->conf = ['transport' => 'Websocket', 'fingerprint' => 'chrome'];
$rb->changeFingerprint('android');
fpAssert($rb->conf['fingerprint'] === 'android', 'при обычном TLS android должен выбираться');
$rb->changeFingerprint('randomized');
fpAssert($rb->conf['fingerprint'] === 'edge', 'убранный отпечаток выбрать нельзя: ' . $rb->conf['fingerprint']);
// Ссылки и подписки берут выбор как есть: принудительного chrome в коде нет.
$botSource = file_get_contents(__DIR__ . '/../app/bot.php');
fpAssert(!preg_match('~\$(fp|fingerprint)\s*=\s*\'chrome\'~', $botSource), 'в ссылках или подписках остался принудительный chrome');
// Сервер отпечаток не хранит: это настройка клиента.
fpAssert(!str_contains((string) json_encode(json_decode((string) file_get_contents(__DIR__ . '/../config/xray.json'), true)), 'fingerprint'), 'в серверном шаблоне xray.json появился fingerprint');
// Текст совместимости есть на обоих языках и не длиннее сообщения Telegram.
require __DIR__ . '/../app/i18n.php';
foreach (['en', 'ru'] as $lang) {
    fpAssert(mb_strlen($i['fp compat'][$lang] . $i['fp hint'][$lang] . $i['fp reality core mlkem'][$lang]) < 3000 && str_contains($i['fp compat'][$lang], 'sing-box'), "текст совместимости ($lang) пуст или слишком длинен");
    foreach (['fp reality no tls13', 'fp reality mlkem', 'fp reality mihomo', 'fp reality random', 'fp reality core mlkem', 'fp reality core any'] as $key) {
        fpAssert(($i[$key][$lang] ?? '') !== '', "нет текста $key ($lang)");
    }
}

if ($failed) {
    echo "$failed test(s) failed\n";
    exit(1);
}
echo "fingerprint: all checks passed\n";
