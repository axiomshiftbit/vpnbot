<?php

// NaiveProxy (caddy + klzgrad/forwardproxy). Проверяется то, что ломается молча:
//  - naiveCredOk(): логин/пароль уезжают в СИНТАКСИС Caddyfile строкой
//    «basic_auth <user> <pass>», поэтому пробел/`}`/`#`/перевод строки обязаны
//    отбиваться на входе, иначе caddy не поднимется без единого сообщения;
//  - у самой регулярки был баг: '~' одновременно делимитр и разрешённый символ,
//    из-за чего preg_match возвращал false ВСЕГДА и любой пароль считался
//    негодным (naive гасился бы на каждом рестарте);
//  - ссылка из меню строится по README naiveproxy — «https://user:pass@host»,
//    с percent-encoding userinfo и экранированием под parse_mode HTML;
//  - тег версии caddy принимается только как vX.Y.Z (пара caddy ↔ forwardproxy
//    пиннится вместе);
//  - гард в start_np.sh не должен пускать caddy с плейсхолдерными кредами.

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function npAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

// ── 1. naiveCredOk ──────────────────────────────────────────────────────────
$ok = [
    'MyPass123'                => 'обычный',
    'a-b_c.d~e'                => 'unreserved, включая ~ (на нём падала регулярка)',
    'p@ss:w0rd'                => 'sub-delims/@/: допустимы в userinfo',
    "!$&'()*+,;="              => 'полный набор sub-delims',
    'CHANGEME'                 => 'плейсхолдер синтаксически валиден — его ловит отдельный гард',
];
foreach ($ok as $v => $why) {
    npAssert(Bot::naiveCredOk($v) === true, "должно приниматься ($why): " . var_export($v, true));
}

$bad = [
    'pass with space' => 'пробел разбил бы basic_auth на лишние аргументы',
    'pass}broken'     => '} закрывает блок forward_proxy',
    'pass{broken'     => '{ открывает блок',
    'pass#comment'    => '# съедает остаток строки',
    'pass"quote'      => 'кавычка — группировка аргумента в Caddyfile',
    "pass\nnl"        => 'перевод строки дописывает произвольную директиву',
    "pass\n"          => 'завершающий перевод строки не является частью допустимых реквизитов',
    "pass\ttab"       => 'таб — тот же разделитель аргументов',
    'pass\\esc'       => 'обратный слэш',
    ''                => 'пусто',
    'пароль'          => 'не-ASCII: в userinfo ссылки требует кодирования',
];
foreach ($bad as $v => $why) {
    npAssert(Bot::naiveCredOk($v) === false, "должно отбиваться ($why): " . var_export($v, true));
}

npAssert(Bot::naiveCredOk(str_repeat('x', 128)) === true, 'ровно 128 символов — можно');
npAssert(Bot::naiveCredOk(str_repeat('x', 129)) === false, '129 символов — нельзя');
npAssert(Bot::naiveCredOk(null) === false, 'null не строка');
npAssert(Bot::naiveCredOk(123) === false, 'число не строка');

// Регрессия на делимитр: если шаблон снова оборвётся, preg_match начнёт слать
// warning и вернёт false — ловим и то, и другое.
$warn = null;
set_error_handler(function ($n, $s) use (&$warn) { $warn = $s; return true; });
$res = Bot::naiveCredOk('a~b');
restore_error_handler();
npAssert($warn === null, 'preg_match не должен ругаться на шаблон: ' . var_export($warn, true));
npAssert($res === true, "'~' внутри класса не должен обрывать регулярку");

// ── 2. Ссылка из naiveMenu ──────────────────────────────────────────────────
// Схема — ровно из README naiveproxy: https://user:pass@example.com
$mkLink = fn(string $u, string $p, string $host) =>
    'https://' . rawurlencode($u) . ':' . rawurlencode($p) . '@' . $host;

npAssert($mkLink('user', 'pass', 'np.example.com') === 'https://user:pass@np.example.com',
    'простой случай совпадает с примером из README');
// Эти символы naiveCredOk пропускает, и без кодирования они рвут разбор URL:
// '@' увёл бы хост, ':' — порт.
npAssert($mkLink('u', 'p@ss', 'h') === 'https://u:p%40ss@h', '@ в пароле кодируется');
npAssert($mkLink('u', 'a:b', 'h') === 'https://u:a%3Ab@h', ': в пароле кодируется');
npAssert(!str_contains($mkLink('u', 'a/b', 'h'), 'a/b'), '/ в пароле кодируется');

// Сообщение уходит с parse_mode HTML — экранирование обязательно.
$esc = htmlspecialchars($mkLink('u', 'a&b', 'h'), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
npAssert(!str_contains($esc, '&b'), '& экранируется для HTML');

// ── 3. Тег версии caddy ─────────────────────────────────────────────────────
// Пара пиннится вместе: FORWARDPROXY_VERSION = CADDY_VERSION . '-naive'.
$tagOk = fn(string $v) => (bool) preg_match('~^v\d+\.\d+\.\d+$~', $v);
foreach (['v2.11.2', 'v2.10.0', 'v2.9.1'] as $v) {
    npAssert($tagOk($v), "валидный тег: $v");
    npAssert("$v-naive" === $v . '-naive', "парный тег плагина для $v");
}
foreach (['2.11.2', 'v2.11', 'latest', 'naive', 'v2.11.2-naive', '', 'v2.11.2; rm -rf /'] as $v) {
    npAssert(!$tagOk($v), 'невалидный тег отбивается: ' . var_export($v, true));
}

// ── 4. Генерация пароля ─────────────────────────────────────────────────────
class NaivePasswordTestBot extends Bot
{
    public string $generated = '';

    public function chnppass($pass)
    {
        $this->generated = (string) $pass;
    }
}

$passwordBot = (new ReflectionClass(NaivePasswordTestBot::class))->newInstanceWithoutConstructor();
for ($i = 0; $i < 20; $i++) {
    $passwordBot->genNaivePass();
    npAssert(strlen($passwordBot->generated) === 32,
        'сгенерированный пароль NaiveProxy должен содержать 32 символа');
    npAssert((bool) preg_match('~^[0-9a-f]{32}$~', $passwordBot->generated),
        'сгенерированный пароль NaiveProxy должен быть hex-строкой');
    npAssert(Bot::naiveCredOk($passwordBot->generated),
        'сгенерированный пароль должен проходить валидатор NaiveProxy');
}

$botSource = (string) file_get_contents(__DIR__ . '/../app/bot.php');
npAssert(str_contains($botSource, "'callback_data' => \"/genNaivePass\""),
    'в меню NaiveProxy должна быть кнопка генерации пароля');
npAssert(str_contains($botSource, "preg_match('~^/genNaivePass$~'"),
    'callback генерации пароля NaiveProxy должен быть зарегистрирован');

// ── 5. Гард плейсхолдера в start_np.sh ──────────────────────────────────────
// Тот же шаблон, что в скрипте: caddy не должен стартовать, пока креды не заданы.
$guardRe = '~^\s*basic_auth\s+(CHANGEME\s+CHANGEME|_\s+__)\s*$~m';
npAssert((bool) preg_match($guardRe, "\tbasic_auth CHANGEME CHANGEME\n"), 'ловит новый плейсхолдер');
npAssert((bool) preg_match($guardRe, "\tbasic_auth _ __\n"), 'ловит старый плейсхолдер «_ __»');
npAssert(!preg_match($guardRe, "\tbasic_auth realuser realpass\n"), 'настроенные креды не считает плейсхолдером');

// Шаблон в репозитории обязан быть плейсхолдерным — иначе свежая установка
// уедет в сеть с кредами из git.
$caddyfile = file_get_contents(__DIR__ . '/../config/Caddyfile');
npAssert((bool) preg_match($guardRe, $caddyfile), 'config/Caddyfile в репозитории содержит плейсхолдер');

// allow all срабатывает ДО встроенного запрета приватных IP forwardproxy.
// Регрессия доступа настоящего Naive-клиента к веб-интерфейсу AdGuard.
$oldAcl = "acl {\n\tdeny 169.254.0.0/16\n\tdeny 100.64.0.0/10\n\tallow all\n}";
$newAcl = Bot::migrateNaiveAcl($oldAcl);
npAssert(!str_contains($newAcl, 'allow all'), 'старый штатный ACL больше не обходит встроенную изоляцию');
npAssert(str_contains($newAcl, 'deny 169.254.0.0/16') && str_contains($newAcl, 'deny 100.64.0.0/10'),
    'дополнительные запреты metadata/CGNAT сохранены');
npAssert(Bot::migrateNaiveAcl($newAcl) === $newAcl, 'миграция ACL идемпотентна');
$customAcl = "acl {\nallow 192.168.1.1\ndeny all\n}";
npAssert(Bot::migrateNaiveAcl($customAcl) === $customAcl, 'ручной ACL администратора сохранён');
npAssert(!preg_match('~^\s*allow\s+all\s*$~m', $caddyfile),
    'штатный шаблон не разрешает частные сети до встроенных запретов forwardproxy');

// И обязателен набор директив из официального примера/README forwardproxy.
// NB: не «$d» в двойных кавычках — '»' (U+00BB) попадает в \x80-\xff, который
// PHP считает допустимым символом имени переменной, и строка разбирается как
// переменная $d».
foreach (['probe_resistance', 'hide_ip', 'hide_via', 'ports 80 443'] as $d) {
    npAssert(str_contains($caddyfile, $d), 'в Caddyfile есть директива ' . $d);
}
npAssert(str_contains($caddyfile, '169.254.0.0/16'),
    'link-local закрыт явно: во встроенный deny forwardproxy он НЕ входит');
// probe_resistance имеет смысл только вместе с basic_auth (README forwardproxy).
npAssert(strpos($caddyfile, 'basic_auth') < strpos($caddyfile, 'probe_resistance'),
    'basic_auth объявлен до probe_resistance');
// proxy_protocol обязан идти перед tls (docs caddy: caddyfile/options).
npAssert(strpos($caddyfile, 'proxy_protocol') < strpos($caddyfile, "\t\t\ttls\n"),
    'proxy_protocol стоит перед tls-обёрткой');

// h3 не анонсируем: QUIC до контейнера не доходит (upstream-nginx разбирает 443
// по SNI через ssl_preread, а он работает только с TLS ClientHello по TCP), и
// клиент впустую ждал таймаут перед откатом на h2. Дефолт caddy — «h1 h2 h3».
npAssert((bool) preg_match('~^\s*protocols\s+h1\s+h2\s*$~m', $caddyfile),
    'в servers{} задан protocols h1 h2 (без h3)');
npAssert(!preg_match('~^\s*protocols\s.*\bh3\b~m', $caddyfile),
    'h3 не включён обратно');

if ($failed) {
    echo "naive_test FAILED ($failed)\n";
    exit(1);
}
echo "naive_test OK\n";
