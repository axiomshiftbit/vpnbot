<?php

// Shadowsocks и его SIP003-плагины (v2ray-plugin, Cloak, simple-tls).
// Проверяется то, что ломается молча:
//  - `pkill -f <шаблон>` матчит и СОБСТВЕННУЮ командную строку шелла, которому
//    её отдали. Из-за этого «pkill -f ck-server; jq … && ck-server …» убивал сам
//    себя на первой команде: cloak включался в конфиге, но процесс не стартовал
//    и лог не создавался вовсе. Шаблон обязан быть в bracket-форме;
//  - ss://-ссылка по SIP002 требует websafe-base64 (base64url) без паддинга:
//    обычный base64 может выдать '/' в userinfo и порвать разбор URI;
//  - опции плагинов должны совпадать с тем, что понимают сами бинари
//    (README forwardproxy/simple-tls/v2ray-plugin).

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function ssAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

// ── 1. pkill-шаблоны не должны матчить собственную командную строку ─────────
// Модель: шелл получает всю строку в argv, поэтому «сама себя» = шаблон как
// регулярка, приложенная к тексту команды.
$selfMatches = function (string $pattern, string $cmdline): bool {
    return (bool) preg_match('~' . $pattern . '~', $cmdline);
};

foreach (['PKILL_STLS' => Bot::PKILL_STLS] as $name => $cmd) {
    ssAssert(str_contains($cmd, '['), "$name использует bracket-форму шаблона");
    // Вытаскиваем шаблон из «pkill -f '<pattern>'»
    ssAssert((bool) preg_match("~pkill -f '([^']+)'~", $cmd, $m), "$name разбирается");
    $pattern = $m[1];
    ssAssert(!$selfMatches($pattern, $cmd), "$name НЕ матчит собственную строку (иначе шелл убьёт сам себя)");
}

// Тот же шаблон обязан по-прежнему находить реальный процесс.
ssAssert($selfMatches('[c]k-server', 'ck-server -c /tmp/ckserver.json'),
    'шаблон cloak находит реальный ck-server');
ssAssert($selfMatches('[s]imple-tls', 'simple-tls -s -b :3443 -d 127.0.0.1:8388'),
    'шаблон simple-tls находит реальный процесс');

// Регрессия: старый, беззащитный вид обязан проваливать проверку выше —
// иначе тест бесполезен.
ssAssert($selfMatches('ck-server', 'pkill -f ck-server; jq … && ck-server -c /tmp/x'),
    'контроль: старый шаблон действительно матчил свою же строку');

// Команда рестарта cloak целиком: в ней есть и pkill, и запуск ck-server —
// именно эта комбинация и самоубивалась.
$restart = (new ReflectionMethod(Bot::class, 'ckServerRestartCmd'))->invoke(
    (new ReflectionClass(Bot::class))->newInstanceWithoutConstructor()
);
ssAssert(str_starts_with($restart, 'pkill -x ck-server; '), 'полная команда рестарта ищет имя процесса, а не свой SSH argv');
ssAssert($selfMatches('[c]k-server', "pkill -f '[c]k-server'; jq … && ck-server -c /tmp/x"),
    'bracket-шаблон тоже матчится на полный рестарт — одного теста pkill недостаточно');
ssAssert(!preg_match('~(?<!\[)\bpkill -f ck-server\b~', $restart), 'в ckServerRestartCmd нет голого pkill -f ck-server');
ssAssert(str_contains($restart, 'nohup setsid ck-server'), 'ckServerRestartCmd всё ещё запускает ck-server');
ssAssert(str_contains($restart, '/logs/ck-server.log'), 'вывод ck-server уходит в лог');

$acl = file_get_contents(__DIR__ . '/../config/ss.acl');
$ssTemplate = json_decode(file_get_contents(__DIR__ . '/../config/ssserver.json'), true);
ssAssert(($ssTemplate['acl'] ?? '') === '/config/ss.acl', 'ssserver включает запрет служебных сетей');
ssAssert(str_contains($acl, '[outbound_block_list]'), 'ACL фильтрует назначения, не клиентские IP');
foreach (['10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '::1/128', 'fc00::/7'] as $net) {
    ssAssert(str_contains($acl, $net), 'SS закрывает ' . $net);
}

// ── 2. SIP002: userinfo — base64url без паддинга ────────────────────────────
$enc = fn(string $s) => rtrim(strtr(base64_encode($s), '+/', '-_'), '=');

// Пароль, чей обычный base64 содержит '/' и '+' — ровно тот случай, который
// рвал ссылку (клиент принимал '/' за начало path).
$raw = "chacha20-ietf-poly1305:" . base64_decode('+/8=');
$std = base64_encode($raw);
ssAssert(strpbrk($std, '+/') !== false, 'контроль: обычный base64 такого пароля содержит + или /');
ssAssert(strpbrk($enc($raw), '+/=') === false, 'base64url не содержит + / =');
ssAssert(base64_decode(strtr($enc($raw), '-_', '+/')) === $raw, 'base64url декодируется обратно без потерь');

// Паддинг: старый код срезал только '==', одиночный '=' оставался.
$one = 'chacha20-ietf-poly1305:abc';            // даёт ровно один '='
ssAssert(substr(base64_encode($one), -1) === '=', 'контроль: этот вход даёт одиночный паддинг');
ssAssert(substr($enc($one), -1) !== '=', 'одиночный паддинг тоже срезается');

// ── 3. Опции плагинов ───────────────────────────────────────────────────────
// simple-tls (SIP003): клиентские ключи по README — n=<sni>, no-verify как
// голый флаг. Серверная сторона запускается отдельно с -s -b -d -cert -key.
$stls = fn(string $sni, bool $selfSigned) => 'simple-tls;n=' . $sni . ($selfSigned ? ';no-verify' : '');
ssAssert($stls('a.example.com', false) === 'simple-tls;n=a.example.com', 'simple-tls: только n= при валидном серте');
ssAssert(str_ends_with($stls('a.example.com', true), ';no-verify'), 'simple-tls: no-verify при self-signed');
ssAssert(!str_contains($stls('a.example.com', true), 'no-verify='), 'no-verify — голый флаг, без значения');

// Cloak: EncryptionMethod «aes-256-gcm» валиден (README: синоним aes-gcm),
// BrowserSig — chrome/firefox/safari, Transport — direct/CDN.
foreach (['plain', 'aes-gcm', 'aes-256-gcm', 'aes-128-gcm', 'chacha20-poly1305'] as $m2) {
    ssAssert(in_array($m2, ['plain', 'aes-gcm', 'aes-256-gcm', 'aes-128-gcm', 'chacha20-poly1305'], true),
        "cloak EncryptionMethod допускает $m2");
}
$ck = json_decode(file_get_contents(__DIR__ . '/../config/ckclient.json'), true);
ssAssert(in_array($ck['EncryptionMethod'], ['plain', 'aes-gcm', 'aes-256-gcm', 'aes-128-gcm', 'chacha20-poly1305'], true),
    'ckclient.json: EncryptionMethod из списка README');
ssAssert(in_array($ck['BrowserSig'], ['chrome', 'firefox', 'safari'], true), 'ckclient.json: BrowserSig валиден');
ssAssert(in_array($ck['Transport'], ['direct', 'CDN'], true), 'ckclient.json: Transport валиден');

// ck-server не понимает наше служебное поле Enabled и пустые AdminUID/
// DatabasePath — их обязаны вырезать и start_ss.sh, и команда бота.
foreach (['Enabled', 'AdminUID', 'DatabasePath'] as $k) {
    ssAssert(str_contains($restart, $k), "ckServerRestartCmd вычищает $k");
}

// v2ray-plugin: серверная сторона поднимается без path (дефолт '/'), поэтому
// nginx обязан срезать весь префикс — location должен содержать хеш целиком,
// а proxy_pass — оканчиваться слэшем.
$nginx = file_get_contents(__DIR__ . '/../config/nginx.conf');
ssAssert((bool) preg_match('~location /v2ray[^\s{]*\s*\{[^}]*proxy_pass http://ss:8388/;~s', $nginx),
    'nginx: /v2ray-локация проксирует на ss:8388 со слэшем (срезает префикс до "/")');

if ($failed) {
    echo "ss_test FAILED ($failed)\n";
    exit(1);
}
echo "ss_test OK\n";
