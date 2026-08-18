<?php

// ВЫСОКИЕ отчёта AUDIT-2026-08-18-01-bot-security.md.
//
// 1. downloadPeer()/upload() — path traversal через имя WG-пира: имя чистилось
//    только от пробелов и скобок, а путь строился конкатенацией "/logs/$name".
//    Пир «../config/nginx» превращал «скачать конфиг» в перезапись и unlink()
//    конфига фронтового nginx (php работает от root, ./config был на запись).
// 2. delAdmin() позволял удалить последнего админа: config.php оставался с
//    пустым admin, а auth() работает по trust-on-first-use — админом
//    становился автор следующего апдейта, кто бы это ни был.
// 3. denyIp()/whiteIp()/addInclude() не проверяли значение, а syncDeny()
//    писала его прямо в /config/deny, который include'ится ВНУТРЬ stream{}
//    фронтового nginx: инъекция директив либо неподнимающийся 443.

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function secAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

$src = (string) file_get_contents(__DIR__ . '/../app/bot.php');

// ── 1. Имя файла ────────────────────────────────────────────────────────────
secAssert(Bot::safeFileName('../config/nginx.conf') === '__config_nginx.conf',
    'обход вверх по дереву обезврежен: ' . Bot::safeFileName('../config/nginx.conf'));
secAssert(!str_contains(Bot::safeFileName('/etc/passwd'), '/'), 'слэш в имя файла не проходит');
secAssert(!str_contains(Bot::safeFileName('a/../../b'), '..'), '«..» не остаётся в имени');
secAssert(Bot::safeFileName('..') !== '' && Bot::safeFileName('..') !== '.',
    'вход из одних точек не даёт пустое имя');
secAssert(Bot::safeFileName('') === 'file' && Bot::safeFileName('', 'qr') === 'qr',
    'пустое имя заменяется фолбэком');
secAssert(Bot::safeFileName('wg_client-1.conf') === 'wg_client-1.conf',
    'нормальное имя не калечится');
// Кириллица в именах клиентов — обычное дело, но в путь она не идёт.
secAssert(!preg_match('~[^\w.-]~u', Bot::safeFileName('клиент (2).conf')),
    'в имени остаются только безопасные символы');

// Санитайзер обязан стоять в САМОМ upload(), а не у вызывающих: иначе
// следующий вызывающий снова принесёт сырое имя.
secAssert((bool) preg_match("~public function upload\(.*?\)\s*\{\s*\n\s*\\\$path = '/logs/' \. self::safeFileName\(\\\$name\);~s", $src),
    'upload() строит путь через safeFileName()');
secAssert(!preg_match('~\$path = "/logs/\$name";~', $src),
    'старая конкатенация "/logs/$name" удалена');
secAssert(substr_count($src, 'self::safeFileName(') >= 2,
    'общий санитайзер используется и в upload(), и в sendQr()');

// ── 2. Последний админ ──────────────────────────────────────────────────────
$delAdmin = substr($src, strpos($src, 'public function delAdmin('), 1800);
secAssert((bool) preg_match("~count\(\(array\) \\\$c\['admin'\]\) <= 1~", $delAdmin),
    'delAdmin() отказывается удалять последнего админа');
secAssert(strpos($delAdmin, 'cannot remove the last admin') < strpos($delAdmin, "unset(\$c['admin']"),
    'проверка стоит ДО unset, иначе она бесполезна');

// ── 3. allow/deny фронтового nginx ─────────────────────────────────────────
$ok = ['1.2.3.4', '10.0.0.0/8', '0.0.0.0/0', '2001:db8::1', '2001:db8::/32', '255.255.255.255'];
foreach ($ok as $v) {
    secAssert(Bot::ipOrCidr($v), "должен приниматься: $v");
}
$bad = [
    '1.2.3.4; } server { listen 8443; proxy_pass 10.10.0.2:443;', // инъекция директив
    '1.2.3.4 ',            // хвостовой пробел ломает директиву
    '1.2.3.4;',
    "1.2.3.4\ndeny all;",  // перевод строки
    'example.com',
    '10.0.0.0/33',
    '10.0.0.0/-1',
    '1.2.3.4/abc',
    '',
    null,
    '999.1.1.1',
];
foreach ($bad as $v) {
    secAssert(!Bot::ipOrCidr($v), 'должен отклоняться: ' . var_export($v, true));
}

$syncDeny = substr($src, strpos($src, 'public function syncDeny('), 3400);
secAssert(str_contains($syncDeny, "array_filter(array_unique(\$pac['white']), [self::class, 'ipOrCidr'])"),
    'syncDeny() фильтрует белый список перед записью в конфиг');
secAssert(str_contains($syncDeny, 'if (!self::ipOrCidr($v)) {'),
    'syncDeny() фильтрует чёрный список: в pac.json уже мог осесть мусор из импорта');
secAssert(strpos($syncDeny, 'nginx -t') !== false
    && strpos($syncDeny, 'nginx -t') < strpos($syncDeny, 'nginx -s reload'),
    'конфиг проверяется до reload: невалидный не должен доживать до рестарта контейнера');

// Вход тоже закрыт — иначе мусор копится в pac.json до ближайшей синхронизации.
secAssert((bool) preg_match("~in_array\(\\\$type, \['white', 'deny'\]\)\) \{\s*\n(\s*//[^\n]*\n)*\s*if \(!self::ipOrCidr\(\\\$v\)\)~", $src),
    'addInclude() не кладёт в white/deny ничего, кроме адреса или подсети');

if ($failed) {
    echo "audit_bot_security_test FAILED ($failed)\n";
    exit(1);
}
echo "audit_bot_security_test OK\n";
