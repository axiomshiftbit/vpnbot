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
// Окно в БАЙТАХ: комментарии кириллицей — по два байта на символ.
$delAdmin = substr($src, strpos($src, 'public function delAdmin('), 3200);
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
secAssert(str_contains($src, "if (in_array(\$type, ['white', 'deny'], true)) {")
    && str_contains($src, 'if (self::ipOrCidr($entry)) $list[] = $entry;'),
    'addInclude() не кладёт в white/deny ничего, кроме адреса или подсети');

// ── 4. СРЕДНИЕ того же отчёта ───────────────────────────────────────────────

// importFile(): первым аргументом из reply() приходит ТЕКСТ пользователя, то
// есть на промпт «send the export file:» можно было ответить строкой и
// получить file_get_contents() по произвольному пути или URL (allow_url_fopen
// включён) — чтение файла и SSRF во внутреннюю сеть от root.
$import = substr($src, strpos($src, 'public function importFile('), 2400);
secAssert(str_contains($import, '$file !== $this->update'),
    'importFile() принимает локальный путь только от selfUpdate()');
secAssert(strpos($import, '$file !== $this->update') < strpos($import, 'backupReadFile($file)'),
    'проверка стоит до чтения файла');

// config(): серверный wg0.conf уходил в чат вместе с PrivateKey сервера и
// PresharedKey каждого пира, да ещё и без экранирования — имя пира «Home <PC>»
// ломало разметку, и экран не открывался больше никогда.
secAssert((bool) preg_match('~PrivateKey\|PresharedKey~', $src),
    'ключи в серверном конфиге маскируются перед отправкой в чат');
secAssert((bool) preg_match('~"Server config:.*?htmlspecialchars\(\$conf~s', $src),
    'серверный конфиг экранируется для parse_mode=HTML');

// Экранирование и валидация relay/dnstt.
secAssert(Bot::esc('a<b & "c"') === 'a&lt;b &amp; &quot;c&quot;', 'esc() экранирует HTML');
$bot = (new ReflectionClass(Bot::class))->newInstanceWithoutConstructor();
foreach (['example.com', 'relay-1.example.org', '203.0.113.7', '2001:db8::1'] as $v) {
    secAssert($bot->isHostOrIp($v), "адрес relay должен приниматься: $v");
}
foreach (['a<b', 'host name', '', 'http://example.com', str_repeat('a', 300)] as $v) {
    secAssert(!$bot->isHostOrIp($v), 'адрес relay должен отклоняться: ' . var_export($v, true));
}
secAssert(substr_count($src, 'self::esc(') >= 12,
    'значения из ввода экранируются во всех точках рендера relay/telemt/dnstt');
foreach (['setRelayAddress', 'setRelayAwgAddress', 'setRelayHyAddress', 'setRelayNpAddress', 'telemtRelaySetAddress'] as $fn) {
    // Окно в БАЙТАХ, а комментарии кириллицей — по два байта на символ.
    $body = substr($src, strpos($src, "public function $fn("), 2000);
    secAssert(str_contains($body, 'isHostOrIp'), "$fn() валидирует адрес");
}

// setFakeDomain(): битый домен уезжал в xray.json и pac.json, ядро
// перезапускалось, а setUpstreamDomain() молча делал return — reality лежал,
// бот рапортовал об успехе.
$fake = substr($src, strpos($src, 'public function setFakeDomain('), 2400);
secAssert(str_contains($fake, 'isHostname($domain)'), 'setFakeDomain() проверяет домен');
secAssert(strpos($fake, 'isHostname($domain)') < strpos($fake, 'getXray()'),
    'проверка домена стоит до записи конфигов');

// HWID-заголовки публичного эндпоинта: ключ массива в общем hwid.json, который
// переписывается целиком под LOCK_EX на каждую выдачу подписки.
secAssert((bool) preg_match("~HTTP_X_HWID.*?\), 0, 128\)~s", $src),
    'X-HWID нормализуется и режется по длине');
secAssert((bool) preg_match('~\[\[:cntrl:\]\]~', $src),
    'управляющие символы вырезаются из остальных HWID-заголовков');

// Примитив блокировки RMW.
secAssert(method_exists('Bot', 'withLock') && method_exists('Bot', 'pacConfUpdate')
    && method_exists('Bot', 'xrayConfUpdate'),
    'примитив транзакций над конфигами введён');
secAssert($bot->withLock('selftest', fn() => 'ok') === 'ok', 'withLock() возвращает результат замыкания');
secAssert(str_contains(substr($src, strpos($src, 'public function hwidUpdate('), 600), 'withLock('),
    'hwidUpdate() переведён на общий примитив, а не дублирует лок');

// ── 5. НИЗКИЕ отчётов 01 и 02 ───────────────────────────────────────────────

// Полный текст упавшей ssh-команды уходил в чат при debug=1 — а там бывает
// «echo <PrivateKey> | wg pubkey». В лог писалась только первая строка, к
// отправке в чат то же рассуждение не применили.
$sshBlk = substr($src, strpos($src, "\$this->sshFailed = true;"), 1800);
secAssert(!str_contains($sshBlk, '$e->getMessage(), $this->input[\'message_id\']'),
    'в чат уходит усечённое сообщение, а не всё исключение целиком');
secAssert(str_contains($sshBlk, 'self::esc($first)'), 'и оно экранировано');

// Приватный ключ больше не подставляется в командную строку.
secAssert(!preg_match('~echo \{\$conf\[\x27interface\x27\]\[\x27PrivateKey\x27\]\}~', $src),
    'ключ WireGuard не идёт в argv контейнера (виден в ps)');
secAssert(substr_count($src, 'printf \'%s\'') >= 1, 'значение передаётся переменной окружения');

// Админы сравниваются строго и хранятся числами.
secAssert(str_contains($src, "in_array((int) \$this->input['from'], array_map('intval'"),
    'auth() сравнивает id админа строго');
$addAdmin = substr($src, strpos($src, 'public function addAdmin('), 2200);
secAssert(str_contains($addAdmin, '$id = (int) trim((string) $id);'),
    'addAdmin() приводит id к int и отвергает мусор');

// Единственный exec() с неэкранированными значениями из апдейта.
$pacU = substr($src, strpos($src, 'public function pacUpdate('), 1800);
secAssert(substr_count($pacU, 'escapeshellarg(') >= 4, 'pacUpdate() экранирует все подстановки');

// upstream_dns AdGuard — резолвер всей установки; мусор в нём не давал AdGuard стартовать.
$ups = substr($src, strpos($src, 'public function upstream('), 2200);
secAssert(str_contains($ups, 'wrong upstream format'), 'upstream() проверяет формат адреса');

// Ответ стороннего сервиса в сообщении.
$ipinfo = substr($src, strpos($src, 'ipinfo.io/$search'), 800);
secAssert(str_contains($ipinfo, 'self::esc('),
    'ответ ipinfo.io экранируется перед отправкой');

// subVless: 500 вместо 404 на нечитаемом конфиге и перебор без ведра промахов.
$svl = substr($src, strpos($src, 'public function subVless('), 2600);
secAssert(str_contains($svl, 'if (!is_array($xr))'), 'subVless проверяет читаемость конфига');
secAssert(str_contains($svl, "subRateLimit('', 'miss')"), 'промахи subVless идут в ведро перебора');

// Нестрогое сравнение в fallback по uuid.
secAssert(!preg_match("~\(\\\$v\['id'\] \?\? ''\) == \\\$sid~", $src),
    'findClientBySid сравнивает id строго');

// Поблажка браузерному UA — только на странице предпросмотра.
secAssert(str_contains($src, 'bool $htmlPreview = false'),
    'processHwidRequest различает страницу предпросмотра и выдачу конфига');
secAssert(str_contains($src, '$isBrowser = $htmlPreview && $this->isBrowserRequest();'),
    'браузерный UA обходит лимит устройств только на HTML-пути');

if ($failed) {
    echo "audit_bot_security_test FAILED ($failed)\n";
    exit(1);
}
echo "audit_bot_security_test OK\n";
