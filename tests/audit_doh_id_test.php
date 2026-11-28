<?php

// DoH-идентификатор клиента (аудит 2026-08-18).
//
// В URL /dns-query<hashbot>/<id>, который клиент дёргает на КАЖДЫЙ DNS-запрос,
// стоял сам $client['id'] — учётные данные VLESS. Путь целиком писался в
// /logs/nginx_doh_access (секрет в $uri, формат noargs его не резал), те же
// значения лежали в dns.allowed_clients AdGuardHome.yaml и печатались в
// Telegram-меню adguard. /logs смонтирован почти во все контейнеры сборки.
//
// Теперь и в URL, и в allowed_clients идёт производный dohClientId().

require_once __DIR__ . '/../app/bot.php';

// Хостовый CI проверяет bot.php без ext-yaml, тогда как production-образ PHP
// расширение содержит. Для чистой проверки миграции достаточно симметричного
// JSON-backed полифила: функция работает с уже разобранными PHP-массивами.
if (!function_exists('yaml_parse_file')) {
    function yaml_parse_file(string $path)
    {
        return json_decode((string) file_get_contents($path), true);
    }
}
if (!function_exists('yaml_emit_file')) {
    function yaml_emit_file(string $path, $data)
    {
        return false !== file_put_contents($path,
            json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    }
}

$failed = 0;

function dohAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

class DohMigrationBot extends Bot
{
    public array $xrayFake = [];
    public int $adStops = 0;
    public int $adStarts = 0;

    public function getXray()
    {
        return $this->xrayFake;
    }

    public function stopAd()
    {
        $this->adStops++;
        return '';
    }

    public function startAd()
    {
        $this->adStarts++;
        return '';
    }
}

$bot = (new ReflectionClass(Bot::class))->newInstanceWithoutConstructor();
$bot->key = '123456:AAHtestBotTokenValue';

$uid = 'd0b8f2a4-1c3e-4f5a-9b7d-2e6c8a0f4b11';
$id  = $bot->dohClientId($uid);

// ── 1. Свойства идентификатора ──────────────────────────────────────────────
dohAssert($id !== $uid, 'ГЛАВНОЕ: в DoH-URL уходит не сам uuid клиента');
dohAssert(strpos($id, $uid) === false && strpos($uid, $id) === false,
    'производный id не содержит uuid и не содержится в нём');
dohAssert((bool) preg_match('~^doh-[0-9a-f]{16}$~', $id),
    'client-id AdGuard: явный префикс + 64 бита HMAC — ' . $id);
dohAssert(!preg_match('~^[0-9a-f]{12,16}$~i', $id),
    'client-id не похож на MAC/EUI-64, иначе AdGuard потеряет имя клиента');
dohAssert((bool) preg_match('~^[0-9a-f]{16}$~', $bot->legacyDohClientId($uid)),
    'старый HMAC-формат распознаётся для бесшовной миграции');
dohAssert($id === 'doh-' . $bot->legacyDohClientId($uid),
    'новый id сохраняет прежний HMAC и лишь выводит его из MAC-формата');
dohAssert($bot->dohClientId($uid) === $id,
    'детерминирован: URL подписки и allowed_clients считаются раздельно и обязаны совпасть');
dohAssert($bot->dohClientId('') === '', 'пустой uuid не превращается в «валидный» id');
dohAssert($bot->dohClientId($uid) !== $bot->dohClientId('11111111-2222-3333-4444-555555555555'),
    'разные клиенты — разные id');

// Ключ HMAC — токен бота: производный id нельзя посчитать, зная только uuid.
$other = (new ReflectionClass(Bot::class))->newInstanceWithoutConstructor();
$other->key = 'другой-токен';
dohAssert($other->dohClientId($uid) !== $id, 'id привязан к токену бота, а не только к uuid');

// ── 2. Сторож по исходникам ─────────────────────────────────────────────────
// Регрессия сюда вернулась бы одной правкой шаблонной подстановки, поэтому
// проверяем сам текст: в DoH-путях не должно остаться «/$uid».
$src = (string) file_get_contents(__DIR__ . '/../app/bot.php');
dohAssert(!preg_match('~dns-query\$hash/\$uid~', $src),
    'в bot.php не осталось DoH-URL с сырым uuid');
dohAssert(substr_count($src, 'dohClientId(') >= 4,
    'dohClientId() используется во всех точках: ~dns~, ~dnspath~, nameserver шаблона, allowed_clients');
dohAssert((bool) preg_match('~allowed_clients\'\]\[\] = \$this->dohClientId~', $src),
    'allowed_clients заполняется производным id, иначе AdGuard отказал бы всем клиентам');

// Миграция обязана существовать и вызываться из selfUpdate: URL меняется сразу,
// а allowlist AdGuard без переписывания остался бы со старыми uuid.
dohAssert((bool) preg_match('~function migrateDohClientIds~', $src), 'миграция allowed_clients на месте');
dohAssert((bool) preg_match('~\$this->migrateDohClientIds\(\)~', $src),
    'миграция вызывается из selfUpdate');
dohAssert(str_contains($src, "'migrateDohClientIds',"),
    'и стоит в шагах cron: selfUpdate мог оборваться раньше своей последней строки');
// Персональные записи клиентов AdGuard тоже переезжают: по ним раздаётся
// per-client политика, и адрес из DoH-пути должен с ними совпадать.
$mig = substr($src, strpos($src, 'public function migrateDohClientIds('), 4000);
dohAssert(str_contains($mig, "\$c['clients']['persistent']"),
    'миграция переписывает и persistent-клиентов, а не только allowed_clients');
$mergeCheck = Bot::adguardMergeClients([], [['id' => 'd0b8f2a4-1c3e-4f5a-9b7d-2e6c8a0f4b11', 'email' => 'm']],
    static fn(string $u) => 'doh-0123456789abcdef', 'UTC');
dohAssert(($mergeCheck[0]['ids'] ?? null) === ['doh-0123456789abcdef'],
    'adguardXrayClients() пишет производный id в ids, иначе миграцию тут же откатывало бы обратно');
dohAssert(str_contains($mig, "implode(':', str_split(\$legacy, 2))"),
    'миграция узнаёт EUI-64, в который AdGuard переписал старый 16-hex id');
dohAssert(str_contains($mig, '$next[] = $legacyMap[$v]'),
    'persistent-клиент переезжает со старого HMAC на prefixed id');
dohAssert(str_contains($src, 'isset($previous[$legacy])'),
    'пересборка allowlist не ломает уже выданные конфиги со старым HMAC');
// А вот uid обязан остаться UUID: на 16-hex значении AdGuardHome отказывается
// читать конфиг («invalid UUID length: 16») и не поднимается вовсе — DNS всей
// установки ложится. Поймано на рабочем сервере 2026-08-18.
dohAssert(($mergeCheck[0]['uid'] ?? null) === 'd0b8f2a4-1c3e-4f5a-9b7d-2e6c8a0f4b11',
    'uid персонального клиента остаётся UUID, а не производным id');
dohAssert(!str_contains($mig, "['uid'] = \$map["),
    'миграция не переписывает uid');

// ── 3. Переход с UUID/голого HMAC/EUI-64 без обрыва DNS ────────────────────
$migration = (new ReflectionClass(DohMigrationBot::class))->newInstanceWithoutConstructor();
$migration->key = $bot->key;
$uid2 = '11111111-2222-4333-8444-555555555555';
$old1 = $migration->legacyDohClientId($uid);
$old2 = $migration->legacyDohClientId($uid2);
$new1 = $migration->dohClientId($uid);
$new2 = $migration->dohClientId($uid2);
$mac2 = implode(':', str_split($old2, 2));
$migration->xrayFake = ['inbounds' => [[
    'settings' => ['clients' => [['id' => $uid], ['id' => $uid2]]],
]]];
$migration->adguard = sys_get_temp_dir() . '/doh_migrate_' . bin2hex(random_bytes(4)) . '.yaml';
yaml_emit_file($migration->adguard, [
    'dns' => ['allowed_clients' => ['10.10.0.0/24', $uid, $old2]],
    'clients' => ['persistent' => [
        ['name' => 'one', 'ids' => [$old1], 'uid' => $uid],
        ['name' => 'two', 'ids' => [$mac2], 'uid' => $uid2],
    ]],
]);

dohAssert($migration->migrateDohClientIds(), 'legacy-конфиг требует миграции');
$migrated = yaml_parse_file($migration->adguard);
$allowed = $migrated['dns']['allowed_clients'] ?? [];
dohAssert(!in_array($uid, $allowed, true) && in_array($new1, $allowed, true),
    'сырой UUID удалён из allowlist и заменён новым безопасным id');
dohAssert(in_array($old2, $allowed, true) && in_array($new2, $allowed, true),
    'старый HMAC остаётся разрешённым рядом с новым до обновления подписки');
dohAssert(($migrated['clients']['persistent'][0]['ids'] ?? null) === [$new1],
    'голый 16-hex persistent id получает префикс');
dohAssert(($migrated['clients']['persistent'][1]['ids'] ?? null) === [$new2],
    'нормализованный AdGuard EUI-64 получает префикс');
dohAssert(($migrated['clients']['persistent'][0]['uid'] ?? null) === $uid
    && ($migrated['clients']['persistent'][1]['uid'] ?? null) === $uid2,
    'внутренние UUID AdGuard не меняются');
dohAssert($migration->adStops === 1 && $migration->adStarts === 1,
    'AdGuard перезапускается ровно один раз после фактической миграции');
$before = file_get_contents($migration->adguard);
dohAssert(!$migration->migrateDohClientIds(), 'повторная миграция идемпотентна');
dohAssert(file_get_contents($migration->adguard) === $before
    && $migration->adStops === 1 && $migration->adStarts === 1,
    'cron не переписывает YAML и не перезапускает AdGuard повторно');
@unlink($migration->adguard);

// ── 4. Сторож по nginx-конфигам ─────────────────────────────────────────────
// Путь DoH — секрет целиком, поэтому логировать его нельзя ни в каком формате.
foreach (['nginx.conf', 'nginx_default.conf'] as $f) {
    $conf = (string) file_get_contents(__DIR__ . '/../config/' . $f);
    // Строка защиты от multipart (nginx_php_guard_test) содержит свои «{ }»:
    // тела location ниже разбираются до первой «}», поэтому её убираем.
    $conf = (string) preg_replace('~^[^\n]*# ' . Bot::NGINX_PHP_GUARD . '\n~m', '', $conf);
    dohAssert((bool) preg_match('~log_format nopath~', $conf), "$f: формат без пути объявлен");
    dohAssert(!preg_match('~access_log /logs/nginx_doh_access;~', $conf),
        "$f: DoH больше не пишется дефолтным combined (путь в логе)");
    dohAssert(substr_count($conf, 'access_log /logs/nginx_doh_access nopath;') === 2,
        "$f: формат nopath стоит и в активном, и в закомментированном #-domain блоке");
    dohAssert(substr_count($conf, 'access_log /logs/nginx_pac_access nopath;') === 2,
        "$f: токен подписки в пути также исключён из обоих журналов /pac");
    preg_match('~log_format noargs (.*?);~s', $conf, $logFormat);
    dohAssert(!str_contains($logFormat[1] ?? '', '$http_user_agent'), "$f: заголовок клиента не попадает в журнал статики");
    dohAssert(!str_contains($logFormat[1] ?? '', '$http_referer'),
        "$f: Referer не раскрывает ссылку подписки или авторизации");
    foreach (['@php', '/tlgrm', '/webapp', '/pac', '/dns-query'] as $location) {
        preg_match_all('~location ' . preg_quote($location, '~') . ' \\{([^}]+)\\}~s', $conf, $blocks);
        foreach ($blocks[1] as $block) {
            dohAssert(str_contains($block, 'error_log /dev/null;'), "$f $location: error_log не раскрывает URL при отказе upstream");
            if ($location === '@php') {
                dohAssert(str_contains($block, 'access_log /logs/nginx_webapp_access noargs;'),
                    "$f: внутренний переход WebApp в PHP сохраняет защиту query");
            }
        }
    }
    // Заодно XFF на /pac — из той же партии: без него лимит подписок обходится
    // подделкой заголовка (ключ ведра это hash(sid|ip|scope)).
    dohAssert((bool) preg_match('~location /pac \{[^}]*proxy_set_header X-Forwarded-For \$remote_addr;~s', $conf),
        "$f: /pac перетирает X-Forwarded-For своим значением");
    dohAssert((bool) preg_match('~location /pac \{[^}]*proxy_set_header X-Real-IP \$remote_addr;~s', $conf),
        "$f: /pac ставит X-Real-IP");
}

// ── 5. Сторож по unit.json ──────────────────────────────────────────────────
// Unit стоит ЗА nginx и логировал те же запросы своим дефолтным форматом с
// $request_line: туда попадали токен бота, subtoken'ы и tg.initData.
$unit = json_decode((string) file_get_contents(__DIR__ . '/../config/unit.json'), true);
dohAssert(is_array($unit['access_log'] ?? null), 'unit.json: access_log задан объектом с явным форматом');
dohAssert(strpos((string) ($unit['access_log']['format'] ?? ''), '$request_line') === false,
    'unit.json: $request_line (вместе с query-строкой) в лог не пишется');
dohAssert(strpos((string) ($unit['access_log']['format'] ?? ''), '$uri') === false,
    'unit.json: путь с токеном подписки не попадает в журнал backend');
dohAssert(str_starts_with((string) ($unit['access_log']['format'] ?? ''), '$remote_addr '),
    'unit.json: адрес клиента остаётся доступен для поиска по журналам');

// ── 6. Переходный период старого id: обе формы и срок жизни ────────────────
// Какую из форм AdGuard держит в dns.allowed_clients — сырые 16 hex или
// EUI-64, в который он их переписывает, — зависит от версии. Держим обе,
// иначе «плавная» миграция рвёт DNS ровно тем клиентам, ради которых она есть.
$compat = (new ReflectionClass(DohMigrationBot::class))->newInstanceWithoutConstructor();
$compat->key      = $bot->key;
$compat->xrayFake = ['inbounds' => [['settings' => ['clients' => [['id' => $uid2]]]]]];
$compat->adguard  = sys_get_temp_dir() . '/doh_compat_' . bin2hex(random_bytes(4)) . '.yaml';
yaml_emit_file($compat->adguard, ['dns' => ['allowed_clients' => [$mac2]]]);
dohAssert($compat->migrateDohClientIds(), 'EUI-64 в allowlist требует миграции');
$compatAllowed = yaml_parse_file($compat->adguard)['dns']['allowed_clients'] ?? [];
dohAssert(in_array($old2, $compatAllowed, true) && in_array($mac2, $compatAllowed, true),
    'в allowlist остаются обе формы старого id — сырая и EUI-64');
dohAssert(in_array($new2, $compatAllowed, true), 'новый prefixed id добавлен');
@unlink($compat->adguard);

// Срок: alias объявлен временным, значит обязан исчезать сам.
$src2 = (string) file_get_contents(__DIR__ . '/../app/bot.php');
dohAssert(str_contains($src2, 'public const DOH_LEGACY_TTL'), 'у переходного периода есть срок');
dohAssert((bool) preg_match('~public function dohLegacyAllowed\(\): bool~', $src2),
    'срок проверяется отдельным хелпером');
dohAssert(str_contains($src2, '$keepLegacy = $this->dohLegacyAllowed();'),
    'миграция спрашивает про срок, а не хранит alias вечно');
dohAssert((bool) preg_match('~\(isset\(\$previous\[\$legacy\]\) \|\| isset\(\$previous\[\$legacyMac\]\)\) && \$keepLegacy~', $src2),
    'ручная пересборка allowlist тоже уважает срок');

$expired = (new ReflectionClass(DohMigrationBot::class))->newInstanceWithoutConstructor();
$expired->key      = $bot->key;
$expired->xrayFake = ['inbounds' => [['settings' => ['clients' => [['id' => $uid2]]]]]];
$expired->adguard  = sys_get_temp_dir() . '/doh_expired_' . bin2hex(random_bytes(4)) . '.yaml';
$expired->pac      = sys_get_temp_dir() . '/doh_pac_' . bin2hex(random_bytes(4)) . '.json';
file_put_contents($expired->pac, json_encode(['dohlegacy' => time() - 10]));
yaml_emit_file($expired->adguard, ['dns' => ['allowed_clients' => [$old2]]]);
dohAssert($expired->migrateDohClientIds(), 'просроченный alias требует изменения конфига');
$expiredAllowed = yaml_parse_file($expired->adguard)['dns']['allowed_clients'] ?? [];
dohAssert(!in_array($old2, $expiredAllowed, true) && !in_array($mac2, $expiredAllowed, true),
    'после дедлайна старый id перестаёт быть пропуском в DNS');
dohAssert(in_array($new2, $expiredAllowed, true), 'новый id остаётся');
@unlink($expired->adguard);
@unlink($expired->pac);

// Пересборка после удаления последнего клиента: пустой список, без warning
// и без null вместо последовательности YAML.
$empty = (new ReflectionClass(DohMigrationBot::class))->newInstanceWithoutConstructor();
$empty->xrayFake = ['inbounds' => [['settings' => ['clients' => []]]]];
$empty->adguard = sys_get_temp_dir() . '/doh_empty_' . bin2hex(random_bytes(4)) . '.yaml';
yaml_emit_file($empty->adguard, ['clients' => ['persistent' => [['name' => 'removed']]]]);
set_error_handler(function ($level, $message) { throw new RuntimeException($message); });
try {
    $empty->adguardXrayClients();
    dohAssert(yaml_parse_file($empty->adguard)['clients']['persistent'] === [],
        'последний удалённый клиент очищает список AdGuard');
    dohAssert($empty->adStops === 1 && $empty->adStarts === 1, 'AdGuard перечитывает пустой список');
} finally {
    restore_error_handler();
    @unlink($empty->adguard);
}

if ($failed) {
    echo "audit_doh_id_test FAILED ($failed)\n";
    exit(1);
}
echo "audit_doh_id_test OK\n";
