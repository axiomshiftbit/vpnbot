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

$failed = 0;

function dohAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
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
dohAssert((bool) preg_match('~^[0-9a-f]{16}$~', $id),
    'client-id AdGuard: только буквы/цифры, длина в пределах 63 — ' . $id);
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
dohAssert(str_contains($src, "'ids'                         => [\$this->dohClientId("),
    'adguardXrayClients() пишет производный id в ids, иначе миграцию тут же откатывало бы обратно');
// А вот uid обязан остаться UUID: на 16-hex значении AdGuardHome отказывается
// читать конфиг («invalid UUID length: 16») и не поднимается вовсе — DNS всей
// установки ложится. Поймано на рабочем сервере 2026-08-18.
dohAssert(str_contains($src, "'uid'                         => (string) \$v['id'],"),
    'uid персонального клиента остаётся UUID, а не производным id');
dohAssert(!str_contains($mig, "['uid'] = \$map["),
    'миграция не переписывает uid');

// ── 3. Сторож по nginx-конфигам ─────────────────────────────────────────────
// Путь DoH — секрет целиком, поэтому логировать его нельзя ни в каком формате.
foreach (['nginx.conf', 'nginx_default.conf'] as $f) {
    $conf = (string) file_get_contents(__DIR__ . '/../config/' . $f);
    dohAssert((bool) preg_match('~log_format nopath~', $conf), "$f: формат без пути объявлен");
    dohAssert(!preg_match('~access_log /logs/nginx_doh_access;~', $conf),
        "$f: DoH больше не пишется дефолтным combined (путь в логе)");
    dohAssert(substr_count($conf, 'access_log /logs/nginx_doh_access nopath;') === 2,
        "$f: формат nopath стоит и в активном, и в закомментированном #-domain блоке");
    // Заодно XFF на /pac — из той же партии: без него лимит подписок обходится
    // подделкой заголовка (ключ ведра это hash(sid|ip|scope)).
    dohAssert((bool) preg_match('~location /pac \{[^}]*proxy_set_header X-Forwarded-For \$remote_addr;~s', $conf),
        "$f: /pac перетирает X-Forwarded-For своим значением");
    dohAssert((bool) preg_match('~location /pac \{[^}]*proxy_set_header X-Real-IP \$remote_addr;~s', $conf),
        "$f: /pac ставит X-Real-IP");
}

// ── 4. Сторож по unit.json ──────────────────────────────────────────────────
// Unit стоит ЗА nginx и логировал те же запросы своим дефолтным форматом с
// $request_line: туда попадали токен бота, subtoken'ы и tg.initData.
$unit = json_decode((string) file_get_contents(__DIR__ . '/../config/unit.json'), true);
dohAssert(is_array($unit['access_log'] ?? null), 'unit.json: access_log задан объектом с явным форматом');
dohAssert(strpos((string) ($unit['access_log']['format'] ?? ''), '$request_line') === false,
    'unit.json: $request_line (вместе с query-строкой) в лог не пишется');
dohAssert(strpos((string) ($unit['access_log']['format'] ?? ''), '$uri') !== false,
    'unit.json: путь без аргументов в логе остаётся — иначе разбор логов ослепнет');

if ($failed) {
    echo "audit_doh_id_test FAILED ($failed)\n";
    exit(1);
}
echo "audit_doh_id_test OK\n";
