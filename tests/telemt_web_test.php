<?php

// WEB-режим telemt (тип прокси «WEB» в Telegram Desktop, telemt >= 3.5.0).
//
// Класс ошибок здесь дороже обычного: telemt не «пропускает» невалидную
// WEB-секцию, а ОТКАЗЫВАЕТСЯ грузить конфиг целиком — вместе с обычным
// MTProto-листенером. То есть опечатка в generated toml гасит прокси
// полностью, и по симптомам это неотличимо от упавшего контейнера.
//
// Проверяем то, что telemt валидирует у себя в load/validate_web.rs:
//   * WEB-листенер без vhost'ов запрещён (и наоборот);
//   * public_addr — конкретный адрес и ровно порт 443;
//   * secret_mode только plain|dd (ee в WEB не поддерживается);
//   * carrier — один из четырёх, а набор кандидатов уникален и не длиннее 4;
//   * [web.limits] проходят совместную валидацию (память, WebSocket, handler'ы);
//   * профилей не больше web.limits.max_profiles (32).
// Плюс согласованность с nginx-шаблоном: порт апстрима, доверенный CIDR и
// проброс Upgrade, без которого WebSocket-carrier'ы недостижимы.
//
// NB: НЕИЗВЕСТНЫЕ ключи telemt конфиг НЕ рушат — он их логирует и игнорирует
// (жёсткая ошибка только при general.config_strict=true, который бот не
// ставит). Проверено на 3.4.25 и 3.5.5. Рушат именно невалидные ЗНАЧЕНИЯ и их
// комбинации — их тут и проверяем.

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function twAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

class TelemtWebTestBot extends Bot
{
    public array $pacFake = [];

    public function getPacConf()
    {
        return $this->pacFake;
    }

    public function setPacConf(array $conf)
    {
        $this->pacFake = $conf;
        return true;
    }

    public function getPorts()
    {
        return ['telemt' => ['port' => 8443, 'enable' => 1]];
    }
}

$mk = static function (array $extra = []): TelemtWebTestBot {
    $b = (new ReflectionClass(TelemtWebTestBot::class))->newInstanceWithoutConstructor();
    $b->key = 'test-bot-key';
    $b->ip  = '203.0.113.10';
    $b->pacFake = $extra + [
        'domain'        => 'vpn.example',
        'letsencrypt'   => 'letsencrypt',
        'telemt_web'    => 1,
        'telemt_domain' => 'www.google.com',
        'telemt_users'  => ['bob' => 'aabbccddeeff00112233445566778899'],
    ];
    return $b;
};

// ── 1. Предусловия ──────────────────────────────────────────────────────────
$b = $mk();
twAssert($b->telemtWebBlockers($b->pacFake) === [], 'полный конфиг: препятствий нет');
twAssert($b->telemtWebEnabled($b->pacFake), 'полный конфиг: WEB включён');

$b = $mk(['domain' => '']);
twAssert(in_array('telemt web need domain', $b->telemtWebBlockers($b->pacFake), true), 'без домена — блокер');
twAssert(!$b->telemtWebEnabled($b->pacFake), 'без домена WEB не включается');

$b = $mk(['letsencrypt' => '']);
twAssert(in_array('telemt web need cert', $b->telemtWebBlockers($b->pacFake), true), 'без сертификата — блокер');

$b = $mk();
$b->ip = '';
twAssert(in_array('telemt web need ip', $b->telemtWebBlockers($b->pacFake), true), 'без IP — блокер');

$b = $mk(['telemt_users' => []]);
twAssert(in_array('telemt web need users', $b->telemtWebBlockers($b->pacFake), true), 'без пользователей — блокер');

// Тумблер выключен — WEB выключен даже когда всё остальное готово.
$b = $mk(['telemt_web' => 0]);
twAssert(!$b->telemtWebEnabled($b->pacFake), 'выключенный тумблер сильнее готовности');

// ── 2. Хост vhost'а ─────────────────────────────────────────────────────────
$b = $mk();
$host = $b->telemtWebHost($b->pacFake);
twAssert((bool) preg_match('~^[a-f0-9]{8}\.vpn\.example$~', $host), "хост — хеш-поддомен: $host");
twAssert($b->telemtWebHost(['domain' => '']) === '', 'без домена хоста нет');
twAssert($b->telemtWebHost(['domain' => 'плохой домен']) === '', 'мусорный домен отвергается');
// telemt требует FQDN, не IP и не однолейбловое имя.
twAssert(str_contains($host, '.') && !filter_var($host, FILTER_VALIDATE_IP), 'хост — FQDN, а не IP');

// ── 3. Нормализация carrier и secret_mode ───────────────────────────────────
$b = $mk();
twAssert($b->telemtWebCarrierOf([]) === 'https-lanes', 'carrier по умолчанию — https-lanes');
twAssert($b->telemtWebCarrierOf(['telemt_web_carrier' => 'https']) === 'https', 'заданный carrier сохраняется');
twAssert($b->telemtWebCarrierOf(['telemt_web_carrier' => 'quic']) === 'https-lanes', 'мусорный carrier → дефолт');
twAssert($b->telemtWebSecretModeOf([]) === 'dd', 'secret_mode по умолчанию — dd');
twAssert($b->telemtWebSecretModeOf(['telemt_web_secret_mode' => 'plain']) === 'plain', 'plain сохраняется');
// ee (Fake-TLS) в WEB не поддерживается — любое иное значение обязано стать dd.
twAssert($b->telemtWebSecretModeOf(['telemt_web_secret_mode' => 'ee']) === 'dd', 'ee → dd');

// ── 4. Ссылка tg://webproxy ─────────────────────────────────────────────────
$b = $mk();
$link = $b->linkTelemtWeb('bob', $b->pacFake);
twAssert(str_starts_with($link, 'tg://webproxy?'), "схема ссылки: $link");
parse_str((string) parse_url($link, PHP_URL_QUERY), $p);
twAssert(!array_key_exists('port', $p), 'порта в ссылке нет: Telegram Desktop принимает только 443');
twAssert($p['server'] === $host, 'server ссылки = хост vhost');
twAssert($p['secret'] === 'dd' . 'aabbccddeeff00112233445566778899', 'dd-секрет');

$b = $mk(['telemt_web_secret_mode' => 'plain']);
parse_str((string) parse_url($b->linkTelemtWeb('bob', $b->pacFake), PHP_URL_QUERY), $p);
twAssert($p['secret'] === 'aabbccddeeff00112233445566778899', 'plain-секрет без префикса');

$b = $mk();
twAssert($b->linkTelemtWeb('нет такого', $b->pacFake) === '', 'неизвестный пользователь — пустая ссылка');
twAssert($mk(['domain' => ''])->linkTelemtWeb('bob') === '', 'без домена ссылки нет');

// ── 5. telemt.toml ──────────────────────────────────────────────────────────
$b    = $mk();
$toml = $b->telemtToml($b->pacFake);

twAssert(substr_count($toml, '[[server.listeners]]') === 2, 'два листенера: mtproxy + web');
twAssert(str_contains($toml, 'transport = "web"'), 'transport=web присутствует');
twAssert(str_contains($toml, 'port = ' . Bot::TELEMT_WEB_PORT), 'порт WEB-листенера задан явно');
twAssert(str_contains($toml, 'proxy_protocol = false'), 'proxy_protocol=false (telemt запрещает true для web)');
twAssert(str_contains($toml, 'web_client_ip_source = "x_forwarded_for"'), 'источник IP клиента — X-Forwarded-For');
twAssert(str_contains($toml, 'web_trusted_proxy_cidrs = ["' . Bot::TELEMT_WEB_TRUSTED_CIDR . '"]'), 'доверенный пир — ng');
twAssert(!str_contains($toml, "transport = \"web\"\nannounce_ip"), 'announce_ip у web-листенера нет');

twAssert(str_contains($toml, "[web]\nenabled = true"), 'секция [web] включена');
twAssert(str_contains($toml, 'carrier = "https-lanes"'), 'carrier уехал в конфиг');
twAssert(str_contains($toml, '[[web.vhosts]]'), 'vhost объявлен');
twAssert(str_contains($toml, 'host = "' . $host . '"'), 'host vhost совпадает с хостом ссылки');
twAssert(str_contains($toml, 'public_addr = "203.0.113.10:443"'), 'public_addr — конкретный адрес на 443');
twAssert(str_contains($toml, "[web.vhosts.decoy]\nmode = \"static_directory\""), 'decoy — статический каталог');
twAssert(str_contains($toml, 'directory = "' . Bot::TELEMT_WEB_DECOY_DIR . '"'), 'каталог decoy задан');
twAssert(str_contains($toml, "[[web.vhosts.profiles]]\nuser = \"bob\"\nsecret_mode = \"dd\""), 'профиль пользователя');

// Порядок секций: [web]-таблицы идут последними, иначе ключи уехали бы в них.
twAssert(strpos($toml, '[web]') > strpos($toml, '[[upstreams]]'), '[web] после [[upstreams]]');
twAssert(strpos($toml, '[[server.listeners]]') < strpos($toml, '[censorship]'), 'листенеры до [censorship]');

// Выключенный WEB не оставляет в конфиге НИ листенера, ни секции: листенер без
// vhost'ов telemt считает фатальной ошибкой конфигурации.
$off = $mk(['telemt_web' => 0])->telemtToml($mk(['telemt_web' => 0])->pacFake);
twAssert(!str_contains($off, 'transport = "web"'), 'WEB выключен: листенера нет');
twAssert(!str_contains($off, '[web]'), 'WEB выключен: секции нет');
twAssert(substr_count($off, '[[server.listeners]]') === 1, 'WEB выключен: остаётся один листенер');

// Не выполнены предусловия — секции нет, даже если тумблер стоит.
$noip = $mk();
$noip->ip = '';
twAssert(!str_contains($noip->telemtToml($noip->pacFake), '[web]'), 'без IP секции [web] нет');

// ── 6. Лимит профилей ───────────────────────────────────────────────────────
$many = [];
for ($i = 0; $i < 40; $i++) {
    $many[sprintf('u%02d', $i)] = str_pad(dechex($i), 32, '0', STR_PAD_LEFT);
}
$b = $mk(['telemt_users' => $many]);
twAssert(count($b->telemtWebProfiles($b->pacFake)) === Bot::TELEMT_WEB_MAX_PROFILES,
    'список профилей режется по лимиту telemt');
$toml = $b->telemtToml($b->pacFake);
twAssert(substr_count($toml, '[[web.vhosts.profiles]]') === Bot::TELEMT_WEB_MAX_PROFILES,
    'в конфиг уезжает не больше 32 профилей');
// Пользователи при этом остаются доступны обычному MTProto-пути целиком.
twAssert(substr_count($toml, '"u39" = "') === 1 && substr_count($toml, '"u00" = "') === 1,
    'все пользователи остаются в [access.users], включая не попавших в профили');

// Длина callback_data кнопки WEB-ссылки: лимит Telegram — 64 байта, а имя
// пользователя ограничено 20 символами (telemtUserAdd).
twAssert(strlen('/telemtWebLink ') + 20 <= 64, 'кнопка WEB-ссылки влезает в лимит callback_data');

// ── 7. Согласованность с nginx-шаблоном ─────────────────────────────────────
$tpl = file_get_contents(__DIR__ . '/../config/nginx_default.conf');
twAssert(substr_count($tpl, '#-tgweb') === 2, 'в шаблоне ровно пара маркеров #-tgweb');
twAssert((bool) preg_match('~#\s+server 10\.10\.0\.20:' . Bot::TELEMT_WEB_PORT . ';~', $tpl),
    'апстрем nginx смотрит в тот же порт, что и листенер telemt');
twAssert(str_contains($tpl, 'server_name tgweb;'), 'плейсхолдер server_name на месте');

// Раскомментированный блок обязан быть валидным nginx: ни одной строки,
// начинающейся с «#», кроме самих маркеров.
preg_match('~#-tgweb.+?#-tgweb~s', $tpl, $m);
$bot  = (new ReflectionClass(TelemtWebTestBot::class))->newInstanceWithoutConstructor();
$open = $bot->uncomment($m[0], 'tgweb');
foreach (explode("\n", $open) as $line) {
    $t = ltrim($line);
    twAssert($t === '' || $t === '##tgweb' || $t[0] !== '#', "раскомментировано: «{$line}»");
}
twAssert(str_contains($open, 'proxy_read_timeout 95s;'), 'таймаут больше http_idle_secs (75s)');
twAssert(str_contains($open, 'access_log off;'), 'access_log выключен: в query едут креденшелы');
twAssert(substr_count($open, '{') === substr_count($open, '}'), 'скобки блока сбалансированы');

// WebSocket-carrier'ы (websocket, websocket-lanes) делают GET /api/v1/ws через
// HTTP/1.1 Upgrade. Без проброса этих двух заголовков апгрейд не доходит до
// telemt, и каждый WS-кандидат в цепочке негоциации гарантированно провалится.
twAssert(str_contains($open, 'proxy_set_header Upgrade $http_upgrade;'), 'Upgrade пробрасывается');
twAssert(str_contains($open, 'proxy_set_header Connection $connection_upgrade;'),
    'Connection берётся из map, а не гасится пустой строкой');
twAssert(!str_contains($open, 'proxy_set_header Connection "";'),
    'старое гашение Connection убрано: оно ломало WebSocket');
// $connection_upgrade объявлен один раз в http-контексте выше и виден здесь.
// Второе объявление — duplicate map и падение nginx -t.
twAssert(substr_count($tpl, 'map $http_upgrade') === 1,
    'map $http_upgrade объявлен ровно один раз на весь шаблон');
// Отдельной location для carrier-пути быть не должно: cloakNginx() дописывает
// хеш-суффикс ко всем путям вида /ws, и такая локация сломалась бы.
twAssert(!str_contains($tpl, 'location /api/v1/ws'), 'carrier-путь обслуживает catch-all location /');

// ── 8. Кто получает WEB-профиль ─────────────────────────────────────────────
// Лимит telemt — 32 профиля. Пользователю за лимитом кнопку 🌐 рисовать
// нельзя: ссылка сгенерируется, Telegram Desktop её примет, а telemt не
// пустит — и по симптомам это неотличимо от сетевой проблемы.
$b = $mk(['telemt_users' => $many]);
$profiles = $b->telemtWebProfiles($b->pacFake);
twAssert(in_array('u31', $profiles, true), '32-й по счёту пользователь профиль получает');
twAssert(!in_array('u32', $profiles, true), '33-й — уже нет');
twAssert(!in_array('u39', $profiles, true), 'последний — тем более нет');

// Имя из одних цифр json_decode отдаёт INT-ключом массива, а из callback_data
// оно приходит строкой: строгое сравнение такого пользователя не нашло бы
// никогда, и кнопка 🌐 у него молча не работала бы (та же ловушка описана в
// селекторе relay).
$b = $mk(['telemt_users' => json_decode('{"123":"aabbccddeeff00112233445566778899"}', true)]);
$flip = array_flip($b->telemtWebProfiles($b->pacFake));
twAssert(isset($flip['123']), 'пользователь с числовым именем находится по строке');
twAssert($b->linkTelemtWeb('123', $b->pacFake) !== '', 'и ссылка для него строится');

// ── 9. Самолечение: telemt не поднялся с секцией [web] ──────────────────────
// Невалидную [web] telemt не игнорирует, а отказывается грузить конфиг
// целиком — вместе с обычным MTProto. Тогда бот обязан снять WEB и поднять
// прокси без него: лучше потерять WEB, чем telemt.
class TelemtHealTestBot extends TelemtWebTestBot
{
    public array $sshCalls = [];
    public array $tomls    = [];
    public bool  $alive    = true;   // что отвечает проба pgrep
    public int   $probes   = 0;

    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
    {
        $this->sshCalls[] = $cmd;
        if (str_contains($cmd, 'while [ $i -lt 3 ]')) {
            $this->probes++;
            return $this->alive ? '250' : '';
        }
        return '';
    }

    public function telemtWriteToml(string $toml): void
    {
        $this->tomls[] = $toml;
    }

    public function telemtWebDecoy(): void
    {
    }

    public int $nginxReloads = 0;

    public function cloakNginx()
    {
        $this->nginxReloads++;
        return true;
    }
}

$mkHeal = static function (bool $alive, array $extra = []) use ($mk): TelemtHealTestBot {
    $h = (new ReflectionClass(TelemtHealTestBot::class))->newInstanceWithoutConstructor();
    $h->key = 'test-bot-key';
    $h->ip  = '203.0.113.10';
    $h->alive = $alive;
    $h->pacFake = $extra + $mk()->pacFake;
    return $h;
};

// Процесс не поднялся — WEB снимается, конфиг переписывается без него,
// telemt стартует второй раз.
$h = $mkHeal(false);
$h->restartTelemt();
twAssert(empty($h->pacFake['telemt_web']), 'WEB выключен после неудачного старта');
twAssert(count($h->tomls) === 2, 'конфиг переписан: ' . count($h->tomls));
twAssert(str_contains($h->tomls[0], '[web]'), 'первый конфиг был с [web]');
twAssert(!str_contains($h->tomls[1], '[web]'), 'второй — уже без [web]');
twAssert(!str_contains($h->tomls[1], 'transport = "web"'), 'и без WEB-листенера');
twAssert(count(array_filter($h->sshCalls, fn($c) => str_starts_with($c, 'telemt run'))) === 2,
    'telemt запущен повторно');
// Блок #-tgweb обязан уйти вместе с секцией [web], иначе nginx проксирует в
// несуществующий листенер и WEB-хост отвечает 502 вместо decoy.
twAssert($h->nginxReloads === 1, 'nginx перегенерирован после отката');

// Процесс поднялся — ничего не трогаем.
$h = $mkHeal(true);
$h->restartTelemt();
twAssert(!empty($h->pacFake['telemt_web']), 'рабочий WEB остаётся включённым');
twAssert(count($h->tomls) === 1, 'конфиг переписан один раз');
twAssert(count(array_filter($h->sshCalls, fn($c) => str_starts_with($c, 'telemt run'))) === 1,
    'telemt запущен один раз');
twAssert($h->nginxReloads === 0, 'без отката nginx не трогаем');

// WEB выключен — пробы вообще нет, лишнего ssh-захода не делаем.
$h = $mkHeal(false, ['telemt_web' => 0]);
$h->restartTelemt();
twAssert($h->probes === 0, 'без WEB пробы не делаем');

// Контейнер недоступен (ssh не прошёл) — это не «WEB виноват»: там не работает
// вообще ничего, и выключать тумблер не за что.
class TelemtDeadContainerBot extends TelemtHealTestBot
{
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
    {
        $this->sshCalls[] = $cmd;
        $this->sshFailed  = true;
        return '';
    }
}
$d = (new ReflectionClass(TelemtDeadContainerBot::class))->newInstanceWithoutConstructor();
$d->key = 'test-bot-key';
$d->ip  = '203.0.113.10';
$d->pacFake = $mk()->pacFake;
$d->restartTelemt();
twAssert(!empty($d->pacFake['telemt_web']), 'при недоступном контейнере WEB не выключаем');
twAssert($d->nginxReloads === 0, 'и nginx не трогаем');

// Пользователей нет — telemt не стартует вовсе (существующее поведение),
// значит и самолечению нечего чинить.
$h = $mkHeal(false, ['telemt_users' => []]);
$h->restartTelemt();
twAssert(!array_filter($h->sshCalls, fn($c) => str_starts_with($c, 'telemt run')),
    'без пользователей telemt не запускается');

// ── 10. Авто-негоциация carrier (telemt >= 3.5.4) ───────────────────────────
// Пресет хранит ПОЛНУЮ цепочку вместе с fallback; telemtToml() отрезает
// последний элемент в web.carrier, остаток кладёт в web.carriers. telemt
// дописывает fallback в конец сам и ровно один раз, поэтому внутри carriers
// его быть не должно — дубликаты он отвергает вместе со всем конфигом.
$b = $mk();
twAssert($b->telemtWebNegotiationOf([]) === 'off', 'дефолт негоциации — off');
twAssert($b->telemtWebNegotiationOf(['telemt_web_negotiation' => 'мусор']) === 'off',
    'неизвестный пресет → off');
twAssert($b->telemtWebNegotiationOf(['telemt_web_negotiation' => ['full']]) === 'off',
    'массив вместо строки → off, без TypeError');
twAssert($b->telemtWebCandidates(['telemt_web_negotiation' => 'off']) === [],
    'при off кандидатов нет');

foreach (['off', 'https', 'full'] as $mode) {
    $cands = Bot::TELEMT_WEB_NEGOTIATION[$mode];
    twAssert(count($cands) === count(array_unique($cands)), "$mode: кандидаты уникальны");
    twAssert(count($cands) <= 4, "$mode: кандидатов не больше четырёх (потолок telemt)");
    foreach ($cands as $c) {
        twAssert(in_array($c, ['https', 'https-lanes', 'websocket', 'websocket-lanes'], true),
            "$mode: carrier «{$c}» известен telemt");
    }
    if ($cands) {
        // Клиент без метаданных негоциации (Telegram iOS) всегда берёт
        // фиксированный web.carrier, а поддерживает он только https.
        twAssert(end($cands) === 'https', "$mode: fallback — https");
    }
}

$toml = $mk(['telemt_web_negotiation' => 'full'])->telemtToml();
twAssert(str_contains($toml, 'carrier = "https"'), 'full: fallback https');
twAssert(str_contains($toml, 'carriers = ["websocket-lanes", "websocket", "https-lanes"]'),
    'full: три кандидата перед fallback');
twAssert(str_contains($toml, 'carrier_learning = true'), 'full: обучение включено');
twAssert(str_contains($toml, 'carrier_negotiation_aggressiveness = "conservative"'),
    'full: conservative-политика');
twAssert(!str_contains($toml, '"https", "https"'), 'full: fallback не продублирован');

$toml = $mk(['telemt_web_negotiation' => 'https'])->telemtToml();
twAssert(str_contains($toml, 'carriers = ["https-lanes"]'), 'https: один кандидат перед fallback');
twAssert(str_contains($toml, 'carrier = "https"'), 'https: fallback https');

// off — прежнее поведение: ключа carriers нет вовсе (именно его отсутствие и
// выключает негоциацию), carrier берётся из отдельной кнопки.
$toml = $mk(['telemt_web_negotiation' => 'off'])->telemtToml();
twAssert(!str_contains($toml, "\ncarriers = "), 'off: ключа carriers нет');
twAssert(!str_contains($toml, "\ncarrier_learning = "), 'off: обучения нет');
twAssert(str_contains($toml, 'carrier = "https-lanes"'), 'off: carrier из кнопки');
$toml = $mk(['telemt_web_negotiation' => 'off', 'telemt_web_carrier' => 'https'])->telemtToml();
twAssert(str_contains($toml, 'carrier = "https"'), 'off: кнопка carrier по-прежнему работает');

// Длина callback_data новой кнопки: лимит Telegram — 64 байта.
twAssert(strlen('/telemtWebNegotiation') <= 64, 'кнопка негоциации влезает в callback_data');

// Гейт по версии: на бинаре старше 3.5.4 ключ web.carriers не принимается.
// Кнопка обязана оставлять выход в off, иначе на откатившемся образе оператор
// заперт во включённом пресете, который этот бинарь не грузит.
class TelemtOldBinaryBot extends TelemtWebTestBot
{
    public array  $answers      = [];
    public int    $restarts     = 0;
    public int    $nginxReloads = 0;
    public string $ver          = '3.5.3';

    public function telemtVersion(): string
    {
        return $this->ver;
    }

    public function answer($id, $text = '', $alert = false)
    {
        $this->answers[] = $text;
        return true;
    }

    public function restartTelemt()
    {
        $this->restarts++;
    }

    public function cloakNginx()
    {
        $this->nginxReloads++;
        return true;
    }

    public function telemtWeb($update = false)
    {
    }
}
$mkOld = static function (string $mode) use ($mk): TelemtOldBinaryBot {
    $o = (new ReflectionClass(TelemtOldBinaryBot::class))->newInstanceWithoutConstructor();
    $o->key = 'test-bot-key';
    $o->ip  = '203.0.113.10';
    $o->input = ['chat' => 1, 'message_id' => 2, 'callback_id' => 3];
    $o->pacFake = ['telemt_web_negotiation' => $mode] + $mk()->pacFake;
    return $o;
};
$o = (new ReflectionClass(TelemtOldBinaryBot::class))->newInstanceWithoutConstructor();
twAssert(!$o->telemtWebNegotiationVersionOk(), '3.5.3 не проходит гейт негоциации');

$o = $mkOld('off');
$o->telemtWebNegotiation();
twAssert($o->telemtWebNegotiationOf($o->pacFake) === 'off', 'со старым бинарём негоциация не включается');
// i18n в тесте не загружен, поэтому i18n() отдаёт сам ключ — его и сверяем.
twAssert($o->answers === ['telemt web negotiation need version'], 'оператор получает модалку про версию');
twAssert($o->restarts === 0, 'и рестарта ради отказа не делаем');

$o = $mkOld('full');
$o->telemtWebNegotiation();
twAssert($o->telemtWebNegotiationOf($o->pacFake) === 'off', 'из включённого пресета выпускает в off');
twAssert($o->restarts === 1, 'и применяет это рестартом');

// Переключение пресета НЕ трогает nginx: блок #-tgweb от набора кандидатов не
// зависит (проброс Upgrade в нём безусловный), а перегенерацию шаблона на
// установке со старым nginx.conf делает service.php при старте стека. Лишний
// reload на каждое нажатие — чистый шум.
$o = $mkOld('off');
$o->ver = '3.5.5';
$o->telemtWebNegotiation();
twAssert($o->telemtWebNegotiationOf($o->pacFake) === 'https', 'цикл off → только HTTPS');
twAssert($o->restarts === 1 && $o->nginxReloads === 0, 'пресет применяется рестартом telemt, без reload nginx');
$o->telemtWebNegotiation();
twAssert($o->telemtWebNegotiationOf($o->pacFake) === 'full', 'цикл только HTTPS → полный');
$o->telemtWebNegotiation();
twAssert($o->telemtWebNegotiationOf($o->pacFake) === 'off', 'цикл полный → off замыкается');
twAssert($o->nginxReloads === 0, 'ни одно переключение не дёргает nginx');

// ── 11. Пин [web.limits]: пересчёт совместной валидации telemt ──────────────
// Дефолтный memory_envelope_bytes у telemt 3.5.5 — 1.25 GiB, что больше всей
// памяти типового VPS. Бот пинит свой профиль, и ошибка здесь означает не
// «лишний ключ проигнорирован», а отказ загрузки конфига и падение всего
// прокси. Поэтому повторяем здесь арифметику самого telemt из
// load/validate_web.rs и load/validate_web/{memory,websocket}.rs.
$toml = $mk(['telemt_web_negotiation' => 'full'])->telemtToml();
twAssert(str_contains($toml, "[web.limits]\n"), 'блок [web.limits] присутствует');
twAssert(strpos($toml, '[web.limits]') > strpos($toml, '[web]'), '[web.limits] после [web]');
twAssert(strpos($toml, '[web.limits]') < strpos($toml, '[[web.vhosts]]'),
    '[web.limits] до vhost, иначе ключи уедут не в ту таблицу');
twAssert(!str_contains($mk(['telemt_web' => 0])->telemtToml(), '[web.limits]'),
    'без WEB лимитов не пишем');

// Дефолты telemt для ключей, которые бот не переопределяет: без них формулы
// не сойдутся, а их значения — часть контракта версии 3.5.5.
$L = Bot::TELEMT_WEB_LIMITS + [
    'max_header_bytes'                   => 16384,
    'max_body_bytes'                     => 2097152,
    'max_frame_payload_bytes'            => 1048576,
    'carrier_batch_bytes'                => 2097152,
    'max_frames_per_body'                => 4096,
    'max_lane_open_waits_per_session'    => 16,
    'pending_bytes_per_lane'             => 8388608,
    'pending_items_per_lane'             => 1024,
    'websocket_admission_watermark_pct'  => 75,
    'websocket_eviction_watermark_pct'   => 90,
    'websocket_http_connection_reserve'  => 64,
    'max_websocket_evictions_in_flight'  => 8,
    'max_sessions_per_ip'                => 16,
    'max_streams_global'                 => 4096,
    'max_stream_handshakes'              => 256,
    'pending_bytes_per_session'          => 33554432,
    'pending_items_per_session'          => 16384,
    'pending_items_global'               => 262144,
    'control_bytes_per_session'          => 262144,
    'control_bytes_global'               => 16777216,
    'max_bootstraps_global'              => 512,
    'max_bootstraps_per_ip'              => 64,
    'max_static_file_bytes'              => 8388608,
    'max_profiles'                       => 32,
];
// Отрендеренный блок обязан совпадать с константой — иначе тест проверяет не то,
// что уезжает в telemt.
foreach (Bot::TELEMT_WEB_LIMITS as $k => $v) {
    twAssert(str_contains($toml, "\n$k = $v\n"), "лимит $k = $v в toml");
}

// Диапазоны отдельных ключей.
twAssert($L['max_header_bytes'] >= 8192 && $L['max_header_bytes'] <= 65536, 'max_header_bytes в [8192, 65536]');
twAssert($L['max_tombstones_per_session'] >= 1 && $L['max_tombstones_per_session'] <= 4096,
    'max_tombstones_per_session в [1, 4096]');
twAssert($L['max_streams_per_session'] <= 65535, 'потоки влезают в synthetic source port');
twAssert($L['carrier_batch_bytes'] <= $L['max_body_bytes']
    && $L['carrier_batch_bytes'] >= $L['max_frame_payload_bytes'] + 8, 'carrier_batch_bytes согласован');
foreach ($L as $k => $v) {
    twAssert($v > 0, "лимит $k > 0");
}

// Потолки «на владельца» не выше глобальных.
foreach ([
    ['max_sessions_per_ip', 'max_sessions_global'],
    ['max_streams_per_session', 'max_streams_global'],
    ['max_stream_handshakes', 'max_streams_global'],
    ['max_bootstraps_per_ip', 'max_bootstraps_global'],
    ['max_http_handlers', 'max_http_connections'],
    ['max_body_readers', 'max_http_handlers'],
    ['max_lane_open_waits_per_session', 'max_streams_per_session'],
    ['pending_bytes_per_session', 'pending_bytes_global'],
    ['pending_items_per_session', 'pending_items_global'],
    ['pending_bytes_per_lane', 'pending_bytes_per_session'],
    ['pending_items_per_lane', 'pending_items_per_session'],
    ['control_bytes_per_session', 'control_bytes_global'],
    ['control_bytes_per_session', 'pending_bytes_per_session'],
    ['control_bytes_global', 'pending_bytes_global'],
    ['max_static_file_bytes', 'max_static_bytes'],
] as [$a, $bKey]) {
    twAssert($L[$a] <= $L[$bKey], "$a <= $bKey");
}
twAssert($L['max_body_readers'] * $L['max_body_bytes'] <= $L['max_body_bytes_global'],
    'резерв сборщиков тел влезает в max_body_bytes_global');

// Резервы control-фреймов и прогресс очередей.
$cips = 16 + $L['max_streams_per_session'] * 3;
$cig  = $cips * $L['max_sessions_global'];
$cfc  = 8 + 4 + 256;
twAssert($cips < $L['pending_items_per_session'], 'control-элементы оставляют место данным (сессия)');
twAssert($cig < $L['pending_items_global'], 'control-элементы оставляют место данным (глобально)');
twAssert($cips * $cfc <= $L['control_bytes_per_session'], 'control_bytes_per_session покрывает фреймы');
twAssert($cig * $cfc <= $L['control_bytes_global'], 'control_bytes_global покрывает фреймы');
$uplink = $L['max_frames_per_body'] * 256 + $L['max_body_bytes'];
$minDown = 8 + 1 + 256;
twAssert($L['control_bytes_per_session'] + $uplink + $minDown <= $L['pending_bytes_per_session'],
    'сессия вмещает uplink-батч и downlink-прогресс');
twAssert($cips + $L['max_frames_per_body'] + 1 <= $L['pending_items_per_session'],
    'элементы сессии вмещают uplink-батч');
twAssert($L['control_bytes_global'] + $uplink + $minDown <= $L['pending_bytes_global'],
    'глобальные байты вмещают uplink-батч');
twAssert($cig + $L['max_frames_per_body'] + 1 <= $L['pending_items_global'],
    'глобальные элементы вмещают uplink-батч');

// WebSocket: подбюджет и ёмкость соединений (проверяется, когда WS в наборе).
twAssert(1 <= $L['websocket_admission_watermark_pct']
    && $L['websocket_admission_watermark_pct'] < $L['websocket_eviction_watermark_pct']
    && $L['websocket_eviction_watermark_pct'] < 100, 'watermark-и WebSocket упорядочены');
twAssert($L['carrier_batch_bytes'] <= 2097152, 'WebSocket требует carrier_batch_bytes <= 2 MiB');
twAssert($L['websocket_http_connection_reserve'] > 0
    && $L['websocket_http_connection_reserve'] < $L['max_http_connections'],
    'резерв обычных HTTP-соединений в допустимом диапазоне');
$wsCap = $L['max_http_connections'] - $L['websocket_http_connection_reserve'];
twAssert($L['max_websocket_evictions_in_flight'] <= $wsCap, 'вытеснений не больше ёмкости WS');
$minProgress = ($L['carrier_batch_bytes'] + 14) * 2 + (64 * 1024 * 2 + 4096);
twAssert($L['websocket_bytes_global'] >= $minProgress,
    'websocket_bytes_global сохраняет чтение и запись одного сокета');
$queueProgress = $L['max_body_bytes'] + $L['max_frames_per_body'] * 256 + $L['carrier_batch_bytes'];
twAssert($L['websocket_bytes_global']
    <= $L['pending_bytes_global'] - $L['control_bytes_global'] - $queueProgress,
    'websocket_bytes_global оставляет прогресс очередям');

// Кандидаты предъявляют требования к числу handler'ов.
twAssert($L['max_http_handlers'] >= 2, 'https требует max_http_handlers >= 2');
twAssert($L['max_http_handlers'] >= 4, 'https-lanes требует max_http_handlers >= 4');
twAssert($L['max_carrier_learning_entries'] >= 3, 'обучение требует >= 3 записей');

// Профилей не больше, чем режет бот: иначе telemt откажет в загрузке конфига.
twAssert($L['max_profiles'] >= Bot::TELEMT_WEB_MAX_PROFILES,
    'max_profiles не ниже лимита, по которому бот режет список');

// Главная арифметика: заявленный envelope обязан покрыть все резервации.
$idx  = $L['debug_records_capacity'] * 8;
$dbg  = $L['debug_bytes_global'] + $idx * 2 + 2 * 4 * 1024 * 1024;
$lane = ($L['max_streams_per_session'] + $L['max_tombstones_per_session'] + 1)
    * $L['max_sessions_global'] * 512;
$reserved = $L['pending_bytes_global'] + $L['max_body_bytes_global'] + $L['max_static_bytes']
    + $idx + 2 * 8 * 1024 * 1024 + $dbg + $L['max_carrier_learning_entries'] * 512
    + $lane + $L['max_http_connections'] * $L['max_header_bytes'];
twAssert($reserved <= $L['memory_envelope_bytes'],
    sprintf('резервации %.1f MiB влезают в envelope %.1f MiB',
        $reserved / 1048576, $L['memory_envelope_bytes'] / 1048576));
twAssert($L['memory_envelope_bytes'] <= 4 * 1024 * 1024 * 1024, 'envelope не больше 4 GiB');
// Ради чего всё это: потолок telemt обязан быть НИЖЕ лимита cgroup, иначе
// раньше backpressure сработает OOM-killer и убьёт весь telemt.
$compose = file_get_contents(__DIR__ . '/../docker-compose.yml');
preg_match('~\n    telemt:.*?\n        mem_limit: (\d+)m~s', $compose, $mm);
twAssert((bool) $mm, 'mem_limit сервиса telemt найден в compose');
if ($mm) {
    twAssert($L['memory_envelope_bytes'] < (int) $mm[1] * 1048576,
        "envelope ниже mem_limit контейнера ({$mm[1]}m)");
}

// ── 12. Самолечение: сначала снимаем негоциацию, и только потом весь WEB ────
// Ключи web.carriers есть лишь с 3.5.4. Меню проверяет версию в момент
// нажатия, но образ мог уехать назад позже — ронять из-за этого весь WEB не за
// что, конфиг без carriers валиден для любого 3.5.x.
class TelemtNegotiationHealBot extends TelemtHealTestBot
{
    // Результаты последовательных проб pgrep: '' — не поднялся, '250' — живой.
    public array $probeResults = [];

    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
    {
        $this->sshCalls[] = $cmd;
        if (str_contains($cmd, 'while [ $i -lt 3 ]')) {
            $this->probes++;
            return array_shift($this->probeResults) ?? '';
        }
        return '';
    }
}
$mkNeg = static function (array $probeResults) use ($mk): TelemtNegotiationHealBot {
    $n = (new ReflectionClass(TelemtNegotiationHealBot::class))->newInstanceWithoutConstructor();
    $n->key = 'test-bot-key';
    $n->ip  = '203.0.113.10';
    $n->probeResults = $probeResults;
    $n->pacFake = ['telemt_web_negotiation' => 'full'] + $mk()->pacFake;
    return $n;
};

// Не поднялся с негоциацией, поднялся без неё — WEB сохранён.
$n = $mkNeg(['', '250']);
$n->restartTelemt();
twAssert($n->telemtWebNegotiationOf($n->pacFake) === 'off', 'негоциация снята');
twAssert(!empty($n->pacFake['telemt_web']), 'а сам WEB остался включён');
twAssert(count($n->tomls) === 2, 'конфиг переписан один раз: ' . count($n->tomls));
twAssert(str_contains($n->tomls[0], 'carriers = ['), 'первый конфиг был с carriers');
twAssert(!str_contains($n->tomls[1], 'carriers = ['), 'второй — уже без них');
twAssert(str_contains($n->tomls[1], '[web]'), 'но секция [web] на месте');
twAssert($n->nginxReloads === 0, 'блок #-tgweb остаётся: WEB-листенер никуда не делся');

// Не поднялся и без негоциации — срабатывает прежний откат всего WEB.
$n = $mkNeg(['', '']);
$n->restartTelemt();
twAssert($n->telemtWebNegotiationOf($n->pacFake) === 'off', 'негоциация снята на первой ступени');
twAssert(empty($n->pacFake['telemt_web']), 'WEB выключен на второй');
twAssert(count($n->tomls) === 3, 'три конфига: с негоциацией, без неё, без WEB');
twAssert(!str_contains($n->tomls[2], '[web]'), 'последний — без [web]');
twAssert(count(array_filter($n->sshCalls, fn($c) => str_starts_with($c, 'telemt run'))) === 3,
    'telemt запускался трижды');
twAssert($n->nginxReloads === 1, 'nginx перегенерирован вместе с уходом [web]');

// Поднялся сразу — ни одной лишней ступени.
$n = $mkNeg(['250']);
$n->restartTelemt();
twAssert($n->telemtWebNegotiationOf($n->pacFake) === 'full', 'рабочая негоциация не трогается');
twAssert(count($n->tomls) === 1, 'конфиг переписан один раз');
twAssert($n->probes === 1, 'проба одна');

if ($failed) {
    echo "telemt_web_test FAILED ($failed)\n";
    exit(1);
}
echo "telemt_web_test OK\n";
