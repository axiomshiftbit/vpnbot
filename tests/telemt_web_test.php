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
//   * carrier только https|https-lanes;
//   * профилей не больше web.limits.max_profiles (32).
// Плюс согласованность с nginx-шаблоном: порт апстрима и доверенный CIDR.

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
twAssert(str_contains($open, 'proxy_read_timeout 35s;'), 'таймаут больше long_poll_secs (25s)');
twAssert(str_contains($open, 'access_log off;'), 'access_log выключен: в query едут креденшелы');
twAssert(substr_count($open, '{') === substr_count($open, '}'), 'скобки блока сбалансированы');

if ($failed) {
    echo "telemt_web_test FAILED ($failed)\n";
    exit(1);
}
echo "telemt_web_test OK\n";
