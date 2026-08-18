<?php

// TeleMT: 43 функции и 361 упоминание в bot.php при одной строке проверок во
// всём каталоге тестов (аудит AUDIT-2026-08-18-06-code-quality.md). Класс кода
// ровно такой, где ошибка тихая: неверный префикс secret даёт ссылку, которую
// Telegram примет, но прокси не подключится, и по симптомам это не отличить от
// сетевой проблемы.
//
// Формат secret зависит от режима:
//   classic = <hex32>
//   secure  = dd<hex32>
//   tls     = ee<hex32><домен в hex>

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function tmAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

// Заглушка: pac.json в памяти, сеть и контейнеры не трогаем.
class TelemtTestBot extends Bot
{
    public array $pacFake  = [];
    public int   $restarts = 0;
    public string $srvDomain = 'vpn.example';

    public function getPacConf()
    {
        return $this->pacFake;
    }

    public function setPacConf(array $conf)
    {
        $this->pacFake = $conf;
        return true;
    }

    public function restartTelemt()
    {
        $this->restarts++;
        return true;
    }

    public function getDomain($cdn = false)
    {
        return $this->srvDomain;
    }

    public function getPorts()
    {
        return ['telemt' => ['port' => 8443]];
    }
}

$mk = static function (string $mode, array $users = ['bob' => 'aabbccddeeff00112233445566778899']): TelemtTestBot {
    $b = (new ReflectionClass(TelemtTestBot::class))->newInstanceWithoutConstructor();
    $b->pacFake = [
        'telemt_mode'   => $mode,
        'telemt_domain' => 'www.google.com',
        'telemt_users'  => $users,
    ];
    return $b;
};

$q = static function (string $link): array {
    parse_str((string) parse_url($link, PHP_URL_QUERY), $out);
    return $out;
};

$secret = 'aabbccddeeff00112233445566778899';

// ── 1. Формат secret по режимам ─────────────────────────────────────────────
$p = $q($mk('classic')->linkTelemt('bob'));
tmAssert($p['secret'] === $secret, 'classic: секрет как есть — ' . $p['secret']);

$p = $q($mk('secure')->linkTelemt('bob'));
tmAssert($p['secret'] === "dd$secret", 'secure: префикс dd');

$p = $q($mk('tls')->linkTelemt('bob'));
tmAssert($p['secret'] === 'ee' . $secret . bin2hex('www.google.com'),
    'tls: префикс ee + секрет + домен в hex');
tmAssert(str_ends_with($p['secret'], bin2hex('www.google.com')),
    'домен Fake-TLS уезжает в конец секрета именно в hex');

// Неизвестный режим — это tls, а не пустая ссылка.
$p = $q($mk('чепуха')->linkTelemt('bob'));
tmAssert(str_starts_with($p['secret'], 'ee'), 'неизвестный режим трактуется как tls');

// Домен по умолчанию, когда telemt_domain не задан.
$b = $mk('tls');
unset($b->pacFake['telemt_domain']);
$p = $q($b->linkTelemt('bob'));
tmAssert(str_ends_with($p['secret'], bin2hex('www.google.com')), 'дефолтный домен Fake-TLS подставлен');

// ── 2. Сервер и порт, в том числе через relay ───────────────────────────────
$p = $q($mk('classic')->linkTelemt('bob'));
tmAssert($p['server'] === 'vpn.example' && $p['port'] === '8443', 'origin: домен и порт установки');

$p = $q($mk('classic')->linkTelemt('bob', ['address' => 'relay.example']));
tmAssert($p['server'] === 'relay.example' && $p['port'] === '8443',
    'relay без своего порта наследует порт origin');

$p = $q($mk('classic')->linkTelemt('bob', ['address' => 'relay.example', 'port' => '9443']));
tmAssert($p['server'] === 'relay.example' && $p['port'] === '9443', 'явный порт relay побеждает');

$p = $q($mk('classic')->linkTelemt('bob', [
    'address' => 'relay.example',
    'portmap' => ['8443' => '7443'],
]));
tmAssert($p['port'] === '7443', 'portmap отображает порт origin');

// Секрет и домен Fake-TLS через relay не меняются — та же идея, что у applyRelay.
$direct = $q($mk('tls')->linkTelemt('bob'))['secret'];
$viaRl  = $q($mk('tls')->linkTelemt('bob', ['address' => 'relay.example']))['secret'];
tmAssert($direct === $viaRl, 'relay подменяет только адрес и порт, не секрет');

// Пустой адрес relay — это «нет relay», а не пустой server в ссылке.
$p = $q($mk('classic')->linkTelemt('bob', ['address' => '']));
tmAssert($p['server'] === 'vpn.example', 'relay с пустым адресом игнорируется');

// ── 3. Ссылка целиком ───────────────────────────────────────────────────────
$link = $mk('classic')->linkTelemt('bob');
tmAssert(str_starts_with($link, 'tg://proxy?'), 'схема ссылки tg://proxy');
tmAssert(!str_contains($link, ' '), 'в ссылке нет пробелов (RFC3986-кодирование)');

// ── 4. normalizeTelemtUsers ─────────────────────────────────────────────────
$b = $mk('classic', ['bob' => 'ЗАВЕДОМО НЕ HEX']);
[$conf, $changed] = $b->normalizeTelemtUsers($b->pacFake);
tmAssert($changed, 'битый секрет перевыпускается');
tmAssert((bool) preg_match('~^[a-f0-9]{32}$~', $conf['telemt_users']['bob']),
    'новый секрет — 32 hex-символа: ' . $conf['telemt_users']['bob']);

$b = $mk('classic', ['bob' => strtoupper($secret)]);
[$conf, $changed] = $b->normalizeTelemtUsers($b->pacFake);
tmAssert($conf['telemt_users']['bob'] === $secret && $changed,
    'регистр приводится к нижнему');

// Дубликаты недопустимы: два клиента с одним секретом неотличимы для прокси.
$b = $mk('classic', ['bob' => $secret, 'eve' => $secret]);
[$conf] = $b->normalizeTelemtUsers($b->pacFake);
tmAssert($conf['telemt_users']['bob'] !== $conf['telemt_users']['eve'],
    'одинаковые секреты разводятся');

// Тумблер включённости не должен переживать удаление пользователя.
$b = $mk('classic', ['bob' => $secret]);
$b->pacFake['telemt_user_enabled'] = ['bob' => 0, 'ghost' => 0];
[$conf, $changed] = $b->normalizeTelemtUsers($b->pacFake);
tmAssert(!array_key_exists('ghost', $conf['telemt_user_enabled']) && $changed,
    'осиротевший тумблер снят');

// ── 5. Режимы и политика неизвестного SNI ───────────────────────────────────
$b = $mk('classic');
tmAssert($b->telemtModeOf([]) === 'tls', 'режим по умолчанию — tls');
tmAssert($b->telemtModeOf(['telemt_mode' => 'secure']) === 'secure', 'заданный режим сохраняется');
tmAssert($b->telemtModeOf(['telemt_mode' => 'нет такого']) === 'tls', 'мусорный режим → tls');
tmAssert($b->telemtSniOf([]) === 'reject_handshake', 'политика SNI по умолчанию');
tmAssert($b->telemtSniOf(['telemt_unknown_sni' => 'mask']) === 'mask', 'заданная политика SNI');
tmAssert($b->telemtSniOf(['telemt_unknown_sni' => 'нет']) === 'reject_handshake', 'мусорная политика → дефолт');

// ── 6. Секреты уникальны ────────────────────────────────────────────────────
$b   = $mk('classic');
$s1  = $b->telemtSecret();
$s2  = $b->telemtSecret();
tmAssert($s1 !== $s2 && preg_match('~^[a-f0-9]{32}$~', $s1) && preg_match('~^[a-f0-9]{32}$~', $s2),
    'telemtSecret выдаёт разные 32-hex значения');

// ── 7. Длина callback_data (ВЫСОКИЙ того же отчёта) ────────────────────────
// Имя пользователя целиком уезжает в callback_data четырёх кнопок при лимите
// Telegram в 64 байта; превышение — BUTTON_DATA_INVALID и НЕОТКРЫВАЮЩЕЕСЯ меню.
$maxName = 20;
foreach (['/telemtToggleUser ', '/telemtRegen ', '/telemtDelUser '] as $prefix) {
    tmAssert(strlen($prefix) + $maxName <= 64, "кнопка «{$prefix}» влезает в лимит");
}
tmAssert(strlen('/telemtQr ') + $maxName + 1 + 32 <= 64,
    'кнопка QR с именем relay (до 32 символов) тоже влезает');

if ($failed) {
    echo "telemt_test FAILED ($failed)\n";
    exit(1);
}
echo "telemt_test OK\n";
