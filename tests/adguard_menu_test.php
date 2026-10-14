<?php

// Меню AdGuard: проверка ввода, сохранность конфига, сведение клиентов с
// пользователями Xray, настройки через API и предупреждения безопасности.

require_once __DIR__ . '/../app/bot.php';

// Хостовый CI запускает тесты без ext-yaml (в образе PHP расширение есть):
// JSON-подмена симметрична, функции работают с уже разобранными массивами.
if (!function_exists('yaml_parse_file')) {
    function yaml_parse_file(string $path) { return json_decode((string) file_get_contents($path), true); }
}
if (!function_exists('yaml_emit_file')) {
    function yaml_emit_file(string $path, $data) { return false !== file_put_contents($path, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)); }
}

$failed = 0; $checks = 0;
function adgAssert(bool $ok, string $what): void
{
    global $failed, $checks;
    $checks++;
    if (!$ok) { $failed++; echo "FAIL: $what\n"; }
}

class AdguardTestBot extends Bot
{
    public ?array $xrayFake = ['inbounds' => [['settings' => ['clients' => []]]]];
    public int $stops = 0;
    public int $starts = 0;
    public array $sent = [];
    public array $screens = [];
    public array $apiCalls = [];
    public array $apiReply = [];
    public bool $apiDown = false;
    public bool $dotPublished = false;

    public function getXray() { return $this->xrayFake; }
    public function stopAd() { $this->stops++; return ''; }
    public function startAd() { $this->starts++; return ''; }
    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false) { $this->sent[] = $text; return []; }
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML') { $this->screens[] = [$text, is_array($button) ? $button : []]; }
    public function menu($type = false, $arg = false, $return = false) { $this->screens[] = ['menu ' . $type, []]; }
    public function i18n(string $menu): string { return $menu; }
    public function adguardApi(string $method, string $path, ?array $body = null, int $timeout = 8): ?array
    {
        $this->apiCalls[] = [$method, $path, $body];
        $this->adguardApiError = $this->apiDown ? 'AdGuard не отвечает' : '';
        return $this->apiDown ? null : ($this->apiReply["$method $path"] ?? []);
    }
    public function getDomain($alias = false) { return 'vpn.example.test'; }
    public function getHashBot($notset = false) { return 'h4sh'; }
    public function nginxGetTypeCert() { return false; }
    public function adguardVersion(): array { return ['running' => 'v0.107.79', 'pinned' => 'v0.107.79']; }
    public function getPorts() { return ['ad' => ['port' => '853', 'enable' => $this->dotPublished]]; }
    public function cloakNginx() {}
}

$dir = sys_get_temp_dir() . '/vpnbot-adg-' . bin2hex(random_bytes(4));
mkdir($dir, 0700);
$new = function () use ($dir): AdguardTestBot {
    $bot = (new ReflectionClass(AdguardTestBot::class))->newInstanceWithoutConstructor();
    $bot->key = '123456:AAHtestBotTokenValue';
    $bot->adguard = "$dir/AdGuardHome.yaml";
    $bot->pac = "$dir/pac.json";
    $bot->ip = '192.0.2.1';
    $bot->input = ['chat' => 1, 'from' => 1, 'message_id' => 2, 'callback_id' => 'x', 'username' => 'adm'];
    return $bot;
};
$yaml = fn() => yaml_parse_file("$dir/AdGuardHome.yaml");
$pac  = fn() => json_decode(file_get_contents("$dir/pac.json"), true);
$base = ['http' => ['address' => '0.0.0.0:80'], 'users' => [['name' => 'admin', 'password' => 'old-hash']],
    'dns' => ['upstream_dns' => ['tls://1.1.1.1'], 'ratelimit' => 20], 'filtering' => ['safe_search' => ['enabled' => false]]];

try {
    // ── Проверка ввода ──────────────────────────────────────────────────────
    foreach (['my-key', 'a', 'abc123', str_repeat('a', 63)] as $id) adgAssert(Bot::adguardClientIdValid($id), "ClientID отвергнут: $id");
    foreach (['', 'My Key!', 'UPPER', '-lead', 'trail-', 'a_b', 'a.b', 'ключ', "a\nb", str_repeat('a', 64)] as $id) {
        adgAssert(!Bot::adguardClientIdValid($id), 'ClientID принят: ' . json_encode($id));
    }
    adgAssert(Bot::adguardPasswordValid('pass<&>word') && Bot::adguardPasswordValid(str_repeat('p', 72)), 'обычный пароль отвергнут');
    foreach (['', 'short', str_repeat('p', 73), "pass\nword1", "pass\0word1"] as $pw) adgAssert(!Bot::adguardPasswordValid($pw), 'пароль принят: ' . json_encode($pw));
    foreach (['1.1.1.1', '2606:4700:4700::1111', 'tls://dns.example', 'https://dns.example/dns-query', 'h3://dns.example/dns-query',
        'quic://dns.example', 'sdns://AQIAAAAAAAAA', 'dns.example:5353', '[/example.org/]9.9.9.9', '[/a.test/b.test/]tls://dns.example', '[/local/]#'] as $u) {
        adgAssert(Bot::adguardUpstreamValid($u), "апстрим отвергнут: $u");
    }
    foreach (['', '#', 'bogus://x', 'tls://', "1.1.1.1\n8.8.8.8", '1.1.1.1 8.8.8.8', '[/example.org/]', '[/exa mple/]1.1.1.1', 'tls://a"b', '<b>', 'a\\b'] as $u) {
        adgAssert(!Bot::adguardUpstreamValid($u), 'апстрим принят: ' . json_encode($u));
    }

    // ── Клиенты: настройки из панели переживают правку пользователя ─────────
    $doh = static fn(string $uid) => 'doh-' . substr(hash('sha256', $uid), 0, 16);
    $u1 = '11111111-1111-4111-8111-111111111111'; $u2 = '22222222-2222-4222-8222-222222222222'; $gone = '33333333-3333-4333-8333-333333333333';
    $existing = [
        ['name' => 'old-name', 'uid' => $u1, 'ids' => [$doh($u1), '192.0.2.50'], 'filtering_enabled' => true, 'use_global_settings' => false,
            'blocked_services' => ['ids' => ['tiktok']], 'upstreams' => ['tls://family.example']],
        ['name' => 'removed', 'uid' => $gone, 'ids' => [$doh($gone)]],
        ['name' => 'legacy-removed', 'uid' => '44444444-4444-4444-8444-444444444444', 'ids' => ['0123456789abcdef']],
        ['name' => 'kids-tablet', 'uid' => '55555555-5555-4555-8555-555555555555', 'ids' => ['192.0.2.77'], 'parental_enabled' => true],
        ['name' => 'bob', 'uid' => '66666666-6666-4666-8666-666666666666', 'ids' => ['192.0.2.78']],
        ['name' => 'no-ids', 'uid' => '77777777-7777-4777-8777-777777777777'],
    ];
    $merged = Bot::adguardMergeClients($existing, [['id' => $u1, 'email' => 'alice'], ['id' => $u2, 'email' => 'bob'], ['id' => $u2, 'email' => 'dup']], $doh, 'UTC');
    $byName = array_column($merged, null, 'name');
    adgAssert(array_keys($byName) === ['alice', 'bob', 'kids-tablet'], 'состав клиентов: ' . json_encode(array_keys($byName)));
    adgAssert($byName['alice']['filtering_enabled'] === true && $byName['alice']['use_global_settings'] === false
        && $byName['alice']['blocked_services']['ids'] === ['tiktok'] && $byName['alice']['upstreams'] === ['tls://family.example'], 'личные настройки пользователя стёрты');
    adgAssert($byName['alice']['ids'] === [$doh($u1), '192.0.2.50'] && $byName['alice']['uid'] === $u1, 'идентификаторы пользователя: ' . json_encode($byName['alice']['ids']));
    adgAssert($byName['bob']['uid'] === $u2 && $byName['bob']['ids'] === [$doh($u2)] && $byName['bob']['use_global_settings'] === true, 'новый пользователь заведён не по умолчанию');
    adgAssert($byName['kids-tablet']['parental_enabled'] === true && $byName['kids-tablet']['ids'] === ['192.0.2.77'], 'клиент, заведённый в панели, потерян');
    adgAssert(Bot::adguardMergeClients($merged, [['id' => $u1, 'email' => 'alice'], ['id' => $u2, 'email' => 'bob']], $doh, 'UTC') === $merged, 'повторное сведение меняет список');

    // ── adguardXrayClients: список разрешённых и лишние перезапуски ─────────
    $bot = $new();
    $id1 = $bot->dohClientId($u1); $id2 = $bot->dohClientId($u2); $idGone = $bot->dohClientId($gone);
    file_put_contents($bot->pac, json_encode(['adpswd' => 'secret-pass']));
    yaml_emit_file($bot->adguard, $base + ['clients' => ['persistent' => []]]);
    $bot->xrayFake['inbounds'][0]['settings']['clients'] = [['id' => $u1, 'email' => 'alice']];
    $bot->adguardXrayClients();
    adgAssert($bot->stops === 1 && $bot->starts === 1 && $yaml()['clients']['persistent'][0]['ids'] === [$id1], 'клиент не записан');
    adgAssert(empty($yaml()['dns']['allowed_clients']) && $yaml()['dns']['upstream_dns'] === ['tls://1.1.1.1'], 'пустой список разрешённых должен остаться пустым, апстримы — на месте');
    $bot->adguardXrayClients();
    adgAssert($bot->stops === 1 && $bot->starts === 1, 'AdGuard перезапущен без изменений');
    // Список ведётся: новый пользователь добавляется, удалённый убирается, сети и ключ остаются.
    $c = $yaml(); $c['dns']['allowed_clients'] = ['10.10.0.0/24', 'my-key', $id1, $idGone]; yaml_emit_file($bot->adguard, $c);
    $bot->xrayFake['inbounds'][0]['settings']['clients'][] = ['id' => $u2, 'email' => 'bob'];
    $bot->adguardXrayClients();
    adgAssert($yaml()['dns']['allowed_clients'] === ['10.10.0.0/24', 'my-key', $id1, $id2], 'список разрешённых: ' . json_encode($yaml()['dns']['allowed_clients']));
    // Нечитаемые файлы: ничего не пишется и не перезапускается.
    $stops = $bot->stops; file_put_contents($bot->adguard, '');
    $bot->adguardXrayClients(); $bot->adguardSync();
    adgAssert($bot->stops === $stops && file_get_contents($bot->adguard) === '', 'нечитаемый конфиг перезаписан');
    adgAssert($bot->adguardConf() === null, 'пустой файл принят за конфиг');
    yaml_emit_file($bot->adguard, $base); $bot->xrayFake = null;
    $bot->adguardXrayClients();
    adgAssert($bot->stops === $stops && $yaml() == $base, 'при нечитаемом xray.json конфиг AdGuard изменён');

    // ── Пароль ──────────────────────────────────────────────────────────────
    $bot = $new(); yaml_emit_file($bot->adguard, $base); file_put_contents($bot->pac, json_encode(['adpswd' => 'secret-pass', 'domain' => 'vpn.example.test']));
    $bot->chpsswd('short');
    adgAssert($pac()['adpswd'] === 'secret-pass' && $yaml()['users'][0]['password'] === 'old-hash' && $bot->stops === 0 && count($bot->sent) === 1, 'короткий пароль принят');
    $bot->chpsswd(" new<&>pass \n");
    adgAssert($pac()['adpswd'] === 'new<&>pass' && password_verify('new<&>pass', $yaml()['users'][0]['password']) && $pac()['domain'] === 'vpn.example.test', 'пароль не сменён');
    adgAssert($yaml()['dns']['upstream_dns'] === ['tls://1.1.1.1'], 'смена пароля задела остальной конфиг');
    // Хеш — bcrypt (другого AdGuardHome не понимает), файл с ним закрыт от посторонних.
    adgAssert(str_starts_with($yaml()['users'][0]['password'], '$2y$') && !password_verify('new<&>pass ', $yaml()['users'][0]['password']), 'хеш пароля не bcrypt');
    clearstatcache();
    adgAssert((fileperms($bot->adguard) & 0777) === 0600 && glob("$dir/*.tmp") === [], 'конфиг с хешем пароля читаем посторонним либо остался временный файл');
    adgAssert(!str_contains(json_encode($bot->sent) . json_encode($bot->screens), 'new<&>pass') && !str_contains(json_encode($bot->sent), 'short'), 'пароль попал в сообщения');
    chmod($bot->adguard, 0644); $bot->chpsswd('second-password'); clearstatcache();
    adgAssert((fileperms($bot->adguard) & 0777) === 0600 && $pac()['adpswd'] === 'second-password', 'запись не закрыла файл, открытый прежде');
    $bot->chpsswd('new<&>pass');
    file_put_contents($bot->adguard, '');
    $bot->chpsswd('another-password');
    adgAssert($pac()['adpswd'] === 'new<&>pass' && file_get_contents($bot->adguard) === '', 'пароль сохранён при нечитаемом конфиге AdGuard');

    // ── ClientID ────────────────────────────────────────────────────────────
    $bot = $new(); yaml_emit_file($bot->adguard, $base + []); file_put_contents($bot->pac, json_encode(['adpswd' => 'secret-pass', 'adguardkey' => 'old-key']));
    $c = $base; $c['dns']['allowed_clients'] = ['10.10.0.0/24', 'old-key']; yaml_emit_file($bot->adguard, $c);
    $bot->setAdKey('My Key!');
    adgAssert($pac()['adguardkey'] === 'old-key' && $yaml()['dns']['allowed_clients'] === ['10.10.0.0/24', 'old-key'] && count($bot->sent) === 1, 'неверный ClientID сохранён');
    $bot->setAdKey(' New-Key ');
    adgAssert($pac()['adguardkey'] === 'new-key' && $yaml()['dns']['allowed_clients'] === ['10.10.0.0/24', 'new-key'] && $bot->stops === 1, 'ClientID не заменён в списке разрешённых');
    $bot->setAdKey('-');
    adgAssert($pac()['adguardkey'] === '' && $yaml()['dns']['allowed_clients'] === ['10.10.0.0/24'], 'ClientID не убран');
    // Ключ, сохранённый прежней версией без проверки, в список не попадает.
    file_put_contents($bot->pac, json_encode(['adpswd' => 'secret-pass', 'adguardkey' => 'Bad Key!']));
    $bot->adgFillAllowedClients();
    adgAssert(!in_array('Bad Key!', $yaml()['dns']['allowed_clients'], true) && in_array('10.10.0.0/24', $yaml()['dns']['allowed_clients'], true), 'неверный ключ попал в allowed_clients');

    // ── Апстримы ────────────────────────────────────────────────────────────
    $bot = $new(); yaml_emit_file($bot->adguard, $base); file_put_contents($bot->pac, json_encode(['adpswd' => 'secret-pass']));
    $bot->upstream('bogus://x');
    $bot->upstream('tls://1.1.1.1');
    adgAssert($yaml()['dns']['upstream_dns'] === ['tls://1.1.1.1'] && $bot->stops === 0 && count($bot->sent) === 2, 'неверный или повторный апстрим принят');
    $bot->apiReply['POST test_upstream_dns'] = ['tls://192.0.2.1:853' => "couldn't communicate with upstream <x>"];
    $bot->sent = [];
    $bot->upstream('tls://192.0.2.1');
    adgAssert($yaml()['dns']['upstream_dns'] === ['tls://1.1.1.1'] && str_contains($bot->sent[0] ?? '', '&lt;x&gt;'), 'неотвечающий апстрим добавлен: ' . json_encode($bot->sent));
    $bot->apiReply['POST test_upstream_dns'] = ['9.9.9.9:53' => 'WARNING: wrong response'];
    $bot->upstream(' [/example.org/]9.9.9.9 ');
    adgAssert($yaml()['dns']['upstream_dns'] === ['tls://1.1.1.1', '[/example.org/]9.9.9.9'] && $bot->stops === 1, 'рабочий апстрим не добавлен');
    // AdGuard не запущен — проверить нечем, добавление не блокируется.
    $bot->apiDown = true;
    $bot->upstream('tls://8.8.8.8');
    adgAssert(count($yaml()['dns']['upstream_dns']) === 3, 'без ответа AdGuard добавление заблокировано');
    $bot->delupstream(7);
    adgAssert(count($yaml()['dns']['upstream_dns']) === 3, 'удаление по устаревшему номеру что-то удалило');
    $bot->delupstream(1);
    adgAssert($yaml()['dns']['upstream_dns'] === ['tls://1.1.1.1', 'tls://8.8.8.8'], 'апстрим не удалён');

    // ── Настройки через API: в запрос уходит только предложенное меню ───────
    $bot = $new(); yaml_emit_file($bot->adguard, $base); file_put_contents($bot->pac, json_encode(['adpswd' => 'secret-pass']));
    $bot->apiReply = ['GET status' => ['protection_enabled' => true], 'GET dns_info' => ['ratelimit' => 20, 'upstream_mode' => ''],
        'GET querylog/config' => ['enabled' => true, 'interval' => 7776000000, 'anonymize_client_ip' => false, 'ignored' => ['skip.test']],
        'GET stats/config' => ['enabled' => true, 'interval' => 86400000, 'ignored' => []],
        'GET safesearch/status' => ['enabled' => false, 'google' => true, 'yandex' => true]];
    $writes = fn() => array_values(array_filter($bot->apiCalls, fn($call) => $call[0] !== 'GET'));
    foreach (Bot::ADG_RATE_LIMITS as $limit) {
        $bot->apiCalls = []; $bot->adgSet('rate', (string) $limit);
        adgAssert($writes() === [['POST', 'dns_config', ['ratelimit' => $limit]]], "лимит $limit не отправлен");
    }
    adgAssert(Bot::ADG_RATE_LIMITS === [0, 20, 100, 300, 500, 700, 900, 1100], 'набор лимитов изменён');
    foreach ([['rate', '250'], ['rate', '-1'], ['mode', 'bogus'], ['qlog', '5'], ['stats', '365'], ['protection', '999'], ['safesearch', 'maybe'], ['anon', '1']] as [$key, $value]) {
        $bot->apiCalls = []; $bot->sent = []; $bot->adgSet($key, $value);
        adgAssert($writes() === [] && count($bot->sent) === 1, "значение вне списка ушло в AdGuard: $key $value");
    }
    $bot->apiCalls = []; $bot->adgSet('qlog', '7');
    adgAssert($writes() === [['PUT', 'querylog/config/update', ['enabled' => true, 'interval' => 604800000, 'ignored' => ['skip.test'], 'anonymize_client_ip' => false]]], 'срок журнала: ' . json_encode($writes()));
    $bot->apiCalls = []; $bot->adgSet('qlog', '0');
    adgAssert($writes()[0][2]['enabled'] === false && $writes()[0][2]['interval'] === 7776000000, 'выключение журнала меняет срок');
    $bot->apiCalls = []; $bot->adgSet('stats', '30');
    adgAssert($writes() === [['PUT', 'stats/config/update', ['enabled' => true, 'interval' => 2592000000, 'ignored' => []]]], 'срок статистики: ' . json_encode($writes()));
    $bot->apiCalls = []; $bot->adgSet('anon', 'on');
    adgAssert($writes()[0][2] === ['enabled' => true, 'interval' => 7776000000, 'ignored' => ['skip.test'], 'anonymize_client_ip' => true], 'скрытие IP задело остальные настройки журнала');
    $bot->apiCalls = []; $bot->adgSet('mode', 'parallel');
    adgAssert($writes() === [['POST', 'dns_config', ['upstream_mode' => 'parallel']]], 'режим апстримов не отправлен');
    $bot->apiCalls = []; $bot->adgSet('protection', '10');
    adgAssert($writes() === [['POST', 'protection', ['enabled' => false, 'duration' => 600000]]], 'пауза защиты не отправлена');
    $bot->apiCalls = []; $bot->adgSet('safesearch', 'on');
    adgAssert($writes() === [['PUT', 'safesearch/settings', ['enabled' => true, 'google' => true, 'yandex' => true]]], 'безопасный поиск: ' . json_encode($writes()));
    adgAssert(Bot::adgRetentionDays(['enabled' => true, 'interval' => 604800000]) === 7 && Bot::adgRetentionDays(['enabled' => false, 'interval' => 604800000]) === 0
        && Bot::adgRetentionDays(null) === 0, 'срок хранения читается неверно');
    // Экран настроек и подменю.
    $bot->screens = []; $bot->adgSettings();
    $buttons = json_encode(end($bot->screens)[1], JSON_UNESCAPED_UNICODE);
    foreach (['/adgSet protection off', '/adgSet protection 10', '/adgSet safesearch on', '/adgSettings rate', '/adgSet mode parallel', '/adgSettings qlog', '/adgSettings stats', '/adgSet anon on'] as $want) {
        adgAssert(str_contains($buttons, $want), "нет кнопки $want");
    }
    adgAssert(str_contains($buttons, '✅ adg mode lb') && str_contains($buttons, '90 adg days'), 'текущие значения не отмечены: ' . $buttons);
    $bot->adgSettings('rate');
    $buttons = json_encode(end($bot->screens)[1], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    adgAssert(str_contains($buttons, '✅ 20/s') && str_contains($buttons, '/adgSet rate 1100') && str_contains($buttons, '/adgSet rate 0'), 'подменю лимита: ' . $buttons);
    foreach (end($bot->screens)[1] as $row) foreach ($row as $button) adgAssert(strlen($button['callback_data']) <= 64, 'длинные данные кнопки');
    $bot->apiDown = true; $bot->adgSettings(); $bot->adgStats();
    adgAssert(str_contains(end($bot->screens)[0], 'adg not responding'), 'нет сообщения при неотвечающем AdGuard');

    // ── Статистика ──────────────────────────────────────────────────────────
    $bot = $new(); yaml_emit_file($bot->adguard, $base); file_put_contents($bot->pac, json_encode(['adpswd' => 'secret-pass']));
    $bot->xrayFake['inbounds'][0]['settings']['clients'] = [['id' => $u1, 'email' => 'alice <admin>']];
    $bot->apiReply['GET stats'] = ['time_units' => 'hours', 'dns_queries' => array_fill(0, 24, 1), 'num_dns_queries' => 200, 'num_blocked_filtering' => 50,
        'avg_processing_time' => 0.0123, 'top_blocked_domains' => [['ads.<b>.test' => 30]], 'top_queried_domains' => [['example.org' => 90]],
        'top_clients' => [[$bot->dohClientId($u1) => 120], ['10.0.1.7' => 80]]];
    $bot->adgStats();
    $text = end($bot->screens)[0];
    adgAssert(str_contains($text, 'adg queries: 200') && str_contains($text, 'adg blocked: 50 (25%)') && str_contains($text, '12.3 ms'), 'сводка: ' . $text);
    adgAssert(str_contains($text, 'alice &lt;admin&gt;') && str_contains($text, '10.0.1.7') && str_contains($text, 'ads.&lt;b&gt;.test') && !str_contains($text, '<b>.test'), 'имена не подставлены или не экранированы');

    // ── Главное меню: экранирование и предупреждения ────────────────────────
    $bot = $new();
    $c = $base; $c['dns']['allowed_clients'] = []; yaml_emit_file($bot->adguard, $c);
    file_put_contents($bot->pac, json_encode(['adpswd' => 'p<a>&ss"word', 'adguardkey' => 'Bad <Key>']));
    $bot->apiReply = ['GET status' => ['protection_enabled' => false, 'protection_disabled_duration' => 540000], 'GET stats' => ['num_dns_queries' => 10, 'num_blocked_filtering' => 1]];
    $menu = $bot->adguardMenu();
    adgAssert(str_contains($menu['text'], 'p&lt;a&gt;&amp;ss&quot;word') && !str_contains($menu['text'], 'p<a>'), 'пароль в меню не экранирован');
    adgAssert(!str_contains($menu['text'], 'Bad <Key>'), 'неверный ClientID подставлен в адреса');
    adgAssert(str_contains($menu['text'], 'adg protection: off (9 min) ⚠️') && str_contains($menu['text'], 'adg queries: 10, adg blocked: 1 (10%)'), 'нет состояния защиты или сводки: ' . $menu['text']);
    adgAssert(str_contains($menu['text'], 'adg rate limit: 20/s') && !str_contains($menu['text'], 'adg dot open'), 'лимит не показан либо ложное предупреждение о DoT');
    $bot->dotPublished = true;
    adgAssert(str_contains($bot->adguardMenu()['text'], 'adg dot open'), 'нет предупреждения об открытом DoT');
    // Список разрешённых показывается целиком, у идентификаторов пользователей — имя.
    $bot->xrayFake['inbounds'][0]['settings']['clients'] = [['id' => $u1, 'email' => 'alice <admin>'], ['id' => $u2, 'email' => 'bob']];
    $legacyBob = $bot->legacyDohClientId($u2);
    $c['dns']['allowed_clients'] = array_merge(['10.10.0.0/24', 'my-key', $bot->dohClientId($u1), $legacyBob],
        array_map(fn($i) => sprintf('doh-%016x', $i), range(1, 300))); yaml_emit_file($bot->adguard, $c);
    $text = $bot->adguardMenu()['text'];
    adgAssert(!str_contains($text, 'adg dot open') && str_contains($text, 'my-key') && str_contains($text, sprintf('doh-%016x', 300)), 'список разрешённых показан не целиком');
    adgAssert(str_contains($text, $bot->dohClientId($u1) . ' — alice &lt;admin&gt;') && str_contains($text, "$legacyBob — bob"), 'у идентификаторов нет имён пользователей: ' . mb_substr($text, -800));
    $callbacks = json_encode($bot->adguardMenu()['data']);
    adgAssert(str_contains($callbacks, '/adgSettings') && str_contains($callbacks, '/adgStats') && str_contains($callbacks, '/menuhelp adguard 0'), 'нет кнопок настроек, статистики или справки');
    file_put_contents($bot->adguard, '');
    adgAssert(str_contains($bot->adguardMenu()['text'], 'не читается'), 'меню не сообщает о нечитаемом конфиге');

    // ── Образ: интерфейс официального выпуска ───────────────────────────────
    // Сборка «как в Makefile» берёт client_v2 — интерфейс канала edge; выпуски
    // release собираются с каталогом client.
    $dockerfile = (string) file_get_contents(__DIR__ . '/../dockerfile/adguard.dockerfile');
    adgAssert(str_contains($dockerfile, 'npm --prefix client ci') && str_contains($dockerfile, 'npm --prefix client run build-prod')
        && !preg_match('~--prefix\s+client_v2~', $dockerfile), 'образ AdGuard собирается не с интерфейсом официального выпуска');
    adgAssert(str_contains($dockerfile, 'go-security.sh') && str_contains($dockerfile, 'version.channel=release'), 'из сборки AdGuard пропали исправления Go или канал release');

    // ── Справка: кнопки на экранах, возврат туда, откуда открыта ────────────
    $bot = $new(); yaml_emit_file($bot->adguard, $base); file_put_contents($bot->pac, json_encode(['adpswd' => 'secret-pass']));
    $bot->adgSettings();
    adgAssert(str_contains(json_encode(end($bot->screens)[1]), '/menuhelp adguard 0 settings'), 'в настройках нет кнопки справки');
    adgAssert(mb_strlen(end($bot->screens)[0]) < 200, 'экран настроек снова перегружен подсказкой');
    $bot->adgSettings('rate');
    adgAssert(str_contains(json_encode(end($bot->screens)[1]), '/menuhelp adguard 0 rate'), 'в выборе лимита нет кнопки справки');
    $bot->adgStats();
    adgAssert(str_contains(json_encode(end($bot->screens)[1]), '/menuhelp adguard 0 statistics'), 'в статистике нет кнопки справки');
    foreach (['' => '/menu adguard', 'settings' => '/adgSettings', 'qlog' => '/adgSettings qlog', 'statistics' => '/adgStats', 'junk' => '/menu adguard'] as $ctx => $route) {
        adgAssert(($bot->menuHelpContent('adguard', $ctx)[1] ?? '') === $route, "справка из «{$ctx}» возвращает не туда");
    }
    $pages = $bot->menuHelpContent('adguard')[2];
    adgAssert(count($pages) >= 8, 'в справке AdGuard не хватает тем');
    foreach ($pages as $title => $body) {
        adgAssert($bot->messageTextLength("AdGuard → help\n\n<b>$title</b>\n\n$body") < 3500, "страница «{$title}» не влезает в сообщение");
        $tags = preg_replace('~</?(?:b|code)>~', '', $body);
        adgAssert(!str_contains($tags, '<') && !str_contains($tags, '>'), "в странице «{$title}» разметка, которую Telegram не примет");
        adgAssert(substr_count($body, '<b>') === substr_count($body, '</b>') && substr_count($body, '<code>') === substr_count($body, '</code>'), "в странице «{$title}» незакрытый тег");
    }
    adgAssert(strlen('/menuhelp adguard ' . count($pages) . ' statistics') <= 64, 'данные кнопки справки длиннее 64 байт');

    // ── Сброс — только с подтверждением ─────────────────────────────────────
    $bot = $new(); yaml_emit_file($bot->adguard, $base); file_put_contents($bot->pac, json_encode(['adpswd' => 'secret-pass']));
    $bot->adguardreset();
    adgAssert($bot->stops === 0 && str_contains(json_encode(end($bot->screens)[1]), '/adguardreset yes') && $yaml() == $base, 'сброс выполнен без подтверждения');
} finally {
    foreach (glob("$dir/*") ?: [] as $file) unlink($file);
    rmdir($dir);
}
echo $failed ? "adguard_menu_test FAILED ($failed из $checks)\n" : "adguard_menu_test OK ($checks проверок)\n";
exit($failed ? 1 : 0);
