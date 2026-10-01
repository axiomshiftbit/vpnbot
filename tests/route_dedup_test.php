<?php

// Семантическая дедупликация записей маршрутизации.
//
// Списки в pac.json — это ассоциативный массив «запись => вкл/выкл», поэтому
// раньше схлопывались только буквальные повторы. Записи, означающие одно и то
// же, но набранные по-разному (vk.com / domain:vk.com / VK.com / vk.com.,
// 1.2.3.4 / 1.2.3.4/32, 2001:DB8::1 / 2001:db8::1), копились в меню и уезжали
// в конфиги всех трёх ядер дважды.

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function dedupAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        echo "FAIL: $msg\n";
        $failed++;
    }
}

// intl есть в php-контейнере, но не всегда в CLI, которым гоняют тесты локально.
// Полифилл повторяет ровно то, что нужно этим кейсам (ASCII-имена не меняются),
// приём тот же, что в routes_list_test.php.
if (!function_exists('idn_to_ascii')) {
    echo "  (intl не загружен — punycode заменён полифиллом)\n";
    function idn_to_ascii($domain, $flags = 0, $variant = 1, &$idna_info = null)
    {
        return preg_match('~^[\x20-\x7e]*$~', $domain) ? strtolower($domain) : false;
    }
}

class RouteDedupTestBot extends Bot
{
    public array $pacFake  = [];
    public array $saved    = [];
    public array $sent     = [];
    public array $backCall = [];

    public function getPacConf()
    {
        return $this->pacFake;
    }

    public function setPacConf(array $conf)
    {
        $this->saved = $this->pacFake = $conf;
        return true;
    }

    public function datSync(bool $force = false, ?bool &$changed = null): array { return []; }
    public function xrayUpdateRules(?array $previousPac = null) { return true; }

    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false)
    {
        $this->sent[] = $text;
        return ['result' => ['message_id' => 1]];
    }

    public function i18n(string $menu): string
    {
        return $menu;
    }

    public function backXtlsList($type, $page = 0)
    {
        $this->backCall = [$type, $page];
    }
}

$bot = (new ReflectionClass(RouteDedupTestBot::class))->newInstanceWithoutConstructor();

// ── ipCanon ─────────────────────────────────────────────────────────────────
$ipCases = [
    '1.2.3.4'                  => '1.2.3.4',
    '1.2.3.4/32'               => '1.2.3.4',     // host-маска = тот же адрес
    '1.2.3.4/24'               => '1.2.3.4/24',  // сеть НЕ пересчитываем
    '2001:DB8::1'              => '2001:db8::1',
    '2001:0db8:0000:0000:0000:0000:0000:0001' => '2001:db8::1',
    '2001:db8::1/128'          => '2001:db8::1',
    '2001:db8::/32'            => '2001:db8::/32',
];
foreach ($ipCases as $in => $want) {
    dedupAssert($bot->ipCanon($in) === $want, "ipCanon($in) = {$bot->ipCanon($in)}, ждали $want");
}
dedupAssert($bot->ipCanon($bot->ipCanon('2001:DB8::1/128')) === '2001:db8::1', 'ipCanon не идемпотентен');

// ipWithCidr должен остаться прежним по контракту (его гоняет route_prefix_test),
// но теперь схлопывать разнописанные адреса.
dedupAssert($bot->ipWithCidr('1.2.3.4') === '1.2.3.4/32', 'ipWithCidr v4');
dedupAssert($bot->ipWithCidr('10.0.0.0/24') === '10.0.0.0/24', 'ipWithCidr сеть не трогает');
dedupAssert($bot->ipWithCidr('2001:DB8::1') === '2001:db8::1/128', 'ipWithCidr канонизирует IPv6');

// ── routeEntryCanonKey: что считается одной записью ─────────────────────────
$same = [
    'голая запись и domain:' => ['vk.com', 'domain:vk.com'],
    'регистр'                => ['vk.com', 'VK.com'],
    'завершающая точка'      => ['vk.com', 'vk.com.'],
    'префикс в регистре'     => ['vk.com', 'Domain:VK.COM.'],
    'host-маска IPv4'        => ['1.2.3.4', '1.2.3.4/32'],
    'регистр IPv6'           => ['2001:DB8::1', '2001:db8::1'],
    'развёрнутый IPv6'       => ['2001:db8::1', '2001:0db8:0000:0000:0000:0000:0000:0001/128'],
    'keyword'                => ['keyword:Reddit', 'keyword:reddit'],
    'geoip'                  => ['geoip:CN', 'geoip:cn'],
    'ext-тег'                => ['ext:dlc.dat:Github', 'ext:dlc.dat:github'],
];
foreach ($same as $what => [$a, $b]) {
    dedupAssert(
        $bot->routeEntryCanonKey($a) === $bot->routeEntryCanonKey($b),
        "$what: [$a] и [$b] должны быть одной записью",
    );
}

$diff = [
    'full против domain'  => ['full:vk.com', 'domain:vk.com'],
    'разные хосты'        => ['vk.com', 'ok.com'],
    'сеть против хоста'   => ['1.2.3.4/24', '1.2.3.4/32'],
    'regexp регистрозав.' => ['regexp:VK', 'regexp:vk'],
    'keyword против дом.' => ['keyword:vk.com', 'domain:vk.com'],
    'geosite против geoip'=> ['geosite:cn', 'geoip:cn'],
];
foreach ($diff as $what => [$a, $b]) {
    dedupAssert(
        $bot->routeEntryCanonKey($a) !== $bot->routeEntryCanonKey($b),
        "$what: [$a] и [$b] НЕ должны схлопываться",
    );
}

// Непригодные записи канона не имеют — их нельзя схлопывать друг с другом.
foreach (['keyword:', 'regexp:', 'domain:', '1.2.3.4/64', '999.1.1.1', 'ext:dlc.dat'] as $bad) {
    dedupAssert($bot->routeEntryCanonKey($bad) === '', "мусор [$bad] не должен иметь канона");
}

// ── dedupeRouteList ─────────────────────────────────────────────────────────
// Победитель — явная форма, состояние объединяется по ИЛИ.
$r = $bot->dedupeRouteList(['vk.com' => false, 'domain:vk.com' => true]);
dedupAssert($r['removed'] === 1, 'ждали одну удалённую запись, получили ' . $r['removed']);
dedupAssert(array_keys($r['list']) === ['domain:vk.com'], 'победить должна явная форма: ' . json_encode(array_keys($r['list'])));
dedupAssert($r['list']['domain:vk.com'] === true, 'включённая копия не должна теряться');

// Обратный порядок ключей — тот же победитель.
$r = $bot->dedupeRouteList(['domain:vk.com' => false, 'vk.com' => true]);
dedupAssert(array_keys($r['list']) === ['domain:vk.com'], 'победитель зависит от порядка ввода');
dedupAssert($r['list']['domain:vk.com'] === true, 'ИЛИ по состоянию не сработало');

// Обе выключены — объединённая остаётся выключенной.
$r = $bot->dedupeRouteList(['vk.com' => false, 'VK.com.' => false]);
dedupAssert($r['list'] === ['vk.com' => false], 'два выключенных дубля: ' . json_encode($r['list']));

// Мусор не схлопывается и не теряется.
$r = $bot->dedupeRouteList(['keyword:' => true, 'regexp:' => true, 'vk.com' => true]);
dedupAssert($r['removed'] === 0 && count($r['list']) === 3, 'непригодные записи не должны схлопываться');

// ── addInclude: повтор не воскрешает выключенную запись ─────────────────────
$bot->pacFake = ['blocklist' => ['domain:vk.com' => false]];
$bot->sent    = [];
$bot->input   = ['from' => 1, 'message_id' => 1, 'chat' => 1];
$bot->limit   = 20;
$bot->addInclude('vk.com', 'blocklist');
dedupAssert(
    $bot->pacFake['blocklist'] === ['domain:vk.com' => false],
    'повторное добавление изменило список: ' . json_encode($bot->pacFake['blocklist']),
);
dedupAssert(
    count(array_filter($bot->sent, fn($t) => str_contains($t, 'duplicates skipped'))) === 1,
    'о пропущенном дубле не сообщили: ' . json_encode($bot->sent),
);

// Пачка из одних дублей одной и той же записи в одном сообщении.
$bot->pacFake = ['blocklist' => []];
$bot->sent    = [];
$bot->addInclude("vk.com, domain:vk.com, VK.com\nvk.com.", 'blocklist');
dedupAssert(count($bot->saved['blocklist']) === 1, 'пачка дублей: ' . json_encode($bot->saved['blocklist']));
dedupAssert(array_keys($bot->saved['blocklist']) === ['domain:vk.com'], 'в списке должна остаться явная форма');

// Разные записи добавляются все.
$bot->pacFake = ['blocklist' => []];
$bot->sent    = [];
$bot->addInclude('vk.com, ok.com, 1.2.3.4', 'blocklist');
dedupAssert(count($bot->saved['blocklist']) === 3, 'разные записи не должны схлопываться: ' . json_encode($bot->saved['blocklist']));
dedupAssert($bot->sent === [], 'лишнее сообщение о дублях: ' . json_encode($bot->sent));

// Дубль IP в другой форме.
$bot->pacFake = ['blocklist' => ['1.2.3.4' => true]];
$bot->sent    = [];
$bot->addInclude('1.2.3.4/32', 'blocklist');
dedupAssert(array_keys($bot->pacFake['blocklist']) === ['1.2.3.4'], 'IP-дубль: ' . json_encode($bot->pacFake['blocklist']));

// ── генераторы конфигов не должны выдавать дубли ────────────────────────────
$x = $bot->listToXrayRules([
    '1.2.3.4'       => true,
    '1.2.3.4/32'    => true,
    'vk.com'        => true,
    'domain:vk.com' => true,
]);
dedupAssert($x['ip'] === ['1.2.3.4'], 'xray ip[]: ' . json_encode($x['ip']));
dedupAssert($x['domain'] === ['domain:vk.com'], 'xray domain[]: ' . json_encode($x['domain']));

$b = $bot->srsBuckets(['vk.com', 'domain:vk.com', 'VK.com', '1.2.3.4', '1.2.3.4/32', 'keyword:X', 'keyword:x']);
dedupAssert($b['domain_suffix'] === ['vk.com'], 'sing-box domain_suffix: ' . json_encode($b['domain_suffix']));
dedupAssert($b['ip_cidr'] === ['1.2.3.4/32'], 'sing-box ip_cidr: ' . json_encode($b['ip_cidr']));
dedupAssert($b['domain_keyword'] === ['x'], 'sing-box domain_keyword: ' . json_encode($b['domain_keyword']));

// ── addInclude на списке, которого ещё нет в pac.json ───────────────────────
// Свежая установка: config/pac.json это {} — ни одного списка. Если весь ввод
// отсеялся как мусор, ключ $type не создавала ни одна ветка, и
// dedupeRouteList($conf[$type]) получала null → TypeError валил обработчик
// сообщения целиком (бот молча переставал отвечать на добавление в список).
foreach (['blocklist' => '1.2.3.4/64', 'subnetlist' => 'keyword:', 'warplist' => 'geoip:'] as $type => $junk) {
    $bot->pacFake = [];
    $bot->sent    = [];
    $bot->addInclude($junk, $type);
    dedupAssert(
        ($bot->pacFake[$type] ?? null) === [],
        "addInclude('$junk', '$type') на пустом pac.json: " . json_encode($bot->pacFake[$type] ?? null),
    );
}

// Мусор не должен оседать и в существующем списке: в конфиги он всё равно не
// уйдёт (routeEntryUsable), но останется висеть кнопкой в меню. Пустая строка
// после нормализации бывает только у битого IP — "keyword:" нормализуется сам
// в себя, поэтому проверка на пустоту его пропускала.
foreach (['keyword:', 'regexp:', 'domain:', 'full:', 'geosite:', 'geoip:', '1.2.3.4/64'] as $junk) {
    $bot->pacFake = ['blocklist' => ['vk.com' => true]];
    $bot->addInclude($junk, 'blocklist');
    dedupAssert(
        array_keys($bot->pacFake['blocklist']) === ['vk.com'],
        "мусор [$junk] осел в списке: " . json_encode(array_keys($bot->pacFake['blocklist'])),
    );
}

// ── idn на пустом значении ──────────────────────────────────────────────────
// Проверяем НЕ через полифилл: idn_to_ascii('') в PHP 8 бросает ValueError, а
// не возвращает false, и «domain:» без значения роняло фаталом весь обработчик
// сообщения (в контейнере intl загружен — вылезало только в бою). Здесь важен
// именно контракт обёрток: пустая строка → false, без исключения.
foreach (['', '   '] as $empty) {
    dedupAssert($bot->idnAscii($empty) === false, 'idnAscii на пустой строке должна вернуть false');
    dedupAssert($bot->idnUtf8($empty) === false, 'idnUtf8 на пустой строке должна вернуть false');
}
// Записи без значения обязаны и нормализоваться, и отрисоваться без фатала:
// первое — путь добавления, второе — отрисовка КАЖДОЙ кнопки меню списка, где
// такие записи уже лежат со старых версий.
foreach (['domain:', 'full:', 'keyword:', 'regexp:', 'geosite:', 'geoip:', 'ext:'] as $bad) {
    $bot->normalizeRouteEntry($bad);
    $bot->routeEntryLabel($bad);
    $bot->routeEntryCanonKey($bad);
    dedupAssert(true, "нормализация/отрисовка [$bad] не должна падать");
}

// ── importListFile-регрессии на чистой части логики ─────────────────────────
// Простой список доменов без второй колонки обязан приезжать ВКЛЮЧЁННЫМ:
// (bool) $t[1] на отсутствующем индексе давал false и выключал весь импорт.
$t = explode(';', 'vk.com');
dedupAssert((bool) ($t[1] ?? 1) === true, 'строка без ";1" должна импортироваться включённой');
$t = explode(';', 'vk.com;0');
dedupAssert((bool) ($t[1] ?? 1) === false, 'явный ";0" должен оставаться выключенным');

if ($failed) {
    echo "route_dedup_test: провалено проверок — $failed\n";
    exit(1);
}
echo "route_dedup_test OK\n";
