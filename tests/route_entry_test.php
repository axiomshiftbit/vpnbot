<?php

require_once __DIR__ . '/../app/bot.php';

function routeTestAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$bot = (new ReflectionClass(Bot::class))->newInstanceWithoutConstructor();

// ── Классификация: валидные формы не должны деградировать ────────────────────
$expectKind = [
    'vk.com'                   => 'suffix',
    'domain:vk.com'            => 'domain',
    'full:vk.com'              => 'full',
    'keyword:reddit'           => 'keyword',
    'regexp:.*\.ru$'           => 'regexp',
    'ext:zkeen.dat:ru'         => 'ext',
    'extip:zkeenip.dat:akamai' => 'extip',
    'geosite:cn'               => 'geosite',
    'geoip:cn'                 => 'geoip',
    '1.2.3.4'                  => 'ip',
    '1.2.3.4/24'               => 'ip',
    '2001:db8::1'              => 'ip',
    '2001:db8::/32'            => 'ip',
];
foreach ($expectKind as $entry => $kind) {
    $c = $bot->classifyRouteEntry($entry);
    routeTestAssert($c['kind'] === $kind, "classify($entry): ожидался $kind, получен {$c['kind']}");
    routeTestAssert($bot->routeEntryUsable($c), "usable($entry) должен быть true");
}

// ── Битый IP не должен попадать в ip[] ───────────────────────────────────────
// Такая запись отвергается разбором конфига xray, и ядро не стартует вовсе:
// одна опечатка в block-списке роняла весь VPN.
foreach (['999.1.1.1', '256.256.256.256', '1.2.3.4/33', '1.2.3.4/64', '2001:db8::/300'] as $bad) {
    $c = $bot->classifyRouteEntry($bad);
    routeTestAssert(!$bot->routeEntryUsable($c), "битый IP $bad не должен считаться пригодным");
}
routeTestAssert(
    $bot->listToXrayRules(['999.1.1.1' => true, '1.2.3.4/64' => true]) === ['domain' => [], 'ip' => []],
    'битые IP не должны попадать в правила xray',
);

// ── Пустое значение префикса не должно давать catch-all ──────────────────────
// В поле domain[] у xray голая строка означает совпадение по подстроке, а пустая
// подстрока входит в ЛЮБОЙ домен: "keyword:" превращал block-список в
// «блокировать всё».
foreach (['keyword:', 'regexp:', 'domain:', 'full:', 'ext:', 'extip:', 'ext:dlc.dat', ' '] as $empty) {
    $c = $bot->classifyRouteEntry($empty);
    routeTestAssert(!$bot->routeEntryUsable($c), "пустая запись [$empty] не должна считаться пригодной");
}
$rules = $bot->listToXrayRules(['keyword:' => true, 'vk.com' => true]);
routeTestAssert($rules['domain'] === ['vk.com'], 'пустой keyword: должен отсеиваться, домен — оставаться');

// ── geoip/geosite раскладываются по правильным полям xray ────────────────────
$rules = $bot->listToXrayRules(['geoip:cn' => true, 'geosite:cn' => true]);
routeTestAssert($rules['ip'] === ['geoip:cn'], 'geoip: должен уходить в ip[]');
routeTestAssert($rules['domain'] === ['geosite:cn'], 'geosite: должен уходить в domain[]');

// ── ipWithCidr идемпотентен и различает семейства ────────────────────────────
routeTestAssert($bot->ipWithCidr('1.2.3.4') === '1.2.3.4/32', 'IPv4 без маски → /32');
routeTestAssert($bot->ipWithCidr('1.2.3.4/24') === '1.2.3.4/24', 'готовую маску не трогаем');
routeTestAssert($bot->ipWithCidr('2001:db8::1') === '2001:db8::1/128', 'IPv6 без маски → /128');

// ── splitRouteInput: regexp: поглощает остаток строки (запятые в {1,3}) ───────
routeTestAssert(
    $bot->splitRouteInput("a.com, b.com\nregexp:a{1,3}\\.ru\nkeyword:x, full:y.com")
        === ['a.com', 'b.com', 'regexp:a{1,3}\\.ru', 'keyword:x', 'full:y.com'],
    'splitRouteInput не должен резать regexp по запятой',
);

echo "route_entry_test OK\n";
