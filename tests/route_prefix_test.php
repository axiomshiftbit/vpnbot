<?php

// Классификация записей маршрутизации и раскладка по полям ядер.
// Покрывает регрессии, найденные аудитом b0a2764..76a2cc6:
//  - geoip:/geosite: классифицировались как suffix и уезжали в domain[];
//  - ext:/extip: без тега давали невалидный для xray токен;
//  - datSync() не замечал смену URL при сохранённом имени файла.

require_once __DIR__ . '/../app/bot.php';

function routeAssert(bool $cond, string $msg): void
{
    if (!$cond) {
        throw new RuntimeException($msg);
    }
}

class RoutePrefixTestBot extends Bot
{
    public array $ready = [];

    public function datFileReady(string $value): bool
    {
        return !empty($this->ready[explode(':', $value, 2)[0]]);
    }
}

$bot = (new ReflectionClass(RoutePrefixTestBot::class))->newInstanceWithoutConstructor();
// geosite.dat/geoip.dat — встроенные категории ядра: с недавних пор
// listToXrayRules() тоже требует их наличия на диске (образ xray их не несёт),
// поэтому в наборе «готовых» они обязаны быть.
$bot->ready = ['dlc.dat' => true, 'zkeenip.dat' => true, 'geosite.dat' => true, 'geoip.dat' => true];

// ── classifyRouteEntry ──────────────────────────────────────────────────────
$cases = [
    'regexp:.*\.ru$'            => ['regexp', '.*\.ru$'],
    'keyword:reddit'            => ['keyword', 'reddit'],
    'full:example.com'          => ['full', 'example.com'],
    'domain:vk.com'             => ['domain', 'vk.com'],
    'ext:dlc.dat:github'        => ['ext', 'dlc.dat:github'],
    'extip:zkeenip.dat:akamai'  => ['extip', 'zkeenip.dat:akamai'],
    'geosite:category-ads-all'  => ['geosite', 'category-ads-all'],
    'geoip:cn'                  => ['geoip', 'cn'],
    'GeoIP:private'             => ['geoip', 'private'],
    'google.com'                => ['suffix', 'google.com'],
    '1.2.3.4'                   => ['ip', '1.2.3.4'],
    '10.0.0.0/24'               => ['ip', '10.0.0.0/24'],
    '2001:db8::1'               => ['ip', '2001:db8::1'],
    '2001:db8::/32'             => ['ip', '2001:db8::/32'],
];
foreach ($cases as $in => [$kind, $value]) {
    $c = $bot->classifyRouteEntry($in);
    routeAssert($c['kind'] === $kind, "classify($in): kind={$c['kind']}, ждали $kind");
    routeAssert($c['value'] === $value, "classify($in): value={$c['value']}, ждали $value");
}

// Голое двоеточие не должно превращать не-IPv6 в ip.
routeAssert($bot->classifyRouteEntry('geoip:')['kind'] !== 'ip', 'geoip: без категории — не ip');

// ...но и суффиксом такая запись быть не должна. Раньше geosite:/geoip: без
// категории не матчились своей веткой (там стояло (.+)), проваливались во все
// остальные и возвращались как suffix со значением "geoip:" — то есть считались
// валидным доменом и уезжали в конфиги правилом domain:geoip: (xray) и
// domain_suffix "geoip:" (sing-box). Теперь категория пустая, а запись целиком
// отсеивается routeEntryUsable — как и пустой keyword:.
foreach (['geoip:' => 'geoip', 'geosite:' => 'geosite'] as $in => $kind) {
    $c = $bot->classifyRouteEntry($in);
    routeAssert($c['kind'] === $kind, "classify($in): kind={$c['kind']}, ждали $kind");
    routeAssert($c['value'] === '', "classify($in): value должно быть пустым");
    routeAssert(!$bot->routeEntryUsable($c), "$in не должна попадать в конфиги");
}
routeAssert(
    $bot->listToXrayRules(['geoip:' => true, 'geosite:' => true]) === ['domain' => [], 'ip' => []],
    'пустые geoip:/geosite: не уезжают в xray-правила',
);

// ── extRefValid ─────────────────────────────────────────────────────────────
routeAssert($bot->extRefValid('dlc.dat:github'), 'ext с тегом валиден');
routeAssert(!$bot->extRefValid('dlc.dat'), 'ext без тега невалиден');
routeAssert(!$bot->extRefValid('dlc.dat:'), 'ext с пустым тегом невалиден');
routeAssert(!$bot->extRefValid(':github'), 'ext без файла невалиден');

// ── listToXrayRules ─────────────────────────────────────────────────────────
$out = $bot->listToXrayRules([
    'domain:vk.com'            => true,
    'keyword:reddit'           => true,
    'geosite:category-ads-all' => true,
    'geoip:cn'                 => true,
    'ext:dlc.dat:github'       => true,
    'extip:zkeenip.dat:akamai' => true,
    'ext:dlc.dat'              => true,  // без тега — xray не стартует, режем
    'ext:missing.dat:tag'      => true,  // файла нет — режем
    '1.2.3.4'                  => true,
    'disabled.example'         => false, // выключенная запись
]);
routeAssert($out['domain'] === [
    'domain:vk.com',
    'reddit',
    'geosite:category-ads-all',
    'ext:dlc.dat:github',
], 'domain[]: ' . json_encode($out['domain']));
routeAssert($out['ip'] === [
    'geoip:cn',
    'ext:zkeenip.dat:akamai',
    '1.2.3.4',
], 'ip[]: ' . json_encode($out['ip']));

// geoip: обязан оказаться в ip[], а не в domain[] — иначе xray отвергает конфиг.
foreach ($out['domain'] as $d) {
    routeAssert(!str_starts_with($d, 'geoip:'), "geoip: просочился в domain[]: $d");
}

// В domain[] не должно быть невалидных для xray ext-указателей: токен без
// категории (ext:dlc.dat) ядро не разбирает и не стартует вовсе.
foreach ($out['domain'] as $d) {
    if (str_starts_with($d, 'ext:')) {
        routeAssert(
            substr_count($d, ':') === 2 && !str_ends_with($d, ':'),
            "ext-токен без категории в domain[]: $d",
        );
    }
}

// Перечитывание собственного domain[] (так делает пересборка клиентского
// конфига при t=s) не должно менять смысл доменных записей. Разбирать при этом
// надо по xray-семантике: голая строка в конфиге — keyword, а не суффикс,
// поэтому здесь classifyXrayToken, ровно как в $sort() клиентской пересборки.
$again = array_map(
    fn($t) => $bot->xrayDomainToken($bot->classifyXrayToken($t)),
    $out['domain'],
);
routeAssert(
    $again === $out['domain'],
    'domain[] не идемпотентен: ' . json_encode($again),
);

// ── голая запись списка → суффикс, keyword → голая строка ───────────────────
// Голая строка в xray domain[] означает подстроку: "vk.com" матчил бы и
// "myvk.community.org". Список у пользователя означает суффикс — как в
// sing-box (domain_suffix) и mihomo (DOMAIN-SUFFIX).
$bare = $bot->listToXrayRules(['google.com' => true, 'keyword:reddit' => true]);
routeAssert(
    $bare['domain'] === ['domain:google.com', 'reddit'],
    'голая запись/keyword в domain[]: ' . json_encode($bare['domain']),
);
// А вот при разборе уже готового конфига голая строка обязана остаться keyword.
routeAssert(
    $bot->classifyXrayToken('reddit')['kind'] === 'keyword',
    'голый токен xray-конфига — keyword, не suffix',
);
routeAssert(
    $bot->classifyXrayToken('domain:vk.com')['kind'] === 'domain',
    'domain:-токен xray-конфига должен остаться domain',
);

// ── normalizeRouteEntry: категории ядра не трогаем ──────────────────────────
foreach (['geoip:cn', 'geosite:category-ads-all', 'regexp:.*\.ru$', 'ext:dlc.dat:github'] as $e) {
    routeAssert($bot->normalizeRouteEntry($e) === $e, "normalize($e) изменила запись");
}

// ── splitRouteInput: regexp поглощает запятые ───────────────────────────────
routeAssert(
    $bot->splitRouteInput("domain:vk.com, keyword:reddit\nregexp:a{1,3},b") === [
        'domain:vk.com', 'keyword:reddit', 'regexp:a{1,3},b',
    ],
    'splitRouteInput: ' . json_encode($bot->splitRouteInput("domain:vk.com, keyword:reddit\nregexp:a{1,3},b")),
);

// ── ipWithCidr ──────────────────────────────────────────────────────────────
routeAssert($bot->ipWithCidr('1.2.3.4') === '1.2.3.4/32', 'ipWithCidr v4');
routeAssert($bot->ipWithCidr('2001:db8::1') === '2001:db8::1/128', 'ipWithCidr v6');
routeAssert($bot->ipWithCidr('10.0.0.0/24') === '10.0.0.0/24', 'ipWithCidr идемпотентен');

// ── datSync: смена URL при сохранённом имени файла ──────────────────────────
class DatUrlTestBot extends Bot
{
    public string $testDir;
    public array $conf     = [];
    public array $fetched  = [];
    public string $body    = "\x0a\x07\x0a\x05FIRST";

    public function datDir(): string
    {
        return $this->testDir;
    }

    public function getPacConf()
    {
        return $this->conf;
    }

    public function datFetchSum(string $url): ?string
    {
        return null; // сеть в тесте не трогаем
    }

    public function datFetchRaw(string $url, array $validators = []): array
    {
        $this->fetched[] = ['url' => $url, 'validators' => $validators];
        return ['ok' => true, 'body' => $this->body, 'etag' => '"tag"', 'last_modified' => ''];
    }
}

$dir = sys_get_temp_dir() . '/routetest' . getmypid();
@mkdir($dir, 0777, true);
$b = (new ReflectionClass(DatUrlTestBot::class))->newInstanceWithoutConstructor();
$b->testDir = $dir;
$b->conf = ['datlist' => ['dlc.dat:https://a.example/dlc.dat' => true]];

routeAssert($b->datSync() === [], 'первая синхронизация без ошибок');
routeAssert(count($b->fetched) === 1, 'первая синхронизация качает файл');

// Повторный проход: файл на месте, URL тот же — сети быть не должно.
$b->fetched = [];
$b->datSync();
routeAssert($b->fetched === [], 'повторная синхронизация не ходит в сеть');

// URL сменили, имя то же — файл обязан перекачаться с нового адреса.
$b->conf = ['datlist' => ['dlc.dat:https://b.example/dlc.dat' => true]];
$b->body = "\x0a\x08\x0a\x06SECOND";
$b->fetched = [];
$b->datSync();
routeAssert(count($b->fetched) === 1, 'смена URL не подхвачена: сети не было');
routeAssert($b->fetched[0]['url'] === 'https://b.example/dlc.dat', 'качали не с нового URL');
routeAssert(
    $b->fetched[0]['validators'] === [],
    'валидаторы прежнего источника ушли новому: ' . json_encode($b->fetched[0]['validators']),
);
routeAssert(file_get_contents("$dir/dlc.dat") === "\x0a\x08\x0a\x06SECOND", 'на диске остался файл от старого URL');

// Две записи с одним именем и разными URL — коллизия, а не тихая победа первой.
$b->conf = ['datlist' => [
    'dlc.dat:https://b.example/dlc.dat' => true,
    'dlc.dat:https://c.example/dlc.dat' => true,
]];
$errors = $b->datSync();
routeAssert(isset($errors['dlc.dat']), 'коллизия имён не отмечена ошибкой');

array_map('unlink', glob("$dir/*") ?: []);
@rmdir($dir);

echo "route_prefix_test OK\n";
