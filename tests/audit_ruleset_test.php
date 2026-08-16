<?php

// Маршруты: встроенные geosite/geoip, rule-set'ы и dat-реестр.
// Регрессии из аудита 2026-08-12 (K6, K11 и раздел «Маршруты / PAC / шаблоны»):
//  - listToXrayRules(): geosite:/geoip: уезжали в конфиг ядра, хотя .dat в
//    образе нет — xray падал на «failed to load geosite» без самовосстановления;
//  - datSync(): встроенные .dat подметались как осиротевшие;
//  - cleanEmptyKeys(): unset внутри списка превращал JSON-массив в объект,
//    и `sing-box rule-set compile` такой файл не принимал;
//  - parseRuleSetKey(): два потребителя rulessetlist разбирали ключ по-разному;
//  - xrayUpdateRules(): outbounds перезаписывались целиком, и добавленный
//    админом аутбаунд молча исчезал.

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function rsAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

class RuleSetTestBot extends Bot
{
    public array $pacFake = [];
    public array $xrFake  = [];
    public array $written = [];
    public string $dir    = '';

    public function getPacConf()
    {
        return $this->pacFake;
    }

    public function setPacConf(array $conf)
    {
        $this->pacFake = $conf;
        return true;
    }

    public function getXray()
    {
        return $this->xrFake;
    }

    public function restartXray($c, $norestart = false)
    {
        $this->written = $c;
    }

    public function datDir(): string
    {
        return $this->dir;
    }

    // Сеть в тестах не трогаем: фиксируем сам факт запроса.
    public array $fetched = [];
    public array $fetchedUrls = [];

    public function datDownload(string $name, string $url, ?bool &$changed = null): string
    {
        $this->fetched[]           = $name;
        $this->fetchedUrls[$name]  = $url;
        file_put_contents($this->datPath($name), 'dat');
        $changed = true;
        return '';
    }
}

$bot = (new ReflectionClass(RuleSetTestBot::class))->newInstanceWithoutConstructor();
$bot->dir = sys_get_temp_dir() . '/geodata_' . getmypid();
@mkdir($bot->dir, 0777, true);
array_map('unlink', glob($bot->dir . '/*') ?: []);

// ── 1. geosite:/geoip: не уезжают в конфиг без .dat ─────────────────────────
$list = ['geosite:category-ads-all' => true, 'geoip:cn' => true, 'vk.com' => true];
$x = $bot->listToXrayRules($list);
rsAssert($x['domain'] === ['domain:vk.com'],
    'без geosite.dat запись отброшена: ' . json_encode($x['domain']));
rsAssert($x['ip'] === [], 'без geoip.dat запись отброшена: ' . json_encode($x['ip']));

file_put_contents($bot->datPath('geosite.dat'), 'x');
file_put_contents($bot->datPath('geoip.dat'), 'x');
$x = $bot->listToXrayRules($list);
rsAssert(in_array('geosite:category-ads-all', $x['domain'], true),
    'с geosite.dat запись попадает в domain[]: ' . json_encode($x['domain']));
rsAssert($x['ip'] === ['geoip:cn'], 'с geoip.dat запись попадает в ip[]: ' . json_encode($x['ip']));

// ── 2. coreDatNeeded / datSync ──────────────────────────────────────────────
rsAssert($bot->coreDatNeeded(['blocklist' => ['vk.com' => true]]) === [],
    'без записей geosite:/geoip: ничего не нужно');
rsAssert($bot->coreDatNeeded(['blocklist' => ['geosite:ads' => true]]) === ['geosite.dat'],
    'geosite: требует geosite.dat');
rsAssert($bot->coreDatNeeded(['warplist' => ['geoip:cn' => false]]) === [],
    'выключенная запись файла не требует');
$need = $bot->coreDatNeeded(['blocklist' => ['geosite:ads' => true], 'includelist' => ['geoip:ru' => true]]);
sort($need);
rsAssert($need === ['geoip.dat', 'geosite.dat'], 'оба файла: ' . json_encode($need));

// Встроенные .dat переживают уборку осиротевших файлов.
$bot->pacFake = ['datlist' => []];
file_put_contents($bot->datPath('stale.dat'), 'x');
$bot->datSync();
rsAssert(is_file($bot->datPath('geosite.dat')), 'geosite.dat не подметён');
rsAssert(is_file($bot->datPath('geoip.dat')), 'geoip.dat не подметён');
rsAssert(!is_file($bot->datPath('stale.dat')), 'чужой осиротевший файл удалён');
rsAssert($bot->fetched === [], 'ничего не качали: записей geosite:/geoip: нет');

// Появилась запись geosite: — файла нет → качаем.
unlink($bot->datPath('geosite.dat'));
$bot->pacFake = ['datlist' => [], 'blocklist' => ['geosite:ads' => true]];
$bot->datSync();
rsAssert($bot->fetched === ['geosite.dat'], 'подтянули только недостающий файл: ' . json_encode($bot->fetched));

// Реестр уже объявляет geoip.dat своим источником (частый случай: у админа
// свой, более полный файл). Встроенную ссылку в этом случае не добавляем —
// иначе datSync сообщал бы «имя занято другим источником» на каждом проходе.
$bot->fetched = [];
unlink($bot->datPath('geoip.dat'));
$bot->pacFake = [
    'datlist'   => ['geoip.dat:https://example.com/mygeoip.dat' => true],
    'blocklist' => ['geoip:cn' => true],
];
$errors = $bot->datSync();
rsAssert(!isset($errors['geoip.dat']),
    'коллизии с пользовательским geoip.dat нет: ' . json_encode($errors, JSON_UNESCAPED_UNICODE));
rsAssert(($bot->fetchedUrls['geoip.dat'] ?? '') === 'https://example.com/mygeoip.dat',
    'качаем по ссылке ИЗ РЕЕСТРА, а не по встроенной: ' . json_encode($bot->fetchedUrls));
rsAssert(is_file($bot->datPath('geoip.dat')), 'файл на месте, guard маршрутов пройдёт');

// ── 3. cleanEmptyKeys не превращает список в объект ─────────────────────────
$clean = $bot->cleanEmptyKeys([
    ['domain_suffix' => ['a.com']],
    ['domain_suffix' => []],      // пустое правило — выпадает
    ['domain_suffix' => ['b.com']],
]);
rsAssert(array_is_list($clean), 'после чистки это по-прежнему список');
rsAssert(str_starts_with(json_encode(['rules' => $clean]), '{"rules":[{'),
    'json остаётся массивом, а не объектом с ключами "0"/"2": ' . json_encode(['rules' => $clean]));
rsAssert(count($clean) === 2, 'пустое правило выброшено');
// Ассоциативный массив ключи сохраняет.
$assoc = $bot->cleanEmptyKeys(['a' => 1, 'b' => 0, 'c' => 3]);
rsAssert($assoc === ['a' => 1, 'c' => 3], 'у объекта ключи не переиндексируются: ' . json_encode($assoc));

// ── 4. parseRuleSetKey: обе формы ключа ─────────────────────────────────────
$a = Bot::parseRuleSetKey('proxy:86400:https://x.example/y.mrs');
rsAssert($a === ['outbound' => 'proxy', 'behavior' => 'classical', 'interval' => '86400', 'url' => 'https://x.example/y.mrs'],
    'форма без behavior: ' . json_encode($a));
$b = Bot::parseRuleSetKey('proxy:domain:86400:https://x.example/y.srs');
rsAssert($b === ['outbound' => 'proxy', 'behavior' => 'domain', 'interval' => '86400', 'url' => 'https://x.example/y.srs'],
    'форма с behavior: ' . json_encode($b));
rsAssert(Bot::parseRuleSetKey('block:1d:http://x/y.srs')['interval'] === '1d',
    'длительность вида 1d сохраняется');
rsAssert(Bot::parseRuleSetKey('мусор') === null, 'мусор не разбирается');
rsAssert(Bot::parseRuleSetKey(':86400:https://x/y.srs') === null, 'пустой outbound не проходит');
rsAssert(Bot::parseRuleSetKey('a:b:c:86400:https://x/y.srs') === null, 'лишние поля не проходят');

// ── 5. xrayUpdateRules сохраняет чужие outbounds ────────────────────────────
$bot->pacFake = ['blocklist' => ['vk.com' => true]];
$bot->xrFake  = [
    'inbounds'  => [['tag' => 'vless_tls', 'settings' => ['clients' => []]]],
    'outbounds' => [
        ['protocol' => 'freedom', 'tag' => 'direct'],
        ['protocol' => 'vless', 'tag' => 'my-chain'],   // добавлен админом через webapp
        ['protocol' => 'blackhole', 'tag' => 'block'],
    ],
];
$bot->xrayUpdateRules();
$tags = array_column($bot->written['outbounds'], 'tag');
rsAssert(in_array('my-chain', $tags, true), 'чужой аутбаунд на месте: ' . json_encode($tags));
rsAssert($tags[0] === 'direct', 'дефолтный маршрут остался первым: ' . json_encode($tags));
rsAssert(in_array('warp', $tags, true), 'недостающий свой аутбаунд дописан');
rsAssert(count($tags) === count(array_unique($tags)), 'дублей тегов нет: ' . json_encode($tags));

array_map('unlink', glob($bot->dir . '/*') ?: []);
@rmdir($bot->dir);

if ($failed) {
    echo "audit_ruleset_test FAILED: $failed\n";
    exit(1);
}
echo "audit_ruleset_test OK\n";
