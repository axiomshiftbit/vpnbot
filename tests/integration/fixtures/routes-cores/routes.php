<?php
// Набор стенда routes_cores. Списки routes (block, WARP, domains, subnet,
// process, package, rulesset) на настоящих ядрах из проверяемых образов: профили собирает бот из своих шаблонов, списки отдаются
// ядрам по HTTP так же, как отдаёт их бот, маршрут проверяется запросом.
putenv('VPNBOT_ROUTES_FIXTURE_ONLY=1');
require '/src/tests/routes_behavior_test.php';

class Lab3Bot extends RoutesBehaviorBot
{
    public function __construct()
    {
        parent::__construct();
        foreach (['v2ray' => 'v2ray.json', 'sing' => 'sing.json', 'clash' => 'clash.json'] as $k => $f) {
            $this->templates[$k] = json_decode(file_get_contents("/src/config/$f"), true);
        }
        if (is_file('/work/conf.json')) $this->conf = json_decode(file_get_contents('/work/conf.json'), true);
    }
    public function setPacConf(array $conf) { $this->conf = $conf; file_put_contents('/work/conf.json', json_encode($conf)); return true; }
    public function subDomain(array $pac): string { return '127.0.0.1'; }
    public function validateRouteRegexes(array $patterns): bool { return Bot::validateRouteRegexes($patterns); }
}

if (($argv[1] ?? '') === 'serve') {
    $q = unserialize(base64_decode($argv[2]), ['allowed_classes' => false]);
    $_GET = ['t' => $q['t'], 's' => $q['s'], 'r' => $q['r']];
    $bot = new Lab3Bot();
    $out = $bot->subscription(true);
    if (is_string($out)) echo $out;
    exit(0);
}

$fail = 0; $n = 0;
$check = function (bool $ok, string $what, string $detail = '') use (&$fail, &$n) {
    $n++; echo ($ok ? 'PASS ' : 'FAIL ') . $what . ($ok || $detail === '' ? '' : "\n     $detail") . "\n"; if (!$ok) $fail++;
};
$sh = function (string $cmd) { exec($cmd . ' 2>&1', $out, $rc); return [$rc, implode("\n", $out)]; };
@mkdir('/work/rs', 0755, true);
foreach (glob('/work/*') as $f) if (is_file($f)) unlink($f);

// Имена для проверки: всё ведёт на локальный «прямой» узел.
$hosts = ['example.com', 'sub.example.com', 'notexample.com', 'vk.com', 'm.vk.com', 'myvk.com', 'exact.test', 'sub.exact.test',
    'www.reddit.com', 'redditstatic.net', 'site.ru', 'site.ru.com', 'off.test', 'upper.test', 'xn--e1afmkfd.xn--p1ai',
    'ads.test', 'sub.ads.test', 'tracker-banner.net', 'warp.test', 'plain.test', 'rsblock.test', 'a.rsblock.test', 'rsproxy.test',
    'rsdirect.test', 'rsmrs.test', 'rscustom.test', 'comma1.test', 'comma2.test', 'space1.test', 'space2.test', 'geo.test', 'dup.test', 'blk7.test', 'blkx.test'];
file_put_contents('/etc/hosts', "127.0.0.1 localhost\n127.0.0.1 " . implode(' ', $hosts) . "\n");
exec('python3 -u /lab/markers.py >/work/markers.log 2>&1 &');
foreach ([80, 3128, 3129, 8099] as $port) for ($i = 0; $i < 80 && !@fsockopen('127.0.0.1', $port, $e, $es, 0.2); $i++) usleep(100000);

// ── Сторонние rule-set: по одному на каждый поддерживаемый формат ──────────
file_put_contents('/work/rs/b.json', json_encode(['version' => 1, 'rules' => [['domain_suffix' => ['rsblock.test']]]]));
[$rc, $out] = $sh('cd /work/rs && sing-box rule-set compile b.json -o b.srs');
$check($rc === 0, 'sing-box собрал b.srs', $out);
file_put_contents('/work/rs/d.json', json_encode(['version' => 1, 'rules' => [['domain' => ['rsdirect.test']]]]));
$sh('cd /work/rs && sing-box rule-set compile d.json -o d.srs');
file_put_contents('/work/rs/p.json', json_encode(['version' => 1, 'rules' => [['domain_suffix' => ['rsproxy.test']], ['ip_cidr' => ['192.0.2.0/24']]]]));
file_put_contents('/work/rs/b.yaml', "payload:\n  - DOMAIN-SUFFIX,rsblock.test\n");
file_put_contents('/work/rs/d.txt', "DOMAIN,rsdirect.test\n");
file_put_contents('/work/rs/p.yml', "payload:\n  - DOMAIN-SUFFIX,rsproxy.test\n  - IP-CIDR,192.0.2.0/24\n");
file_put_contents('/work/rs/m-src.yaml', "payload:\n  - '+.rsmrs.test'\n");
[$rc, $out] = $sh('cd /work/rs && mihomo convert-ruleset domain yaml m-src.yaml m.mrs');
$check($rc === 0 && is_file('/work/rs/m.mrs'), 'mihomo собрал m.mrs', $out);
file_put_contents('/work/rs/ip-src.yaml', "payload:\n  - '192.0.2.128/25'\n");
$sh('cd /work/rs && mihomo convert-ruleset ipcidr yaml ip-src.yaml ip.mrs');
file_put_contents('/work/rs/c.yaml', "payload:\n  - DOMAIN-SUFFIX,rscustom.test\n");

// ── Заполнение списков теми же действиями, что ввод в меню ─────────────────
$bot = new Lab3Bot();
$bot->setPacConf($bot->conf);
$R = 'http://127.0.0.1:8099';
$inputs = [
    'includelist' => "example.com\ndomain:vk.com\nfull:exact.test\nkeyword:reddit\nregexp:.*\\.ru$\n203.0.113.7\n2001:db8::/32\nUPPER.Test.\nпример.рф\n"
        . "comma1.test, comma2.test\nrsdirect.test\ndup.test\nDUP.test\ndomain:dup.test\nkeyword:\n999.1.1.1\nbad_domain!.test\nspace1.test space2.test\n",
    'blocklist'   => "ads.test\n198.51.100.0/24\nkeyword:banner\nfull:blocked.exact.test",
    'warplist'    => "warp.test\n203.0.113.200",
    'subnetlist'  => "10.1.0.0/16, 2001:db8:1::/48\n172.16.5.5\nnot-an-ip\n10.300.0.0/8",
    'packagelist' => "org.telegram.messenger, com.example.app",
    'rulessetlist' => "block:1d:$R/b.srs\nproxy:1h:$R/p.json\ndirect:3600:$R/d.srs\n"
        . "block:1d:$R/b.yaml\nproxy:domain:1h:$R/m.mrs\ndirect:1h:$R/d.txt\nproxy:1h:$R/p.yml\nproxy:ipcidr:2h:$R/ip.mrs\n"
        . "proxy:1h:$R/skip.txt?off=1\n"
        . "nointerval:$R/x.srs\nproxy:1x:$R/x.srs\nproxy:1h:ftp://x/x.srs\nproxy:1h:$R/x.exe\nproxy:classical:1h:$R/c.mrs\nproxy:wrong:1h:$R/x.yaml\na,b:1h:$R/x.srs\n:1h:$R/x.srs",
];
foreach ($inputs as $type => $text) { $bot->messages = []; $bot->addInclude($text, $type); $said[$type] = implode(' | ', $bot->messages); }
$c = $bot->conf;
$keys = fn(string $t) => array_keys($c[$t] ?? []);
$check(count($c['includelist']) === 15 && !isset($c['includelist']['keyword:']) && !isset($c['includelist']['999.1.1.1']) && !isset($c['includelist']['bad_domain!.test']),
    'domains: 15 записей принято, три неверные отброшены', json_encode($keys('includelist'), JSON_UNESCAPED_UNICODE) . ' | ' . $said['includelist']);
$check(str_contains($said['includelist'], '3') && isset($c['includelist']['comma1.test'], $c['includelist']['comma2.test'], $c['includelist']['space1.test'], $c['includelist']['space2.test']),
    'domains: записи через запятую и через пробел разобраны, о пропусках сообщено', $said['includelist']);
$check(count(preg_grep('~dup\.test~i', $keys('includelist'))) === 1, 'domains: три записи одного домена сведены к одной', json_encode($keys('includelist')));
$check($keys('subnetlist') == ['10.1.0.0/16', '172.16.5.5', '2001:db8:1::/48'], 'subnet: приняты только адреса и подсети', json_encode($keys('subnetlist')) . ' | ' . $said['subnetlist']);
$check(count($c['rulessetlist']) === 9, 'rulesset: девять верных источников принято, восемь неверных отброшено', json_encode($keys('rulessetlist')) . ' | ' . $said['rulessetlist']);
$check(count($c['blocklist']) === 4 && count($c['warplist']) === 2 && count($c['packagelist']) === 2, 'block, WARP, package заполнены');
// Выключенные записи.
$off = function (string $type, string $key) use ($bot) { $bot->changeRouteList($type, function (&$l) use ($key) { $l[$key] = false; }); };
$bot->addInclude('off.test', 'includelist'); $off('includelist', 'off.test');
$off('rulessetlist', "proxy:1h:$R/skip.txt?off=1");
// Свой outbound для Mihomo: имя группы из шаблона.
$group = $bot->templates['clash']['proxy-groups'][0]['name'] ?? '';

// ── Общие помощники запуска ядра и пробы маршрута ──────────────────────────
$stop = function () { exec('pkill -x sing-box; pkill -x mihomo; pkill -f "/xray run"'); usleep(300000); };
$probe = function (int $port, string $host) {
    exec('curl -4 -s --max-time 6 --proxy socks5h://127.0.0.1:' . $port . ' ' . escapeshellarg("http://$host/") . ' 2>/dev/null', $out, $rc);
    $body = implode('', $out);
    return $body === 'DIRECT' || $body === 'PROXY' ? $body : 'BLOCK';
};
$matrix = function (string $core, int $port, array $expect) use ($probe, $check) {
    $bad = [];
    foreach ($expect as $host => $want) { $got = $probe($port, $host); if ($got !== $want) $bad[] = "$host: ждали $want, получили $got"; }
    $check($bad === [], "$core: маршрут всех " . count($expect) . ' проб совпал с ожидаемым', implode('; ', $bad));
};
$wait = function (int $port) { for ($i = 0; $i < 60; $i++) { if (@fsockopen('127.0.0.1', $port, $e, $s, 0.3)) return true; usleep(250000); } return false; };

// Ожидаемый маршрут: один и тот же смысл записи во всех трёх ядрах.
$expect = [
    'example.com' => 'PROXY', 'sub.example.com' => 'PROXY', 'notexample.com' => 'DIRECT',   // голый домен — суффикс, не подстрока
    'vk.com' => 'PROXY', 'm.vk.com' => 'PROXY', 'myvk.com' => 'DIRECT',                     // domain:
    'exact.test' => 'PROXY', 'sub.exact.test' => 'DIRECT',                                  // full:
    'www.reddit.com' => 'PROXY', 'redditstatic.net' => 'PROXY',                             // keyword:
    'site.ru' => 'PROXY', 'site.ru.com' => 'DIRECT',                                        // regexp:
    'upper.test' => 'PROXY', 'xn--e1afmkfd.xn--p1ai' => 'PROXY',                            // регистр, точка в конце, IDN
    'comma1.test' => 'PROXY', 'comma2.test' => 'PROXY', 'space1.test' => 'PROXY', 'space2.test' => 'PROXY', 'dup.test' => 'PROXY',
    'off.test' => 'DIRECT', 'plain.test' => 'DIRECT',                                       // выключенная и посторонняя
    '203.0.113.7' => 'PROXY', '10.1.2.3' => 'PROXY', '172.16.5.5' => 'PROXY',               // IP из domains и subnet
    'ads.test' => 'BLOCK', 'sub.ads.test' => 'BLOCK', 'tracker-banner.net' => 'BLOCK', '198.51.100.9' => 'BLOCK',
    'warp.test' => 'PROXY', '203.0.113.200' => 'PROXY',                                     // WARP на клиенте — через VPN
];
$rsExpect = ['rsblock.test' => 'BLOCK', 'a.rsblock.test' => 'BLOCK', 'rsproxy.test' => 'PROXY', '192.0.2.10' => 'PROXY',
    'rsdirect.test' => 'DIRECT'];                                                           // прямое исключение сильнее списка domains
$sub = function (string $t) { $_GET = ['t' => $t, 's' => 'routes-test']; return (new Lab3Bot())->subscription(true); };

// ── sing-box ───────────────────────────────────────────────────────────────
echo "== sing-box ==\n";
$run = function (array $cfg, string $label) use ($sh, $wait, $stop, $check) {
    $stop();
    $out = [];
    foreach ($cfg['outbounds'] as $o) {
        $tag = $o['tag'] ?? '';
        if (($o['type'] ?? '') === 'block') { $out[] = $o; continue; }
        $out[] = ['type' => 'http', 'tag' => $tag, 'server' => '127.0.0.1', 'server_port' => $tag === 'direct' ? 3129 : 3128];
    }
    $cfg['outbounds'] = $out;
    $cfg['inbounds'] = [['type' => 'mixed', 'tag' => 'lab', 'listen' => '127.0.0.1', 'listen_port' => 1089]];
    unset($cfg['experimental'], $cfg['dns'], $cfg['route']['default_domain_resolver'], $cfg['ntp']);
    $cfg['log'] = ['level' => 'info'];
    file_put_contents("/work/$label.json", json_encode($cfg, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    [$rc, $text] = $sh("sing-box check -c /work/$label.json");
    $check($rc === 0, "$label: профиль бота проходит sing-box check", $text);
    exec("sing-box run -c /work/$label.json >/work/$label.log 2>&1 &");
    $up = $wait(1089);
    $check($up, "$label: ядро запустилось и скачало все rule-set", substr((string) @file_get_contents("/work/$label.log"), -400));
    return $up;
};
$si = json_decode($sub('si'), true);
$tags = array_column($si['route']['rule_set'] ?? [], 'tag');
$check(count(array_filter($tags, fn($t) => str_contains($t, '8099'))) === 3 && !preg_grep('~yaml|mrs|txt|yml|skip~', $tags), 'sing-box: из rulesset взяты только srs и json, выключенный пропущен', json_encode($tags));
if ($run($si, 'singbox')) {
    $matrix('sing-box', 1089, $expect + $rsExpect);
    $bot2 = new Lab3Bot(); $bot2->addInclude('curl', 'processlist');
    if ($run(json_decode($sub('si'), true), 'singbox-process')) {
        $check($probe(1089, 'plain.test') === 'PROXY' && $probe(1089, 'ads.test') === 'BLOCK', 'sing-box: process — запросы названной программы идут через VPN, блокировка сильнее');
    }
    $bot2 = new Lab3Bot(); $bot2->changeRouteList('processlist', function (&$l) { $l = []; });
}
// Списки, которые бот отдаёт sing-box сам: содержимое по каждому имени.
foreach (['pac', 'block', 'warp', 'subnet', 'package', 'process'] as $name) {
    $b64 = base64_encode(serialize(['h' => 'fixture', 't' => 'si', 's' => 'routes-test', 'r' => $name]));
    exec('php /lab/routes.php serve ' . escapeshellarg($b64) . " > /work/own-$name.srs 2>/work/own-$name.err", $o, $rc);
    [$rc2, $json] = $sh("sing-box rule-set decompile /work/own-$name.srs -o /work/own-$name.json && cat /work/own-$name.json");
    $own[$name] = $rc === 0 && $rc2 === 0 ? json_encode(json_decode($json, true)['rules'] ?? null, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) : "ошибка: $json " . @file_get_contents("/work/own-$name.err");
}
$check(str_contains($own['package'], 'org.telegram.messenger') && str_contains($own['package'], 'package_name'), 'sing-box: package отдаётся как package_name', $own['package']);
$check(str_contains($own['subnet'], '10.1.0.0/16') && str_contains($own['subnet'], '2001:db8:1::/48') && str_contains($own['subnet'], 'ip_cidr'), 'sing-box: subnet отдаётся как ip_cidr, включая IPv6', $own['subnet']);
$check(str_contains($own['pac'], '2001:db8::/32') && str_contains($own['pac'], 'domain_regex') && !str_contains($own['pac'], 'off.test'), 'sing-box: domains — IPv6 и regexp на месте, выключенная запись не отдаётся', $own['pac']);
echo "     pac: {$own['pac']}\n     block: {$own['block']}\n     warp: {$own['warp']}\n     process: {$own['process']}\n";

// ── Mihomo ─────────────────────────────────────────────────────────────────
echo "== mihomo ==\n";
$runMihomo = function (string $yaml, string $label) use ($sh, $wait, $stop, $check, $hosts) {
    $stop();
    $cfg = yaml_parse($yaml);
    $names = array_column($cfg['proxies'] ?? [], 'name');
    $cfg['proxies'] = array_map(fn($name) => ['name' => $name, 'type' => 'http', 'server' => '127.0.0.1', 'port' => 3128], $names);
    $cfg['mixed-port'] = 1090; $cfg['bind-address'] = '127.0.0.1'; $cfg['allow-lan'] = false;
    unset($cfg['tun'], $cfg['external-controller'], $cfg['port'], $cfg['socks-port'], $cfg['listeners'], $cfg['external-ui']);
    $cfg['dns'] = ['enable' => false];
    $cfg['hosts'] = array_fill_keys($hosts, '127.0.0.1');
    yaml_emit_file("/work/$label.yaml", $cfg);
    @mkdir("/work/$label-home");
    [$rc, $text] = $sh("mihomo -t -d /work/$label-home -f /work/$label.yaml");
    $check($rc === 0, "$label: профиль бота проходит mihomo -t", substr($text, -500));
    exec("mihomo -d /work/$label-home -f /work/$label.yaml >/work/$label.log 2>&1 &");
    $up = $wait(1090);
    sleep(3); // поставщики правил подгружаются после открытия порта
    $log = (string) @file_get_contents("/work/$label.log");
    $check($up && !preg_match('~level=(error|fatal)~', $log), "$label: ядро запустилось, поставщики правил загружены без ошибок", implode(' | ', array_slice(preg_grep('~level=(error|fatal|warning)~', explode("\n", $log)), 0, 4)));
    return $up;
};
$cl = $sub('cl');
$clCfg = yaml_parse($cl);
$providers = $clCfg['rule-providers'] ?? [];
$ext = array_filter($providers, fn($p) => str_contains($p['url'], ':8099/'));
$check(count($ext) === 5 && !preg_grep('~srs|json|skip~', array_column($ext, 'url')), 'Mihomo: из rulesset взяты yaml, yml, txt и mrs; srs, json и выключенный пропущены', json_encode(array_column($ext, 'url')));
$check(array_column($ext, 'format', 'url')["$R/p.yml"] === 'yaml' && array_column($ext, 'behavior', 'url')["$R/ip.mrs"] === 'ipcidr' && array_column($ext, 'interval', 'url')["$R/ip.mrs"] === 7200,
    'Mihomo: yml → yaml, behavior и интервал переданы', json_encode(array_values($ext)));
if ($runMihomo($cl, 'mihomo')) {
    $matrix('Mihomo', 1090, $expect + $rsExpect + ['rsmrs.test' => 'PROXY', '192.0.2.200' => 'PROXY']);
    $bot2 = new Lab3Bot(); $bot2->addInclude('curl', 'processlist');
    if ($runMihomo($sub('cl'), 'mihomo-process')) {
        $check($probe(1090, 'plain.test') === 'PROXY' && $probe(1090, 'ads.test') === 'BLOCK', 'Mihomo: process — запросы названной программы идут через VPN, блокировка сильнее');
    }
    $bot2 = new Lab3Bot(); $bot2->changeRouteList('processlist', function (&$l) { $l = []; });
}
foreach (['pac', 'block', 'warp', 'subnet', 'package', 'process'] as $name) {
    $b64 = base64_encode(serialize(['h' => 'fixture', 't' => 'cl', 's' => 'routes-test', 'r' => $name]));
    exec('php /lab/routes.php serve ' . escapeshellarg($b64) . ' 2>&1', $o2, $rc); $ownCl[$name] = implode(' ', $o2); $o2 = [];
}
$check(str_contains($ownCl['package'], 'PROCESS-NAME,org.telegram.messenger') || str_contains($ownCl['package'], 'org.telegram.messenger'), 'Mihomo: package отдаётся списком', $ownCl['package']);
echo "     pac: {$ownCl['pac']}\n     subnet: {$ownCl['subnet']}\n     package: {$ownCl['package']}\n     block: {$ownCl['block']}\n";

// ── Xray (клиентский профиль) ──────────────────────────────────────────────
echo "== xray ==\n";
$stop();
$x = json_decode($sub('s'), true);
foreach ($x['outbounds'] as $i => $o) {
    if (!in_array($o['protocol'] ?? '', ['freedom', 'blackhole', 'dns'], true)) {
        $x['outbounds'][$i] = ['tag' => $o['tag'], 'protocol' => 'http', 'settings' => ['servers' => [['address' => '127.0.0.1', 'port' => 3128]]]];
    }
}
$x['inbounds'] = [['listen' => '127.0.0.1', 'port' => 1091, 'protocol' => 'socks', 'settings' => ['udp' => false], 'sniffing' => ['enabled' => false]]];
unset($x['dns'], $x['api'], $x['stats'], $x['policy'], $x['observatory'], $x['burstObservatory']);
file_put_contents('/work/xray.json', json_encode($x, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
[$rc, $text] = $sh('/xray run -test -format json -config /work/xray.json');
$check($rc === 0, 'xray: профиль бота проходит проверку ядра', substr($text, -400));
exec('/xray run -format json -config /work/xray.json >/work/xray.log 2>&1 &');
if ($wait(1091)) {
    $matrix('Xray', 1091, $expect);
}
$stop();

// ── Сервер: block и WARP в рабочем конфиге Xray ────────────────────────────
echo "== xray, серверные правила block / WARP ==\n";
$srv = new Lab3Bot();
$srv->addInclude("regexp:^blk[0-9]+\\.test$", 'blocklist');
$srv->addInclude("domain:vk.com\nkeyword:reddit", 'warplist');
$srv = new Lab3Bot();
$srv->written = [];
$check($srv->xrayUpdateRules() !== false && $srv->written, 'сервер: правила собраны');
$cfg = end($srv->written);
$tags = array_column($cfg['outbounds'], 'tag');
$check(in_array('warp', $tags, true) && in_array('block', $tags, true) && in_array('direct', $tags, true), 'сервер: выходы direct, block и warp на месте', json_encode($tags));
foreach ($cfg['outbounds'] as $i => $o) {
    if (($o['tag'] ?? '') === 'warp') $cfg['outbounds'][$i] = ['tag' => 'warp', 'protocol' => 'http', 'settings' => ['servers' => [['address' => '127.0.0.1', 'port' => 3128]]]];
}
$cfg['inbounds'] = [['listen' => '127.0.0.1', 'port' => 1092, 'protocol' => 'socks', 'settings' => ['udp' => false]]];
file_put_contents('/work/server.json', json_encode($cfg, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
[$rc, $text] = $sh('/xray run -test -format json -config /work/server.json');
$check($rc === 0, 'сервер: конфиг с правилами проходит проверку ядра', substr($text, -400));
exec('/xray run -format json -config /work/server.json >/work/server.log 2>&1 &');
if ($wait(1092)) {
    $matrix('Xray-сервер', 1092, [
        'ads.test' => 'BLOCK', 'sub.ads.test' => 'BLOCK', 'tracker-banner.net' => 'BLOCK', '198.51.100.9' => 'BLOCK', 'blk7.test' => 'BLOCK', 'blkx.test' => 'DIRECT',
        'warp.test' => 'PROXY', '203.0.113.200' => 'PROXY', 'vk.com' => 'PROXY', 'm.vk.com' => 'PROXY', 'myvk.com' => 'DIRECT', 'www.reddit.com' => 'PROXY',
        // Списки domains и subnet — клиентские: на сервере они ничего не меняют.
        'example.com' => 'DIRECT', 'plain.test' => 'DIRECT',
    ]);
}
$stop();
echo "     запросов к серверам проверки: " . count(file('/work/requests.log')) . "\n";
echo $fail ? "ИТОГ: проверок $n, отказов $fail\n" : "ИТОГ: все $n проверок прошли\n";
exit($fail ? 1 : 0);
