<?php

require_once __DIR__ . '/../app/bot.php';

class RoutesBehaviorBot extends Bot
{
    public array $conf = [];
    public array $templates = [];
    public array $written = [];
    public array $messages = [];
    public bool $regexValid = true;
    public bool $coreAccepts = true;
    public bool $diskWritable = true;
    public array $updates = [];
    public string $exported = '';
    public function __construct()
    {
        $this->ip = '192.0.2.1'; $this->limit = 5;
        $this->input = ['chat' => 1, 'from' => 1, 'message_id' => 1, 'file_id' => 'fixture', 'callback_id' => 'fixture'];
        $this->conf = array_fill_keys(['includelist', 'blocklist', 'warplist', 'processlist', 'packagelist', 'subnetlist', 'rulessetlist'], [])
            + ['domain' => 'vpn.example.test', 'outbound' => 'proxy', 'transport' => 'Reality', 'xray' => str_repeat('A', 43)];
        $this->templates['v2ray'] = json_decode(file_get_contents(__DIR__ . '/../config/v2ray.json'), true);
    }
    public function getPacConf() { return $this->conf + self::PAC_DEFAULTS; }
    public function setPacConf(array $conf) { if (!$this->diskWritable) return false; $this->conf = $conf; return true; }
    public function getXray() { return ['inbounds' => [['settings' => ['clients' => [[
        'id' => '00000000-0000-4000-8000-000000000001', 'subtoken' => 'routes-test', 'email' => 'routes',
    ]]], 'streamSettings' => ['realitySettings' => ['serverNames' => ['example.test'], 'shortIds' => ['abcd']]]]],
        'outbounds' => [['tag' => 'direct', 'protocol' => 'freedom']], 'routing' => ['rules' => []]]; }
    public function restartXray($c, $norestart = false) { if (!$this->coreAccepts) return false; $this->written[] = $c; return true; }
    public function datSync(bool $force = false, ?bool &$changed = null): array { return []; }
    public function getHashBot($notset = false) { return 'fixture'; }
    public function subDomain(array $pac): string { return 'vpn.example.test'; }
    public function nginxGetTypeCert() { return false; }
    public function flagName(string $name, string|array $hosts, bool $cacheOnly = true): string { return $name; }
    public function subscriptionCompatibilityError(array $xr, array $pac, string $type): string { return ''; }
    public function smuxActive(?array $p = null): bool { return false; }
    public function subTemplate(string $template, string $type, array $pac) { return $this->templates[$type]; }
    public function appendXrayProtocols(array &$config, array $client, string $type, int $index, ?array $relay = null, bool $keepPrimary = true): bool { return false; }
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML') { $this->updates[] = [$text, $button]; return []; }
    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false) { $this->messages[] = $text; return []; }
    public function i18n(string $menu): string { return $menu; }
    public function request($method, $data, $json_header = 0) { return ['result' => ['file_path' => '']]; }
    public function pacUpdate($import = '') {}
    public function answer($callback_id, $textNotify = false, $notify = false) {}
    public function sendFile($chat, $id_url_cFile, $caption = false, $to = false) { $this->exported = $id_url_cFile->data; }
    public function sessionApply(callable $fn) { $fn(); }
    public function validateRouteRegexes(array $patterns): bool { return !$patterns || $this->regexValid; }
    public array $probe = [];
    public function ruleSetProbe(string $url): string { return $this->probe[$url] ?? ''; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
}

if (getenv('VPNBOT_ROUTES_FIXTURE_ONLY') === '1') return;

$failures = []; $checks = 0;
$check = function (bool $ok, string $label) use (&$failures, &$checks) { $checks++; if (!$ok) $failures[] = $label; };
$bot = new RoutesBehaviorBot();
$_GET = ['t' => 's', 's' => 'routes-test'];
$bot->conf['blocklist'] = ['198.51.100.1' => true];
$bot->conf['includelist'] = ['Example.COM.' => true, 'keyword:ads' => true, 'disabled.test' => false];
$config = json_decode($bot->subscription(true), true);
$rules = $config['routing']['rules'];
$check(($rules[0]['outboundTag'] ?? '') === 'block', 'Xray: IP-блокировка сохраняет приоритет перед доменным proxy');
$domain = array_merge(...array_column($rules, 'domain'));
$check(in_array('domain:example.com', $domain, true), 'Xray: голый домен PAC означает суффикс и канонизируется');
$check(in_array('ads', $domain, true) && !in_array('keyword:ads', $domain, true), 'Xray: keyword означает подстроку');
$check(!in_array('disabled.test', $domain, true), 'Выключенная запись не попадает в профиль');

$custom = [
    ['type' => 'field', 'outboundTag' => 'direct', 'ip' => ['198.51.100.0/24'], 'network' => 'udp'],
    ['type' => 'field', 'outboundTag' => 'block', 'domain' => ['full:example.test'], 'port' => '443', 'ruleTag' => 'restricted'],
    ['type' => 'field', 'balancerTag' => 'pool', 'domain' => ['keyword'], 'network' => 'tcp'],
    ['type' => 'field', 'outboundTag' => 'proxy', 'domain' => ['domain:other.test'], 'ip' => ['203.0.113.0/24']],
];
$bot->templates['v2ray']['routing']['rules'] = $custom;
$config = json_decode($bot->subscription(true), true);
$check($config['routing']['rules'] === $custom, 'Xray: порядок, AND-условия, ruleTag и balancerTag шаблона сохранены');

foreach (['blocklist', 'warplist'] as $type) {
    $bot->conf[$type] = ['example.test' => true]; $bot->written = [];
    $bot->deleteYes($type);
    $check(count($bot->written) === 1, "$type: удаление всех правил применяется к ядру");
}

$bot->conf['blocklist'] = ['b.test' => true, 'c.test' => true];
[$menu] = $bot->listPac('blocklist', 0, 'xtlsblock');
$button = $menu[1][1]['callback_data'];
$bot->conf['blocklist'] = ['a.test' => true] + $bot->conf['blocklist'];
preg_match('~^/deleteblocklist (\S+) (\d+)$~', $button, $m);
$bot->listPacChange('blocklist', 'delete', $m[1], $m[2]);
$check(isset($bot->conf['blocklist']['a.test']) && !isset($bot->conf['blocklist']['b.test']), 'Старая кнопка удаляет исходную запись после сдвига списка');

$tmp = tempnam(sys_get_temp_dir(), 'routes-import-');
try {
    $bot->file = $tmp;
    file_put_contents($tmp, "regexp:^foo;bar$;1\ndomain:off.test;0\n");
    $bot->importListFile('', 'includelist');
    $check(($bot->conf['includelist']['regexp:^foo;bar$'] ?? false) === true, 'Импорт сохраняет точку с запятой внутри regexp');
    $check(($bot->conf['includelist']['domain:off.test'] ?? null) === false, 'Импорт сохраняет выключенное состояние');
    $before = $bot->conf['includelist'];
    file_put_contents($tmp, "domain:\nkeyword:\n");
    $bot->importListFile('', 'includelist');
    $check($bot->conf['includelist'] === $before, 'Невалидный импорт не стирает существующий список');
} finally { unlink($tmp); }

$bot->conf['rulessetlist'] = [
    'block:1d:https://rules.test/block.srs' => true,
    'proxy:86400:https://rules.test/proxy.srs?version=1' => true,
];
$route = $bot->addRuleSet(['rules' => [['action' => 'reject', 'addruleset' => true], ['outbound' => 'proxy', 'addruleset' => true]]]);
$check(count($route['rule_set'] ?? []) === 2, 'sing-box: URL rule-set с query не пропускается');
$check(($route['rule_set'][1]['update_interval'] ?? '') === '86400s', 'sing-box: числовой интервал переводится в секунды');
$bot->conf['rulessetlist'] = [
    'block:1d:https://rules.test/block.yaml' => true,
    'MyProxy:domain:1h:https://rules.test/other.mrs?version=1' => true,
];
$cl = $bot->addClashRuleSet(['add-rule-providers' => true, 'proxy-groups' => [['name' => 'MyProxy']], 'rules' => [['MATCH', 'DIRECT']]]);
$check(($cl['rules'][0][2] ?? '') === 'REJECT', 'Mihomo: block преобразуется в REJECT');
$providers = array_column($cl['rule-providers'] ?? [], null, 'url');
$check(($providers['https://rules.test/block.yaml']['interval'] ?? 0) === 86400, 'Mihomo: 1d означает 86400 секунд');
$check(in_array('MyProxy', array_column($cl['rules'], 2), true), 'Mihomo: сохраняется регистр пользовательского outbound');
$check(count(array_filter($providers, fn($p) => ($p['proxy'] ?? '') === 'DIRECT')) === count($providers), 'Mihomo скачивает правила независимо от маршрутизации');

$bot = new RoutesBehaviorBot();
foreach (['includelist' => 'domain:example.test', 'blocklist' => 'full:block.test', 'warplist' => 'warp.test',
    'subnetlist' => '2001:db8::/32', 'processlist' => 'firefox', 'packagelist' => 'org.telegram.messenger',
    'rulessetlist' => 'proxy:1h:https://rules.test/set.srs?a=1,2'] as $type => $entry) {
    $bot->conf[$type] = [];
    $bot->addInclude($entry, $type);
    $check(($bot->conf[$type][$entry] ?? false) === true, "$type: добавление");
    $key = 'k' . substr(hash('sha256', $entry), 0, 20);
    $bot->listPacChange($type, 'change', $key);
    $check($bot->conf[$type][$entry] === false, "$type: выключение");
    $bot->addInclude($entry, $type);
    $check($bot->conf[$type][$entry] === false, "$type: повтор не включает запись");
    $bot->listPacChange($type, 'change', $key);
    $check($bot->conf[$type][$entry] === true, "$type: повторное включение");
    $bot->exportList($type);
    $check(str_contains($bot->exported, $entry . ';1'), "$type: экспорт");
    $bot->listPacChange($type, 'delete', $key);
    $check($bot->conf[$type] === [], "$type: удаление одной записи");
    $bot->listPacChange($type, 'change', $key);
    $check($bot->conf[$type] === [], "$type: удалённая запись не возвращается старой кнопкой");
}
$before = $bot->conf;
$bot->deleteYes('domain');
$check($bot->conf === $before, 'Произвольный callback не стирает настройки вне списков');
$bot->addInclude('example.test, 999.1.1.1, 1.2.3.4/33, 2001:db8::/129, 198.51.100.7', 'subnetlist');
$check($bot->conf['subnetlist'] === ['198.51.100.7' => true], 'Subnet принимает только корректные IP/CIDR');
$bot->conf['blocklist'] = ['good.test' => true];
$bot->coreAccepts = false; $before = $bot->conf; $written = $bot->written;
$bot->addInclude('new.test', 'blocklist');
$check($bot->conf === $before && $bot->written === $written, 'Отказ ядра сохраняет прежние список и конфигурацию');
$bot->deleteYes('blocklist');
$check($bot->conf === $before, 'Отказ ядра при очистке тоже откатывает список');
$bot->coreAccepts = true; $bot->diskWritable = false;
$bot->addInclude('new.test', 'blocklist');
$check($bot->conf === $before && $bot->written === $written, 'Ошибка записи не перезапускает ядро');
$bot->diskWritable = true; $bot->regexValid = false;
$bot->addInclude('regexp:[', 'includelist');
$check($bot->conf === $before, 'Ошибка RE2 не сохраняет сломанный клиентский список');
$bot->conf['includelist'] = ['regexp:[' => false]; $before = $bot->conf;
$bot->listPacChange('includelist', 'change', 'k' . substr(hash('sha256', 'regexp:['), 0, 20));
$check($bot->conf === $before, 'Включение старого невалидного regexp отклоняется');
$bot->addInclude('ext:missing-fixture.dat:ads', 'blocklist');
$check($bot->conf === $before, 'Отсутствующий DAT не создаёт фиктивно включённое правило');
$bot->regexValid = true; $bot->conf['blocklist'] = ['ext:missing-fixture.dat:ads' => true];
$bot->addInclude('other.test', 'blocklist');
$check(isset($bot->conf['blocklist']['other.test']), 'Выключенный DAT не мешает редактировать остальные правила');
$check($bot->routeEntryCanonKey('ext:A.dat:TAG') !== $bot->routeEntryCanonKey('ext:a.dat:tag'), 'Разный регистр файлов DAT не считается дублем');
foreach (['0', '-1', '1oops', 'NaN', '1.5', '1e999'] as $bad) {
    $check(Bot::parseRuleSetKey("proxy:$bad:https://rules.test/a.srs") === null, "Неверный интервал $bad отклоняется");
}
foreach (['domain:','full:', 'https://example.test/path', 'example.test:443', '2001:wrong::1', '1.2.3.4/999'] as $bad) {
    $check(!$bot->routeListEntryValid('includelist', $bad), "Неверный адрес $bad отклоняется");
}
$check($bot->normalizeSrsRules([['domain_suffix' => ['ext:test.dat:ads']]]) === [], 'Неподдерживаемый DAT не превращается в catch-all SRS');
$check($bot->normalizeSrsRules([['ip_cidr' => ['bad.test', '198.51.100.1']]]) === [['ip_cidr' => ['198.51.100.1/32']]], 'Старые ошибочные подсети не ломают SRS');
$check($bot->normalizeSrsRules([['domain_suffix' => [], 'port' => [443]]]) === [], 'Пустой PAC-селектор не расширяется до всех соединений на порту');

class CustomRouteBot extends RoutesBehaviorBot {
    public array $custom = [];
    public function getXray() { $c = parent::getXray(); $c['routing']['rules'] = $this->custom; return $c; }
}
$customBot = new CustomRouteBot();
$customBot->conf['blocklist'] = ['new.test' => true];
$customBot->custom = [
    ['type' => 'field', 'outboundTag' => 'block', 'domain' => ['domain:old.test']],
    ['type' => 'field', 'outboundTag' => 'block', 'domain' => ['full:manual.test']],
    ['type' => 'field', 'outboundTag' => 'warp', 'ip' => ['203.0.113.0/24']],
];
$customBot->xrayUpdateRules(['blocklist' => ['old.test' => true]]);
$changed = end($customBot->written)['routing']['rules'];
$check(!in_array($customBot->custom[0], $changed, true), 'Прежнее правило бота без ruleTag заменено');
$check(in_array($customBot->custom[1], $changed, true) && in_array($customBot->custom[2], $changed, true), 'Простые пользовательские block/warp-правила сохранены');
$customBot->conf['rulessetlist'] = ['direct:1h:https://rules.test/direct.yaml' => true];
$cl = $customBot->addClashRuleSet(['add-rule-providers' => true, 'rules' => [
    ['type' => 'RULE-SET', 'action' => 'REJECT', 'name' => 'block'],
    ['type' => 'RULE-SET', 'action' => 'PROXY', 'name' => 'pac'], ['type' => 'MATCH', 'action' => 'DIRECT'],
]]);
$check(($cl['rules'][0]['action'] ?? '') === 'REJECT' && ($cl['rules'][1][2] ?? '') === 'DIRECT'
    && ($cl['rules'][2]['action'] ?? '') === 'PROXY', 'Прямые исключения Mihomo после блокировки и перед VPN, как в sing-box');

// Незнакомый outbound не должен ломать весь профиль Mihomo.
$bot->conf['rulessetlist'] = ['ghost:1h:https://rules.test/no.yaml' => true,
    'proxy:1h:https://rules.test/yes.yaml' => true];
$cl = $bot->addClashRuleSet(['add-rule-providers' => true, 'proxy-groups' => [['name' => 'PROXY']],
    'rules' => [['MATCH', 'DIRECT'], ['DOMAIN', 'unreachable.test', 'DIRECT']]]);
$check(count($cl['rule-providers'] ?? []) === 1, 'Неизвестный outbound не создаёт битое правило Mihomo');
$check(($cl['rules'][0][0] ?? '') === 'RULE-SET' && $cl['rules'][1][0] === 'MATCH', 'Внешний набор вставляется до первого MATCH');
foreach (['white', 'deny'] as $type) {
    $bot->conf[$type] = [];
    $bot->changeRouteList($type, function (&$list) use ($bot, $type) {
        foreach (['198.51.100.1', '2001:db8::/32', 'evil.test', '1.2.3.4;exec'] as $entry)
            if ($bot->routeListEntryValid($type, $entry)) $list[] = $entry;
    });
    $check($bot->conf[$type] === ['198.51.100.1', '2001:db8::/32'], "$type допускает только IP/CIDR");
}
$check(!$bot->routeListEntryValid('datlist', 'a.dat:https://bad host/a'), 'DAT с некорректным URL отклоняется и при импорте');

class RouteDatRollbackBot extends RoutesBehaviorBot {
    public string $assetDir;
    public function datDir(): string { return $this->assetDir; }
    public function datSync(bool $force = false, ?bool &$changed = null): array {
        @unlink($this->datPath('sample.dat')); @unlink($this->datPath('sample.dat.meta')); return [];
    }
}
$assetBot = new RouteDatRollbackBot();
$assetBot->assetDir = sys_get_temp_dir() . '/routes-dat-' . getmypid(); mkdir($assetBot->assetDir);
try {
    file_put_contents($assetBot->datPath('sample.dat'), 'working-data');
    file_put_contents($assetBot->datPath('sample.dat.meta'), 'working-metadata');
    $assetBot->conf['datlist'] = ['sample.dat:https://example.test/a' => true];
    $before = $assetBot->getPacConf(); $assetBot->coreAccepts = false;
    $ok = $assetBot->changeRouteList('datlist', function (&$list) { $list = []; });
    $check(!$ok && $before === $assetBot->conf, 'Отказ Xray откатывает реестр DAT');
    $check(file_get_contents($assetBot->datPath('sample.dat')) === 'working-data'
        && file_get_contents($assetBot->datPath('sample.dat.meta')) === 'working-metadata', 'Откат DAT восстанавливает удалённые assets и metadata');
    $assetBot->coreAccepts = true;
    $check($assetBot->changeRouteList('datlist', function (&$list) { $list = []; })
        && !glob($assetBot->assetDir . '/*'), 'Успешное удаление DAT не оставляет backup-файлов');
} finally { foreach (glob($assetBot->assetDir . '/*') ?: [] as $f) unlink($f); rmdir($assetBot->assetDir); }

$bot->routes();
$check(str_contains(json_encode(end($bot->updates), JSON_UNESCAPED_UNICODE), '/routeshelp 0'), 'Справка доступна из routes');
$help = require __DIR__ . '/../app/routes_help.php';
$titles = array_keys($help);
$pageCount = count($help);
$bot->routesHelp();
[$indexBody, $indexButtons] = end($bot->updates);
$check(array_column(array_merge(...$indexButtons), 'callback_data')
    === [...array_map(fn($n) => "/routeshelp $n", range(1, $pageCount)), '/routes'], 'Оглавление открывает каждую тему и возвращает в routes');
foreach ([...range(0, $pageCount), -1, 999] as $page) {
    $bot->routesHelp($page); [$body, $buttons] = end($bot->updates);
    $current = max(0, min($page, $pageCount));
    $check(strlen(mb_convert_encoding($body, 'UTF-16LE', 'UTF-8')) / 2 <= 4096, 'Справка вместе с заголовком укладывается в лимит Telegram');
    preg_match_all('~</?(b|code)>~', $body, $tags);
    $stack = []; $validHtml = true;
    foreach ($tags[0] as $tag) {
        if ($tag[1] !== '/') $stack[] = substr($tag, 1, -1);
        elseif (array_pop($stack) !== substr($tag, 2, -1)) $validHtml = false;
    }
    $check($validHtml && !$stack && !preg_match('~[<>]~', preg_replace('~</?(b|code)>~', '', $body)), 'HTML справки корректен, примеры не ломают разметку');
    foreach ($buttons as $row) foreach ($row as $button) $check(strlen($button['callback_data']) <= 64, 'Кнопки справки укладываются в лимит Telegram');
    $callbacks = array_column(array_merge(...$buttons), 'callback_data');
    $check(end($callbacks) === '/routes', 'Из каждой страницы можно вернуться к спискам');
    if ($current === 0) {
        $check($body === $indexBody && $buttons === $indexButtons, 'Нулевая и отрицательная страницы открывают оглавление');
    } else {
        $check(str_contains($body, $help[$titles[$current - 1]]), 'Кнопка открывает выбранную тему');
        $expected = [];
        if ($current > 1) $expected[] = '/routeshelp ' . ($current - 1);
        $expected[] = "/routeshelp $current";
        if ($current < $pageCount) $expected[] = '/routeshelp ' . ($current + 1);
        $check($callbacks === [...$expected, '/routeshelp 0', '/routes'], 'Стрелки ведут к соседним темам, кнопка всех тем — к оглавлению');
    }
}

// ── rule-set: проверка источника при добавлении и подпись ядра в меню ───────
$check(Bot::ruleSetBodyError('srs', "SRS\x01rest") === '' && Bot::ruleSetBodyError('srs', '<html>404</html>') !== '', 'rule-set: .srs узнаётся по сигнатуре');
$check(Bot::ruleSetBodyError('mrs', "\x28\xb5\x2f\xfd\x04") === '' && Bot::ruleSetBodyError('mrs', 'payload:') !== '', 'rule-set: .mrs узнаётся по сигнатуре');
$check(Bot::ruleSetBodyError('json', '{"version":1,"rules":[]}') === '' && Bot::ruleSetBodyError('json', '{"message":"Not Found"}') !== ''
    && Bot::ruleSetBodyError('json', 'not json') !== '', 'rule-set: JSON обязан содержать rules');
$check(Bot::ruleSetBodyError('yaml', "# list\npayload:\n  - DOMAIN,a.test\n") === '' && Bot::ruleSetBodyError('yml', "<!DOCTYPE html><p>payload:</p>") !== ''
    && Bot::ruleSetBodyError('yaml', "rules:\n - a\n") !== '', 'rule-set: YAML обязан содержать payload');
$check(Bot::ruleSetBodyError('txt', "DOMAIN,a.test\n") === '' && Bot::ruleSetBodyError('txt', " \n") !== ''
    && Bot::ruleSetBodyError('txt', "<html><body>blocked</body></html>") !== '', 'rule-set: пустой TXT и страница HTML отмечаются');
$check(Bot::ruleSetCore('https://x.test/a.srs?v=1') === 'sing-box' && Bot::ruleSetCore('https://x.test/a.json') === 'sing-box'
    && Bot::ruleSetCore('https://x.test/a.yaml') === 'Mihomo' && Bot::ruleSetCore('https://x.test/a.mrs') === 'Mihomo', 'rule-set: ядро определяется по формату');
$rs = new RoutesBehaviorBot();
$rs->probe = ['https://rules.test/dead.srs' => 'http 404'];
$rs->addInclude("block:1d:https://rules.test/dead.srs\nproxy:1h:https://rules.test/ok.yaml", 'rulessetlist');
$check(count($rs->conf['rulessetlist']) === 2, 'rule-set: непрошедший проверку источник всё равно сохраняется');
$warn = implode("\n", $rs->messages);
$check(str_contains($warn, 'dead.srs — http 404') && !str_contains($warn, 'ok.yaml'), 'rule-set: о недоступном источнике сообщается, об исправном — нет');
$rs->messages = [];
$rs->addInclude('block:1d:https://rules.test/dead.srs', 'rulessetlist');
$check(!str_contains(implode("\n", $rs->messages), 'не прошёл проверку'), 'rule-set: повторное добавление той же записи источник не перепроверяет');
$plainRs = (new ReflectionClass(Bot::class))->newInstanceWithoutConstructor();
$check($plainRs->ruleSetProbe('http://127.0.0.1/a.srs') === '' && $plainRs->ruleSetProbe('https://127.0.0.1/a.srs') !== '', 'rule-set: http не запрашивается, внутренний адрес по https не проходит');
$rs->updates = [];
$rs->xtlsrulesset();
$menuText = end($rs->updates)[0];
$check(str_contains($menuText, '→ sing-box') && str_contains($menuText, '→ Mihomo'), 'rule-set: в меню подписано, каким ядром источник используется');

// ── Ввод записей: столбик, запятая, пробел — и их смесь ─────────────────────
$forms = [
    'столбик'             => "vk.com\nyoutube.com\nkeyword:reddit",
    'запятая'             => 'vk.com,youtube.com,keyword:reddit',
    'запятая с пробелом'  => 'vk.com, youtube.com, keyword:reddit',
    'пробел'              => 'vk.com youtube.com keyword:reddit',
    'несколько пробелов'  => "  vk.com   youtube.com\tkeyword:reddit  ",
    'смесь'               => "vk.com youtube.com,\n keyword:reddit\r\n",
];
foreach (['includelist', 'blocklist', 'warplist'] as $type) {
    foreach ($forms as $name => $input) {
        $in = new RoutesBehaviorBot(); $in->addInclude($input, $type);
        $check(array_keys($in->conf[$type]) === ['keyword:reddit', 'vk.com', 'youtube.com'] && $in->messages === [],
            "Ввод «{$name}» в $type даёт три записи: " . json_encode(array_keys($in->conf[$type])) . ' ' . json_encode($in->messages, JSON_UNESCAPED_UNICODE));
    }
}
foreach (["10.0.0.0/8\n172.16.5.5\n2001:db8::/32", '10.0.0.0/8,172.16.5.5,2001:db8::/32', '10.0.0.0/8 172.16.5.5 2001:db8::/32', "10.0.0.0/8, 172.16.5.5\n2001:db8::/32"] as $input) {
    $in = new RoutesBehaviorBot(); $in->addInclude($input, 'subnetlist');
    $check(array_keys($in->conf['subnetlist']) == ['10.0.0.0/8', '172.16.5.5', '2001:db8::/32'], 'subnet: ввод ' . json_encode($input) . ' → ' . json_encode(array_keys($in->conf['subnetlist'])));
}
foreach (["org.a.b\ncom.c.d", 'org.a.b,com.c.d', 'org.a.b com.c.d', 'org.a.b,  com.c.d'] as $input) {
    $in = new RoutesBehaviorBot(); $in->addInclude($input, 'packagelist');
    $check(array_keys($in->conf['packagelist']) === ['com.c.d', 'org.a.b'], 'package: ввод ' . json_encode($input) . ' → ' . json_encode(array_keys($in->conf['packagelist'])));
}
// Имя процесса может содержать пробел: разделители — только запятая и новая строка.
$in = new RoutesBehaviorBot(); $in->addInclude("Google Chrome Helper, firefox\nchrome.exe", 'processlist');
$check(array_keys($in->conf['processlist']) === ['Google Chrome Helper', 'chrome.exe', 'firefox'], 'process: пробел остаётся частью имени: ' . json_encode(array_keys($in->conf['processlist'])));
// regexp: забирает остаток строки вместе с запятыми и пробелами; до него записи делятся как обычно.
$check($bot->splitRouteInput('a.com b.com regexp:^x{1,3} y, z$') === ['a.com', 'b.com', 'regexp:^x{1,3} y, z$'], 'regexp после пробела забирает остаток строки: ' . json_encode($bot->splitRouteInput('a.com b.com regexp:^x{1,3} y, z$')));
$check($bot->splitRouteInput("regexp:a b,c\nd.com e.com") === ['regexp:a b,c', 'd.com', 'e.com'], 'regexp в начале строки не делится, следующая строка — как обычно');
$check($bot->splitRouteInput('a.com, b.com c.com', false) === ['a.com', 'b.com c.com'], 'без деления по пробелам пробел остаётся в записи');
$check($bot->splitRouteInput(" \n ,  , \t") === [], 'пустой ввод не даёт записей');
// Отклонённые записи называются, а верные из того же ввода сохраняются.
$in = new RoutesBehaviorBot(); $in->addInclude('good.test bad_domain!.test 999.1.1.1 keyword: <b>x</b>', 'includelist');
$said = implode("\n", $in->messages);
$check(array_keys($in->conf['includelist']) === ['good.test'] && str_contains($said, 'пропущено: 4') && str_contains($said, '<code>999.1.1.1</code>')
    && str_contains($said, '&lt;b&gt;x&lt;/b&gt;') && !str_contains($said, '<b>x</b>'), 'Неверные записи названы и экранированы, верная сохранена: ' . $said);

// ── Сведение дублей: одна и та же запись в разных написаниях ────────────────
$dup = function (string $type, array $inputs, array $start = []) { $b = new RoutesBehaviorBot(); $b->conf[$type] = $start; foreach ($inputs as $i) $b->addInclude($i, $type); return $b; };
foreach ([
    'регистр, точка в конце и префикс domain:' => [['vk.com VK.COM vk.com. domain:vk.com'], ['domain:vk.com']],
    'то же в два приёма'                       => [['vk.com', 'domain:VK.com'], ['vk.com']],
    'keyword без учёта регистра'               => [['keyword:Reddit keyword:reddit'], ['keyword:Reddit']],
    'IDN и его punycode'                       => [['пример.рф xn--e1afmkfd.xn--p1ai'], ['xn--e1afmkfd.xn--p1ai']],
    'адрес и адрес/32'                         => [['1.2.3.4 1.2.3.4/32'], ['1.2.3.4']],
    'IPv6 в трёх написаниях'                   => [['2001:0DB8::1 2001:db8::1/128 2001:db8:0:0::1'], ['2001:0DB8::1']],
    'одна подсеть дважды'                      => [['10.0.0.0/8, 10.0.0.0/8'], ['10.0.0.0/8']],
    'одинаковый regexp'                        => [['regexp:.*\.ru$', 'regexp:.*\.ru$'], ['regexp:.*\.ru$']],
    'категория geosite без учёта регистра'     => [['geosite:CN geosite:cn'], ['geosite:CN']],
] as $name => [$inputs, $want]) {
    $b = $dup('includelist', $inputs);
    $check(array_keys($b->conf['includelist']) === $want && preg_match('~duplicates (skipped|merged)~', implode(' ', $b->messages)) === 1,
        "Дубли ($name) сведены к одной записи: " . json_encode(array_keys($b->conf['includelist']), JSON_UNESCAPED_UNICODE) . ' ' . json_encode($b->messages));
}
// Разные по смыслу записи дублями не считаются.
foreach ([['full:vk.com vk.com'], ['sub.vk.com vk.com'], ['keyword:vk vk.com'], ['1.2.3.0/24 1.2.3.4'], ["regexp:^vk\\.com$\nvk.com"], ['geosite:cn geoip:cn']] as $inputs) {
    $b = $dup('includelist', $inputs);
    $check(count($b->conf['includelist']) === 2 && $b->messages === [], 'Разные записи не сведены: ' . json_encode($inputs) . ' → ' . json_encode(array_keys($b->conf['includelist'])));
}
foreach (['blocklist', 'warplist'] as $type) {
    $b = $dup($type, ['ads.test ADS.test domain:ads.test 198.51.100.1 198.51.100.1/32']);
    $check(array_keys($b->conf[$type]) === ['198.51.100.1', 'domain:ads.test'], "Дубли в $type сведены: " . json_encode(array_keys($b->conf[$type])));
}
$b = $dup('subnetlist', ['10.0.0.1 10.0.0.1/32 10.0.0.0/24 10.0.0.0/24']);
$check(array_keys($b->conf['subnetlist']) == ['10.0.0.0/24', '10.0.0.1'], 'Дубли в subnet сведены: ' . json_encode(array_keys($b->conf['subnetlist'])));
$b = $dup('packagelist', ['org.a.b org.a.b, org.a.b']);
$check(array_keys($b->conf['packagelist']) === ['org.a.b'], 'Повтор пакета не добавляется');
$b = $dup('rulessetlist', ["block:1d:https://r.test/a.srs\nblock:1d:https://r.test/a.srs"]);
$check(count($b->conf['rulessetlist']) === 1, 'Повтор rule-set не добавляется');
// Запись уже есть, но выключена: не включается молча и не дублируется — о ней сообщается.
$b = $dup('includelist', ['VK.com domain:vk.com new.test'], ['vk.com' => false]);
$check($b->conf['includelist'] === ['new.test' => true, 'vk.com' => false] && str_contains(implode("\n", $b->messages), 'выключены') && str_contains(implode("\n", $b->messages), '<code>vk.com</code>'),
    'Повторный ввод выключенной записи: состояние не меняется, о ней сказано: ' . json_encode($b->conf['includelist']) . ' ' . json_encode($b->messages, JSON_UNESCAPED_UNICODE));
// Кнопка «схлопнуть дубли» на списке, накопленном до появления канона.
$b = new RoutesBehaviorBot();
$b->conf['includelist'] = ['VK.com' => true, 'domain:vk.com' => true, 'vk.com' => false, '1.2.3.4' => true, '1.2.3.4/32' => true, 'keep.test' => true];
$b->dedupeList('includelist');
$check(count($b->conf['includelist']) === 3 && isset($b->conf['includelist']['keep.test']) && in_array(true, array_intersect_key($b->conf['includelist'], ['VK.com' => 1, 'domain:vk.com' => 1, 'vk.com' => 1]), true),
    'Кнопка сведения дублей оставляет по одной включённой записи: ' . json_encode($b->conf['includelist']));

foreach ($failures as $failure) echo "FAIL: $failure\n";
echo "routes_behavior_test: $checks checks, " . count($failures) . " failures\n";
exit($failures ? 1 : 0);
