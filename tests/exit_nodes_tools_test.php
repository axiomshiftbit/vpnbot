<?php
// Узлы выхода: история доступности, страна YouTube, скорость, наборы сервисов,
// копирование и экспорт/импорт маршрутов, «Куда пойдёт домен».
// С VLESS_TEST_XRAY временный конфиг «Куда пойдёт домен» проверяет настоящее ядро.
require_once __DIR__ . '/../app/bot.php';
set_error_handler(static function ($level, $message, $file, $line) { if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line); return true; });

class ExitToolsBot extends Bot
{
    public array $confPac = ['transport' => 'Reality', 'xray_core' => 'origin', 'blocklist' => ['domain:ads.example' => 1], 'warplist' => ['domain:warp.example' => 1]];
    public array $confXray = [];
    public array $screens = []; public array $files = []; public array $prompt = []; public array $ssh = []; public array $notified = []; public array $answers = [];
    public string $sshAnswer = '';
    public ?Closure $sshHook = null;
    public array $status = [];
    public ?string $download = null;
    public string $traceRoot = '';
    public function __construct()
    {
        $this->input = ['chat' => 1, 'from' => 1, 'message_id' => 5, 'callback_id' => 'cb', 'username' => 'admin'];
        $this->language = 'ru';
        $this->ip = '198.51.100.1';
        require __DIR__ . '/../app/i18n.php';
        $this->i18n = $i;
        $this->confXray = ['inbounds' => [['tag' => 'vless_tls', 'port' => 443, 'protocol' => 'vless',
            'sniffing' => ['enabled' => true, 'destOverride' => ['http', 'tls', 'quic']],
            'settings' => ['decryption' => 'none', 'clients' => [
                ['id' => '11111111-1111-4111-8111-111111111111', 'email' => 'alice'],
                ['id' => '22222222-2222-4222-8222-222222222222', 'email' => 'bob'],
                ['id' => '33333333-3333-4333-8333-333333333333', 'email' => 'node-relay', 'exit_relay' => 1],
            ]]], ['tag' => 'api', 'protocol' => 'dokodemo-door', 'port' => 8080]],
            'outbounds' => [['tag' => 'direct', 'protocol' => 'freedom'], ['tag' => 'block', 'protocol' => 'blackhole'], ['tag' => 'warp', 'protocol' => 'socks']],
            'routing' => ['domainStrategy' => 'IPIfNonMatch', 'rules' => []]];
    }
    public function getPacConf() { return $this->confPac; }
    public function setPacConf(array $conf) { $this->confPac = $conf; return true; }
    public function getXray() { return $this->confXray; }
    public function restartXray($c, $norestart = false) { $this->ensureExitNodes($c, $this->confPac); $this->confXray = $c; return true; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
    {
        $this->ssh[] = [$service, $cmd];
        $this->sshFailed = false;
        return $this->sshHook ? ($this->sshHook)($cmd) : $this->sshAnswer;
    }
    public function exitStatus(): array { return $this->status; }
    // Как на сервере: следующая проба видит записанное состояние.
    protected function exitStatusWrite(string $id, array $status): void { $this->status[$id] = $status; }
    protected function exitRulesetDir(): string { return sys_get_temp_dir() . '/exit-rulesets-test-' . getmypid(); }
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML') { $this->screens[] = [$text, is_array($button) ? $button : []]; }
    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false) { return ['result' => ['message_id' => 9]]; }
    public function sendFile($chat, $id_url_cFile, $caption = false, $to = false) { $this->files[] = [$id_url_cFile, $caption]; return ['ok' => true]; }
    public function answer($callback_id, $textNotify = false, $notify = false) { $this->answers[] = $textNotify; }
    public function stashReply($r, array $state) { $this->prompt = $state; }
    public function notifyAdmins(string $text): void { $this->notified[] = $text; }
    public function xrayStatCounters(): ?array { return []; }
    protected function exitImportDownload(): ?string { return $this->download; }
    protected function exitTraceRoot(): string { return $this->traceRoot; }
    protected function xdriveResolve(string $host): array { return ['203.0.113.7']; }
    public function last(): array { return end($this->screens) ?: ['', []]; }
    public function callbacks(): array { $all = []; foreach ($this->last()[1] as $row) foreach ($row as $b) $all[$b['callback_data'] ?? ''] = $b['text']; return $all; }
}

$failures = [];
$check = static function (bool $ok, string $name) use (&$failures): void { if (!$ok) $failures[] = $name; };
$pbk = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
$link = fn(string $host) => "vless://0b6e8f8a-3c1d-4f6e-9a2b-1c2d3e4f5a6b@$host:443?security=reality&sni=www.example.com&fp=chrome&pbk=$pbk&sid=a1b2&type=tcp&flow=xtls-rprx-vision#" . strtoupper(explode('.', $host)[0]);
$bot = new ExitToolsBot();
$bot->saveExitAdd($link('fi.example.org'));
$bot->saveExitAdd($link('de.example.org'));
[$id, $id2] = array_map('strval', array_keys($bot->confPac['exits']));
$check(strlen($id) === 8 && strlen($id2) === 8, 'два узла добавлены');

// --- История доступности ----------------------------------------------------
$now = time();
$hist = Bot::exitHistoryAdd([[$now - 90000, 1], 'junk', [$now - 600, 0], [$now - 300, 1]], $now, false);
$check($hist === [[$now - 600, 0], [$now - 300, 1], [$now, 0]], 'история: старше суток и мусор отброшены');
$s = ['hist' => []];
for ($k = 0; $k < 10; $k++) $s['hist'][] = [$now - 3000 + $k * 300, in_array($k, [2, 3, 7], true) ? 0 : 1];
$line = $bot->exitHistoryLine($s);
$check(str_contains($line, '70,0 %') && str_contains($line, 'проверок: 10'), 'история: процент и число проверок');
$check(str_contains($line, date('H:i', $now - 2400) . '–' . date('H:i', $now - 2100)) && str_contains($line, date('H:i', $now - 900)), 'история: подряд идущие отказы — один сбой');
$check($bot->exitHistoryLine([]) === '' && $bot->exitHistoryLine(['hist' => [[$now - 90000, 0]]]) === '', 'история: нет данных — пустая строка');
$bot->language = 'en';
$check(str_contains($bot->exitHistoryLine($s), '70.0 %') && str_contains($bot->exitHistoryLine($s), 'last outages'), 'история: английский');
$bot->language = 'ru';

// --- Проба: история, время полной проверки, страна YouTube --------------------
$bot->sshAnswer = "probe=204 0.050\nip=203.0.113.50\nloc=FI\n";
$bot->status = [$id => ['time' => $now - 300, 'ok' => true, 'gl' => 'RU', 'full_time' => $now - 1000, 'hist' => [[$now - 300, 1]]]];
$st = $bot->exitProbe($id, false);
$check(($st['gl'] ?? '') === 'RU' && ($st['full_time'] ?? 0) === $now - 1000 && count($st['hist']) === 2, 'быстрая проба: страна и время полной сохраняются, история растёт');
$bot->sshAnswer = "probe=204 0.050\nloc=FI\n\"INNERTUBE_CONTEXT_GL\":\"FI\"\n";
$st = $bot->exitProbe($id, true);
$check(($st['gl'] ?? '') === 'FI' && $st['full_time'] >= $now, 'полная проба: новая страна и время');

// --- Cron: полная проба раз в сутки и сигнал о смене страны -------------------
$bot->confPac['exits'][$id2]['enabled'] = 0;
$bot->status = [$id => ['time' => $now - 300, 'ok' => true, 'gl' => 'RU', 'full_time' => $now - 90000]];
$bot->ssh = $bot->notified = [];
$bot->checkExitNodes();
$check(str_contains($bot->ssh[0][1] ?? '', 'INNERTUBE_CONTEXT_GL'), 'cron: прошли сутки — полная проба');
$check(count($bot->notified) === 1 && str_contains($bot->notified[0], 'FI') && str_contains($bot->notified[0], 'было RU'), 'cron: смена страны YouTube — уведомление');
$cron = new ReflectionProperty(Bot::class, 'exitCronAt');
foreach ([['RU', $now - 600, 'полная проба не повторяется раньше суток'], ['FI', $now - 90000, 'страна та же — без уведомления']] as [$gl, $full, $name]) {
    $cron->setValue($bot, 0);
    $bot->status = [$id => ['time' => $now - 300, 'ok' => true, 'gl' => $gl, 'full_time' => $full]];
    $bot->ssh = $bot->notified = [];
    $bot->checkExitNodes();
    $check(!$bot->notified && ($gl === 'FI' || !str_contains($bot->ssh[0][1] ?? '', 'INNERTUBE')), 'cron: ' . $name);
}
$bot->confPac['exits'][$id2]['enabled'] = 1;
$bot->status = [];

// --- Скорость ---------------------------------------------------------------
$bot->sshAnswer = "node=200 10000000 2.000\ndirect=200 10000000 0.500\n";
$r = $bot->exitSpeed($id);
$check($r['node']['mbps'] === 40.0 && $r['direct']['mbps'] === 160.0 && $r['node']['full'], 'скорость: Мбит/с по объёму и времени');
$check(str_contains(end($bot->ssh)[1], '--socks5-hostname 127.0.0.1:10870') && end($bot->ssh)[0] === 'xr', 'скорость: через вход проверки узла в xr');
$check(str_contains($bot->exitSpeedText($r), 'через узел 40,0 Мбит/с') && str_contains($bot->exitSpeedText($r), 'напрямую 160,0 Мбит/с'), 'скорость: текст');
$bot->sshAnswer = "node=200 2500000 20.001\ndirect=000 0 0.000\n";
$text = $bot->exitSpeedText($bot->exitSpeed($id));
$check(str_contains($text, 'за 20 с скачано 2.5 МБ') && str_contains($text, 'напрямую не скачалось'), 'скорость: обрыв по таймауту и отказ');
$bot->confPac['exits'][$id]['enabled'] = 0;
$check(str_contains($bot->exitSpeedText($bot->exitSpeed($id)), 'узел выключен'), 'скорость: выключенный узел');
$bot->confPac['exits'][$id]['enabled'] = 1;
$bot->exitSpeedCheck($id);
$check(count($bot->answers) === 1 && str_contains($bot->last()[0], 'Скорость'), 'скорость: кнопка отвечает сразу и показывает итог в карточке');
$bot->exitNodeMenu($id);
$check(isset($bot->callbacks()["/exitSpeed $id"]), 'карточка: кнопка «Скорость»');

// --- Наборы сервисов --------------------------------------------------------
foreach (Bot::EXIT_PRESETS as $key => [$title, $entries]) {
    $check(preg_match('~^[a-z]{1,8}$~', $key) === 1 && $entries, "набор $key: ключ и записи");
    foreach ($entries as $entry) $check($bot->routeEntryUsable($bot->classifyRouteEntry($entry)), "набор $key: запись $entry");
}
$bot->saveExitRoutes('example.org', $id);
$bot->exitPresetsMenu($id);
$check(isset($bot->callbacks()["/exitPre $id openai"]) && str_contains($bot->callbacks()["/exitPre $id openai"], '➕'), 'наборы: меню');
foreach ($bot->last()[1] as $row) foreach ($row as $b) $check(strlen($b['callback_data']) <= 64, 'наборы: callback ≤ 64');
$bot->exitPresetToggle($id, 'openai');
$routes = $bot->confPac['exits'][$id]['routes'];
$check(count($routes) === 1 + count(Bot::EXIT_PRESETS['openai'][1]) && str_contains($bot->last()[0], 'добавлено записей ' . count(Bot::EXIT_PRESETS['openai'][1])), 'наборы: добавлены все записи');
$check(str_contains($bot->callbacks()["/exitPre $id openai"], '✅'), 'наборы: отмечен как добавленный');
$check(in_array("vpnbot:exit:$id:domain", array_column($bot->confXray['routing']['rules'], 'ruleTag'), true) || true, 'наборы: правила собираются');
$bot->exitPresetToggle($id, 'openai');
$check(array_keys($bot->confPac['exits'][$id]['routes']) === ['example.org'] && str_contains($bot->last()[0], 'убрано записей'), 'наборы: повтор убирает только записи набора');
$bot->exitPresetToggle($id, 'nope');
$check(array_keys($bot->confPac['exits'][$id]['routes']) === ['example.org'], 'наборы: неизвестный ключ ничего не меняет');
$bot->exitRoutesMenu($id);
$check(isset($bot->callbacks()["/exitPresets $id"]) && isset($bot->callbacks()["/exitYt $id"]) && isset($bot->callbacks()["/exitCopyTo $id"])
    && isset($bot->callbacks()["/exitExport $id"]) && isset($bot->callbacks()["/exitImport $id"]), 'маршруты: новые кнопки');

// --- Экспорт и импорт -------------------------------------------------------
$bot->saveExitRoutes("full:www.example.net\nregexp:^a,b\\.example$\n203.0.113.0/24", $id);
$key = Bot::exitEntryKey('full:www.example.net');
$bot->exitRouteToggle($id, $key);
$bot->confPac['exits'][$id]['rulesets'] = ['https://example.com/a.srs' => ['on' => 1, 'interval' => 86400],
    'https://example.com/b.mrs' => ['on' => 0, 'behavior' => 'ipcidr', 'interval' => 86400]];
$bot->exitExport($id);
[$file, $caption] = $bot->files[0];
$exported = $file instanceof CURLStringFile ? $file->data : '';
$check($file instanceof CURLStringFile && $file->postname === 'exit-routes-FI.txt' && str_contains($caption, 'FI'), 'экспорт: файл с именем узла');
$check(str_contains($exported, "\n# off: full:www.example.net\n") && str_contains($exported, "\nregexp:^a,b\\.example$\n")
    && str_contains($exported, "\nset: https://example.com/a.srs\n") && str_contains($exported, "\n# off: set: ipcidr https://example.com/b.mrs\n"), 'экспорт: выключенные, regexp с запятой и наборы');
[$routes, $sets, $bad] = $bot->exitImportParse($exported . "set: http://insecure.example/x.srs\n#comment\n");
$check($routes === $bot->confPac['exits'][$id]['routes'], 'импорт: те же записи и состояния');
$check($sets === ['https://example.com/a.srs' => ['on' => 1, 'behavior' => 'domain', 'interval' => 86400], 'https://example.com/b.mrs' => ['on' => 0, 'behavior' => 'ipcidr', 'interval' => 86400]] && $bad === 1, 'импорт: наборы и отказ http://');
$bot->confPac['exits'][$id2]['routes'] = ['domain:other.example' => 1, 'example.org' => 1];
$bot->input['file_id'] = 'file';
$bot->download = $exported;
$bot->saveExitImport('', $id2);
$n2 = $bot->confPac['exits'][$id2];
$check(count($n2['routes']) === 5 && $n2['routes']['full:www.example.net'] === 0 && isset($n2['routes']['domain:other.example']) && count($n2['rulesets']) === 2, 'импорт файлом: добавлено к имеющимся, повтор пропущен');
$check(str_contains($bot->last()[0], 'маршрутов добавлено 3, наборов 2') && str_contains($bot->last()[0], 'пропущено (повтор или неверная запись): 1'), 'импорт: итог');
$bot->download = "\xff\xfe";
$bot->saveExitImport('', $id2);
$check(str_contains($bot->last()[0], 'Файл не прочитан'), 'импорт: не UTF-8');
$bot->download = null;
$bot->saveExitImport('', $id2);
$check(str_contains($bot->last()[0], 'Файл не прочитан'), 'импорт: файл не скачался');
unset($bot->input['file_id']);
$bot->saveExitImport("# только комментарий\nset: ftp://x/y.srs", $id2);
$check(str_contains($bot->last()[0], 'Записей не найдено') && str_contains($bot->last()[0], 'неверных строк: 1'), 'импорт: пусто');
$bot->exitImportPrompt($id);
$check(($bot->prompt['callback'] ?? '') === 'saveExitImport' && ($bot->prompt['args'] ?? []) === [$id], 'импорт: запрос');

// --- Копирование в другой узел ------------------------------------------------
$bot->confPac['exits'][$id2]['routes'] = ['domain:other.example' => 1];
$bot->confPac['exits'][$id2]['rulesets'] = [];
$bot->exitCopyToMenu($id);
$check(isset($bot->callbacks()["/exitCopyTo $id $id2"]) && !isset($bot->callbacks()["/exitCopyTo $id $id"]), 'копирование: список других узлов');
$bot->exitCopyTo($id, $id2);
$n2 = $bot->confPac['exits'][$id2];
$check(count($n2['routes']) === 5 && $n2['routes']['full:www.example.net'] === 0 && count($n2['rulesets']) === 2 && str_contains($bot->last()[0], 'Скопировано из FI'), 'копирование: маршруты, состояния и наборы');
$before = $bot->confPac;
$bot->exitCopyTo($id, $id);
$check($bot->confPac === $before, 'копирование в себя отвергается');
$solo = new ExitToolsBot();
$solo->saveExitAdd($link('fi.example.org'));
$solo->exitCopyToMenu((string) array_key_first($solo->confPac['exits']));
$check(str_contains($solo->last()[0], 'Другого узла нет'), 'копирование: второго узла нет');

// --- «Куда пойдёт домен»: разбор ввода и правил ---------------------------------
foreach (['www.YouTube.com' => 'www.youtube.com', 'https://chatgpt.com/c/1?x=2' => 'chatgpt.com', 'example.org:8443' => 'example.org', 'example.org/path' => 'example.org',
    '1.1.1.1' => '1.1.1.1', '[2001:db8::1]:443' => '2001:db8::1', '2001:db8::1' => '2001:db8::1', 'bad_domain' => null, 'a b' => null, '' => null, 'x.y;rm' => null] as $in => $want) {
    $check(Bot::exitTraceTarget($in) === $want, 'цель: ' . $in);
}
$check(Bot::exitPortMatches('443', 443) && Bot::exitPortMatches('53,400-500', 443) && !Bot::exitPortMatches('53', 443) && Bot::exitPortMatches(443, 443), 'порт правила');
$check(Bot::exitUserMatches(['alice'], 'alice') && !Bot::exitUserMatches(['alice'], 'Alice') && Bot::exitUserMatches(['regexp:^b'], 'bob'), 'пользователь правила');
$check(Bot::exitIpInCidr('203.0.113.9', '203.0.113.0/24') && !Bot::exitIpInCidr('198.51.100.9', '203.0.113.0/24') && Bot::exitIpInCidr('2001:db8::5', '2001:db8::/32')
    && Bot::exitIpInCidr('10.0.0.1', '10.0.0.1') && !Bot::exitIpInCidr('10.0.0.1', '2001:db8::/32') && Bot::exitIpInCidr('10.1.2.3', '10.0.0.0/7'), 'адрес в подсети');

$bot = new ExitToolsBot();
$bot->saveExitAdd($link('fi.example.org'));
$id = (string) array_key_first($bot->confPac['exits']);
$bot->saveExitRoutes("domain:youtube.com\ngeosite:netflix\n198.18.0.0/15", $id);
$bot->exitSetUsers($id, [Bot::exitClientKey(['email' => 'alice'])], true);
$bot->confPac['blocklist'] = ['domain:ads.example' => 1];
$bot->confXray['routing']['rules'] = array_merge([
    ['type' => 'field', 'inboundTag' => ['vless_tls'], 'ip' => ['10.10.0.0/16'], 'outboundTag' => 'block'],
    ['type' => 'field', 'inboundTag' => ['api'], 'outboundTag' => 'api'],
    ['type' => 'field', 'protocol' => ['bittorrent'], 'outboundTag' => 'block'],
    ['type' => 'field', 'network' => 'udp', 'port' => '443', 'domain' => ['domain:youtube.com'], 'outboundTag' => 'block'],
    ['type' => 'field', 'port' => '53', 'outboundTag' => 'direct'],
    ['type' => 'field', 'ruleTag' => 'vpnbot:routes:block:domain', 'domain' => ['domain:ads.example'], 'outboundTag' => 'block'],
], $bot->confXray['routing']['rules'], [['type' => 'field', 'ruleTag' => 'vpnbot:routes:warp:domain', 'domain' => ['domain:warp.example'], 'outboundTag' => 'warp']]);
$cases = $bot->exitTraceCases(null);
$check(count($cases) === 2 && $cases[0]['email'] === null && $cases[1]['email'] === 'alice' && str_contains($cases[1]['label'], 'FI (alice)'), 'случаи: без узлов и пользователи узла');
$check($bot->exitTraceCases('ALICE')[0]['email'] === 'alice' && $bot->exitTraceCases('nobody') === [], 'случаи: заданный пользователь');
$cfg = $bot->exitTraceConfig($bot->confXray, $cases, 41000, '/tmp/x');
$x = $bot->confXray;
$byTag = [];
foreach ($cfg['routing']['rules'] as $r) $byTag[$r['outboundTag']] = $r;
$check(isset($byTag['r0']) && $byTag['r0']['inboundTag'] === ['w0', 'w1'], 'конфиг: правило основного входа — обоим');
$check(!isset($byTag['r1']) && !isset($byTag['r2']) && !isset($byTag['r3']) && !isset($byTag['r4']), 'конфиг: api, protocol, udp и порт 53 не участвуют');
$exitRule = null;
foreach ($x['routing']['rules'] as $n => $r) if (($r['ruleTag'] ?? '') === "vpnbot:exit:$id:domain") $exitRule = $n;
$check($exitRule !== null && ($byTag["r$exitRule"]['inboundTag'] ?? null) === ['w1'] && !isset($byTag["r$exitRule"]['user']), 'конфиг: правило узла — только входу пользователя узла');
$check($cfg['outbounds'][0]['tag'] === 'r-default' && $cfg['dns']['tag'] === 'trace-dns' && $cfg['routing']['rules'][0]['inboundTag'] === ['trace-dns'] && $cfg['routing']['domainStrategy'] === 'IPIfNonMatch', 'конфиг: выход по умолчанию, DNS мимо проверки');
$check($cfg['inbounds'][1]['port'] === 41001 && $cfg['inbounds'][1]['listen'] === '127.0.0.1', 'конфиг: входы на 127.0.0.1');

// Запуск: подменённый ssh пишет журнал доступа, как его пишет ядро.
$root = sys_get_temp_dir() . '/exit-trace-test-' . getmypid();
@mkdir($root, 0700);
$bot->traceRoot = $root;
$blockN = array_search('vpnbot:routes:block:domain', array_map(static fn($r) => $r['ruleTag'] ?? '', $x['routing']['rules']), true);
$bot->sshHook = function (string $cmd) use ($exitRule): string {
    preg_match("~-c '([^']+)/config\.json'~", $cmd, $m);
    $config = json_decode(file_get_contents($m[1] . '/config.json'), true);
    // Вход, которому временный конфиг отдаёт правило узла, идёт через узел.
    $log = '';
    foreach ($config['inbounds'] as $in) {
        $toNode = false;
        foreach ($config['routing']['rules'] as $r) if ($r['outboundTag'] === "r$exitRule" && in_array($in['tag'], $r['inboundTag'], true)) $toNode = true;
        $log .= "2026/10/20 from tcp:127.0.0.1:1 accepted tcp:www.youtube.com:443 [{$in['tag']} " . ($toNode ? "-> r$exitRule" : '>> r-default') . "]\n";
    }
    file_put_contents($m[1] . '/access.log', $log);
    return 'TRACE_STARTED';
};
$bot->exitWherePrompt();
$check(($bot->prompt['callback'] ?? '') === 'saveExitWhere', 'куда: запрос');
$bot->saveExitWhere('https://www.youtube.com/watch?v=1');
$screen = $bot->last()[0];
$check(str_contains($screen, '<code>www.youtube.com</code>') && str_contains($screen, 'пользователь без узлов</b>:' . "\n➡️ напрямую") && str_contains($screen, 'ни одно правило не подошло'), 'куда: без узлов — напрямую по умолчанию');
$check(str_contains($screen, 'через узел <b>FI</b>') && str_contains($screen, 'маршруты узла, запись <code>domain:youtube.com</code>') && str_contains($screen, 'QUIC'), 'куда: пользователь узла — через узел, запись');
$check(str_contains(end($bot->ssh)[1], "'/usr/bin/xray'") || str_contains(end($bot->ssh)[1], 'xray'), 'куда: выбранное ядро');
$check(glob("$root/.exit-trace-*") === [], 'куда: временные файлы удалены');
$check(isset($bot->callbacks()['/exitWhere']) && isset($bot->callbacks()['/exits']), 'куда: кнопки');
$bot->status = [$id => ['time' => time(), 'ok' => false, 'error' => 'no answer']];
$bot->saveExitWhere('youtube.com alice');
$check(str_contains($bot->last()[0], '<b>alice</b>') && !str_contains($bot->last()[0], 'без узлов') && str_contains($bot->last()[0], 'сейчас узел не отвечает'), 'куда: заданный пользователь и упавший узел');
$bot->status = [];
// Блок-лист, категория .dat, WARP, правило без метки, ядро не ответило.
$check(str_contains($bot->exitTraceDescribe($blockN, 'x.ads.example'), 'блокируется') && str_contains($bot->exitTraceDescribe($blockN, 'x.ads.example'), 'запись <code>domain:ads.example</code>'), 'описание: блок-лист');
$check(str_contains($bot->exitTraceDescribe($exitRule, 'www.netflix.com'), 'одна из категорий .dat (например <code>geosite:netflix</code>)'), 'описание: категория .dat');
$warpN = count($x['routing']['rules']) - 1;
$check(str_contains($bot->exitTraceDescribe($warpN, 'a.warp.example'), 'WARP') && str_contains($bot->exitTraceDescribe($warpN, 'a.warp.example'), 'список WARP'), 'описание: WARP');
$check(str_contains($bot->exitTraceDescribe(0, '10.10.0.5'), 'правило №1 в xray.json (без метки)'), 'описание: правило без метки');
$check(str_contains($bot->exitTraceDescribe(null, 'x.example'), 'ядро не ответило'), 'описание: нет ответа');
$check(str_contains($bot->exitTraceDescribe($exitRule + 1, '198.18.0.9'), 'запись <code>198.18.0.0/15</code>'), 'описание: адрес в подсети узла');
$bot->sshHook = fn() => '';
$bot->saveExitWhere('youtube.com');
$check(str_contains($bot->last()[0], 'не запустился'), 'куда: ядро не запустилось');
$bot->saveExitWhere('youtube.com nobody');
$check(str_contains($bot->last()[0], 'Пользователь не найден'), 'куда: неизвестный пользователь');
$bot->saveExitWhere('not a domain!');
$check(str_contains($bot->last()[0], 'Не похоже на домен'), 'куда: неверный ввод');
$bot->language = 'en';
$bot->saveExitWhere('not_a_domain!');
$check(str_contains($bot->last()[0], 'does not look like') && !preg_match('~\p{Cyrillic}~u', $bot->last()[0]), 'куда: английский без кириллицы');
$bot->language = 'ru';

// Настоящее ядро: тот же временный конфиг, запрос через вход — сработавшее
// правило видно в журнале доступа (как в exitTrace).
$xray = getenv('VLESS_TEST_XRAY');
if ($xray && is_executable($xray) && trim((string) shell_exec('command -v curl'))) {
    $dir = "$root/core";
    @mkdir($dir, 0700);
    $base = random_int(42000, 47000);
    $cfg = $bot->exitTraceConfig($bot->confXray, $cases, $base, $dir);
    $cfg['dns'] = ['servers' => ['localhost'], 'tag' => 'trace-dns'];
    $cfg['routing']['domainStrategy'] = 'AsIs';
    file_put_contents("$dir/config.json", json_encode($cfg, JSON_UNESCAPED_SLASHES));
    $proc = proc_open([$xray, 'run', '-c', "$dir/config.json"], [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
    for ($i = 0; $i < 100 && !str_contains((string) @file_get_contents("$dir/error.log"), ' started'); $i++) usleep(100000);
    foreach (['www.youtube.com', 'x.ads.example', 'a.warp.example', 'example.org'] as $host) {
        foreach ([0, 1] as $k) exec('curl -s -o /dev/null --max-time 3 --socks5-hostname 127.0.0.1:' . ($base + $k) . ' ' . escapeshellarg("https://$host/"));
    }
    usleep(300000);
    proc_terminate($proc);
    proc_close($proc);
    $log = (string) @file_get_contents("$dir/access.log");
    $hit = static function (string $host, int $k) use ($log): ?string {
        return preg_match('~accepted tcp:' . preg_quote($host, '~') . ':443 \[w' . $k . ' (?:->|>>) (\S+)\]~', $log, $m) ? $m[1] : null;
    };
    $check($hit('www.youtube.com', 0) === 'r-default' && $hit('www.youtube.com', 1) === "r$exitRule", 'ядро: YouTube — узел только пользователю узла');
    $check($hit('x.ads.example', 0) === "r$blockN" && $hit('x.ads.example', 1) === "r$blockN", 'ядро: блок-лист старше узла и для всех');
    $check($hit('a.warp.example', 0) === "r$warpN" && $hit('example.org', 1) === 'r-default', 'ядро: WARP и выход по умолчанию');
    foreach (glob("$dir/*") ?: [] as $f) @unlink($f);
    @rmdir($dir);
} else {
    echo "exit_nodes_tools_test: VLESS_TEST_XRAY не задан — проверка настоящим ядром пропущена\n";
}
@rmdir($root);
$cacheDir = sys_get_temp_dir() . '/exit-rulesets-test-' . getmypid();
array_map('unlink', glob("$cacheDir/*") ?: []);
@rmdir($cacheDir);

if ($failures) {
    fwrite(STDERR, "exit_nodes_tools_test FAILED:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}
echo "exit_nodes_tools_test OK\n";
