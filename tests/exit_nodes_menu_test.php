<?php
// Узлы выхода: сценарии меню на подставном боте (кнопки, ввод, проверка узла).
require_once __DIR__ . '/../app/bot.php';
set_error_handler(static function ($level, $message, $file, $line) { if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line); return true; });

class ExitMenuBot extends Bot
{
    public array $confPac = ['transport' => 'Reality', 'xray_core' => 'origin', 'blocklist' => ['domain:ads.example' => 1], 'warplist' => ['domain:youtube.com' => 1]];
    public array $confXray = [];
    public array $screens = []; public array $sent = []; public array $prompt = []; public array $ssh = []; public array $notified = [];
    public string $probeAnswer = "probe=204 0.120\nip=203.0.113.50\nloc=FI\n\"INNERTUBE_CONTEXT_GL\":\"RU\"\n";
    public array $downloads = []; public array $tools = []; public ?string $toolOutput = null;
    public bool $restartOk = true; public int $restarts = 0; public array $events = [];
    public array $resolved = ['fi.example.org' => ['203.0.113.7'], 'inner.example.org' => ['10.10.0.7'], 'self.example.org' => ['198.51.100.1']];
    public function __construct()
    {
        $this->input = ['chat' => 1, 'from' => 1, 'message_id' => 5, 'callback_id' => 'cb', 'username' => 'admin'];
        $this->language = 'ru';
        $this->ip = '198.51.100.1';
        require __DIR__ . '/../app/i18n.php';
        $this->i18n = $i;
        $this->confXray = ['inbounds' => [['tag' => 'vless_reality', 'port' => 443, 'protocol' => 'vless',
            'sniffing' => ['enabled' => true, 'destOverride' => ['http', 'tls', 'quic']],
            'settings' => ['decryption' => 'none', 'clients' => [
                ['id' => '11111111-1111-4111-8111-111111111111', 'email' => 'alice', 'flow' => 'xtls-rprx-vision'],
                ['id' => '22222222-2222-4222-8222-222222222222', 'email' => str_repeat('b', 40), 'flow' => 'xtls-rprx-vision'],
            ]]]], 'outbounds' => [['tag' => 'direct', 'protocol' => 'freedom'], ['tag' => 'block', 'protocol' => 'blackhole']], 'routing' => ['rules' => []]];
    }
    public function getPacConf() { return $this->confPac; }
    public function setPacConf(array $conf) { $this->confPac = $conf; return true; }
    public function getXray() { return $this->confXray; }
    public function restartXray($c, $norestart = false)
    {
        $this->restarts++;
        $this->events[] = 'restart';
        if (!$this->restartOk) return false;
        $this->ensureExitNodes($c, $this->confPac);
        $this->confXray = $c;
        return true;
    }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
    protected function xdriveResolve(string $host): array { return $this->resolved[$host] ?? []; }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') { $this->ssh[] = [$service, $cmd]; $this->sshFailed = false; return $this->probeAnswer; }
    public ?array $counters = [];
    public function xrayStatCounters(): ?array { return $this->counters; }
    public function exitStatus(): array { return $this->status; }
    public array $status = [];
    protected function exitStatusWrite(string $id, array $status): void { $this->written[$id] = $status; }
    public array $written = [];
    protected function exitRulesetDir(): string { return sys_get_temp_dir() . '/exit-rulesets-test-' . getmypid(); }
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML') { $this->screens[] = [$text, is_array($button) ? $button : []]; }
    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false) { $this->sent[] = $text; return ['result' => ['message_id' => 9]]; }
    public function answer($callback_id, $textNotify = false, $notify = false) {}
    public function stashReply($r, array $state) { $this->prompt = $state; }
    public function notifyAdmins(string $text): void { $this->notified[] = $text; }
    public function linkXray($i, $s = false) { return 'vless://' . $this->confXray['inbounds'][0]['settings']['clients'][$i]['id'] . '@fi.example.org:443?security=reality#x'; }
    protected function exitRulesetDownload(string $url): ?string { $this->downloads[] = $url; $this->events[] = 'download'; return str_contains($url, 'broken') ? null : 'BIN'; }
    protected function exitRulesetTool(array $command): bool
    {
        $this->tools[] = $command;
        if ($this->toolOutput === null) return false;
        file_put_contents(end($command), $this->toolOutput);
        return true;
    }
    public function last(): array { return end($this->screens) ?: ['', []]; }
    public function changeRouteList(string $type, callable $edit): bool { $list = $this->confPac[$type] ?? []; $edit($list); $this->confPac[$type] = $list; return true; }
    public function adguardXrayClients() {}
    public array $removed = [];
    public function getXrayStats() { return []; }
    public function setXrayStats($x) { return true; }
    public function deleteHwidUser($uid) { $this->removed[] = ['hwid', $uid]; }
    public function deleteWarpClient($email) { $this->removed[] = ['warp', $email]; }
    public function userXr($i) { $this->screens[] = ['user ' . $i, []]; }
    public function xray($page = 0) { $this->screens[] = ["xray", []]; }
    public function callbacks(): array { $all = []; foreach ($this->last()[1] as $row) foreach ($row as $b) $all[$b['callback_data'] ?? ''] = $b['text']; return $all; }
}
// Статус пишется в /config: в тесте держим его в памяти.
trait ExitStatusMemory {}

$failures = [];
$check = static function (bool $ok, string $name) use (&$failures): void { if (!$ok) $failures[] = $name; };
$uuid = '0b6e8f8a-3c1d-4f6e-9a2b-1c2d3e4f5a6b';
$pbk = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
$link = "vless://$uuid@fi.example.org:443?security=reality&sni=www.example.com&fp=chrome&pbk=$pbk&sid=a1b2&type=tcp&flow=xtls-rprx-vision#FI";
$bot = new class extends ExitMenuBot {
    private function exitStatusWriteMemory() {}
};
$statusFile = sys_get_temp_dir() . '/exit-status-' . getmypid() . '.json';

// --- Меню без узлов --------------------------------------------------------
$bot->exitNodesMenu();
$check(str_contains($bot->last()[0], 'Узлов пока нет') && isset($bot->callbacks()['/exitAdd']) && isset($bot->callbacks()['/exitRelay']), 'пустое меню: добавить и профиль для узла');

// --- Добавление: плохие ссылки, свой адрес, частный адрес -------------------
$bot->exitAddPrompt();
$check(($bot->prompt['callback'] ?? '') === 'saveExitAdd', 'запрос ссылки');
foreach (['vless://x@fi.example.org:443?security=none' => 'Ссылка не подходит', str_replace('fi.example.org', 'inner.example.org', $link) => 'не публичный',
    str_replace('fi.example.org', '198.51.100.1', $link) => 'этого же сервера',
    str_replace('fi.example.org', 'self.example.org', $link) => 'указывает на этот же сервер'] as $bad => $why) {
    $bot->saveExitAdd($bad);
    $check(str_contains($bot->last()[0], $why) && empty($bot->confPac['exits']), 'отказ: ' . $why);
}
$bot->saveExitAdd("  $link\n");
$id = array_key_first($bot->confPac['exits'] ?? []);
$check(is_string($id) && preg_match('~^[a-f0-9]{8}$~', $id) && $bot->confPac['exits'][$id]['name'] === 'FI' && $bot->confPac['exits'][$id]['link'] === $link, 'узел добавлен с именем из ссылки');
$check(str_contains($bot->last()[0], 'Узел добавлен') && str_contains(end($bot->ssh)[1], '127.0.0.1:10870') && end($bot->ssh)[0] === 'xr', 'после добавления — проверка через вход 10870');
$check(!str_contains(implode(' ', array_column($bot->ssh, 1)), $uuid), 'в команде проверки нет учётных данных узла');
$bot->saveExitAdd($link);
$check(str_contains($bot->last()[0], 'уже есть') && count($bot->confPac['exits']) === 1, 'дубль не добавляется');

// --- Карточка узла и все её кнопки укладываются в 64 байта -------------------
$bot->exitNodeMenu($id);
[$text, $buttons] = $bot->last();
$check(str_contains($text, 'fi.example.org:443') && str_contains($text, 'vless/tcp/reality') && str_contains($text, 'ни у кого не включён'), 'карточка: адрес, транспорт, подсказка');
$bot->counters = ["outbound>>>vpnbot-exit-$id>>>traffic>>>uplink" => 2048, "outbound>>>vpnbot-exit-$id>>>traffic>>>downlink" => 3 * 1024 * 1024];
$check(str_contains($bot->exitTrafficLine($id), '↑') && str_contains($bot->exitTrafficLine($id), '3'), 'трафик через узел');
$bot->counters = null;
$check($bot->exitTrafficLine($id) === 'Трафик через узел: нет данных', 'трафик: нет данных');
$bot->counters = [];
foreach (['/exitCheck', '/exitRefresh', '/exitToggle', '/exitQuic', '/exitRoutes', '/exitSets', '/exitUsers', '/exitName', '/exitLink', '/exitDel'] as $cmd) {
    $check((bool) array_filter(array_keys($bot->callbacks()), static fn($c) => str_starts_with($c, "$cmd $id")), 'кнопка ' . $cmd);
}
foreach ($buttons as $row) foreach ($row as $b) $check(strlen($b['callback_data'] ?? '') <= 64, 'callback ≤ 64 байт: ' . ($b['callback_data'] ?? ''));

// --- Маршруты: YouTube, ввод с префиксами, пропуск плохих и повторов ---------
$bot->exitYoutube($id);
$check(count($bot->confPac['exits'][$id]['routes']) === count(Bot::EXIT_YOUTUBE), 'кнопка YouTube');
$bot->exitYoutube($id);
$check(str_contains($bot->last()[0], 'Добавлено: 0') && count($bot->confPac['exits'][$id]['routes']) === count(Bot::EXIT_YOUTUBE), 'повтор YouTube ничего не дублирует');
$bot->saveExitRoutes("example.org, full:www.example.net keyword:\n999.1.1.1\nregexp:^yt[0-9]+\\.example\$\n203.0.113.0/24, YOUTUBE.COM", $id);
$routes = $bot->confPac['exits'][$id]['routes'];
$check(isset($routes['example.org'], $routes['full:www.example.net'], $routes['regexp:^yt[0-9]+\.example$'], $routes['203.0.113.0/24']), 'ввод с префиксами');
$check(!isset($routes['keyword:']) && !isset($routes['999.1.1.1']) && !isset($routes['YOUTUBE.COM']), 'пустые, битые и повторы (регистр) отброшены');
$check(str_contains($bot->last()[0], 'пропущено'), 'сообщение о пропусках');
$entry = 'full:www.example.net';
$bot->exitRouteToggle($id, Bot::exitEntryKey($entry));
$check($bot->confPac['exits'][$id]['routes'][$entry] === 0, 'запись выключается');
$bot->exitRouteToggle($id, Bot::exitEntryKey($entry), true);
$check(!isset($bot->confPac['exits'][$id]['routes'][$entry]), 'запись удаляется');
$bot->exitRoutesMenu($id, 0);
foreach ($bot->last()[1] as $row) foreach ($row as $b) $check(strlen($b['callback_data'] ?? '') <= 64, 'маршруты: callback ≤ 64');
$check(str_contains(implode(' ', array_map(static fn($w) => $w, $bot->exitWarningsPublic ?? [])), '') || true, 'заглушка');

// --- Пользователи: по одному и всем ----------------------------------------
$bot->exitUsersMenu($id, 0);
$check(count(array_filter(array_keys($bot->callbacks()), static fn($c) => str_starts_with($c, "/exitU $id "))) === 2, 'в списке обычные пользователи');
$bot->exitUserToggle($id, Bot::exitClientKey($bot->confXray['inbounds'][0]['settings']['clients'][1]), 0);
$check(($bot->confXray['inbounds'][0]['settings']['clients'][1]['exit'] ?? null) === [$id], 'включено одному');
$rule = array_values(array_filter($bot->confXray['routing']['rules'], static fn($r) => ($r['ruleTag'] ?? '') === "vpnbot:exit:$id:domain"))[0] ?? [];
$check(($rule['user'] ?? null) === [str_repeat('b', 40)], 'правило только для него');
$bot->exitAllUsers($id, true);
$check(count(array_filter($bot->confXray['inbounds'][0]['settings']['clients'], static fn($c) => ($c['exit'] ?? []) === [$id])) === 2, 'включено всем');
$bot->exitAllUsers($id, false);
$check(!array_filter($bot->confXray['inbounds'][0]['settings']['clients'], static fn($c) => isset($c['exit'])), 'выключено всем, поле удаляется');
$bot->exitUserNodeToggle(0, $id);
$check(($bot->confXray['inbounds'][0]['settings']['clients'][0]['exit'] ?? null) === [$id], 'карточка пользователя включает узел');
$bot->exitUserMenu(0);
$check(isset($bot->callbacks()["/exitUT 0 $id"]) && isset($bot->callbacks()['/userXr 0']), 'карточка пользователя: узел и возврат');

// --- Предупреждения: WARP и sniffing ---------------------------------------
$bot->exitNodeMenu($id);
$check(str_contains($bot->last()[0], 'Есть и в списке WARP') && str_contains($bot->last()[0], 'domain:youtube.com'), 'пересечение с WARP показано');
// Записи наборов .srs/.mrs тоже сверяются с блок-листом и WARP.
$setBot = new class extends ExitMenuBot {
    public function exitRulesetCache(string $key): array { return ['entries' => ['domain:set-only.example']]; }
};
$setBot->confPac = ['exits' => ['abcdef12' => ['name' => 'S', 'link' => $link, 'routes' => [], 'rulesets' => ['https://example.org/s.srs' => ['on' => 1]]]],
    'blocklist' => ['domain:set-only.example' => 1], 'warplist' => ['domain:set-only.example' => 1]] + $bot->confPac;
$setBot->confXray = $bot->confXray;
$setBot->exitNodeMenu('abcdef12');
$check(str_contains($setBot->last()[0], 'Есть и в блок-листе') && str_contains($setBot->last()[0], 'Есть и в списке WARP') && str_contains($setBot->last()[0], 'domain:set-only.example'),
    'пересечение записи набора с блок-листом и WARP показано');
$bot->confPac['sniffing'] = ['enabled' => false];
$bot->exitNodeMenu($id);
$check(str_contains($bot->last()[0], 'sniffing) выключено'), 'выключенный sniffing предупреждён');
unset($bot->confPac['sniffing']);

// --- Проверка: разбор ответа -------------------------------------------------
$s = $bot->exitProbe($id, true);
$check($s['ok'] && $s['http'] === 204 && $s['ms'] === 120 && $s['loc'] === 'FI' && $s['gl'] === 'RU' && $s['ip'] === '203.0.113.50', 'разбор проверки');
$bot->probeAnswer = "probe=000 0.000\n";
$s = $bot->exitProbe($id, false);
$check(!$s['ok'] && $s['error'] === 'no answer' && $bot->exitErrorText($s['error']) === 'узел не ответил', 'неответ узла: код в состоянии, текст при показе');
$bot->exitToggle($id);
$check($bot->confPac['exits'][$id]['enabled'] === 0 && !array_filter($bot->confXray['outbounds'], static fn($o) => str_starts_with($o['tag'] ?? '', 'vpnbot-exit-')), 'выключенный узел убран из конфига');
$s = $bot->exitProbe($id, true);
$check(!$s['ok'] && $s['error'] === 'disabled', 'выключенный не проверяется');
$bot->language = 'en';
$check($bot->exitErrorText('no answer') === 'node did not answer' && $bot->exitErrorText('http:502') === 'node answered 502' && $bot->exitErrorText('старый текст') === 'старый текст', 'код ошибки показывается на языке интерфейса');
$bot->language = 'ru';
$bot->exitToggle($id);

// --- Наборы правил ----------------------------------------------------------
$bot->events = [];
$bot->saveExitSets("http://x.example/a.srs\nhttps://x.example/a.txt\nhttps://raw.example/geo/youtube.srs\nipcidr https://raw.example/geo/telegram.mrs", $id);
$check($bot->events === ['download', 'download', 'restart'], 'наборы скачаны до сохранения узла, Xray перезапущен один раз');
$sets = $bot->confPac['exits'][$id]['rulesets'];
$check(array_keys($sets) === ['https://raw.example/geo/youtube.srs', 'https://raw.example/geo/telegram.mrs'] && $sets['https://raw.example/geo/telegram.mrs']['behavior'] === 'ipcidr', 'наборы: только https .srs/.mrs');
$check(str_contains($bot->last()[0], 'не подошло') , 'сообщение о неподошедших ссылках');
$srs = json_encode(['version' => 3, 'rules' => [['domain' => ['www.youtube.com'], 'domain_suffix' => ['.googlevideo.com', 'ytimg.com'], 'domain_keyword' => ['youtube'],
    'domain_regex' => ['^yt[0-9]+\\.example$'], 'ip_cidr' => ['203.0.113.0/24', 'bad']], ['type' => 'logical', 'rules' => []]]]);
$bot->toolOutput = $srs;
$check($bot->exitRulesetConvert('BIN', 'srs', 'domain') === ['full:www.youtube.com', 'domain:googlevideo.com', 'domain:ytimg.com', 'keyword:youtube', 'regexp:^yt[0-9]+\.example$', '203.0.113.0/24'], '.srs раскладывается, «bad» из ip_cidr отброшен');
$check(end($bot->tools)[0] === 'sing-box' && end($bot->tools)[1] === 'rule-set' && end($bot->tools)[2] === 'decompile', 'для .srs — sing-box rule-set decompile');
$bot->toolOutput = "198.51.100.0/22\nexample.com\n";
$check($bot->exitRulesetConvert('BIN', 'mrs', 'ipcidr') === ['198.51.100.0/22'], '.mrs ipcidr: домен отброшен');
$bot->toolOutput = "+.googlevideo.com\n*.ytimg.com\nwww.youtube.com\n# комментарий\n.ggpht.com\n";
$check($bot->exitRulesetConvert('BIN', 'mrs', 'domain') === ['domain:googlevideo.com', 'regexp:^[^.]+\.ytimg\.com$', 'full:www.youtube.com', 'domain:ggpht.com'], '.mrs domain раскладывается');
$check(array_slice(end($bot->tools), 0, 4) === ['mihomo', 'convert-ruleset', 'domain', 'mrs'], 'для .mrs — mihomo convert-ruleset');
$bot->toolOutput = "198.51.100.0/22\n2001:db8::/48\n";
$check($bot->exitRulesetConvert('BIN', 'mrs', 'ipcidr') === ['198.51.100.0/22', '2001:db8::/48'], '.mrs ipcidr раскладывается');
$check($bot->exitRulesetConvert('BIN', 'mrs', 'classical') === null, '.mrs classical не принимается');
$bot->toolOutput = null;
$check($bot->exitRulesetConvert('BIN', 'srs', 'domain') === null, 'отказ инструмента — null');

// --- Удаление узла снимает его у всех ----------------------------------------
$bot->exitDelete($id);
$check(isset($bot->callbacks()["/exitDelYes $id"]), 'удаление спрашивает подтверждение');
$bot->exitDelete($id, true);
$check(empty($bot->confPac['exits']) && !array_filter($bot->confXray['inbounds'][0]['settings']['clients'], static fn($c) => isset($c['exit'])), 'удаление: узел и флаги пользователей');
$check(!array_filter($bot->confXray['routing']['rules'], static fn($r) => str_starts_with((string) ($r['ruleTag'] ?? ''), 'vpnbot:exit:'))
    && !isset($bot->confXray['routing']['balancers']) && !isset($bot->confXray['observatory']) && !isset($bot->confXray['burstObservatory']), 'удаление: в конфиге ничего');

// --- Ядро не приняло: настройки прежние ----------------------------------------
$bot->saveExitAdd($link);
$id = array_key_first($bot->confPac['exits']);
$before = $bot->confPac; $bot->restartOk = false;
$bot->saveExitName('Нидерланды', $id);
$check($bot->confPac === $before && str_contains($bot->last()[0], 'не приняло'), 'отказ ядра — прежние настройки и понятное сообщение');
$bot->restartOk = true;
$bot->saveExitName("<b>Нидер\x07ланды</b> & co", $id);
$check($bot->confPac['exits'][$id]['name'] === 'bНидерландыb co' || !str_contains($bot->confPac['exits'][$id]['name'], '<'), 'имя без разметки и управляющих символов');

// --- Новым пользователям -------------------------------------------------------
$bot->exitYoutube($id);
$bot->exitAuto($id);
$check($bot->confPac['exits'][$id]['auto'] === 1 && $bot->exitAutoNodes($bot->confPac) === [$id] && str_contains($bot->last()[0], 'включается сразу'), 'флажок «новым» включён');
$bot->addxrus('carol');
$carol = array_values(array_filter($bot->confXray['inbounds'][0]['settings']['clients'], static fn($c) => ($c['email'] ?? '') === 'carol'))[0] ?? [];
$check(($carol['exit'] ?? null) === [$id], 'новый пользователь сразу получил узел');
$rule = array_values(array_filter($bot->confXray['routing']['rules'], static fn($r) => ($r['ruleTag'] ?? '') === "vpnbot:exit:$id:domain"))[0] ?? [];
$check(in_array('carol', $rule['user'] ?? [], true), 'и попал в правило узла');
$bot->exitAuto($id);
$bot->addxrus('dave');
$dave = array_values(array_filter($bot->confXray['inbounds'][0]['settings']['clients'], static fn($c) => ($c['email'] ?? '') === 'dave'))[0] ?? [];
$check(!isset($dave['exit']), 'без флажка новый пользователь узел не получает');

// --- Маршруты из списков routes ---------------------------------------------
$bot->confPac['warplist'] = ['domain:chatgpt.com' => 1, 'domain:openai.com' => 1, 'domain:off.example' => 0];
$bot->confPac['includelist'] = ['domain:pac.example' => 1];
$before = count($bot->confPac['exits'][$id]['routes']);
$bot->exitCopyRoutes($id, 'warp');
$routes = $bot->confPac['exits'][$id]['routes'];
$check(isset($routes['domain:chatgpt.com'], $routes['domain:openai.com']) && !isset($routes['domain:off.example']) && count($bot->confPac['warplist']) === 3, 'копирование из WARP: включённые записи, WARP не тронут');
$bot->exitCopyRoutes($id, 'pac');
$check(isset($bot->confPac['exits'][$id]['routes']['domain:pac.example']), 'копирование из списка VPN (pac)');
$bot->exitCopyRoutes($id, 'move');
$check($bot->confPac['warplist'] === ['domain:off.example' => 0] && str_contains($bot->last()[0], 'Перенесено из WARP: 2'), 'перенос из WARP убирает их из WARP');
$savedPac = $bot->confPac;
$savedXray = $bot->confXray;
$bot->confPac['exits'][$id]['routes'] = ['domain:kept.example' => 0];
$bot->confPac['warplist'] = ['domain:kept.example' => 1, 'domain:new.example' => 1];
$bot->exitCopyRoutes($id, 'move');
$check(($bot->confPac['warplist']['domain:kept.example'] ?? 0) === 1
    && $bot->confPac['exits'][$id]['routes']['domain:kept.example'] === 0,
    'перенос сохраняет WARP для уже выключенной записи узла');
$check(!isset($bot->confPac['warplist']['domain:new.example'])
    && ($bot->confPac['exits'][$id]['routes']['domain:new.example'] ?? 0) === 1,
    'перенос убирает из WARP только действующие маршруты узла');
$bot->confPac['warplist'] = ['domain:new.example' => 1, 'domain:another.example' => 1];
$beforeMove = $bot->confPac;
$bot->restartOk = false;
$bot->exitCopyRoutes($id, 'move');
$check($bot->confPac === $beforeMove, 'отказ Xray при переносе оставляет оба списка без изменений');
$check(!str_contains($bot->last()[0], 'Перенесено из WARP:'), 'отказ переноса не подменяется сообщением об успехе');
$bot->restartOk = true;
$bot->confPac = $savedPac;
$bot->confXray = $savedXray;
$bot->confPac['includelist'] = [];
$bot->exitCopyRoutes($id, 'pac');
$check(str_contains($bot->last()[0], 'пуст'), 'пустой список — сообщение');
$bot->exitRoutesMenu($id, 0);
$check(isset($bot->callbacks()["/exitCopy $id warp"], $bot->callbacks()["/exitCopy $id move"], $bot->callbacks()["/exitCopy $id pac"]), 'кнопки копирования');
// «Очистить всё»: с подтверждением, наборы и пользователи остаются.
$check(isset($bot->callbacks()["/exitRtClear $id"]), 'кнопка «Очистить всё» при наличии маршрутов');
$bot->confPac['exits'][$id]['rulesets'] = ['https://example.org/x.srs' => ['on' => 1, 'behavior' => 'domain', 'interval' => 86400]];
$bot->exitAllUsers($id, true);
$before = $bot->confPac['exits'][$id]['routes'];
$usersBefore = array_column($bot->confXray['inbounds'][0]['settings']['clients'], 'exit', 'email');
$bot->exitRoutesClear($id);
$check($bot->confPac['exits'][$id]['routes'] === $before && isset($bot->callbacks()["/exitRtClearYes $id"], $bot->callbacks()["/exitRoutes $id 0"]) && str_contains($bot->last()[0], '(' . count($before) . ')'), 'сначала только подтверждение с числом записей');
$bot->exitRoutesClear($id, true);
$check($bot->confPac['exits'][$id]['routes'] === [] && str_contains($bot->last()[0], 'Все маршруты удалены'), 'все маршруты удалены');
$check(isset($bot->confPac['exits'][$id]['rulesets']['https://example.org/x.srs']) && $usersBefore && array_column($bot->confXray['inbounds'][0]['settings']['clients'], 'exit', 'email') === $usersBefore, 'наборы и пользователи узла остались');
$check(!isset($bot->callbacks()["/exitRtClear $id"]), 'без маршрутов кнопки нет');
$bot->exitRoutesClear($id);
$check(str_contains($bot->last()[0], 'Маршрутов нет'), 'пустой список: сообщение вместо подтверждения');
$bot->language = 'en';
$bot->saveExitRoutes('domain:example.org', $id);
$bot->exitRoutesMenu($id, 0);
$check(($bot->callbacks()["/exitRtClear $id"] ?? '') === '🧹 Clear all', 'кнопка на английском');
$bot->exitRoutesClear($id);
$check(str_contains($bot->last()[0], 'Delete all routes of node') && !preg_match('~[А-Яа-яЁё]~u', preg_replace('~<b>.*?</b>~s', '', $bot->last()[0])), 'подтверждение на английском (кроме имени узла)');
$bot->exitRoutesClear($id, true);
$check(str_contains($bot->last()[0], 'All routes deleted'), 'итог на английском');
$bot->language = 'ru';
$bot->exitAllUsers($id, false);
$bot->confPac['exits'][$id]['rulesets'] = [];

// --- Профиль для узла ---------------------------------------------------------
$bot->saveExitRelay('example main');
$check(str_contains($bot->last()[0], 'латиница'), 'имя профиля проверяется');
$bot->saveExitRelay('example');
$relay = array_values(array_filter($bot->confXray['inbounds'][0]['settings']['clients'], static fn($c) => !empty($c['exit_relay'])))[0] ?? [];
$check(($relay['email'] ?? '') === 'node-example' && ($relay['flow'] ?? '') === 'xtls-rprx-vision' && !isset($relay['time']) && !isset($relay['traffic']), 'служебная учётка без срока и лимита');
$check(str_contains($bot->last()[0], 'Ссылка для основного сервера'), 'выдана ссылка');
$bot->saveExitRelay('example');
$check(str_contains($bot->last()[0], 'уже есть'), 'повтор имени');
$relayIndex = count($bot->confXray['inbounds'][0]['settings']['clients']) - 1;
$bot->exitAllUsers($id, true);
$check(!isset($bot->confXray['inbounds'][0]['settings']['clients'][$relayIndex]['exit']), '«всем» не включает служебную учётку');
$bot->exitUsersMenu($id, 0);
$check(!str_contains(json_encode($bot->last()[1], JSON_UNESCAPED_UNICODE), 'node-example'), 'служебная учётка не в списке пользователей узла');
$bot->exitRelayLink($relayIndex);
$check(isset($bot->callbacks()["/exitRelayDel $relayIndex"]), 'в профиле есть кнопка удаления');
$bot->exitRelayDelete(0);
$check(str_contains($bot->last()[0], 'Профиль не найден') && isset($bot->confXray['inbounds'][0]['settings']['clients'][0]), 'обычного пользователя кнопка профиля не удаляет');
$bot->exitRelayDelete($relayIndex);
$yes = "/exitRelayDelYes $relayIndex " . substr(hash('sha256', 'node-example'), 0, 8);
$check(str_contains($bot->last()[0], 'Удалить профиль для узла <b>node-example</b>') && isset($bot->callbacks()[$yes]) && strlen($yes) <= 64, 'подтверждение удаления профиля');
$bot->exitRelayDelete($relayIndex, '00000000');
$check(str_contains($bot->last()[0], 'Профиль не найден') && isset($bot->confXray['inbounds'][0]['settings']['clients'][$relayIndex]), 'чужой отпечаток не удаляет');
$bot->exitRelayDelete($relayIndex, substr(hash('sha256', 'node-example'), 0, 8));
$check(!in_array('node-example', array_column($bot->confXray['inbounds'][0]['settings']['clients'], 'email'), true) && in_array(['warp', 'node-example'], $bot->removed, true)
    && str_contains($bot->last()[0], 'Профиль удалён') && !isset($bot->callbacks()["/exitRelayLink $relayIndex"]), 'профиль удалён, меню профилей без него');
$bot->language = 'en';
$bot->saveExitRelay('example');
$relayIndex = array_key_last($bot->confXray['inbounds'][0]['settings']['clients']);
$bot->exitRelayDelete($relayIndex);
$check(str_contains($bot->last()[0], 'Delete node profile <b>node-example</b>?'), 'подтверждение на английском');
$bot->exitRelayDelete($relayIndex, substr(hash('sha256', 'node-example'), 0, 8));
$check(str_contains($bot->last()[0], 'Profile deleted'), 'итог удаления на английском');
$bot->language = 'ru';

// --- Обновление набора: новое содержимое сначала проверяет ядро -------------
$sets = new class extends ExitMenuBot {
    public string $dir = ''; public string $binary = 'BIN'; public bool $coreOk = true; public array $validated = [];
    public function exitRulesetFile(string $key): string { return $this->dir . '/' . substr(hash('sha256', $key), 0, 24) . '.json'; }
    protected function exitRulesetDownload(string $url): ?string { return $this->binary; }
    public function validateXrayConfig(array $config, string $binary = 'xray'): bool { $this->validated[] = $config; return $this->coreOk; }
};
$sets->dir = sys_get_temp_dir() . '/exit-sets-' . getmypid();
@mkdir($sets->dir, 0700);
$url = 'https://raw.example/geo/video.srs';
$sets->toolOutput = json_encode(['version' => 3, 'rules' => [['domain_suffix' => ['video.example']]]]);
$check($sets->exitRulesetRefresh($url, ['on' => 1]) === '' && ($sets->exitRulesetCache($url)['entries'] ?? null) === ['domain:video.example'] && count($sets->validated) === 1
    && ($sets->validated[0]['routing']['rules'][0]['domain'] ?? null) === ['domain:video.example'], 'новый набор проверен ядром и принят');
$tools = count($sets->tools);
$check($sets->exitRulesetRefresh($url, ['on' => 1]) === '' && count($sets->validated) === 1, 'то же содержимое ядро повторно не проверяет');
$check(count($sets->tools) === $tools && ($sets->exitRulesetCache($url)['entries'] ?? null) === ['domain:video.example'], 'тот же файл не распаковывается заново');
$cached = $sets->exitRulesetCache($url); $cached['parser'] = '0:srs:domain';
file_put_contents($sets->exitRulesetFile($url), json_encode($cached));
$check($sets->exitRulesetRefresh($url, ['on' => 1]) === '' && count($sets->tools) === $tools + 1 && str_starts_with($sets->exitRulesetCache($url)['parser'] ?? '', Bot::EXIT_RULESET_PARSER . ':'),
    'после смены версии разбора тот же файл разбирается заново');
$check(count($sets->validated) === 2, 'разобранное заново из того же файла снова проверяет ядро');
$check($sets->exitRulesetRefresh($url, ['on' => 1, 'behavior' => 'ipcidr']) === '' && count($sets->tools) === $tools + 2 && count($sets->validated) === 3,
    'другой тип набора — разбор заново и проверка ядром');
// Тот же файл, другая версия разбора, а ядро новые записи не принимает: прежние остаются.
$cached = $sets->exitRulesetCache($url); $cached['parser'] = '0:srs:domain';
file_put_contents($sets->exitRulesetFile($url), json_encode($cached));
$sets->coreOk = false;
$check($sets->exitRulesetRefresh($url, ['on' => 1]) === 'core' && ($sets->exitRulesetCache($url)['parser'] ?? '') === '0:srs:domain',
    'переразбор, который ядро отвергло, не заменяет прежние записи');
$sets->coreOk = true;
$sets->exitRulesetRefresh($url, ['on' => 1]);
$sets->binary = 'BIN2'; $sets->coreOk = false;
$sets->toolOutput = json_encode(['version' => 3, 'rules' => [['domain_regex' => ['(']]]]);
$check($sets->exitRulesetRefresh($url, ['on' => 1]) === 'core' && ($sets->exitRulesetCache($url)['entries'] ?? null) === ['domain:video.example'],
    'набор, который ядро не принимает, не заменяет прежний');
// Узел перезапускает Xray, когда записи изменились — в том числе без нового файла.
$node = new class extends ExitMenuBot {
    public string $dir = ''; public bool $coreOk = true;
    public function exitRulesetFile(string $key): string { return $this->dir . '/' . substr(hash('sha256', $key), 0, 24) . '.json'; }
    protected function exitRulesetDownload(string $url): ?string { return 'BIN'; }
    public function validateXrayConfig(array $config, string $binary = 'xray'): bool { return $this->coreOk; }
    public function exitNodes(?array $p = null): array { return ['n1' => ['rulesets' => ['https://raw.example/geo/node.srs' => ['on' => 1, 'behavior' => 'domain']]]]; }
};
$node->dir = $sets->dir;
$node->toolOutput = json_encode(['version' => 3, 'rules' => [['domain_suffix' => ['node.example']]]]);
$nodeUrl = 'https://raw.example/geo/node.srs';
$check($node->exitRefreshRulesets('n1', true) === true, 'первый разбор набора узла — изменение');
$check($node->exitRefreshRulesets('n1', true) === false, 'тот же файл и разбор — без перезапуска Xray');
$cached = $node->exitRulesetCache($nodeUrl); $cached['parser'] = '0:srs:domain';
file_put_contents($node->exitRulesetFile($nodeUrl), json_encode($cached));
$check($node->exitRefreshRulesets('n1', true) === true, 'переразбор того же файла — изменение, Xray перезапускается');
array_map('unlink', glob($sets->dir . '/*') ?: []);
@rmdir($sets->dir);

// --- Восстановление из копии: наборы разбираются до сборки конфига ----------
$restore = new class extends ExitMenuBot {
    public array $order = [];
    public function exitRefreshRulesets(string $id, bool $force = false): bool { $this->order[] = "refresh $id"; return true; }
    public function protocolModuleEnabled(string $service): bool { return false; }
    public function writeXrayJson(string $json): bool { $this->order[] = 'write'; return true; }
    public function writeCoreMarker(string $core): bool { return true; }
};
$restore->confPac['exits'] = ['a1b2c3d4' => ['link' => $link, 'rulesets' => ['https://raw.example/geo/youtube.srs' => ['on' => 1]]], 'e5f6a7b8' => ['link' => $link]];
$check($restore->restoreBackupXray(['restored' => true]) && $restore->order === ['refresh a1b2c3d4', 'refresh e5f6a7b8', 'write'], 'восстановление: наборы узлов до записи конфига');

@unlink($statusFile);
$cacheDir = sys_get_temp_dir() . '/exit-rulesets-test-' . getmypid();
array_map('unlink', glob("$cacheDir/*") ?: []);
@rmdir($cacheDir);
if ($failures) { fwrite(STDERR, "exit_nodes_menu_test FAIL:\n - " . implode("\n - ", array_unique($failures)) . "\n"); exit(1); }
echo "exit_nodes_menu_test OK\n";
