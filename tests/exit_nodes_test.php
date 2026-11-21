<?php
// Узлы выхода: сборка правил, выходов и балансировщиков в xray.json.
require_once __DIR__ . '/../app/bot.php';
set_error_handler(static function ($level, $message, $file, $line) { if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line); return true; });

class ExitBot extends Bot
{
    public array $confPac = ['transport' => 'Reality', 'xray_core' => 'origin'];
    public array $confXray = [];
    public bool $restartOk = true;
    public int $restarts = 0;
    public function __construct()
    {
        $this->input = ['chat' => 1, 'from' => 1, 'message_id' => 5, 'callback_id' => 'cb', 'username' => 'admin'];
        $this->language = 'ru';
        require __DIR__ . '/../app/i18n.php';
        $this->i18n = $i;
    }
    public function getPacConf() { return $this->confPac; }
    public function setPacConf(array $conf) { $this->confPac = $conf; return true; }
    public function getXray() { return $this->confXray; }
    public function restartXray($c, $norestart = false)
    {
        $this->restarts++;
        if (!$this->restartOk) return false;
        $this->ensureExitNodes($c, $this->confPac);
        $this->confXray = $c;
        return true;
    }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
}

$failures = [];
$check = static function (bool $ok, string $name) use (&$failures): void { if (!$ok) $failures[] = $name; };
$uuid = '0b6e8f8a-3c1d-4f6e-9a2b-1c2d3e4f5a6b';
$pbk = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
$link = "vless://$uuid@203.0.113.7:443?security=reality&sni=www.example.com&fp=chrome&pbk=$pbk&sid=a1b2&type=tcp&flow=xtls-rprx-vision&encryption=none#fi";
$base = ['inbounds' => [
    ['tag' => 'vless_reality', 'port' => 443, 'protocol' => 'vless', 'sniffing' => ['enabled' => true, 'destOverride' => ['http', 'tls', 'quic']],
        'settings' => ['decryption' => 'none', 'clients' => [
            ['id' => '11111111-1111-4111-8111-111111111111', 'email' => 'alice', 'flow' => 'xtls-rprx-vision'],
            ['id' => '22222222-2222-4222-8222-222222222222', 'email' => 'bob', 'flow' => 'xtls-rprx-vision'],
            ['id' => '33333333-3333-4333-8333-333333333333', 'email' => 'carol', 'flow' => 'xtls-rprx-vision', 'off' => 'x'],
            ['id' => '44444444-4444-4444-8444-444444444444', 'email' => 'relay-example', 'flow' => 'xtls-rprx-vision', 'exit_relay' => 1],
        ]],
        'streamSettings' => ['network' => 'tcp', 'security' => 'reality', 'realitySettings' => ['dest' => '127.0.0.1:8443', 'serverNames' => ['www.example.com'],
            'privateKey' => rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '='), 'shortIds' => ['a1b2']]]],
    ['tag' => 'api', 'listen' => '127.0.0.1', 'port' => 8080, 'protocol' => 'dokodemo-door', 'settings' => ['address' => '127.0.0.1']],
], 'outbounds' => [['tag' => 'direct', 'protocol' => 'freedom'], ['tag' => 'block', 'protocol' => 'blackhole'],
    ['tag' => 'warp', 'protocol' => 'socks', 'settings' => ['servers' => [['address' => '10.10.0.13', 'port' => 1080]]]]],
'routing' => ['rules' => [
    ['type' => 'field', 'inboundTag' => ['api'], 'outboundTag' => 'api'],
    ['type' => 'field', 'outboundTag' => 'block', 'ruleTag' => 'vpnbot:routes:block:domain', 'domain' => ['domain:ads.example']],
    ['type' => 'field', 'outboundTag' => 'warp', 'ruleTag' => 'vpnbot:routes:warp:domain', 'domain' => ['domain:chatgpt.com']],
    ['type' => 'field', 'outboundTag' => 'direct', 'domain' => ['domain:custom.example']],
]]];
$tags = static fn(array $c, string $field) => array_map(static fn($x) => $x['tag'] ?? '', $c[$field] ?? []);
$ruleTags = static fn(array $c) => array_map(static fn($r) => $r['ruleTag'] ?? '-', $c['routing']['rules']);

// --- Без узлов: конфиг не меняется, прежние следы снимаются ---------------
$bot = new ExitBot();
$c = $base; $bot->ensureExitNodes($c, []);
$check($c === $base, 'без узлов конфиг не меняется');
$dirty = $base;
$dirty['outbounds'][] = ['tag' => 'vpnbot-exit-deadbeef', 'protocol' => 'freedom'];
$dirty['inbounds'][] = ['tag' => 'vpnbot-exit-probe-deadbeef', 'port' => 10870, 'protocol' => 'socks'];
$dirty['routing']['rules'][] = ['type' => 'field', 'ruleTag' => 'vpnbot:exit:deadbeef:domain', 'domain' => ['x'], 'balancerTag' => 'vpnbot-exit-deadbeef'];
$dirty['routing']['balancers'] = [['tag' => 'vpnbot-exit-deadbeef', 'selector' => ['vpnbot-exit-deadbeef']]];
$dirty['observatory'] = ['subjectSelector' => ['vpnbot-exit-a1b2c3d4'], 'probeURL' => 'https://x'];
$dirty['burstObservatory'] = ['subjectSelector' => ['vpnbot-exit-a1b2c3d4'], 'pingConfig' => ['interval' => '10s']];
$bot->ensureExitNodes($dirty, []);
$check($dirty === $base, 'следы удалённого узла снимаются полностью');

// --- Узел без пользователей: выход и вход проверки, правил по доменам нет --
$pac = ['exits' => ['a1b2c3d4' => ['name' => 'FI', 'link' => $link, 'routes' => array_fill_keys(ExitBotRoutes::YT, 1)]]];
class ExitBotRoutes { public const YT = ['domain:youtube.com', 'domain:googlevideo.com', 'full:www.youtube.com', 'keyword:ytimg', 'regexp:^yt[0-9]+\.example$', '203.0.113.0/24']; }
$c = $base; $bot->ensureExitNodes($c, $pac);
$check(in_array('vpnbot-exit-a1b2c3d4', $tags($c, 'outbounds'), true), 'выход узла');
$probe = array_values(array_filter($c['inbounds'], static fn($i) => $i['tag'] === 'vpnbot-exit-probe-a1b2c3d4'))[0] ?? [];
$check(($probe['listen'] ?? '') === '127.0.0.1' && ($probe['port'] ?? 0) === 10870 && ($probe['protocol'] ?? '') === 'socks', 'вход проверки только на 127.0.0.1');
$check($c['routing']['rules'][0] === ['type' => 'field', 'ruleTag' => 'vpnbot:exit:a1b2c3d4:probe', 'inboundTag' => ['vpnbot-exit-probe-a1b2c3d4'], 'outboundTag' => 'vpnbot-exit-a1b2c3d4'],
    'правило проверки первым и прямо в узел');
$check(!isset($c['routing']['balancers']) && !isset($c['observatory']) && count(array_filter($ruleTags($c), static fn($t) => str_starts_with($t, 'vpnbot:exit:'))) === 1,
    'без пользователей нет балансировщика и правил');

// --- Пользователи: только alice, правила между block и warp ---------------
$c = $base;
$c['inbounds'][0]['settings']['clients'][0]['exit'] = ['a1b2c3d4'];
$c['inbounds'][0]['settings']['clients'][2]['exit'] = ['a1b2c3d4']; // off
$c['inbounds'][0]['settings']['clients'][3]['exit'] = ['a1b2c3d4']; // служебная учётка узла
$withUsers = $c;
$bot->ensureExitNodes($c, $pac);
$order = $ruleTags($c);
$check($order === ['vpnbot:exit:a1b2c3d4:probe', '-', 'vpnbot:routes:block:domain', 'vpnbot:exit:a1b2c3d4:quic-domain', 'vpnbot:exit:a1b2c3d4:quic-ip',
    'vpnbot:exit:a1b2c3d4:domain', 'vpnbot:exit:a1b2c3d4:ip', 'vpnbot:routes:warp:domain', '-'], 'порядок правил: block → узел → warp → свои');
$rule = array_values(array_filter($c['routing']['rules'], static fn($r) => ($r['ruleTag'] ?? '') === 'vpnbot:exit:a1b2c3d4:domain'))[0];
$check($rule['user'] === ['alice'], 'только включённый, не отключённый и не служебная учётка');
$check($rule['balancerTag'] === 'vpnbot-exit-a1b2c3d4' && !isset($rule['outboundTag']), 'через балансировщик');
$check($rule['domain'] === ['domain:youtube.com', 'domain:googlevideo.com', 'full:www.youtube.com', 'ytimg', 'regexp:^yt[0-9]+\.example$'], 'домены с префиксами');
$ipRule = array_values(array_filter($c['routing']['rules'], static fn($r) => ($r['ruleTag'] ?? '') === 'vpnbot:exit:a1b2c3d4:ip'))[0];
$check($ipRule['ip'] === ['203.0.113.0/24'], 'подсеть отдельным правилом');
$quic = array_values(array_filter($c['routing']['rules'], static fn($r) => ($r['ruleTag'] ?? '') === 'vpnbot:exit:a1b2c3d4:quic-domain'))[0];
$check($quic['network'] === 'udp' && $quic['port'] === '443' && $quic['outboundTag'] === 'block' && $quic['user'] === ['alice'], 'QUIC к доменам узла режется');
$check($c['routing']['balancers'] === [['tag' => 'vpnbot-exit-a1b2c3d4', 'selector' => ['vpnbot-exit-a1b2c3d4'], 'strategy' => ['type' => 'random'], 'fallbackTag' => 'direct']],
    'random + fallbackTag direct (leastPing до первой пробы отдал бы трафик мимо узла)');
$check($c['burstObservatory'] === ['subjectSelector' => ['vpnbot-exit-a1b2c3d4'], 'pingConfig' => ['destination' => 'https://www.gstatic.com/generate_204', 'interval' => '10s', 'sampling' => 3, 'timeout' => '5s']]
    && !isset($c['observatory']), 'своя burstObservatory (одна потерянная проба не хоронит узел)');
$again = $c; $bot->ensureExitNodes($again, $pac);
$check($again === $c, 'повторная сборка ничего не меняет');

// --- Без блок-листа правила узла всё равно ниже правила торрентов ----------
$c = $withUsers;
$c['routing']['rules'] = [['type' => 'field', 'inboundTag' => ['vless_reality'], 'protocol' => ['bittorrent'], 'outboundTag' => 'block'],
    ['type' => 'field', 'inboundTag' => ['api'], 'outboundTag' => 'api']];
$bot->ensureExitNodes($c, $pac);
$check(($c['routing']['rules'][1]['protocol'] ?? null) === ['bittorrent'] && str_starts_with($c['routing']['rules'][2]['ruleTag'] ?? '', 'vpnbot:exit:a1b2c3d4:quic'),
    'торренты блокируются раньше правила узла');

// --- QUIC «пропускать», выключенный узел, битая ссылка ---------------------
$c = $withUsers; $q = $pac; $q['exits']['a1b2c3d4']['quic'] = 'pass';
$bot->ensureExitNodes($c, $q);
$check(!array_filter($ruleTags($c), static fn($t) => str_contains($t, ':quic-')), 'QUIC пропускается по настройке');
foreach (['выключенный узел' => ['enabled' => 0], 'битая ссылка' => ['link' => 'vless://x@y:1?security=none']] as $name => $patch) {
    $c = $withUsers; $q = $pac; $q['exits']['a1b2c3d4'] = $patch + $q['exits']['a1b2c3d4'];
    $bot->ensureExitNodes($c, $q);
    $check($c === $withUsers, $name . ': в конфиге ничего');
}
$c = $withUsers; $q = $pac; $q['exits']['a1b2c3d4']['routes'] = ['keyword:' => 1, '999.1.1.1' => 1, 'ext:missing.dat:x' => 1];
$bot->ensureExitNodes($c, $q);
$check(!isset($c['routing']['balancers']), 'пустые и битые записи не превращаются в правило «всё»');

// Полное назначение действует даже при пустом списке и при сломанном наборе другого узла.
$full = $withUsers;
$id = 'a1b2c3d4';
$other = 'beadbead';
foreach ([0, 2, 3] as $i) $full['inbounds'][0]['settings']['clients'][$i]['exit_full'] = $id;
$full['inbounds'][0]['settings']['clients'][0]['exit'][] = $other;
$full['inbounds'][0]['settings']['clients'][1]['exit'] = [$id];
$q = ['exits' => [$other => ['link' => $link, 'fallback' => 'block', 'routes' => ['ext:missing.dat:x' => 1]]] + $pac['exits']];
$c = $full; $bot->ensureExitNodes($c, $q);
$byTag = static fn(array $c) => array_column($c['routing']['rules'], null, 'ruleTag');
$rules = $byTag($c);
$check($rules["vpnbot:exit:$id:full"] === ['type' => 'field', 'ruleTag' => "vpnbot:exit:$id:full", 'user' => ['alice'], 'outboundTag' => "vpnbot-exit-$id"]
    && $rules["vpnbot:exit:$id:domain"]['user'] === ['bob'], 'один узел для полного и выборочного выхода, без прямого fallback для полного');
$check(!isset($rules[Bot::EXIT_UNAVAILABLE . $other]) && $rules["vpnbot:exit:$id:quic-full"]['user'] === ['alice'], 'чужой строгий набор и QUIC');
$order = $ruleTags($c);
$check(array_search('vpnbot:routes:block:domain', $order) < array_search("vpnbot:exit:$id:full", $order)
    && array_search("vpnbot:exit:$id:full", $order) < array_search('vpnbot:routes:warp:domain', $order), 'приоритет блок-листа и WARP');
$bot->ensureWgGuard($c);
$check($byTag($c)['vpnbot:exit:full-guard']['user'] === ['alice'] && $c['routing']['rules'][0]['ip'] === [Bot::INTERNAL_DNS], 'штатный DNS и запрет прямого WARP-SOCKS');
$again = $c; $bot->ensureExitNodes($again, $q); $bot->ensureWgGuard($again);
$check($again === $c, 'повторная сборка полного маршрута с защитными правилами');
foreach ([['enabled' => 0], ['link' => 'invalid']] as $patch) {
    $c = $full; $down = $q; $down['exits'][$id] = $patch + $down['exits'][$id]; $bot->ensureExitNodes($c, $down);
    $deny = $byTag($c)[Bot::EXIT_UNAVAILABLE . 'full'] ?? [];
    $check(($deny['user'] ?? null) === ['alice'] && $deny['outboundTag'] === 'block', 'выключенный или повреждённый выход закрывается');
}
$c = $full; $bot->ensureExitNodes($c, []);
$check($byTag($c)[Bot::EXIT_UNAVAILABLE . 'full']['user'] === ['alice'], 'утраченный при восстановлении узел закрывается');
$c = $full; $q['exits'][$id]['routes'] = []; $q['exits'][$id]['quic'] = 'pass';
$c['inbounds'][0]['settings']['clients'][0]['email'] = 'regexp:.*';
$bot->ensureExitNodes($c, $q);
$users = $byTag($c)["vpnbot:exit:$id:full"]['user'] ?? [];
$check(Bot::exitUserMatches($users, 'regexp:.*') && !Bot::exitUserMatches($users, 'bob')
    && !isset($byTag($c)["vpnbot:exit:$id:quic-full"]), 'без списков, имя с regexp: буквально, QUIC разрешён');

$full['routing']['domainStrategy'] = 'IPIfNonMatch';
$full['routing']['rules'][] = ['type' => 'field', 'ruleTag' => 'vpnbot:routes:block:ip', 'ip' => ['198.51.100.2'], 'outboundTag' => 'block'];
$c = $full; $bot->ensureExitNodes($c, $q);
$rules = $byTag($c);
$hop = $rules["vpnbot:exit:$id:full"]['outboundTag'];
$resolve = array_column($c['outbounds'], null, 'tag')[$hop];
$check($resolve['protocol'] === 'loopback' && $resolve['targetStrategy'] === 'ForceIP'
    && $rules["vpnbot:exit:$id:resolved"]['inboundTag'] === [$hop] && $rules["vpnbot:exit:$id:resolved"]['outboundTag'] === "vpnbot-exit-$id"
    && $rules["vpnbot:exit:$id:unresolved"]['outboundTag'] === 'block', 'повторная проверка IP ограничена полным назначением');
$check(in_array('198.51.100.2', $rules['vpnbot:exit:resolved-block']['ip'], true)
    && array_search('vpnbot:exit:resolved-block', $ruleTags($c)) < array_search("vpnbot:exit:$id:resolved", $ruleTags($c)), 'запрет IP исполняется раньше выхода после DNS');

// Ручное разрешение до блок-листа сохраняется только для обычного клиента.
array_unshift($full['routing']['rules'], ['type' => 'field', 'ruleTag' => 'early-direct', 'outboundTag' => 'direct', 'network' => 'tcp,udp']);
$c = $full; $bot->ensureExitNodes($c, $q); $bot->ensureWgGuard($c);
$order = $ruleTags($c);
$check(array_search("vpnbot:exit:$id:full", $order, true) < array_search('early-direct', $order, true)
    && array_search('early-direct', $order, true) < array_search('vpnbot:routes:block:domain', $order, true)
    && $byTag($c)['vpnbot:exit:full-policy:0']['user'] === ['alice'], 'ранний ручной direct не обходит полный выход или его блок-лист');
$again = $c; $bot->ensureExitNodes($again, $q); $bot->ensureWgGuard($again);
$check($c === $again, 'повторная сборка при нестандартном порядке');

// --- Чужая observatory сохраняется ----------------------------------------
$c = $withUsers; $c['observatory'] = ['subjectSelector' => ['proxy-'], 'probeURL' => 'https://custom.example/204'];
$bot->ensureExitNodes($c, $pac);
$check($c['observatory'] === ['subjectSelector' => ['proxy-', 'vpnbot-exit-a1b2c3d4'], 'probeURL' => 'https://custom.example/204'], 'чужая observatory дополнена');
$bot->ensureExitNodes($c, []);
$check($c['observatory'] === ['subjectSelector' => ['proxy-'], 'probeURL' => 'https://custom.example/204'] && !isset($c['burstObservatory']), 'после удаления узлов чужая observatory прежняя');
$c = $withUsers; $c['burstObservatory'] = ['subjectSelector' => ['lb-'], 'pingConfig' => ['interval' => '1m']];
$bot->ensureExitNodes($c, $pac);
$check($c['burstObservatory']['subjectSelector'] === ['lb-', 'vpnbot-exit-a1b2c3d4'] && $c['burstObservatory']['pingConfig'] === ['interval' => '1m'] && !isset($c['observatory']), 'чужая burstObservatory дополнена');
$bot->ensureExitNodes($c, []);
$check($c['burstObservatory'] === ['subjectSelector' => ['lb-'], 'pingConfig' => ['interval' => '1m']], 'чужая burstObservatory восстановлена');

// --- Несколько узлов: свои порты проверки, порядок = приоритет -------------
$q = $pac; $q['exits']['b5b6b7b8'] = ['name' => 'DE', 'link' => $link, 'routes' => ['domain:example.org' => 1]];
$c = $withUsers; $c['inbounds'][0]['settings']['clients'][1]['exit'] = ['b5b6b7b8'];
$bot->ensureExitNodes($c, $q);
$ports = array_column(array_values(array_filter($c['inbounds'], static fn($i) => str_starts_with($i['tag'], 'vpnbot-exit-probe-'))), 'port', 'tag');
$check($ports === ['vpnbot-exit-probe-a1b2c3d4' => 10870, 'vpnbot-exit-probe-b5b6b7b8' => 10871], 'порты проверки по порядку узлов');
$check($bot->exitProbePort('b5b6b7b8', $q) === 10871 && $bot->exitProbePort('ffffffff', $q) === null, 'exitProbePort');
$deRule = array_values(array_filter($c['routing']['rules'], static fn($r) => ($r['ruleTag'] ?? '') === 'vpnbot:exit:b5b6b7b8:domain'))[0];
$check($deRule['user'] === ['bob'], 'второй узел — своим пользователям');

// --- id из одних цифр: ключ-число из json_decode не теряется ----------------
$numeric = json_decode(json_encode(['exits' => ['12345678' => ['link' => $link, 'routes' => ['domain:example.org' => 1]]]]), true);
$check(array_map('strval', array_keys($bot->exitNodes($numeric))) === ['12345678'] && $bot->exitProbePort('12345678', $numeric) === 10870, 'числовой ключ узла читается');
for ($n = 0; $n < 2000; $n++) if (!preg_match('~^(?=.*[a-f])[a-f0-9]{8}$~', Bot::exitNewId())) { $check(false, 'новый id всегда с буквой'); break; }

// --- Транзакция: ядро отвергло — pac прежний ------------------------------
$bot->confPac = $pac; $bot->confXray = $withUsers; $bot->restartOk = false;
$error = $bot->applyExitNodes(static function (array &$p) { $p['exits']['a1b2c3d4']['enabled'] = 0; return ''; });
$check($error === 'exit check failed' && $bot->confPac === $pac, 'отказ ядра возвращает прежний pac');
$bot->restartOk = true;
$check($bot->applyExitNodes(static fn(array &$p) => 'exit bad') === 'exit bad' && $bot->confPac === $pac, 'ошибка правки ничего не пишет');
$restarts = $bot->restarts;
$check($bot->applyExitNodes(static fn(array &$p) => '') === '' && $bot->restarts === $restarts, 'без изменений Xray не перезапускается');

// --- Настоящее ядро принимает собранный конфиг ------------------------------
$xray = getenv('VLESS_TEST_XRAY');
if (is_string($xray) && $xray !== '' && is_executable($xray)) {
    $c = $withUsers; $bot->ensureExitNodes($c, $q);
    $c['inbounds'] = array_values(array_filter($c['inbounds'], static fn($i) => $i['tag'] !== 'api'));
    $c['routing']['rules'] = array_values(array_filter($c['routing']['rules'], static fn($r) => ($r['outboundTag'] ?? '') !== 'api'));
    $file = sys_get_temp_dir() . '/exit-nodes-' . getmypid() . '.json';
    file_put_contents($file, json_encode($c, JSON_UNESCAPED_SLASHES));
    exec(escapeshellarg($xray) . ' run -test -config ' . escapeshellarg($file) . ' 2>&1', $out, $code);
    unlink($file);
    $check($code === 0, 'ядро принимает конфиг с узлами: ' . implode(' ', array_slice($out, -3)));
}

if ($failures) { fwrite(STDERR, "exit_nodes_test FAIL:\n - " . implode("\n - ", $failures) . "\n"); exit(1); }
echo "exit_nodes_test OK\n";
