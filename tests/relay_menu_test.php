<?php

// Меню relay (Vless → relay), relay-подписки пользователя и выдача подписки
// через relay. Проверяется то, что ломалось молча или путало администратора:
//  1. экраны: список → карточка со сводкой каналов → экран канала; кнопки
//     ведут на существующие маршруты, callback_data ≤ 64 байт даже при имени
//     из 32 символов, HTML экрана валиден при «&» и «<» в данных;
//  2. ввод: неверный адрес, порт и карта портов не сохраняются и не стирают
//     прежнее значение, а экран объясняет причину; 0 — очистка;
//  3. удаление только после подтверждения и со снятием выбора в WireGuard;
//  4. статус: проба знает свою точку, NaiveProxy проверяется отдельно, UDP-
//     каналы чужой статус не показывают;
//  5. relay-подписки: список, сводка «что идёт через relay», 404 для
//     удалённого relay и для истёкшего пользователя в base64-подписке.

require_once __DIR__ . '/../app/bot.php';

set_error_handler(static function ($level, $message, $file, $line) {
    if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line);
    return false;
});

$checks = 0;
function rmCheck(bool $ok, string $label): void
{
    global $checks;
    if (!$ok) throw new RuntimeException($label);
    $checks++;
}

final class RelayMenuNotFound extends RuntimeException {}

class RelayMenuTransport
{
    public array $calls = [];
    public function call($method, $data, $json = 0)
    {
        $this->calls[] = [$method, $data];
        return ['ok' => true, 'result' => ['message_id' => count($this->calls) + 10, 'chat' => ['id' => 1]]];
    }
}

class RelayMenuBot extends Bot
{
    public array $conf = [];
    public array $xr = [];
    public array $prompts = [];
    public array $probes = [];
    public array $health = [];
    public int $naiveSync = 0;
    public array $screen = ['', []];
    public function __construct(array $strings, string $lang = 'ru')
    {
        $this->admin = true; $this->i18n = $strings; $this->language = $lang; Lang::$en = $lang === 'en';
        $this->ip = '192.0.2.1'; $this->key = 'fixture';
        $this->input = ['chat' => 1, 'from' => 1, 'message_id' => 5, 'callback_id' => 'cb', 'username' => 'admin', 'message' => '', 'callback' => ''];
        $this->transport = new RelayMenuTransport();
        $this->xr = ['inbounds' => [['settings' => ['clients' => [
            ['id' => '11111111-2222-4333-8444-555555555555', 'email' => 'Ann & <b>', 'subtoken' => 'tok0'],
            ['id' => '21111111-2222-4333-8444-555555555555', 'email' => 'old', 'subtoken' => 'tok1', 'time' => time() - 60],
        ]]]]];
    }
    public function getPacConf() { return $this->conf + self::PAC_DEFAULTS; }
    public function setPacConf(array $conf) { $this->conf = $conf; return true; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
    public function getXray() { return $this->xr; }
    public function getDomain($cdn = false) { return 'origin.example.test'; }
    public function getHashBot($notset = false) { return 'fixture'; }
    public string $cert = 'letsencrypt';
    public function nginxGetTypeCert() { return $this->cert; }
    public function getWgMsg() { return null; }
    protected function sessionApply(callable $fn) { $fn(); }
    public function readRelayHealth(): array { return $this->health; }
    public function writeRelayHealth(array $health): void { $this->health = $health; }
    public function tcpProbe(string $host, int $port, float $timeout = 3.0): array
    {
        $this->probes[] = "$host:$port";
        return ['ok' => $host !== 'dead.example.test', 'ms' => 7, 'at' => time(), 'err' => $host === 'dead.example.test' ? '111 refused' : ''];
    }
    public function setUpstreamDomainNaive($domain) { $this->naiveSync++; }
    public function getHashSubdomain($name = '') { return 'npfixture'; }
    public function stashReply($r, array $state) { $this->prompts[] = $state; }
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML')
    {
        $this->screen = [$text, $this->protocolNavigationButtons(is_array($button) ? $button : [])];
    }
    public function click(string $callback): void { $this->input['callback'] = $callback; $this->action(); $this->input['callback'] = ''; }
    public function callbacks(): array { return array_column(array_merge(...($this->screen[1] ?: [[]])), 'callback_data'); }
    public function subNotFound($reason = 'Subscription not found or disabled.') { throw new RelayMenuNotFound((string) $reason); }
    public function subRateLimit($sid, $scope = '') {}
    public function subSecurityHeaders() {}
    public function processHwidRequest(array $client, bool $htmlPreview = false) { return true; }
    public function xraySubscriptionMetadata(array $client, int $index): void {}
    public function getXrayStats() { return []; }
    public function xrayProtocolUsage(array $client): array { return []; }
    public function linkXray($i, $s = false) { return 'vless://cred@origin.example.test:443?security=reality#' . rawurlencode('🇫🇮 user'); }
    public function flagName(string $name, string|array $hosts, bool $cacheOnly = true): string { return $name; }
    public function protocolModuleEnabled(string $module): bool { return false; }
}

// Экран: валидный HTML Telegram, длина, callback_data, каждый callback
// разбирается роутером (иначе кнопка «мёртвая»).
function rmScreen(RelayMenuBot $bot, string $label): array
{
    [$text, $buttons] = $bot->screen;
    rmCheck($bot->messageTextLength($text) < 4096, "$label: длина текста");
    preg_match_all('~<(/?)([a-z]+)(?:\s[^<>]*)?>~i', $text, $tags, PREG_SET_ORDER);
    $stack = [];
    foreach ($tags as $tag) {
        if ($tag[1] === '/') rmCheck(array_pop($stack) === $tag[2], "$label: HTML закрывает правильный тег");
        else { rmCheck(in_array($tag[2], ['b', 'i', 'code', 'pre', 'a'], true), "$label: только теги Telegram ($tag[2])"); $stack[] = $tag[2]; }
    }
    rmCheck($stack === [], "$label: все теги закрыты");
    rmCheck(!preg_match('~&(?!(?:amp|lt|gt|quot|#039|#\d+);)~', $text), "$label: «&» экранирован");
    foreach ($buttons as $row) foreach ($row as $b) {
        rmCheck(strlen($b['callback_data'] ?? '') <= 64, "$label: callback ≤ 64 байт: " . ($b['callback_data'] ?? ''));
    }
    return [$text, $bot->callbacks()];
}

$routes = (new ReflectionMethod(Bot::class, 'action'))->getFileName();
$routerSource = file_get_contents($routes);
function rmRouted(string $callback): bool
{
    global $routerSource;
    preg_match_all('#case preg_match\(\'(~\^/[^\']+)\', \$this->input\[\'callback\'\]#', $routerSource, $m);
    foreach ($m[1] as $re) if (@preg_match($re, $callback)) return true;
    return false;
}

foreach (['ru', 'en'] as $lang) {
    require __DIR__ . '/../app/i18n.php';
    $bot = new RelayMenuBot($i, $lang);
    $name = str_repeat('r', 32); // предельная длина имени

    // ── 1. Пустой список ────────────────────────────────────────────────────
    $bot->click('/relayMenu');
    [$text, $cbs] = rmScreen($bot, "$lang пустой список");
    rmCheck(in_array('/relayAdd', $cbs, true) && in_array('/switchRelayAggregate', $cbs, true)
        && in_array('/menuhelp relay 0', $cbs, true) && end($cbs) === '/xray', "$lang: кнопки пустого списка");
    rmCheck(str_contains($text, 'DNAT') && str_contains($text, 'base64'), "$lang: экран объясняет relay и «одной подпиской»");
    if ($lang === 'en') rmCheck(!preg_match('~\p{Cyrillic}~u', strip_tags($text)), 'en: без русского текста');

    // ── 2. Создание ─────────────────────────────────────────────────────────
    $bot->setRelayName('bad name!');
    rmCheck(empty($bot->conf['relays']) && str_contains($bot->screen[0], '⚠️'), "$lang: неверное имя не создаёт relay и объясняется");
    $bot->setRelayName($name);
    rmCheck(isset($bot->conf['relays'][$name]) && $bot->conf['relays'][$name] === ['address' => '', 'portmap' => []], "$lang: relay создан в прежнем формате");
    [$text, $cbs] = rmScreen($bot, "$lang карточка");
    $bot->setRelayName($name);
    rmCheck(str_contains($bot->screen[0], '⚠️') && count($bot->conf['relays']) === 1, "$lang: дубль имени отклоняется");

    // ── 3. Карточка ─────────────────────────────────────────────────────────
    $bot->click("/relayEdit $name");
    [$text, $cbs] = rmScreen($bot, "$lang карточка");
    foreach (['vless', 'wg', 'hy', 'np'] as $ch) rmCheck(in_array("/relayCh $ch $name", $cbs, true), "$lang: канал $ch в карточке");
    foreach (array_keys(ManagedProtocol::NAMES) as $protocol) rmCheck(in_array("/prset $protocol $name", $cbs, true), "$lang: канал $protocol в карточке");
    rmCheck(in_array("/relayDel $name", $cbs, true) && in_array("/menuhelp relay 0 $name", $cbs, true) && end($cbs) === '/relayMenu', "$lang: удаление, справка, назад");
    foreach ($cbs as $cb) rmCheck(rmRouted($cb), "$lang: маршрут для $cb");

    // ── 4. Канал VLESS: ввод ────────────────────────────────────────────────
    $bot->click("/relayCh vless $name");
    [$text, $cbs] = rmScreen($bot, "$lang канал vless");
    rmCheck(in_array("/setRelayAddress $name", $cbs, true) && in_array("/setRelayPortMap $name", $cbs, true) && end($cbs) === "/relayEdit $name", "$lang: поля VLESS");
    rmCheck(!in_array("/relayChClear vless $name", $cbs, true), "$lang: пустой канал нечего очищать");
    foreach ($cbs as $cb) rmCheck(rmRouted($cb), "$lang: маршрут для $cb");
    foreach (['1.2.3.4:443', 'https://relay.example.test', 'a<b', 'two words'] as $bad) {
        $bot->setRelayAddress($bad, $name);
        rmScreen($bot, "$lang ошибка адреса");
        rmCheck($bot->conf['relays'][$name]['address'] === '' && str_contains($bot->screen[0], '⚠️'), "$lang: адрес «{$bad}» не сохранён и объяснён");
    }
    $bot->setRelayAddress('1.2.3.4:443', $name);
    rmCheck(str_contains($bot->screen[0], $lang === 'ru' ? 'порт задаётся отдельной' : 'the port has its own'), "$lang: адрес с портом — подсказка, где задать порт");
    $bot->setRelayAddress(' relay.example.test ', $name);
    rmCheck($bot->conf['relays'][$name]['address'] === 'relay.example.test', "$lang: адрес сохранён без пробелов");
    $bot->setRelayPortMap('443:8443, 80:8080', $name);
    rmCheck($bot->conf['relays'][$name]['portmap'] === ['443' => '8443', '80' => '8080'], "$lang: карта сохранена");
    foreach (['443:70000', '443:0', 'abc', '443-8443', '443:8443,bad', ':'] as $bad) {
        $bot->setRelayPortMap($bad, $name);
        rmCheck($bot->conf['relays'][$name]['portmap'] === ['443' => '8443', '80' => '8080'] && str_contains($bot->screen[0], '⚠️'), "$lang: карта «{$bad}» отклонена, прежняя цела");
    }
    [$text, $cbs] = rmScreen($bot, "$lang канал vless заполнен");
    rmCheck(str_contains($text, '<code>relay.example.test:8443</code>') && str_contains($text, '443→8443'), "$lang: итог для клиента — адрес:порт relay");
    rmCheck(in_array("/relayChClear vless $name", $cbs, true), "$lang: заполненный канал можно очистить");
    $bot->setRelayPortMap('0', $name);
    rmCheck($bot->conf['relays'][$name]['portmap'] === [], "$lang: 0 очищает карту");
    $bot->setRelayPortMap('443:8443', $name);

    // ── 5. Каналы WG, Hysteria, NaiveProxy ──────────────────────────────────
    $bot->setRelayAwgAddress('wg.example.test', $name);
    $bot->setRelayAwgPortMap('51820:443', $name);
    rmCheck($bot->conf['relays'][$name]['awg_address'] === 'wg.example.test' && $bot->conf['relays'][$name]['awg_portmap'] === ['51820' => '443'], "$lang: канал WG");
    $bot->setRelayAwgPortMap('51820:99999', $name);
    rmCheck($bot->conf['relays'][$name]['awg_portmap'] === ['51820' => '443'], "$lang: неверная карта WG не стирает прежнюю");
    $bot->setRelayHyAddress('hy.example.test', $name);
    $bot->setRelayHyPort('8443', $name);
    $bot->setRelayHyPort('abc', $name);
    rmCheck($bot->conf['relays'][$name]['hy_port'] === '8443' && str_contains($bot->screen[0], '⚠️'), "$lang: неверный порт Hysteria не стирает прежний");
    $bot->setRelayHyPort('0', $name);
    rmCheck(!isset($bot->conf['relays'][$name]['hy_port']), "$lang: 0 очищает порт Hysteria");
    $bot->setRelayHyPortMap('36712:443', $name);
    $before = $bot->naiveSync;
    $bot->setRelayNpAddress('np.alias.example.test', $name);
    rmCheck($bot->conf['relays'][$name]['np_address'] === 'np.alias.example.test' && $bot->naiveSync === $before + 1, "$lang: адрес Naive и маршрут SNI");
    $bot->setRelayNpPort('70000', $name);
    rmCheck(!isset($bot->conf['relays'][$name]['np_port']) && str_contains($bot->screen[0], '⚠️'), "$lang: порт Naive вне диапазона отклонён");
    $bot->setRelayNpPort('9443', $name);
    foreach (['wg', 'hy', 'np'] as $ch) {
        $bot->click("/relayCh $ch $name");
        [, $cbs] = rmScreen($bot, "$lang канал $ch");
        foreach ($cbs as $cb) rmCheck(rmRouted($cb), "$lang: маршрут для $cb");
    }
    $bot->click("/relayChClear hy $name");
    rmCheck(!isset($bot->conf['relays'][$name]['hy_address']) && !isset($bot->conf['relays'][$name]['hy_portmap']), "$lang: очистка канала Hysteria");
    $bot->click("/relayChClear vless $name");
    rmCheck($bot->conf['relays'][$name]['address'] === '' && $bot->conf['relays'][$name]['portmap'] === [], "$lang: очистка VLESS оставляет прежний формат записи");
    $bot->setRelayAddress('relay.example.test', $name);
    $bot->setRelayPortMap('443:8443', $name);
    $bot->click("/relayEdit $name");
    [$text] = rmScreen($bot, "$lang заполненная карточка");
    rmCheck(str_contains($text, 'wg.example.test') && str_contains($text, 'np.alias.example.test') && str_contains($text, 'relay.example.test'), "$lang: сводка каналов в карточке");

    // ── 6. Протокол-модуль через общий ответ ────────────────────────────────
    $bot->protocolRelayReply('mod.example.test 10443', 'anytls', $name);
    rmCheck($bot->conf['relays'][$name]['anytls_address'] === 'mod.example.test' && $bot->conf['relays'][$name]['anytls_port'] === 10443, "$lang: канал AnyTLS");
    rmScreen($bot, "$lang карточка после модуля");

    // ── 7. Статус ───────────────────────────────────────────────────────────
    $bot->conf['relays']['dead'] = ['address' => 'dead.example.test', 'portmap' => [], 'np_address' => 'dead.example.test'];
    $bot->conf['relays']['udp'] = ['address' => '', 'portmap' => [], 'awg_address' => 'udp.example.test', 'hy_address' => 'udp.example.test'];
    $bot->time_relayhealth = 0; $bot->probes = [];
    $bot->checkRelayHealth();
    rmCheck(in_array('relay.example.test:8443', $bot->probes, true) && in_array('np.alias.example.test:9443', $bot->probes, true), "$lang: проба VLESS через карту и отдельная проба Naive");
    rmCheck(count(array_keys($bot->probes, 'dead.example.test:443')) === 1 && $bot->health['np:dead'] === $bot->health['dead'], "$lang: совпадающая точка не стучится дважды");
    rmCheck(!preg_grep('~udp\.example~', $bot->probes) && !isset($bot->health['udp']), "$lang: UDP-каналы не пробуются");
    rmCheck(($bot->health[$name]['host'] ?? '') === 'relay.example.test' && ($bot->health[$name]['port'] ?? 0) === 8443, "$lang: проба помнит свою точку");
    $bot->click('/relayMenu');
    [$text] = rmScreen($bot, "$lang список со статусами");
    $labels = array_column(array_merge(...$bot->screen[1]), 'text');
    rmCheck((bool) preg_grep('~^🔗 dead · dead\.example\.test  ⛔~u', $labels) && (bool) preg_grep('~^🔗 udp · WireGuard / AWG, Hysteria$~u', $labels), "$lang: строки списка: статус VLESS, каналы без VLESS");
    $bot->hyRelay();
    rmCheck(!preg_grep('~[✅⛔]~u', array_column(array_merge(...$bot->screen[1]), 'text')), "$lang: меню Hysteria не показывает TCP-статус");
    $bot->npRelay();
    rmCheck((bool) preg_grep('~np\.alias\.example\.test  ✅~u', array_column(array_merge(...$bot->screen[1]), 'text')), "$lang: меню Naive показывает статус своего канала");

    // ── 8. Relay-подписки пользователя ──────────────────────────────────────
    $bot->conf['relays']['empty'] = ['address' => '', 'portmap' => []];
    $bot->click('/userRelay 0');
    [$text, $cbs] = rmScreen($bot, "$lang relay-подписки");
    rmCheck(str_contains($text, 'Ann &amp; &lt;b&gt;'), "$lang: имя пользователя экранировано");
    rmCheck(in_array("/relaySub 0_$name", $cbs, true) && in_array('/relaySub 0_udp', $cbs, true) && !in_array('/relaySub 0_empty', $cbs, true), "$lang: в списке только relay с каналами подписки");
    rmCheck(in_array('/menuhelp relay_user 0 0', $cbs, true) && end($cbs) === '/userXr 0', "$lang: справка и назад");
    $bot->click("/relaySub 0_$name");
    [$text, $cbs] = rmScreen($bot, "$lang relay-подписка");
    rmCheck(str_contains($text, 'relay.example.test · 443→8443') && str_contains($text, 'AnyTLS → <code>mod.example.test:10443</code>'), "$lang: что идёт через relay");
    rmCheck(substr_count($text, 'import://') === 10 && str_contains($text, 'import://Happ') && substr_count($text, '<pre><code>') === 5, "$lang: ссылки импорта и пять адресов подписки");
    rmCheck(!str_contains($text, 'http://') && !str_contains($text, '⚠️'), "$lang: с сертификатом только https и без предупреждения");
    $bot->cert = '';
    $bot->click("/relaySub 0_$name");
    [$text] = rmScreen($bot, "$lang relay-подписка без сертификата");
    rmCheck(str_contains($text, 'http://') && str_contains($text, $bot->subPlaintextWarning()), "$lang: без сертификата — предупреждение об открытом http");
    $bot->cert = 'letsencrypt';
    $bot->click('/relaySub 0_udp');
    [$text] = rmScreen($bot, "$lang relay без VLESS");
    rmCheck(str_contains($text, $lang === 'ru' ? 'напрямую на сервер' : 'directly to the server'), "$lang: VLESS без канала честно идёт напрямую");
    $bot->click('/relaySub 0_empty');
    rmCheck(str_contains($bot->screen[0], 'relay') && in_array('/relaySub 0_udp', $bot->callbacks(), true), "$lang: relay без каналов возвращает к списку");

    // ── 9. Базовая подписка: удалённый relay, истёкший пользователь ─────────
    $_GET = ['s' => 'tok0', 'relay' => $name];
    ob_start(); $bot->subVless(); $body = base64_decode(ob_get_clean());
    rmCheck(str_starts_with($body, 'vless://cred@relay.example.test:8443?'), "$lang: base64 через relay: адрес и порт relay");
    foreach ([['s' => 'tok0', 'relay' => 'gone'], ['s' => 'tok0', 'relay' => ''], ['s' => 'tok0', 'relay' => ['x']], ['s' => 'tok1']] as $query) {
        $_GET = $query;
        try { ob_start(); $bot->subVless(); ob_end_clean(); rmCheck(false, "$lang: 404 ожидался"); }
        catch (RelayMenuNotFound $e) { ob_end_clean(); rmCheck(true, ''); }
    }
    $bot->conf['relay_aggregate'] = 1;
    $_GET = ['s' => 'tok0'];
    ob_start(); $bot->subVless(); $lines = explode("\n", base64_decode(ob_get_clean()));
    rmCheck(count($lines) === 2 && str_contains($lines[1], '@relay.example.test:8443'), "$lang: «одной подпиской»: сервер и рабочий relay, мёртвый и пустой — нет");
    rmCheck(str_ends_with($lines[1], '#' . rawurlencode("Ann & <b> · $name")) && !str_contains($lines[0], $name), "$lang: узел relay назван по relay, узел сервера — нет");
    $bot->click('/switchRelayAggregate');
    rmCheck(empty($bot->conf['relay_aggregate']), "$lang: переключатель «одной подпиской»");

    // ── 10. Удаление ────────────────────────────────────────────────────────
    $bot->conf['relay'] = $name; $bot->conf['wg1_relay'] = 'udp';
    $bot->click("/relayDel $name");
    [$text, $cbs] = rmScreen($bot, "$lang подтверждение удаления");
    rmCheck(isset($bot->conf['relays'][$name]) && in_array("/relayDelOk $name", $cbs, true) && end($cbs) === "/relayEdit $name", "$lang: удаление спрашивает подтверждение");
    rmCheck(str_contains($text, 'WireGuard / AWG 1'), "$lang: подтверждение называет выбор в WireGuard");
    $sync = $bot->naiveSync;
    $bot->click("/relayDelOk $name");
    rmCheck(!isset($bot->conf['relays'][$name]) && !isset($bot->conf['relay']) && $bot->conf['wg1_relay'] === 'udp', "$lang: удалён relay и только его выбор в WireGuard");
    rmCheck($bot->naiveSync === $sync + 1, "$lang: маршрут SNI Naive пересобран");
    rmScreen($bot, "$lang список после удаления");
    $bot->click("/relayDelOk $name");
    rmCheck(!str_contains($bot->screen[0], '🗑'), "$lang: повторное подтверждение ничего не ломает");
    $_GET = [];
}

// ── 11. Строгая карта портов ────────────────────────────────────────────────
rmCheck(Bot::relayPortMapInput('443:8443') === ['443' => '8443'], 'карта: одна пара');
rmCheck(Bot::relayPortMapInput(' 443 : 8443 ,, 80:8080 ') === ['443' => '8443', '80' => '8080'], 'карта: пробелы и пустые сегменты');
rmCheck(Bot::relayPortMapInput('0443:08443') === ['443' => '8443'], 'карта: ведущие нули');
foreach (['', ',', '443', '443:', ':8443', '443:8443:1', '0:1', '1:65536', 'a:b', '443;8443'] as $bad) {
    rmCheck(Bot::relayPortMapInput($bad) === null, "карта: «{$bad}» отклоняется");
}

echo "relay_menu_test OK ($checks проверок)\n";
