<?php

// Узлы выхода: подписка узла (ссылка обновляется сама), диагностика проверки,
// защита от петли и служебная учётка «Профиль для узла» в карточке пользователя.
//  1. подписка: только https, ссылка из неё проходит строгий разбор и проверку
//     адреса; ошибка оставляет прежнюю ссылку; cron обновляет по расписанию и
//     после отказа проверки и пишет администраторам; 0 отключает;
//  2. проверка: при отказе узла команда не делает лишних загрузок, а проверяет
//     TCP до адреса; ответ tcp=0/1 превращается в понятную причину;
//  3. петля: узел на домен, алиас, домен для ссылок, IPv4 или IPv6 этого
//     сервера не принимается;
//  4. служебная учётка: в карточке — «Профиль для узла», экран «Узлы выхода»
//     ведёт в профиль; подписка профиля — в карточке профиля, лимит HWID её
//     не касается; имя профиля не получает двойной «node-».

require_once __DIR__ . '/../app/bot.php';

set_error_handler(static function ($level, $message, $file, $line) {
    if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line);
    return false;
});

$checks = 0;
function esCheck(bool $ok, string $label): void
{
    global $checks;
    if (!$ok) throw new RuntimeException($label);
    $checks++;
}

class ExitSubBot extends Bot
{
    public array $confPac = ['transport' => 'Reality', 'domain' => 'vpn.example.org', 'domain_aliases' => ['alias.example.org'],
        'linkdomain' => 'cdn.example.org', 'xray_core' => 'origin'];
    public array $confXray = [];
    public array $screens = [];
    public array $ssh = [];
    public array $notified = [];
    public array $subBody = [];
    public array $resolved = ['node.example.net' => ['203.0.113.7'], 'new.example.net' => ['203.0.113.8'],
        'back.example.net' => ['198.51.100.1'], 'v6.example.net' => ['2001:db8:ffff::1']];
    public string $probeAnswer = "probe=204 0.1\nip=203.0.113.7\nloc=FI\n";
    public array $statusMap = [];
    public array $ipv6Net = [];
    public function __construct(array $strings)
    {
        $this->i18n = $strings; $this->language = 'ru'; Lang::$en = false;
        $this->ip = '198.51.100.1'; $this->key = 'fixture'; $this->admin = true;
        $this->input = ['chat' => 1, 'from' => 1, 'message_id' => 5, 'callback_id' => 'cb', 'username' => 'admin', 'callback' => '', 'message' => ''];
        $this->confXray = ['inbounds' => [['tag' => 'vless_reality', 'protocol' => 'vless', 'sniffing' => ['enabled' => true],
            'settings' => ['decryption' => 'none', 'clients' => [
                ['id' => '11111111-1111-4111-8111-111111111111', 'email' => 'alice', 'flow' => 'xtls-rprx-vision'],
                ['id' => '22222222-2222-4222-8222-222222222222', 'email' => 'node-main', 'flow' => 'xtls-rprx-vision', 'exit_relay' => 1, 'subtoken' => str_repeat('a', 32)],
            ]]]], 'outbounds' => [['tag' => 'direct', 'protocol' => 'freedom'], ['tag' => 'block', 'protocol' => 'blackhole']], 'routing' => ['rules' => []]];
    }
    public function getPacConf() { return $this->confPac; }
    public function setPacConf(array $conf) { $this->confPac = $conf; return true; }
    public function getXray() { return $this->confXray; }
    public function restartXray($c, $norestart = false) { $this->ensureExitNodes($c, $this->confPac); $this->confXray = $c; return true; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
    protected function xdriveResolve(string $host): array { return $this->resolved[$host] ?? []; }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') { $this->ssh[] = [$service, $cmd]; $this->sshFailed = false; return $this->probeAnswer; }
    public function doFetchExtSub(string $url): array|string { return $this->subBody[$url] ?? 'http 404'; }
    public function exitStatus(): array { return $this->statusMap; }
    protected function exitStatusWrite(string $id, array $status): void { $this->statusMap[$id] = $status; }
    protected function exitIpv6Network(): array { return $this->ipv6Net; }
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML') { $this->screens[] = [$text, is_array($button) ? $button : []]; }
    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false) { return ['result' => ['message_id' => 9]]; }
    public function answer($callback_id, $textNotify = false, $notify = false) {}
    public function stashReply($r, array $state) {}
    public function notifyAdmins(string $text): void { $this->notified[] = $text; }
    public function nginxGetTypeCert() { return 'letsencrypt'; }
    public function getXrayStats() { return []; }
    public function setXrayStats($x) { return true; }
    public function linkXray($i, $s = false) { return 'vless://' . $this->confXray['inbounds'][0]['settings']['clients'][$i]['id'] . '@vpn.example.org:443?security=reality&sni=www.example.com&pbk=' . str_repeat('A', 43) . '&sid=ab&type=tcp#x'; }
    public function adguardXrayClients() {}
    public function last(): array { return end($this->screens) ?: ['', []]; }
    public function callbacks(): array { $all = []; foreach ($this->last()[1] as $row) foreach ($row as $b) $all[$b['callback_data'] ?? ''] = $b['text']; return $all; }
}

require __DIR__ . '/../app/i18n.php';
$link = static fn(string $host, string $uuid = '33333333-3333-4333-8333-333333333333') => "vless://$uuid@$host:443?security=reality&sni=www.example.com&fp=chrome&pbk=" . str_repeat('B', 43) . '&sid=ab&type=tcp&flow=xtls-rprx-vision#FI';

// ── 3. Петля ─────────────────────────────────────────────────────────────────
$bot = new ExitSubBot($i);
foreach (['vpn.example.org', 'www.vpn.example.org', 'alias.example.org', 'cdn.example.org', 'back.example.net', '198.51.100.1'] as $own) {
    esCheck($bot->exitAddressProblem($own) !== '', "свой адрес отклоняется: $own");
}
$bot->ipv6Net = ['enabled' => true, 'public' => '2001:db8:ffff::1'];
esCheck($bot->exitAddressProblem('v6.example.net') !== '' && $bot->exitAddressProblem('2001:db8:ffff:0::1') !== '', 'свой IPv6 (и в другой записи) отклоняется');
$bot->ipv6Net = [];
esCheck($bot->exitAddressProblem('node.example.net') === '', 'чужой узел принимается');

// ── 1. Подписка узла ────────────────────────────────────────────────────────
$bot->saveExitAdd($link('node.example.net'));
$id = array_key_first($bot->confPac['exits']);
$bot->exitNodeMenu($id);
esCheck(isset($bot->callbacks()["/exitSub $id"]) && str_contains($bot->last()[0], 'Подписка узла: нет'), 'карточка: кнопка и строка подписки');
$bot->saveExitSub('http://node.example.net/sub', $id);
esCheck($bot->exitNodes()[$id]['sub'] === '' && str_contains($bot->last()[0], 'не сохранена'), 'подписка только по https');
$sub = 'https://node.example.net/pacabc/token';
$bot->subBody[$sub] = ['trojan://short@x.example.net:443?security=tls#bad', $link('vpn.example.org'), $link('new.example.net', '44444444-4444-4444-8444-444444444444')];
$bot->saveExitSub($sub, $id);
$node = $bot->exitNodes()[$id];
esCheck($node['sub'] === $sub && $node['link'] === $link('new.example.net', '44444444-4444-4444-8444-444444444444') && $node['sub_error'] === '',
    'из подписки берётся первая ссылка, прошедшая разбор и проверку адреса (неверная и петля пропущены)');
esCheck(str_contains($bot->last()[0], 'ссылка узла обновлена'), 'админ видит, что ссылка обновлена');
$rule = array_values(array_filter($bot->confXray['outbounds'], static fn($o) => ($o['tag'] ?? '') === Bot::EXIT_TAG . $id))[0] ?? [];
esCheck(($rule['settings']['vnext'][0]['address'] ?? '') === 'new.example.net', 'в конфиге Xray новый адрес узла');

// Подписка без подходящей ссылки — прежняя ссылка остаётся, ошибка видна.
$bot->subBody[$sub] = [$link('vpn.example.org')];
esCheck($bot->exitSubRefresh($id) === false && $bot->exitNodes()[$id]['link'] === $link('new.example.net', '44444444-4444-4444-8444-444444444444')
    && $bot->exitNodes()[$id]['sub_error'] !== '', 'плохая подписка не трогает рабочую ссылку');
$bot->exitNodeMenu($id);
esCheck(str_contains($bot->last()[0], '⚠️'), 'ошибка подписки в карточке');

// Cron: узел не ответил → подписка проверяется сразу, новая ссылка применяется и проверяется.
$bot->subBody[$sub] = [$link('node.example.net')];
$bot->probeAnswer = "probe=000 0\ntcp=1\n";
$bot->statusMap = [$id => ['ok' => true, 'time' => time() - 600, 'full_time' => time()]];
$bot->confPac['exits'][$id]['sub_time'] = time();
$bot->checkExitNodes();
esCheck($bot->exitNodes()[$id]['link'] === $link('node.example.net') && (bool) preg_grep('~обновлена по его подписке~u', $bot->notified), 'после отказа cron берёт ссылку из подписки и пишет админам');
// По расписанию: узел работает, но подписка давно не проверялась.
(new ReflectionProperty(Bot::class, 'exitCronAt'))->setValue($bot, 0);
$bot->probeAnswer = "probe=204 0.1\nip=203.0.113.7\nloc=FI\n";
$bot->subBody[$sub] = [$link('new.example.net', '55555555-5555-4555-8555-555555555555')];
$bot->confPac['exits'][$id]['sub_time'] = time() - Bot::EXIT_SUB_PERIOD - 1;
$bot->checkExitNodes();
esCheck(str_contains($bot->exitNodes()[$id]['link'], '55555555-5555'), 'раз в 6 часов ссылка сверяется с подпиской');
(new ReflectionProperty(Bot::class, 'exitCronAt'))->setValue($bot, 0);
$before = count($bot->notified);
$bot->checkExitNodes();
esCheck(count($bot->notified) === $before, 'без изменений — без уведомлений и лишних проверок подписки');
$bot->saveExitSub('0', $id);
esCheck($bot->exitNodes()[$id]['sub'] === '', '0 отключает подписку');

// ── 2. Проверка узла ────────────────────────────────────────────────────────
$bot->ssh = [];
$bot->probeAnswer = "probe=000 0\ntcp=0\n";
$s = $bot->exitProbe($id, true);
$cmd = end($bot->ssh)[1];
esCheck($s['error'] === 'tcp' && $s['tcp'] === 0 && str_contains($bot->exitErrorText('tcp'), 'TCP'), 'TCP до узла закрыт — понятная причина');
esCheck(str_contains($cmd, "nc -z -w 4 'new.example.net' 443") && str_contains($cmd, 'case "$r" in probe=204*)'), 'команда: TCP-проверка только при отказе');
$tmp = tempnam(sys_get_temp_dir(), 'probe');
file_put_contents($tmp, $cmd);
exec('sh -n ' . escapeshellarg($tmp) . ' 2>&1', $out, $code);
unlink($tmp);
esCheck($code === 0, 'команда проверки — корректный shell: ' . implode(' ', $out));
$bot->probeAnswer = "probe=000 0\ntcp=1\n";
$s = $bot->exitProbe($id, false);
$bot->statusMap[$id] = $s;
esCheck($s['error'] === 'no answer' && str_contains($bot->exitStatusLine($id, $bot->exitNodes()[$id]), 'TCP до узла есть'), 'TCP есть, прокси молчит — подсказка про ссылку и my_server');
esCheck(!str_contains($cmd, '33333333') && !str_contains($cmd, str_repeat('B', 43)), 'в команде нет учётных данных узла');

// ── 4. Служебная учётка ─────────────────────────────────────────────────────
$bot->exitUserMenu(1);
esCheck(isset($bot->callbacks()['/exitRelayLink 1']) && !preg_grep('~^/exitUT ~', array_keys($bot->callbacks())) && str_contains($bot->last()[0], 'Профиль для узла'), 'экран узлов у служебной учётки ведёт в профиль');
$bot->exitRelayLink(1);
esCheck(str_contains($bot->last()[0], 'Подписка для автообновления') && str_contains($bot->last()[0], 'https://vpn.example.org/pac'), 'профиль показывает адрес подписки');
$tok = [];
preg_match('~/pac[0-9a-f]+/([A-Za-z0-9+/=]+)</code>~', $bot->last()[0], $tok);
$token = unserialize(base64_decode($tok[1] ?? ''), ['allowed_classes' => false]);
esCheck(($token['t'] ?? '') === 'vl' && ($token['s'] ?? '') === str_repeat('a', 32), 'подписка профиля — base64 (vl) по его токену');
$bot->confPac['hwid_limit_enabled'] = 1; $bot->confPac['hwid_device_count'] = 1;
unset($_SERVER['HTTP_X_HWID']);
esCheck($bot->processHwidRequest($bot->confXray['inbounds'][0]['settings']['clients'][1]) === true, 'лимит HWID не закрывает подписку служебного профиля');
foreach (['node-fr', 'NODE-fr'] as $typed) {
    $bot->saveExitRelay($typed);
}
$emails = array_column($bot->confXray['inbounds'][0]['settings']['clients'], 'email');
esCheck(in_array('node-fr', $emails, true) && !preg_grep('~^node-node-~i', $emails), 'имя профиля без двойного «node-»');

$stale = new class($i) extends ExitSubBot {
    public function doFetchExtSub(string $url): array|string {
        $result = parent::doFetchExtSub($url);
        // Администратор сменил подписку, пока прежняя скачивалась.
        $this->confPac['exits']['abcdefab']['sub'] = 'https://replacement.example.net/sub';
        return $result;
    }
};
$stale->confPac['exits']['abcdefab'] = ['link' => $link('node.example.net'), 'sub' => $sub];
$stale->subBody[$sub] = [$link('new.example.net')];
esCheck(!$stale->exitSubRefresh('abcdefab')
    && $stale->exitNodes()['abcdefab']['link'] === $link('node.example.net'),
    'ответ прежней подписки не заменяет ссылку после одновременного изменения настроек');

echo "exit_nodes_sub_test OK ($checks проверок)\n";
