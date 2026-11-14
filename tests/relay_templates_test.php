<?php
require_once __DIR__ . '/../app/bot.php';
require_once __DIR__ . '/../app/i18n.php';

set_error_handler(static function ($level, $message, $file, $line) {
    if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line);
    return false;
});
$checks = 0;
function rtCheck(bool $ok, string $label): void {
    global $checks;
    if (!$ok) throw new RuntimeException($label);
    $checks++;
}

class RelayTemplatesBot extends Bot {
    public array $answers = [];
    public int $queries = 0;
    public array $xr = [];
    public array $tpl = [];
    public function __construct(string $root) {
        $this->pac = "$root/pac.json";
        $this->xrayConf = "$root/xray.json";
        $this->protocolRoot = "$root/protocols";
        $this->protocolModulesFile = "$root/modules.json";
        $this->ip = '192.0.2.1'; $this->language = 'ru';
        $this->i18n = $GLOBALS['i'];
    }
    protected function resolveRelayIpv4(string $host): array|false { $this->queries++; return $this->answers[$host] ?? false; }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') { throw new RuntimeException('Unexpected SSH'); }
    public function getXray() { return $this->xr; }
    public function getXrayStats() { return []; }
    public function getHashBot($notset = false) { return 'fixture'; }
    public function subDomain(array $pac): string { return 'vpn.example.test'; }
    public function nginxGetTypeCert() { return 'letsencrypt'; }
    public function flagName(string $name, string|array $hosts, bool $cacheOnly = true): string { return $name; }
    public function subscriptionCompatibilityError(array $xr, array $pac, string $type): string { return ''; }
    public function smuxActive(?array $p = null): bool { return false; }
    public function subTemplate(string $template, string $type, array $pac) { return $this->tpl; }
    public array $updated = [];
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML') { $this->updated[] = [$text, $button]; return ['ok' => true]; }
    public function getDomain($cdn = false) { return 'vpn.example.test'; }
}

$root = sys_get_temp_dir() . '/vpnbot-relay-tpl-' . bin2hex(random_bytes(6));
mkdir($root, 0700);
try {
    $bot = new RelayTemplatesBot($root);
    $bot->ensureDefaultTemplates();
    $pac = $bot->getPacConf();
    rtCheck(count($pac['singtemplates']) === 3 && count($pac['clashtemplates']) === 1, 'Чистая установка получает четыре шаблона');
    rtCheck(empty($pac['defaultsingtemplate']) && empty($pac['defaultclashtemplate']), 'Установка не меняет активный шаблон');
    $pac['singtemplates']['15_direct'] = ['custom' => true];
    unset($pac['singtemplates']['15_relay']);
    $pac['defaultsingtemplate'] = base64_encode('15_direct');
    $bot->setPacConf($pac);
    (new RelayTemplatesBot($root))->ensureDefaultTemplates();
    rtCheck($bot->getPacConf() === $pac, 'Перезапуск сохраняет правки, удаление и выбор');
    unset($pac['installed_templates']);
    $bot->setPacConf($pac);
    (new RelayTemplatesBot($root))->ensureDefaultTemplates();
    rtCheck($bot->getPacConf()['singtemplates']['15_direct'] === ['custom' => true], 'Обновление сохраняет одноимённый пользовательский шаблон');

    $pac = $bot->getPacConf();
    $pac['relays'] = [
        'one' => ['address' => 'RELAY.example.test:443', 'awg_address' => '192.0.2.10', 'np_address' => 'relay.example.test'],
        'two' => ['hy_address' => '[2001:db8::1]:443', 'anytls_address' => 'other.example.test', 'name' => 'ignored.example.test'],
    ];
    $bot->setPacConf($pac);
    $bot->answers = ['relay.example.test' => ['192.0.2.11', '192.0.2.12', '192.0.2.11']];
    $bot->resolveRelayHosts();
    rtCheck($bot->queries === 2, 'Домены всех каналов разрешаются по одному разу');
    $bot->resolveRelayHosts();
    rtCheck($bot->queries === 2, 'TTL ограничивает обращения DNS');
    rtCheck((fileperms("$root/relay.dns.json") & 0777) === 0600, 'Кеш адресов закрыт правами 0600');
    $data = $bot->relayTemplateData($pac);
    rtCheck($data['domains'] === ['relay.example.test', 'other.example.test'], 'Только адресные поля каналов, без дублей');
    rtCheck($data['hosts']['relay.example.test'] === ['192.0.2.11', '192.0.2.12'], 'Все IPv4 домена');
    $idn = $bot->relayTemplateData(['relays' => ['idn' => ['address' => 'relay.xn--p1ai']]]);
    rtCheck($idn['domains'] === ['relay.xn--p1ai'], 'Допустимый в меню IDN в форме Punycode попадает в шаблон');
    rtCheck(in_array('2001:db8::1/128', $data['ips'], true) && in_array('192.0.2.10/32', $data['ips'], true), 'IPv4 и IPv6 CIDR');
    $bot->time_relaydns = 0; $bot->answers = []; $bot->resolveRelayHosts();
    rtCheck($bot->relayTemplateData($pac) === $data, 'Сбой DNS сохраняет последний ответ');
    $pac['relays'] = []; $bot->setPacConf($pac);
    rtCheck($bot->relayTemplateData($pac) === ['hosts' => [], 'ips' => [], 'domains' => []], 'Удаление relay действует даже до обновления кеша');
    $bot->time_relaydns = 0; $bot->resolveRelayHosts();
    rtCheck(json_decode(file_get_contents("$root/relay.dns.json"), true) === [], 'Кеш удалённых relay очищается');
    foreach (['{broken', 'null', '42', '"bad"'] as $broken) {
        file_put_contents("$root/relay.dns.json", $broken);
        rtCheck($bot->relayTemplateData($pac)['ips'] === [], 'Повреждённый кеш не роняет подписку');
    }

    $template = ['dns' => ['hosts' => ['~relay_hosts~' => '', 'relay.example.test' => ['192.0.2.99']]],
        'routing' => ['rules' => [['type' => 'field', 'ip' => ['~relay_ips~'], 'outboundTag' => 'proxy'],
            ['type' => 'field', 'domain' => ['fixed.example.test', '~relay_domains~'], 'outboundTag' => 'proxy']]],
        'rules' => ['IP-CIDR,~relay_ips~,PROXY,no-resolve', 'DOMAIN,~relay_domains~,PROXY', 'MATCH,DIRECT']];
    $expanded = Bot::expandRelayPlaceholders($template, $data);
    rtCheck($expanded['dns']['hosts']['relay.example.test'] === ['192.0.2.99'], 'Явная запись hosts приоритетнее автоматической');
    rtCheck(in_array('IP-CIDR6,2001:db8::1/128,PROXY,no-resolve', $expanded['rules'], true), 'Mihomo использует IP-CIDR6');
    rtCheck(!str_contains(json_encode($expanded), '~relay_'), 'Плейсхолдеры раскрыты в ключах и значениях');
    $empty = Bot::expandRelayPlaceholders($template, ['hosts' => [], 'ips' => [], 'domains' => []]);
    rtCheck(count($empty['routing']['rules']) === 1 && $empty['routing']['rules'][0]['domain'] === ['fixed.example.test'], 'Пустое условие удаляет правило, смешанное сохраняется');
    rtCheck($empty['rules'] === ['MATCH,DIRECT'], 'Пустые строковые правила удаляются');

    $pac = array_fill_keys(['includelist', 'blocklist', 'warplist', 'processlist', 'packagelist', 'subnetlist', 'rulessetlist'], [])
        + ['domain' => 'vpn.example.test', 'outbound' => 'proxy', 'transport' => 'Websocket', 'xray' => 'fixture'];
    $client = ['id' => Bot::xrayUuid(), 'subtoken' => bin2hex(random_bytes(16)), 'email' => 'fixture'];
    $bot->xr = ['inbounds' => [['settings' => ['clients' => [$client]], 'streamSettings' => ['network' => 'ws']]]];
    foreach ([[], ['relay' => ['address' => '192.0.2.10', 'np_address' => 'relay.example.test']]] as $relays) {
        $pac['relays'] = $relays; $bot->setPacConf($pac);
        foreach (glob(__DIR__ . '/../config/templates/*/*.json') as $file) {
            $bot->tpl = json_decode(file_get_contents($file), true, 512, JSON_THROW_ON_ERROR);
            $format = basename(dirname($file)) === 'sing' ? 'si' : 'clj';
            $_GET = ['s' => $client['subtoken'], 't' => $format];
            $result = $bot->subscription(true);
            if ($output = getenv('VPNBOT_TEST_OUTPUT')) {
                if (!is_dir($output)) mkdir($output, 0700, true);
                file_put_contents($output . '/' . (empty($relays) ? 'empty-' : 'relay-') . basename($file), $result);
            }
            $conf = json_decode($result, true, 512, JSON_THROW_ON_ERROR);
            rtCheck(is_array($conf) && !str_contains($result, '~relay_'), basename($file) . ': полная выдача без SSH и нераскрытых relay');
            foreach ($conf['route']['rules'] ?? [] as $rule) {
                rtCheck($rule !== ['outbound' => 'proxy'], 'Нет безусловного proxy из пустого списка relay');
            }
            if (basename($file) === '15_relay.json') {
                $cidrs = array_merge(...array_map(static fn($r) => $r['ip_cidr'] ?? [], $conf['route']['rules']));
                rtCheck(in_array('192.0.2.1/32', $cidrs, true), '15_relay: IP своего сервера идёт через outbound');
                $hosts = array_values(array_filter($conf['dns']['servers'], static fn($x) => ($x['type'] ?? '') === 'hosts'))[0]['predefined'];
                rtCheck(empty($relays) ? !in_array('192.0.2.10/32', $cidrs, true) : in_array('192.0.2.10/32', $cidrs, true), '15_relay: адреса relay из раздела Relay');
                rtCheck(isset($hosts['vpn.example.test']) && !array_filter(array_keys($hosts), static fn($k) => str_contains($k, '~')), '15_relay: hosts без плейсхолдеров');
            }
        }
        $bot->tpl = json_decode(file_get_contents(__DIR__ . '/../config/v2ray.json'), true);
        $bot->tpl['routing']['rules'][] = ['type' => 'field', 'ip' => ['~relay_ips~'], 'outboundTag' => '~outbound~'];
        $_GET = ['s' => $client['subtoken'], 't' => 's'];
        $result = $bot->subscription(true);
        if ($output = getenv('VPNBOT_TEST_OUTPUT')) file_put_contents($output . '/' . (empty($relays) ? 'empty-' : 'relay-') . 'xray.json', $result);
        rtCheck(is_array(json_decode($result, true)) && !str_contains($result, '~relay_'), 'Xray origin и relay-подстановка');
    }
    // ♻️ — вернуть штатный шаблон вместо старой копии с вписанными адресами.
    rtCheck(Bot::bundledTemplate('sing', '15_relay') === json_decode(file_get_contents(__DIR__ . '/../config/templates/sing/15_relay.json'), true), 'Штатный шаблон читается');
    foreach ([['sing', '../pac'], ['sing', 'missing'], ['other', '15_relay'], ['sing', '']] as [$type, $name]) rtCheck(Bot::bundledTemplate($type, $name) === null, "Нет штатного: $type/$name");
    $pac = $bot->getPacConf();
    $old = Bot::bundledTemplate('sing', '15_relay');
    $old['dns']['servers'][3]['predefined'] = ['~domain~' => '~ip~', 'relay.example.test' => '192.0.2.10'];
    $pac['singtemplates'] = ['15_relay' => $old, 'mine' => ['custom' => true]];
    $bot->setPacConf($pac);
    $bot->input = ['chat' => 1, 'message_id' => 2, 'callback_id' => 3];
    $bot->templates('sing');
    $rows = end($bot->updated)[1];
    $resets = array_merge(...array_map(static fn($row) => array_values(array_filter(array_column($row, 'callback_data'), static fn($c) => str_starts_with((string) $c, '/resetTemplate'))), $rows));
    rtCheck($resets === ['/resetTemplate sing ' . base64_encode('15_relay')], 'Кнопка ♻️ только у изменённой копии штатного шаблона');
    $route = '~^/resetTemplate (sing|clash) ([A-Za-z0-9+/=]{1,40})( yes)?$~D';
    rtCheck(str_contains(file_get_contents(__DIR__ . '/../app/bot.php'), "preg_match('$route'") && preg_match($route, $resets[0] . ' yes') === 1, 'Маршрут кнопки');
    $bot->resetTemplate('sing', base64_encode('15_relay'));
    [$text, $buttons] = end($bot->updated);
    rtCheck($bot->getPacConf()['singtemplates']['15_relay'] === $old && str_contains($text, '⚠') && $buttons[0][0]['callback_data'] === $resets[0] . ' yes', 'Сначала подтверждение, шаблон не тронут');
    $bot->resetTemplate('sing', base64_encode('15_relay'), true);
    $after = $bot->getPacConf();
    rtCheck($after['singtemplates']['15_relay'] === Bot::bundledTemplate('sing', '15_relay') && $after['singtemplates']['mine'] === ['custom' => true], 'Заменён только этот шаблон');
    rtCheck(!str_contains(json_encode($after['singtemplates']['15_relay']), 'relay.example.test'), 'Вписанные адреса ушли');
    $bot->templates('sing');
    rtCheck(!str_contains(json_encode(end($bot->updated)[1]), '/resetTemplate'), 'После замены кнопки нет');
    $bot->resetTemplate('sing', base64_encode('mine'), true);
    rtCheck($bot->getPacConf()['singtemplates']['mine'] === ['custom' => true], 'Свой шаблон без штатного не заменяется');

    file_put_contents("$root/pac.json", '{broken');
    try { (new RelayTemplatesBot($root))->ensureDefaultTemplates(); rtCheck(false, 'Повреждённый pac должен отклоняться'); }
    catch (RuntimeException $e) { rtCheck(file_get_contents("$root/pac.json") === '{broken', 'Повреждённый конфиг не затирается'); }
} finally {
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($it as $file) $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
    rmdir($root);
    restore_error_handler();
}
echo "relay_templates_test OK ($checks)\n";
