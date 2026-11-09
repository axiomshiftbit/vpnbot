<?php
// Exercise the rendered menu and its callbacks, not just field metadata.
ob_start(); require __DIR__.'/managed_nodes_test.php'; ob_end_clean();

class VpnSourcesMenuFixture extends ManagedFixtureBot
{
    public array $prompt = [];
    public function __construct()
    {
        parent::__construct();
        $this->admin = true;
        $this->input += ['callback' => '', 'message' => ''];
        $this->pacState['managed_nodes']['aabbccdd']['job'] = null;
    }
    public function getWgMsg() { return null; }
    public function click(string $callback): void { $this->input['callback'] = $callback; $this->action(); }
    public function callbacks(): array { return array_column(array_merge(...end($this->screens)[1]), 'callback_data'); }
    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false)
    {
        return ['ok' => true, 'result' => ['message_id' => 6]];
    }
    public function stashReply($r, array $state) { $this->prompt = $state; }
}

$checks = 0;
$check = static function (bool $ok, string $name) use (&$checks): void { $checks++; if (!$ok) throw new RuntimeException('FAIL '.$name); };
$id = 'aabbccdd';
foreach (['ru', 'en'] as $lang) foreach (['reality', 'ws', 'grpc', 'xhttp', 'trojan-grpc'] as $transport) foreach (['empty', 'saved', 'draft'] as $state) {
    $bot = new VpnSourcesMenuFixture();
    $bot->language = $lang;
    $node = $bot->pacState['managed_nodes'][$id];
    $node['status']['options']['transport'] = $transport;
    if ($state !== 'empty') $node['status']['options']['vpn_sources'] = ['11.77.0.200'];
    if ($state === 'draft') $node['draft'] = ['vpn_sources' => ['11.77.0.201']] + $node['status']['options'];
    $bot->pacState['managed_nodes'][$id] = $node;
    $before = $bot->pacState;
    // The list moved from IPv4 / IPv6 settings to the node card.
    $bot->click("/nodeSettings $id network");
    $callbacks = $bot->callbacks();
    $check(!in_array("/nodeField $id vpn_sources", $callbacks, true), "not in network settings $lang/$transport/$state");
    foreach (['44', '46', '64', '66'] as $pair) $check(count(array_keys($callbacks, "/nodeNetwork $id $pair", true)) === 1, 'family pair remains available');
    $check(!in_array("/nodeField $id family", $callbacks, true) && !in_array("/nodeField $id connect_family", $callbacks, true), 'no duplicate family controls');
    $bot->click("/nodeSettings $id");
    $check(!in_array("/nodeSettings $id vpn", $bot->callbacks(), true), 'no settings group for the list');
    $bot->click("/node $id");
    $callbacks = $bot->callbacks();
    $check(count(array_keys($callbacks, "/nodeVpn $id", true)) === 1, "card button $lang/$transport/$state");
    $buttons = array_merge(...end($bot->screens)[1]);
    $vpnButton = $buttons[array_search("/nodeVpn $id", $callbacks, true)];
    $check($vpnButton['text'] === ($lang === 'ru' ? '🛡 Серверы для VPN (без SSH)' : '🛡 VPN servers (no SSH)'), 'localized label');
    $bot->click($vpnButton['callback_data']);
    $screen = end($bot->screens)[0];
    $check(in_array("/nodeEdit $id vpn_sources", $bot->callbacks(), true), 'list editor accessible');
    $check(in_array("/node $id", $bot->callbacks(), true), 'back returns to the node card');
    $check(in_array("/menuHelp nodeconfig {$id}_vpn", $bot->callbacks(), true) || count(array_filter($bot->callbacks(), static fn($c) => str_contains((string) $c, "{$id}_vpn"))) === 1, 'help button');
    $check(str_contains($screen, $lang === 'ru' ? 'SSH им закрыт' : 'SSH stays closed'), 'explains SSH stays closed');
    if ($state !== 'empty') $check(str_contains($screen, '11.77.0.200'), 'applied list shown');
    if ($state === 'draft') $check(str_contains($screen, '11.77.0.201') && in_array("/nodeApply $id", $bot->callbacks(), true)
        && in_array("/nodeDiscard $id vpn", $bot->callbacks(), true), 'draft list with Apply and Discard');
    $bot->click("/nodeField $id vpn_sources");
    $check(end($bot->screens)[0] === $screen, 'old field callback opens the new screen');
    $bot->click("/nodeEdit $id vpn_sources");
    $check($bot->prompt['callback'] === 'saveManagedNodeField' && $bot->prompt['args'] === [$id, 'vpn_sources'], 'prompt targets VPN-only list');
    $check($bot->pacState === $before && $bot->events === [], 'navigation does not write settings or contact node');
    $bot->{$bot->prompt['callback']}('11.77.0.202 2606:4700:4700:0::1001 11.77.0.202', ...$bot->prompt['args']);
    $node = $bot->pacState['managed_nodes'][$id];
    $expected = ['11.77.0.202', '2606:4700:4700::1001'];
    $check($node['draft']['vpn_sources'] === $expected, 'input canonicalized in draft');
    $oldOptions = $before['managed_nodes'][$id]['draft'] ?? $node['status']['options'];
    $oldOptions['vpn_sources'] = $expected;
    $check($node['draft'] === $oldOptions, 'other draft options preserved');
    $check($node['status'] === $before['managed_nodes'][$id]['status'] && $bot->events === [], 'saved settings untouched before Apply');
    $check(in_array("/nodeApply $id", $bot->callbacks(), true) && in_array("/nodeDiscard $id vpn", $bot->callbacks(), true), 'Apply and Discard on the VPN screen');
    $check(str_contains(end($bot->screens)[0], '2606:4700:4700::1001'), 'draft list shown after input');
    $bot->click("/nodeNetwork $id 46");
    $node = $bot->pacState['managed_nodes'][$id];
    $check($node['draft']['vpn_sources'] === $expected && $node['draft']['connect_family'] === 4 && $node['draft']['family'] === 6, 'family switch preserves VPN-only list');
    $beforeInvalid = $node['draft'];
    foreach (['10.0.0.1', 'fe80::1', '11.77.0.0/24', 'bad-address', implode(' ', array_map(static fn($i) => "11.77.0.$i", range(1, 33)))] as $bad) {
        $bot->saveManagedNodeField($bad, $id, 'vpn_sources');
        $node = $bot->pacState['managed_nodes'][$id];
        $check($node['draft'] === $beforeInvalid && $bot->events === [], 'invalid input preserves draft');
    }
    $bot->saveManagedNodeField('-', $id, 'vpn_sources');
    $node = $bot->pacState['managed_nodes'][$id];
    $check($node['draft']['vpn_sources'] === [] && $node['draft']['family'] === 6 && $bot->events === [], 'clear changes only draft list');
    $bot->click("/nodeDiscard $id vpn");
    $node = $bot->pacState['managed_nodes'][$id];
    $check(!isset($node['draft']) && in_array("/nodeEdit $id vpn_sources", $bot->callbacks(), true) && $bot->events === [], 'discard returns to the VPN screen');
}
echo "PASS $checks managed node VPN-only menu checks\n";
