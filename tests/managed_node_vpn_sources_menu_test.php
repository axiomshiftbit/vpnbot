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
    $bot->click("/nodeSettings $id network");
    $callbacks = $bot->callbacks();
    $check(count(array_keys($callbacks, "/nodeField $id vpn_sources", true)) === 1, "VPN-only button $lang/$transport/$state");
    $buttons = array_merge(...end($bot->screens)[1]);
    $vpnButton = $buttons[array_search("/nodeField $id vpn_sources", $callbacks, true)];
    $check(str_starts_with($vpnButton['text'], $lang === 'ru' ? 'Серверы для VPN (без SSH)' : 'VPN servers (no SSH)'), 'localized label');
    foreach (['44', '46', '64', '66'] as $pair) $check(count(array_keys($callbacks, "/nodeNetwork $id $pair", true)) === 1, 'family pair remains available');
    $check(!in_array("/nodeField $id family", $callbacks, true) && !in_array("/nodeField $id connect_family", $callbacks, true), 'no duplicate family controls');
    $bot->click($vpnButton['callback_data']);
    $check(in_array("/nodeEdit $id vpn_sources", $bot->callbacks(), true), 'list editor accessible');
    $check(in_array("/nodeSettings $id network", $bot->callbacks(), true), 'back returns to network');
    $expectedAddress = $state === 'draft' ? '11.77.0.201' : '11.77.0.200';
    if ($state !== 'empty') $check(str_contains(end($bot->screens)[0], $expectedAddress), 'editor shows current draft or saved list');
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
    $check(in_array("/nodeApply $id", $bot->callbacks(), true), 'Apply available');
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
}
echo "PASS $checks managed node VPN-only menu checks\n";
