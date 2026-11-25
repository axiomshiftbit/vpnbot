<?php
// The node WARP screen: status, masked configuration, mode, official ports, MASQUE transport,
// a WARP+ key and a new account. Every change is a normal node job.
require __DIR__ . '/managed_nodes_test.php';

class WarpScreenBot extends ManagedFixtureBot
{
    public array $submitted = []; public array $info = []; public array $trace = []; public array $prompts = [];
    protected function managedNodeRpc(string $id, array $request): array {
        if ($request['action'] === 'warp_info') { $this->events[] = 'warp_info'; return $this->info; }
        if ($request['action'] === 'submit') $this->submitted[] = $request['request'];
        return parent::managedNodeRpc($id, $request);
    }
    protected function managedNodeWarpTrace(string $id): array { return $this->trace; }
    protected function nodeRoutesProbeAddresses(string $host): array { return ['198.51.100.200']; }
    public function request($method, $data, $json_header = 0) { $this->prompts[] = $data; return ['ok' => true, 'result' => ['message_id' => 7]]; }
    public function stashReply($r, array $state) { $this->prompts[] = $state; }
}
$id = 'aabbccdd';
$check = static function ($ok, $text) { if (!$ok) throw new RuntimeException('FAIL ' . $text); };
$fresh = static function () use ($id): WarpScreenBot {
    $bot = new WarpScreenBot();
    $node = &$bot->pacState['managed_nodes'][$id];
    $node['job'] = null;
    $node['status'] += ['warp_egress' => true, 'warp_account' => true, 'shared_routes' => true];
    $node['status']['pending'] = null;
    $node['status']['options'] = ['transport' => 'reality', 'core' => 'origin', 'family' => 4, 'connect_family' => 4, 'cover' => false,
        'domain' => '', 'mask' => 'mask.example.test', 'warp_mode' => 'wireguard'];
    unset($node);
    $bot->remoteStatus['pending'] = null;
    $bot->info = ['mode' => 'wireguard', 'account' => 'legacy', 'port' => null, 'default_port' => 2408,
        'account_fields' => [['device_id', 'device-1'], ['license_key', '…CCCC'], ['private_key', '…9999']],
        'profile' => [['PrivateKey', '…5678'], ['Address', '172.16.0.2/32'], ['Endpoint', 'engage.cloudflareclient.com:2408']]];
    $bot->trace = ['warp' => 'plus', 'ip' => '203.0.113.9', 'colo' => 'FRA', 'loc' => 'FI'];
    return $bot;
};
$cb = static fn(WarpScreenBot $b) => array_column(array_merge(...end($b->screens)[1]), 'callback_data');

$bot = $fresh();
$bot->managedNodeMenu($id);
$check(in_array("/nodeWarp $id", $cb($bot), true), 'card opens the WARP screen');
$bot->managedNodeWarp($id);
[$text] = end($bot->screens);
$check(str_contains($text, 'WARP+') && str_contains($text, '203.0.113.9') && str_contains($text, 'FRA'), 'status from the trace');
$check(str_contains($text, '2408') && str_contains($text, 'license_key = …CCCC') && str_contains($text, '<pre>'), 'port and masked configuration');
foreach (["/nwMode $id off", "/nwMode $id masque", "/nwPorts $id", "/nwKey $id", "/nwReg $id", "/nlist $id warp 0"] as $button)
    $check(in_array($button, $cb($bot), true), "button $button");
foreach ($cb($bot) as $data) $check(strlen($data) <= 64, 'callback fits Telegram');

// Official ports only; the port belongs to its mode.
$bot->managedNodeWarpPorts($id);
$check(in_array("/nwPort $id 500", $cb($bot), true) && !in_array("/nwPort $id 443", $cb($bot), true), 'WireGuard ports');
$bot->managedNodeWarpPort($id, '500');
$check(($bot->submitted[0]['operation'] ?? '') === 'configure' && ($bot->submitted[0]['value']['warp_port'] ?? 0) === 500, 'port applied by a configure job');
$bot = $fresh();
$bot->managedNodeWarpPort($id, '443');
$check($bot->submitted === [], 'a port of another mode is refused');
$bot = $fresh();
$bot->pacState['managed_nodes'][$id]['status']['options']['warp_port'] = 500;
$bot->managedNodeWarpMode($id, 'masque');
$sent = $bot->submitted[0]['value'] ?? [];
$check(($sent['warp_mode'] ?? '') === 'masque' && !isset($sent['warp_port']), 'switching mode drops the old port');
$bot = $fresh();
$bot->pacState['managed_nodes'][$id]['status']['options'] = ['warp_mode' => 'masque', 'warp_port' => 8443] + $bot->pacState['managed_nodes'][$id]['status']['options'];
$bot->managedNodeWarpHttp($id, 'h2');
$sent = $bot->submitted[0]['value'] ?? [];
$check(($sent['warp_http'] ?? '') === 'h2' && !isset($sent['warp_port']), 'HTTP/2 uses TCP 443');
$bot = $fresh();
$bot->managedNodeWarpMode($id, 'off');
$sent = $bot->submitted[0]['value'] ?? [];
$check(($sent['warp_mode'] ?? '') === 'off' && !isset($sent['warp_port']) && !isset($sent['warp_http']), 'off keeps no WARP choices');

// A pending settings draft never rides along with a WARP change.
$bot = $fresh();
$bot->pacState['managed_nodes'][$id]['draft'] = ['transport' => 'ws'] + $bot->pacState['managed_nodes'][$id]['status']['options'];
$bot->managedNodeWarpPort($id, '500');
$check($bot->submitted === [] && str_contains(end($bot->screens)[0], 'черновик'), 'draft blocks WARP changes');

// A WARP+ key: validated, sent as an account job, never shown on the screen.
$bot = $fresh();
$bot->managedNodeWarpKeyPrompt($id);
$check(($bot->prompts[1]['callback'] ?? '') === 'saveNodeWarpKey' && ($bot->prompts[1]['args'] ?? []) === [$id], 'key prompt');
$bot->saveNodeWarpKey('bad key', $id);
$check($bot->submitted === [] && str_contains(end($bot->screens)[0], '8–64'), 'invalid key refused');
$bot->saveNodeWarpKey(' AAAA-BBBB-CCCC ', $id);
$check(($bot->submitted[0]['operation'] ?? '') === 'warp_account' && ($bot->submitted[0]['value'] ?? []) === ['action' => 'license', 'key' => 'AAAA-BBBB-CCCC'], 'key job submitted');
foreach ($bot->screens as [$screen]) $check(!str_contains($screen, 'AAAA-BBBB-CCCC'), 'key never on a screen');
$check(!str_contains(json_encode($bot->pacState), 'AAAA-BBBB-CCCC'), 'key never stored in the PAC');

// A new account asks first.
$bot = $fresh();
$bot->managedNodeWarpRegister($id, false);
$check($bot->submitted === [] && in_array("/nwRegYes $id", $cb($bot), true), 'new account asks for confirmation');
$bot->managedNodeWarpRegister($id, true);
$check(($bot->submitted[0]['value'] ?? []) === ['action' => 'register'], 'register job submitted');

// Older node code: no account actions, no info request.
$bot = $fresh();
unset($bot->pacState['managed_nodes'][$id]['status']['warp_account']);
$bot->managedNodeWarp($id);
$check(!in_array("/nwKey $id", $cb($bot), true) && !in_array("/nwPorts $id", $cb($bot), true) && !in_array('warp_info', $bot->events, true), 'older nodes keep the basic screen');
echo "PASS node WARP screen\n";
