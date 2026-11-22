<?php
require __DIR__ . '/managed_nodes_test.php';
class ManagedPeerFixture extends ManagedFixtureBot {
    public array $requests = []; public array $deliveries = [];
    public bool $deliveryOk = true;
    public function __construct() {
        parent::__construct();
        $this->input['chat'] = -123; $this->input['from'] = 123;
        $this->pacState['managed_nodes']['aabbccdd']['job'] = null;
        $this->pacState['managed_nodes']['aabbccdd']['status']['pending'] = null;
        $this->pacState['managed_nodes']['aabbccdd']['status']['peers'] = [['id' => '22222222-2222-4222-8222-222222222222', 'name' => 'panel', 'enabled' => true]];
        $this->profile['link'] = str_replace('11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222', $this->profile['link']);
    }
    protected function managedNodeRpc(string $id, array $request): array { $this->requests[] = $request; return parent::managedNodeRpc($id, $request); }
    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false) { $this->deliveries[] = [$chat, $text]; return ['ok' => $this->deliveryOk]; }
    public function sendFile($chat, $file, $caption = false, $to = false) { $this->deliveries[] = [$chat, $file]; return ['ok' => $this->deliveryOk]; }
}
$id = 'aabbccdd'; $uuid = '22222222-2222-4222-8222-222222222222'; $key = Bot::exitEntryKey($uuid);
$checks = 0;
$check = static function ($ok, $name) use (&$checks) { $checks++; if (!$ok) throw new RuntimeException('FAIL '.$name); };
$test = new ManagedPeerFixture();
$state =& $test->pacState['managed_nodes'][$id];
$state['status']['adguard_filter'] = true;
$state['status']['options']['adguard'] = ['enabled'=>true,'controller'=>false,'peers'=>[$uuid]];
$test->managedNodePeerAction($id, $key, 'rotate', true);
$rpc = end($test->requests)['request'] ?? [];
$check(($rpc['operation'] ?? '') === 'rotate' && $rpc['value'] === $uuid, 'rotate keeps the selected DNS client on the remote node');
$test = new ManagedPeerFixture();
$state =& $test->pacState['managed_nodes'][$id];
$state['status']['adguard_filter'] = true;
$state['status']['options']['adguard'] = ['enabled'=>true,'controller'=>false,'peers'=>[]];
$state['draft_generation'] = $state['status']['generation'];
$state['draft'] = ['mask'=>'pending.example.test'] + $state['status']['options'];
$test->nodeAdguardClients($id, true);
$state = $test->pacState['managed_nodes'][$id];
$check(!$test->requests && $state['draft']['mask'] === 'pending.example.test' && $state['draft']['adguard']['controller']
    && $state['draft']['adguard']['peers'] === [$uuid], 'filling allowed clients preserves a pending settings draft');
foreach (['ru', 'en'] as $language) {
    $bot = new ManagedPeerFixture(); $bot->language = $language;
    $bot->managedNodePeersMenu($id); $bot->managedNodePeerMenu($id, $key);
    foreach ($bot->screens as [$text, $rows]) {
        $check(!str_contains($text, $uuid), 'peer menu does not expose credential');
        foreach ($rows as $row) foreach ($row as $button) $check(strlen($button['callback_data']) <= 64 && !str_contains($button['callback_data'], $uuid), 'short callbacks contain no credential');
    }
    $bot->saveManagedNodePeerAdd('other-panel', $id);
    $request = end($bot->requests)['request'];
    $check($request['operation'] === 'peers' && count($request['value']) === 2 && $request['generation'] === str_repeat('b', 32), 'peer add submits complete list with expected generation');
    $check($request['value'][1]['id'] !== $uuid && $request['value'][1]['id'] !== '11111111-1111-4111-8111-111111111111', 'peer gets separate identity');
    foreach (['panel', '../escape', "line\nnext", '', str_repeat('a', 41)] as $name) {
        $bot = new ManagedPeerFixture(); $bot->saveManagedNodePeerAdd($name, $id);
        $check(!$bot->requests, 'bad or duplicate name does not submit RPC');
    }
    foreach (['off', 'on', 'rotate', 'delete'] as $action) {
        $bot = new ManagedPeerFixture(); $bot->managedNodePeerAction($id, $key, $action);
        $check(!$bot->requests, 'peer mutation waits for button confirmation');
        $bot->managedNodePeerAction($id, $key, $action, true);
        $peers = end($bot->requests)['request']['value'];
        $check(match ($action) { 'off' => !$peers[0]['enabled'], 'on' => $peers[0]['enabled'], 'rotate' => $peers[0]['id'] !== $uuid, 'delete' => $peers === [] }, 'peer operation submitted correctly');
    }
    foreach (['link', 'json', 'sub'] as $format) {
        $bot = new ManagedPeerFixture(); $bot->managedNodePeerExport($id, $key, $format);
        $check(count($bot->deliveries) === 1 && $bot->deliveries[0][0] === 123, 'credentials sent only to admin private chat');
        $check($bot->requests[0] === ['action' => 'profile', 'peer' => $uuid], 'export requests dedicated peer only');
        $body = $bot->deliveries[0][1];
        if ($format === 'json') {
            $out = json_decode($body->data, true, 64, JSON_THROW_ON_ERROR);
            $check($out['settings']['vnext'][0]['users'][0]['id'] === $uuid && $out['streamSettings']['sockopt']['tcpMptcp'] === false, 'JSON preserves identity and MPTCP guard');
        } elseif ($format === 'sub') $check(base64_decode($body->data, true) === $bot->profile['link']."\n", 'subscription contains validated peer link');
        else $check(str_contains($body, $uuid), 'link contains selected identity');
    }
    foreach (['pending', 'disabled', 'stale', 'wrong_peer', 'injected'] as $case) {
        $bot = new ManagedPeerFixture(); $selected = $key;
        if ($case === 'pending') $bot->pacState['managed_nodes'][$id]['job'] = ['id' => str_repeat('a', 32)];
        if ($case === 'disabled') $bot->pacState['managed_nodes'][$id]['status']['peers'][0]['enabled'] = false;
        if ($case === 'stale') $selected = '0000000000';
        if ($case === 'wrong_peer') $bot->profile['link'] = str_replace($uuid, '11111111-1111-4111-8111-111111111111', $bot->profile['link']);
        if ($case === 'injected') $bot->profile['outbound']['proxySettings'] = ['tag' => 'secret'];
        $bot->managedNodePeerExport($id, $selected, 'json');
        $check(!$bot->deliveries, 'unsafe or unavailable peer is never exported');
    }
    foreach (['link', 'json', 'sub'] as $format) {
        $bot = new ManagedPeerFixture(); $bot->deliveryOk = false;
        $bot->managedNodePeerExport($id, $key, $format);
        $check(count($bot->screens) > 0, 'failed private delivery is reported in originating menu');
    }
}
echo "PASS $checks external node peer checks\n";
