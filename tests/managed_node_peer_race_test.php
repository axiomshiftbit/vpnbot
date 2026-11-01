<?php
require __DIR__ . '/managed_nodes_test.php';
class ManagedPeerRace extends ManagedFixtureBot {
    public array $request = [];
    public function __construct() {
        parent::__construct();
        $this->pacState['managed_nodes']['aabbccdd']['job'] = null;
        $this->pacState['managed_nodes']['aabbccdd']['status']['peers'] = [['id' => '22222222-2222-4222-8222-222222222222', 'name' => 'panel', 'enabled' => true]];
    }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) {
        if ($name === 'managed-node-aabbccdd') {
            $this->pacState['managed_nodes']['aabbccdd']['status']['generation'] = str_repeat('d', 32);
            $this->pacState['managed_nodes']['aabbccdd']['status']['peers'][] = ['id' => '33333333-3333-4333-8333-333333333333', 'name' => 'parallel-panel', 'enabled' => true];
        }
        return $fn();
    }
    protected function managedNodeRpc(string $id, array $request): array { $this->request = $request; return parent::managedNodeRpc($id, $request); }
}
$failed = 0;
foreach (['add', 'off'] as $action) {
    $bot = new ManagedPeerRace();
    if ($action === 'add') $bot->saveManagedNodePeerAdd('new-panel', 'aabbccdd');
    else $bot->managedNodePeerAction('aabbccdd', Bot::exitEntryKey('22222222-2222-4222-8222-222222222222'), 'off', true);
    $r = $bot->request['request'] ?? [];
    $ok = ($r['generation'] ?? '') === str_repeat('b', 32) || in_array('parallel-panel', array_column($r['value'] ?? [], 'name'), true);
    echo ($ok ? 'PASS ' : 'FAIL ')."peer $action cannot overwrite a concurrently added identity\n";
    $failed += !$ok;
}
exit($failed ? 1 : 0);
