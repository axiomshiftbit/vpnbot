<?php
require __DIR__ . '/managed_nodes_test.php';

class ConnectFixtureBot extends ManagedFixtureBot
{
    protected function managedNodeTransport(string $id, string $action, $value = null): array {
        if ($action === 'connect') { $this->events[] = 'connect'; return ['connected' => true]; }
        return parent::managedNodeTransport($id, $action, $value);
    }
}
$failed = 0;
foreach (['snapshot', 'probe'] as $failure) {
    $bot = new ConnectFixtureBot();
    $bot->pacState['managed_nodes']['aabbccdd']['connected'] = false;
    $bot->pacState['managed_nodes']['aabbccdd']['job'] = null;
    unset($bot->pacState['exits']['aabbccdd']);
    $bot->remoteStatus['pending'] = null;
    if ($failure === 'snapshot') $bot->snapshotPass = false;
    else $bot->probePass = false;
    $bot->saveManagedNodeEndpoint('1.1.1.1 22 ssh-ed25519 FIXTURE', 'aabbccdd');
    $reached = in_array($failure, $bot->events);
    $ok = $reached && !$bot->pacState['managed_nodes']['aabbccdd']['connected'] && !isset($bot->pacState['exits']['aabbccdd']);
    echo ($ok ? 'PASS ' : 'FAIL ').'failed '.$failure.' leaves no connected node or partial route'.PHP_EOL;
    if (!$reached) echo 'Fixture stopped before requested failure: '.implode(',', $bot->events).PHP_EOL;
    $failed += !$ok;
}
$bot = new ConnectFixtureBot();
$bot->pacState['managed_nodes']['aabbccdd']['job'] = null;
$before = $bot->pacState['exits']['aabbccdd'];
$bot->probePass = false;
$bot->remoteStatus['pending'] = null;
$bot->saveManagedNodeEndpoint('1.1.1.1 22 ssh-ed25519 FIXTURE', 'aabbccdd');
$ok = $bot->pacState['exits']['aabbccdd'] === $before;
echo ($ok ? 'PASS ' : 'FAIL ').'failed reconnect preserves existing route'.PHP_EOL;
$failed += !$ok;
$bot = new ConnectFixtureBot();
$bot->pacState['managed_nodes']['aabbccdd']['connected'] = false;
$bot->pacState['managed_nodes']['aabbccdd']['job'] = null;
$bot->remoteStatus['pending'] = null;
$bot->saveManagedNodeEndpoint('1.1.1.1 22 ssh-ed25519 FIXTURE', 'aabbccdd');
$ok = $bot->pacState['managed_nodes']['aabbccdd']['connected'] && in_array('probe', $bot->events);
echo ($ok ? 'PASS ' : 'FAIL ').'valid endpoint connects and tests traffic'.PHP_EOL;
$failed += !$ok;
exit($failed ? 1 : 0);
