<?php
require __DIR__ . '/managed_nodes_test.php';
$bot = new ManagedFixtureBot();
$bot->remoteJob = ['state' => 'missing'];
$bot->remoteStatus['pending'] = null;
$bot->managedNodePoll('aabbccdd');
if ($bot->pacState['managed_nodes']['aabbccdd']['job'] !== null
    || $bot->pacState['exits']['aabbccdd']['link'] !== $bot->profile['link']
    || !in_array('probe', $bot->events) || in_array('confirm', $bot->events)) {
    throw new RuntimeException('FAIL restored obsolete job must reconcile to current confirmed node with traffic test');
}
echo "PASS restored obsolete job reconciled\n";
$bot = new ManagedFixtureBot();
$bot->remoteJob = ['state' => 'missing'];
$before = $bot->pacState['exits'];
$bot->managedNodePoll('aabbccdd');
if ($bot->pacState['managed_nodes']['aabbccdd']['job'] === null || $bot->pacState['exits'] !== $before || in_array('confirm', $bot->events)) {
    throw new RuntimeException('FAIL obsolete job must wait for unrelated pending transaction');
}
echo "PASS unrelated node change is not confirmed\n";
