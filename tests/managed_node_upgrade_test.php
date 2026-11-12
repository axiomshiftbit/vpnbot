<?php
require __DIR__.'/managed_nodes_test.php';

class UpgradeFixtureBot extends ManagedFixtureBot
{
    public array $submitted = [];
    protected function managedNodeRpc(string $id, array $request): array {
        if ($request['action'] === 'submit') $this->submitted[] = $request['request'];
        return parent::managedNodeRpc($id, $request);
    }
}

$idle = static function (bool $upgrade): UpgradeFixtureBot {
    $b = new UpgradeFixtureBot();
    $b->pacState['managed_nodes']['aabbccdd']['job'] = null;
    $b->pacState['managed_nodes']['aabbccdd']['status']['pending'] = null;
    if ($upgrade) $b->pacState['managed_nodes']['aabbccdd']['status']['code'] = ['source' => str_repeat('7', 40), 'upgrade' => true];
    return $b;
};

// A node without the upgrade unit keeps the image-only operation and says so.
$b = $idle(false);
$b->managedNodeRun('aabbccdd', 'update_latest');
$check(str_contains(end($b->screens)[0], 'только образы'), 'old node: confirmation explains image-only update');
$b->managedNodeRun('aabbccdd', 'update_latest', true);
$check(($b->submitted[0]['operation'] ?? '') === 'update' && $b->submitted[0]['value'] === 'latest', 'old node: image update submitted');
$b->managedNodeMaintenance('aabbccdd');
$check(str_contains(end($b->screens)[0], 'вручную'), 'old node: maintenance screen asks for one manual code update');

// A node reporting the capability gets the full code and image update.
foreach (['update_latest' => 'latest', 'update_dev' => 'dev'] as $action => $channel) {
    $b = $idle(true);
    $b->managedNodeRun('aabbccdd', $action);
    $check(!str_contains(end($b->screens)[0], 'только образы') && str_contains(end($b->screens)[0], 'код'), 'new node: confirmation describes code update '.$channel);
    $b->managedNodeRun('aabbccdd', $action, true);
    $check(($b->submitted[0] ?? null) === ['operation' => 'upgrade', 'value' => $channel, 'generation' => str_repeat('b', 32)], 'new node: upgrade submitted '.$channel);
    $check(($b->pacState['managed_nodes']['aabbccdd']['job']['operation'] ?? '') === 'upgrade', 'job remembers full update '.$channel);
}
$b = $idle(true);
$b->managedNodeMaintenance('aabbccdd');
$check(str_contains(end($b->screens)[0], '<code>7777777</code>'), 'maintenance shows installed commit');
$check(str_contains(json_encode(end($b->screens)[1], JSON_UNESCAPED_UNICODE), 'Обновить с ветки master'), 'button label kept');

// A failed code phase is reported with its stage and never confirmed.
foreach (['downgrade' => 'старее', 'fetch' => 'deploy-ключ', 'setup_firewall' => '[firewall]', '<b>x' => 'непредвиденный'] as $stage => $needle) {
    $b = new UpgradeFixtureBot();
    $b->pacState['managed_nodes']['aabbccdd']['job']['operation'] = 'upgrade';
    $b->remoteJob = ['state' => 'failed', 'error' => 'code_upgrade_failed', 'stage' => $stage];
    $b->managedNodePoll('aabbccdd');
    $n = $b->pacState['managed_nodes']['aabbccdd'];
    $check(!in_array('confirm', $b->events, true) && $n['job'] === null, 'failed code phase is not confirmed '.$stage);
    $check(($n['error'] ?? '') === 'code_upgrade_failed', 'code failure recorded '.$stage);
    $b->managedNodeMenu('aabbccdd');
    $text = end($b->screens)[0];
    $check(str_contains($text, $needle) && str_contains($text, 'Образы не менялись') && !str_contains($text, '<b>x'), 'card explains code failure '.$stage);
}
$b->language = 'en';
$b->managedNodeMenu('aabbccdd');
$check(str_contains(end($b->screens)[0], 'Node code update failed'), 'English code failure text');

// An ordinary failure keeps the generic rollback notice.
$b = new UpgradeFixtureBot();
$b->pacState['managed_nodes']['aabbccdd']['job']['operation'] = 'upgrade';
$b->remoteJob = ['state' => 'failed', 'error' => 'operation_failed'];
$b->managedNodePoll('aabbccdd');
$check(($b->pacState['managed_nodes']['aabbccdd']['error'] ?? '') === 'rolled_back', 'image phase failure is a rollback');

// Success after traffic confirmation reports a clone kept with local edits.
foreach (['kept' => true, 'updated' => false] as $checkout => $notice) {
    $b = new UpgradeFixtureBot();
    $b->pacState['managed_nodes']['aabbccdd']['job']['operation'] = 'upgrade';
    $b->remoteJob['checkout'] = $checkout;
    $b->managedNodePoll('aabbccdd');
    $n = $b->pacState['managed_nodes']['aabbccdd'];
    $check(in_array('confirm', $b->events, true) && ($n['last_operation']['checkout'] ?? '') === $checkout, 'confirmed upgrade records clone result '.$checkout);
    $b->managedNodeMenu('aabbccdd');
    $text = end($b->screens)[0];
    $check(str_contains($text, 'обновление кода и образов'), 'card names full update '.$checkout);
    $check(str_contains($text, '/root/vpnbot') === $notice, 'local edits notice only when clone kept '.$checkout);
}
echo "PASS managed node full update ($checks checks)\n";
