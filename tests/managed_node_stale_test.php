<?php
require __DIR__ . '/managed_nodes_test.php';
class StaleFixtureBot extends ManagedFixtureBot {
    public ?array $submitted = null;
    protected function managedNodeRpc(string $id, array $request): array {
        if ($request['action'] === 'submit') $this->submitted = $request['request'];
        return parent::managedNodeRpc($id, $request);
    }
}
$bot = new StaleFixtureBot();
$bot->pacState['managed_nodes']['aabbccdd']['job'] = null;
$bot->managedNodeChoice('aabbccdd', 'transport', 'xhttp');
$generation = $bot->pacState['managed_nodes']['aabbccdd']['status']['generation'];
// Status can advance while an old settings draft is still open.
$bot->pacState['managed_nodes']['aabbccdd']['status']['generation'] = str_repeat('e', 32);
$bot->managedNodeApply('aabbccdd');
if (($bot->submitted['generation'] ?? null) !== $generation) throw new RuntimeException('FAIL settings draft must retain its base generation');
echo "PASS settings draft carries original generation\n";
