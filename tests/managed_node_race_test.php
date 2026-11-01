<?php
require __DIR__ . '/managed_nodes_test.php';
class RaceFixtureBot extends ManagedFixtureBot {
    public array $locks = [];
    public int $submits = 0;
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) {
        if (!empty($this->locks[$name])) return $busy;
        $this->locks[$name] = true;
        try { return $fn(); } finally { unset($this->locks[$name]); }
    }
    protected function managedNodeRpc(string $id, array $request): array {
        if ($request['action'] === 'submit' && ++$this->submits === 1) {
            // A second request arrives after the remote worker has completed,
            // while the first response has not yet been recorded locally.
            try { $this->managedNodeSubmit($id, 'restart', null); } catch (RuntimeException $error) {}
        }
        return parent::managedNodeRpc($id, $request);
    }
}
$bot = new RaceFixtureBot();
$bot->pacState['managed_nodes']['aabbccdd']['job'] = null;
$bot->managedNodeSubmit('aabbccdd', 'restart', null);
if ($bot->submits !== 1) throw new RuntimeException('FAIL overlapping maintenance requests submit two remote jobs');
echo "PASS overlapping maintenance requests serialized\n";
