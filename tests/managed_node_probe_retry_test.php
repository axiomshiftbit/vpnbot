<?php
require __DIR__ . '/managed_nodes_test.php';
class ResumeFixtureBot extends ManagedFixtureBot {
    public int $attempts = 0;
    public function exitProbe(string $id, bool $full = true): array {
        $this->events[] = 'probe';
        return ['ok' => ++$this->attempts > 1];
    }
}
$bot = new ResumeFixtureBot();
$bot->managedNodePoll('aabbccdd');
if ($bot->attempts !== 2 || $bot->pacState['managed_nodes']['aabbccdd']['job'] !== null || !in_array('confirm', $bot->events)) {
    throw new RuntimeException('FAIL a failed stale session must be retried before node rollback');
}
echo "PASS stale session gets one verified retry\n";
