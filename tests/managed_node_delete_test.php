<?php
require __DIR__ . '/managed_nodes_test.php';
class DeleteManagedFixture extends ManagedFixtureBot {
    public function __construct() {
        parent::__construct();
        $this->pacState['managed_nodes']['aabbccdd']['job'] = null;
    }
    protected function managedNodeTransport(string $id, string $action, $value = null): array {
        if ($action === 'forget') { $this->events[] = 'forget'; return ['forgotten' => true]; }
        return parent::managedNodeTransport($id, $action, $value);
    }
}
$failures = [];
foreach (['connected', 'busy', 'core_failure', 'unenrolled', 'confirmation'] as $case) {
    $bot = new DeleteManagedFixture();
    if ($case === 'busy') $bot->pacState['managed_nodes']['aabbccdd']['job'] = ['id' => str_repeat('a', 32)];
    if ($case === 'core_failure') $bot->corePass = false;
    if ($case === 'unenrolled') { unset($bot->pacState['exits']); $bot->pacState['managed_nodes']['aabbccdd']['connected'] = false; }
    $before = $bot->pacState;
    $bot->exitDelete('aabbccdd', $case !== 'confirmation');
    $blocked = in_array($case, ['busy', 'core_failure', 'confirmation'], true);
    $ok = $blocked ? $bot->pacState === $before && !in_array('forget', $bot->events)
        : !isset($bot->pacState['managed_nodes']['aabbccdd'], $bot->pacState['exits']['aabbccdd'])
            && !isset($bot->pacState['managed_nodes']['aabbccdd']) && in_array('forget', $bot->events);
    echo ($ok ? 'PASS ' : 'FAIL ') . 'managed deletion ' . $case . PHP_EOL;
    if (!$ok) $failures[] = $case;
}
if ($failures) exit(1);
