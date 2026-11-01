<?php
require __DIR__ . '/managed_nodes_test.php';
class UnavailableLockBot extends ManagedFixtureBot {
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) {
        return (new ReflectionMethod(Bot::class, 'withLock'))->invoke($this, $name, $fn, $timeout, $busy);
    }
}
$root = '/logs';
if (!is_dir($root)) mkdir($root, 0700);
$failed = 0;
foreach (['audit-unavailable', 'managed-node-aabbccdd'] as $name) mkdir("$root/.lock.$name", 0700);
try {
    $bot = new UnavailableLockBot();
    $ok = $bot->withLock('audit-working', static fn() => 'locked', 1, false) === 'locked';
    echo ($ok ? 'PASS ' : 'FAIL ')."available lock allows normal operation\n"; $failed += !$ok;
    $called = false;
    $result = $bot->withLock('audit-unavailable', static function () use (&$called) { $called = true; return true; }, 1, false);
    $ok = !$called && $result === false;
    echo ($ok ? 'PASS ' : 'FAIL ')."main callback cannot run without required lock\n"; $failed += !$ok;
    $bot->pacState['managed_nodes']['aabbccdd']['job'] = null;
    $before = $bot->pacState;
    try { $bot->managedNodeSubmit('aabbccdd', 'restart', null); } catch (RuntimeException $e) {}
    $ok = $bot->pacState === $before && !in_array('submit', $bot->events, true);
    echo ($ok ? 'PASS ' : 'FAIL ')."node cannot submit operation when controller lock is unavailable\n"; $failed += !$ok;
} finally {
    foreach (['audit-unavailable', 'managed-node-aabbccdd'] as $name) rmdir("$root/.lock.$name");
    @unlink("$root/.lock.audit-working");
}
exit($failed ? 1 : 0);
