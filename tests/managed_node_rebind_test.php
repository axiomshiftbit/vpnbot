<?php
require __DIR__ . '/managed_nodes_test.php';

class RebindFixture extends ManagedFixtureBot {
    public bool $rejectHost = false;
    public bool $lockedRecovery = false;
    public array $prompts = [];
    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false) { $this->screens[] = [$text, []]; return ['ok' => true]; }
    public function stashReply($r, array $state) { $this->prompts[] = $state; }
    protected function managedNodeTransport(string $id, string $action, $value = null): array {
        if ($action === 'rebind') {
            if (empty($this->managedNodes()[$id]['recovery_required'])) throw new RuntimeException('Recovery not protected');
            if ($this->rejectHost) throw new RuntimeException('Wrong host pin');
            $this->events[] = 'rebind';
            return ['status' => $this->remoteStatus];
        }
        if ($action === 'saved' || $action === 'restore-source') return ['snapshot' => ['fixture' => true], 'hash' => '0123456789abcdef'];
        return parent::managedNodeTransport($id, $action, $value);
    }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) {
        if ($name === 'managed-node-aabbccdd' && $this->lockedRecovery) {
            $this->pacState['managed_nodes']['aabbccdd']['recovery_required'] = true;
        }
        return $fn();
    }
}
$checks = 0;
$check = static function ($ok, $name) use (&$checks) { $checks++; if (!$ok) throw new RuntimeException('FAIL '.$name); };
foreach (['ru', 'en'] as $lang) {
    $bot = new RebindFixture(); $bot->language = $lang;
    $node =& $bot->pacState['managed_nodes']['aabbccdd'];
    $node['job'] = null; $node['recovery_required'] = true;
    $bot->managedNodeBackupRefresh();
    $check(!in_array('snapshot', $bot->events), 'fresh install cannot overwrite recovery source');
    $node['recovery_required'] = false; $bot->lockedRecovery = true;
    $bot->managedNodeBackupRefresh();
    $check(!in_array('snapshot', $bot->events), 'backup rechecks recovery after acquiring node lock');
    $bot->lockedRecovery = false;
    $denied = false;
    try { $bot->managedNodeSubmit('aabbccdd', 'rotate', 'controller'); } catch (Throwable $e) { $denied = true; }
    $check($denied && !in_array('submit', $bot->events), 'unrestored node cannot accept unrelated mutation');
    $bot->managedNodeRestore('aabbccdd', '0123456789abcdef');
    $check(!$node['job'], 'pending remote transaction refuses recovery');
    $bot->remoteStatus['pending'] = null;
    $bot->managedNodeRestore('aabbccdd', '0123456789abcdef');
    $check(($node['job']['operation'] ?? '') === 'restore', 'restore explicitly recorded during recovery');
    $bot->remoteJob = ['state' => 'missing']; $bot->events = [];
    $bot->managedNodePoll('aabbccdd');
    $check(!$node['job'] && $node['recovery_required'] && !in_array('profile', $bot->events) && !in_array('snapshot', $bot->events), 'missing restore job never adopts fresh identities');

    $bot = new RebindFixture(); $bot->language = $lang;
    $bot->remoteStatus['pending'] = null;
    $route = $bot->exitNodes();
    $bot->managedNodeRebindPrompt('aabbccdd');
    $check(end($bot->prompts)['callback'] === 'saveManagedNodeRebind' && str_contains(end($bot->screens)[0], 'PUBLIC-FIXTURE'), 'reinstall prompt supplies existing public controller key');
    $bot->saveManagedNodeRebind('1.1.1.1 22 ssh-ed25519 FIXTURE', 'aabbccdd');
    $node = $bot->managedNodes()['aabbccdd'];
    $check(!empty($node['recovery_required']) && !$node['job'] && $bot->exitNodes() === $route, 'explicit rebind clears stale jobs but preserves VPN routes');
    $check(!in_array('snapshot', $bot->events), 'rebind never replaces cached backup');
    $bot->managedNodeRestore('aabbccdd', '0123456789abcdef');
    $bot->remoteJob = ['state' => 'done', 'result' => ['pending' => ['after' => str_repeat('b', 32)]]];
    $bot->managedNodePoll('aabbccdd');
    $check(empty($bot->managedNodes()['aabbccdd']['recovery_required']), 'confirmed recovery clears restriction');

    foreach ([false, true] as $previous) {
        $bot = new RebindFixture(); $bot->rejectHost = true;
        $bot->pacState['managed_nodes']['aabbccdd']['recovery_required'] = $previous;
        $bot->pacState['managed_nodes']['aabbccdd']['recovery_required'] = true;
        $bot->events = [];
        $bot->managedNodePoll('aabbccdd');
        $check(!$bot->events, 'recovery never polls a stale mutation from before reinstall');
        $bot->pacState['managed_nodes']['aabbccdd']['recovery_required'] = $previous;
        $before = $bot->managedNodes()['aabbccdd'];
        $bot->saveManagedNodeRebind('1.1.1.1 22 ssh-ed25519 FIXTURE', 'aabbccdd');
        $before['recovery_required'] = true;
        $check($bot->managedNodes()['aabbccdd'] === $before, 'ambiguous rebind failure keeps recovery protection and previous job');
    }
}
echo "PASS $checks cold node recovery checks\n";
