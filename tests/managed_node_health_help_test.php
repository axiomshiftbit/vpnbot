<?php
require __DIR__.'/managed_nodes_test.php';
class NodeHealthFixture extends ManagedFixtureBot {
    public bool $sshReady = true;
    protected function managedNodeRpc(string $id, array $request): array {
        if ($request['action'] === 'status' && !$this->sshReady) throw new RuntimeException('fixture SSH unavailable');
        return parent::managedNodeRpc($id, $request);
    }
    public function exitStatus(): array {return [];}
}
foreach (['up','down','stale','ssh-error'] as $case) {
    $b = new NodeHealthFixture(); $n = &$b->pacState['managed_nodes']['aabbccdd'];
    $n['job'] = null; $n['checked'] = time()-($case==='stale'?600:0);
    $n['status']['running'] = $case!=='down'; $n['status_error'] = $case==='ssh-error'; unset($n);
    $b->managedNodeMenu('aabbccdd'); $text = end($b->screens)[0];
    $check(str_contains($text,'🟢')===($case==='up'), 'green status requires fresh positive evidence '.$case);
    $check(str_contains($text,'🔴')===in_array($case,['down','ssh-error'],true), 'red status for failed check '.$case);
}
foreach ([true,false] as $ssh) {
    $b = new NodeHealthFixture(); $b->sshReady=$ssh;
    $b->pacState['managed_nodes']['aabbccdd']['job']=null;
    $b->remoteStatus['running']=false; $b->checkManagedNodes();
    $n=$b->managedNodes()['aabbccdd'];
    $check(!empty($n['status_attempt']),'periodic status attempt persisted');
    $check($ssh ? $n['status']['running']===false : !empty($n['status_error']), 'periodic check records result');
}
$b=new NodeHealthFixture(); $b->managedNodeMaintenance('aabbccdd'); $rows=end($b->screens)[1];
$check(str_contains($rows[count($rows)-2][0]['callback_data'],'help'), 'help is the last maintenance item before Back');
$b->managedNodeMaintenanceHelp('aabbccdd'); $rows=end($b->screens)[1];
$check(count($rows)>15,'maintenance help lists named sections');
foreach ($rows as $row) foreach ($row as $button) $check(strlen($button['callback_data'])<=64,'help callback fits Telegram');
echo "PASS node status freshness, background checks and named help\n";
