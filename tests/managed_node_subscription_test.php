<?php
ob_start(); require __DIR__.'/managed_node_peers_test.php'; ob_end_clean();
class NodeSubscriptionFixture extends ManagedPeerFixture {
    public function getDomain($cdn=false) { return 'controller.example.org'; }
    public function nginxGetTypeCert() { return 'letsencrypt'; }
    public function getHashBot($notset=false) { return 'fixture'; }
    public $afterAuthorization;
    public function subRateLimit($sid,$scope='') {
        if ($this->afterAuthorization) ($this->afterAuthorization)();
    }
}
$b=new NodeSubscriptionFixture();
$check(method_exists($b,'managedNodeSubscriptionDocument'),'HTTPS subscription handler exists');
$b->managedNodePeerExport($id,$key,'https');
$check(count($b->deliveries)===1 && $b->deliveries[0][0]===123,'URL delivered only to private chat');
$record=$b->pacState['managed_nodes'][$id]['subscriptions'][$key]??[];
$token=$record['token']??'';
$check(strlen($token)===64 && !str_contains($token,$uuid),'separate random subscription capability');
$b->remoteStatus=$b->pacState['managed_nodes'][$id]['status'];
$doc=$b->managedNodeSubscriptionDocument($id,$token,'sub');
$check(base64_decode($doc['body'],true)===$b->profile['link']."\n",'HTTPS subscription contains current dedicated peer');
$check($b->managedNodeSubscriptionDocument($id,str_repeat('0',64),'sub')===null,'invalid token rejected');
$check($b->managedNodeSubscriptionDocument($id,$token,'yaml')===null,'unsupported format rejected');
$b->afterAuthorization = function () use ($b,$id,$key) {
    unset($b->pacState['managed_nodes'][$id]['subscriptions'][$key]);
};
$before=count($b->requests);
$check($b->managedNodeSubscriptionDocument($id,$token,'sub')===null && count($b->requests)===$before,'revoked capability is rechecked under the node lock before reading the profile');
$b->afterAuthorization=null;
$b->pacState['managed_nodes'][$id]['subscriptions'][$key]=$record;
$requests=count($b->requests);
$b->pacState['managed_nodes'][$id]['status']['peers'][0]['enabled']=false;
$check($b->managedNodeSubscriptionDocument($id,$token,'sub')===null && count($b->requests)===$requests,'disabled peer rejected without SSH');
$b->pacState['managed_nodes'][$id]['status']['peers'][0]['enabled']=true;
$b->pacState['managed_nodes'][$id]['job']=['id'=>'pending'];
try { $b->managedNodeSubscriptionDocument($id,$token,'sub'); $check(false,'pending state unavailable'); } catch (RuntimeException $e) {}
$b->pacState['managed_nodes'][$id]['job']=null;
$b->pacState['managed_nodes'][$id]['status']['peers'][0]['id']='33333333-3333-4333-8333-333333333333';
$check($b->managedNodeSubscriptionDocument($id,$token,'sub')===null,'old subscription invalid after identity rotation');
class ChangingSubscriptionFixture extends NodeSubscriptionFixture {
    public int $statusCalls=0;
    protected function managedNodeRpc(string $id,array $request): array {
        if ($request['action']==='status' && ++$this->statusCalls===2) $this->remoteStatus['generation']=str_repeat('f',32);
        return parent::managedNodeRpc($id,$request);
    }
}
foreach (['stale','pending','wrong_peer','remote_disabled','generation_race','recovery'] as $case) {
    $b=$case==='generation_race'?new ChangingSubscriptionFixture():new NodeSubscriptionFixture();
    $b->managedNodePeerExport($id,$key,'https');
    $token=$b->pacState['managed_nodes'][$id]['subscriptions'][$key]['token'];
    $b->remoteStatus=$b->pacState['managed_nodes'][$id]['status'];
    if($case==='stale')$b->remoteStatus['generation']=str_repeat('f',32);
    if($case==='pending')$b->remoteStatus['pending']=['nonce'=>'fixture'];
    if($case==='wrong_peer')$b->profile['link']=str_replace($uuid,'11111111-1111-4111-8111-111111111111',$b->profile['link']);
    if($case==='remote_disabled')$b->remoteStatus['peers'][0]['enabled']=false;
    if($case==='recovery')$b->pacState['managed_nodes'][$id]['recovery_required']=true;
    try { $b->managedNodeSubscriptionDocument($id,$token,'sub'); $rejected=false; } catch (RuntimeException $e) { $rejected=true; }
    $check($rejected,'unconfirmed or unrelated profile is not published: '.$case);
}
$b=new NodeSubscriptionFixture();$b->managedNodePeerExport($id,$key,'https');
$token=$b->pacState['managed_nodes'][$id]['subscriptions'][$key]['token'];$b->remoteStatus=$b->pacState['managed_nodes'][$id]['status'];
$doc=$b->managedNodeSubscriptionDocument($id,$token,'json');
$parsed=json_decode($doc['body'],true,flags:JSON_THROW_ON_ERROR);
$check($parsed['settings']['vnext'][0]['users'][0]['id']===$uuid && $parsed['streamSettings']['sockopt']['tcpMptcp']===false,'JSON retains identity and MPTCP protection');
foreach (['wireguard','amnezia'] as $channel) {
    $b=new NodeSubscriptionFixture();$b->managedNodePeerExport($id,$key,'https');
    $token=$b->pacState['managed_nodes'][$id]['subscriptions'][$key]['token'];
    $b->pacState['managed_nodes'][$id]['status']['peers'][0]['channel']=$channel;
    $b->remoteStatus=$b->pacState['managed_nodes'][$id]['status'];
    $requests=count($b->requests);
    $check($b->managedNodeSubscriptionDocument($id,$token,'sub')===null && count($b->requests)===$requests,'old VLESS subscription revoked after channel change: '.$channel);
}
echo "PASS HTTPS node subscription checks\n";
