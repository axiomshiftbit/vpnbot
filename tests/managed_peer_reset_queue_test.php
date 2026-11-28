<?php
require_once __DIR__.'/../app/bot.php';
function queueCheck(bool $ok,string $message):void { if (!$ok) throw new RuntimeException($message); }
class CounterQueueFixture extends Bot {
    public array $nodes=[], $seen=[]; public bool $offline=false, $drop=false, $replace=false, $removed=false;
    public int $remote=0, $usage=400;
    public function __construct(){ $this->admin=true; $this->input=['chat'=>1,'from'=>1,'message_id'=>1]; }
    public function getPacConf(){return $this->nodes;}
    public function setPacConf(array $conf){$this->nodes=$conf;return true;}
    public function withLock(string $name, callable $fn,int $timeout=0,$busy=null){return $fn();}
    public function managedNodePeerMenu(string $id,string $key,string $notice=''):void{}
    protected function managedNodeRpc(string $id,array $request):array {
        if ($this->offline) throw new RuntimeException('offline');
        $n=$request['sequence']; $key=$request['peer']; $this->seen[]=$n;
        if (!$this->removed && $n>$this->remote) {$this->usage=0; $this->remote=$n;}
        if ($this->drop) { $this->drop=false; throw new RuntimeException('reply lost'); }
        if ($this->replace) { $this->replace=false; $this->nodes['managed_nodes'][$id]['peer_resets'][$key]=$n+1; }
        return ['peer'=>$key,'sequence'=>$n,'result'=>$this->removed?'removed':'applied'];
    }
}
$id='abeccedd'; $peer=['id'=>'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee','enabled'=>true,'name'=>'Panel'];
$key=Bot::exitEntryKey($peer['id']);$identity=substr(hash('sha256','peer-counter:'.$peer['id']),0,32);
$b=new CounterQueueFixture();$b->nodes=['managed_nodes'=>[$id=>['connected'=>true,'status'=>['peers'=>[$peer],'peer_counter_support'=>true]]]];
$send=static function($bot) use($id){(new ReflectionMethod($bot,'deliverPeerResets'))->invoke($bot,$id);};
$b->offline=true;$b->managedNodePeerAction($id,$key,'reset',true);
queueCheck(!empty($b->nodes['managed_nodes'][$id]['peer_resets'][$identity]) && $b->usage===400,'Offline operation durably queued before RPC');
$afterRestart=new CounterQueueFixture();$afterRestart->nodes=$b->nodes;$b=$afterRestart;$b->drop=true;
try{$send($b);}catch(RuntimeException $e){}
queueCheck($b->usage===0 && !empty($b->nodes['managed_nodes'][$id]['peer_resets']),'Lost ack retains pending reset');
$b->usage=29;$send($b);queueCheck($b->usage===29 && !isset($b->nodes['managed_nodes'][$id]['peer_resets']),'Retry of applied reset preserves new traffic');
$b->replace=true;$b->managedNodePeerAction($id,$key,'reset',true);queueCheck($b->nodes['managed_nodes'][$id]['peer_resets'][$identity]>$b->remote,'Older ack cannot clear a concurrent reset');
$send($b);queueCheck(!isset($b->nodes['managed_nodes'][$id]['peer_resets']),'Newer operation completes');
$b->offline=true;$b->managedNodePeerAction($id,$key,'reset',true);$b->offline=false;$b->removed=true;$b->usage=81;$send($b);
queueCheck($b->usage===81 && !isset($b->nodes['managed_nodes'][$id]['peer_resets']),'Deleted identity cannot reset replacement');
$b->admin=false;$b->managedNodePeerAction($id,$key,'reset',true);queueCheck(empty($b->nodes['managed_nodes'][$id]['peer_resets']),'Admin-only reset');
echo "managed_peer_reset_queue_test OK\n";
