<?php
require __DIR__.'/managed_nodes_test.php';
class NodeFamilyFixture extends ManagedFixtureBot {
    public array $ipv6=[];
    protected function exitIpv6Network(): array {return $this->ipv6;}
}
foreach(['missing','disabled','not-allowed','ready'] as $case) {
    $b=new NodeFamilyFixture();$n=&$b->pacState['managed_nodes']['aabbccdd'];$n['job']=null;
    $options=$n['status']['options'];$options['connect_family']=6;
    $n['status']['public6']='2606:4700:4700::4';
    $n['status']['sources']=$case==='ready'?['2606:4700:4700::2']:['11.77.0.2'];
    if($case!=='missing')$b->ipv6=['enabled'=>$case!=='disabled','public'=>'2606:4700:4700::2'];
    unset($n);$rejected=false;
    try{$b->managedNodeSubmit('aabbccdd','configure',$options);}catch(RuntimeException $e){$rejected=true;}
    $check($rejected===($case!=='ready'),'IPv6 preflight '.$case);
    $check(in_array('submit',$b->events)===($case==='ready'),'no remote operation without prepared IPv6 '.$case);
}
echo "PASS node network preflight\n";
