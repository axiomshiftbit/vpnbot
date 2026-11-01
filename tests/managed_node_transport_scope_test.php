<?php
// Settings groups follow the transport; Trojan flows through the controller.
ob_start();require __DIR__.'/managed_nodes_test.php';ob_end_clean();
class NodeScopeFixture extends ManagedFixtureBot {
    public function __construct(){parent::__construct();$this->admin=true;$this->input+=['callback'=>'','message'=>''];$this->pacState['managed_nodes']['aabbccdd']['job']=null;}
    public function getWgMsg(){return null;}
    public function click(string $callback):void{$this->input['callback']=$callback;$this->action();}
    public function set(array $changes):void{$this->pacState['managed_nodes']['aabbccdd']['status']['options']=$changes+$this->pacState['managed_nodes']['aabbccdd']['status']['options'];}
    public function callbacks():array{return array_column(array_merge(...end($this->screens)[1]),'callback_data');}
}
$id='aabbccdd';$checks=0;
$expected=['reality'=>['reality'=>1,'xhttp'=>0,'crypto'=>1],'ws'=>['reality'=>0,'xhttp'=>0,'crypto'=>1],'grpc'=>['reality'=>0,'xhttp'=>0,'crypto'=>1],
 'xhttp'=>['reality'=>0,'xhttp'=>1,'crypto'=>1],'trojan-grpc'=>['reality'=>0,'xhttp'=>0,'crypto'=>0]];
foreach(['ru','en'] as $lang) foreach($expected as $transport=>$groups){
 $b=new NodeScopeFixture();$b->language=$lang;$b->set(['transport'=>$transport]);
 $b->click("/nodeSettings $id");$root=$b->callbacks();
 foreach($groups as $group=>$visible){
  if(in_array("/nodeSettings $id $group",$root,true)!==(bool)$visible)throw new RuntimeException("Root $transport/$group");
  // Stale button from an older message: back to the root screen, never hidden fields.
  $b->click("/nodeSettings $id $group");
  if(!$visible && in_array("/nodeSettings $id basic",$b->callbacks(),true)===false)throw new RuntimeException("Stale $transport/$group");
  $checks++;
 }
 foreach(['basic','network','domains','smux','dpi','finalmask','sniffing','torrent','reserve','wireguard','amnezia'] as $group)
  if(!in_array("/nodeSettings $id $group",$root,true))throw new RuntimeException("Always-visible $group");
 // Reality options inside the crypto screen are Reality-only, as in the main bot.
 if($groups['crypto']){
  $b->click("/nodeSettings $id crypto");$c=$b->callbacks();
  if(in_array("/nodeField $id xray.reality.mldsa",$c,true)!==($transport==='reality'))throw new RuntimeException("ML-DSA $transport");
  if(!in_array("/nodeField $id xray.encryption.auth",$c,true))throw new RuntimeException("Encryption $transport");
 }
 $before=count($b->screens);$b->click("/nodeField $id ".($transport==='reality'?'xray.xhttp.mode':'mask'));
 if(in_array("/nodeEdit $id mask",$b->callbacks(),true))throw new RuntimeException('Hidden field opened');
 $checks++;
}
// A transport change never strands a draft with an option that is now hidden.
$options=['transport'=>'xhttp','core'=>'fork','xray'=>['xhttp'=>['mux'=>true],'reality'=>['requireMlkem'=>true,'mldsa'=>false],'encryption'=>['auth'=>'x25519','mode'=>'native']]];
$out=ManagedNodeFields::change($options,'transport','ws');
if($out['xray']['xhttp']['mux']!==false||$out['xray']['reality']['requireMlkem']!==false||$out['xray']['encryption']['auth']!=='x25519')throw new RuntimeException('Leaving XHTTP');
$out=ManagedNodeFields::change($options,'transport','trojan-grpc');
if($out['xray']['encryption']['auth']!=='off')throw new RuntimeException('Trojan keeps encryption');
$out=ManagedNodeFields::change($options,'transport','xhttp');
if($out['xray']['xhttp']['mux']!==true)throw new RuntimeException('Same transport lost mux');
$checks+=3;
// The main bot's parser accepts the node's Trojan profile and keeps its identity.
$uuid='22222222-2222-4222-8222-222222222222';$path=str_repeat('ab',16);
$profile=['link'=>"trojan://$uuid@11.77.0.4:443?type=grpc&security=tls&sni=node.example.test&fp=chrome&serviceName=$path#panel",
 'outbound'=>['tag'=>'panel','protocol'=>'trojan','settings'=>['address'=>'11.77.0.4','port'=>443,'password'=>$uuid],
  'streamSettings'=>['network'=>'grpc','security'=>'tls','tlsSettings'=>['serverName'=>'node.example.test','fingerprint'=>'chrome','alpn'=>['h2','http/1.1']],'grpcSettings'=>['serviceName'=>$path]]],'subscription'=>'x'];
$parsed=ManagedNodeProfile::parse($profile,'origin');
if($parsed['protocol']!=='trojan'||ManagedNodeProfile::credential($parsed['outbound'])!==$uuid
 ||($parsed['managed_outbound']['streamSettings']['sockopt']['tcpMptcp']??true)!==false)throw new RuntimeException('Trojan profile');
$outbound=$parsed['managed_outbound'];ManagedNodeProfile::setEndpoint($outbound,'127.0.0.1',10920);
if($outbound['settings']['servers'][0]['address']!=='127.0.0.1'||isset($outbound['settings']['vnext']))throw new RuntimeException('Trojan carrier endpoint');
$v=['settings'=>['vnext'=>[['address'=>'a','port'=>1,'users'=>[['id'=>$uuid]]]]]];ManagedNodeProfile::setEndpoint($v,'127.0.0.1',10920);
if($v['settings']['vnext'][0]['port']!==10920||ManagedNodeProfile::credential($v)!==$uuid)throw new RuntimeException('VLESS carrier endpoint');
$panel=ManagedNodeProfile::panel($profile,'origin','panel');
if($panel['protocol']!=='trojan'||$panel['tag']!=='panel')throw new RuntimeException('Trojan panel export');
$checks+=3;
// Card names the protocol actually in use.
$b=new NodeScopeFixture();$b->set(['transport'=>'trojan-grpc','amnezia'=>['enabled'=>true,'active'=>true]]);
$b->click("/node $id");$card=(string)end($b->screens)[0];
if(!str_contains($card,'Trojan через AmneziaWG')||str_contains($card,'VLESS через'))throw new RuntimeException('Card protocol');
$checks++;
// Names the node would refuse never leave the menu.
foreach(['controller','Controller','PANEL'] as $name){
 $b=new NodeScopeFixture();$b->pacState['managed_nodes'][$id]['status']['peers']=[['id'=>'22222222-2222-4222-8222-222222222222','name'=>'panel','enabled'=>true]];
 $b->events=[];$b->saveManagedNodePeerAdd($name,$id);
 if(in_array('submit',$b->events,true))throw new RuntimeException('Reserved peer name submitted');
 $checks++;
}
echo "PASS $checks node transport scope and Trojan controller checks\n";
