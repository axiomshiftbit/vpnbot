<?php
require '/audit-source/app/bot.php';
class NativeManagedSync extends Bot {
    public function __construct(string $root) {
        $this->protocolRoot="$root/protocols"; $this->protocolModulesFile="$root/modules.json";
        $this->xrayConf="$root/xray.json"; $this->language='ru';
    }
    public function getXrayStats() { return []; }
}
$root=$argv[1];$action=$argv[2];$b=new NativeManagedSync($root);
if($action==='init') {
    $modules=new ProtocolModules($b->protocolModulesFile);
    foreach(['anytls','mieru','masque']as$p){$b->protocolStore($p)->configure(['host'=>'vpn.example.test','sni'=>$p==='mieru'?'':'vpn.example.test'],true);$modules->set($p,true);}
    $clients=[];foreach(['a','b','c']as$i=>$letter)$clients[]=['id'=>sprintf('00000000-0000-4000-8000-%012d',$i+1),'protocol_source'=>str_repeat($letter,32),'email'=>'synthetic-'.$letter,'traffic'=>$letter==='c'?10000000:0];
    ManagedProtocol::writeJson($b->xrayConf,['inbounds'=>[['settings'=>['clients'=>$clients]]]]);
    $b->syncXrayProtocolUsers();
    foreach(['anytls','mieru','masque']as$p){$store=$b->protocolStore($p);$rows=[];foreach($store->read()['users']as$id=>$u)$rows[$id]=['upload'=>0,'download'=>0,'reset'=>$u['reset']];ManagedProtocol::writeJson($store->directory().'/runtime/usage.json',['users'=>$rows]);}
    $b->syncXrayProtocolUsers();
} elseif($action==='fault') {
    $kind=$argv[3];$operation=$argv[4];$bad=$kind==='target'?'anytls':($kind==='desired'?'masque':'mieru');
    $path=$b->protocolStore($bad)->directory().($kind==='usage'?'/runtime/usage.json':'/desired.json');
    file_put_contents("$root/recovery",file_get_contents($path));file_put_contents("$root/recovery-path",$path);file_put_contents($path,'{synthetic-invalid');
    $x=$b->getXray();$client=&$x['inbounds'][0]['settings']['clients'][0];
    if($operation==='disable')$client['off']=$client['id'];
    if($operation==='rotate')$client['id']=Bot::xrayUuid();unset($client);
    if($operation==='delete')array_shift($x['inbounds'][0]['settings']['clients']);
    if(!$b->writeXrayJson(json_encode($x)))throw new RuntimeException('synthetic source write failed');
} elseif($action==='repair') {
    file_put_contents(file_get_contents("$root/recovery-path"),file_get_contents("$root/recovery"));
    $b->syncXrayProtocolUsers();
} else throw new RuntimeException('invalid fixture action');
echo json_encode(['ok'=>true]),"\n";
