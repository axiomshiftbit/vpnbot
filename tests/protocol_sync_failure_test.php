<?php
// Actual stores, atomic files and process locks; no network or Telegram calls.
require_once (getenv('VPNBOT_TEST_SOURCE') ?: dirname(__DIR__)) . '/app/bot.php';
class SyncFailureBot extends Bot {
    public string $fixture;
    public bool $slow = false;
    public function __construct(string $root) {
        $this->fixture=$root; $this->protocolRoot="$root/protocols"; $this->protocolModulesFile="$root/modules.json";
        $this->xrayConf="$root/xray.json"; $this->language='ru';
    }
    public function getXray() {
        $value=ManagedProtocol::readJson($this->xrayConf);
        if($this->slow) {
            touch("$this->fixture/old-read"); $end=microtime(true)+3;
            while(!is_file("$this->fixture/new-start") && microtime(true)<$end) usleep(1000);
            usleep(150000);
        }
        return $value;
    }
    public function getXrayStats() { return []; }
    public function restartXray($config,$norestart=false) { return $this->writeXrayJson(json_encode($config)); }
    public function notifyAdmins(string $text): void {}
    public function withLock(string $name,callable $fn,int $timeout=0,$busy=null) {
        $f=fopen("$this->fixture/lock-$name",'c'); if(!$f||!flock($f,LOCK_EX)) return $busy;
        try{return $fn();}finally{flock($f,LOCK_UN);fclose($f);}
    }
}
function failureSync(SyncFailureBot $b): bool { try{$b->syncXrayProtocolUsers();return true;}catch(RuntimeException $e){return false;} }
function failureUser(ManagedProtocol $store,string $source): ?array {
    foreach($store->read()['users'] as $id=>$u) if(($u['xray_source']??'')===$source) return [$id,$u];
    return null;
}
if(($argv[1]??'')==='worker') {
    $b=new SyncFailureBot($argv[2]); $b->slow=$argv[3]==='old';
    if(!$b->slow) touch("$b->fixture/new-start"); failureSync($b); exit(0);
}
$root=sys_get_temp_dir().'/protocol-sync-failure-'.bin2hex(random_bytes(6));mkdir($root,0700);
$checks=0;$fails=[];$check=static function(bool $ok,string $label)use(&$checks,&$fails){$checks++;if(!$ok)$fails[]=$label;};
$sources=[str_repeat('a',32),str_repeat('b',32),str_repeat('c',32)];
$seed=static function(string $dir)use($sources):SyncFailureBot {
    mkdir($dir,0700);$b=new SyncFailureBot($dir);$modules=new ProtocolModules($b->protocolModulesFile);
    foreach(array_keys(ManagedProtocol::NAMES)as$p){$b->protocolStore($p)->configure(['host'=>'vpn.example.test','sni'=>in_array($p,['mieru','snolc'],true)?'':'vpn.example.test'],true);$modules->set($p,true);}
    $clients=[];foreach($sources as$i=>$source)$clients[]=['id'=>sprintf('00000000-0000-4000-8000-%012d',$i+1),'protocol_source'=>$source,'email'=>'synthetic-'.$i,'traffic'=>$i===1?1000:0];
    ManagedProtocol::writeJson($b->xrayConf,['inbounds'=>[['settings'=>['clients'=>$clients]]]]);failureSync($b);
    foreach(array_keys(ManagedProtocol::NAMES)as$p){$store=$b->protocolStore($p);$rows=[];foreach($store->read()['users']as$id=>$u)$rows[$id]=['upload'=>10,'download'=>20,'reset'=>$u['reset']];ManagedProtocol::writeJson($store->directory().'/runtime/usage.json',['users'=>$rows]);}
    if(!failureSync($b))throw new RuntimeException('healthy sync control failed');return $b;
};
try {
    $fresh=new SyncFailureBot($root.'/fresh');mkdir($fresh->protocolRoot,0700,true);
    $check(failureSync($fresh),'fresh empty protocol root does not require an Xray configuration');
    $case=0;
    foreach(['anytls','masque']as$bad)foreach(['usage-json','usage-directory','usage-missing','desired-json','state-lock']as$fault)foreach([true,false]as$moduleEnabled)foreach(['disable','delete','rotate','expiry']as$operation){
        $b=$seed($root.'/case-'.++$case);$store=$b->protocolStore($bad);$dir=$store->directory();
        if(!$moduleEnabled)$store->configure([],false);
        $healthy=[];foreach(array_keys(ManagedProtocol::NAMES)as$p)if($p!==$bad)$healthy[$p]=failureUser($b->protocolStore($p),$sources[0])[1];
        $file=$dir.'/'.(str_starts_with($fault,'usage')?'runtime/usage.json':($fault==='desired-json'?'desired.json':'state.lock'));
        $saved=file_get_contents($file);unlink($file);
        if(in_array($fault,['usage-directory','state-lock'],true))mkdir($file);elseif($fault!=='usage-missing')file_put_contents($file,'{synthetic-invalid');
        $x=$b->getXray();$client=&$x['inbounds'][0]['settings']['clients'][0];
        if($operation==='disable')$client['off']=$client['id'];
        if($operation==='rotate')$client['id']=Bot::xrayUuid();
        if($operation==='expiry')$client['time']=time()-60;
        $expectedEpoch=ManagedProtocol::xrayCredential($client);unset($client);
        if($operation==='delete')array_shift($x['inbounds'][0]['settings']['clients']);
        $check($b->writeXrayJson(json_encode($x)),"$bad/$fault/$operation primary write control");
        $check(failureSync($b)===str_starts_with($fault,'usage'),"$bad/$fault/$operation access apply outcome distinguishes quota diagnostics");
        if(is_file($b->protocolRoot.'/xray-sync.status.json'))$check(!ManagedProtocol::readJson($b->protocolRoot.'/xray-sync.status.json')['complete'],"$bad/$fault diagnostics record partial state");
        foreach($healthy as$p=>$before){
            $user=failureUser($b->protocolStore($p),$sources[0]);
            $correct=match($operation){'delete'=>$user===null,'disable'=>$user!==null&&!$user[1]['enabled'],'rotate'=>$user!==null&&$user[1]['password']!==$before['password']&&$user[1]['xray_credential']===$expectedEpoch,'expiry'=>$user!==null&&$user[1]['expires']<=time()};
            $check($correct,"$bad/$fault/$operation reaches $p");
            $check(failureUser($b->protocolStore($p),$sources[2])[1]['enabled'],"$bad/$fault independent unlimited user stays enabled in $p");
            if($fault!=='state-lock')$check(!failureUser($b->protocolStore($p),$sources[1])[1]['enabled'],"$bad/$fault unknown common quota denied in $p");
        }
        if(in_array($fault,['desired-json','state-lock'],true))$check(is_file($dir.'/xray-sync.quarantine.json'),"$bad/$fault target quarantined");
        if(is_dir($file))rmdir($file);elseif(file_exists($file))unlink($file);file_put_contents($file,$saved);
        $check(failureSync($b),"$bad/$fault repaired target synchronizes");
        $check(!file_exists($dir.'/xray-sync.quarantine.json'),"$bad/$fault repaired target leaves quarantine only after sync");
    }
    $b=$seed($root.'/quota');file_put_contents($b->protocolStore('anytls')->directory().'/runtime/usage.json','{synthetic-invalid');
    $unknown=false;try{$b->xrayProtocolUsage($b->getXray()['inbounds'][0]['settings']['clients'][1]);}catch(RuntimeException$e){$unknown=true;}
    $check($unknown,'unknown aggregate is not returned as zero');
    try{$b->checkTrafficLimits();$check(true,'unknown usage enforcement completes');}catch(Throwable$e){$check(false,'unknown usage enforcement completes');}
    $clients=$b->getXray()['inbounds'][0]['settings']['clients'];
    $check(!empty($clients[1]['off'])&&!empty($clients[1]['traffic_usage_unavailable']),'VLESS limited access fails closed when aggregate is unknown');
    $check(empty($clients[0]['off'])&&empty($clients[2]['off']),'VLESS unlimited access independent of unavailable quota');
    $summary=[];try{$summary=$b->subscriptionCardSummary($clients[1],1);}catch(Throwable$e){$check(false,'unknown usage summary remains available');}
    $check(str_contains(implode(' ',$summary),'недоступен')&&!str_contains(implode(' ',$summary),'квота исчерпана'),'UI distinguishes unknown usage from exhausted quota');
    foreach(['disable','delete','rotate']as$operation){
        $b=$seed($root.'/race-'.$operation);file_put_contents($b->protocolStore('anytls')->directory().'/runtime/usage.json','{synthetic-invalid');
        $desc=[0=>['file','/dev/null','r'],1=>['file','/dev/null','w'],2=>['file','/dev/null','w']];
        $old=proc_open([PHP_BINARY,__FILE__,'worker',$b->fixture,'old'],$desc,$pipes);
        $end=microtime(true)+3;while(!is_file("$b->fixture/old-read")&&microtime(true)<$end)usleep(1000);
        $x=$b->getXray();$client=&$x['inbounds'][0]['settings']['clients'][0];
        if($operation==='disable')$client['off']=$client['id'];if($operation==='rotate')$client['id']=Bot::xrayUuid();$epoch=ManagedProtocol::xrayCredential($client);unset($client);
        if($operation==='delete')array_shift($x['inbounds'][0]['settings']['clients']);ManagedProtocol::writeJson($b->xrayConf,$x);
        $new=proc_open([PHP_BINARY,__FILE__,'worker',$b->fixture,'new'],$desc,$pipes);$oldCode=proc_close($old);$newCode=proc_close($new);
        $check($oldCode===0&&$newCode===0,"$operation parallel workers completed");
        foreach(['mieru','tuic','shadowtls','snolc','masque']as$p){$u=failureUser($b->protocolStore($p),$sources[0]);$check(match($operation){'delete'=>$u===null,'disable'=>$u!==null&&!$u[1]['enabled'],'rotate'=>$u!==null&&$u[1]['xray_credential']===$epoch},"$operation stale snapshot cannot undo $p update despite unrelated failure");}
    }
} finally {
    $remove=static function(string$path)use(&$remove){if(is_dir($path)&&!is_link($path)){foreach(scandir($path)as$f)if($f!=='.'&&$f!=='..')$remove("$path/$f");rmdir($path);}else unlink($path);};$remove($root);
}
foreach($fails as$label)echo "FAIL: $label\n";echo 'protocol_sync_failure_test: ',count($fails)," failure(s), $checks checks\n";exit($fails?1:0);
