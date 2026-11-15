<?php
// Actual PHP control flow, files and locks. SSH/core state is an explicit adapter.
require_once (getenv('VPNBOT_TEST_SOURCE') ?: dirname(__DIR__)) . '/app/bot.php';
class ClassicApplyBot extends Bot {
    public int $menus=0;
    public int $writes=0;
    public array $commands=[];
    public string $fault='';
    public bool $injected=false;
    public function __construct(public string $root) {
        $this->pac="$root/pac.json";$this->language='ru';$this->input=['chat'=>1,'message_id'=>1];
    }
    public function withLock(string $name,callable $fn,int $timeout=0,$busy=null) {
        $h=fopen("$this->root/.lock.$name",'c');if(!$h||!flock($h,LOCK_EX))return $busy;
        try{return $fn();}finally{flock($h,LOCK_UN);fclose($h);}
    }
    public function menu($type=false,$arg=false,$return=false){$this->menus++;}
    public function dnstt($update=false){$this->menus++;}
    public function protocolModuleEnabled(string $name):bool{return in_array($name,['ss','proxy','dnstt'],true);}
    public function sshHostKeyRememberDnstt():void{}
    public function warpSocksAllowSS(bool $on):bool{return true;}
    public function warpStatus(){return 'on';}
    public function ssWarpUrl():string{return 'socks5://127.0.0.1:1080';}
    public function getSSLocalConfig(){
        $config=parent::getSSLocalConfig();
        if(getenv('VPNBOT_CLASSIC_SLOW')){touch("$this->root/worker-in-apply");usleep(250000);}
        return $config;
    }
    public function setPacConf($data) {
        if($this->fault==='pac-write')throw new RuntimeException('synthetic PAC write failure');
        return parent::setPacConf($data);
    }
    public function writePrivateKey(string $path,string $body):bool {
        if($this->fault==='settings-write'&&str_ends_with($path,'settings.json'))return false;
        return parent::writePrivateKey($path,$body);
    }
    protected function backupWriteInPlace(string $path,string $body):bool {
        if(str_ends_with($path,'.json')&&in_array(basename($path),['ssserver.json','sslocal.json'],true)){
            $this->writes++;
            if(!$this->injected&&(($this->fault==='write-server'&&str_ends_with($path,'ssserver.json'))||($this->fault==='write-local'&&str_ends_with($path,'sslocal.json')))){
                $this->injected=true;file_put_contents($path,substr($body,0,7));return false;
            }
        }
        return parent::backupWriteInPlace($path,$body);
    }
    public function ssh($cmd,$service='wg',$wait=true,$log='/dev/null') {
        $this->commands[]=[$service,$cmd];$this->sshFailed=false;
        $lock=fopen("$this->root/.lock.pac",'c');if(!flock($lock,LOCK_EX|LOCK_NB))throw new RuntimeException('PAC held during SSH');flock($lock,LOCK_UN);fclose($lock);
        if($this->fault==='ssh'){$this->sshFailed=true;return 'VPNBOT_SERVICE_READY:ssserver';}
        if($this->fault==='missing-helper')return '';
        if(str_contains($cmd,'/service_supervisor.sh')){
            preg_match('~(start|stop|restart) (ssserver|sslocal)$~',$cmd,$m);if(!$m)throw new RuntimeException('unexpected synthetic service');
            [$all,$action,$name]=$m;
            if($this->fault===$action.'-'.$name)return '';
            if($action==='stop')file_put_contents("$this->root/runtime-$name",'stopped');
            else{ $cfg=json_decode(file_get_contents("$this->root/$name.json"),true);if(($cfg['method']??'')==='invalid-cipher')return '';file_put_contents("$this->root/runtime-$name",hash('sha256',$cfg['password'])); }
            if(getenv('VPNBOT_CLASSIC_SLOW')&&$action==='stop'&&$name==='ssserver'){touch("$this->root/worker-in-apply");usleep(250000);}
            return ($action==='stop'?'VPNBOT_SERVICE_STOPPED:':'VPNBOT_SERVICE_READY:').$name.($this->fault==='bad-marker'?' extra':'');
        }
        if(str_contains($cmd,'start_dnstt.sh --reload')){
            if($this->fault==='reload')return '';
            $settings=json_decode(file_get_contents("$this->root/dnstt/settings.json"),true);
            if(getenv('VPNBOT_CLASSIC_SLOW')){touch("$this->root/worker-in-apply");usleep(250000);}
            file_put_contents("$this->root/runtime-dnstt",json_encode($settings));
            return $this->fault==='bad-marker'?'prefix-dnstt-ready-suffix':'dnstt-ready';
        }
        // Original baseline uses these unacknowledged commands.
        if(preg_match('~^pkill (ssserver|sslocal)(?: |$)~',$cmd,$m)){
            if($this->fault!=='stop-'.$m[1])file_put_contents("$this->root/runtime-".$m[1],'stopped');return '';
        }
        if(preg_match('~(?:nohup setsid |^)(ssserver|sslocal) ~',$cmd,$m)){
            if($this->fault!=='start-'.$m[1]){ $cfg=json_decode(file_get_contents("$this->root/".$m[1].'.json'),true);if(($cfg['method']??'')==='invalid-cipher')return '';file_put_contents("$this->root/runtime-".$m[1],hash('sha256',(string)($cfg['password']??''))); }return '';
        }
        if(preg_match('~pgrep -x (ssserver|sslocal)~',$cmd,$m)&&str_contains($cmd,'VPNBOT_SERVICE_READY'))return file_get_contents("$this->root/runtime-".$m[1])==='stopped'?'':'VPNBOT_SERVICE_READY';
        throw new RuntimeException('unexpected command');
    }
}
class ClassicExportCaptured extends RuntimeException {}
class ClassicExportBot extends ClassicApplyBot {
    public array $pair=[];
    public function __construct(string $root){
        parent::__construct($root);$this->clients="$root/clients.json";$this->clients1="$root/clients1.json";$this->xrayConf="$root/absent-xray";$this->hwid="$root/absent-hwid";
        $this->protocolCertRoot="$root/no-certs";$this->adguard="$root/AdGuardHome.yaml";$this->hysteriaUsersRoot="$root/hysteria";
    }
    public function withOcUsersSnapshot(callable $fn){return ['telemt'=>['pac'=>[],'telemt_quota'=>null],'oc'=>'','ocu'=>''];}
    public function getHwidStorage(){return [];}
    public function getXray(){return ['inbounds'=>[]];}
    public function getXrayStats(){return ['users'=>[]];} // No Xray runtime in the SS snapshot fixture.
    public function getSSConfig(){
        $config=json_decode(file_get_contents("$this->root/ssserver.json"),true);$this->pair[]=$config;
        touch("$this->root/export-read");$end=microtime(true)+3;while(!is_file("$this->root/export-writer-start")&&microtime(true)<$end)usleep(1000);usleep(150000);return $config;
    }
    public function getSSLocalConfig(){
        $this->pair[]=json_decode(file_get_contents("$this->root/sslocal.json"),true);
        // Stop after the actual export captured its SS pair. Other protocols
        // and the final JSON encoding are outside this race fixture.
        throw new ClassicExportCaptured();
    }
}
function classicInvoke(callable $call):bool{try{return $call()!==false;}catch(Throwable $e){return false;}}
if(($argv[1]??'')==='worker'){
    $b=new ClassicApplyBot($argv[2]);$action=$argv[3];
    if(getenv('VPNBOT_CLASSIC_WAIT_EXPORT')){
        $end=microtime(true)+3;while(!is_file("$b->root/export-read")&&microtime(true)<$end)usleep(1000);
        touch("$b->root/export-writer-start");putenv('VPNBOT_CLASSIC_WAIT_EXPORT');
    }
    if($action==='ss')$ok=classicInvoke(fn()=>$b->sspwdch($argv[4],true));
    elseif($action==='warp')$ok=classicInvoke(fn()=>$b->ssWarp());
    elseif($action==='domain')$ok=classicInvoke(fn()=>$b->setdnsttDomain($argv[4]));
    else $ok=classicInvoke(fn()=>$b->setdnsttPassword($argv[4]));
    exit($ok?0:1);
}
$external=getenv('VPNBOT_CLASSIC_FIXTURE');
if($external&&($external!=='/config'||!is_file('/config/.synthetic-only')))throw new RuntimeException('isolated fixture required');
$root=$external?:sys_get_temp_dir().'/classic-apply-'.bin2hex(random_bytes(6));if(!$external)mkdir($root,0700);
$checks=0;$fails=[];$check=static function(bool $ok,string $label)use(&$checks,&$fails){$checks++;if(!$ok)$fails[]=$label;};
$seed=static function()use($root):ClassicApplyBot{
    foreach(['ssserver','sslocal']as$name){
        $config=['server'=>$name==='ssserver'?'0.0.0.0':'ss','server_port'=>8388,'method'=>'chacha20-ietf-poly1305','password'=>'synthetic-old'];
        if($name==='sslocal')$config+=['local_address'=>'127.0.0.1','local_port'=>1080];
        file_put_contents("$root/$name.json",json_encode($config));file_put_contents("$root/runtime-$name",hash('sha256','synthetic-old'));
    }
    if(!is_dir("$root/dnstt"))mkdir("$root/dnstt",0700);
    file_put_contents("$root/pac.json",json_encode(['dnsttDomain'=>'dns.example.test','dnsttPassword'=>'synthetic-old']));
    file_put_contents("$root/dnstt/settings.json",json_encode(['domain'=>'dns.example.test','password_hash'=>crypt('synthetic-old','$6$syntheticsalt$')]));
    file_put_contents("$root/runtime-dnstt",file_get_contents("$root/dnstt/settings.json"));
    return new ClassicApplyBot($root);
};
try{
    $b=$seed();
    $check(classicInvoke(fn()=>$b->withShadowsocksLock(fn()=>$b->withShadowsocksLock(fn()=>42))), 'SS scoped nested lock does not reacquire flock');
    classicInvoke(fn()=>$b->withShadowsocksLock(fn()=>throw new RuntimeException('synthetic nested failure')));
    $held=classicInvoke(fn()=>$b->withShadowsocksLock(function()use($root){$h=fopen("$root/.lock.shadowsocks",'c');$free=flock($h,LOCK_EX|LOCK_NB);fclose($h);return !$free;}));
    $check($held,'SS exception resets depth and next operation acquires actual lock');
    foreach(['ssh','missing-helper','bad-marker','stop-ssserver','stop-sslocal','start-ssserver','start-sslocal','write-server','write-local']as$fault){
        $b=$seed();$b->fault=$fault;$before=[];$inodes=[];foreach(['ssserver','sslocal']as$n){$before[$n]=file_get_contents("$root/$n.json");$inodes[$n]=fileinode("$root/$n.json");}
        $check(!classicInvoke(fn()=>$b->sspwdch('synthetic-new')),"SS $fault returns failure");$check($b->menus===0,"SS $fault does not show success menu");
        foreach($before as$n=>$raw){clearstatcache();$check(file_get_contents("$root/$n.json")===$raw,"SS $fault restores $n file");$check(fileinode("$root/$n.json")===$inodes[$n],"SS $fault retains $n inode");}
        if(in_array($fault,['start-ssserver','start-sslocal','write-server','write-local'],true))foreach(['ssserver','sslocal']as$n)$check(file_get_contents("$root/runtime-$n")==='stopped',"SS $fault never restarts old credentials in $n");
    }
    foreach([null,"bad\0password",'']as$pass){$b=$seed();$check(!classicInvoke(fn()=>$b->sspwdch($pass)), 'SS invalid password rejected');$check(!$b->commands,'SS invalid password keeps running services');}
    $b=$seed();file_put_contents("$root/sslocal.json",'{synthetic-invalid');$check(!classicInvoke(fn()=>$b->sspwdch('synthetic-new')),'SS corrupt pair rejected');$check(!$b->commands,'SS corrupt pair is rejected before stop');
    $b=$seed();$inode=fileinode("$root/ssserver.json");$check(classicInvoke(fn()=>$b->sspwdch('synthetic-new')),'SS positive apply control');
    foreach(['ssserver','sslocal']as$n){$check(file_get_contents("$root/runtime-$n")===hash('sha256','synthetic-new'),"SS $n applies new credentials");$check((fileperms("$root/$n.json")&0777)===0600,"SS $n remains private");}
    clearstatcache();$check(fileinode("$root/ssserver.json")===$inode,'SS positive inode control');$check($b->menus===1,'SS positive success menu');
    foreach(['ssh','reload','bad-marker','settings-write','pac-write']as$fault)foreach(['synthetic-new','']as$password){
        $b=$seed();$b->fault=$fault;$check(!classicInvoke(fn()=>$b->setdnsttPassword($password)),"DNSTT $fault change/disable fails");$check($b->menus===0,"DNSTT $fault no success menu");
        if($fault!=='pac-write')$check(!empty($b->getPacConf()['dnstt_apply_pending']),"DNSTT $fault remains explicitly pending");
    }
    foreach(['ssh','reload','settings-write','pac-write']as$fault)foreach(['new.example.test','']as$domain){
        $b=$seed();$b->fault=$fault;$check(!classicInvoke(fn()=>$b->setdnsttDomain($domain)),"DNSTT $fault domain change/disable fails");$check($b->menus===0,"DNSTT $fault domain no success menu");
    }
    $b=$seed();$check(classicInvoke(fn()=>$b->setdnsttDomain('new.example.test')),'DNSTT positive domain control');$check(json_decode(file_get_contents("$root/runtime-dnstt"),true)['domain']==='new.example.test','DNSTT new domain applied');
    foreach(['synthetic-new','']as$password){$b=$seed();$check(classicInvoke(fn()=>$b->setdnsttPassword($password)),'DNSTT positive change/disable control');$settings=json_decode(file_get_contents("$root/runtime-dnstt"),true);$check($password===''?$settings===[]:password_verify($password,$settings['password_hash']),'DNSTT applied hash/disabled control');$check(empty($b->getPacConf()['dnstt_apply_pending']),'DNSTT success clears pending');}
    foreach(['ss','dnstt']as$kind){
        $b=$seed();@unlink("$root/worker-in-apply");$desc=[0=>['file','/dev/null','r'],1=>['file','/dev/null','w'],2=>['file','/dev/null','w']];
        putenv('VPNBOT_CLASSIC_SLOW=1');$first=proc_open([PHP_BINARY,__FILE__,'worker',$root,$kind,'synthetic-first'],$desc,$pipes);putenv('VPNBOT_CLASSIC_SLOW');
        $end=microtime(true)+3;while(!is_file("$root/worker-in-apply")&&microtime(true)<$end)usleep(1000);
        $second=proc_open([PHP_BINARY,__FILE__,'worker',$root,$kind,'synthetic-last'],$desc,$pipes);$a=proc_close($first);$z=proc_close($second);
        $check($a===0&&$z===0,"$kind concurrent workers finish");
        if($kind==='ss')foreach(['ssserver','sslocal']as$n)$check(file_get_contents("$root/runtime-$n")===hash('sha256','synthetic-last')&&json_decode(file_get_contents("$root/$n.json"),true)['password']==='synthetic-last',"SS concurrent applied/saved $n match");
        else{$settings=json_decode(file_get_contents("$root/runtime-dnstt"),true);$check(password_verify('synthetic-last',$settings['password_hash'])&&$b->getPacConf()['dnsttPassword']==='synthetic-last','DNSTT concurrent applied/PAC match');}
    }
    $b=$seed();foreach(['export-read','export-writer-start']as$f)@unlink("$root/$f");
    foreach([0,1]as$n)file_put_contents("$root/wg$n.conf","[Interface]\nAddress = 10.0.$n.1/24\n");
    file_put_contents("$root/AdGuardHome.yaml","dns: {}\n");file_put_contents("$root/hysteria.yaml","listen: :443\n");
    $desc=[0=>['file','/dev/null','r'],1=>['file','/dev/null','w'],2=>['file','/dev/null','w']];
    putenv('VPNBOT_CLASSIC_WAIT_EXPORT=1');$writer=proc_open([PHP_BINARY,__FILE__,'worker',$root,'ss','synthetic-new'],$desc,$pipes);putenv('VPNBOT_CLASSIC_WAIT_EXPORT');
    $export=new ClassicExportBot($root);$captured=false;try{$export->export();}catch(ClassicExportCaptured$e){$captured=true;}catch(Throwable$e){}
    $check($captured,'actual export reaches SS snapshot');$check(proc_close($writer)===0,'concurrent export writer completes');
    $check(count($export->pair)===2&&$export->pair[0]['password']===$export->pair[1]['password'],'actual export cannot mix old/new SS pair');
    $b=$seed();$backup=new ReflectionMethod(Bot::class,'restoreBackupShadowsocks');
    $configs=['ss'=>json_decode(file_get_contents("$root/ssserver.json"),true),'sl'=>json_decode(file_get_contents("$root/sslocal.json"),true)];
    $before=['ssserver'=>file_get_contents("$root/ssserver.json"),'sslocal'=>file_get_contents("$root/sslocal.json")];
    $configs['ss']['password']=$configs['sl']['password']='synthetic-restored';$configs['sl']['method']='invalid-cipher';
    $applyBackup=static function(array $sections)use($backup,$b){
        if($backup->getNumberOfParameters()===1)return $backup->invoke($b,$sections);
        $ok=true;foreach($sections as$key=>$value)if(!$backup->invoke($b,$key,$value))$ok=false;return $ok;
    };
    $check(!classicInvoke(fn()=>$applyBackup($configs)),'SS backup rejected second service propagates failure');
    foreach($before as$n=>$raw){$check(file_get_contents("$root/$n.json")===$raw,"SS backup pair rollback restores $n");$check(file_get_contents("$root/runtime-$n")===hash('sha256','synthetic-old'),"SS backup explicitly restores old $n generation");}
    foreach(['ss','sl']as$only){$b=$seed();$cfg=json_decode(file_get_contents("$root/".($only==='ss'?'ssserver':'sslocal').'.json'),true);$cfg['password']='synthetic-restored';
        $ok=$backup->getNumberOfParameters()===1?$backup->invoke($b,[$only=>$cfg]):$backup->invoke($b,$only,$cfg);
        $check($ok,"SS backup supports legacy $only section alone");
    }
    foreach(['ss'=>'warp','dnstt'=>'domain']as$firstKind=>$secondKind){
        $b=$seed();@unlink("$root/worker-in-apply");$desc=[0=>['file','/dev/null','r'],1=>['file','/dev/null','w'],2=>['file','/dev/null','w']];
        putenv('VPNBOT_CLASSIC_SLOW=1');$first=proc_open([PHP_BINARY,__FILE__,'worker',$root,$firstKind,'synthetic-first'],$desc,$pipes);putenv('VPNBOT_CLASSIC_SLOW');
        $end=microtime(true)+3;while(!is_file("$root/worker-in-apply")&&microtime(true)<$end)usleep(1000);
        $check(is_file("$root/worker-in-apply"),"$firstKind actual overlap barrier reached");
        $second=proc_open([PHP_BINARY,__FILE__,'worker',$root,$secondKind,'new.example.test'],$desc,$pipes);
        $check(proc_close($first)===0&&proc_close($second)===0,"$firstKind mixed workers finish");
        if($firstKind==='ss'){$cfg=json_decode(file_get_contents("$root/ssserver.json"),true);$check($cfg['password']==='synthetic-first'&&!empty($cfg['outbound_proxy']),'SS concurrent WARP and password both preserved');}
        else{$settings=json_decode(file_get_contents("$root/runtime-dnstt"),true);$check(password_verify('synthetic-first',$settings['password_hash'])&&$settings['domain']==='new.example.test','DNSTT concurrent domain/password both applied');}
    }
}finally{
    $remove=static function($p)use(&$remove){if(is_dir($p)&&!is_link($p)){foreach(scandir($p)as$f)if($f!=='.'&&$f!=='..')$remove("$p/$f");rmdir($p);}else unlink($p);};
    if(!$external)$remove($root);
}
foreach($fails as$f)echo "FAIL: $f\n";echo 'classic_proxy_apply_test: ',count($fails)," failure(s), $checks checks\n";exit($fails?1:0);
