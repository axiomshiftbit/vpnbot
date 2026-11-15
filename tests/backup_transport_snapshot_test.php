<?php
// Real files, flock and independent PHP processes. Only absolute fixture paths,
// unrelated backup sections and SSH are adapted; no real tunnel is claimed.
$source = getenv('VPNBOT_TEST_SOURCE') ?: dirname(__DIR__);
$worker = ($argv[1] ?? '') === 'worker';
$root = $worker ? $argv[2] : sys_get_temp_dir() . '/backup-transport-' . bin2hex(random_bytes(6));
if (!$worker) mkdir($root, 0700);
$code = file_get_contents($source . '/app/bot.php');
$code = str_replace('__DIR__', var_export($source . '/app', true), $code);
$code = str_replace("'/config/", "'" . $root . '/', $code);
$adapter = tempnam($root, 'source-'); file_put_contents($adapter, $code);
require $adapter;
if (!function_exists('yaml_parse_file')) { function yaml_parse_file($path) { return []; } }
class TransportSnapshotBot extends Bot {
    public string $fault = '';
    public bool $moduleEnabled = true;
    public bool $injected = false;
    public bool $activeWrite = false;
    public bool $rpcLocks = true;
    public array $actions = [];
    public string $race = '';
    public bool $blocked = false;
    public $child = null;
    public function __construct(public string $root) {
        $this->pac="$root/pac.json"; $this->clients="$root/clients.json"; $this->clients1="$root/clients1.json";
        $this->xrayConf="$root/xray.json"; $this->hwid="$root/hwid.json"; $this->adguard="$root/adguard.yaml";
        $this->protocolCertRoot="$root/certs"; $this->hysteriaUsersRoot="$root/hysteria"; $this->managedNodeRoot="$root/nodes";
        $this->backupWarpRoot="$root/warp"; $this->telemtDecoyDir="$root/decoy"; $this->htpasswd="$root/web/passwords";
        $this->language='ru'; $this->ip='192.0.2.1';
    }
    public function withLock(string $name, callable $fn, int $timeout=0, $busy=null) {
        $h=fopen("$this->root/.lock.$name",'c'); if (!$h || !flock($h,LOCK_EX)) return $busy;
        try { return $fn(); } finally { flock($h,LOCK_UN); fclose($h); }
    }
    public function store(): ?PDO { return null; }
    public function menu($type=false,$arg=false,$return=false) {}
    public function getPorts() { return ['wg'=>['port'=>51820],'wg1'=>['port'=>51821]]; }
    public function protocolModuleEnabled(string $name): bool { return $name==='ss' && $this->moduleEnabled; }
    public function managedNodeBackupRefresh(): void {}
    public function getHwidStorage() { return []; }
    public function exportOvpnPki(bool $locked=false) { return []; }
    public function exportIpsecPki() { return []; }
    public function ovpnLimitsSnapshot(): array { return []; }
    public function exportManagedProtocols(): array { return []; }
    public function validateBackup(array $json): void {}
    public function withOcUsersSnapshot(callable $fn) {
        if ($this->race==='wg-export') { $this->startWorker('wg'); $this->finishWorker(); }
        return ['telemt'=>['pac'=>$this->getPacConf(),'telemt_quota'=>null],'oc'=>'synthetic','ocu'=>''];
    }
    public function backupExtraFiles(): array {
        if ($this->race==='ss-export') { $this->startWorker('ss'); $this->finishWorker(); }
        return parent::backupExtraFiles();
    }
    public function startWorker(string $action): void {
        $this->child=proc_open([PHP_BINARY,__FILE__,'worker',$this->root,$action],[0=>['file','/dev/null','r'],1=>['file','/dev/null','w'],2=>['file','/dev/null','w']],$pipes);
        if (!is_resource($this->child)) throw new RuntimeException('Could not start synthetic worker');
    }
    public function finishWorker(): void {
        if (!is_resource($this->child)) return;
        $deadline=microtime(true)+8;
        do { $state=proc_get_status($this->child); if (!$state['running']) break; usleep(1000); } while (microtime(true)<$deadline);
        if ($state['running']) { proc_terminate($this->child,9); proc_close($this->child); $this->child=null; throw new RuntimeException('Synthetic worker timed out'); }
        proc_close($this->child); $this->child=null;
        if ($state['exitcode']!==0) throw new RuntimeException('Synthetic worker failed');
    }
    public function writePrivateKey(string $path,string $body): bool {
        if ($path==="$this->root/stlsserver.json") {
            $this->activeWrite |= @file_get_contents("$this->root/runtime")==='on';
            if ($this->race==='stls-restore' && !$this->injected) {
                $this->injected=true; $this->startWorker('sni'); $end=microtime(true)+3;
                while (!is_file("$this->root/attempted") && microtime(true)<$end) usleep(1000);
                usleep(150000); $this->blocked=!is_file("$this->root/done");
            }
            if (in_array($this->fault,['write','published-write'],true) && !$this->injected) {
                $this->injected=true;
                if ($this->fault==='published-write') parent::writePrivateKey($path,$body);
                return false;
            }
        }
        return parent::writePrivateKey($path,$body);
    }
    public function ssh($cmd,$service='wg',$wait=true,$log='/dev/null') {
        $this->sshFailed=false;
        if (!preg_match('~^/bin/sh /service_supervisor.sh (start|stop|restart) (simple-tls|ck-server)$~',$cmd,$m)) throw new RuntimeException('Unexpected synthetic RPC');
        foreach (["$this->root/.lock.pac","$this->root/nodes/.retired.lock"] as $path) {
            if (!is_dir(dirname($path))) mkdir(dirname($path),0700,true);
            $h=fopen($path,'c'); $free=flock($h,LOCK_EX|LOCK_NB); $this->rpcLocks &= $free; fclose($h);
        }
        $h=fopen("$this->root/.lock.shadowsocks",'c'); $this->rpcLocks &= !flock($h,LOCK_EX|LOCK_NB); fclose($h);
        $this->actions[]=$m[1];
        if ($this->fault==='stop' && $m[1]==='stop') return '';
        if ($this->fault==='ssh') { $this->sshFailed=true; return 'VPNBOT_SERVICE_STOPPED:'.$m[2]; }
        if ($this->fault==='start' && $m[1]==='start' && !$this->injected) { $this->injected=true; file_put_contents("$this->root/runtime",'on'); return ''; }
        if ($m[2]==='simple-tls') file_put_contents("$this->root/runtime",$m[1]==='stop'?'off':'on');
        return ($m[1]==='stop'?'VPNBOT_SERVICE_STOPPED:':'VPNBOT_SERVICE_READY:').$m[2];
    }
}
function transportSeed(string $root): TransportSnapshotBot {
    foreach (['attempted','done'] as $n) @unlink("$root/$n");
    foreach (['ssserver','sslocal'] as $name) file_put_contents("$root/$name.json",json_encode(['method'=>'chacha20-ietf-poly1305','password'=>'synthetic-only','server_port'=>8388]));
    file_put_contents("$root/stlsserver.json",json_encode(['Enabled'=>1,'ServerName'=>'before.example.test']));
    file_put_contents("$root/ckserver.json",'{"Enabled":0}'); file_put_contents("$root/ckusers.json",'[]');
    file_put_contents("$root/pac.json",'{"wg1_amnezia":0,"domain":"example.test","unrelated":"preserve"}');
    foreach ([0,1] as $i) {
        file_put_contents("$root/wg$i.conf","[Interface]\nAddress = 10.0.$i.1/24\nListenPort = ".(51820+$i)."\n");
        file_put_contents($i?"$root/clients1.json":"$root/clients.json",'[{"name":"before"}]');
    }
    file_put_contents("$root/xray.json",'{"inbounds":[{"settings":{"clients":[]}}]}');
    file_put_contents("$root/xray.stats",'{"_schema":1,"global":{"upload":0,"download":0},"session":{"upload":0,"download":0},"users":[]}'); file_put_contents("$root/hwid.json",'{}');
    file_put_contents("$root/adguard.yaml",'{}'); file_put_contents("$root/hysteria.yaml",'{}');
    file_put_contents("$root/runtime",'on');
    return new TransportSnapshotBot($root);
}
function transportCall(callable $fn): bool { try { return $fn()!==false; } catch (Throwable $error) { return false; } }
if ($worker) {
    try {
        $b=new TransportSnapshotBot($root);
        if ($argv[3]==='sni') { touch("$root/attempted"); $b->chStlsSNI('concurrent.example.test'); touch("$root/done"); }
        elseif ($argv[3]==='ss') { $b->simpleTls(); }
        else {
            foreach ([0,1] as $i) {
                $b->wg=$i;
                $ok=(new ReflectionMethod(Bot::class,'restoreBackupWireGuard'))->invoke($b,['server'=>['interface'=>['Address'=>"10.1.$i.1/24",'ListenPort'=>53000+$i]],'clients'=>[['name'=>'after']]],1,true);
                if (!$ok) throw new RuntimeException('Synthetic WG restore failed');
            }
            $b->pacConfUpdate(function (&$pac) { $pac['concurrent']='preserved'; });
        }
        exit(0);
    } catch (Throwable $error) { exit(1); }
    finally { @unlink($adapter); }
}
$checks=0; $failures=[];
$check=static function(bool $ok,string $name) use (&$checks,&$failures) { $checks++; if (!$ok) $failures[]=$name; };
$new=['stlsserver.json'=>base64_encode('{"Enabled":1,"ServerName":"restore.example.test"}')];
try {
    foreach (['stop','ssh','write','published-write','start'] as $fault) {
        $b=transportSeed($root); $b->fault=$fault; $old=file_get_contents("$root/stlsserver.json");
        $ok=transportCall(fn()=>$b->restoreBackupExtraFiles($new));
        $check(!$ok,"$fault: failure is explicit");
        $check(file_get_contents("$root/stlsserver.json")===$old,"$fault: old file preserved or rolled back");
        $check(file_get_contents("$root/runtime")==='on',"$fault: previous runtime preserved or restarted");
        $check(!$b->activeWrite,"$fault: no write while old runtime active");
        $check($b->rpcLocks,"$fault: SS held and PAC/node locks free during RPC");
    }
    $b=transportSeed($root); $check(transportCall(fn()=>$b->restoreBackupExtraFiles($new)),'standalone positive restore');
    $check($b->actions===['stop','start'] && !$b->activeWrite && $b->rpcLocks,'standalone checked stop write start lock contract');
    $check($b->getStlsConfig()['ServerName']==='restore.example.test','standalone restored content');
    $b=transportSeed($root); $b->moduleEnabled=false;
    $check(transportCall(fn()=>$b->restoreBackupExtraFiles($new)) && !$b->actions && $b->getStlsConfig()['ServerName']==='restore.example.test','disabled module stores without requiring RPC');
    $b=transportSeed($root); $old=file_get_contents("$root/stlsserver.json");
    $check(transportCall(fn()=>$b->restoreBackupExtraFiles([])) && !$b->actions && file_get_contents("$root/stlsserver.json")===$old,'legacy absent STLS leaves state unchanged');
    $b=transportSeed($root); $off=['stlsserver.json'=>base64_encode('{"Enabled":0}')];
    $check(transportCall(fn()=>$b->restoreBackupExtraFiles($off)) && file_get_contents("$root/runtime")==='off','disabled restore proves stop');
    $b=transportSeed($root); $old=file_get_contents("$root/stlsserver.json");
    $check(!transportCall(fn()=>$b->restoreBackupExtraFiles(['stlsserver.json'=>base64_encode('{')])) && !$b->actions && file_get_contents("$root/stlsserver.json")===$old,'invalid input validated before stop');
    $b=transportSeed($root); $b->race='stls-restore';
    $check(transportCall(fn()=>$b->restoreBackupExtraFiles($new)),'concurrent restore completed'); $b->finishWorker();
    $check($b->blocked && is_file("$root/done"),'concurrent SNI writer waits for restore apply lock');
    $check($b->getStlsConfig()['ServerName']==='concurrent.example.test','concurrent later SNI mutation preserved');
    $b=transportSeed($root); $failed=(new ReflectionMethod(Bot::class,'restoreBackupExtraServices'))->invoke($b,$new);
    $check($failed===[] && $b->getStlsConfig()['ServerName']==='restore.example.test','late full restore writes captured STLS section');
    $b=transportSeed($root); $b->fault='stop'; $failed=(new ReflectionMethod(Bot::class,'restoreBackupExtraServices'))->invoke($b,$new);
    $check($failed===['simple-tls'] && $b->getStlsConfig()['ServerName']==='before.example.test','late full restore reports service failure without early write');
    $b=transportSeed($root); file_put_contents("$root/ckserver.json",'{"Enabled":1}'); file_put_contents("$root/stlsserver.json",'{"Enabled":0}'); $b->race='ss-export';
    $dump=json_decode((new ReflectionMethod(Bot::class,'exportBackup'))->invoke($b),true,512,JSON_THROW_ON_ERROR);
    $stls=json_decode(base64_decode($dump['extra_files']['stlsserver.json']),true);
    $check(!empty($dump['cloak']['Enabled']) && empty($stls['Enabled']),'export preserves one SS Cloak STLS generation');
    $check(empty($b->getCloakConfig()['Enabled']) && !empty($b->getStlsConfig()['Enabled']),'export race control actual concurrent transport toggle completed');
    $b=transportSeed($root); file_put_contents("$root/ckserver.json",'{"Enabled":1}'); unlink("$root/stlsserver.json"); $b->race='ss-export';
    $dump=json_decode((new ReflectionMethod(Bot::class,'exportBackup'))->invoke($b),true,512,JSON_THROW_ON_ERROR);
    $check(!isset($dump['extra_files']['stlsserver.json']) && is_file("$root/stlsserver.json"),'export preserves STLS absence despite later concurrent creation');
    $b=transportSeed($root); $b->race='wg-export';
    $dump=json_decode((new ReflectionMethod(Bot::class,'exportBackup'))->invoke($b),true,512,JSON_THROW_ON_ERROR);
    $check(!array_key_exists('amnezia',$dump['pac']) && $dump['pac']['wg1_amnezia']===0,'WG modes captured per instance and absence retained');
    $check($dump['wg']['server']['interface']['ListenPort']==51820 && $dump['wg1']['server']['interface']['ListenPort']==51821,'WG files are original locked generation');
    $check($dump['wg']['clients'][0]['name']==='before' && $dump['wg1']['clients'][0]['name']==='before'
        && json_decode(file_get_contents($b->clients),true)[0]['name']==='after' && json_decode(file_get_contents($b->clients1),true)[0]['name']==='after','WG clients travel with captured server generation');
    $check(array_keys($dump['wg'])===['server','clients'] && array_keys($dump['wg1'])===['server','clients'],'WG serialized schema unchanged');
    $now=$b->getPacConf(); $check($now['amnezia']===1 && $now['wg1_amnezia']===1 && $dump['pac']['concurrent']==='preserved','WG race control restores both instances and preserves other PAC updates');
} catch (Throwable $error) {
    // Exception class/line only; configs, credentials and HTML never reach output.
    $failures[]='fixture exception '.get_class($error).' at line '.$error->getLine();
} finally {
    if (isset($b)) { try { $b->finishWorker(); } catch (Throwable $ignored) {} }
    $it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($it as $p) { if ($p->isDir()&&!$p->isLink()) rmdir($p->getPathname()); else unlink($p->getPathname()); } rmdir($root);
}
foreach ($failures as $name) echo "FAIL: $name\n";
echo count($failures).' failure(s), '.$checks." checks\n";
exit($failures?1:0);
