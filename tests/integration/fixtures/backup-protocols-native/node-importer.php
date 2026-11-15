<?php
// Call inside the existing disposable managed-main fixture after peer-export.
// The common importer is real; irrelevant frontend callbacks have no services
// in this controller-only fixture. Pinned SSH, node RPC and Xray payload are real.
if (!is_file('/work/pac.json') || !is_file('/work/core.json') || !is_file('/work/peer-outbound.json')) exit(2);
define('VPNBOT_MANAGED_NATIVE_LIBRARY',true);
require '/lab/tests/integration/fixtures/managed-node-main.php';
class NativeManagedImporter extends NativeManagedBot {
    public function __construct(){parent::__construct();$this->clients='/work/clients.json';$this->clients1='/work/clients1.json';$this->protocolModulesFile='/work/protocol-services.json';}
    // This fixture has only the controller's Xray and remote node. Full stand
    // coverage separately checks readiness of the other restored protocols.
    public function protocolModuleEnabled(string $service): bool { return $service === 'xr'; }
    public function restartNaive(){return true;}
    public function pacUpdate($import=''){}
    public function setUpstreamDomainOcserv($domain){}
    public function setUpstreamDomainNaive($domain){}
    public function dnsttStart(){return true;}
    public function cloakNginx(){return true;}
}
$b=new NativeManagedImporter();$checks=[];$saved=false;$restored=false;$path='/work/node-importer-backup.json';
$check=static function($ok,$name)use(&$checks){$checks[$name]=(bool)$ok;echo($ok?'PASS ':'FAIL ').'node-importer-'.$name.PHP_EOL;if(!$ok)throw new RuntimeException('native assertion');};
try {
    $node=$b->managedNodes()['aabbccdd']??[];
    $check(!empty($node['connected'])&&empty($node['job']),'connected_settled_node');
    $check($b->transport('rpc',['action'=>'ping'])===['schema'=>1],'pinned_rpc_before');
    $b->testProbePort=10873;$check($b->exitProbe('aabbccdd')['ok'],'old_external_profile_payload_before');$b->testProbePort=0;
    $original=$b->getPacConf();$pac=$original+['language'=>'ru','limitpage'=>5];
    $extra=$b->backupExtraFiles();$profile=hash_file('sha256','/work/peer-outbound.json');
    $check(count(array_filter(array_keys($extra),fn($name)=>str_starts_with($name,'nodes/aabbccdd/')))===4,'confirmed_node_identity_and_snapshot_exported');
    $check(file_put_contents($path,json_encode(['pac'=>$pac,'extra_files'=>$extra],JSON_THROW_ON_ERROR))!==false&&chmod($path,0600),'private_backup_saved');$saved=true;
    foreach(glob('/ssh/nodes/aabbccdd/*')as$file){if(is_link($file)||!is_file($file))throw new RuntimeException('unexpected fixture entry');unlink($file);}rmdir('/ssh/nodes/aabbccdd');
    $b->setPacConf(['language'=>'ru','limitpage'=>5,'xray_core'=>'origin']);
    $denied=false;try{$b->transport('rpc',['action'=>'ping']);}catch(Throwable $e){$denied=true;}
    $check($denied,'fresh_controller_has_no_rpc_identity');
    $check($b->importCliFile($path)===true,'common_importer_restores_node_pac_and_files');$restored=true;
    $check($b->transport('rpc',['action'=>'ping'])===['schema'=>1],'restored_controller_pinned_rpc');
    $check($b->managedNodes()['aabbccdd']['connected']===true,'connected_metadata_restored');
    $check($b->restartXray($b->getXray()),'restored_controller_routes_apply');
    $check($b->exitProbe('aabbccdd')['ok'],'restored_controller_payload');
    $b->testProbePort=10873;$check($b->exitProbe('aabbccdd')['ok'],'old_external_profile_payload_after');
    $check(hash_file('sha256','/work/peer-outbound.json')===$profile,'external_profile_not_regenerated');
    $b->setPacConf($original);unlink($path);
    echo json_encode(['ok'=>true,'checks'=>$checks]),"\n";
}catch(Throwable $e){
    if($saved&&!$restored){try{$restored=$b->importCliFile($path)===true;}catch(Throwable $ignored){}}
    if($restored&&isset($original))$restored=$b->setPacConf($original)!==false;
    echo json_encode(['ok'=>false,'checks'=>$checks,'controller_recovered'=>$restored,'error_type'=>get_class($e),'line'=>$e->getLine()]),"\n";exit(1);
}
