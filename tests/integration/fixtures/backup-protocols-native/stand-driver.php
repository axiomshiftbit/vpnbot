<?php
// ONLY the synthetic bootstrap stand; never print exported contents/credentials.
if (getenv('TELEGRAM_API') !== 'tg-audit:8443') exit(2);
require '/app/config.php'; require '/app/bot.php'; require '/app/i18n.php';
umask(0077);
$b=new Bot($c['key'],$i);$b->admin=true;$b->input=['chat'=>1,'from'=>1,'message_id'=>1,'callback_id'=>'synthetic','username'=>'audit'];
$b->transport=new class {
    public array $messages=[];
    public function call($method,$data,$json=0){if(isset($data['text']))$this->messages[]=$data['text'];return ['ok'=>true,'result'=>['message_id'=>1]];}
};
$dir='/logs/audit-backup-protocols-native';$checks=[];
function checkNative(bool $ok,string $name):void{global $checks;$checks[$name]=$ok;if(!$ok)throw new RuntimeException('native assertion');}
try {
 switch($argv[1]??'') {
  case 'save':
   checkNative(!file_exists($dir),'exclusive_fixture_directory');checkNative(mkdir($dir,0700),'fixture_directory');
   foreach(['oc','ipsec']as$service)checkNative($b->protocolModuleEnabled($service),'enabled_'.$service);
   checkNative(isset($b->getIkev2Users()['auditike']),'existing_ike_identity');
   checkNative(isset($b->getPacConf()['ocserv_users']['auditoc']),'existing_oc_identity');
   $copy=$b->export();checkNative(is_string($copy),'full_backup_export');
   checkNative(file_put_contents("$dir/full.json",$copy)!==false,'full_backup_saved');
   $snapshot=json_decode($copy,true,128,JSON_THROW_ON_ERROR);
   foreach(['wg','wg1','ipsec','oc','ocu','pac']as$key)checkNative(!empty($snapshot[$key]),'saved_'.$key);
   foreach([0,1]as$instance){$b->wg=$instance;$users=$b->readClients();checkNative(!empty($users[0]),'old_wg_client_'.$instance);file_put_contents("$dir/wg$instance.conf",$b->createConfig($users[0]));$types[$instance]=$b->getWGType();}
   file_put_contents("$dir/client-meta.json",json_encode(['wg_types'=>$types,'oc_host'=>$b->getHashSubdomain('oc').'.vpnbot.test','oc_password'=>$b->getPacConf()['ocserv_users']['auditoc']]));
   break;
  case 'clear-users':
   checkNative(is_file("$dir/full.json"),'backup_present');
   foreach(['wg','wg1']as$service){
    $check=$b->withWireguardUpdate(function()use($b,$service){$config=$b->readConfig();$config['peers']=[];if(!$b->restartWG($b->createConfig($config)))return false;return $b->saveClients([])!==false;},$service);
    checkNative($check,'empty_native_peers_'.$service);
   }
   $b->disableIkev2User('auditike');
   checkNative(empty($b->getIkev2Status()['auditike']),'old_ike_session_closed');
   // Only the fixture's synthetic users, no production files or keys.
   checkNative($b->writePrivateKey($b->ipsecPaths()['users'],'{}'),'empty_ike_user_store');
   checkNative($b->restartIpsec()===true,'empty_ike_store_applied');
   $index=array_search('auditoc',$b->getClientsOc(),true);if($index!==false)$b->deloc($index);
   checkNative(!isset($b->getPacConf()['ocserv_users']['auditoc']),'old_oc_user_removed');
   break;
  case 'restore':
  case 'restore-failure':
   $expected=($argv[1]==='restore');$result=$b->importCliFile("$dir/full.json");
   checkNative($result===$expected,'full_import_result');
   $success=(bool)array_filter($b->transport->messages,fn($m)=>str_contains($m,$b->i18n('backup restore completed')));
   checkNative($success===$expected,'no_false_global_success');
   break;
  default:throw new RuntimeException('unknown action');
 }
 echo json_encode(['ok'=>true,'checks'=>$checks]),"\n";
}catch(Throwable $e){echo json_encode(['ok'=>false,'checks'=>$checks,'error_type'=>get_class($e),'line'=>$e->getLine()]),"\n";exit(1);}
