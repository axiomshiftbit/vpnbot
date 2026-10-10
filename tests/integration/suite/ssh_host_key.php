<?php
// Проверка ключей узлов на живом стенде: бот подключается к каждому сервису.
require '/app/config.php'; require '/app/bot.php'; require '/app/i18n.php'; require '/app/calc.php';
$warnings=[];
set_error_handler(function($s,$m) use (&$warnings){if(error_reporting()&$s)$warnings[]=$m;return true;});
$b=new Bot($c['key'],$i);$b->language='ru';$b->admin=true;
$result=[];
foreach(array_slice($argv,1) as $service){
 $reachable=$b->protocolModuleEnabled($service) && $b->tcpProbe($service,22,1.0)['ok'];
 $out=$reachable ? $b->ssh('printf VPNBOT_HOST_KEY_OK',$service) : '';
 // Ключ, который сервис отдаёт на самом деле: подмена в проверке должна быть настоящей.
 $served='';
 if($reachable && ($probe=@ssh2_connect($service,22,['hostkey'=>'ssh-ed25519']))){$served=bin2hex((string)ssh2_fingerprint($probe,SSH2_FINGERPRINT_SHA1|SSH2_FINGERPRINT_RAW));ssh2_disconnect($probe);}
 $result[$service]=['reachable'=>$reachable,'ok'=>$out==='VPNBOT_HOST_KEY_OK','failed'=>$b->sshFailed,'served'=>$served,
  'pinned'=>is_file($b->sshHostKeys."/$service/ssh_host_ed25519_key.pub")];
}
echo json_encode(['result'=>$result,'strict'=>is_dir($b->sshHostKeys),'warning_count'=>count($warnings)],JSON_UNESCAPED_UNICODE);
