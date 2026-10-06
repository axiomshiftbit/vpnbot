<?php
require '/app/config.php'; require '/app/bot.php'; require '/app/i18n.php'; require '/app/calc.php';
$warnings=[];
set_error_handler(function($s,$m) use (&$warnings){if(error_reporting()&$s)$warnings[]=$m;return true;});
class TtProofTransport {public array $calls=[];public function call($method,$data,$json=0){$this->calls[]=[$method,$data];return ['ok'=>true,'result'=>['message_id'=>1,'chat'=>['id'=>1]]];}}
$b=new Bot($c['key'],$i);$b->transport=new TtProofTransport();$b->language='ru';$b->admin=true;
$b->input=['chat'=>1,'from'=>1,'message_id'=>1,'callback_id'=>'audit','username'=>'audit','message'=>'','callback'=>''];
if(($argv[1]??'')==='stats')$result=$b->ttClientStats();
elseif(($argv[1]??'')==='restart')$result=$b->restartTt();
elseif(($argv[1]??'')==='menu'){
 $b->ttClientMenu('audittt');$matches=array_values(array_filter($b->transport->calls,fn($x)=>isset($x[1]['text'])));$data=end($matches)[1]??[];$text=$data['text']??'';
 $result=['sessions'=>str_contains($text,'Активные сессии:'),'upload'=>str_contains($text,'Отправлено клиентом:'),'download'=>str_contains($text,'Получено клиентом:'),'lifetime'=>str_contains($text,'обнуляются'),'help'=>str_contains(json_encode($data),'menuhelp tt 0 audittt')];
}elseif(($argv[1]??'')==='help'){
 $b->input['callback']='/menuhelp tt 1 audittt';$b->action();$call=end($b->transport->calls);$result=['help'=>$call!==false && str_contains($call[1]['text']??'','TrustTunnel')];
}else throw new RuntimeException('unknown proof');
echo json_encode(['result'=>$result,'warning_count'=>count($warnings)],JSON_UNESCAPED_UNICODE);
