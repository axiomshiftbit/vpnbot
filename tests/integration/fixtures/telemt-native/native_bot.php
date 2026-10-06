<?php
require $argv[1] . '/app/bot.php'; require $argv[1] . '/app/i18n.php';
set_error_handler(function($level,$message,$file,$line) { if(error_reporting()&$level)throw new ErrorException($message,0,$level,$file,$line);return false; });
class NativeLimitsBot extends Bot {
 public string $root; public array $fixture, $screen=[], $prompt=[];
 public function getWgMsg(){return null;}
 public function getPorts(){return ['telemt'=>['port'=>8443,'enable'=>true]];}
 public function telemtVersion():string{return '3.5.13';}
 public function telemtQuotaPath():string{return $this->root.'/data/telemt.limit.json';}
 public function withLock(string $name,callable $fn,int $timeout=0,$busy=null){$f=fopen($this->root.'/.lock.'.$name,'c');flock($f,LOCK_EX);try{return $fn();}finally{flock($f,LOCK_UN);fclose($f);}}
 public function telemtWriteServiceState(bool $enabled):void{file_put_contents($this->root.'/service-enabled',$enabled?"1\n":"0\n");}
 public function telemtWriteToml(string $toml):void{
  file_put_contents($this->root.'/generated.toml',$toml);
  $toml=str_replace(['port = 443', 'port = 8080','"0.0.0.0"','"127.0.0.1:9091"','"10.10.0.2/32"','mask = true','tls_emulation = true','/telemt/decoy'],
   ['port = '.$this->fixture['n'],'port = '.$this->fixture['w'],'"127.0.0.1"','"127.0.0.1:'.$this->fixture['a'].'"','"127.0.0.1/32"','mask = false','tls_emulation = false',$this->root.'/decoy'],$toml);
  $toml=str_replace('type = "direct"','type = "socks5"'."\n".'address = "127.0.0.1:'.$this->fixture['dc'].'"',$toml);
  $toml.="\n[network]\nipv6 = false\nstun_use = false\nhttp_ip_detect_urls = []\n";
  file_put_contents($this->root.'/telemt.toml',$toml);
 }
 public function telemtWebDecoy():void{}
 public function cloakNginx(){}
 public function ssh($cmd,$service='wg',$wait=true,$log='/dev/null'){
  $this->sshFailed=false;
  if(str_starts_with($cmd,'telemt run'))$action='start';
  elseif(str_contains($cmd,'while [ $i -lt 3 ]'))$action='probe';
  elseif(preg_match('~telemt_state.py (version|prepare|ready|checkpoint|stop|reset)(?: \'([A-Za-z0-9+/=]+)\')?~',$cmd,$m)){$action=$m[1];$arg=$m[2]??'';}
  else throw new RuntimeException('Unexpected SSH command');
  $command='python3 '.escapeshellarg(dirname(__FILE__).'/native_runner.py').' '.escapeshellarg($this->root).' '.escapeshellarg($action).' '.escapeshellarg($arg??'');
  exec($command.' 2>>'.escapeshellarg($this->root.'/helper.log'),$lines,$exit);return $exit===0?implode("\n",$lines):'';
 }
 public function telemtApiFetch(array $paths):array {
  $r=[];foreach($paths as $path){$v=@file_get_contents('http://127.0.0.1:'.$this->fixture['a'].$path,false,stream_context_create(['http'=>['timeout'=>2]]));$r[$path]=$v?json_decode($v,true)['data']:null;}return $r;
 }
 public function update($chat,$message,$text,$button=false,$reply=false,$mode='HTML',$disable_notification=false){$this->screen=['text'=>$text,'buttons'=>$button];}
 public function send($chat,$text,?int $to=0,$button=false,$reply=false,$mode='HTML',$disable_notification=false){return ['result'=>['message_id'=>55]];}
 public function stashReply($r,array $state){$this->prompt=$state;}
 public function answer($callback_id,$textNotify=false,$notify=false){}
 public function click($cb){$this->input['callback']=$cb;$this->action();}
}
$b=(new ReflectionClass(NativeLimitsBot::class))->newInstanceWithoutConstructor();$b->root=$argv[2];$b->fixture=json_decode(file_get_contents($b->root.'/fixture.json'),true);
$b->pac=$b->root.'/pac.json';$b->protocolModulesFile=$b->root.'/modules.json';$b->key='fixture';$b->ip='203.0.113.10';$b->language='ru';$b->i18n=$i;$b->admin=true;
$b->input=['chat'=>1,'message_id'=>2,'callback_id'=>3,'callback'=>'','message'=>''];$q=json_decode(stream_get_contents(STDIN),true);$name=$q['name']??'alice';
try {
 switch($q['action']){
 case 'start':$b->restartTelemt();break;
 case 'http':$b->click('/telemtWebHttp '.$q['setting'].' '.$q['value']);break;
 case 'web-toggle':$b->click('/telemtWebToggle');break;
 case 'set':$b->telemtChangeLimit($name,$q['field'],$q['value'],hash('sha256',$b->getPacConf()['telemt_users'][$name]));break;
 case 'reply':$b->click($b->telemtUserCallback($name,1,'',$q['field']));$b->telemtLimitReply($q['value'],...$b->prompt['args']);break;
 case 'click':$b->click($b->telemtUserCallback($name,1,'',$q['op']));break;
 case 'reset':$b->click($b->telemtUserCallback($name,1,'','reset'));$b->click($b->screen['buttons'][0][0]['callback_data']);break;
 case 'add':$b->telemtUserAdd($name);break;
 case 'service':$b->toggleTelemtService();break;
 case 'backup':file_put_contents($b->root.'/backup.json',json_encode($b->telemtBackupSnapshot()));break;
 case 'restore':$data=json_decode(file_get_contents($b->root.'/backup.json'),true);$b->telemtQuotaRestore($data['telemt_quota'],$data['pac']);break;
 }
 echo json_encode(['ok'=>true,'screen'=>$b->screen,'limits'=>$b->getPacConf()['telemt_user_limits']??[]]);
}catch(Throwable $e){echo json_encode(['ok'=>false,'error'=>$e->getMessage()]);exit(1);}
