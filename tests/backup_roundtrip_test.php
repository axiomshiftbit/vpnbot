<?php
// Полный export/import на изолированных файлах; перезапуски служб подменены.
$root=sys_get_temp_dir().'/vpnbot-roundtrip-'.bin2hex(random_bytes(6));mkdir($root,0700);
foreach (['app','config','certs','logs','webapp','warp','config/telemt/data','config/trusttunnel','config/hysteria/runtime','config/dnstt'] as $d) mkdir("$root/$d",0700,true);
foreach (glob(__DIR__.'/../app/*.php') as $source) {
 if (in_array(basename($source),['config.php','debug.php'],true))continue;
 $body=file_get_contents($source);
 if(basename($source)==='bot.php')$body=str_replace(['/config/','/certs/','/logs/','/app/webapp/'],["$root/config/","$root/certs/","$root/logs/","$root/webapp/"],$body);
 file_put_contents("$root/app/".basename($source),$body);
}
require "$root/app/bot.php";
require __DIR__.'/managed_protocol_fixture.php';
require __DIR__.'/../app/i18n.php';
class RoundTripBot extends Bot {
 public function __construct(public string $dir,array $translations){
  $this->pac="$dir/config/pac.json";$this->clients="$dir/config/clients.json";$this->clients1="$dir/config/clients1.json";
  $this->protocolRoot="$dir/config/protocols";$this->protocolModulesFile="$dir/config/protocol-services.json";
  $this->protocolCertRoot="$dir/certs";$this->protocolNginxFile="$dir/absent-nginx";$this->upstreamFile="$dir/absent-upstream";
  $this->hysteriaUsersRoot="$dir/config/hysteria";$this->hysteriaConf="$dir/config/hysteria.yaml";
  $this->backupWarpRoot="$dir/warp";$this->telemtDecoyDir="$dir/config/telemt/decoy";$this->update="$dir/backup.json";
  $this->input=['chat'=>1,'message_id'=>1];$this->i18n=$translations;$this->language='ru';$this->ip='192.0.2.1';
  $this->ports=['wg'=>'51820/udp','wg1'=>'51821/udp'];
 }
 protected function syncOcUsers(?array $clients=null):array{return [];}
 public function protocolModuleEnabled(string $service):bool{return false;}
 public function ssh($cmd,$service='wg',$wait=true,$log='/dev/null'){return '';}
 public function restartNaive(){return true;}
 public function pacUpdate($import=''){}
 public function stopAd(){} public function startAd(){}
 public function update($chat,$message_id,$text,$button=false,$reply=false,$mode='HTML'){}
 public function send($chat,$text,?int $to=0,$button=false,$reply=false,$mode='HTML',$disable_notification=false){throw new RuntimeException('Непредвиденный вызов Telegram');}
 public function cloakNginx(){}
 public function adguardXrayClients(){}
 public function setUpstreamDomain($domain){}
 public function setUpstreamDomainOcserv($domain){}
 public function setUpstreamDomainNaive($domain){}
 public function restartOcserv($conf,bool $syncCamouflage=true){return file_put_contents("$this->dir/config/ocserv.conf",$conf)!==false;}
 public function dnsttStart(){}
 public function telemtQuotaPath():string{return "$this->dir/config/telemt/data/telemt.limit.json";}
 public function telemtQuotaRestore(?array $state,array $conf):void{$this->telemtQuotaWrite($state);$this->setPacConf($conf);}
 public function writeCoreMarker(string $core):bool{return file_put_contents("$this->dir/logs/xray_core",$core)!==false;}
}
function rtCheck(bool $ok,string $name):void{if(!$ok)throw new RuntimeException($name);}
function rtRemove(string $p):void{if(is_dir($p)&&!is_link($p)){foreach(scandir($p) as $n)if($n!=='.'&&$n!=='..')rtRemove("$p/$n");rmdir($p);}else unlink($p);}
try{
 $b=new RoundTripBot($root,$i);
 $pac=['language'=>'ru','domain'=>'vpn.example.test','limitpage'=>5,'xray_core'=>'origin3','transport'=>'Websocket',
  'telemt_users'=>['test'=>str_repeat('a',32)],'telemt_web'=>1,'telemt_web_carrier'=>'https','telemt_web_path'=>'example-path',
  'telemt_user_limits'=>['test'=>['quota'=>1073741824,'ips'=>2]],'finalmask'=>['enabled'=>false],
  'blocklist'=>['domain:example.test','regexp:.*\\.ru$'],'singtemplates'=>['custom'=>['route'=>['rules'=>[]]]],
  'vless_encryption'=>['enabled'=>false],'relays'=>['relay.example.test'=>['host'=>'relay.example.test']]];
 $b->setPacConf($pac);
 $b->telemtQuotaWrite(['last_reset_epoch_secs'=>0,'users'=>['test'=>['used_bytes'=>123456,'last_reset_epoch_secs'=>0]]]);
 foreach([0,1] as $n){
  $server=['interface'=>['PrivateKey'=>base64_encode(str_repeat(chr(65+$n),32)),'Address'=>"10.0.$n.1/24",'ListenPort'=>51820+$n],
   'peers'=>[['PublicKey'=>base64_encode(str_repeat('P',32)),'AllowedIPs'=>"10.0.$n.2/32"]]];
  file_put_contents("$root/config/wg$n.conf",$b->createConfig($server));
  $client=['interface'=>['PrivateKey'=>base64_encode(str_repeat('K',32)),'Address'=>"10.0.$n.2/32",'## name'=>'Тест'],
   'peers'=>[['PublicKey'=>base64_encode(str_repeat('S',32)),'AllowedIPs'=>'0.0.0.0/0','Endpoint'=>'vpn.example.test:'.(51820+$n)]]];
  file_put_contents("$root/config/clients".($n?'1':'').'.json',json_encode([$client]));
 }
 foreach(['AdGuardHome.yaml'=>"dns: {}\n",'hysteria.yaml'=>"listen: :443\n",'ocserv.conf'=>"tcp-port = 443\n",'ocserv.passwd'=>'',
  'trusttunnel/credentials.toml'=>'','ssserver.json'=>json_encode(['server_port'=>8388,'password'=>'synthetic','acl'=>"$root/config/ss.acl"]),
  'sslocal.json'=>'{"server":"example.test","server_port":8488,"password":"synthetic"}',
  'ckserver.json'=>'{"Enabled":0,"BypassUID":[]}','xray.json'=>'{"inbounds":[{"settings":{"clients":[]}}],"outbounds":[],"routing":{"rules":[]}}',
  'xray.stats'=>'{"users":[]}','hwid.json'=>'{}'] as $name=>$body)file_put_contents("$root/config/$name",$body);
 $b->restoreBackupExtraFiles(['stlsserver.json'=>base64_encode('{"Enabled":1}'),'telemt/decoy/index.html'=>base64_encode('Custom decoy'),
 'warp/wgcf-profile.conf'=>base64_encode('synthetic-profile'),'sing.json'=>base64_encode('{"outbounds":[]}')]);
 $key=openssl_pkey_new(['private_key_bits'=>2048]);$csr=openssl_csr_new(['commonName'=>'example.test'],$key);$crt=openssl_csr_sign($csr,null,$key,1);
 openssl_pkey_export($key,$private);openssl_x509_export($crt,$public);
 file_put_contents("$root/certs/cert_private",$private);file_put_contents("$root/certs/cert_public",$public);
 $json=$b->export();$snapshot=json_decode($json,true,512,JSON_THROW_ON_ERROR);file_put_contents($b->update,$json);
 rtCheck(count($snapshot)>=23,'Полный экспорт включает все секции');
 foreach(['pac','telemt_quota','extra_files','managed_protocols','hy_users','wg','wg1','ssl','ss','sl','xray','ad','tt','ovpn','ipsec'] as $section)rtCheck(array_key_exists($section,$snapshot),"Секция $section присутствует");
 $b->setPacConf(['language'=>'ru']);file_put_contents("$root/config/wg0.conf",'changed');file_put_contents("$root/config/wg1.conf",'changed');
 file_put_contents("$root/config/telemt/decoy/index.html",'changed');file_put_contents("$root/warp/wgcf-profile.conf",'changed');
 rtCheck($b->importFile($b->update)===true,'Полное восстановление возвращает успех');
 $after=json_decode($b->export(),true,512,JSON_THROW_ON_ERROR);
 foreach(['pac','telemt_quota','extra_files','wg','wg1','ssl','ss','sl','xray','ad','tt'] as $section)rtCheck($after[$section]===$snapshot[$section],"$section: данные пережили полный цикл");
 rtCheck($after['hy_users']['state']['users']===$snapshot['hy_users']['state']['users'] && $after['hy_users']['usage']===$snapshot['hy_users']['usage'],'Пользователи и расход Hysteria сохранены');
 rtCheck(file_get_contents("$root/logs/xray_core")==='origin3','Выбор версии Xray восстановлен и при выключенном контейнере');
 rtCheck($b->importFile($b->update)===true,'Повторное восстановление работает');
 echo "backup_roundtrip_test OK\n";
}finally{rtRemove($root);}
