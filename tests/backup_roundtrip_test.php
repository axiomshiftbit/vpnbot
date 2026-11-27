<?php
// Полный export/import на изолированных файлах; перезапуски служб подменены.
$root=sys_get_temp_dir().'/vpnbot-roundtrip-'.bin2hex(random_bytes(6));mkdir($root,0700);
foreach (['app','config','certs','logs','webapp','warp','config/telemt/data','config/trusttunnel','config/hysteria/runtime','config/dnstt'] as $d) mkdir("$root/$d",0700,true);
foreach (['sing','clash'] as $type) {
 mkdir("$root/config/templates/$type",0700,true);
 foreach (glob(__DIR__."/../config/templates/$type/*.json") as $template) copy($template,"$root/config/templates/$type/".basename($template));
}
foreach (glob(__DIR__.'/../app/*.php') as $source) {
 if (in_array(basename($source),['config.php','debug.php'],true))continue;
 $body=file_get_contents($source);
 if(basename($source)==='bot.php')$body=str_replace('dirname(__DIR__) . "/config/templates/', '"/config/templates/', $body);
 if(basename($source)==='bot.php')$body=str_replace(['/config/','/certs/','/logs/','/app/webapp/'],["$root/config/","$root/certs/","$root/logs/","$root/webapp/"],$body);
 file_put_contents("$root/app/".basename($source),$body);
}
require "$root/app/bot.php";
require __DIR__.'/managed_protocol_fixture.php';
require __DIR__.'/../app/i18n.php';
class RoundTripBot extends Bot {
 public string $syncedDomain = '';
 public bool $rejectXray = false;
 public bool $nodeOnline = false;
 public int $offlineRequests = 0;
 public string $nodeGeneration = '1234567890abcdef1234567890abcdef';
 public array $nodeProfile = [];
 public string $nodeSnapshot = '';
 protected function managedNodeTransport(string $id, string $action, $value = null): array {
  if ($id!=='c0ffee00') throw new RuntimeException('Unexpected fixture node');
  if (!$this->nodeOnline) { $this->offlineRequests++; throw new RuntimeException('Fixture node offline'); }
  if ($action==='rpc' && ($value['action']??'')==='profile') return $this->nodeProfile;
  if ($action!=='snapshot' || $value!==$this->nodeGeneration) throw new RuntimeException('Unexpected fixture request');
  file_put_contents("$this->managedNodeRoot/$id/snapshot.json",$this->nodeSnapshot);
  return ['saved'=>true,'sha256'=>hash('sha256',$this->nodeSnapshot)];
 }
 protected function restoreBackupXrayLocked(array $config): bool { return !$this->rejectXray && parent::restoreBackupXrayLocked($config); }
 public function syncManagedUpstreams(): void { $this->syncedDomain=$this->getPacConf()['domain']??''; }
 public function __construct(public string $dir,array $translations){
  $this->managedNodeRoot="$dir/nodes";
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
 public function dnsttStart(){return true;}
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
  'telemt_user_limits'=>['test'=>['quota'=>1073741824,'ips'=>2,'period'=>'monthly']],'finalmask'=>['enabled'=>false],
  'blocklist'=>['domain:example.test','regexp:.*\\.ru$'],'singtemplates'=>['custom'=>['route'=>['rules'=>[]]]],
  'vless_encryption'=>['enabled'=>false],'relays'=>['relay.example.test'=>['host'=>'relay.example.test']],
  // Узел выхода, XDRIVE и режим WARP MASQUE живут в pac.json.
  'exits'=>['a1b2c3d4'=>['name'=>'fi','link'=>'vless://00000000-0000-4000-8000-000000000001@node.example.test:443?security=reality&type=tcp&pbk=x&sid=00&fp=firefox&sni=www.example.test#fi',
   'enabled'=>1,'quic'=>'block','routes'=>['domain:youtube.com'=>1,'full:www.example.test'=>0],
   'rulesets'=>['https://example.test/yt.srs'=>['on'=>0,'behavior'=>'domain','interval'=>86400]],'auto'=>1,'created'=>1700000000,'status'=>[]]],
  'xdrive'=>['enabled'=>0,'service'=>'webdav','url'=>'https://dav.example.test','folder'=>'vpnbot-xdrive','login'=>'u','password'=>'synthetic','poll'=>500],
  'managed_nodes'=>['a1b2c3d4'=>['name'=>'fixture-node','connected'=>false,
   'subscriptions'=>['fixture'=>['peer'=>'00000000-0000-4000-8000-000000000004','token'=>str_repeat('c',64)]],
   'draft'=>['domain'=>'node.example.test','domain_aliases'=>['alt.example.test'],'wireguard'=>['keepalive'=>17],
    'amnezia'=>['keepalive'=>'18-24','parameters'=>['Jc'=>5]],'xray'=>['xhttp'=>['extra'=>['xmux'=>['maxConcurrency'=>'2-4']]]]]]],
  'warp_mode'=>'masque',
  // Сертификат Let's Encrypt и пометка запроса к acme-window этого сервера.
  'letsencrypt'=>'letsencrypt','acme_requested'=>1700000000];
 mkdir("$root/nodes/a1b2c3d4",0700,true);
 foreach (['key'=>'SYNTHETIC-PRIVATE-FIXTURE','key.pub'=>'SYNTHETIC-PUBLIC-FIXTURE'] as $n=>$v) file_put_contents("$root/nodes/a1b2c3d4/$n",$v);
 // Подключённая нода: в общий бэкап обязаны попасть ключ управления,
 // закреплённый адрес/ключ хоста и последняя подтверждённая копия ноды.
 $options=['transport'=>'reality','family'=>4,'core'=>'origin','domain'=>'','mask'=>'mask.example.test'];
 $identity=['uuid'=>'11111111-1111-4111-8111-111111111111','private'=>str_repeat('A',43),'public'=>str_repeat('B',43),
  'short_id'=>'0123456789abcdef','path'=>str_repeat('0123456789abcdef',2)];
 $b->nodeProfile=['link'=>'vless://'.$identity['uuid'].'@198.51.100.20:443?security=reality&type=tcp&pbk='.$identity['public'].'&sid='.$identity['short_id'].'&sni=mask.example.test',
  'outbound'=>['protocol'=>'vless','settings'=>[],'streamSettings'=>[]]];
 $pac['exits']['c0ffee00']=['name'=>'connected-node','link'=>$b->nodeProfile['link'],'managed_profile'=>$b->nodeProfile];
 $pac['managed_nodes']['c0ffee00']=['name'=>'connected-node','connected'=>true,'job'=>null,
  'status'=>['generation'=>$b->nodeGeneration,'pending'=>null,'options'=>$options]];
 $peers=[];
 for ($peer=1;$peer<=32;$peer++) $peers[]=['id'=>sprintf('20000000-0000-4000-8000-%012d',$peer),'name'=>'roundtrip-fixture-peer-'.$peer,'enabled'=>true];
 $b->nodeSnapshot=json_encode(['schema'=>1,'options'=>$options,'identity'=>$identity,'peers'=>$peers,
  'images'=>['xr'=>'ghcr.io/axiomshiftbit/vpnbot-xr@sha256:'.str_repeat('a',64)],'tls'=>new stdClass],JSON_UNESCAPED_SLASHES);
 $nodeFiles=['key'=>"SYNTHETIC-CONTROLLER-PRIVATE\n",'key.pub'=>"SYNTHETIC-CONTROLLER-PUBLIC\n",
  'endpoint.json'=>'{"address":"198.51.100.20","port":22,"host_key":"SYNTHETIC"}',
  'snapshot.json'=>$b->nodeSnapshot];
 mkdir("$root/nodes/c0ffee00",0700,true);
 foreach ($nodeFiles as $n=>$v) { file_put_contents("$root/nodes/c0ffee00/$n",$v); chmod("$root/nodes/c0ffee00/$n",0600); }
 $b->setPacConf($pac);
 $b->ensureDefaultTemplates();
 $pac=$b->getPacConf();unset($pac['singtemplates']['15_dns_google']);
 $pac['singtemplates']['15_direct']['audit_edit']='preserve';$b->setPacConf($pac);
 $quota=['last_reset_epoch_secs'=>100,'users'=>['test'=>['used_bytes'=>123456,'last_reset_epoch_secs'=>100,'quota_period'=>'monthly','period_cursor_epoch_secs'=>100]]];
 $b->telemtQuotaWrite($quota);
 $quota['users']['test']['used_bytes']=222222;
 file_put_contents("$root/config/telemt/data/telemt.checkpoint.json",json_encode($quota));
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
  'ckserver.json'=>'{"Enabled":0,"BypassUID":[]}',
  // Отметки узла у пользователя и служебная учётка «Профиля для узла».
  'xray.json'=>json_encode(['inbounds'=>[['settings'=>['clients'=>[['id'=>'00000000-0000-4000-8000-000000000002','email'=>'user','exit'=>['a1b2c3d4']],
   ['id'=>'00000000-0000-4000-8000-000000000003','email'=>'main-server','subtoken'=>str_repeat('a',32),'exit_relay'=>1,'exit_ipv6'=>1,'exit_transport_ipv6'=>1]]]]],'outbounds'=>[],'routing'=>['rules'=>[]]]),
  'xray.stats'=>'{"users":[]}','hwid.json'=>'{}'] as $name=>$body)file_put_contents("$root/config/$name",$body);
 $b->restoreBackupExtraFiles(['stlsserver.json'=>base64_encode('{"Enabled":1}'),'telemt/decoy/index.html'=>base64_encode('Custom decoy'),
 'warp/wgcf-profile.conf'=>base64_encode('synthetic-profile'),'sing.json'=>base64_encode('{"outbounds":[]}'),
 'warp/masque/device.json'=>base64_encode('{"id":"synthetic"}'),'warp/masque/key.pem'=>base64_encode('synthetic-key'),'warp/masque/license.sha256'=>base64_encode('mark')]);
 $key=openssl_pkey_new(['private_key_bits'=>2048]);$csr=openssl_csr_new(['commonName'=>'example.test'],$key);$crt=openssl_csr_sign($csr,null,$key,1);
 openssl_pkey_export($key,$private);openssl_x509_export($crt,$public);
 file_put_contents("$root/certs/cert_private",$private);file_put_contents("$root/certs/cert_public",$public);
 if (extension_loaded('pdo_sqlite')) {
  $b->setHwidStorage(['fixture' => ['device' => ['time' => 1]]]);
  // После миграции JSON больше не источник данных. Даже его повреждение
  // не должно мешать экспорту актуальной базы и последующему восстановлению.
  file_put_contents("$root/config/hwid.json", '{obsolete-broken');
 }
 file_put_contents("$root/config/ipv6-egress.json",json_encode(['enabled'=>true,'public'=>'2606:4700:4700::1111']));
 $b->pacConfUpdate(static function (&$conf) {
  $conf['adg_panel_epoch']='fixture-main';$conf['adg_browser_epoch']='fixture-browser';
  $conf['managed_nodes']['a1b2c3d4']['adguard_panel']=['ticket'=>str_repeat('a',64),'until'=>time()+900];
 });
 $unboundRejected=false;
 try { $b->export(); }
 catch (RuntimeException $e) { $unboundRejected=str_contains($e->getMessage(),'первого общего бэкапа'); }
 rtCheck($unboundRejected && $b->offlineRequests>0,'Архив старой offline-карточки без доказанного поколения отклонён');
 $b->nodeOnline=true;
 $b->managedNodeBackupRefresh();
 $b->nodeOnline=false;
 $confirmed=$b->managedNodes()['c0ffee00'];
 $binding=['generation'=>$b->nodeGeneration,'sha256'=>hash('sha256',$b->nodeSnapshot)];
 rtCheck(($confirmed['confirmed_snapshot']??null)===$binding && !empty($confirmed['backup_time']),'Штатное получение снимка связало его байты и поколение с карточкой');
 $pac['managed_nodes']['c0ffee00']=$confirmed;
 $attempts=$b->offlineRequests;
 $json=$b->export();$snapshot=json_decode($json,true,512,JSON_THROW_ON_ERROR);file_put_contents($b->update,$json);
 rtCheck($b->offlineRequests>$attempts && $snapshot['pac']['managed_nodes']['c0ffee00']['confirmed_snapshot']===$binding,'Полная выгрузка недоступной ноды использует подтверждённую локальную копию');
 $beforeInvalid=$b->getPacConf();
 foreach (['file','generation'] as $change) {
  $mixed=$snapshot;
  if ($change==='file') $mixed['extra_files']['nodes/c0ffee00/snapshot.json']=base64_encode(str_replace('roundtrip-fixture-peer-1','other-fixture-peer-1',$b->nodeSnapshot));
  else $mixed['pac']['managed_nodes']['c0ffee00']['status']['generation']=str_repeat('e',32);
  file_put_contents($b->update,json_encode($mixed));
  rtCheck($b->importFile($b->update)===false && $b->getPacConf()===$beforeInvalid
   && file_get_contents("$root/nodes/c0ffee00/snapshot.json")===$b->nodeSnapshot,"Противоречие записи снимка ($change) отклонено до записи");
 }
 file_put_contents($b->update,$json);
 $legacy=$snapshot;
 unset($legacy['pac']['managed_nodes']['c0ffee00']['confirmed_snapshot']);
 $b->validateBackup($legacy);
 rtCheck(!isset($snapshot['pac']['adg_panel_epoch']) && !isset($snapshot['pac']['adg_browser_epoch'])
  && !isset($snapshot['pac']['managed_nodes']['a1b2c3d4']['adguard_panel']),'Local panel grants are excluded from export');
 rtCheck(!isset($snapshot['extra_files']['ipv6-egress.json']),'Host IPv6 setup is not imported from another server');
 foreach ($nodeFiles as $n=>$v) rtCheck(($snapshot['extra_files']["nodes/c0ffee00/$n"]??null)===base64_encode($v),"Общий бэкап содержит файл ноды $n побайтно");
 rtCheck(!isset($snapshot['extra_files']['nodes/a1b2c3d4/snapshot.json']) && isset($snapshot['extra_files']['nodes/a1b2c3d4/key']),'Неподключённая нода: только ключ, без несуществующей копии');
 // Размер файла растёт ровно на закодированные файлы ноды: копия сама по себе невелика.
 $withNode=strlen(json_encode($snapshot,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_PRETTY_PRINT));
 $node=$snapshot;foreach (array_keys($nodeFiles) as $n) unset($node['extra_files']["nodes/c0ffee00/$n"]);
 rtCheck($withNode-strlen(json_encode($node,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_PRETTY_PRINT))>4000,'Копия ноды заметно увеличивает файл экспорта');
 $localMarker=json_encode(['enabled'=>true,'public'=>'2620:fe::fe']);
 file_put_contents("$root/config/ipv6-egress.json",$localMarker);
 if (extension_loaded('pdo_sqlite')) rtCheck($snapshot['hwid']===['fixture'=>['device'=>['time'=>1]]], 'Экспорт использует актуальную SQLite');
 rtCheck($snapshot['telemt_quota']===$quota,'Копия объединяет checkpoint расхода с календарём ядра');
 rtCheck(!isset($snapshot['pac']['singtemplates']['15_dns_google']) && !empty($snapshot['pac']['installed_templates']['sing']['15_dns_google']), 'Удаление штатного шаблона и отметка установки сохранены');
 rtCheck(count($snapshot)>=23,'Полный экспорт включает все секции');
 rtCheck(($snapshot['pac']['letsencrypt']??'')==='letsencrypt' && !array_key_exists('acme_requested',$snapshot['pac']),'Признак Let\'s Encrypt в копии, пометки запроса acme-window нет');
 rtCheck($snapshot['ssl']===['private'=>$private,'public'=>$public],'TLS-пара в копии целиком');
 foreach(['pac','telemt_quota','extra_files','managed_protocols','hy_users','wg','wg1','ssl','ss','sl','xray','ad','tt','ovpn','ipsec'] as $section)rtCheck(array_key_exists($section,$snapshot),"Секция $section присутствует");
 foreach(['warp/masque/device.json','warp/masque/key.pem','warp/masque/license.sha256'] as $name)rtCheck(isset($snapshot['extra_files'][$name]),"Устройство WARP MASQUE в копии: $name");
 // Неподтверждённая регистрация MASQUE в копию не идёт.
 touch("$root/warp/masque/.pending");rtCheck(!isset(json_decode($b->export(),true)['extra_files']['warp/masque/device.json']),'Неподтверждённое устройство MASQUE не сохраняется');
 $b->setPacConf(['language'=>'ru']);file_put_contents("$root/certs/cert_public",'changed');file_put_contents("$root/certs/cert_private",'changed');file_put_contents("$root/config/wg0.conf",'changed');file_put_contents("$root/config/wg1.conf",'changed');
 file_put_contents("$root/config/telemt/decoy/index.html",'changed');file_put_contents("$root/warp/wgcf-profile.conf",'changed');
 file_put_contents("$root/warp/masque/device.json",'{"id":"other"}');file_put_contents("$root/config/xray.json",'{"inbounds":[{"settings":{"clients":[]}}],"outbounds":[],"routing":{"rules":[]}}');
 foreach (array_keys($nodeFiles) as $n) unlink("$root/nodes/c0ffee00/$n");
 rmdir("$root/nodes/c0ffee00");
 rtCheck($b->importFile($b->update)===true,'Полное восстановление возвращает успех');
 foreach ($nodeFiles as $n=>$v) rtCheck(file_get_contents("$root/nodes/c0ffee00/$n")===$v && (fileperms("$root/nodes/c0ffee00/$n")&0777)===0600,"Файл ноды $n восстановлен побайтно и закрыт");
 rtCheck((fileperms("$root/nodes/c0ffee00")&0777)===0700 && ($b->managedNodes()['c0ffee00']['backup_time']??0)===$confirmed['backup_time']
  && ($b->managedNodes()['c0ffee00']['confirmed_snapshot']??null)===$binding,'Каталог ноды закрыт, время и привязка копии восстановлены');
 rtCheck(file_get_contents("$root/config/ipv6-egress.json")===$localMarker,'Restore preserves this host IPv6 network marker');
 rtCheck($b->syncedDomain===$snapshot['pac']['domain'],'Маршруты протоколов применены после восстановления домена');
 $after=json_decode($b->export(),true,512,JSON_THROW_ON_ERROR);
 foreach(['pac','telemt_quota','extra_files','wg','wg1','ssl','ss','sl','xray','ad','tt'] as $section)rtCheck($after[$section]===$snapshot[$section],"$section: данные пережили полный цикл");
 rtCheck($after['pac']['managed_nodes']===$pac['managed_nodes'],'Node HTTPS capabilities, aliases and advanced settings survive full export/import');
 rtCheck($after['hy_users']['state']['users']===$snapshot['hy_users']['state']['users'] && $after['hy_users']['usage']===$snapshot['hy_users']['usage'],'Пользователи и расход Hysteria сохранены');
 rtCheck($after['hwid']===$snapshot['hwid'],'HWID восстановлены в SQLite');
 rtCheck(!file_exists("$root/config/telemt/data/telemt.checkpoint.json"),'Старый checkpoint не перекрывает восстановленный расход');
 $b->ensureDefaultTemplates();
 rtCheck($b->getPacConf()['singtemplates']===$snapshot['pac']['singtemplates'],'Удалённый шаблон не появляется снова, пользовательская правка сохранена');
 rtCheck(array_keys($b->exitNodes())===['a1b2c3d4','c0ffee00'] && $b->exitNodes()['a1b2c3d4']['routes']===['domain:youtube.com'=>1,'full:www.example.test'=>0],'Узлы выхода и маршруты восстановлены');
 rtCheck($b->exitNodeEmails($b->getXray(),'a1b2c3d4')===['user'] && !empty($b->getXray()['inbounds'][0]['settings']['clients'][1]['exit_relay']),'Отметки узла у пользователей и служебная учётка восстановлены');
 rtCheck(($b->getPacConf()['xdrive']['url']??'')==='https://dav.example.test' && $b->warpMode()==='masque','XDRIVE и режим WARP восстановлены');
 rtCheck(file_get_contents("$root/warp/masque/device.json")==='{"id":"synthetic"}' && !file_exists("$root/warp/masque/.pending"),'Устройство MASQUE восстановлено, отметка незавершённой регистрации снята');
 rtCheck(file_get_contents("$root/logs/xray_core")==='origin3','Выбор версии Xray восстановлен и при выключенном контейнере');
 rtCheck(file_get_contents("$root/certs/cert_public")===$public && file_get_contents("$root/certs/cert_private")===$private && ($b->getPacConf()['letsencrypt']??'')==='letsencrypt','Сертификат и признак Let\'s Encrypt восстановлены: служба продлит его по сроку');
 rtCheck($b->importFile($b->update)===true,'Повторное восстановление работает');
 if (extension_loaded('pdo_sqlite')) {
  // Новая БД и новый объект, как при переносе копии на чистую установку.
  $b=null;gc_collect_cycles();
  foreach (['vpnbot.sqlite','vpnbot.sqlite-wal','vpnbot.sqlite-shm','hwid.json'] as $file) if (is_file("$root/config/$file")) unlink("$root/config/$file");
  $b=new RoundTripBot($root,$i);$b->setPacConf(['language'=>'ru']);
  rtCheck($b->importFile($b->update)===true,'Восстановление на чистую SQLite');
  rtCheck($b->getHwidStorage()===$snapshot['hwid'],'Все устройства перенесены в новую БД');
  rtCheck(!$b->hwidRegister('fixture','new-device',1,[]),'Восстановленный HWID участвует в ограничении числа устройств');
  rtCheck($b->telemtQuotaRead($b->getPacConf())===$quota,'Квота и календарь сохраняются при переносе');
  $b->ensureDefaultTemplates();
  rtCheck($b->getPacConf()['singtemplates']===$snapshot['pac']['singtemplates'],'Новая установка сохраняет удаление и правки шаблонов');
 }
 $beforeStats=['users'=>[['global'=>['upload'=>123,'download'=>456]]]];
 $b->setXrayStats($beforeStats);$beforeStats=$b->getXrayStats();$b->rejectXray=true;
 file_put_contents($b->update,json_encode(['xray'=>$snapshot['xray'],'xraystats'=>['users'=>[['global'=>['upload'=>99999,'download'=>77777]]]]]));
 rtCheck($b->importFile($b->update)===false,'Отказ ядра возвращает неполное восстановление');
 rtCheck($b->getXrayStats()===$beforeStats,'Отвергнутый снимок Xray не меняет расход прежних пользователей');
 echo "backup_roundtrip_test OK\n";
}finally{rtRemove($root);}
