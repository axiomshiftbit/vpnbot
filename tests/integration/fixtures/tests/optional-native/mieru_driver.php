<?php
umask(0077);
require '/app/config.php'; require '/tmp/managed_protocol_fixture.php'; require '/app/bot.php'; require '/app/i18n.php';
class ProtocolAuditTransport {
    public array $calls=[];
    public function call($method,$data,$json=0) {
        $this->calls[]=[$method,$data];
        if (($data['document']??null) instanceof CURLStringFile) file_put_contents('/logs/audit-mieru/'.basename($data['document']->postname),$data['document']->data);
        return ['ok'=>true,'result'=>['message_id'=>count($this->calls),'chat'=>['id'=>1]]];
    }
}
$warnings=[];
set_error_handler(function($level,$message)use(&$warnings) { if(error_reporting()&$level)$warnings[]=$level; return true; });
$b=new Bot($c['key'],$i);$b->transport=new ProtocolAuditTransport();$b->admin=true;$b->language='ru';
$b->input=['chat'=>1,'from'=>1,'message_id'=>1,'callback_id'=>'audit','callback'=>'','message'=>'','username'=>'audit'];
$m=$b->protocolStore('mieru');$dir='/logs/audit-mieru';if(!is_dir($dir))mkdir($dir,0700,true);
$idsfile=$b->protocolRoot.'/.test-mieru-ids.json';$action=$argv[1]??'';$result=[];
if($action==='init') {
    $m->configure(['host'=>'127.0.0.1','sni'=>'','port'=>24445,'transport'=>'TCP','blocked_ips'=>[$b->ip]],true);
    if(!is_file($idsfile))ManagedProtocol::writeJson($idsfile,['a'=>managedProtocolFixtureUser($m,'Доступ А < & 🇷🇺'), 'b'=>managedProtocolFixtureUser($m,'Доступ Б')]);
    foreach(ManagedProtocol::readJson($idsfile) as $label=>$id) $m->user($id,['name'=>$label==='a'?'Доступ А < & 🇷🇺':'Доступ Б','enabled'=>true,'expires'=>null,'quota'=>null,'rolling_quota'=>null]);
    (new ProtocolModules($b->protocolModulesFile))->set('mieru',true);
    $b->syncManagedUpstreams();$result=['initialized'=>true];
} elseif($action==='transport') {
    $m->configure(['transport'=>$argv[2]]);$result=['changed'=>true];
} elseif($action==='port') {
    $m->configure(['port'=>(int)$argv[2]]);$result=['changed'=>true];
} elseif($action==='module') {
    $b->protocolModulesToggle($argv[2]);$result=['desired'=>(new ProtocolModules($b->protocolModulesFile))->read()];
} elseif($action==='menu') {
    $b->menu();$text='';$buttons=[];
    foreach($b->transport->calls as [$method,$data]) { $text.=$data['text']??'';if(isset($data['reply_markup']))$buttons[]=json_decode($data['reply_markup'],true); }
    foreach(['oc','ovpn','ikev2','l2tp'] as $key) $result[$key]=str_contains(json_encode($buttons),'/menu '.$key);
    $result['warnings']=count($warnings);
} elseif($action==='cards') {
    $ids=ManagedProtocol::readJson($idsfile);
    $b->protocolMenu('mieru',$ids['a']);
    $data=end($b->transport->calls)[1];
    $buttons=json_decode($data['reply_markup'],true)['inline_keyboard'];
    $result=['message_length'=>mb_strlen(html_entity_decode(strip_tags($data['text']))),'button_count'=>count($buttons),'escaped'=>str_contains($data['text'],'&lt; &amp;'),'warnings'=>count($warnings)];
    foreach(['a','b'] as $label)foreach(['native','native-uri','mihomo','uri'] as $format){
        $profile=$m->profile($ids[$label],$format);
        file_put_contents($dir.'/'.$label.'-'.$format.'.json',is_array($profile)?json_encode($profile):$profile);
    }
    file_put_contents($dir.'/subscription.json',json_encode(['url'=>'https://'.$b->getDomain().'/pac'.$b->getHashBot().'/protocol/mieru/'.$m->read()['users'][$ids['a']]['token'].'/native']));
} elseif($action==='snapshot') {
    ManagedProtocol::writeJson($dir.'/snapshot.json',$b->exportManagedProtocols());$result=['saved'=>true];
} elseif($action==='restore') {
    $snapshot=ManagedProtocol::readJson($dir.'/snapshot.json');$snapshot['protocols']=['mieru'=>$snapshot['protocols']['mieru']];$settings=$snapshot['protocols']['mieru']['state']['settings'];$snapshot['certificates']=array_intersect_key($snapshot['certificates']??[],array_flip(array_filter([$settings['certificate']??null,$settings['private_key']??null])));$b->importManagedProtocols($snapshot);$result=['queued'=>true];
} elseif($action==='mutate') {
    $ids=ManagedProtocol::readJson($idsfile);$id=$ids[$argv[2]];$op=$argv[3];
    $fields=match($op){'disable'=>['enabled'=>false],'enable'=>['enabled'=>true],'rename'=>['name'=>'Переименован'],
        'quota'=>['quota'=>(int)$argv[4]],'rolling'=>['rolling_quota'=>['days'=>1,'megabytes'=>(int)$argv[4]]],'unrolling'=>['rolling_quota'=>null],'unquota'=>['quota'=>null],'expires'=>['expires'=>(int)$argv[4]],'unexpire'=>['expires'=>null],default=>[]};
    $m->user($id,$fields,in_array($op,['rotate','delete','reset'],true)?$op:'');$result=['changed'=>true];
} elseif($action==='http-policy-save') {
    $pac=$b->getPacConf();ManagedProtocol::writeJson($dir.'/http-policy.json',array_intersect_key($pac,array_flip(['hwid_limit_enabled','hwid_device_count','sub_rate_max','sub_rate_window'])));
    $pac['hwid_limit_enabled']=1;$pac['hwid_device_count']=1;$pac['sub_rate_max']=100;$b->setPacConf($pac);$result=['saved'=>true];
} elseif($action==='http-policy-restore') {
    $pac=$b->getPacConf();foreach(['hwid_limit_enabled','hwid_device_count','sub_rate_max','sub_rate_window'] as $k)unset($pac[$k]);
    $b->setPacConf(array_replace($pac,ManagedProtocol::readJson($dir.'/http-policy.json')));$result=['restored'=>true];
} else throw new RuntimeException('unknown test action');
echo json_encode($result,JSON_UNESCAPED_UNICODE)."\n";

if ($warnings) exit(91);
