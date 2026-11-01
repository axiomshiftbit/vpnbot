<?php
require __DIR__.'/managed_nodes_test.php';
$b=new ManagedFixtureBot();
$b->pacState['managed_nodes']['aabbccdd']['job']['operation']='renew';
$b->remoteStatus['pending']=null;
$b->remoteJob=['state'=>'done','result'=>['certificate_result'=>'unchanged']];
$b->managedNodePoll('aabbccdd');
$b->managedNodeMenu('aabbccdd');
$check(str_contains(end($b->screens)[0],'не требовалось'),'unchanged certificate has an explicit no-op result');
$b->managedNodeMaintenance('aabbccdd');
$buttons=json_encode(end($b->screens)[1],JSON_UNESCAPED_UNICODE);
$check(str_contains($buttons,'Обновить с ветки master'),'master branch label');
$check(str_contains($buttons,'Создать копию ноды'),'explicit snapshot action');
$check(str_contains($buttons,'Справка'),'maintenance help');
echo "PASS node maintenance feedback\n";

foreach (['renewed','issued','mismatch','expired','failed'] as $case) {
    $b=new ManagedFixtureBot();
    $b->pacState['managed_nodes']['aabbccdd']['job']['operation']='renew_force';
    $b->remoteJob['result']['certificate_result']=$case==='issued'?'issued':'renewed';
    $b->remoteJob['result']['certificate_fingerprint']=str_repeat('f',64);
    $b->remoteStatus['certificate']=['fingerprint'=>str_repeat($case==='mismatch'?'e':'f',64),'expires'=>time()+($case==='expired'?-10:86400)];
    if($case==='failed')$b->remoteJob=['state'=>'failed'];
    $b->managedNodePoll('aabbccdd');
    $n=$b->pacState['managed_nodes']['aabbccdd'];
    if(in_array($case,['renewed','issued'],true)) {
        $check(($n['last_operation']['certificate_result']??'')===$case,'verified certificate result '.$case);
        $check(in_array('confirm',$b->events),'verified certificate confirmed after traffic');
    } else {
        $check(!in_array('confirm',$b->events),'unverified certificate never confirmed '.$case);
        $check(!isset($n['last_operation']),'unverified certificate never marked successful '.$case);
    }
}
$b=new ManagedFixtureBot();$b->pacState['managed_nodes']['aabbccdd']['job']=null;
foreach ([0,1,2] as $page) {
    $b->managedNodeMaintenanceHelp('aabbccdd',$page);
    $check(mb_strlen(end($b->screens)[0])<4000,'help fits Telegram');
}
echo "PASS certificate evidence and failure notices\n";

class CertificateNoticeFixture extends ManagedFixtureBot {
    public array $sent=[];
    public function send($chat,$text,?int $to=0,$button=false,$reply=false,$mode='HTML',$disable_notification=false) {$this->sent[]=$text;return ['ok'=>true];}
}
foreach(['renewed','unchanged','failed'] as $case) {
    $b=new CertificateNoticeFixture();
    $b->pacState['managed_nodes']['aabbccdd']['job']['operation']='renew';
    $b->pacState['managed_nodes']['aabbccdd']['job']['origin']=['chat'=>1,'message_id'=>5];
    if($case==='renewed') {
        $b->remoteJob['result']['certificate_result']='renewed';
        $b->remoteJob['result']['certificate_fingerprint']=str_repeat('a',64);
        $b->remoteStatus['certificate']=['fingerprint'=>str_repeat('a',64),'expires'=>time()+86400];
    } elseif($case==='unchanged') {$b->remoteJob=['state'=>'done','result'=>['certificate_result'=>'unchanged']];$b->remoteStatus['pending']=null;}
    else $b->remoteJob=['state'=>'failed'];
    $b->managedNodePoll('aabbccdd');
    $check(count($b->sent)===1,'separate certificate result message '.$case);
    $check(str_contains($b->sent[0],'✅')===($case==='renewed'),'success notice only for verified renewal '.$case);
    $b->managedNodePoll('aabbccdd');$check(count($b->sent)===1,'no duplicate result on next poll '.$case);
}
echo "PASS separate certificate notifications\n";
