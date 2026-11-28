<?php
require_once __DIR__ . '/../app/bot.php';
require_once __DIR__ . '/managed_protocol_fixture.php';

function expectAccess(bool $condition, string $message): void { if (!$condition) throw new RuntimeException($message); }
class AccessGroupFixture extends Bot
{
    public array $state = [], $config = [], $stats = [], $keys = [];
    public string $screen = '';
    public function __construct(string $root) {
        $this->hysteriaUsersRoot = "$root/hy"; $this->protocolRoot = "$root/protocols";
        $this->input = ['from' => 101, 'chat' => 101, 'message_id' => 1]; $this->admin = true;
        $this->lockDir = $root . '/'; $this->pac = "$root/pac.json";
    }
    public function getXray() { return $this->config; }
    public function getXrayStats() { return $this->stats; }
    public function restartXray($c, $norestart = false) { $this->config = $c; return true; }
    public function getPacConf() { return $this->state; }
    public function setPacConf(array $conf) { $this->state = $conf; return true; }
    protected function sessionApply(callable $fn) { $fn(); }
    public function update($chat, $message_id, $text, $button=false, $reply=false, $mode='HTML') { $this->screen=$text; $this->keys=$button ?: []; }
    public function protocolError(string $message, string $back, string $retry=''): void { $this->screen=$message; }
    protected function userXrLocked($i) {}
    public function delete($chat,$message_id) {}
    public function getWgMsg() { return null; }
    public function hyUserMenu(string $id): void {}
    public function i18n(string $menu): string { return $menu; }
    public function moveTo(string $group, string $key): void {
        $this->click("/agpick $key");
        $this->click("/agmove $group " . $_SESSION['access_group_pick'][101]['token']);
    }
    public function confirmation(): string { return $_SESSION['access_review'][101]['token']; }
    public function click(string $command): void { $this->input['callback'] = $command; $this->action(); }
}
$root = sys_get_temp_dir() . '/vpnbot-group-test-' . bin2hex(random_bytes(6)); mkdir($root,0700);
try {
    $_SESSION=[]; $bot = new AccessGroupFixture($root); $hy = $bot->hysteriaUsersStore(); $id = $hy->add('User <A>');
    $read = fn() => $hy->read()['users'][$id];
    $hy->edit($id, 'toggle');
    $hy->edit($id, 'expires', strtotime('2090-01-01 UTC'));
    foreach (['2028-01-28','2028-01-29','2028-01-30','2028-01-31','2029-01-31','2028-12-31'] as $date) {
        $before = $read(); $input = 'month ' . $date . ' 06:30';
        // Calculate future fixtures relative to the caller's clock when testing the menu.
        $anchor = AccessPolicy::date($date . ' 06:30');
        $schedule = AccessPolicy::schedule($input, $anchor-3600);
        if ($anchor <= time()) continue;
        $bot->accessPolicyReply($input,'hy',$id,'schedule');
        expectAccess($read() === $before && str_contains($bot->screen,'2089-12-31 23:59:59'), 'Preview before saving and last valid second');
        $next = AccessPolicy::next('month', $anchor, $anchor);
        expectAccess(str_contains($bot->screen,gmdate('Y-m-d H:i',$next)), 'UTC calendar dates');
        $bot->click('/areview ' . $bot->confirmation() . ' apply');
        expectAccess($read()['quota_schedule'] === $schedule && !$read()['enabled'] && $read()['reset'] === $before['reset'], 'Exact reviewed schedule and preserved switch, expiry and traffic');
    }
    $bot->hyUserReply('1.5',$id,'quota'); $token=$bot->confirmation();
    $bot->click("/areview $token cancel"); $bot->click("/areview $token apply");
    expectAccess($read()['quota'] === null,'Cancelled preview cannot be replayed');
    $bot->hyUserReply('1.5',$id,'quota'); $token=$bot->confirmation(); $hy->edit($id,'name','Changed');
    $bot->click("/areview $token apply"); expectAccess($read()['quota'] === null,'Concurrent edit rejected');
    $bot->hyUserReply('2',$id,'quota'); $token=$bot->confirmation(); $bot->input['chat']=202;
    $bot->accessEditFinish($token,true); $bot->input['chat']=101; $bot->admin=false; $bot->accessEditFinish($token,true);
    expectAccess($read()['quota'] === null,'Chat and administrator restriction');
    $bot->admin=true; $bot->click("/areview $token apply"); $rev=$hy->read()['revision']; $bot->click("/areview $token apply");
    expectAccess($read()['quota']===2*1073741824 && $hy->read()['revision']===$rev,'Single-use confirmation');
    $bot->accessPolicyReply('0','hy',$id,'schedule'); $bot->accessEditFinish($bot->confirmation(),true);
    expectAccess(!isset($read()['quota_schedule']),'Removing schedule needs confirmation');
    $xid = str_repeat('c',32); $bot->config = ['inbounds'=>[['settings'=>['clients'=>[['protocol_source'=>$xid,'email'=>'Member','off'=>'fixture','time'=>2000000000]]]]]];
    $bot->previewXrayEdit('0',0,'expires'); $bot->accessEditFinish($bot->confirmation(),true);
    expectAccess(!isset($bot->config['inbounds'][0]['settings']['clients'][0]['time']) && isset($bot->config['inbounds'][0]['settings']['clients'][0]['off']), 'Changing Xray expiry preserves manual disable');
    $bot->previewXrayEdit('0.5',0,'quota'); $bot->accessEditFinish($bot->confirmation(),true);
    expectAccess($bot->config['inbounds'][0]['settings']['clients'][0]['traffic']===536870912,'Xray quota applied in bytes');
    foreach (['saveTrafficXr'=>'3','setTimerXr'=>'2037-06-02 03:01 UTC'] as $old=>$input) {
        $original=$bot->config; $bot->input['reply']=18; $bot->input['message']=$input;
        $_SESSION['reply']['101:18']=['callback'=>$old,'args'=>[0],'xray_source'=>$xid,'chat'=>101,'start_message'=>1];
        $bot->reply(); expectAccess($bot->config===$original && isset($_SESSION['access_review'][101]),'Prompt saved by an earlier version requires preview');
        $bot->accessEditFinish($bot->confirmation(),false);
    }
    $savedXray = $bot->config;
    $bot->config['inbounds'][0]['settings']['clients'][0]['time'] = time()-10;
    $bot->config['inbounds'][0]['settings']['clients'][0]['traffic_off'] = true;
    $bot->previewXrayEdit('0',0,'quota'); $bot->accessEditFinish($bot->confirmation(),true);
    expectAccess(!empty($bot->config['inbounds'][0]['settings']['clients'][0]['off']), 'Lifting a quota must keep an expired VLESS identity disabled');
    $bot->config = $savedXray;
    $meter = static function ($store, $id, $n) {
        $dir = $store instanceof HysteriaUsers ? $store->root : $store->directory();
        if (!is_dir("$dir/runtime")) mkdir("$dir/runtime",0700,true);
        ManagedProtocol::writeJson("$dir/runtime/usage.json",['users'=>[$id=>['upload'=>$n,'download'=>0,'reset'=>$store->read()['users'][$id]['reset']]]]);
    };
    $member = "hy.$id"; $meter($hy,$id,100); $bot->accessGroupName('Team'); $group=array_key_first($bot->state['access_groups']['groups']);
    $bot->moveTo($group, $member); $meter($hy,$id,180); $bot->click("/ag show $group"); $bot->captureAccessGroupUsage();
    $total = fn($g) => $bot->state['access_groups']['groups'][$g]['bytes'];
    expectAccess($total($group)===80,'Joining excludes earlier bytes, repeat sample adds nothing');
    $bot->accessGroupName('Renamed',$group); expectAccess($total($group)===80,'Renaming preserves usage');
    $bot->accessGroupName('Next'); $other=array_key_last($bot->state['access_groups']['groups']);
    $bot->click("/agpick $member"); $staleMove = $_SESSION['access_group_pick'][101]['token']; $firstAdmin = $_SESSION;
    $_SESSION=[]; $bot->input['from']=202; $meter($hy,$id,200); $bot->moveTo($other, $member);
    $_SESSION=$firstAdmin; $bot->input['from']=101; $bot->click("/agmove - $staleMove");
    expectAccess($bot->state['access_groups']['members'][$member]['group']===$other, 'Old group picker cannot overwrite another administrator');
    $oldEpoch=$read()['reset'];
    expectAccess($total($group)===100 && $total($other)===0,'Transfer credits the old group up to the move');
    $meter($hy,$id,250); $bot->captureAccessGroupUsage(); $hy->edit($id,'reset'); $meter($hy,$id,22); $bot->captureAccessGroupUsage();
    expectAccess($total($other)===72,'Changed counter epoch adds post-reset bytes once');
    $before=$hy->read()['users'][$id]; $hy->edit($id,'delete'); $bot->click("/ag show $other");
    expectAccess($total($other)===72 && str_contains($bot->screen,'1'),'Removed member retains recorded bytes');
    $hy->change(static function(&$s) use($id,$before){$s['users'][$id]=$before;}); $meter($hy,$id,12); $bot->captureAccessGroupUsage();
    expectAccess($total($other)===72,'Restoring an older reading does not re-credit it');
    $linked = $bot->protocolStore('anytls'); $linked->syncXrayUsers([$xid => ['name'=>'Member','enabled'=>true,'quota'=>null,'expires'=>null,'xray_credential'=>hash('sha256','synthetic')]]);
    $linkId=array_key_first($linked->read()['users']);
    expectAccess($linkId!==null,'Shared protocol fixture created');
    $meter($linked,$linkId,60); $bot->stats=['users'=>[['global'=>['upload'=>50,'download'=>0]]]];
    $bot->moveTo($other, "xr.$xid"); $bot->stats['users'][0]['global']['upload']=90; $meter($linked,$linkId,110);
    $bot->captureAccessGroupUsage(); expectAccess($total($other)===162,'Shared VLESS transports counted once');
    $bot->stats['group_epochs'][$xid]=str_repeat('a',16); $bot->stats['users'][0]['global']['upload']=9; $bot->captureAccessGroupUsage();
    expectAccess($total($other)===171,'New VLESS counter epoch retains historical total');
    $bot->groupXrayReply('quota 2',$other,0); $token=$_SESSION['group_xray'][101]['token'];
    $bot->moveTo($group, "xr.$xid"); $bot->groupXrayFinish($token,true);
    expectAccess($bot->config['inbounds'][0]['settings']['clients'][0]['traffic']===536870912,'Moved member excluded from stale mass edit');
    $bot->groupXrayReply('quota 2',$group,0); $bot->click('/agxrapply '.$_SESSION['group_xray'][101]['token'].' yes');
    expectAccess($bot->config['inbounds'][0]['settings']['clients'][0]['traffic']===2147483648,'Reviewed Xray group quota saved');
    $bot->accessBatchStart('hy',$other); $token=$_SESSION['access_batch'][101]['token']; $bot->accessBatchReply('3',$token,'quota');
    $confirm=$_SESSION['access_batch'][101]['confirm']; $bot->moveTo($group, $member); $bot->accessBatch($token,'apply',$confirm);
    expectAccess($read()['quota']===2147483648,'Stale independent group bulk confirmation rejected');
    try { $bad=$bot->state['access_groups']; $bad['groups'][$group]['bytes']=-1; Bot::validateAccessGroups($bad); throw new LogicException('Invalid backup accepted'); }
    catch (InvalidArgumentException $ok) {}
    $activeEpoch=$read()['reset']; $credited=$total($group);
    $hy->change(static function(&$s) use($id,$oldEpoch){$s['users'][$id]['reset']=$oldEpoch;});
    $meter($hy,$id,240); $bot->captureAccessGroupUsage(); expectAccess($total($group)===$credited,'Returning to an earlier epoch after moving does not double count');
    $hy->change(static function(&$s) use($id,$activeEpoch){$s['users'][$id]['reset']=$activeEpoch;});
    $meter($hy,$id,12);
    $copy=$bot->config['inbounds'][0]['settings']['clients'][0]; $bot->config['inbounds'][0]['settings']['clients'][]=$copy;
    $bot->groupXrayReply('quota 5',$group,0); expectAccess(!isset($_SESSION['group_xray'][101]),'Ambiguous shared identity cannot be bulk edited');
    array_pop($bot->config['inbounds'][0]['settings']['clients']);
    $disk = new class($root) extends AccessGroupFixture {
        public function getPacConf() { return file_exists($this->pac) ? ManagedProtocol::readJson($this->pac) : []; }
        public function setPacConf(array $conf) { ManagedProtocol::writeJson($this->pac,$conf); return true; }
    };
    $disk->config=$bot->config; $disk->stats=$bot->stats; $disk->setPacConf($bot->state);
    $start=$disk->getPacConf()['access_groups']['groups'][$group]['bytes']; $meter($hy,$id,52);
    if (function_exists('pcntl_fork')) {
        $workers=[];
        for($i=0;$i<2;$i++) {
            $pid=pcntl_fork(); if ($pid===-1) throw new RuntimeException('fork failed');
            if ($pid===0) { for($j=0;$j<5;$j++) $disk->captureAccessGroupUsage(); exit(0); }
            $workers[]=$pid;
        }
        foreach($workers as $pid) { pcntl_waitpid($pid,$status); expectAccess(pcntl_wifexited($status) && pcntl_wexitstatus($status)===0,'Concurrent reader exit'); }
    } else $disk->captureAccessGroupUsage();
    expectAccess($disk->getPacConf()['access_groups']['groups'][$group]['bytes']===$start+30,'Serialized group observations credit each byte once');
    $disk->accessGroupCommand('list'); expectAccess(end($disk->keys)[0]['callback_data']==='/xray','Group list returns to the VLESS menu');
    $nowGroup=$disk->getPacConf()['access_groups']['groups'][$other]['bytes'];
    unlink($hy->root.'/runtime/usage.json'); $disk->moveTo($other,$member);
    $meter($hy,$id,105); $disk->captureAccessGroupUsage();
    expectAccess($disk->getPacConf()['access_groups']['groups'][$other]['bytes']===$nowGroup,'Unavailable reading at transfer cannot charge the new group for the gap');
    expectAccess(!empty($disk->getPacConf()['access_groups']['groups'][$group]['incomplete']),'Old group shows partial historical usage');
    echo "access_groups_preview_test OK\n";
} finally {
    $it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);
    foreach($it as $f) $f->isDir()?rmdir($f->getPathname()):unlink($f->getPathname()); rmdir($root);
}
