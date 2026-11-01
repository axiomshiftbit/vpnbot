<?php
require_once __DIR__ . '/../app/bot.php';
set_error_handler(static function ($n, $s, $f, $l) { if (error_reporting() & $n) throw new ErrorException($s, 0, $n, $f, $l); return true; });
class NodeNavigationFixture extends Bot {
    public array $p, $screen = [], $replies = [];
    public function showSetting(string $setting): void {
        $transport = in_array($setting, ['reality', 'mask'], true) || str_starts_with($setting, 'xray.reality.') ? 'reality'
            : ($setting === 'xhttp' || str_starts_with($setting, 'xray.xhttp.') ? 'xhttp' : 'ws');
        $this->p['managed_nodes']['aabbccdd']['status']['options']['transport'] = $transport;
        if (isset($this->p['managed_nodes']['aabbccdd']['draft'])) $this->p['managed_nodes']['aabbccdd']['draft']['transport'] = $transport;
    }
    public function __construct() {
        require __DIR__ . '/../app/i18n.php'; $this->i18n = $i; $this->language = 'ru'; $this->admin = true;
        $this->input = ['chat'=>1,'from'=>1,'message_id'=>10,'callback_id'=>'fixture','callback'=>'','message'=>'','username'=>'admin'];
        $link = 'vless://' . '11111111-1111-4111-8111-111111111111' . '@1.1.1.1:443?security=tls&sni=node.example.org&type=ws&path=%2Fnode&encryption=none';
        $options = ['transport'=>'ws','core'=>'origin','family'=>6,'connect_family'=>4,'domain'=>'node.example.org',
            'domain_aliases'=>['alt.example.org'],'mask'=>'mask.example.org','cover'=>true];
        $this->p = ['xray_core'=>'origin','managed_nodes'=>['aabbccdd'=>['name'=>'Test node','connected'=>true,'job'=>null,
            'status'=>['running'=>true,'generation'=>str_repeat('a',32),'options'=>$options,
                'cores'=>['origin'=>'26.10.31','origin2'=>'26.10.29','origin3'=>'25.9.11','fork'=>'26.10.28-1202'],
                'certificate'=>['domains'=>['node.example.org','alt.example.org'],'expires'=>1893456000]],]],
            'exits'=>['aabbccdd'=>['name'=>'Test node','link'=>$link,'routes'=>['domain:example.org'=>1]]]];
    }
    public function getPacConf() { return $this->p; }
    public function setPacConf(array $value) { $this->p=$value; return true; }
    public function getXray() { return ['inbounds'=>[], 'outbounds'=>[], 'routing'=>['rules'=>[]]]; }
    public function getXrayStats() { return []; }
    public function exitStatus(): array { return []; }
    public function getWgMsg() { return null; }
    public function withLock(string $name, callable $f, int $timeout=0, $busy=null) { return $f(); }
    public function update($chat,$message_id,$text,$button=false,$reply=false,$mode='HTML') {
        if (method_exists($this,'managedNodeNavigationButtons')) $button=$this->managedNodeNavigationButtons($button);
        $this->screen=[$text,$button ?: []];
    }
    public function send($chat,$text,?int $to=0,$button=false,$reply=false,$mode='HTML',$disable_notification=false) { return ['ok'=>true,'result'=>['message_id'=>11]]; }
    public function stashReply($r,array $state) { $this->replies[]=$state; }
    public function click(string $callback): void { $this->input['callback']=$callback; $this->action(); }
    public function callbacks(): array { return array_column(array_merge(...$this->screen[1]),'callback_data'); }
    public function labels(): string { return implode(' ',array_column(array_merge(...$this->screen[1]),'text')); }
}
$fail=[]; $count=0;
$check=static function($ok,$name) use (&$fail,&$count) { $count++; if (!$ok) $fail[]=$name; };
foreach (['ru','en'] as $lang) {
    $b=new NodeNavigationFixture(); $b->language=$lang; Lang::$en=$lang==='en';
    $b->managedNodeSettingsMenu('aabbccdd','crypto');
    $check(!in_array('/nodeSettings aabbccdd smux',$b->callbacks(),true),'encryption screen contains no sibling menus');
    $check(end($b->screen[1])[0]['callback_data']==='/nodeSettings aabbccdd','section returns to settings hub');
    $b->managedNodeField('aabbccdd','core');
    $check(str_contains($b->labels(),'26.10.31') && str_contains($b->labels(),'26.10.28-1202'),'core choices show remote versions');
    $b->managedNodeField('aabbccdd','connect_family');
    $check(str_contains($b->labels(),'IPv4') && str_contains($b->labels(),'IPv6'),'family labels are explicit');
    $b->managedNodeMenu('aabbccdd');
    $check(str_contains($b->screen[0],'node.example.org') && str_contains($b->screen[0],'alt.example.org'),'node card lists domains and aliases');
    $check(str_contains($b->screen[0],'2030-01-01'),'node card shows certificate expiry');
    $check(in_array('/nr aabbccdd',$b->callbacks(),true),'routes enter node-scoped navigation');
    $b->click('/nr aabbccdd');
    $check(end($b->screen[1])[0]['callback_data']==='/node aabbccdd','routes return to node card');
    $b->click('/nrRoutes aabbccdd 0');
    $check(end($b->screen[1])[0]['callback_data']==='/nr aabbccdd','nested routes preserve node scope');
    foreach ($b->callbacks() as $cb) $check(strlen($cb)<=64,'callback fits Telegram');
}
$b=new NodeNavigationFixture();
$b->managedNodeSettingsMenu('aabbccdd','reserve');
$check(in_array('/nodeChannel aabbccdd direct',$b->callbacks(),true), 'reserve has direct channel selector');
$b->click('/nr aabbccdd');
$check(!str_contains($b->screen[0], 'Узлы выхода'), 'node routes have their own breadcrumb');
$b->p['managed_nodes']['aabbccdd']['status']['options']['transport']='reality';
$b->saveManagedNodeField('external.example.org','aabbccdd','mask');
$check(($b->p['managed_nodes']['aabbccdd']['draft']['cover'] ?? null)===false, 'manual REALITY domain disables own target');
$b=new NodeNavigationFixture();
$b->input['callback']='/ntaabbccdd xtlsdat'; $b->managedNodeNavigationStart();
$check($b->input['callback']==='/xtlsdat','node DAT callback unwraps');
$rows=$b->managedNodeNavigationButtons([[['callback_data'=>'/routes'],['callback_data'=>'/datschedule']]]);
$check($rows[0][0]['callback_data']==='/nrDat aabbccdd','shared DAT registry returns to node DAT picker');
$check($rows[0][1]['callback_data']==='/ntaabbccdd datschedule','DAT child retains origin');
class NodeReplyFixture extends NodeNavigationFixture {
    protected function sessionApply(callable $fn) { $fn(); }
    public function stashReply($r,array $state) { (new ReflectionMethod(Bot::class,'stashReply'))->invoke($this,$r,$state); }
    public function delete($chat,$message_id) { return true; }
    public function saveExitFixture($text,$id): void { $this->exitSetsMenu($id); }
}
$_SESSION=[]; $b=new NodeReplyFixture();
$b->input['callback']='/nrSets aabbccdd'; $b->managedNodeNavigationStart();
$b->stashReply(['result'=>['message_id'=>11]],['callback'=>'saveExitFixture','args'=>['aabbccdd'],'start_message'=>10]);
$b->input['chat']=2; $b->input['reply']=11; $b->reply();
$check(isset($_SESSION['reply']['1:11']),'another chat cannot consume the pending reply');
$b->input['chat']=1; $b->managedNodeNavigation=[]; $b->reply();
$check(end($b->screen[1])[0]['callback_data']==='/nr aabbccdd','force reply preserves node scope');
$check(!$b->managedNodeNavigation && !isset($_SESSION['reply']['1:11']),'reply context is consumed and cleared');
$b->input['callback']='/exit aabbccdd'; $b->managedNodeNavigationStart();
$check(!$b->managedNodeNavigation,'next regular exit screen has no stale node scope');
foreach (['ru','en'] as $lang) {
    $b=new NodeNavigationFixture(); $b->language=$lang;
    foreach (array_keys(ManagedNodeFields::GROUPS) as $group) {
        $b->showSetting($group); $b->managedNodeSettingsMenu('aabbccdd',$group);
        $check(end($b->screen[1])[0]['callback_data']==='/nodeSettings aabbccdd','every section returns to its hub');
        foreach ($b->callbacks() as $cb) $check(strlen($cb)<=64,'section callback fits Telegram: '.$cb);
    }
    foreach (ManagedNodeFields::all() as $path=>$field) {
        $b->showSetting($path); $b->managedNodeField('aabbccdd',$path);
        $check(end($b->screen[1])[0]['callback_data']===('/nodeSettings aabbccdd'.($field[3]==='bool'?'':' '.$field[0])),'field returns to its own section: '.$path);
        foreach ($b->callbacks() as $cb) $check(strlen($cb)<=64,'field callback fits Telegram: '.$cb);
    }
}
class DisabledNodeModuleFixture extends NodeNavigationFixture {
    public function protocolModuleEnabled(string $module): bool { return false; }
    public function protocolModulesMenu(): void { $this->screen=['modules',[]]; }
}
$b=new DisabledNodeModuleFixture();
$b->click('/nr aabbccdd');
$b->click('/telemt');
$check(!$b->managedNodeNavigation,'disabled module return clears the previous node scope');
foreach ($fail as $name) echo "FAIL $name\n";
echo 'node navigation: '.($count-count($fail))."/$count PASS\n";
exit($fail ? 1 : 0);
