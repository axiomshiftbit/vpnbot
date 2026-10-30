<?php
require_once __DIR__ . '/../app/bot.php';
set_error_handler(static function ($n, $s, $f, $l) { if (error_reporting() & $n) throw new ErrorException($s, 0, $n, $f, $l); return true; });
class ExitNavigationBot extends Bot {
    public array $p = [], $x = [], $screen = [], $stats = [], $states = [];
    public int $writes = 0, $restarts = 0;
    public bool $restartOk = true;
    public function __construct() {
        require __DIR__ . '/../app/i18n.php'; $this->i18n = $i; $this->language = 'ru'; $this->admin = true;
        $this->input = ['chat'=>1, 'message_id'=>1, 'callback_id'=>'fixture', 'callback'=>'', 'message'=>''];
        $link = 'vless://11111111-1111-4111-8111-111111111111@node.example.org:443?security=tls&sni=node.example.org&type=ws&path=%2Fnode&encryption=none';
        $this->p = ['sniffing' => ['enabled'=>true], 'exits' => [
            'aaaaaaaa' => ['name'=>'Alpha', 'link'=>$link, 'routes'=>['domain:example.org'=>1]],
            '12345678' => ['name'=>'Beta', 'link'=>$link, 'routes'=>['domain:example.org'=>1]],
            'cccccccc' => ['name'=>'Group', 'kind'=>'group', 'members'=>['aaaaaaaa','12345678'], 'fallback'=>'block', 'choice'=>'12345678', 'routes'=>['domain:example.org'=>1]],
            'dddddddd' => ['name'=>'IPv6', 'kind'=>'ipv6', 'routes'=>['domain:example.org'=>1]],
        ]];
        $this->x = ['inbounds'=>[['tag'=>'vless', 'protocol'=>'vless', 'settings'=>['clients'=>[
            ['id'=>'11111111-1111-4111-8111-111111111111', 'email'=>'alice', 'exit'=>['aaaaaaaa','12345678','cccccccc','dddddddd']]]]]],
            'outbounds'=>[['tag'=>'direct','protocol'=>'freedom'],['tag'=>'block','protocol'=>'blackhole']],
            'routing'=>['rules'=>[['type'=>'field','ruleTag'=>'vpnbot:routes:block:fixture','domain'=>['full:blocked.example.org'],'outboundTag'=>'block']]]];
    }
    public function getPacConf() { return $this->p; }
    public function setPacConf(array $p) { $this->writes++; $this->p = $p; return true; }
    public function getXray() { return $this->x; }
    public function restartXray($c, $norestart = false) { $this->restarts++; if (!$this->restartOk) return false; $this->ensureExitNodes($c); $this->x = $c; return true; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
    public function getWgMsg() { return null; }
    public function getXrayStats() { return $this->stats; }
    public function setXrayStats($s) { $this->stats = $s; return true; }
    public function exitStatus(): array { return $this->states; }
    protected function exitIpv6Network(): array { return []; }
    protected function exitIpv6Attached(): bool { return false; }
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML') { $this->screen = [$text, $button ?: []]; }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') { throw new RuntimeException('Unexpected SSH'); }
    public function click(string $callback): void { $this->input['callback'] = $callback; $this->action(); }
    public function buttons(): array { return array_column(array_merge(...$this->screen[1]), 'callback_data'); }
}
$checks = 0;
$check = static function ($ok, $name) use (&$checks) { $checks++; if (!$ok) throw new RuntimeException($name); };
foreach (['ru','en'] as $lang) {
    $b = new ExitNavigationBot(); $b->language = $lang; Lang::$en = $lang === 'en';
    $before = [$b->p, $b->x, $b->stats];
    foreach (['/exits','/exitCreate','/exitOrder','/exit aaaaaaaa','/exit 12345678','/exit cccccccc','/exit dddddddd',
        '/exitSettings aaaaaaaa','/exitSettings cccccccc','/exitSettings dddddddd','/exitDiag aaaaaaaa','/exitDiag cccccccc',
        '/exitGroup cccccccc','/exitFallback aaaaaaaa','/exitTraf aaaaaaaa','/exitSettings deadbeef','/exitDiag deadbeef'] as $cb) {
        $b->click($cb);
        $check($before === [$b->p,$b->x,$b->stats] && !$b->writes && !$b->restarts, "$cb: viewing has no side effects");
        $check($b->messageTextLength($b->screen[0]) < 4096 && !str_contains($b->screen[0], '\\n'), "$cb: Telegram text limits/newlines");
        $check(!str_contains($b->screen[0], '11111111-1111-4111-8111-111111111111'), "$cb: no connection credentials");
        foreach ($b->buttons() as $button) $check(strlen($button) <= 64, "$cb: callback length");
        if ($lang === 'en') $check(!preg_match('~\p{Cyrillic}~u', $b->screen[0]), "$cb: English text");
    }
    $b->click('/exitGroup cccccccc');
    $check(str_contains($b->screen[0], 'Beta') && !str_contains($b->screen[0], '12345678'), 'Human-readable manual choice');
    $b->click('/exitSettings dddddddd');
    $check(!in_array('/exitFallback dddddddd', $b->buttons(), true) && !in_array('/exitLink dddddddd', $b->buttons(), true), 'IPv6 has no direct fallback or remote credentials controls');
    foreach (['create'=>'/exitCreate','order'=>'/exitOrder','node_aaaaaaaa'=>'/exit aaaaaaaa','settings_aaaaaaaa'=>'/exitSettings aaaaaaaa',
        'diag_aaaaaaaa'=>'/exitDiag aaaaaaaa','group_cccccccc'=>'/exitGroup cccccccc'] as $context=>$back) {
        [$title,$route,$pages] = $b->menuHelpContent('exitnodes',$context);
        $check($route === $back, 'Contextual help return');
        foreach (range(0,count($pages)) as $page) {
            $b->click("/menuhelp exitnodes $page $context");
            $check(end($b->screen[1])[0]['callback_data'] === $back && $b->messageTextLength($b->screen[0]) < 4096, 'Every help page returns to the originating menu');
        }
    }
    $check($b->menuHelpContent('exitnodes','settings_aaaaaaaa /menu') === [], 'Invalid help context rejected');
    $b->click('/exitPolicy aaaaaaaa block');
    $check($b->exitNodes()['aaaaaaaa']['fallback'] === 'block', 'Explicit strict choice');
    $writes = $b->writes; $b->click('/exitPolicy aaaaaaaa block');
    $check($writes === $b->writes, 'Repeated explicit choice is idempotent');
    $b->click('/exitPolicy dddddddd direct');
    $check($b->exitNodes()['dddddddd']['fallback'] === 'block', 'Stale/forged button never weakens IPv6');
    $b->click('/exitOrder'); $move = array_values(array_filter($b->buttons(), static fn($cb)=>str_starts_with($cb,'/exitMove 12345678 up ')))[0];
    $before = $b->p; $clients = $b->x['inbounds'][0]['settings']['clients'];
    $b->click($move);
    $check(array_map('strval',array_keys($b->exitNodes())) === ['12345678','aaaaaaaa','cccccccc','dddddddd'], 'Priority supports numeric IDs');
    foreach ($before['exits'] as $id=>$node) $check($b->p['exits'][$id] === $node, 'Priority preserves node settings');
    $check($clients === $b->x['inbounds'][0]['settings']['clients'], 'Priority preserves assignments');
    $rules = array_values(array_filter($b->x['routing']['rules'], static fn($r)=>isset($r['domain'])));
    $check($rules[0]['ruleTag'] === 'vpnbot:routes:block:fixture' && str_starts_with($rules[1]['ruleTag'], 'vpnbot:exit:12345678:'), 'Generated routing honors priority below security rules');
    $after = [$b->p,$b->x]; $b->click($move);
    $check([$b->p,$b->x] === $after, 'Repeated stale movement is rejected');
    $b->click('/exitOrder'); $move = array_values(array_filter($b->buttons(), static fn($cb)=>str_starts_with($cb,'/exitMove aaaaaaaa up ')))[0];
    $b->restartOk = false; $b->click($move);
    $check([$b->p,$b->x] === $after, 'Priority rolls back if Xray rejects it');
    $b->restartOk = true;
    $b->stats = ['users'=>['alice'=>['global'=>['up'=>5]]], 'exits'=>['aaaaaaaa'=>['session'=>['up'=>30,'down'=>50], 'global'=>['up'=>2,'down'=>3]]]];
    $stats = $b->stats; $b->click('/exitTraf aaaaaaaa');
    $check($b->stats === $stats, 'Old counter button requires confirmation');
    $b->click('/exitTrafYes aaaaaaaa');
    $check($b->stats['users'] === $stats['users'] && $b->exitTraffic('aaaaaaaa')['down'] === 0, 'Counter reset keeps user totals');
    $b->states = ['aaaaaaaa'=>['ok'=>true,'time'=>time()-1000]]; $b->click('/exit aaaaaaaa');
    $check(str_contains($b->screen[0], $lang === 'ru' ? 'устарела' : 'stale'), 'Old green status is explicitly stale');
    $b->p['exits']['cccccccc']['members'] = []; $b->click('/exitGroup cccccccc');
    $check(str_contains($b->screen[0], $lang === 'ru' ? 'выбранный участник недоступен' : 'selected member unavailable'), 'Missing manual member explains blocking');
}
echo "exit_navigation_test: $checks OK\n";
