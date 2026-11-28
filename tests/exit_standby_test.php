<?php
require_once __DIR__ . '/../app/bot.php';

class StandbyBot extends Bot
{
    public array $settings = [];
    public array $buttons = [];
    public function __construct() { $this->input = ['chat' => 1, 'message_id' => 1]; }
    public function getPacConf() { return $this->settings; }
    protected function exitIpv6Attached(): bool { return false; }
    public function i18n(string $menu): string { return $menu; }
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML') { $this->buttons = $button; }
    public function exitSettingsMenu(string $id, string $notice = ''): void {}
    public function applyExitNodes(callable $edit, bool $renewSession = false): string {
        $pac = $this->settings;
        $error = $edit($pac);
        if ($error === '') $this->settings = $pac;
        return $error;
    }
}
function standbyCheck(bool $ok, string $message): void {
    if (!$ok) throw new RuntimeException($message);
}
$bot = new StandbyBot();
$first = 'aaaaaaaa';
$second = 'bbbbbbbb';
$link = 'vless://11111111-2222-4333-8444-555555555555@node.example.test:443?security=tls&sni=node.example.test&type=ws&path=%2F';
$node = ['link' => $link, 'quic' => 'pass', 'enabled' => 1, 'routes' => ['domain:sample.test' => 1]];
$clients = [
    ['id' => '11111111-1111-4111-8111-111111111111', 'email' => 'full', 'exit_full' => $first],
    ['id' => '22222222-2222-4222-8222-222222222222', 'email' => 'listed', 'exit' => [$first]],
    ['id' => '33333333-3333-4333-8333-333333333333', 'email' => 'other'],
];
$base = ['inbounds' => [['tag' => 'in', 'port' => 10869, 'protocol' => 'vless',
    'settings' => ['decryption' => 'none', 'clients' => $clients]]],
    'outbounds' => [['tag' => 'direct', 'protocol' => 'freedom'], ['tag' => 'block', 'protocol' => 'blackhole']],
    'routing' => ['rules' => []]];
$generate = function ($target, $backup, $guard = false, $controller = false) use ($bot, $base, $first, $second, $node) {
    $bot->settings = ['exits' => [$first => ['standby' => $target, 'standby_delay' => 30] + $node]];
    if ($backup !== null) $bot->settings['exits'][$second] = $backup;
    if ($guard) $bot->settings['exits'][$first]['policy'] = ['routes' => ['block' => [
        'domain' => ['full:blocked.sample.test'], 'ip' => ['192.0.2.1/32']]]];
    $c = $base;
    if ($controller) $c['routing'] = ['domainStrategy' => 'IPIfNonMatch', 'rules' => [[
        'type' => 'field', 'ruleTag' => 'vpnbot:routes:block:ip', 'ip' => ['203.0.113.9/32'], 'outboundTag' => 'block']]];
    $bot->ensureExitNodes($c, $bot->settings);
    return $c;
};
foreach ([[$second,$node,'vpnbot-exit-'.$second], ['main',$node,'direct'], [$second,null,'block'],
          [$second,['enabled'=>0]+$node,'block'], [$second,['link'=>'']+$node,'block']] as [$choice,$backup,$target]) {
    $c = $generate($choice,$backup);
    $tag = "vpnbot-exit-timed-$first-$choice-30-$target";
    $balancers = array_column($c['routing']['balancers'] ?? [], null, 'tag');
    standbyCheck(isset($balancers[$tag]) && $balancers[$tag]['fallbackTag'] === 'vpnbot-exit-'.$first, 'primary stays selected during grace');
    $rules = array_column($c['routing']['rules'], null, 'ruleTag');
    foreach (['full','domain'] as $kind) standbyCheck(($rules["vpnbot:exit:$first:$kind"]['balancerTag'] ?? '') === $tag, 'both routes use timed policy');
    standbyCheck($rules["vpnbot:exit:$first:probe"]['outboundTag'] === 'vpnbot-exit-'.$first, 'probe goes through primary only');
    $again = $c; $bot->ensureExitNodes($again, $bot->settings);
    standbyCheck($again === $c,'repeated generation changes configuration');
}
$guarded = $generate($second,$node,true);
$ruleTags = array_column($guarded['routing']['rules'],null,'ruleTag');
standbyCheck(($ruleTags["vpnbot:exit:fallback-$first:domain"]['outboundTag'] ?? '') === 'block', 'reserved domain protection');
standbyCheck(($ruleTags["vpnbot:exit:fallback-$first:ip"]['outboundTag'] ?? '') === 'block', 'reserved IP protection');
$legacyPolicy = ['routes_digest'=>hash('sha256','[]'), 'bindings'=>['all'=>[['action'=>'block','list'=>'restricted']]],
    'lists'=>['restricted'=>['domain'=>['full:backup-only.test']]]];
$backupConfig = $generate($second, ['quic'=>'block', 'policy'=>$legacyPolicy]+$node);
$backupRules = array_column($backupConfig['routing']['rules'], null, 'ruleTag');
standbyCheck(in_array('full:backup-only.test', $backupRules["vpnbot:exit:fallback-$first:domain"]['domain'] ?? [], true), 'confirmed backup block with an empty routes digest');
standbyCheck(($backupRules["vpnbot:exit:fallback-$first:quic"]['outboundTag'] ?? '') === 'block', 'backup UDP/443 policy');
foreach ([$first, 'invalid', []] as $bad) {
    $nodes = $bot->exitNodes(['exits'=>[$first=>['standby'=>$bad]+$node]]);
    standbyCheck($nodes[$first]['standby']==='' && $nodes[$first]['fallback']==='block','invalid standby fails closed');
}
$bot->settings = ['exits' => [$first => $node, $second => $node + ['name' => 'Резерв']]];
$bot->exitStandby($first, $second, null);
$bot->exitStandby($first, null, 120);
standbyCheck($bot->settings['exits'][$first]['standby'] === $second && $bot->settings['exits'][$first]['standby_delay'] === 120, 'select a standby and change its delay');
$buttons = array_merge(...$bot->buttons);
standbyCheck(in_array('/exitDelay '.$first.' 300', array_column($buttons, 'callback_data'), true), 'delay buttons are reachable');
foreach ([$first,'cccccccc'] as $invalid) $bot->exitStandby($first, $invalid, null);
standbyCheck($bot->settings['exits'][$first]['standby'] === $second, 'stale callback changed the existing target');
$bot->exitFallback($first,'block');
standbyCheck($bot->settings['exits'][$first]['standby'] === '', 'disable timed standby');
if (($argv[1] ?? '') === '--fixture') {
    echo json_encode($generate(($argv[2] ?? '') === 'main' ? 'main' : $second,
        ['policy'=>$legacyPolicy]+$node, true, ($argv[3] ?? '') === 'controller'), JSON_THROW_ON_ERROR);
} else echo "exit_standby_test OK\n";
