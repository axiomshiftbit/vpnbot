<?php
require_once __DIR__ . '/../app/bot.php';
class SelfCoverFixture extends Bot {
    public array $p = ['transport' => 'Reality', 'domain' => 'cover.example.test', 'reality' => ['xver' => 0]];
    public array $x = ['inbounds' => [['streamSettings' => ['security' => 'reality', 'realitySettings' => ['dest' => 'external.example.test:443', 'serverNames' => ['external.example.test'], 'xver' => 0]]]]];
    public array $commands = [];
    public bool $accept = true;
    public bool $upstreamOk = true;
    public function __construct() { $this->input = ['chat' => 1, 'message_id' => 1]; $this->language = 'ru'; }
    public function getPacConf() { return $this->p; }
    public function setPacConf(array $p) { $this->p = $p; return true; }
    public function getXray() { return $this->x; }
    public function restartXray($c, $norestart = false) { if (!$this->accept) return false; $this->x = $c; return true; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
    public function realityAcksServerName(): bool { return true; }
    public function realityMaskCheck(bool $fresh = false): ?array { return null; }
    public function xray($page = 0) {}
    public function setUpstreamDomain($domain) { return $this->upstreamOk; }
    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false) { return []; }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') { $this->commands[] = $cmd; $this->sshFailed = false; return ''; }
}
$results = []; $failed = 0; $emit = ($argv[1] ?? '') === '--emit';
$check = static function ($ok, $name) use (&$failed, $emit) { if (!$emit) echo ($ok ? 'PASS ' : 'FAIL ').$name.PHP_EOL; $failed += !$ok; };
foreach ([0, 1, 2] as $xver) {
    $bot = new SelfCoverFixture(); $bot->p['reality']['xver'] = $xver; $bot->x['inbounds'][0]['streamSettings']['realitySettings']['xver'] = $xver;
    $bot->selfFakeDomain();
    $rs = $bot->x['inbounds'][0]['streamSettings']['realitySettings']; $results[] = $rs;
    $check($rs['dest'] === ($xver ? '10.10.0.2:443' : '10.10.1.2:443'), "own cover chooses matching NGINX listener xver=$xver");
    $bot->p['reality']['xver'] = $xver ? 0 : 2;
    $bot->syncRealityLive($bot->p);
    $check($bot->x['inbounds'][0]['streamSettings']['realitySettings']['dest'] === ($xver ? '10.10.1.2:443' : '10.10.0.2:443'), "live xver change preserves own cover xver=$xver");
}
$bot = new SelfCoverFixture(); $p = $bot->p; $x = $bot->x; $bot->accept = false;
$bot->selfFakeDomain();
$check($bot->p === $p && $bot->x === $x, 'failed core change preserves main bot cover settings');
$bot = new SelfCoverFixture(); $p = $bot->p; $x = $bot->x; $bot->upstreamOk = false;
$bot->selfFakeDomain();
$check($bot->p === $p && $bot->x === $x, 'failed NGINX change restores main bot cover settings');
$bot = new SelfCoverFixture(); $bot->realityMaskProbe('10.10.0.2:443', 'cover.example.test');
$check(str_contains(end($bot->commands), '10.10.1.2:443'), 'self-cover probe uses equivalent TLS listener without PROXY header');
if ($emit) { echo json_encode($results, JSON_THROW_ON_ERROR); exit(0); }
exit($failed ? 1 : 0);
