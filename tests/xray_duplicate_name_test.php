<?php
// Xray refuses two clients with the same email, case-insensitively ("User Alice
// already exists"). The bot compared names case-sensitively on add and not at
// all on rename: the core then rejected the whole configuration and the
// administrator only saw "Could not apply Xray settings".
require_once __DIR__ . '/../app/bot.php';
require __DIR__ . '/../app/i18n.php';

class DupNameBot extends Bot
{
    public array $sent = [], $applied = [], $opened = [];
    public array $xr = ['inbounds' => [['settings' => ['clients' => [
        ['id' => '11111111-1111-4111-8111-111111111111', 'email' => 'alice'],
        ['id' => '22222222-2222-4222-8222-222222222222', 'email' => 'bob'],
    ]]]]];
    public function __construct(array $strings) { $this->i18n = $strings; $this->language = 'en'; $this->input = ['chat' => 1, 'from' => 1, 'message_id' => 2, 'callback_id' => '']; }
    public function getXray() { return $this->xr; }
    public function getPacConf() { return ['transport' => 'Reality']; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
    public function restartXray($c, $norestart = false) { $this->applied[] = array_column($c['inbounds'][0]['settings']['clients'], 'email'); $this->xr = $c; return true; }
    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false) { $this->sent[] = $text; return []; }
    public function xray($page = 0) { $this->opened[] = 'xray'; }
    protected function userXrLocked($i) { $this->opened[] = "user:$i"; }
    public function adguardXrayClients() {}
    public function adgFillAllowedClients($delete = false) {}
}
$failed = 0; $count = 0;
$check = static function (bool $ok, string $what) use (&$failed, &$count) { $count++; if (!$ok) { $failed++; echo "FAIL: $what\n"; } };
foreach (['Alice', 'ALICE', 'bob'] as $name) {
    $b = new DupNameBot($i);
    try { $b->addxrus($name); $error = null; } catch (Throwable $e) { $error = $e; }
    $check($error === null && $b->applied === [], "add '$name': refused before Xray, no generic failure");
    $check((bool) array_filter($b->sent, fn($t) => str_contains($t, 'already exists')), "add '$name': the administrator is told the name exists");
}
$b = new DupNameBot($i);
try { $b->addxrus('carol,Carol'); $error = null; } catch (Throwable $e) { $error = $e; }
$check($error === null && $b->applied === [], 'add a name twice in one input: refused before Xray');
$b = new DupNameBot($i); $b->addxrus('carol');
$check($b->applied === [['alice', 'bob', 'carol']], 'a new name is still added');

foreach (['bob', 'BOB'] as $name) {
    $b = new DupNameBot($i);
    try { $b->renXrUs($name, 0); $error = null; } catch (Throwable $e) { $error = $e; }
    $check($error === null && $b->applied === [], "rename alice -> '$name': refused before Xray");
    $check((bool) array_filter($b->sent, fn($t) => str_contains($t, 'already exists')) && $b->opened === ['user:0'], "rename alice -> '$name': message and the user card");
}
$b = new DupNameBot($i); $b->renXrUs('Alice', 0);
$check($b->applied === [['Alice', 'bob']], 'changing only the case of the own name is allowed');
$b = new DupNameBot($i); $b->renXrUs('dave', 0);
$check($b->applied === [['dave', 'bob']], 'a free name is still applied');
echo "xray_duplicate_name_test: " . ($count - $failed) . "/$count\n";
exit($failed ? 1 : 0);
