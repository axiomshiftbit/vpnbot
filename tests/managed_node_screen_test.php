<?php
// A finished node job must not replace a screen the admin has moved to in the
// same message: it redraws only an untouched origin, otherwise sends a notice.
require_once __DIR__ . '/../app/bot.php';

class NodeScreenFixture extends Bot {
    public array $state = [];
    public array $menus = [];
    public array $sent = [];
    public function __construct() {}
    public function getPacConf() { return $this->state; }
    public function setPacConf(array $state) { $this->state = $state; return true; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
    public function managedNodeMenu(string $id, string $notice = ''): void { $this->menus[] = [$id, $this->input['message_id'] ?? null]; }
    public function send($chat, $text, $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_preview = false, $disable_notification = false, $protect = false)
    { $this->sent[] = [$chat, $text]; return ['ok' => true, 'result' => ['message_id' => 1]]; }
}

$checks = 0;
$check = static function ($ok, $name) use (&$checks) { $checks++; if (!$ok) throw new RuntimeException('FAIL '.$name); };
$job = ['id' => str_repeat('a', 32), 'operation' => 'configure', 'subject' => '', 'origin' => ['chat' => 777, 'message_id' => 50]];
$fresh = static fn() => ['managed_nodes' => ['aabbccdd' => ['name' => 'yt', 'connected' => true, 'job' => $job]]];

$bot = new NodeScreenFixture();
$moved = static function (array $input) use ($bot, $fresh) {
    $bot->state = $fresh();
    $bot->input = $input + ['chat' => 777, 'message_id' => 50];
    $bot->managedNodeTrackScreen();
    return !empty($bot->state['managed_nodes']['aabbccdd']['job']['origin']['moved']);
};
$check($moved(['callback' => '/nodeMaintenance aabbccdd']), 'another screen in the origin message marks it moved');
$check(!$moved(['callback' => '/node aabbccdd']), 'reopening the same node screen keeps it owned by the job');
$check(!$moved(['callback' => '/nodeRefresh aabbccdd']), 'refreshing the node screen keeps it owned by the job');
$check(!$moved(['callback' => '/nodeMaintenance aabbccdd', 'message_id' => 51]), 'buttons in other messages do not affect the job');
$check(!$moved(['callback' => false, 'message' => 'text']), 'plain messages do not affect the job');

$screen = new ReflectionMethod(Bot::class, 'managedNodeOperationScreen');
$bot->state = $fresh(); $bot->input = ['chat' => 1, 'message_id' => 2]; $bot->menus = []; $bot->sent = [];
$screen->invoke($bot, 'aabbccdd', $job);
$check($bot->menus === [['aabbccdd', 50]] && $bot->sent === [], 'untouched origin is redrawn in place');
$check($bot->input === ['chat' => 1, 'message_id' => 2], 'caller input restored');

$bot->menus = []; $bot->sent = [];
$screen->invoke($bot, 'aabbccdd', array_replace_recursive($job, ['origin' => ['moved' => true]]));
$check($bot->menus === [] && count($bot->sent) === 1 && $bot->sent[0][0] === 777, 'moved origin gets a notice, menu untouched');
$check(str_contains($bot->sent[0][1], 'yt'), 'notice names the node');

$bot->state['managed_nodes']['aabbccdd']['error'] = 'rolled_back'; $bot->sent = [];
$screen->invoke($bot, 'aabbccdd', array_replace_recursive($job, ['origin' => ['moved' => true]]));
$check(count($bot->sent) === 1 && !str_contains($bot->sent[0][1], '✅'), 'rolled back change is not reported as completed');

echo "PASS $checks managed node screen checks\n";
