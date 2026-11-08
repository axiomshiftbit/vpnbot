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

class NodeScreenRaceFixture extends NodeScreenFixture {
    public string $moveAt = '';
    public string $navigationCallback = '/nodeMaintenance aabbccdd';
    public int $chat = 777;
    public bool $rollback = false;
    public bool $screenLocked = false;
    public bool $renderLocked = false;
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) {
        if (!str_starts_with($name, 'node-screen-')) return $fn();
        $this->screenLocked = true;
        try { return $fn(); } finally { $this->screenLocked = false; }
    }
    private function navigate(): void {
        $input = $this->input;
        $this->input = ['chat'=>$this->chat, 'message_id'=>50, 'callback'=>$this->navigationCallback];
        $this->managedNodeTrackScreen();
        $this->input = $input;
    }
    public function exitProbe(string $id, bool $full = true): array { return ['ok'=>true]; }
    public function applyExitNodes(callable $edit, bool $force = false): string { return ''; }
    protected function managedNodeTransport(string $id, string $action, $value = null): array {
        if ($this->moveAt === $action) $this->navigate();
        return [];
    }
    protected function managedNodeRpc(string $id, array $request): array {
        if ($this->moveAt === $request['action']) $this->navigate();
        return $request['action'] === 'job' ? ['state'=>$this->rollback ? 'failed' : 'done', 'result'=>[]] : ['pending'=>null];
    }
    public function managedNodeMenu(string $id, string $notice = ''): void {
        $this->renderLocked = $this->screenLocked;
        parent::managedNodeMenu($id, $notice);
    }
}
foreach ([false, true] as $rollback) foreach (['', 'job', 'status', 'snapshot'] as $moveAt) {
    if ($rollback && $moveAt === 'snapshot') continue;
    foreach ([['/nodeMaintenance aabbccdd',777], ['/nodeRefresh aabbccdd',777], ['/nodeMaintenance aabbccdd',778]] as [$callback,$chat]) {
        $race = new NodeScreenRaceFixture(); $race->state = $fresh();
        $race->state['managed_nodes']['aabbccdd']['job'] += ['phase'=>'waiting', 'before'=>null];
        $race->input = ['chat'=>1,'message_id'=>2];
        $race->moveAt = $moveAt; $race->navigationCallback = $callback; $race->chat = $chat; $race->rollback = $rollback;
        $race->managedNodePoll('aabbccdd');
        $notice = $moveAt !== '' && $chat === 777 && $callback !== '/nodeRefresh aabbccdd';
        $check($race->state['managed_nodes']['aabbccdd']['job'] === null, 'poll completes job');
        $check($notice ? count($race->sent) === 1 && !$race->menus : count($race->menus) === 1 && $race->renderLocked,
            'navigation during RPC or snapshot respects origin ownership and locks redraw');
        $check($race->input === ['chat'=>1,'message_id'=>2], 'race preserves caller input');
    }
}
echo "PASS $checks managed node screen checks\n";

// Real competing processes: navigation starts after job=null is persisted but
// before Telegram's redraw completes. It must wait even when no job is visible.
class NodeScreenConcurrentFixture extends NodeScreenRaceFixture {
    public function __construct(public string $root) {}
    public function getPacConf() { return json_decode(file_get_contents($this->root.'/state'), true, 512, JSON_THROW_ON_ERROR); }
    public function setPacConf(array $state) { return file_put_contents($this->root.'/state', json_encode($state)) !== false; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) {
        $lock = fopen($this->root.'/'.hash('sha256', $name), 'c');
        if (!$lock || !flock($lock, LOCK_EX)) throw new RuntimeException('Fixture lock failed');
        try { return $fn(); } finally { flock($lock, LOCK_UN); fclose($lock); }
    }
    public function managedNodeMenu(string $id, string $notice = ''): void {
        touch($this->root.'/rendering');
        usleep(300000);
        file_put_contents($this->root.'/screen', 'node');
    }
}
$root = sys_get_temp_dir().'/node-screen-race-'.bin2hex(random_bytes(6)); mkdir($root, 0700);
try {
    $race = new NodeScreenConcurrentFixture($root); $state = $fresh();
    $state['managed_nodes']['aabbccdd']['job'] += ['phase'=>'waiting', 'before'=>null];
    $race->setPacConf($state); $race->input = ['chat'=>777,'message_id'=>50,'callback'=>'/nodeMaintenance aabbccdd'];
    $pid = pcntl_fork();
    if ($pid === -1) throw new RuntimeException('Fixture fork failed');
    if ($pid === 0) { $race->managedNodePoll('aabbccdd'); exit(0); }
    for ($i=0; $i<200 && !file_exists($root.'/rendering'); $i++) usleep(10000);
    $check(file_exists($root.'/rendering'), 'completion reached redraw');
    $race->managedNodeTrackScreen();
    file_put_contents($root.'/screen', 'maintenance');
    pcntl_waitpid($pid, $status);
    $check(pcntl_wifexited($status) && pcntl_wexitstatus($status) === 0, 'completion process succeeded');
    $check(file_get_contents($root.'/screen') === 'maintenance', 'navigation wins after job was cleared during redraw');
    echo "PASS concurrent node screen completion\n";
} finally { foreach (glob($root.'/*') as $path) unlink($path); rmdir($root); }
