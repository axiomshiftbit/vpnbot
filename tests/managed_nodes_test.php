<?php
require_once __DIR__ . '/../app/bot.php';
set_error_handler(static function ($level, $message, $file, $line) { if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line); return true; });

class ManagedFixtureBot extends Bot
{
    public array $pacState = ['transport' => 'Reality', 'xray_core' => 'origin'];
    public array $xrayState = ['inbounds' => [], 'outbounds' => [['tag' => 'direct', 'protocol' => 'freedom']], 'routing' => ['rules' => []]];
    public array $screens = []; public array $events = [];
    public bool $probePass = true; public bool $corePass = true; public bool $lostConfirm = false; public bool $snapshotPass = true;
    public array $remoteStatus; public array $remoteJob; public array $profile;
    // Reality and XHTTP screens exist only for their transport.
    public function showSetting(string $setting): void {
        $transport = in_array($setting, ['reality', 'mask'], true) || str_starts_with($setting, 'xray.reality.') ? 'reality'
            : ($setting === 'xhttp' || str_starts_with($setting, 'xray.xhttp.') ? 'xhttp' : 'ws');
        $this->pacState['managed_nodes']['aabbccdd']['status']['options']['transport'] = $transport;
    }
    public function __construct()
    {
        $this->input = ['chat' => 1, 'from' => 1, 'message_id' => 5, 'callback_id' => 'fixture', 'username' => 'admin'];
        $this->language = 'ru';
        require __DIR__ . '/../app/i18n.php'; $this->i18n = $i;
        $this->remoteStatus = ['running' => true, 'generation' => str_repeat('b', 32), 'pending' => ['before' => str_repeat('a', 32), 'after' => str_repeat('b', 32), 'nonce' => str_repeat('a', 64)],
            'options' => ['transport' => 'ws', 'core' => 'origin', 'family' => 4, 'connect_family' => 4, 'cover' => false, 'domain' => 'node.example.test', 'mask' => 'mask.example.test']];
        $this->remoteJob = ['state' => 'done', 'result' => ['pending' => $this->remoteStatus['pending']]];
        $fixtureUuid = '11111111-1111-4111-8111-111111111111';
        $this->profile = ['link' => 'vless://' . $fixtureUuid . '@1.1.1.1:443?security=tls&type=ws&path=%2Fnew&sni=node.example.test&fp=chrome',
            'outbound' => ['protocol' => 'vless', 'settings' => [], 'streamSettings' => []]];
        $old = str_replace('%2Fnew', '%2Fold', $this->profile['link']);
        $this->pacState['exits']['aabbccdd'] = ['name' => 'node', 'link' => $old, 'enabled' => 1, 'fallback' => 'block'];
        $this->pacState['managed_nodes']['aabbccdd'] = ['name' => 'node', 'connected' => true, 'status' => $this->remoteStatus,
            'job' => ['id' => str_repeat('c', 32), 'before' => ['link' => $old], 'phase' => 'waiting', 'started' => time()]];
    }
    public function getPacConf() { return $this->pacState; }
    public function setPacConf(array $conf) { $this->pacState = $conf; return true; }
    public function getXray() { return $this->xrayState; }
    public function restartXray($c, $norestart = false) {
        $this->events[] = 'core';
        if (!$this->corePass) return false;
        $this->ensureExitNodes($c, $this->pacState); $this->xrayState = $c; return true;
    }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
    public function exitAddressProblem(string $address): string { return ''; }
    public function exitProbe(string $id, bool $full = true): array { $this->events[] = 'probe'; return ['ok' => $this->probePass]; }
    protected function managedNodeTransport(string $id, string $action, $value = null): array {
        $this->events[] = $action;
        if ($action === 'snapshot') { if (!$this->snapshotPass) throw new RuntimeException('fixture'); return ['saved' => true, 'sha256' => hash('sha256', 'fixture')]; }
        if ($action === 'public') return ['public_key' => 'PUBLIC-FIXTURE'];
        throw new RuntimeException('Unexpected transport action');
    }
    protected function managedNodeRpc(string $id, array $request): array {
        $this->events[] = $request['action'];
        return match ($request['action']) {
            'job' => $this->remoteJob, 'status' => $this->remoteStatus, 'profile' => $this->profile,
            'confirm' => $this->confirmFixture(), 'submit' => ['job' => str_repeat('d', 32)],
            default => throw new RuntimeException('Unexpected RPC'),
        };
    }
    private function confirmFixture(): array {
        $this->remoteStatus['pending'] = null;
        if ($this->lostConfirm) throw new RuntimeException('Lost reply');
        return ['confirmed' => true];
    }
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML') { $this->screens[] = [$text, $button ?: []]; }
    public function notifyAdmins(string $text): void {}
}

$checks = 0;
$check = static function (bool $ok, string $name) use (&$checks): void { $checks++; if (!$ok) throw new RuntimeException('FAIL '.$name); };
$bot = new ManagedFixtureBot();
$bot->managedNodePoll('aabbccdd');
$check($bot->pacState['managed_nodes']['aabbccdd']['job'] === null, 'successful job completed');
$check(array_search('probe', $bot->events) < array_search('confirm', $bot->events), 'real traffic probe precedes confirmation');
$check($bot->pacState['exits']['aabbccdd']['link'] === $bot->profile['link'], 'new profile saved');
$check(isset($bot->pacState['managed_nodes']['aabbccdd']['backup_time']), 'confirmed state backed up');

$bot = new ManagedFixtureBot(); $bot->probePass = false;
$old = $bot->pacState['exits']['aabbccdd']['link'];
$bot->managedNodePoll('aabbccdd');
$check(!in_array('confirm', $bot->events) && $bot->pacState['exits']['aabbccdd']['link'] === $old, 'failed traffic restores old client without confirming');
$check($bot->pacState['managed_nodes']['aabbccdd']['job']['phase'] === 'wait_rollback', 'wait for durable node rollback');
$bot->remoteStatus['generation'] = str_repeat('a', 32); $bot->remoteStatus['pending'] = null;
$bot->managedNodePoll('aabbccdd');
// The rollback followed a failed traffic check: the card keeps that reason.
$check($bot->pacState['managed_nodes']['aabbccdd']['job'] === null && $bot->pacState['managed_nodes']['aabbccdd']['error'] === 'probe_failed', 'rollback recovered after controller restart');

$bot = new ManagedFixtureBot(); $bot->lostConfirm = true;
try { $bot->managedNodePoll('aabbccdd'); } catch (RuntimeException $error) {}
$check($bot->pacState['managed_nodes']['aabbccdd']['job'] !== null, 'lost confirmation response retains durable job');
$bot->lostConfirm = false; $bot->events = [];
$bot->managedNodePoll('aabbccdd');
$check(!in_array('confirm', $bot->events) && $bot->pacState['managed_nodes']['aabbccdd']['job'] === null, 'confirmed generation recovered without double confirmation');

$bot = new ManagedFixtureBot(); $bot->snapshotPass = false;
$bot->managedNodePoll('aabbccdd');
// The confirmed result is reported at once; the copy is retried without holding the screen.
$check($bot->pacState['managed_nodes']['aabbccdd']['job'] === null && !empty($bot->pacState['managed_nodes']['aabbccdd']['backup_stale'])
    && !isset($bot->pacState['managed_nodes']['aabbccdd']['backup_time']), 'failed snapshot does not hold the confirmed job');
$bot->pacState['managed_nodes']['aabbccdd']['status']['pending'] = null;
Closure::bind(fn() => $this->managedNodeBackupRetry('aabbccdd'), $bot, Bot::class)();
$check(!empty($bot->pacState['managed_nodes']['aabbccdd']['backup_stale']), 'snapshot still failing stays stale');
$bot->snapshotPass = true;
Closure::bind(fn() => $this->managedNodeBackupRetry('aabbccdd'), $bot, Bot::class)();
$check(empty($bot->pacState['managed_nodes']['aabbccdd']['backup_stale']) && isset($bot->pacState['managed_nodes']['aabbccdd']['backup_time']), 'backup retry saves the copy');

$bot = new ManagedFixtureBot(); $bot->remoteJob = ['state' => 'running'];
$bot->managedNodePoll('aabbccdd');
$check($bot->events === ['job'], 'running job never triggers premature profile switch');

$bot = new ManagedFixtureBot(); $bot->remoteJob = ['state' => 'failed'];
$bot->managedNodePoll('aabbccdd');
$check($bot->pacState['managed_nodes']['aabbccdd']['job'] === null && !in_array('confirm', $bot->events), 'failed worker is not confirmed');

foreach (['ru', 'en'] as $language) {
    $bot = new ManagedFixtureBot(); $bot->language = $language;
    $bot->pacState['managed_nodes']['aabbccdd']['job'] = null;
    $bot->managedNodesMenu(); $bot->managedNodeMenu('aabbccdd'); $bot->managedNodeMaintenance('aabbccdd');
    foreach (array_keys(ManagedNodeFields::GROUPS) as $group) { $bot->showSetting($group); $bot->managedNodeSettingsMenu('aabbccdd', $group); }
    foreach (ManagedNodeFields::all() as $path => $field) if ($field[3] === 'choice') { $bot->showSetting($path); $bot->managedNodeField('aabbccdd', $path); }
    $bot->showSetting('');
    foreach ($bot->screens as [$text, $rows]) {
        $check(mb_strlen($text) < 4096, 'screen fits Telegram');
        foreach ($rows as $row) foreach ($row as $button) $check(strlen($button['callback_data']) <= 64, 'callback fits Telegram');
    }
    $bot->managedNodeChoice('aabbccdd', 'transport', 'xhttp');
    $check($bot->pacState['managed_nodes']['aabbccdd']['draft']['transport'] === 'xhttp' && !in_array('submit', $bot->events), 'editing is local until Apply');
    $bot->managedNodeApply('aabbccdd');
    $check(in_array('submit', $bot->events) && !isset($bot->pacState['managed_nodes']['aabbccdd']['draft']), 'Apply submits one typed job');
}
// A failed job keeps the node's reason (no error text).
$failed = new ManagedFixtureBot();
$failed->remoteJob = ['state' => 'failed', 'error' => 'operation_failed', 'reason' => 'config_too_large'];
$failed->remoteStatus['pending'] = null;
$failed->managedNodePoll('aabbccdd');
$check(($failed->pacState['managed_nodes']['aabbccdd']['error_reason'] ?? '') === 'config_too_large', 'failure reason recorded');
$failed->managedNodeMenu('aabbccdd');
$check(str_contains(end($failed->screens)[0], 'больше лимита ноды'), 'card names the reason');

// Running jobs are polled between maintenance steps: not before the node can have applied
// anything, then at most every five seconds.
$tick = new ManagedFixtureBot();
$tick->pacState['managed_nodes']['aabbccdd']['job']['started'] = time();
$tick->managedNodeJobsTick();
$check(!in_array('job', $tick->events, true), 'a fresh job is not polled yet');
$tick = new ManagedFixtureBot();
$tick->pacState['managed_nodes']['aabbccdd']['job']['started'] = time() - 20;
$tick->managedNodeJobsTick();
$check(in_array('confirm', $tick->events, true) && $tick->pacState['managed_nodes']['aabbccdd']['job'] === null, 'a due job is confirmed between steps');
$tick->events = [];
$tick->pacState['managed_nodes']['aabbccdd']['job'] = ['id' => str_repeat('d', 32), 'operation' => 'configure', 'started' => time() - 20, 'phase' => 'waiting', 'before' => [], 'origin' => []];
$tick->managedNodeJobsTick();
$check($tick->events === [], 'polled at most every five seconds');
echo "PASS $checks managed node controller/menu checks\n";
