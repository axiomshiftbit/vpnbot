<?php
require __DIR__ . '/managed_nodes_test.php';
class RestoreMenuFixture extends ManagedFixtureBot {
    public array $requests = [];
    public array $saved = ['snapshot' => ['fixture' => 'original'], 'hash' => '0123456789abcdef'];
    public ?array $imported = null;
    public bool $rejectSubmit = false;
    public function __construct() {
        parent::__construct();
        $this->pacState['managed_nodes']['aabbccdd']['job'] = null;
        $this->remoteStatus['pending'] = null;
        $this->remoteStatus['generation'] = str_repeat('e', 32);
    }
    protected function managedNodeTransport(string $id, string $action, $value = null): array {
        if ($action === 'restore-source') { $this->events[] = $action; return $this->imported ?? $this->saved; }
        if ($action === 'import-clear') {
            $cleared = $this->imported !== null && $value === $this->imported['hash'];
            if ($cleared) $this->imported = null;
            return ['cleared' => $cleared];
        }
        return parent::managedNodeTransport($id, $action, $value);
    }
    protected function managedNodeRpc(string $id, array $request): array {
        $this->requests[] = $request;
        if ($this->rejectSubmit && $request['action'] === 'submit') throw new RuntimeException('Submit failed');
        return parent::managedNodeRpc($id, $request);
    }
}
$checks = 0;
$check = static function ($ok, $name) use (&$checks) { $checks++; if (!$ok) throw new RuntimeException('FAIL '.$name); };
foreach (['ru', 'en'] as $lang) {
    $bot = new RestoreMenuFixture(); $bot->language = $lang;
    $bot->managedNodeRestore('aabbccdd');
    $check(!$bot->requests, 'opening restore never contacts or mutates remote');
    [$text, $buttons] = end($bot->screens);
    $check(!str_contains($text, 'original') && str_contains($buttons[0][0]['callback_data'], '0123456789abcdef'), 'confirmation binds snapshot without displaying it');
    $bot->managedNodeRestore('aabbccdd', '0123456789abcdef');
    $request = end($bot->requests)['request'];
    $check($request === ['operation' => 'restore', 'value' => $bot->saved['snapshot'], 'generation' => str_repeat('e', 32)], 'old backup restored against current remote generation');
    $check(!in_array('snapshot', $bot->events), 'restore does not overwrite selected backup');
    foreach (['changed', 'pending', 'busy', 'missing', 'bad_generation'] as $case) {
        $bot = new RestoreMenuFixture();
        if ($case === 'changed') $bot->saved['hash'] = 'fedcba9876543210';
        if ($case === 'pending') $bot->remoteStatus['pending'] = ['nonce' => 'fixture'];
        if ($case === 'busy') $bot->pacState['managed_nodes']['aabbccdd']['job'] = ['id' => 'fixture'];
        if ($case === 'missing') $bot->saved = [];
        if ($case === 'bad_generation') $bot->remoteStatus['generation'] = 'bad';
        $bot->managedNodeRestore('aabbccdd', '0123456789abcdef');
        $check(!in_array('submit', $bot->events), 'unsafe restore refused: '.$case);
    }
}
$node = 'aabbccdd';
$bot = new RestoreMenuFixture();
$candidateHash = 'aaaaaaaaaaaaaaaa';
$bot->imported = ['snapshot' => ['options' => ['warp_mode' => 'off'], 'identity' => ['warp_account' => '0123456789abcdef']],
    'hash' => $candidateHash, 'imported' => true];
$bot->pacState['managed_nodes'][$node]['backup_time'] = 1700000000;
$bot->rejectSubmit = true;
$bot->managedNodeRestore($node, $candidateHash);
$check($bot->imported !== null, 'uncertain submit preserves the upload');
$bot->managedNodeRestore($node);
[$notice, $buttons] = end($bot->screens);
$check(!str_contains($notice, date('Y-m-d H:i', 1700000000)), 'an undated upload does not display the date of the confirmed snapshot');
$check(str_contains($notice, 'WARP+'), 'cold restore warns even if a previously registered WARP account is disabled');
$check(in_array("/nodeImportDiscard $node $candidateHash", array_column(array_merge(...$buttons), 'callback_data'), true), 'a rejected upload can be discarded explicitly');
$bot->managedNodeDiscardImport($node, 'bbbbbbbbbbbbbbbb');
$check($bot->imported !== null, 'stale discard keeps the newer import');
$bot->managedNodeDiscardImport($node, $candidateHash);
$bot->managedNodeRestore($node);
$check($bot->imported === null && str_ends_with(end($bot->screens)[1][0][0]['callback_data'], $bot->saved['hash']), 'discard makes the previous confirmed copy available');
echo "PASS $checks saved node restore menu checks\n";
