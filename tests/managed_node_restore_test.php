<?php
require __DIR__ . '/managed_nodes_test.php';
class RestoreMenuFixture extends ManagedFixtureBot {
    public array $requests = [];
    public array $saved = ['snapshot' => ['fixture' => 'original'], 'hash' => '0123456789abcdef'];
    public function __construct() {
        parent::__construct();
        $this->pacState['managed_nodes']['aabbccdd']['job'] = null;
        $this->remoteStatus['pending'] = null;
        $this->remoteStatus['generation'] = str_repeat('e', 32);
    }
    protected function managedNodeTransport(string $id, string $action, $value = null): array {
        if ($action === 'restore-source') { $this->events[] = $action; return $this->saved; }
        return parent::managedNodeTransport($id, $action, $value);
    }
    protected function managedNodeRpc(string $id, array $request): array {
        $this->requests[] = $request;
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
echo "PASS $checks saved node restore menu checks\n";
