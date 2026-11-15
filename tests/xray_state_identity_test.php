<?php
$source = getenv('VPNBOT_TEST_SOURCE') ?: dirname(__DIR__);
require_once $source . '/app/bot.php';
require $source . '/app/i18n.php';
class XrayStateFixture extends Bot {
    public string $root;
    public bool $pauseRead = false;
    public int $sent = 0;
    public function __construct(string $root, array $strings) {
        $this->root = $root; $this->xrayConf = "$root/xray.json"; $this->protocolRoot = "$root/absent";
        $this->language = 'ru'; $this->i18n = $strings; $this->admin = true;
        $this->input = ['chat' => 90001, 'from' => 90001, 'message_id' => 1, 'callback_id' => 'synthetic', 'callback' => '', 'message' => '', 'username' => 'synthetic'];
    }
    public function getPacConf() { return self::PAC_DEFAULTS; }
    public function getWgMsg() { return null; }
    public function getXray() {
        $conf = parent::getXray();
        if ($this->pauseRead) {
            $this->pauseRead = false; touch("$this->root/read"); $until = microtime(true) + 3;
            while (!is_file("$this->root/second") && microtime(true) < $until) usleep(1000);
            if (!is_file("$this->root/second")) throw new RuntimeException('second writer not ready');
            usleep(150000);
        }
        return $conf;
    }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) {
        $lock = fopen("$this->root/lock-$name", 'c'); if (!$lock || !flock($lock, LOCK_EX)) return $busy;
        try { return $fn(); } finally { flock($lock, LOCK_UN); fclose($lock); }
    }
    // Native application is excluded here; persistence and all Bot mutation methods are real.
    public function restartXray($conf, $norestart = false) { return $this->writeXrayJson(json_encode($conf, JSON_THROW_ON_ERROR)); }
    public function saveXray(array $config): void { if (!$this->writeXrayJson(json_encode($config, JSON_THROW_ON_ERROR))) throw new RuntimeException('fixture write'); }
    public function extUser($i, string $notice = '') {}
    public function readClients(): array { return [['interface' => ['PrivateKey' => 'synthetic-wg-private']]]; }
    public function userXr($i) {}
    protected function userXrLocked($i) {}
    public function xray($page = 0) {}
    public function menu($type = false, $arg = false, $return = false) {}
    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false) { return ['ok' => true, 'result' => ['message_id' => ++$this->sent]]; }
    public function answer($callback_id, $textNotify = false, $notify = false) {}
    public function delete($chat, $message_id) {}
    public function chatNavigationStart(): void {}
    public function managedNodeNavigationStart(): void {}
    public function managedNodeTrackScreen(): void {}
    public function protocolNavigationStart(): void {}
    protected function sessionApply(callable $fn) { $fn(); }
}
if (($argv[1] ?? '') === 'worker') {
    $bot = new XrayStateFixture($argv[2], $i);
    if ($argv[3] === 'first') { $bot->pauseRead = true; $bot->switchXr(0, 1); }
    else { touch($argv[2] . '/second'); $bot->switchXr(1, 1); }
    exit(0);
}
$failed = [];
$check = static function (bool $ok, string $label) use (&$failed) { if (!$ok) $failed[] = $label; };
$root = sys_get_temp_dir() . '/xray-state-' . bin2hex(random_bytes(8)); mkdir($root, 0700);
$clients = [];
foreach (['alice', 'bob', 'carol'] as $n => $name) $clients[] = ['email' => $name, 'id' => 'synthetic-' . $name, 'password' => 'synthetic-password-' . $name, 'protocol_source' => str_repeat((string) ($n + 1), 32)];
$config = ['inbounds' => [['settings' => ['clients' => $clients]]]];
try {
    $bot = new XrayStateFixture($root, $i);
    $bot->writeXrayJson(json_encode($config));
    {
        $descriptors = [0 => ['file', '/dev/null', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']];
        $pid = proc_open([PHP_BINARY, __FILE__, 'worker', $root, 'first'], $descriptors, $pipes);
        $until = microtime(true) + 3; while (!is_file("$root/read") && microtime(true) < $until) usleep(1000);
        $other = proc_open([PHP_BINARY, __FILE__, 'worker', $root, 'second'], $descriptors, $pipes);
        $a = proc_close($pid); $b = proc_close($other);
        $result = $bot->getXray()['inbounds'][0]['settings']['clients'];
        $check($a === 0 && $b === 0 && !empty($result[0]['off']) && !empty($result[1]['off']) && $result[2] === $clients[2], 'parallel revocations preserve both users');
    }
    $button = static function (XrayStateFixture $bot, string $command, array $config): string {
        $buttons = [[['callback_data' => $command]]];
        return method_exists($bot, 'xrayIdentityButtons') ? $bot->xrayIdentityButtons($buttons, $config)[0][0]['callback_data'] : $command;
    };
    $oldButton = $button($bot, '/switchXr 1', $config);
    $reindexed = $config; array_shift($reindexed['inbounds'][0]['settings']['clients']);
    $bot->writeXrayJson(json_encode($reindexed));
    $bot->input['callback'] = $oldButton; $bot->action();
    $check($bot->getXray() === $reindexed, 'old callback cannot mutate replacement user');
    $bot->writeXrayJson(json_encode($reindexed)); $bot->input['callback'] = '/switchXr 1'; $bot->action();
    $check($bot->getXray() === $reindexed, 'legacy numeric callback is inert');
    $bot->writeXrayJson(json_encode($config)); $bot->input['callback'] = $button($bot, '/switchXr 1', $config); $bot->action();
    $result = $bot->getXray()['inbounds'][0]['settings']['clients'];
    $check(!empty($result[1]['off']) && empty($result[0]['off']) && empty($result[2]['off']), 'fresh identity callback positive control');
    $bot->writeXrayJson(json_encode($config)); $bot->input['callback'] = $button($bot, '/changeXrPwd 1', $config); $bot->action();
    $prompt = $bot->sent;
    $bot->writeXrayJson(json_encode($reindexed)); $bot->input['reply'] = $prompt; $bot->input['message'] = 'synthetic-replacement'; $bot->reply();
    $check($bot->getXray() === $reindexed, 'stashed reply cannot change replacement password');
    $bot->writeXrayJson(json_encode($config)); $bot->input['callback'] = $button($bot, '/changeXrPwd 1', $config); $bot->action();
    $bot->input['reply'] = $bot->sent; $bot->input['message'] = 'synthetic-confirmed'; $bot->reply();
    $result = $bot->getXray()['inbounds'][0]['settings']['clients'];
    $check($result[1]['password'] === 'synthetic-confirmed' && $result[2] === $clients[2], 'fresh password reply positive control');
    $withExt = $config;
    foreach ($withExt['inbounds'][0]['settings']['clients'] as &$client) $client['ext'] = [['kind' => 'link', 'value' => 'vless://synthetic@example.invalid:443', 'off' => 0]];
    unset($client);
    $rowKey = Bot::extRowKey($withExt['inbounds'][0]['settings']['clients'][1]['ext'][0]);
    $oldExtButton = $button($bot, '/extToggle 1_0_' . $rowKey, $withExt);
    $shiftedExt = $withExt; array_shift($shiftedExt['inbounds'][0]['settings']['clients']);
    $bot->writeXrayJson(json_encode($shiftedExt)); $bot->input['callback'] = $oldExtButton; $bot->action();
    $check($bot->getXray() === $shiftedExt, 'same external row hash does not authorize replacement client');
    $bot->writeXrayJson(json_encode($withExt)); $bot->input['callback'] = $oldExtButton; $bot->action();
    $result = $bot->getXray()['inbounds'][0]['settings']['clients'];
    $check(!empty($result[1]['ext'][0]['off']) && empty($result[2]['ext'][0]['off']), 'fresh external row callback positive control');
    $oldLinkButton = $button($bot, '/setVlessLink 1_0_0', $config);
    $bot->writeXrayJson(json_encode($reindexed)); $bot->input['callback'] = $oldLinkButton; $bot->action();
    $check($bot->getXray() === $reindexed, 'stale WireGuard link cannot target replacement Xray user');
    $bot->writeXrayJson(json_encode($config)); $bot->input['callback'] = $oldLinkButton; $bot->action();
    $result = $bot->getXray()['inbounds'][0]['settings']['clients'];
    $check(($result[1]['awg'] ?? '') === 'synthetic-wg-private' && !isset($result[2]['awg']), 'fresh WireGuard link positive control');
    if (method_exists($bot, 'xrayIdentityButtons')) {
        $cb = $button($bot, '/choiceTemplate sing_1_' . base64_encode('synthetic long template name'), $config);
        $check(strlen($cb) <= 64, 'compact template identity fits callback limit');
    }
} finally {
    foreach (glob("$root/*") as $file) unlink($file); rmdir($root); unset($_SESSION['reply']);
}
foreach ($failed as $label) echo "FAIL: $label\n";
echo 'xray_state_identity_test: ', count($failed), " failure(s)\n";
exit($failed ? 1 : 0);
