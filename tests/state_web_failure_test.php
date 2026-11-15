<?php
// Синтетические файлы и owner-контекст; сеть и установленный app/config.php не используются.
$source = getenv('VPNBOT_TEST_SOURCE') ?: dirname(__DIR__);
require_once $source . '/app/bot.php';
require_once $source . '/app/panel/Panel.php';

$failures = [];
function verifyStateWeb(bool $condition, string $label): void {
    global $failures;
    if (!$condition) $failures[] = $label;
}
class StateWebBot extends Bot {
    public array $conf = [];
    public bool $writeFails = false;
    public bool $lockFails = false;
    public bool $owner = false;
    public int $probes = 0;
    public function __construct() { $this->input = []; $this->language = 'ru'; }
    public function getPacConf() { return $this->conf; }
    public function setPacConf(array $conf) { if ($this->writeFails) return false; $this->conf = $conf; return true; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $this->lockFails ? $busy : $fn(); }
    public function getHashBot($notset = false) { return 'statewebfixture'; }
    public function isOwner(): bool { return $this->owner; }
    public function telegramApiProbe(string $url): array { $this->probes++; return ['ok' => false, 'reason' => 'network']; }
    public function telegramApiClientMenu(string $notice = '') {}
}

$root = sys_get_temp_dir() . '/state-web-failure-' . bin2hex(random_bytes(8));
mkdir($root, 0700);
$remove = static function (string $path) use (&$remove): void {
    if (is_dir($path) && !is_link($path)) {
        foreach (scandir($path) as $name) if ($name !== '.' && $name !== '..') $remove($path . '/' . $name);
        rmdir($path);
    } else unlink($path);
};
try {
    $bot = new StateWebBot();
    $bot->writeFails = true; $rejected = false;
    try { $bot->pacConfUpdate(static function (&$conf) { $conf['setting'] = 1; return true; }); }
    catch (RuntimeException $error) { $rejected = true; }
    verifyStateWeb($rejected && $bot->conf === [], 'PAC write failure is not callback success');
    $bot->writeFails = false; $bot->lockFails = true; $rejected = false;
    try { $bot->pacConfUpdate(static function (&$conf) { $conf['setting'] = 1; return true; }); }
    catch (RuntimeException $error) { $rejected = true; }
    verifyStateWeb($rejected && $bot->conf === [], 'PAC lock failure is explicit');
    $bot->lockFails = false;
    verifyStateWeb($bot->pacConfUpdate(static function (&$conf) { $conf['setting'] = 1; return 17; }) === 17
        && $bot->conf['setting'] === 1, 'PAC success preserves callback result');
    verifyStateWeb($bot->pacConfUpdate(static fn(&$conf) => false) === false, 'PAC logical false remains false');

    $bot->telegramApiReply('https://fixture.example.test', 'client');
    verifyStateWeb($bot->probes === 0, 'non-owner reply cannot probe candidate');
    $beforeOwner = $bot->probes;
    $bot->owner = true; $bot->telegramApiReply('https://fixture.example.test', 'client');
    verifyStateWeb($bot->probes === $beforeOwner + 1, 'owner reaches trusted low-level operation');
    $beforeRevocation = $bot->probes;
    $bot->owner = false; $bot->telegramApiReply('https://fixture.example.test', 'client');
    verifyStateWeb($bot->probes === $beforeRevocation, 'reply rechecks changed owner role');

    $store = new PanelStore($root . '/healthy');
    $transport = new PanelTransport($store);
    $result = $transport->call('sendDocument', ['document' => new CURLStringFile('synthetic', 'fixture.txt')]);
    verifyStateWeb(!empty($result['ok']) && isset($result['result']['message_id']), 'healthy attachment delivery');
    $result = $transport->call('sendDocument', ['document' => new CURLFile($root . '/missing')]);
    verifyStateWeb(empty($result['ok']) && !isset($result['result']['message_id']), 'unreadable attachment cannot be delivered');

    $badFiles = new PanelStore($root . '/bad-files');
    rmdir($badFiles->filesDir()); file_put_contents(rtrim($badFiles->filesDir(), '/'), 'synthetic');
    set_error_handler(static fn() => true);
    try { $result = (new PanelTransport($badFiles))->call('sendDocument', ['document' => new CURLStringFile('synthetic', 'fixture.txt')]); }
    finally { restore_error_handler(); }
    verifyStateWeb(empty($result['ok']) && !isset($result['result']['message_id']), 'failed file write cannot be delivered');

    $badState = new PanelStore($root . '/bad-state');
    mkdir($badState->dir() . '/state.json', 0700);
    set_error_handler(static fn() => true);
    try { $result = (new PanelTransport($badState))->call('sendMessage', ['text' => 'synthetic']); }
    finally { restore_error_handler(); }
    verifyStateWeb(empty($result['ok']) && !isset($result['result']['message_id']), 'failed state commit cannot be delivered');

    $before = $store->read();
    unlink($store->dir() . '/state.json.lock'); mkdir($store->dir() . '/state.json.lock', 0700);
    $rejected = false;
    set_error_handler(static fn() => true);
    try { $store->reset(); } catch (RuntimeException $error) { $rejected = true; }
    finally { restore_error_handler(); }
    verifyStateWeb($rejected && $store->read() === $before, 'failed state lock preserves old messages');
    foreach ($before['messages'] as $message) {
        if (!empty($message['attach']['file'])) verifyStateWeb($store->fileExists($message['attach']['file']), 'failed mutation preserves referenced attachment');
    }

    $bot->conf = ['panelpswd' => password_hash('synthetic-password', PASSWORD_DEFAULT)];
    $panel = new Panel($bot, ['key' => 'synthetic-session-key', 'admin' => [900001]], new PanelStore($root . '/auth'));
    $sign = new ReflectionMethod(Panel::class, 'sign');
    $until = time() + 300;
    foreach ([$until . '.' . $sign->invoke($panel, $until),
              $until . '.900001.' . $sign->invoke($panel, $until, 900001)] as $cookie) {
        $_COOKIE['panel'] = $cookie; verifyStateWeb($panel->authed(), 'plain legacy cookie still works');
        $_COOKIE['panel'] = $cookie . "\n"; verifyStateWeb(!$panel->authed(), 'legacy cookie rejects trailing LF');
    }
    unset($_COOKIE['panel']);
    $rewrite = new ReflectionMethod(Panel::class, 'panelizeUrl');
    $_SERVER['HTTP_HOST'] = 'localhost:8443'; $_SERVER['HTTPS'] = 'on';
    $url = $rewrite->invoke($panel, 'https://fixture.example.test/pacfixture?t=te&ty=xray');
    verifyStateWeb(str_starts_with($url, '/panelstatewebfixture/editor?') && !str_starts_with($url, '//'), 'editor retains current origin');
} finally {
    $remove($root);
}
foreach ($failures as $failure) echo 'FAIL: ', $failure, "\n";
echo 'state_web_failure_test: ', count($failures), " failure(s)\n";
exit($failures ? 1 : 0);
