<?php
// Every button that addresses an Xray user by number must carry that user's
// identity token, or the dispatcher answers "The user list has changed. Open
// the user again." even when nothing changed. Reported: Xray → user → log →
// Back. Screens are rendered by the real code and go through the real
// update()/send(); only the Telegram transport is captured.
require_once __DIR__ . '/../app/bot.php';
set_error_handler(static function ($level, $message, $file, $line) {
    if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line);
    return false;
});
$checks = 0; $failed = [];
function xbCheck(bool $ok, string $label): void { global $checks, $failed; $checks++; if (!$ok) { $failed[] = $label; echo "FAIL $label\n"; } }

class XrayBackBot extends Bot
{
    public array $calls = [], $answers = [], $markups = [];
    public array $xc = [
        ['email' => 'alice', 'id' => '11111111-1111-4111-8111-111111111111'],
        ['email' => 'bob', 'id' => '22222222-2222-4222-8222-222222222222'],
    ];
    public function __construct(string $root)
    {
        $this->hwid = "$root/hwid.json"; $this->pac = "$root/pac.json";
        $this->input = ['chat' => 1, 'from' => 1, 'message_id' => 2, 'callback_id' => 'cb', 'callback' => '', 'message' => ''];
        $this->language = 'ru'; $this->admin = true;
        require __DIR__ . '/../app/i18n.php'; $this->i18n = $i;
    }
    public function getXray() { return ['inbounds' => [['settings' => ['clients' => $this->xc]]]]; }
    public function getPacConf() { return []; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
    public function trackOnline(): array { return []; }
    public function onlineClients(int $window = 60): array { return []; }
    public array $log = [];
    public function getConnLog(): array { return $this->log; }
    public function setConnLog(array $log) { $this->log = $log; return true; }
    public function getGeoCache(): array { return []; }
    public function setGeoCache(array $cache) {}
    public function getHwidStorage() { return []; }
    public function request($method, $data, $json_header = 0)
    {
        if (isset($data['reply_markup'])) $this->markups[] = json_decode($data['reply_markup'], true)['inline_keyboard'] ?? [];
        return ['ok' => true, 'result' => ['message_id' => 2]];
    }
    public function answer($callback_id, $textNotify = false, $notify = false) { $this->answers[] = $textNotify; }
    protected function rememberChatMenu($chat, int $id): void {}  // PHP session: not available in CLI
    protected function sessionApply(callable $fn) { $_SESSION ??= []; return $fn(); }
    // Navigation targets: record the dispatch, render nothing.
    // Real userXr(); its locked part keeps the real identity check, then records instead of rendering.
    protected function userXrLocked($i)
    {
        $bot = $this;
        if (!Closure::bind(fn() => $this->xrayClientMatches((int) $i), $bot, Bot::class)())
            return Closure::bind(fn() => $this->staleXrayAction(), $bot, Bot::class)();
        $this->calls[] = "userXr:$i";
    }
    public function xray($page = 0) { $this->calls[] = 'xray'; }
    public function press(string $callback): void { $this->calls = []; $this->answers = []; $this->input['callback'] = $callback; $this->action(); }
    public function back(): string
    {
        foreach (array_reverse(end($this->markups) ?: []) as $row) foreach ($row as $button)
            if (str_starts_with($button['callback_data'] ?? '', '/userXr ')) return $button['callback_data'];
        return '';
    }
}

$root = sys_get_temp_dir() . '/vpnbot-xray-back-' . bin2hex(random_bytes(4));
mkdir($root, 0700);
try {
    $stale = (new XrayBackBot($root))->i18n('confirm stale');
    $screens = [
        'connection log (no records)' => fn(XrayBackBot $b) => $b->clientLogView(1),
        'connection log (no email)' => function (XrayBackBot $b) { unset($b->xc[1]['email']); $b->clientLogView(1); },
        'help for a user' => fn(XrayBackBot $b) => $b->menuHelp('xray_user', 0, '1'),
    ];
    foreach ($screens as $name => $render) {
        $b = new XrayBackBot($root);
        try { $render($b); } catch (Throwable $e) { xbCheck(false, "$name: render " . get_class($e) . ' ' . $e->getMessage()); continue; }
        $back = $b->back();
        xbCheck($back !== '', "$name: Back to the user is rendered");
        if ($back === '') continue;
        $b->press($back);
        xbCheck(!in_array($stale, $b->answers, true), "$name: Back does not report a changed user list");
        xbCheck($b->calls === ['userXr:1'], "$name: Back opens the same user (" . implode(',', $b->calls) . ')');
    }

    // Any keyboard sent through update()/send() is covered, including screens
    // added later: the token is the one of the user at that index right now.
    $b = new XrayBackBot($root);
    $b->update(1, 2, 'x', [[['text' => 'back', 'callback_data' => '/userXr 1']]]);
    $back = $b->back();
    xbCheck((bool) preg_match('~^/userXr 1 ![A-Za-z0-9_-]{22}$~D', $back), 'update() adds the identity token');
    $b->send(1, 'x', 0, [[['text' => 'back', 'callback_data' => '/userXr 0']]]);
    xbCheck((bool) preg_match('~^/userXr 0 ![A-Za-z0-9_-]{22}$~D', $b->back()), 'send() adds the identity token');
    // Already tokened buttons are left alone (no double token).
    $b->update(1, 2, 'x', [[['text' => 'back', 'callback_data' => $back]]]);
    xbCheck($b->back() === $back, 'a tokened button keeps exactly one token');
    // The token still protects against renumbering: after bob moves, the old
    // Back no longer opens whoever now sits at index 1.
    $b->press($back);
    xbCheck($b->calls === ['userXr:1'], 'tokened Back opens the user');
    array_splice($b->xc, 0, 1, [['email' => 'carol', 'id' => '33333333-3333-4333-8333-333333333333'], $b->xc[0]]);
    $b->press($back);
    xbCheck(in_array($stale, $b->answers, true) && !in_array('userXr:1', $b->calls, true), 'renumbered user: old Back is refused');
    // Non-Xray buttons and the 64-byte Telegram limit.
    $b->update(1, 2, 'x', [[['text' => 'm', 'callback_data' => '/menu']], [['text' => 'l', 'callback_data' => '/clientLog 1 t0 0']]]);
    xbCheck(array_column(array_merge(...end($b->markups)), 'callback_data') === ['/menu', '/clientLog 1 t0 0'], 'other buttons are unchanged');
    foreach ($b->markups as $markup) foreach ($markup as $row) foreach ($row as $button)
        xbCheck(strlen($button['callback_data'] ?? '') <= 64, 'callback_data fits 64 bytes');
    // "Clear log" addressed the user by row number only: after the list was
    // renumbered it erased another user's connection log without asking.
    $b = new XrayBackBot($root);
    $b->log = ['bob' => ['ips' => ['198.51.100.7' => ['first' => time() - 60, 'last' => time(), 'count' => 1]]]];
    $b->clientLogView(1);
    $clear = '';
    foreach (end($b->markups) as $row) foreach ($row as $button) if (str_starts_with($button['callback_data'] ?? '', '/clientLogClear')) $clear = $button['callback_data'];
    xbCheck($clear !== '', 'log screen offers Clear log');
    $b->log['dave'] = ['ips' => ['203.0.113.9' => ['first' => time() - 60, 'last' => time(), 'count' => 1]]];
    array_splice($b->xc, 1, 0, [['email' => 'dave', 'id' => '44444444-4444-4444-8444-444444444444']]);  // dave now at index 1, bob at 2
    $b->markups = [];
    $b->press($clear);
    xbCheck(isset($b->log['dave']), 'renumbered list: Clear log does not erase another user\'s log');
    xbCheck(isset($b->log['bob']), 'renumbered list: the stale button changes nothing');
    $b = new XrayBackBot($root);
    $b->log = ['bob' => ['ips' => ['198.51.100.7' => ['first' => time() - 60, 'last' => time(), 'count' => 1]]]];
    $b->clientLogView(1);
    foreach (end($b->markups) as $row) foreach ($row as $button) if (str_starts_with($button['callback_data'] ?? '', '/clientLogClear')) $clear = $button['callback_data'];
    $b->press($clear);
    xbCheck(!isset($b->log['bob']), 'unchanged list: Clear log clears the user\'s log');
} finally {
    exec('rm -rf ' . escapeshellarg($root));
}
echo "xray_back_identity_test: " . ($checks - count($failed)) . "/$checks\n";
exit($failed ? 1 : 0);
