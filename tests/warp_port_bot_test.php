<?php
// Main bot WARP: official port choice with restore on failure, and a new account through the key path.
require_once __DIR__ . '/../app/bot.php';
set_error_handler(static function ($level, $message, $file, $line) { if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line); return true; });

class WarpPortBot extends Bot
{
    public array $state = []; public array $commands = []; public array $sent = []; public array $screens = []; public array $keys = [];
    public bool $up = true; public bool $await = true; public bool $check = true;
    public function __construct()
    {
        $this->input = ['chat' => 1, 'from' => 1, 'message_id' => 1, 'callback_id' => 'cb', 'username' => 'admin'];
        $this->language = 'ru';
        require __DIR__ . '/../app/i18n.php';
        $this->i18n = $i;
    }
    public function getPacConf() { return $this->state; }
    public function setPacConf($conf) { $this->state = $conf; return true; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
    public function warpAwait(string $mode, bool $h2, int $attempts = 30): bool { $this->commands[] = "await $mode"; return $this->await; }
    // warpCommand() is private in Bot: answer at the transport it uses.
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
    {
        $this->commands[] = $cmd;
        $this->sshFailed = false;
        // The restart on a new port (stop; up) follows $up; restoring the previous port (up alone) works.
        $ok = match (true) {
            str_contains($cmd, 'warp_masque.sh check') => $this->check,
            str_contains($cmd, 'pkill') && str_contains($cmd, 'warp_fixup.sh up') => $this->up,
            default => true,
        };
        return $ok ? 'VPNBOT_WARP_OK' : '';
    }
    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false, $entities = false, $forum = false) { $this->sent[] = $text; return []; }
    public function sendDraft($chat, $draft_id, $text = '', $mode = 'HTML') {}
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML') { $this->screens[] = [$text, $button ?: []]; return []; }
    public function warp() { $this->screens[] = ['warp', []]; }
    public function addWarpPlus($key) { $this->keys[] = $key; }
}
$check = static function (bool $ok, string $name) { if (!$ok) throw new RuntimeException('FAIL ' . $name); };
$cb = static fn(WarpPortBot $b) => array_column(array_merge(...end($b->screens)[1]), 'callback_data');

// WireGuard: auto and the official UDP ports.
$bot = new WarpPortBot();
$bot->warpPorts();
$check($cb($bot) === ['/warpPort auto', '/warpPort 2408', '/warpPort 500', '/warpPort 1701', '/warpPort 4500', '/warp'], 'WireGuard port choices');
$bot->warpPort('4500');
$check(($bot->state['warp_port'] ?? null) === 4500 && str_contains(end($bot->sent), '4500'), 'port saved and applied');
$check((bool) preg_grep('~warp_fixup\.sh up~', $bot->commands), 'link brought up on the new port');
$bot->up = false;
$bot->warpPort('500');
$check(($bot->state['warp_port'] ?? null) === 4500 && str_contains(end($bot->sent), '❌'), 'failed port restores the previous one');
$bot->up = true;
$bot->warpPort('auto');
$check(!isset($bot->state['warp_port']), 'auto removes the choice');
$bot->warpPort('8443');
$check(!isset($bot->state['warp_port']), 'a MASQUE port is refused for WireGuard');

// MASQUE: the endpoint answers on the port before it is saved; HTTP/2 has no choice.
$bot = new WarpPortBot();
$bot->state = ['warp_mode' => 'masque'];
$bot->check = false;
$bot->warpPort('8443');
$check(!isset($bot->state['warp_masque_port']) && (bool) preg_grep('~check h3 8443~', $bot->commands), 'unanswered MASQUE port not saved');
$bot->check = true;
$bot->warpPort('8443');
$check(($bot->state['warp_masque_port'] ?? null) === 8443 && (bool) preg_grep('~rm -f /run/warp-mode~', $bot->commands), 'MASQUE port saved, proxy rebuilt');
$bot->await = false;
$bot->warpPort('4443');
$check(($bot->state['warp_masque_port'] ?? null) === 8443, 'MASQUE port restored when the proxy does not come up');
$bot->state['warp_masque_h2'] = 1;
$bot->warpPorts();
$check($cb($bot) === ['/warp'], 'HTTP/2 offers no port');
$check($bot->warpSelectedPort() === null, 'HTTP/2 always uses 443');

// A new account goes through the key path, keeping the saved WARP+ key.
$bot = new WarpPortBot();
$bot->state = ['warp' => 'AAAA-BBBB-CCCC'];
$bot->warpReregister(false);
$check($bot->keys === [] && in_array('/warpRegYes', $cb($bot), true), 'new account asks first');
$bot->warpReregister(true);
$check($bot->keys === ['AAAA-BBBB-CCCC'], 'new account keeps the saved key');
echo "PASS main bot WARP ports and new account\n";
