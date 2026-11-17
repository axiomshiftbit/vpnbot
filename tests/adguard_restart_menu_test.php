<?php
// AdGuard actions first replace the menu with a buttonless "Restart Adguard
// Home" screen, stop AdGuard, write the YAML and start it again. When a step
// after that screen failed, the exception left the administrator on the
// buttonless screen (only a "Not done" alert); the AdGuard menu never came back.
require_once __DIR__ . '/../app/bot.php';
require __DIR__ . '/../app/i18n.php';
set_error_handler(static function ($level, $message, $file, $line) { if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line); return false; });

class AdgRestartBot extends Bot
{
    public array $events = []; public bool $startFails = true;
    public function __construct(array $strings) { $this->i18n = $strings; $this->language = 'en'; $this->input = ['chat' => 1, 'from' => 1, 'message_id' => 2, 'callback_id' => 'cb']; }
    public function adguardConf(): ?array { return ['users' => [['name' => 'admin', 'password' => 'x']], 'dns' => ['upstream_dns' => ['https://dns.example/dns-query', 'tls://dns2.example'], 'allowed_clients' => []]]; }
    public function adguardWrite(array $c): bool { $this->events[] = 'write'; return true; }
    public function stopAd() { $this->events[] = 'stop'; return ''; }
    public function startAd() { $this->events[] = 'start'; if ($this->startFails) throw new RuntimeException('Could not stop or start AdGuard'); return ''; }
    public function menu($type = false, $arg = false, $return = false) { $this->events[] = 'menu:' . $type; }
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML') { $this->events[] = 'screen'; }
    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false) { $this->events[] = 'send'; return []; }
    public function pacConfUpdate(callable $fn) { return true; }
    public function getPacConf() { return []; }
    public function dohLegacyAllowed(): bool { return false; }
    public function adguardSync() {}
    public function adguardXrayClients() {}
}
$failed = 0; $count = 0;
$check = static function (bool $ok, string $what) use (&$failed, &$count) { $count++; if (!$ok) { $failed++; echo "FAIL: $what\n"; } };
$actions = [
    'add upstream' => fn(AdgRestartBot $b) => $b->upstream('tls://dns3.example'),
    'delete upstream' => fn(AdgRestartBot $b) => $b->delupstream(0),
    'fill allowed clients' => fn(AdgRestartBot $b) => $b->adgFillAllowedClients(),
    'clear allowed clients' => fn(AdgRestartBot $b) => $b->adgFillAllowedClients(true),
    'change password' => fn(AdgRestartBot $b) => $b->chpsswd('new-password-123'),
];
foreach ($actions as $name => $run) {
    foreach ([true, false] as $fails) {
        $b = new AdgRestartBot($i); $b->startFails = $fails;
        $error = null;
        try { $run($b); } catch (Throwable $e) { $error = $e; }
        $label = $name . ($fails ? ' (AdGuard start fails)' : '');
        $check(end($b->events) === 'menu:adguard', "$label: the AdGuard menu is shown at the end (" . implode(',', array_slice($b->events, -3)) . ')');
        if ($fails) $check($error instanceof RuntimeException, "$label: the failure still reaches the administrator");
        else $check($error === null, "$label: success without error");
    }
}
echo "adguard_restart_menu_test: " . ($count - $failed) . "/$count\n";
exit($failed ? 1 : 0);
