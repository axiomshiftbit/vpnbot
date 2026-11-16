<?php
// C-02/C-04 (сверочный аудит): кнопка удаления пользователя OpenConnect
// адресовала его номером строки ocserv.passwd — после удаления другого
// пользователя старая кнопка удаляла и отключала соседа. Кроме того, отказ
// завершения активной сессии удалённого пользователя не замечался.
// Настоящие файлы и блокировки; occtl подменён.
require_once __DIR__ . '/../app/bot.php';
set_error_handler(static function ($level, $message, $file, $line) { if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line); return true; });

class OcStaleBot extends Bot
{
    public array $sent = [], $disconnected = [], $online = [];
    public bool $occtlFails = false;
    public function __construct(public string $root) {
        $this->pac = "$root/pac.json"; $this->language = 'ru';
        $this->input = ['chat' => 1, 'message_id' => 1, 'callback_id' => 'cb'];
        require __DIR__ . '/../app/i18n.php'; $this->i18n = $i;
    }
    protected function ocPasswordPath(): string { return "$this->root/ocserv.passwd"; }
    public function getClientsOc() {
        $users = array_filter(explode("\n", file_get_contents($this->ocPasswordPath())), fn ($e) => !empty($e));
        return array_values(array_map(fn($e) => explode(':', $e)[0], $users));
    }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) {
        $f = fopen("$this->root/.lock.$name", 'c'); flock($f, LOCK_EX);
        try { return $fn(); } finally { flock($f, LOCK_UN); fclose($f); }
    }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') {
        $this->sshFailed = false;
        if (preg_match("~occtl disconnect user '([^']+)'~", $cmd, $m)) {
            if ($this->occtlFails) { $this->sshFailed = true; return ''; }
            $this->disconnected[] = $m[1]; $this->online = array_values(array_diff($this->online, [$m[1]])); return '';
        }
        if (str_contains($cmd, 'occtl show users')) return $this->online ? "id user\n" . implode("\n", array_map(fn($u) => "1 $u", $this->online)) . "\n" : '';
        return '';
    }
    public function menu($type = false, $arg = false, $return = false) {}
    public function answer($callback_id, $textNotify = false, $notify = false) { if ($textNotify) $this->sent[] = $textNotify; }
    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false) { $this->sent[] = $text; return []; }
}

$root = sys_get_temp_dir() . '/vpnbot-oc-stale-' . bin2hex(random_bytes(6)); mkdir($root, 0700);
$failed = 0; $count = 0;
$check = static function (bool $ok, string $what) use (&$failed, &$count) { $count++; if (!$ok) { $failed++; echo "FAIL: $what\n"; } };
$seed = static function () use ($root): OcStaleBot {
    $hash = crypt('synthetic', '$6$' . bin2hex(random_bytes(8)) . '$');
    file_put_contents("$root/ocserv.passwd", "alice:*:$hash\nbob:*:$hash\ncarol:*:$hash\n");
    file_put_contents("$root/pac.json", json_encode(['ocserv_users' => ['alice' => 'a', 'bob' => 'b', 'carol' => 'c']]));
    return new OcStaleBot($root);
};
$token = static fn(OcStaleBot $b, string $name) => method_exists($b, 'ocClientToken') ? $b->ocClientToken($name) : 'deadbeef';
try {
    $b = $seed(); $b->online = ['bob', 'carol'];
    $tokenBob = $token($b, 'bob');                       // кнопка удаления bob: номер 1
    $b->deloc(0, $token($b, 'alice'));                   // администратор удаляет alice
    $check($b->getClientsOc() === ['bob', 'carol'], 'alice удалена');
    $b->deloc(1, $tokenBob);                             // старая кнопка bob (номер 1 теперь у carol)
    $check(in_array('carol', $b->getClientsOc(), true) && !in_array('carol', $b->disconnected, true), 'устаревшая кнопка не удаляет и не отключает carol');
    $b->deloc(0, $tokenBob);                             // свежая кнопка bob
    $check($b->getClientsOc() === ['carol'] && in_array('bob', $b->disconnected, true), 'свежая кнопка удаляет и отключает bob');

    // C-04: сессия удалённого пользователя не завершилась — администратор узнаёт об этом.
    $b = $seed(); $b->online = ['bob']; $b->occtlFails = true; $b->sent = [];
    $b->deloc(1, $token($b, 'bob'));
    $check(!in_array('bob', $b->getClientsOc(), true), 'bob удалён из ocserv.passwd');
    $check((bool) array_filter($b->sent, fn($t) => str_contains((string) $t, 'OpenConnect') && str_contains((string) $t, 'bob')), 'отказ отключения активной сессии сообщается');
    $source = file_get_contents(__DIR__ . '/../app/bot.php');
    $check(str_contains($source, '"/deloc {$i}_" . $this->ocClientToken($clients[$i])'), 'кнопка меню несёт метку пользователя');
} finally {
    exec('rm -rf ' . escapeshellarg($root));
}
echo "oc_stale_delete_test: " . ($count - $failed) . "/$count\n";
exit($failed ? 1 : 0);
