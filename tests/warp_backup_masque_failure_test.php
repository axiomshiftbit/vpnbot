<?php
// AUX-03: возврат или удаление копии WARP после оборванной смены ключа.
// Отказ вложенного warp_masque.sh (rollback/commit) — это отказ всей операции:
// копия остаётся, пользователь видит ошибку. Команды выполняет настоящий sh.
require_once __DIR__ . '/../app/bot.php';

class WarpBackupMasqueBot extends Bot
{
    public array $sent = [];
    public function __construct(public string $root) {
        $this->pac = "$root/pac.json";
        $this->input = ['chat' => 1, 'message_id' => 1];
        $this->language = 'ru';
        require __DIR__ . '/../app/i18n.php';
        $this->i18n = $i;
    }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') {
        $this->sshFailed = false;
        $cmd = str_replace(['/etc/warp', '/warp_masque.sh'], ["$this->root/warp", "$this->root/warp_masque.sh"], $cmd);
        $env = getenv(); $env['PATH'] = "$this->root/bin:" . $env['PATH'];
        $p = proc_open(['sh', '-c', $cmd], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'a']], $pipes, null, $env);
        fclose($pipes[0]); $out = stream_get_contents($pipes[1]); fclose($pipes[1]); proc_close($p);
        return $out;
    }
    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false) { $this->sent[] = $text; return []; }
    public function warp() {}
}

$root = sys_get_temp_dir() . '/vpnbot-warp-masque-backup-' . bin2hex(random_bytes(6));
mkdir("$root/bin", 0700, true);
file_put_contents("$root/bin/pkill", "#!/bin/sh\nexit 0\n"); chmod("$root/bin/pkill", 0755);
$failed = 0; $count = 0;
$check = static function (bool $ok, string $what) use (&$failed, &$count) { $count++; if (!$ok) { $failed++; echo "FAIL: $what\n"; } };
$stale = static function (string $failing) use ($root): WarpBackupMasqueBot {
    exec('rm -rf ' . escapeshellarg("$root/warp"));
    mkdir("$root/warp/.bak", 0700, true);
    file_put_contents("$root/warp/wgcf-account.toml", 'NEW ACCOUNT');
    file_put_contents("$root/warp/.bak/wgcf-account.toml", 'PAID ACCOUNT');
    // Вложенный сценарий MASQUE: указанное действие завершается отказом.
    file_put_contents("$root/warp_masque.sh", "case \"\$1\" in $failing) exit 1;; esac\nexit 0\n");
    file_put_contents("$root/pac.json", json_encode(['warpoff' => 1, 'warp_mode' => 'masque']));
    return new WarpBackupMasqueBot($root);
};
// Каталог удаляет внешняя команда (sh): кеш stat PHP иначе отвечает по старому состоянию.
$gone = static function (string $path): bool { clearstatcache(true, $path); return !is_dir($path); };
try {
    $b = $stale('rollback'); $b->warpBackup('restore');
    $check(!$gone("$root/warp/.bak") && file_get_contents("$root/warp/.bak/wgcf-account.toml") === 'PAID ACCOUNT',
        'Отказ rollback MASQUE: копия прежнего аккаунта не удаляется');
    $check(count($b->sent) === 1 && $b->sent[0] === $b->i18n('warp backup failed'), 'Отказ rollback MASQUE: пользователь видит ошибку');

    $b = $stale('commit'); $b->warpBackup('drop');
    $check(!$gone("$root/warp/.bak"), 'Отказ commit MASQUE: копия не удаляется');
    $check(count($b->sent) === 1 && $b->sent[0] === $b->i18n('warp backup failed'), 'Отказ commit MASQUE: пользователь видит ошибку');

    // Успешные rollback/commit по-прежнему завершают операцию.
    $b = $stale('none'); $b->warpBackup('restore');
    $check($gone("$root/warp/.bak") && file_get_contents("$root/warp/wgcf-account.toml") === 'PAID ACCOUNT'
        && $b->sent[0] === $b->i18n('warp backup restored'), 'Успешный rollback: аккаунт возвращён, копия удалена');
    $b = $stale('none'); $b->warpBackup('drop');
    $check($gone("$root/warp/.bak") && $b->sent[0] === $b->i18n('warp backup dropped'), 'Успешный commit: копия удалена');
    // Без сценария MASQUE (режим WireGuard-образа) поведение прежнее.
    $b = $stale('none'); unlink("$root/warp_masque.sh"); $b->warpBackup('drop');
    $check($gone("$root/warp/.bak") && $b->sent[0] === $b->i18n('warp backup dropped'), 'Без warp_masque.sh удаление копии работает');
} finally {
    exec('rm -rf ' . escapeshellarg($root));
}
echo "warp_backup_masque_failure_test: " . ($count - $failed) . "/$count\n";
exit($failed ? 1 : 0);
