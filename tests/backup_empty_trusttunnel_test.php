<?php
require_once __DIR__ . '/../app/bot.php';

class EmptyTrustTunnelBackupBot extends Bot
{
    public bool $failWrite = false;
    public int $restarts = 0;
    public function __construct(public string $root) {
        $this->pac = "$root/pac.json";
        $this->update = "$root/backup.json";
        $this->input = ['chat' => 1, 'message_id' => 1, 'callback_id' => 'test'];
    }
    public function ttPaths() { return ['dir' => $this->root, 'cred' => "$this->root/credentials.toml"]; }
    public function getPacConf() { return ['language' => 'ru', 'limitpage' => 5]; }
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML') {}
    public function cloakNginx() {}
    public function ssh($cmd,$service='wg',$wait=true,$log='/dev/null') { return str_contains($cmd,'VPNBOT_SERVICE_READY') ? 'VPNBOT_SERVICE_READY' : ''; }
    public function restartTt() { $this->restarts++; return true; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
    public function writePrivateKey(string $path, string $data): bool { return !$this->failWrite && parent::writePrivateKey($path, $data); }
}
$root = sys_get_temp_dir() . '/vpnbot-backup-tt-' . bin2hex(random_bytes(6));
mkdir($root, 0700);
try {
    $b = new EmptyTrustTunnelBackupBot($root);
    $b->writeTtCredentials(['later-user' => 'synthetic-password']);
    file_put_contents($b->update, json_encode(['tt' => '']));
    if (!$b->importFile($b->update) || $b->getClientsTt() || $b->restarts !== 1) {
        throw new RuntimeException('Восстановление пустого списка TrustTunnel должно отзывать более новые доступы');
    }
    $b->writeTtCredentials(['preserved' => 'synthetic-password']);
    $before = file_get_contents($b->ttPaths()['cred']);
    $b->failWrite = true;
    if ($b->importFile($b->update) !== false || $b->restarts !== 1 || file_get_contents($b->ttPaths()['cred']) !== $before) {
        throw new RuntimeException('Ошибка записи бэкапа должна сохранять реквизиты и сообщать отказ без рестарта');
    }
    file_put_contents($b->update, json_encode(['tt' => ['invalid']]));
    if ($b->importFile($b->update) !== false) throw new RuntimeException('Неверный тип TrustTunnel должен отвергаться до записи');
    echo "backup_empty_trusttunnel_test OK\n";
} finally {
    foreach (glob("$root/*") as $file) unlink($file);
    @unlink("$root/.backup.lock");
    rmdir($root);
}
