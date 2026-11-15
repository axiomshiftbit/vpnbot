<?php
require __DIR__ . '/../app/bot.php';

class RollbackWireGuardBot extends Bot {
    public array $starts = [];
    public array $outcomes = [false, true];
    public bool $failClients = false;
    public function __construct(public string $root, int $instance) {
        $this->pac = "$root/pac.json"; $this->clients = "$root/clients.json"; $this->clients1 = "$root/clients1.json";
        $this->protocolModulesFile = "$root/modules.json";
        $this->wg = $instance; $this->ip = '192.0.2.1'; $this->language = 'ru';
    }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) {
        $lock = fopen("$this->root/.lock.$name", 'c');
        try { if (!flock($lock, LOCK_EX)) return $busy; return $fn(); }
        finally { flock($lock, LOCK_UN); fclose($lock); }
    }
    public function getPorts() { return ['wg' => ['port' => 51820], 'wg1' => ['port' => 51821]]; }
    public function restartWG($body, $switch = false) {
        $this->starts[] = ['body' => $body, 'type' => $this->getWGType(), 'switch' => (bool) $switch];
        return array_shift($this->outcomes) ?? false;
    }
    public function iptablesWG() { $this->sshFailed = false; }
    public function saveClients(array $clients) {
        $result = parent::saveClients($clients);
        return $this->failClients ? false : $result;
    }
}
function wgRollbackCheck(bool $ok, string $name): void { if (!$ok) throw new RuntimeException($name); }
$method = new ReflectionMethod(Bot::class, 'restoreBackupWireGuard');
foreach ([0, 1] as $instance) foreach ([false, true] as $oldMode) foreach (['apply', 'clients', 'rollback'] as $failure) {
    $root = sys_get_temp_dir() . '/vpnbot-wg-rollback-' . bin2hex(random_bytes(6)); mkdir($root, 0700);
    try {
        $bot = new RollbackWireGuardBot($root, $instance);
        $mode = $instance ? 'wg1_amnezia' : 'amnezia';
        $bot->setPacConf(['domain' => 'example.test', $mode => (int) !$oldMode, 'unrelated' => 'preserve']);
        $server = "$root/wg$instance.conf"; $clients = $instance ? $bot->clients1 : $bot->clients;
        file_put_contents($server, 'previous-working-config'); file_put_contents($clients, '[{"previous":true}]');
        $inode = fileinode($server);
        $bot->failClients = $failure === 'clients';
        if ($failure === 'clients') $bot->outcomes = [true];
        if ($failure === 'rollback') $bot->outcomes = [false, false];
        $partial = false;
        try { $result = $method->invoke($bot, ['server' => ['interface' => ['Address' => '10.0.0.1/24', 'ListenPort' => 51820]], 'clients' => []], 1); }
        catch (RuntimeException $error) { $partial = $error->getCode() === Bot::BACKUP_PARTIAL; $result = false; }
        wgRollbackCheck($result === false && $partial === ($failure === 'rollback'), 'restore/rollback outcome');
        wgRollbackCheck(file_get_contents($server) === 'previous-working-config' && fileinode($server) === $inode, 'server contents and bind inode');
        wgRollbackCheck(file_get_contents($clients) === '[{"previous":true}]', 'exact clients rollback');
        wgRollbackCheck(!empty($bot->getPacConf()[$mode]) === $oldMode && $bot->getPacConf()['unrelated'] === 'preserve', 'mode and unrelated settings');
        $last = end($bot->starts);
        wgRollbackCheck($last['body'] === 'previous-working-config' && $last['type'] === ($oldMode ? 'awg' : 'wg'), 'old interface restarted in its previous mode');
    } finally {
        foreach (scandir($root) as $name) if ($name !== '.' && $name !== '..') unlink("$root/$name");
        rmdir($root);
    }
}
echo "backup_wireguard_rollback_test: 12 scenarios OK\n";
