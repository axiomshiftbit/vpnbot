<?php
// Actual PHP + Python hook share one synthetic file and stable flock inode.
require_once __DIR__ . '/../app/bot.php';
class AccountingBot extends Bot
{
    public function __construct(public string $root) {}
    public function ovpnPaths() { return ['srv' => "$this->root/server.conf", 'status' => "$this->root/status", 'pki' => "$this->root/pki"]; }
    public function getOvpnUsers() { return ['alice']; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) {
        $lock = fopen("$this->root/lock", 'c'); flock($lock, LOCK_EX);
        try { return $fn(); } finally { flock($lock, LOCK_UN); fclose($lock); }
    }
    public function ovpnClientMenu($user) {}
    public function menu($type = false, $arg = false, $return = false) {}
    public function status(int $rx, int $tx, int $epoch = 100): void {
        file_put_contents("$this->root/status", "CLIENT_LIST,alice,203.0.113.1:1000,10.8.0.2,,$rx,$tx,human,$epoch,UNDEF,1,0,AES-256-GCM\n");
    }
    public function hook(array $changes = []): int {
        $env = $changes + ['script_type' => 'client-connect', 'common_name' => 'alice', 'trusted_ip' => '203.0.113.1',
            'trusted_port' => '1000', 'time_unix' => '100', 'daemon_start_time' => '90', 'daemon_pid' => '42'];
        $program = 'import sys,json;from pathlib import Path;sys.path.insert(0,sys.argv[1]);import ovpn_traffic;'
            . 'ovpn_traffic.event(Path(sys.argv[2])/"traffic.json",Path(sys.argv[2])/"lock",json.load(sys.stdin),now=105)';
        $p = proc_open(['python3', '-B', '-c', $program, __DIR__ . '/../scripts', $this->root],
            [0 => ['pipe', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
        if (!is_resource($p)) throw new RuntimeException('hook test process unavailable');
        fwrite($pipes[0], json_encode($env)); fclose($pipes[0]); return proc_close($p);
    }
}
function checkAccounting(bool $ok, string $message): void { if (!$ok) throw new RuntimeException($message); }
$root = sys_get_temp_dir() . '/ovpn-accounting-' . bin2hex(random_bytes(8)); mkdir($root, 0700);
try {
    $bot = new AccountingBot($root);
    checkAccounting($bot->hook() === 0, 'connect is durable');
    $bot->status(900, 50); $bot->ovpnTrafficSync();
    checkAccounting($bot->ovpnTraffic('alice')['rx'] === 900, 'first live sample survives PHP process boundary');
    checkAccounting($bot->hook(['script_type' => 'client-disconnect', 'bytes_received' => '1500', 'bytes_sent' => '80']) === 0, 'final hook');
    $bot->ovpnTrafficSync(); // The CSV still contains the old live row.
    checkAccounting($bot->ovpnTraffic('alice')['rx'] === 1500, 'stale status cannot count a closed session twice');
    checkAccounting($bot->hook(['time_unix' => '101']) === 0, 'reconnect');
    $bot->status(1000, 200, 101); $bot->ovpnTrafficSync(); $bot->resetOvpnTraffic('alice');
    checkAccounting($bot->ovpnTraffic('alice')['rx'] === 0, 'reset excludes live baseline');
    checkAccounting($bot->hook(['time_unix' => '101', 'script_type' => 'client-disconnect', 'bytes_received' => '1700', 'bytes_sent' => '250']) === 0, 'final after reset');
    $bot->ovpnTrafficSync();
    checkAccounting([$bot->ovpnTraffic('alice')['rx'], $bot->ovpnTraffic('alice')['tx']] === [700, 50], 'reset then final includes only new bytes');
    // The complete next session starts and stops without any PHP status poll.
    checkAccounting($bot->hook(['time_unix' => '102']) === 0, 'short connect');
    checkAccounting($bot->hook(['time_unix' => '102', 'script_type' => 'client-disconnect', 'bytes_received' => '99', 'bytes_sent' => '1']) === 0, 'short disconnect');
    checkAccounting($bot->ovpnTraffic('alice')['rx'] === 799, 'short sessions are accounted without cron');
    file_put_contents($bot->ovpnTrafficPath(), '{broken');
    try { $bot->ovpnTrafficSync(); throw new LogicException('corrupt counters must be rejected'); }
    catch (RuntimeException $expected) {}
    checkAccounting(file_get_contents($bot->ovpnTrafficPath()) === '{broken', 'read failure never resets totals');
    foreach (['traffic.json.tmp.' . str_repeat('a', 16), '.traffic-synthetic123'] as $name) file_put_contents("$root/$name", 'synthetic incomplete checkpoint');
    $snapshot = $bot->exportOvpnPki(true);
    checkAccounting(array_intersect(array_keys($snapshot), ['traffic.json', '.traffic-synthetic123', 'traffic.json.tmp.' . str_repeat('a', 16)]) === [], 'runtime and temporary checkpoints never enter PKI backup');
    checkAccounting(!Bot::isOvpnRuntimePath('pki/issued/.traffic-alice.crt'), 'nested certificate names are not runtime files');
    echo "ovpn accounting: PASS\n";
} finally {
    foreach (array_diff(scandir($root), ['.', '..']) as $file) unlink("$root/$file");
    rmdir($root);
}
