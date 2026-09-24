<?php
require_once __DIR__ . '/../app/bot.php';

class IpsecSessionsBot extends Bot {
    public array $commands = [];
    public string $sas = '';
    public string $sessions = '';
    public function __construct() {}
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') {
        $this->commands[] = $cmd;
        if (str_contains($cmd, '--list-sas')) return $this->sas;
        if (str_starts_with($cmd, 'for f in ')) return $this->sessions;
        return '';
    }
}
$failures = [];
$check = static function ($ok, $name) use (&$failures) { if (!$ok) $failures[] = $name; };
$b = new IpsecSessionsBot();
$sa = static fn($id, $state, $version, $name, $bytes) => "ikev2: #$id, $state, $version, abc_i def_r\n"
    . "  remote 'device-$id' @ 192.0.2.$id\x5b4500] EAP: '$name' [10.9.2.$id]\n"
    . "  established 12s ago\n    in  abc, $bytes bytes, 1 packets\n    out def, $bytes bytes, 1 packets\n";
$b->sas = $sa(1, 'ESTABLISHED', 'IKEv2', 'alice', 1024)
    . $sa(2, 'ESTABLISHED', 'IKEv2', 'alice', 2048)
    . $sa(3, 'ESTABLISHED', 'IKEv1', 'alice', 8192)
    . $sa(4, 'CONNECTING', 'IKEv2', 'alice', 16384)
    . $sa(5, 'ESTABLISHED', 'IKEv2', 'bob', 4096);
$state = $b->getIkev2Status();
$check(($state['alice']['uids'] ?? []) === [1, 2], 'Все IKEv2 SA пользователя сохранены; IKEv1/CONNECTING исключены');
$check(($state['alice']['rx'] ?? 0) === 3072 && ($state['alice']['tx'] ?? 0) === 3072, 'Трафик всех установленных IKEv2 SA суммируется');
$b->kickIkev2Session('alice');
$kicks = array_values(array_filter($b->commands, fn($cmd) => str_contains($cmd, '--terminate')));
$check(count($kicks) === 2 && str_contains($kicks[0], '--ike-id 1 ') && str_contains($kicks[1], '--ike-id 2 '), 'Отзыв закрывает оба SA и не затрагивает другого пользователя');
$b->sessions = "alice.111 10.9.1.2 111 alice\nalice.222 10.9.1.3 222 alice\nbob 10.9.1.4 333\n";
$state = $b->getL2tpOnline();
$check(($state['alice']['pids'] ?? []) === [111, 222], 'Две PPP-сессии одного логина сохранены');
$check(($state['bob']['pids'] ?? []) === [333], 'Старый формат session-файла читается');
$b->commands = [];
$b->kickL2tpSession('alice');
$kills = array_values(array_filter($b->commands, fn($cmd) => str_contains($cmd, 'kill ')));
$check(count($kills) === 2 && str_contains($kills[0], '111') && str_contains($kills[1], '222'), 'L2TP отзывает все PPP-сессии');
$check(count($kills) === 2 && str_contains($kills[0], '/comm') && str_contains($kills[0], 'pppd'), 'Перед kill проверяется процесс pppd');
$tmp = sys_get_temp_dir() . '/vpnbot-ppp-' . bin2hex(random_bytes(6));
mkdir($tmp . '/sessions', 0700, true);
foreach ([111 => 'pppd', 222 => 'sleep'] as $pid => $comm) {
    mkdir("$tmp/proc/$pid", 0700, true);
    file_put_contents("$tmp/proc/$pid/comm", "$comm\n");
}
file_put_contents("$tmp/sessions/alice.111", "10.9.1.2 111 alice\n");
file_put_contents("$tmp/sessions/alice.222", "10.9.1.3 222 alice\n");
file_put_contents("$tmp/sessions/alice.333", "10.9.1.4 333 alice\n");
$real = new class($tmp) extends Bot {
    public function __construct(public string $root) {}
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') {
        return shell_exec(str_replace(['/var/run/l2tp-sessions', '/proc/'], [$this->root . '/sessions', $this->root . '/proc/'], $cmd));
    }
};
$check(($real->getL2tpOnline()['alice']['pids'] ?? []) === [111], 'Умершие PPP и повторно использованные PID не считаются активными');
foreach (glob("$tmp/sessions/*") as $file) unlink($file);
foreach (glob("$tmp/proc/*") as $dir) { unlink("$dir/comm"); rmdir($dir); }
rmdir("$tmp/sessions"); rmdir("$tmp/proc"); rmdir($tmp);
foreach ($failures as $failure) echo "FAIL: $failure\n";
if ($failures) exit(1);
echo "ipsec_sessions_test OK\n";
