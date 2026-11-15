<?php
// Durable revoke intent and serialized read/modify/write; SSH is a stateful mock.
require_once __DIR__ . '/../app/bot.php';
class IpsecUsersBot extends Bot {
    public string $failure = '';
    public array $sas = [1 => 'alice', 2 => 'alice', 3 => 'bob'];
    public array $commands = [];
    public function __construct(public string $root) {}
    public function ipsecPaths() { return ['conf' => $this->root, 'chap' => "$this->root/chap-secrets",
        'users' => "$this->root/users_ikev2.json", 'secrets' => "$this->root/secrets.conf"]; }
    public function getIpsecPsk() { return 'synthetic-psk'; }
    public function protocolModuleEnabled(string $key, ?array $pac = null): bool { return true; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) {
        $lock = fopen("$this->root/lock", 'c'); flock($lock, LOCK_EX);
        try { return $fn(); } finally { flock($lock, LOCK_UN); fclose($lock); }
    }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') {
        $this->commands[] = $cmd; $this->sshFailed = $this->failure === 'transport';
        if ($this->sshFailed) return '';
        if (str_contains($cmd, '--load-creds')) return $this->failure === 'reload' ? '' : 'VPNBOT_IKEV2_CREDS_OK';
        if (str_contains($cmd, '--list-sas')) {
            if ($this->failure === 'status') return '';
            $out = '';
            foreach ($this->sas as $id => $name) {
                $state = $id === 2 ? 'CONNECTING' : 'ESTABLISHED';
                $out .= "ikev2: #$id, $state, IKEv2, synthetic\n  remote '$name' @ 203.0.113.1[4500] [10.9.2.$id]\n";
            }
            return $out . (str_contains($cmd, 'VPNBOT_IKEV2_STATUS_OK') ? "\nVPNBOT_IKEV2_STATUS_OK" : '');
        }
        if (preg_match('~--terminate --ike-id (\d+)~', $cmd, $m)) {
            if ($this->failure === 'terminate') return '';
            if ($this->failure !== 'still-online') unset($this->sas[(int) $m[1]]);
            return 'VPNBOT_IKEV2_TERMINATED';
        }
        return '';
    }
}
function requireIpsec(bool $ok, string $message): void { if (!$ok) throw new RuntimeException($message); }
if (($argv[1] ?? '') === '--child') {
    $bot = new IpsecUsersBot($argv[2]); $protocol = $argv[3]; $action = $argv[4];
    $method = $protocol === 'ikev2' ? 'updateIkev2Users' : 'updateL2tpUsers';
    $ok = $bot->$method(function (&$users) use ($action, $argv) {
        if ($action === 'disable') {
            touch($argv[2] . '/entered');
            $until = microtime(true) + 5;
            while (!file_exists($argv[2] . '/continue') && microtime(true) < $until) usleep(10000);
            $users['alice']['disabled'] = true;
        } else $users['bob']['pass'] = 'changed';
    });
    exit($ok ? 0 : 1);
}
$root = sys_get_temp_dir() . '/ipsec-users-' . bin2hex(random_bytes(8)); mkdir($root, 0700);
try {
    $bot = new IpsecUsersBot($root);
    $initial = ['alice' => ['pass' => 'synthetic-a', 'disabled' => false], 'bob' => ['pass' => 'synthetic-b', 'disabled' => false]];
    foreach (['reload', 'transport', 'status', 'terminate', 'still-online'] as $failure) {
        file_put_contents("$root/users_ikev2.json", json_encode($initial));
        $bot->sas = [1 => 'alice', 2 => 'alice', 3 => 'bob']; $bot->failure = $failure; $bot->commands = [];
        requireIpsec(!$bot->updateIkev2Users(static function (&$users) { $users['alice']['disabled'] = true; }), "failure must be visible: $failure");
        $users = $bot->getIkev2Users();
        requireIpsec($users['alice']['disabled'] && $users['alice']['pending'] === 'disable', "revoke intent must survive: $failure");
        requireIpsec(!str_contains(file_get_contents("$root/secrets.conf"), 'id = "alice"'), 'disabled identity is absent from derived credentials');
        $bot->failure = ''; $bot->retryIkev2Users();
        requireIpsec(!isset($bot->getIkev2Users()['alice']['pending']) && $bot->sas === [3 => 'bob'], 'retry confirms all target SAs are gone and keeps other users');
    }
    $bot->failure = 'reload';
    requireIpsec(!$bot->updateIkev2Users(static function (&$users) { unset($users['alice']); }), 'delete awaits reload');
    requireIpsec(($bot->getIkev2Users()['alice']['pending'] ?? '') === 'delete', 'pending deletion is durable');
    $bot->failure = ''; $bot->retryIkev2Users();
    requireIpsec(!isset($bot->getIkev2Users()['alice']), 'delete commits only after confirmed reload and SA check');
    file_put_contents("$root/users_ikev2.json", json_encode($initial));
    $bot->failure = 'reload'; $bot->updateIkev2Users(static function (&$users) { unset($users['alice']); });
    $bot->failure = '';
    requireIpsec($bot->updateIkev2Users(static function (&$users) { $users['alice']['disabled'] = false; }), 'explicit enable supersedes pending deletion');
    requireIpsec(isset($bot->getIkev2Users()['alice']) && !$bot->getIkev2Users()['alice']['disabled'], 'enabled record remains');

    // A failed derived-file write preserves durable intent, then a fresh retry repairs it.
    unlink("$root/secrets.conf"); mkdir("$root/secrets.conf");
    set_error_handler(static function ($level, $message) { throw new ErrorException('synthetic write failure', 0, $level); });
    try { $bot->updateIkev2Users(static function (&$users) { $users['alice']['disabled'] = true; }); throw new LogicException('write must fail'); }
    catch (ErrorException $expected) {} finally { restore_error_handler(); }
    requireIpsec(($bot->getIkev2Users()['alice']['pending'] ?? '') === 'disable', 'write failure preserves intent');
    rmdir("$root/secrets.conf"); $bot->retryIkev2Users();
    requireIpsec(!isset($bot->getIkev2Users()['alice']['pending']), 'retry repairs derived credentials');

    foreach (['l2tp', 'ikev2'] as $protocol) {
        if ($protocol === 'l2tp') $bot->saveL2tpUsers($initial);
        else file_put_contents("$root/users_ikev2.json", json_encode($initial));
        $children = [];
        foreach (['disable', 'password'] as $action) {
            $children[] = proc_open([PHP_BINARY, __FILE__, '--child', $root, $protocol, $action],
                [0 => ['file', '/dev/null', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
            if ($action === 'disable') {
                $until = microtime(true)+5;
                while (!file_exists("$root/entered") && microtime(true)<$until) usleep(10000);
                requireIpsec(file_exists("$root/entered"), 'first writer holds lock');
            }
        }
        touch("$root/continue");
        foreach ($children as $child) requireIpsec(proc_close($child) === 0, 'concurrent writer completed');
        $users = $protocol === 'l2tp' ? $bot->getL2tpUsers() : $bot->getIkev2Users();
        requireIpsec($users['alice']['disabled'] && $users['bob']['pass'] === 'changed', "$protocol callback preserves both concurrent intents");
        unlink("$root/entered"); unlink("$root/continue");
    }
    foreach (['users_ikev2.json' => '{broken', 'chap-secrets' => 'invalid canonical row'] as $file => $body) {
        file_put_contents("$root/$file", $body);
        try {
            if ($file === 'chap-secrets') $bot->updateL2tpUsers(static function (&$users) { $users = []; });
            else $bot->updateIkev2Users(static function (&$users) { $users = []; });
            throw new LogicException('corrupt store must be rejected');
        } catch (RuntimeException $expected) {}
        requireIpsec(file_get_contents("$root/$file") === $body, 'read failure does not erase database');
    }
    requireIpsec((fileperms("$root/secrets.conf") & 0777) === 0600, 'derived credentials mode 0600');
    echo "ipsec users: PASS\n";
} finally {
    foreach (glob("$root/*") as $file) { if (is_dir($file)) rmdir($file); else unlink($file); }
    rmdir($root);
}
