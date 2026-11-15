<?php
// Два настоящих синтетических файла, настоящая atomic-write и flock; без SSH.
$source = getenv('VPNBOT_TEST_SOURCE') ?: dirname(__DIR__);
require_once $source . '/app/bot.php';
class OcTransactionFixture extends Bot {
    public string $root;
    public bool $failPacOnce = false;
    public bool $failAfterRename = false;
    public bool $crashAfterPassword = false;
    public function __construct(string $root) { $this->root = $root; $this->pac = "$root/pac.json"; $this->language = 'ru'; }
    protected function ocPasswordPath(): string { return getenv('VPNBOT_TEST_PASSWORD_FILE') ?: "$this->root/ocserv.passwd"; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) {
        $lock = fopen("$this->root/lock-$name", 'c'); if (!$lock || !flock($lock, LOCK_EX)) return $busy;
        try { return $fn(); } finally { flock($lock, LOCK_UN); fclose($lock); }
    }
    public function setPacConf(array $conf) {
        if ($this->failPacOnce) {
            $this->failPacOnce = false;
            if ($this->failAfterRename) parent::setPacConf($conf);
            return false;
        }
        return parent::setPacConf($conf);
    }
    public function writePrivateKey(string $path, string $data): bool {
        $ok = parent::writePrivateKey($path, $data);
        if ($ok && $this->crashAfterPassword && $path === $this->ocPasswordPath()) exit(87);
        return $ok;
    }
    public function change(string $pass): bool { return $this->saveOcPassword('synthetic-user', $pass); }
    public function recover(): array { return $this->syncOcUsers(['synthetic-user']); }
}
if (($argv[1] ?? '') === 'crash-worker') {
    $bot = new OcTransactionFixture($argv[2]);
    $bot->crashAfterPassword = true;
    $bot->change('synthetic-new-password');
    exit(1);
}
$root = sys_get_temp_dir() . '/oc-transaction-' . bin2hex(random_bytes(8)); mkdir($root, 0700);
$passwordFile = getenv('VPNBOT_TEST_PASSWORD_FILE') ?: "$root/ocserv.passwd";
$checks = 0;
$assert = static function (bool $ok, string $label) use (&$checks) { if (!$ok) throw new RuntimeException($label); $checks++; };
try {
    $bot = new OcTransactionFixture($root);
    $old = 'synthetic-old-password'; $next = 'synthetic-new-password';
    $initial = ['ocserv_users' => ['synthetic-user' => $old], 'unrelated' => ['preserved' => true]];
    $raw = 'synthetic-user:*:' . crypt($old, '$6$synthetic$') . "\n";
    $seed = static function () use ($bot, $initial, $passwordFile, $raw) { $bot->setPacConf($initial); file_put_contents($passwordFile, $raw); };
    $seed(); $assert($bot->change($next), 'healthy update succeeds');
    $hash = explode(':', trim(file_get_contents($passwordFile)), 3)[2];
    $assert(hash_equals($hash, crypt($next, $hash)) && $bot->getPacConf()['ocserv_users']['synthetic-user'] === $next, 'both healthy states agree');
    echo "positive control: PASS\n";
    foreach ([false, true] as $afterRename) {
        $seed(); $bot->failPacOnce = true; $bot->failAfterRename = $afterRename;
        $assert(!$bot->change($next), 'failed PAC commit cannot report success');
        $assert(file_get_contents($passwordFile) === $raw, 'password file compensation');
        $assert($bot->getPacConf()['ocserv_users'] === $initial['ocserv_users'], 'PAC compensation including failure after rename');
        $assert(!file_exists($passwordFile . '.update.json'), 'confirmed compensation removes intent');
    }
    {
        $seed();
        $child = proc_open([PHP_BINARY, __FILE__, 'crash-worker', $root], [0 => ['file', '/dev/null', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
        $assert(proc_close($child) === 87, 'bounded crash occurred after first publish');
        $assert(is_file($passwordFile . '.update.json'), 'durable prepared intent survives process exit');
        (new OcTransactionFixture($root))->recover();
        $assert(file_get_contents($passwordFile) === $raw && $bot->getPacConf()['ocserv_users'] === $initial['ocserv_users'], 'next process repairs both states');
        $assert($bot->getPacConf()['unrelated'] === $initial['unrelated'], 'recovery preserves other PAC fields');
    }
    echo "oc_password_transaction_test OK ($checks)\n";
} finally {
    foreach (glob("$root/*") as $path) unlink($path); rmdir($root);
}
