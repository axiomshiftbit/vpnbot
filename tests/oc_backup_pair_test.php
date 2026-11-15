<?php
// Real files/flock/process exit; no SSH. Legacy branches replay the old backup
// call order only for the before/after regression against the pre-helper source.
require_once (getenv('VPNBOT_TEST_SOURCE') ?: dirname(__DIR__)) . '/app/bot.php';
class OcBackupFixture extends Bot {
    public string $root;
    public bool $failPac = false, $afterRename = false;
    public string $crash = '';
    public function __construct(string $root) { $this->root = $root; $this->pac = "$root/pac.json"; $this->language = 'ru'; }
    protected function ocPasswordPath(): string { return "$this->root/ocserv.passwd"; }
    public function getClientsOc() { return array_map(fn($line) => explode(':', $line)[0], array_filter(explode("\n", (string) file_get_contents($this->ocPasswordPath())))); }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) {
        $f = fopen("$this->root/lock-$name", 'c'); if (!$f || !flock($f, LOCK_EX)) return $busy;
        try { return $fn(); } finally { flock($f, LOCK_UN); fclose($f); }
    }
    public function setPacConf(array $pac) {
        if ($this->failPac) { $this->failPac = false; if ($this->afterRename) parent::setPacConf($pac); return false; }
        $ok = parent::setPacConf($pac); if ($ok && $this->crash === 'pac') exit(87); return $ok;
    }
    public function writePrivateKey(string $path, string $data): bool {
        $ok = parent::writePrivateKey($path, $data);
        if ($ok && (($this->crash === 'password' && $path === $this->ocPasswordPath())
            || ($this->crash === 'committed' && str_ends_with($path, '.update.json') && (json_decode($data, true)['phase'] ?? '') === 'committed'))) exit(87);
        return $ok;
    }
    public function change(): bool { return $this->saveOcPassword('audit', 'synthetic-next'); }
    public function snapshot(callable $fn) {
        if (method_exists($this, 'withOcUsersSnapshot')) return $this->withOcUsersSnapshot($fn);
        $this->syncOcUsers(); return $fn(null);
    }
    public function restorePair(string $raw, array $pac): bool {
        if (method_exists($this, 'restoreOcPasswordPair')) return $this->restoreOcPasswordPair($raw, $pac);
        return $this->setPacConf($pac) !== false && $this->writePrivateKey($this->ocPasswordPath(), $raw);
    }
}
$rawFor = static fn(string $pass) => 'audit:*:' . crypt($pass, '$6$synthetic$') . "\n";
$matches = static function(string $raw, array $pac): bool {
    $hash = explode(':', trim($raw), 3)[2] ?? '';
    return $hash !== '' && hash_equals($hash, crypt($pac['ocserv_users']['audit'] ?? '', $hash));
};
if (($argv[1] ?? '') === 'writer') {
    $b = new OcBackupFixture($argv[2]); touch($argv[2] . '/started');
    $ok = $b->change(); touch($argv[2] . '/done'); exit($ok ? 0 : 1);
}
if (($argv[1] ?? '') === 'crash') {
    $b = new OcBackupFixture($argv[2]); $b->crash = $argv[3];
    $b->restorePair($rawFor('synthetic-next'), ['ocserv_users'=>['audit'=>'synthetic-next'],'ocserv'=>'synthetic-legacy-next']); exit(1);
}
$root = sys_get_temp_dir() . '/oc-backup-' . bin2hex(random_bytes(7)); mkdir($root, 0700);
$checks = 0; $fails = [];
$check = static function(bool $ok, string $label) use (&$checks,&$fails) { $checks++; if (!$ok) $fails[] = $label; };
$descriptors = [0=>['file','/dev/null','r'],1=>['file','/dev/null','w'],2=>['file','/dev/null','w']];
$seed = static function() use($root,$rawFor): OcBackupFixture {
    foreach(glob("$root/*") as $p) unlink($p);
    $b = new OcBackupFixture($root); $b->setPacConf(['ocserv_users'=>['audit'=>'synthetic-old'],'ocserv'=>'synthetic-legacy-old','unrelated'=>17]);
    file_put_contents("$root/ocserv.passwd", $rawFor('synthetic-old')); return $b;
};
try {
    $b = $seed(); $next = ['ocserv_users'=>['audit'=>'synthetic-next'],'ocserv'=>'synthetic-legacy-next'];
    $check($b->restorePair($rawFor('synthetic-next'),$next), 'healthy restore positive control');
    $check($matches(file_get_contents("$root/ocserv.passwd"),$b->getPacConf()), 'healthy password and PAC agree');
    $check(($b->getPacConf()['unrelated'] ?? null) === 17, 'restore does not replace unrelated PAC fields');
    foreach([false,true] as $after) {
        $b=$seed(); $oldPac=$b->getPacConf(); $oldRaw=file_get_contents("$root/ocserv.passwd"); $b->failPac=true; $b->afterRename=$after;
        $check(!$b->restorePair($rawFor('synthetic-next'),$next), 'failed restore reports failure');
        $check(file_get_contents("$root/ocserv.passwd")===$oldRaw && $b->getPacConf()['ocserv_users']===$oldPac['ocserv_users'] && $b->getPacConf()['ocserv']===$oldPac['ocserv'], 'failure compensates password, user map and legacy field');
    }
    foreach(['password','pac','committed'] as $phase) {
        $b=$seed(); $child=proc_open([PHP_BINARY,__FILE__,'crash',$root,$phase],$descriptors,$pipes);
        $check(proc_close($child)===87, 'bounded process exit at restore publication phase');
        $check(is_file("$root/ocserv.passwd.update.json"), 'durable restore intent survives crash');
        // A different PAC owner writes after crash, before OC recovery.
        $b->pacConfUpdate(static function(&$pac) { $pac['unrelated']=23; });
        $b->snapshot(static fn($raw)=>true); $pac=$b->getPacConf();
        $expected=$phase==='committed'?'synthetic-next':'synthetic-old';
        $check(($pac['ocserv_users']['audit']??'')===$expected && $matches(file_get_contents("$root/ocserv.passwd"),$pac), 'recovery chooses complete committed or previous pair');
        $check(($pac['ocserv']??'')===($phase==='committed'?'synthetic-legacy-next':'synthetic-legacy-old') && $pac['unrelated']===23, 'recovery restores legacy and preserves concurrent non-OC change');
        $check(!file_exists("$root/ocserv.passwd.update.json"), 'recovery removes completed intent');
    }
    $b=$seed(); $worker=null;
    $b->snapshot(function($raw) use($b,$root,$check,$matches,$descriptors,&$worker) {
        $pac=$b->getPacConf();
        $worker=proc_open([PHP_BINARY,__FILE__,'writer',$root],$descriptors,$pipes);
        $deadline=microtime(true)+3; while(!is_file("$root/started")&&microtime(true)<$deadline) usleep(1000);
        if ($raw===null) { while(!is_file("$root/done")&&microtime(true)<$deadline) usleep(1000); }
        else usleep(150000);
        $check(is_file("$root/started")&&!is_file("$root/done"), 'concurrent password writer waits for whole backup snapshot');
        $raw ??= file_get_contents("$root/ocserv.passwd");
        $check($matches($raw,$pac), 'snapshot never mixes old PAC and new password hash');
    });
    $check(proc_close($worker)===0 && $matches(file_get_contents("$root/ocserv.passwd"),$b->getPacConf()) && $b->getPacConf()['ocserv_users']['audit']==='synthetic-next', 'writer completes after snapshot lock release');
    $b=$seed(); unlink("$root/ocserv.passwd"); $b->failPac=true;
    $check(!$b->restorePair($rawFor('synthetic-next'),$next) && !file_exists("$root/ocserv.passwd"), 'rollback preserves previously absent password file');
    $b=$seed(); $old=file_get_contents("$root/ocserv.passwd");
    file_put_contents("$root/ocserv.passwd.update.json",json_encode(['version'=>1,'phase'=>'prepared','password_file'=>base64_encode($old),'users_present'=>true,'users'=>['audit'=>'synthetic-old']]));
    file_put_contents("$root/ocserv.passwd",$rawFor('synthetic-next'));
    $b->pacConfUpdate(static function(&$pac) { $pac['ocserv_users']=['audit'=>'synthetic-next']; $pac['ocserv']='legacy-outside-old-journal'; });
    $b->snapshot(static fn($raw)=>true);
    $check($b->getPacConf()['ocserv_users']['audit']==='synthetic-old' && $b->getPacConf()['ocserv']==='legacy-outside-old-journal' && file_get_contents("$root/ocserv.passwd")===$old, 'old version1 journal remains compatible without invented legacy rollback');
} finally { foreach(glob("$root/*") as $p) unlink($p); rmdir($root); }
foreach($fails as $label) echo "FAIL: $label\n";
echo 'oc_backup_pair_test: ',count($fails)," failure(s), $checks checks\n";
exit($fails?1:0);
