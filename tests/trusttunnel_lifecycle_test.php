<?php
require_once __DIR__ . '/../app/bot.php';
class TtLifecycleBot extends Bot {
    public bool $failWrite = false;
    public bool $slow = false;
    public int $sshCalls = 0;
    public function __construct(public string $root) { $this->input = ['chat' => 1]; }
    public function ttPaths() { return ['dir'=>$this->root, 'cred'=>"$this->root/credentials.toml", 'hosts'=>"$this->root/hosts.toml", 'vpn'=>"$this->root/vpn.toml", 'rules'=>"$this->root/rules.toml", 'log'=>"$this->root/log"]; }
    public function ttDomain() { return 'vpn.example.com'; }
    public function ttBlockers() { return []; }
    public function getClientsTt() { $users = parent::getClientsTt(); if ($this->slow) usleep(80000); return $users; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) {
        $lock = fopen("$this->root/$name.lock", 'c'); flock($lock, LOCK_EX);
        try { return $fn(); } finally { flock($lock, LOCK_UN); fclose($lock); }
    }
    public function writePrivateKey(string $path, string $data): bool { return !$this->failWrite && parent::writePrivateKey($path, $data); }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') { $this->sshCalls++; return str_contains($cmd, 'VPNBOT_TT_STOPPED') ? 'VPNBOT_TT_STOPPED' : ''; }
    public function menu($type = false, $arg = false, $return = false) {}
    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false) { return []; }
}
$root = sys_get_temp_dir() . '/vpnbot-tt-lifecycle-' . bin2hex(random_bytes(6)); mkdir($root, 0700);
$failures=[]; $check=static function ($ok,$name) use (&$failures) {if (!$ok) $failures[]=$name;};
try {
    $bot=new TtLifecycleBot($root); touch("$root/vpn.toml"); touch("$root/rules.toml");
    $bot->writeTtCredentials(['alice'=>'original']); clearstatcache();
    $check((fileperms("$root/credentials.toml") & 0777) === 0600, 'Реквизиты доступны только владельцу');
    $original=file_get_contents("$root/credentials.toml") . "# preserved administrator comment\n";
    file_put_contents("$root/credentials.toml",$original); $check($bot->restartTt() === true, 'Штатный restart подтверждён');
    $check(file_get_contents("$root/credentials.toml") === $original, 'Restart не переписывает и не восстанавливает устаревшие реквизиты');
    $bot->failWrite=true; $bot->sshCalls=0;
    try {$bot->chttpass('changed','alice');} catch (RuntimeException $e) {}
    $check($bot->sshCalls === 0 && $bot->getClientsTt()['alice'] === 'original', 'Ошибка записи не останавливает ядро и не меняет пароль');
    $bot->failWrite=false; $bot->slow=true; $children=[];
    for($i=0;$i<6;$i++) {
        $pid=pcntl_fork(); if($pid===0) {$bot->addttus('parallel'.$i);exit(0);} $children[]=$pid;
    }
    foreach($children as $pid) {pcntl_waitpid($pid,$status);$check(pcntl_wexitstatus($status)===0,'Параллельный процесс завершился');}
    $check(count($bot->getClientsTt())===7,'Параллельное создание не теряет пользователей');
    $bot->delttus('alice',true); $bot->restartTt();
    $check(!isset($bot->getClientsTt()['alice']),'Удалённые реквизиты не воскресают после restart');
} finally {foreach(glob("$root/*") as $file) unlink($file);rmdir($root);}
foreach($failures as $failure) echo "FAIL: $failure\n";
if($failures) exit(1);
echo "trusttunnel_lifecycle_test OK\n";
