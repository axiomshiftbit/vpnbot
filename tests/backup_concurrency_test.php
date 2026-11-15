<?php
require_once __DIR__.'/../app/bot.php';
class BackupLockBot extends Bot {
    public array $messages=[];
    public function __construct(public string $root) { $this->pac="$root/pac.json"; $this->update="$root/incoming.json"; $this->input=['chat'=>1,'message_id'=>1]; }
    public function update($chat,$message_id,$text,$button=false,$reply=false,$mode='HTML') { $this->messages[]=$text; }
    public function restartNaive() { return true; }
    public function pacUpdate($import='') {}
    public function dnsttStart() { return true; }
    public function setUpstreamDomainOcserv($domain) {}
    public function setUpstreamDomainNaive($domain) {}
    public function cloakNginx() { return true; }
    // This fixture tests the backup mutex; service readiness has its own suite.
    public function verifyBackupServices(array $json): array { return []; }
}
function lockCheck(bool $ok,string $message): void { if (!$ok) throw new RuntimeException($message); }
$root=sys_get_temp_dir().'/vpnbot-backup-lock-'.bin2hex(random_bytes(6));mkdir($root,0700);
$log=ini_set('error_log',"$root/error.log");
try {
    $first=new BackupLockBot($root);$second=new BackupLockBot($root);
    $first->setPacConf(['domain'=>'before.example','language'=>'ru','limitpage'=>5]);
    file_put_contents($first->update,json_encode(['pac'=>['domain'=>'restored.example','language'=>'ru','limitpage'=>5]]));
    $lock=new ReflectionMethod(Bot::class,'withBackupLock');
    $lock->invoke($first,function() use($second,$root) {
        $second->checkBackup();
        lockCheck(!is_file("$root/error.log") || filesize("$root/error.log")===0,
            'Выключенное расписание не конкурирует с ручным бэкапом и не пишет ложную ошибку');
    });
    $lock->invoke($first,function() use($second,$first,$lock,$root) {
        lockCheck($lock->invoke($first,fn()=>42)===42,'Вложенный экспорт не блокирует собственную операцию');
        if (function_exists('pcntl_fork')) {
            $pid=pcntl_fork();
            if ($pid===0) { file_put_contents("$root/child-result",$second->importFile($second->update)===false?'rejected':'accepted');exit(0); }
            pcntl_waitpid($pid,$status);
            lockCheck(pcntl_wifexited($status) && pcntl_wexitstatus($status)===0 && file_get_contents("$root/child-result")==='rejected','Другой процесс не начинает восстановление во время экспорта');
        } else lockCheck($second->importFile($second->update)===false,'Параллельная операция не применяется');
        lockCheck($first->getPacConf()['domain']==='before.example','Отказ занятого восстановления ничего не изменил');
    });
    lockCheck($second->importFile($second->update)===true && $first->getPacConf()['domain']==='restored.example','После освобождения блокировки повтор успешен');
    $second->pac="$root/missing/pac.json";
    lockCheck($second->importFile($second->update)===false,'Ошибка открытия lock не разрешает восстановление без блокировки');
    echo "backup_concurrency_test OK\n";
} finally {
    ini_set('error_log',$log);
    foreach(scandir($root) as $name)if($name!=='.' && $name!=='..')unlink("$root/$name");rmdir($root);
}
