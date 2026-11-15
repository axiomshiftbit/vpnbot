<?php
require_once __DIR__ . '/../app/bot.php';
require __DIR__ . '/../app/i18n.php';

// Реальный import и файлы. SSH моделирует отказ ядра на неизвестном шифре;
// саму проверку готовности и возврат прежнего файла не подменяем.
class BackupServiceRollbackBot extends Bot {
    public bool $running = true;
    public int $controlCalls = 0;
    public array $messages = [];
    public function __construct(public string $root, array $translations) {
        $this->pac="$root/pac.json"; $this->update="$root/backup.json";
        $this->i18n=$translations; $this->language='ru';
        $this->input=['chat'=>1,'message_id'=>1];
        $this->setPacConf(['language'=>'ru','limitpage'=>5]);
    }
    public function withLock(string $name, callable $fn, int $timeout=0, $busy=null) {
        $h=fopen($this->root.'/.lock.'.$name,'c');if(!$h||!flock($h,LOCK_EX))return $busy;
        try{return $fn();}finally{flock($h,LOCK_UN);fclose($h);}
    }
    public function protocolModuleEnabled(string $service): bool { return in_array($service,['ss','proxy'],true); }
    public function ssh($cmd,$service='wg',$wait=true,$log='/dev/null') {
        if (preg_match('~^/bin/sh /service_supervisor.sh (stop|start) (ssserver|sslocal)$~',$cmd,$m)) {
            $this->controlCalls++;
            if ($m[1]==='stop') { $this->running=false; return 'VPNBOT_SERVICE_STOPPED:'.$m[2]; }
            $conf=json_decode(file_get_contents($this->root.'/'.$m[2].'.json'),true);
            $this->running=($conf['method']??'')==='chacha20-ietf-poly1305';
            return $this->running ? 'VPNBOT_SERVICE_READY:'.$m[2] : '';
        }
        if (str_contains($cmd,'VPNBOT_SERVICE_READY')) return $this->running ? 'VPNBOT_SERVICE_READY' : '';
        if (str_starts_with($cmd,'pkill ')) $this->running=false;
        if (str_contains($cmd,' -v -d -c /config.json')) {
            $conf=json_decode(file_get_contents($this->root.'/'.($service==='ss'?'ssserver':'sslocal').'.json'),true);
            $this->running=($conf['method']??'')==='chacha20-ietf-poly1305';
        }
        return '';
    }
    public function warpSocksAllowSS(bool $allow): bool { return true; }
    public function cloakNginx() { return true; }
    public function update($chat,$message_id,$text,$button=false,$reply=false,$mode='HTML') { $this->messages[]=$text; }
    public function send($chat,$text,?int $to=0,$button=false,$reply=false,$mode='HTML',$disable_notification=false) { $this->messages[]=$text; }
}
$root=sys_get_temp_dir().'/vpnbot-backup-service-'.bin2hex(random_bytes(6));mkdir($root,0700);
try {
    foreach (['ss'=>'ssserver','sl'=>'sslocal'] as $section=>$binary) {
        $b=new BackupServiceRollbackBot($root,$i);
        $before=json_encode(['server'=>'127.0.0.1','server_port'=>8388,'method'=>'chacha20-ietf-poly1305','password'=>'synthetic']);
        $path="$root/$binary.json";file_put_contents($path,$before);$inode=fileinode($path);
        $invalid=json_decode($before,true);$invalid['method']='invalid-cipher';
        file_put_contents($b->update,json_encode([$section=>$invalid]));
        if ($b->importFile($b->update)!==false || !str_contains(end($b->messages),'❌ Shadowsocks')) throw new RuntimeException('Отказ ядра не показан');
        clearstatcache();
        if ($b->controlCalls < 4) throw new RuntimeException('Применение и откат не исполнялись');
        if (file_get_contents($path)!==$before || fileinode($path)!==$inode || !$b->running) throw new RuntimeException('Прежний файл и сервис не восстановлены');
    }
    echo "backup_service_rollback_test OK\n";
} finally {
    foreach (glob("$root/*") as $file) unlink($file);
    foreach (glob("$root/.lock.*") as $file) unlink($file);
    @unlink("$root/.backup.lock");rmdir($root);
}
