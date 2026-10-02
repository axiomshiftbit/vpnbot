<?php
// Настоящие обработчики import/Hysteria/TrustTunnel. Подменяется только
// транспорт к ядрам; выключатели и файлы конфигурации остаются настоящими.
require_once __DIR__ . '/../app/bot.php';
require __DIR__ . '/../app/i18n.php';
class BackupStatusBot extends Bot {
    public array $messages = [];
    public array $commands = [];
    public array $blockers = [];
    public bool $managed = true;
    public bool $stopFails = false;
    public bool $startFails = false;
    public function __construct(public string $root, array $translations) {
        $this->i18n=$translations; $this->language='ru'; $this->ip='192.0.2.1';
        $this->update="$root/backup.json"; $this->pac="$root/pac.json";
        $this->protocolModulesFile="$root/modules.json";
        $this->hysteriaUsersRoot="$root/hysteria"; $this->hysteriaConf="$root/hysteria.yaml";
        $this->clients="$root/clients.json"; $this->clients1="$root/clients1.json";
        $this->backupWarpRoot="$root/warp";
        $this->input=['chat'=>1,'message_id'=>1,'callback_id'=>false];
        $this->setPacConf(['language'=>'ru','limitpage'=>5,'domain'=>'example.test','hysteria_pass'=>'synthetic-secret']);
        foreach (['vpn','rules'] as $name) file_put_contents("$root/$name.toml", "# fixture\n");
    }
    public function ttPaths() { return ['dir'=>$this->root,'cred'=>"$this->root/credentials.toml",'hosts'=>"$this->root/hosts.toml",'vpn'=>"$this->root/vpn.toml",'rules'=>"$this->root/rules.toml",'log'=>"$this->root/tt.log"]; }
    public function ttBlockers() { return $this->blockers; }
    public function withLock(string $name, callable $fn, int $timeout=0, $busy=null) {
        $lock=fopen("$this->root/$name.lock", 'c'); flock($lock, LOCK_EX);
        try { return $fn(); } finally { flock($lock, LOCK_UN); fclose($lock); }
    }
    public function ssh($cmd, $service='wg', $wait=true, $log='/dev/null') {
        $this->commands[]=[$service,$cmd]; $this->sshFailed=false;
        if (!$this->protocolModuleEnabled($service)) return parent::ssh($cmd,$service,$wait,$log);
        if (str_contains($cmd,'VPNBOT_SERVICE_READY')) return $this->startFails ? '' : 'VPNBOT_SERVICE_READY';
        if ($service==='hy') return $this->managed ? 'managed' : '';
        if ($service==='tt' && str_contains($cmd,'VPNBOT_TT_STOPPED')) return $this->stopFails ? '' : 'VPNBOT_TT_STOPPED';
        if ($service==='tt') $this->sshFailed=$this->startFails;
        return '';
    }
    public function verifyBackupServices(array $json): array {
        // Эмуляция только подтверждения supervisor: обработчик проверки остаётся настоящим.
        $state=$this->hysteriaUsersStore()->read(); @mkdir("$this->root/hysteria/runtime",0700,true);
        ManagedProtocol::writeJson("$this->root/hysteria/runtime/status.json",['time'=>time(),'running'=>true,'revision'=>$state['revision']]);
        return parent::verifyBackupServices($json);
    }
    public function restartWG($conf_str, $switch=false) { return false; }
    public function restartOcserv($conf, bool $syncCamouflage=true) { return false; }
    public function getStlsConfig() { return ['Enabled'=>1]; }
    public function update($chat,$message_id,$text,$button=false,$reply=false,$mode='HTML') { $this->messages[]=$text; }
    public function cloakNginx() {}
}
function protocolStatusCheck(bool $ok, string $name): void { if (!$ok) throw new RuntimeException($name); }
function protocolStatusRemove(string $path): void {
    if (is_dir($path)) { foreach (scandir($path) as $n) if ($n!=='.' && $n!=='..') protocolStatusRemove("$path/$n"); rmdir($path); }
    else unlink($path);
}
$root=sys_get_temp_dir().'/vpnbot-backup-status-'.bin2hex(random_bytes(6)); mkdir($root,0700);
$oldLog=ini_set('error_log',"$root/errors.log");
try {
    $b=new BackupStatusBot($root,$i);
    $modules=new ProtocolModules($b->protocolModulesFile); $modules->setMany(['hy'=>false,'tt'=>false]);
    $id=$b->hysteriaUsersStore()->add('Сохранённый пользователь');
    $users=file_get_contents("$root/hysteria/users.json");
    $hy=['listen'=>':443','auth'=>['type'=>'password','password'=>'previous']];
    $tt="[[client]]\nusername = \"test\"\npassword = \"synthetic\"\n";
    file_put_contents($b->update,json_encode(['hy'=>$hy,'tt'=>$tt]));
    protocolStatusCheck($b->importFile($b->update)===true,'Выключенные Hysteria/TrustTunnel не дают ложный отказ восстановления');
    protocolStatusCheck(!$b->commands,'К выключенным контейнерам нет обращений');
    protocolStatusCheck(file_get_contents("$root/hysteria/users.json")===$users && file_get_contents("$root/credentials.toml")===$tt,'Пользователи выключенных протоколов сохранены');
    protocolStatusCheck(yaml_parse_file($b->hysteriaConf)['auth']['password']==='synthetic-secret','Конфигурация выключенной Hysteria подготовлена');
    protocolStatusCheck(str_contains(end($b->messages),'✅ Восстановление завершено.'),'Показан успешный итог');

    $modules->setMany(['hy'=>true,'tt'=>true]); $b->commands=[];
    protocolStatusCheck($b->importFile($b->update)===true,'Включённые протоколы восстанавливаются через настоящие обработчики');
    protocolStatusCheck(count($b->commands)===4,'Проверены supervisor Hysteria и stop/start TrustTunnel');
    $b->managed=false; file_put_contents($b->update,json_encode(['hy'=>$hy]));
    protocolStatusCheck($b->importFile($b->update)===false && str_contains(end($b->messages),'❌ Hysteria:'),'Сбой включённой Hysteria назван в итоговом сообщении');
    $b->managed=true;

    foreach (['stop','start','config'] as $failure) {
        $b->stopFails=$failure==='stop'; $b->startFails=$failure==='start'; $b->blockers=$failure==='config' ? ['cert'] : [];
        file_put_contents($b->update,json_encode(['tt'=>$tt]));
        protocolStatusCheck($b->importFile($b->update)===false && str_contains(end($b->messages),'❌ TrustTunnel:'),"TrustTunnel $failure: видимый отказ с названием");
    }
    $b->stopFails=false; $b->startFails=false; $b->blockers=[]; $b->commands=[];
    file_put_contents($b->update,json_encode(['tt'=>'']));
    protocolStatusCheck($b->importFile($b->update)===true && !$b->getClientsTt(),'Пустой список отозвал доступы без ложного отказа');
    protocolStatusCheck(count($b->commands)===1 && str_contains($b->commands[0][1],'VPNBOT_TT_STOPPED'),'При пустом списке демон остановлен, новый запуск не требуется');

    foreach (['wg'=>'WireGuard','wg1'=>'WireGuard 1','oc'=>'OpenConnect'] as $key=>$label) {
        $data=$key==='oc' ? 'tcp-port = 443' : ['server'=>['interface'=>['PrivateKey'=>'synthetic','Address'=>'10.0.0.1/24']],'clients'=>[]];
        file_put_contents($b->update,json_encode([$key=>$data]));
        protocolStatusCheck($b->importFile($b->update)===false && str_contains(end($b->messages),'❌ '.$label.':'),"$label: ошибка этапа указана");
    }
    file_put_contents($b->update,json_encode(['extra_files'=>['stlsserver.json'=>base64_encode('{}'),'warp/wgcf-profile.conf'=>base64_encode('fixture')]]));
    protocolStatusCheck($b->importFile($b->update)===false && str_contains(end($b->messages),'❌ WARP:') && str_contains(end($b->messages),'❌ simple-tls:'),'Оба дополнительных сервиса сообщают отдельные ошибки');
    $log=file_get_contents("$root/errors.log");
    protocolStatusCheck(str_contains($log,'Hysteria') && !str_contains($log,'synthetic-secret'),'Журнал называет протокол без секретов');
    echo "backup_protocol_status_test OK\n";
} finally { ini_set('error_log',$oldLog); protocolStatusRemove($root); }
