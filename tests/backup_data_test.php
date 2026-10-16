<?php
require_once __DIR__ . '/../app/bot.php';
require_once __DIR__ . '/managed_protocol_fixture.php';
function dataCheck(bool $ok, string $name): void { if (!$ok) throw new RuntimeException($name); }
function dataRemove(string $path): void {
    if (is_dir($path) && !is_link($path)) { foreach (scandir($path) as $p) if ($p !== '.' && $p !== '..') dataRemove("$path/$p"); rmdir($path); }
    else unlink($path);
}
class BackupDataBot extends Bot {
    public ?string $failName = null;
    public bool $failAfterWrite = false;
    public function __construct(string $dir) {
        mkdir($dir, 0700, true);
        $this->pac="$dir/pac.json"; $this->protocolRoot="$dir/protocols"; $this->protocolModulesFile="$dir/modules.json";
        $this->protocolCertRoot="$dir/certs"; mkdir($this->protocolCertRoot, 0700);
        $this->upstreamFile="$dir/absent-upstream"; $this->telemtDecoyDir="$dir/telemt/decoy";
        $this->htpasswd="$dir/webapp/.htpasswd"; $this->backupWarpRoot="$dir/warp";
        $this->setPacConf(['language'=>'ru']);
    }
    public function writePrivateKey(string $path, string $data): bool {
        if ($this->failName !== null && str_ends_with($path, $this->failName)) {
            $this->failName = null;
            if ($this->failAfterWrite && !parent::writePrivateKey($path, $data)) throw new LogicException('Тестовая запись не выполнена');
            return false;
        }
        return parent::writePrivateKey($path,$data);
    }
}
$root=sys_get_temp_dir().'/vpnbot-backup-data-'.bin2hex(random_bytes(6));mkdir($root,0700);
try {
    $source=new BackupDataBot("$root/source"); $dest=new BackupDataBot("$root/dest");
    $ids=[];
    foreach (ManagedProtocol::NAMES as $protocol=>$_) {
        $store=$source->protocolStore($protocol);
        $store->configure(['host'=>"$protocol.example.test",'sni'=>$protocol === 'snolc' ? '' : "$protocol.example.test"], true);
        $id=managedProtocolFixtureUser($store,'Пользователь '.$protocol); $ids[$protocol]=$id;
        $store->user($id,['quota'=>10000000,'expires'=>2000000000]);
        $state=$store->read();
        $usage=['users'=>[$id=>['upload'=>12345,'download'=>67890,'reset'=>$state['users'][$id]['reset'],'last'=>['upload'=>3]]]];
        if ($protocol==='snolc') $usage['users'][$id]['charged']=90000;
        if ($protocol==='mieru') $usage['native_metrics']=base64_encode('synthetic-native-history');
        ManagedProtocol::writeJson($store->directory().'/runtime/usage.json',$usage);
    }
    $modules=new ProtocolModules($source->protocolModulesFile); $modules->set('masque',false); $modules->set('telemt',false);
    $backup=$source->exportManagedProtocols(); $dest->importManagedProtocols($backup);
    $again=$dest->exportManagedProtocols();
    dataCheck($again['modules']===$backup['modules'],'Выключатели всех протоколов сохранены');
    dataCheck(array_keys($again['protocols'])===array_keys(ManagedProtocol::NAMES),'Все шесть протоколов включены в копию');
    foreach ($ids as $protocol=>$id) {
        $old=$backup['protocols'][$protocol];$new=$again['protocols'][$protocol];
        dataCheck($old['state']['users']===$new['state']['users'],"$protocol: ключи, токены, квоты и срок сохранены");
        dataCheck($old['state']['settings']===$new['state']['settings'],"$protocol: настройки сохранены");
        dataCheck($old['usage']===$new['usage'],"$protocol: повторный бэкап сохраняет расход до запуска ядра");
        $store=$dest->protocolStore($protocol);$pending=$store->read()['restore_usage'];
        $usage=$new['usage'];$usage['users'][$id]['upload']++;$usage['restored']=$pending['id'];
        ManagedProtocol::writeJson($store->directory().'/runtime/usage.json',$usage);
        dataCheck($store->snapshot()['usage']['users'][$id]['upload']===12346,"$protocol: после применения берётся свежий расход");
    }
    $hy=new HysteriaUsers("$root/hy"); $id=$hy->add('Hysteria');$state=$hy->read();
    mkdir("$root/hy/runtime",0700);
    ManagedProtocol::writeJson("$root/hy/runtime/usage.json",['users'=>[$id=>['upload'=>12,'download'=>34,'reset'=>$state['users'][$id]['reset']]]]);
    $snapshot=$hy->snapshot(); $restored=new HysteriaUsers("$root/hy-restored");$restored->restore($snapshot);
    dataCheck($restored->snapshot()['usage']===$snapshot['usage'],'Hysteria: копия ожидающего восстановления без runtime');
    $files=['stlsserver.json'=>base64_encode('{"Enabled":1,"ServerName":"cover.example"}'),
        'ss.acl'=>base64_encode('[outbound_block_list]\n192.0.2.0/24'), 'sing.json'=>base64_encode('{"outbounds":[]}'),
        'trusttunnel/hosts.toml'=>base64_encode('synthetic-hosts'), 'trusttunnel/rules.toml'=>base64_encode('synthetic-rules'),
        'telemt/decoy/index.html'=>base64_encode('<!doctype html>Test'), 'telemt/decoy/loading.css'=>base64_encode('body{color:#333}'),
        'panel/password-display.key'=>base64_encode(random_bytes(32)), 'panel/password-display.json'=>base64_encode('{}'),
        'warp/wgcf-profile.conf'=>base64_encode('synthetic-profile'), 'warp/clients/test-01234567/wgcf-account.toml'=>base64_encode('synthetic-account')];
    $source->restoreBackupExtraFiles($files); $export=$source->backupExtraFiles(); $dest->restoreBackupExtraFiles($export);
    dataCheck($dest->backupExtraFiles()===$export,'Все дополнительные файлы восстановлены побайтно');
    dataCheck((fileperms("$root/dest/panel/password-display.key")&0777)===0600,'Секретные файлы закрыты');
    dataCheck((fileperms("$root/dest/telemt/decoy/index.html")&0777)===0644,'Страница доступна веб-серверу');
    foreach (['../outside','/etc/passwd','warp/clients/../wgcf-profile.conf','unknown','nginx.conf','protocol-services.json'] as $name) {
        try {$dest->restoreBackupExtraFiles([$name=>base64_encode('bad')]);throw new LogicException('Принят посторонний путь');} catch(RuntimeException $e) {}
    }
    foreach ([['sing.json'=>'%%%'],['sing.json'=>base64_encode('broken')],['panel/password-display.key'=>base64_encode(str_repeat('x',32))]] as $bad) {
        try {$dest->restoreBackupExtraFiles($bad);throw new LogicException('Принят повреждённый файл');} catch(RuntimeException $e) {} catch(JsonException $e) {}
    }
    foreach ([false, true] as $afterWrite) {
        $dest->failName='sing.json'; $dest->failAfterWrite=$afterWrite;
        try {$dest->restoreBackupExtraFiles(['ss.acl'=>base64_encode('changed'),'sing.json'=>base64_encode('{}')]);throw new LogicException('Запись должна отказать');}catch(RuntimeException $e){}
        dataCheck($dest->backupExtraFiles()===$export,'Ошибка до или после второй записи откатывает оба файла');
    }
    $tls = new ReflectionMethod(Bot::class, 'restoreBackupCertificates');
    foreach ([false, true] as $existed) {
        foreach (['private','public'] as $part) if ($existed) file_put_contents("$dest->protocolCertRoot/cert_$part", "old-$part");
        $dest->failName='cert_public'; $dest->failAfterWrite=true;
        dataCheck($tls->invoke($dest,['private'=>'new-private','public'=>'new-public'])===false,'Ошибка второй записи TLS отклонена');
        foreach (['private','public'] as $part) {
            $path="$dest->protocolCertRoot/cert_$part";
            dataCheck($existed ? file_get_contents($path)==="old-$part" && (fileperms($path)&0777)===0600 : !file_exists($path),'При отказе TLS восстановлена прежняя пара целиком');
        }
    }
    unlink("$root/dest/ss.acl");symlink("$root/source/ss.acl","$root/dest/ss.acl");
    try {$dest->backupExtraFiles();throw new LogicException('Симлинк принят');}catch(RuntimeException $e){}
    echo "backup_data_test OK\n";
} finally { dataRemove($root); }
