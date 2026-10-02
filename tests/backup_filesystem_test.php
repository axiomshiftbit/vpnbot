<?php
require_once __DIR__ . '/../app/bot.php';
require_once __DIR__ . '/backup_pki_fixture.php';
class BackupFilesystemBot extends Bot {
    public int $renames=0;
    public int $failRename=0;
    public function __construct(public string $root) {}
    public function ovpnPaths() { return ['pki'=>"$this->root/openvpn/pki"]; }
    public function ipsecPaths() { return ['conf'=>"$this->root/ipsec"]; }
    protected function backupRename(string $from,string $to): bool {
        if (++$this->renames===$this->failRename) return false;
        return parent::backupRename($from,$to);
    }
    public function inPlace(string $path,string $body): bool { return $this->backupWriteInPlace($path,$body); }
}
function fsCheck(bool $ok,string $message): void { if (!$ok) throw new RuntimeException($message); }
function fsRemove(string $path): void {
    if (is_dir($path) && !is_link($path)) { foreach (scandir($path) as $n) if ($n!=='.' && $n!=='..') fsRemove("$path/$n"); rmdir($path); }
    else unlink($path);
}
$root=sys_get_temp_dir().'/vpnbot-backup-files-'.bin2hex(random_bytes(6)); mkdir($root,0700);
$oldLog=ini_set('error_log',"$root/errors.log");
try {
    $b=new BackupFilesystemBot($root);
    foreach (['outside','ipsec','openvpn'] as $dir) mkdir("$root/$dir",0700);
    file_put_contents("$root/outside/key",'untouched');
    foreach (['linked/key','linked/new-key'] as $name) {
        symlink("$root/outside","$root/ipsec/linked");
        fsCheck(!$b->importIpsecPki([$name=>base64_encode('overwrite')]),'IPsec: путь через симлинк запрещён');
        fsCheck(file_get_contents("$root/outside/key")==='untouched' && !file_exists("$root/outside/new-key"),'За пределами каталога ничего не изменилось');
        unlink("$root/ipsec/linked");
    }
    symlink("$root/outside","$root/openvpn/pki");
    $ovpn=array_fill_keys(Bot::OVPN_SNAPSHOT_CORE,base64_encode('new'));
    fsCheck(!$b->importOvpnPki($ovpn,true),'OpenVPN: каталог-ссылка отклонён');
    unlink("$root/openvpn/pki");
    foreach ([['a'=>base64_encode('x'),'a/b'=>base64_encode('y')],['a/./b'=>base64_encode('x')],['a\\b'=>base64_encode('x')],['null'."\0"=>base64_encode('x')],['bad'=>[]]] as $bad) {
        fsCheck(!$b->importIpsecPki($bad),'Неоднозначный или повреждённый путь не применяется');
    }
    foreach ([1,2,3] as $step) {
        foreach (['a','b','c'] as $name) { file_put_contents("$root/ipsec/$name","old-$name"); chmod("$root/ipsec/$name",0600); }
        $b->renames=0; $b->failRename=$step;
        fsCheck(!$b->importIpsecPki(array_fill_keys(['a','b','c'],base64_encode('replacement'))),'Сбой переноса возвращает отказ');
        foreach (['a','b','c'] as $name) fsCheck(file_get_contents("$root/ipsec/$name")==="old-$name",'При сбое восстановлены ВСЕ прежние файлы');
        fsCheck(glob("$root/ipsec/.restore-*")===[],'Временные данные удалены');
    }
    $pair=backupPkiFixture();
    $ovpn=array_map('base64_encode',['pki/ca.crt'=>$pair['ca'],'pki/issued/server.crt'=>$pair['server'],'pki/private/server.key'=>$pair['key'],'server.conf'=>'fixture']);
    $b->failRename=0; $b->renames=0;
    fsCheck($b->importOvpnPki($ovpn,true),'Полный OpenVPN принимается');
    file_put_contents("$root/openvpn/old-client.key",'old-client');
    $before=[]; foreach (array_keys($ovpn) as $name) $before[$name]=file_get_contents("$root/openvpn/$name");
    $b->renames=0; $b->failRename=3;
    fsCheck(!$b->importOvpnPki(array_replace($ovpn,['server.conf'=>base64_encode('changed')]),true),'Ошибка переноса OpenVPN возвращает отказ');
    foreach ($before as $name=>$body) fsCheck(file_get_contents("$root/openvpn/$name")===$body,'OpenVPN откатил уже перенесённые файлы');
    fsCheck(file_get_contents("$root/openvpn/old-client.key")==='old-client','При отказе прежние клиенты не удаляются');
    $target="$root/atomic"; $trap=$target.'.'.getmypid().'.tmp';
    symlink("$root/outside/key",$trap);
    fsCheck($b->writePrivateKey($target,'secret'),'Атомарная запись работает');
    fsCheck(file_get_contents("$root/outside/key")==='untouched','Предсказуемый временный путь не позволяет перезаписать чужой файл');
    fsCheck((fileperms($target)&0777)===0600,'Секрет закрыт');
    $inode=fileinode($target);
    foreach (['longer than before','x',''] as $body) {
        fsCheck($b->inPlace($target,$body),'Запись bind-файла успешна'); clearstatcache();
        fsCheck(fileinode($target)===$inode && file_get_contents($target)===$body,'Bind inode и точное содержимое сохранены');
    }
    echo "backup_filesystem_test OK\n";
} finally { ini_set('error_log',$oldLog); fsRemove($root); }
