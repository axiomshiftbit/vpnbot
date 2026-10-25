<?php
$root=sys_get_temp_dir().'/vpnbot-preflight-'.bin2hex(random_bytes(6)); mkdir($root,0700);
mkdir("$root/app",0700); mkdir("$root/config",0700); mkdir("$root/logs",0700);
foreach (glob(__DIR__.'/../app/*.php') as $source) {
    if (in_array(basename($source),['config.php','debug.php'],true)) continue;
    $body=str_replace(['/config/','/logs/'],["$root/config/","$root/logs/"],file_get_contents($source));
    file_put_contents("$root/app/".basename($source),$body);
}
require "$root/app/bot.php";
require_once __DIR__.'/backup_pki_fixture.php';
require __DIR__ . '/../app/i18n.php';
class BackupPreflightBot extends Bot {
    public array $messages = [];
    public int $writes = 0;
    public function __construct(public string $root, array $translations) {
        $this->pac="$root/pac.json"; $this->update="$root/backup.json";
        $this->protocolModulesFile="$root/modules.json"; $this->protocolCertRoot=$root;
        $this->input=['chat'=>1,'message_id'=>1]; $this->i18n=$translations; $this->language='ru';
        parent::setPacConf(['domain'=>'before.example','language'=>'ru','limitpage'=>5]);
    }
    public function setPacConf(array $conf) { $this->writes++; return parent::setPacConf($conf); }
    public function ovpnPaths() { return ['pki'=>"$this->root/openvpn/pki"]; }
    public function ipsecPaths() { return ['conf'=>"$this->root/ipsec"]; }
    public function restartNaive() { return true; }
    public function pacUpdate($import='') {}
    public function dnsttStart() { return true; }
    public function setUpstreamDomainOcserv($domain) {}
    public function setUpstreamDomainNaive($domain) {}
    public function cloakNginx() { return true; }
    public function update($chat,$message_id,$text,$button=false,$reply=false,$mode='HTML') { $this->messages[]=$text; }
    public function send($chat,$text,?int $to=0,$button=false,$reply=false,$mode='HTML',$disable_notification=false) { $this->messages[]=$text; }
}
$oldLog=ini_set('error_log',"$root/errors.log"); $failed=[];
try {
    $pair=backupPkiFixture();
    $pki=['pki/ca.crt'=>$pair['ca'],'pki/issued/server.crt'=>$pair['server'],'pki/private/server.key'=>$pair['key'],'server.conf'=>'fixture'];
    $cases=[
        'oc type'=>['oc'=>['invalid']], 'ocu type'=>['oc'=>'tcp-port = 443','ocu'=>['invalid']],
        'ovpn incomplete'=>['ovpn'=>['pki/ca.crt'=>base64_encode('incomplete')]],
        'ipsec base64'=>['ipsec'=>['psk'=>'%%%']],
        'dnstt pair'=>['dnstt'=>['private'=>'incomplete']],
        'wg interface'=>['wg'=>['server'=>['interface'=>'invalid'],'clients'=>[]]],
        'wg clients'=>['wg'=>['server'=>[],'clients'=>'invalid']],
        'null pac'=>['pac'=>null], 'false hwid'=>['hwid'=>false],
        'ovpn wrong key'=>['ovpn'=>array_map('base64_encode',array_replace($pki,['pki/private/server.key'=>$pair['ca_key']]))],
        'ovpn invalid certificate'=>['ovpn'=>array_map('base64_encode',array_replace($pki,['pki/issued/alice.crt'=>'corrupted PEM']))],
        'ipsec wrong key'=>['ipsec'=>array_map('base64_encode',['pki/ca.crt'=>$pair['ca'],'pki/server.crt'=>$pair['server'],'pki/server.key'=>$pair['ca_key']])],
        'ssl broken chain'=>['ssl'=>['private'=>$pair['key'], 'public'=>$pair['server']."\n-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n"]],
        'ssl truncated chain'=>['ssl'=>['private'=>$pair['key'], 'public'=>$pair['server']."\n-----BEGIN CERTIFICATE-----\ntruncated\n"]],
    ];
    foreach ($cases as $name=>$case) {
        $b=new BackupPreflightBot($root,$i);
        $before=file_get_contents($b->pac);
        file_put_contents($b->update,json_encode($case+['pac'=>['domain'=>'after.example','language'=>'ru','limitpage'=>5]]));
        $result=$b->importFile($b->update);
        if ($result!==false || $b->writes!==0 || file_get_contents($b->pac)!==$before) $failed[]=$name;
    }
    $b->validateBackup(['ssl'=>['private'=>$pair['key'], 'public'=>$pair['server'].$pair['ca']]]);
    if ($failed) throw new RuntimeException('Повреждённые секции изменили настройки: '.implode(', ',$failed));
    echo "backup_preflight_test OK\n";
} finally { ini_set('error_log',$oldLog); (new BotCleanup)->remove($root); }
class BotCleanup {
    public function remove(string $path): void {
        if (is_dir($path) && !is_link($path)) { foreach (scandir($path) as $n) if ($n!=='.' && $n!=='..') $this->remove("$path/$n"); rmdir($path); }
        else unlink($path);
    }
}
