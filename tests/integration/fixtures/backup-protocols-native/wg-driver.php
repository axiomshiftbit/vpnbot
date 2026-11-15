<?php
// Только выделенный native-контейнер. SSH заменён локальным запуском тех же
// wg/awg-quick; конфигурация, peer table и туннельный payload — настоящие.
if (getenv('VPNBOT_NATIVE_BACKUP_FIXTURE') !== 'isolated') exit(2);
require '/source/app/bot.php'; require '/source/app/i18n.php';
umask(0077);
class NativeBackupWireguard extends Bot {
    public array $messages = [];
    public function __construct(array $strings) {
        $this->i18n = $strings; $this->language = 'ru'; $this->wg = 0; $this->ip = '192.0.2.1';
        $this->input = ['chat' => 1, 'message_id' => 1, 'callback_id' => 'synthetic'];
        $this->transport = new class($this) {
            public function __construct(private NativeBackupWireguard $bot) {}
            public function call($method, $data, $json = 0) { if (isset($data['text'])) $this->bot->messages[] = $data['text']; return ['ok'=>true,'result'=>['message_id'=>1]]; }
        };
    }
    public function getPorts() { return ['wg'=>['port'=>51820],'wg1'=>['port'=>51821]]; }
    public function cloakNginx() { return true; } // В этом стенде нет Nginx/других протоколов.
    public function iptablesWG() { $this->sshFailed = false; } // Без forwarding: payload адресован самому WG-серверу.
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') {
        if ($service !== 'wg') throw new RuntimeException('unexpected service');
        $cmd = preg_replace('~\b(a?wg)-quick\b~', '/tmp/$1-quick', $cmd);
        $p = proc_open(['/bin/sh','-c',$cmd], [0=>['file','/dev/null','r'],1=>['pipe','w'],2=>['file','/dev/null','w']], $pipes);
        if (!is_resource($p)) throw new RuntimeException('native process unavailable');
        $body=stream_get_contents($pipes[1]);fclose($pipes[1]);$this->sshFailed=proc_close($p)!==0;return $body;
    }
}
$b=new NativeBackupWireguard($i);$checks=[];
$check=static function($ok,$name)use(&$checks){$checks[$name]=(bool)$ok;if(!$ok)throw new RuntimeException('native assertion');};
$key=static function()use($b){$private=trim($b->ssh('wg genkey'));$p=proc_open(['wg','pubkey'],[0=>['pipe','r'],1=>['pipe','w'],2=>['file','/dev/null','w']],$pipes);fwrite($pipes[0],$private);fclose($pipes[0]);$public=trim(stream_get_contents($pipes[1]));fclose($pipes[1]);if(proc_close($p)!==0)throw new RuntimeException('keygen');return [$private,$public];};
try {
    switch($argv[1]??'') {
        case 'init':
            $mode=$argv[2]??'wg';$b->setPacConf(['language'=>'ru','limitpage'=>5,'amnezia'=>(int)($mode==='awg')]);
            file_put_contents('/config/clients1.json','[]');[$sp,$su]=$key();[$cp,$cu]=$key();
            $server=['interface'=>['PrivateKey'=>$sp,'Address'=>'10.77.0.1/24','ListenPort'=>51820],'peers'=>[['PublicKey'=>$cu,'AllowedIPs'=>'10.77.0.2/32']]];
            $client=['interface'=>['PrivateKey'=>$cp,'Address'=>'10.77.0.2/24','Table'=>'off'],'peers'=>[['PublicKey'=>$su,'AllowedIPs'=>'10.77.0.1/32','Endpoint'=>'VPNBOT_SERVER:51820','PersistentKeepalive'=>1]]];
            file_put_contents('/config/clients.json',json_encode([$client]));
            file_put_contents('/config/client.conf',$b->createConfig($client));
            $check($b->restartWG($b->createConfig($server)),'initial_native_server');
            $method=new ReflectionMethod(Bot::class,'backupWireGuard');
            file_put_contents('/config/backup.json',json_encode(['wg'=>$method->invoke($b,0)],JSON_THROW_ON_ERROR));
            $check(is_file('/config/wg0.conf'),'bind_config_present');
            $backend=$mode==='wg'?'kernel':(is_file('/run/amneziawg/wg0.sock')||file_exists('/run/amneziawg/wg0.sock')?'amneziawg-go':'kernel');
            break;
        case 'fresh':
            [$sp]=$key();$server=['interface'=>['PrivateKey'=>$sp,'Address'=>'10.77.0.1/24','ListenPort'=>51820],'peers'=>[]];
            $check($b->restartWG($b->createConfig($server)),'fresh_native_identity');
            unlink('/config/clients.json');
            $check(!is_file('/config/clients.json'),'fresh_client_store_absent');
            break;
        case 'restore':
        case 'restore-failure':
            $expected=($argv[1]==='restore');$accepted=$b->importCliFile('/config/backup.json');
            $complete=(bool)array_filter($b->messages,fn($message)=>str_contains($message,$b->i18n('backup restore completed')));
            $check($accepted===$expected,'import_result');$check($complete===$expected,'no_false_global_success');
            if($expected){$copy=json_decode(file_get_contents('/config/backup.json'),true);$check(count($b->readClients())===count($copy['wg']['clients']),'old_clients_restored');}
            break;
        default:throw new RuntimeException('unknown action');
    }
    echo json_encode(['ok'=>true,'checks'=>$checks,'backend'=>$backend??null]),"\n";
} catch(Throwable $e) { echo json_encode(['ok'=>false,'checks'=>$checks,'error_type'=>get_class($e),'line'=>$e->getLine()]),"\n";exit(1); }
