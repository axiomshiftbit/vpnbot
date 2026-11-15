<?php
// Native wg/awg-quick + actual kernel/userspace peer table. SSH transport is
// replaced only by local process execution in this dedicated network namespace.
require getenv('VPNBOT_TEST_SOURCE') . '/app/bot.php';
class NativeWgApply extends Bot {
    public bool $fault = false;
    public bool $amnezia;
    public function __construct(bool $amnezia) {
        $this->amnezia = $amnezia; $this->wg = 0; $this->clients = '/config/clients.json'; $this->clients1 = '/config/clients1.json';
        $this->language = 'ru'; $this->input = ['chat' => 1, 'message_id' => 1, 'callback_id' => 'synthetic'];
    }
    public function getPacConf() { return array_replace(self::PAC_DEFAULTS, ['wg_instance' => 0, 'amnezia' => $this->amnezia]); }
    public function getPorts() { return ['wg' => ['port' => 51820]]; }
    public function menu($type = false, $arg = false, $return = false) {}
    public function wgConfUnavailable(string $why): void {}
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') {
        if ($service !== 'wg') { $this->sshFailed = true; return ''; }
        if ($this->fault && str_contains($cmd, 'base64 -d >')) { $this->sshFailed = true; return ''; }
        $cmd = preg_replace('~\\b(a?wg)-quick\\b~', '/audit-bin/bash /audit-bin/$1-quick', $cmd);
        return $this->execSynthetic(['/bin/sh', '-c', $cmd]);
    }
    public function execSynthetic(array $argv, string $input = ''): string {
        $p = proc_open($argv, [0 => ['pipe','r'], 1 => ['pipe','w'], 2 => ['file','/dev/null','w']], $pipes);
        if (!is_resource($p)) throw new RuntimeException('native command unavailable');
        fwrite($pipes[0], $input); fclose($pipes[0]); $out = stream_get_contents($pipes[1]); fclose($pipes[1]);
        $this->sshFailed = proc_close($p) !== 0;
        return $out;
    }
    public function peers(): array {
        $out = $this->execSynthetic([$this->getWGType(), 'show', 'wg0', 'peers']);
        if ($this->sshFailed) throw new RuntimeException('native peer query failed');
        return preg_split('~\s+~', trim($out), -1, PREG_SPLIT_NO_EMPTY);
    }
}
$failed = false; $mode = $argv[1] ?? 'wg'; $b = new NativeWgApply($mode === 'awg'); $checks = [];
$assert = static function(bool $ok, string $label) use (&$checks) { $checks[$label] = $ok; };
$seed = static function() use($b) {
    foreach (glob('/config/*') as $p) @unlink($p);
    $b->fault = false;
    $keys = [];
    for ($i=0; $i<3; $i++) {
        $private = trim($b->execSynthetic(['wg','genkey']));
        $public = trim($b->execSynthetic(['wg','pubkey'], $private));
        if ($b->sshFailed || strlen($public) !== 44) throw new RuntimeException('synthetic key generation failed');
        $keys[] = [$private,$public];
    }
    $clients = [];
    for ($i=1; $i<=2; $i++) $clients[] = ['interface' => ['PrivateKey'=>$keys[$i][0], 'Address'=>'10.77.0.'.($i+1).'/32'] + ($i===1 ? ['## time'=>'2000-01-01'] : []), 'peers'=>[['PublicKey'=>$keys[0][1]]]];
    $config = $b->createConfig(['interface'=>['PrivateKey'=>$keys[0][0],'Address'=>'10.77.0.1/24','ListenPort'=>51820], 'peers'=>[
        ['PublicKey'=>$keys[1][1],'AllowedIPs'=>'10.77.0.2/32'], ['PublicKey'=>$keys[2][1],'AllowedIPs'=>'10.77.0.3/32']]]);
    file_put_contents('/config/clients.json', json_encode($clients)); file_put_contents('/config/clients1.json','[]');
    if (!$b->restartWG($config)) throw new RuntimeException('native setup failed');
    return [$keys[1][1],$keys[2][1]];
};
try {
    [$a,$other]=$seed(); $assert(count($b->peers())===2,'healthy_two_peer_control');
    $b->fault=true; $b->shutdownClient();
    $assert(empty($b->readClients()[0]['# off']) && isset($b->readClients()[0]['interface']['## time']),'failed_expiry_not_published');
    $assert(in_array($a,$b->peers(),true),'failure_injection_keeps_real_peer');
    $b->fault=false; $b->shutdownClient();
    $assert(!in_array($a,$b->peers(),true) && in_array($other,$b->peers(),true) && !empty($b->readClients()[0]['# off']),'retry_revokes_real_peer_only');
    [$a,$other]=$seed(); $b->fault=true; $b->deletePeer(0,0,false);
    $assert(count($b->readClients())===2 && in_array($a,$b->peers(),true),'failed_delete_keeps_identity');
    $b->fault=false; $b->shutdownClient();
    $assert(count($b->readClients())===1 && !in_array($a,$b->peers(),true) && in_array($other,$b->peers(),true),'delete_retry_revokes_real_peer_only');
    $failed = in_array(false,$checks,true);
    echo json_encode(['mode'=>$mode,'checks'=>$checks,'status'=>$failed?'FAIL':'PASS','transport'=>'local-exec-original-commands','backend'=>$mode==='wg'?'kernel':(file_exists('/run/amneziawg/wg0.sock')?'amneziawg-go':'kernel')]), "\n";
} catch(Throwable $e) { echo json_encode(['mode'=>$mode,'status'=>'ERROR','exception'=>get_class($e),'line'=>$e->getLine(),'checks'=>$checks]), "\n"; exit(2);
} finally { $b->fault=false; $b->ssh($b->getWGType().'-quick down wg0 >/dev/null 2>&1'); }

exit($failed ? 1 : 0);
