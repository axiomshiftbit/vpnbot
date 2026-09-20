<?php

// Проверяем shell-команды createPeer(), а не заранее готовые ответы ssh().
// `K=value printf '%s' "$K"` раскрывает старое значение K и передавало в
// wg pubkey пустую строку: на настоящем VPS ни один пир не создавался.
require_once __DIR__ . '/../app/bot.php';

class WgKeyShellBot extends Bot
{
    public string $fixture;
    public array $client = [];
    public string $server = '';
    public array $commands = [];
    public function getPacConf() { return self::PAC_DEFAULTS; }
    public function setPacConf(array $conf) { return true; }
    public function readConfig() {
        return ['interface'=>['Address'=>'10.0.1.1/24', 'PrivateKey'=>'server-test-key'], 'peers'=>[]];
    }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') {
        $this->commands[] = $cmd;
        $cmd = str_replace('/etc/wireguard/wg0.conf', escapeshellarg($this->fixture . '/wg0.conf'), $cmd);
        $proc = proc_open(['/bin/sh', '-c', $cmd], [0=>['pipe','r'], 1=>['pipe','w'], 2=>['pipe','w']], $pipes,
            null, ['PATH'=>$this->fixture . ':/usr/bin:/bin']);
        fclose($pipes[0]);
        $out = stream_get_contents($pipes[1]);
        stream_get_contents($pipes[2]);
        fclose($pipes[1]); fclose($pipes[2]);
        proc_close($proc);
        return $out;
    }
    public function saveClient(array $client) { $this->client = $client; return 0; }
    public function createConfig($data) { return json_encode($data); }
    public function restartWG($conf, $norestart = false) { $this->server = $conf; return true; }
    public function menu($type = false, $arg = false, $return = false) {}
    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false) {}
}

$dir = sys_get_temp_dir() . '/wg-key-shell-' . bin2hex(random_bytes(6));
mkdir($dir, 0700);
file_put_contents($dir . '/wg0.conf', "[Interface]\nPrivateKey = server-test-key\n");
file_put_contents($dir . '/wg', <<<'SH'
#!/bin/sh
case "$1" in
    genkey) printf '%s\n' peer-test-key ;;
    pubkey)
        case "$(cat)" in
            server-test-key) printf '%s\n' server-test-public ;;
            peer-test-key) printf '%s\n' peer-test-public ;;
            *) exit 1 ;;
        esac ;;
    *) exit 1 ;;
esac
SH);
chmod($dir . '/wg', 0700);
try {
    $bot = (new ReflectionClass(WgKeyShellBot::class))->newInstanceWithoutConstructor();
    $bot->fixture = $dir;
    $bot->createPeer(false, 'audit', 0);
    $server = json_decode($bot->server, true);
    if (($bot->client['interface']['PrivateKey'] ?? '') !== 'peer-test-key'
        || ($bot->client['peers'][0]['PublicKey'] ?? '') !== 'server-test-public'
        || ($server['peers'][0]['PublicKey'] ?? '') !== 'peer-test-public') {
        throw new RuntimeException('createPeer: shell не передал ключи в stdin pubkey');
    }
    foreach ($bot->commands as $cmd) {
        if (str_contains($cmd, 'server-test-key') || str_contains($cmd, 'peer-test-key')) {
            throw new RuntimeException('приватный ключ не должен попадать в аргумент SSH-команды');
        }
    }
    echo "wg_key_generation_test OK\n";
} finally {
    unlink($dir . '/wg'); unlink($dir . '/wg0.conf'); rmdir($dir);
}
