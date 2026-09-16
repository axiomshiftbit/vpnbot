<?php

require_once __DIR__ . '/../app/bot.php';

// Реальное ядро: регрессии формата временного файла и stats:{} после
// json_decode(..., true). В CI бинарник проверяется по SHA256.
$binary = getenv('VLESS_TEST_XRAY');
if (!$binary) {
    echo "vless_encryption_check_test SKIP: задайте VLESS_TEST_XRAY для проверки ядром\n";
    exit(0);
}
if (!is_executable($binary) || !is_writable('/logs')) {
    throw new RuntimeException('Нужны исполняемый Xray и доступный /logs');
}

class VlessCheckTestBot extends Bot
{
    public int $checks = 0;
    public array $temporaryFiles = [];
    public function __construct() {}
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
    {
        $this->sshFailed = false;
        if (!preg_match("/-config '([^']+)'/", $cmd, $m)) {
            throw new RuntimeException('Нет проверяемого конфига');
        }
        if ((fileperms($m[1]) & 0777) !== 0600) {
            throw new RuntimeException('Временный конфиг доступен посторонним');
        }
        $this->temporaryFiles[] = $m[1];
        $this->checks++;
        $process = proc_open(['/bin/sh', '-c', $cmd], [0 => ['file', '/dev/null', 'r'],
            1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
        $output = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        proc_close($process);
        return $output;
    }
}

$bot = new VlessCheckTestBot();
$config = ['inbounds' => [['protocol' => 'vless', 'listen' => '127.0.0.1', 'port' => 24443,
    'settings' => ['decryption' => 'none', 'clients' => [['id' => '11111111-2222-4333-8444-555555555555']]]]],
    'outbounds' => [['protocol' => 'freedom']], 'stats' => [], 'policy' => ['levels' => []]];
if (!$bot->validateVlessEncryptionConfig($config, $binary)) {
    throw new RuntimeException('Ядро отклонило корректный конфиг после чтения JSON');
}
$config['policy']['levels'] = [0 => ['statsUserUplink' => true]];
if (!$bot->validateVlessEncryptionConfig($config, $binary)) {
    throw new RuntimeException('Числовой уровень политики превратился в JSON-массив');
}
$config['inbounds'][0]['streamSettings']['network'] = 'invalid-network';
if ($bot->validateVlessEncryptionConfig($config, $binary)) {
    throw new RuntimeException('Невалидный конфиг принят');
}
foreach ($bot->temporaryFiles as $file) {
    if (file_exists($file)) { throw new RuntimeException('Временный конфиг не удалён'); }
}
echo "vless_encryption_check_test OK ({$bot->checks} проверки реальным ядром)\n";
