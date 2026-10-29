<?php

require_once __DIR__ . '/../app/bot.php';

// Реальное ядро: конфигурация через stdin и stats:{} после
// json_decode(..., true). В CI бинарник проверяется по SHA256.
$binary = getenv('VLESS_TEST_XRAY');
if (!$binary) {
    echo "vless_encryption_check_test SKIP: задайте VLESS_TEST_XRAY для проверки ядром\n";
    exit(0);
}
if (!is_executable($binary)) throw new RuntimeException('Нужен исполняемый Xray');

class VlessCheckTestBot extends Bot
{
    public int $checks = 0;
    public function __construct() {}
    protected function sshInputCommand(string $cmd, string $input, string $service): string
    {
        $this->sshFailed = false;
        if (!str_contains($cmd, '-config stdin:') || str_contains($cmd, '11111111-2222')
            || str_contains($cmd, '.xray-check-')) throw new RuntimeException('Конфиг должен идти только в stdin');
        $this->checks++;
        $process = proc_open(['/bin/sh', '-c', $cmd], [0 => ['pipe', 'r'],
            1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
        fwrite($pipes[0], $input);
        // stdin остаётся открытым: ограниченный head должен сам завершить
        // поток для Xray, не ожидая EOF всего SSH-канала.
        stream_set_timeout($pipes[1], 10);
        $output = stream_get_contents($pipes[1]);
        fclose($pipes[0]); fclose($pipes[1]);
        proc_close($process);
        return $output;
    }
}

$bot = new VlessCheckTestBot();
$config = ['inbounds' => [['protocol' => 'vless', 'listen' => '127.0.0.1', 'port' => 24443,
    'settings' => ['decryption' => 'none', 'clients' => [['id' => '11111111-2222-4333-8444-555555555555']]]]],
    'outbounds' => [['protocol' => 'freedom']], 'stats' => [], 'policy' => ['levels' => []]];
if (!$bot->validateXrayConfig($config, $binary)) {
    throw new RuntimeException('Ядро отклонило корректный конфиг после чтения JSON');
}
$config['policy']['levels'] = [0 => ['statsUserUplink' => true]];
if (!$bot->validateXrayConfig($config, $binary)) {
    throw new RuntimeException('Числовой уровень политики превратился в JSON-массив');
}
$config['inbounds'][0]['streamSettings']['network'] = 'invalid-network';
if ($bot->validateXrayConfig($config, $binary)) {
    throw new RuntimeException('Невалидный конфиг принят');
}
echo "vless_encryption_check_test OK ({$bot->checks} проверки реальным ядром)\n";
