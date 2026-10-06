<?php

require_once __DIR__ . '/../app/bot.php';

// Ошибка парсера ядра должна сохранять и процесс, и рабочий файл.
class RestartValidationBot extends Bot
{
    public bool $valid = false;
    public bool $routesValid = true;
    public int $collections = 0;
    public array $commands = [];
    public array $checked = [];
    public function __construct() {}
    public function getPacConf() { return self::PAC_DEFAULTS; }
    public function warpSocksIp(): string { return '10.10.0.13/32'; }
    public function validateXrayConfig(array $config, string $binary = 'xray'): bool
    {
        $this->checked = $config;
        return $this->valid;
    }
    public function collectSession() { $this->collections++; }
    public function syncXrayNginxRoutes(array $config): bool { return $this->routesValid; }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
    {
        $this->commands[] = $cmd;
        return '';
    }
}

$bot = new RestartValidationBot();
$bot->xrayConf = tempnam(sys_get_temp_dir(), 'xray-restart-');
$config = ['inbounds' => [['tag' => 'vless', 'protocol' => 'vless',
    'settings' => ['clients' => [], 'decryption' => 'none']]],
    'outbounds' => [['tag' => 'direct', 'protocol' => 'freedom']],
    'routing' => ['rules' => []]];
try {
    file_put_contents($bot->xrayConf, '{"previous":true}');
    if ($bot->restartXray($config) !== false || $bot->commands || $bot->collections
        || file_get_contents($bot->xrayConf) !== '{"previous":true}') {
        throw new RuntimeException('Отклонённый конфиг изменил рабочее состояние');
    }
    if (!($bot->checked['stats'] instanceof stdClass)
        || !($bot->checked['policy']['levels'] instanceof stdClass)) {
        throw new RuntimeException('Проверяется не окончательный формат конфигурации');
    }
    $bot->valid = true;
    $bot->routesValid = false;
    if ($bot->restartXray($config) !== false || $bot->commands || $bot->collections
        || file_get_contents($bot->xrayConf) !== '{"previous":true}') {
        throw new RuntimeException('Отказ NGINX изменил конфиг или остановил Xray');
    }
    $bot->routesValid = true;
    if (!$bot->restartXray($config) || $bot->collections !== 1 || count($bot->commands) !== 2
        || file_get_contents($bot->xrayConf) === '{"previous":true}') {
        throw new RuntimeException('Корректный конфиг не применён');
    }
} finally {
    unlink($bot->xrayConf);
}
echo "xray_restart_validation_test OK\n";
