<?php

// Выполняем реальную shell-пробу на бинарных fixtures, включая смену ядра.
require_once __DIR__ . '/../app/bot.php';

class BuildInfoTestBot extends Bot
{
    public string $binary;
    public string $binDir;
    public function __construct() {}
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
    {
        $this->sshFailed = false;
        $cmd = 'PATH=' . escapeshellarg($this->binDir . ':' . getenv('PATH')) . '; '
            . str_replace('/usr/local/bin/xray', escapeshellarg($this->binary), $cmd);
        $process = proc_open(['/bin/sh', '-c', $cmd], [0 => ['file', '/dev/null', 'r'],
            1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
        $output = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        if (proc_close($process) !== 0) { throw new RuntimeException('Проба завершилась с ошибкой'); }
        return $output;
    }
}

$root = sys_get_temp_dir() . '/vpnbot-build-info-' . bin2hex(random_bytes(6));
mkdir($root, 0700);
$bot = new BuildInfoTestBot();
$bot->binary = $root . '/binary with spaces';
$bot->binDir = $root;
file_put_contents($root . '/xray', "#!/bin/sh\nprintf '%s\n' 'Xray 26.9.9 (fixture)'\n");
chmod($root . '/xray', 0700);
try {
    // NUL, непечатные байты, длинная строка и похожий, но неверный путь модуля.
    $prefix = str_repeat("\0\xffbinary\x01", 131072)
        . "\ngithubXcom/xtls/reality\tv9.9.9\n";
    $versions = ['v0.0.0-20260322125925-9234c772ba8f', 'v0.0.0-20260908062103-8cdf7bf9c7f0'];
    foreach ($versions as $version) {
        file_put_contents($bot->binary, $prefix . "dep\tgithub.com/xtls/reality\t$version\th1:fixture\n"
            . "dep\tgithub.com/xtls/reality\tv0.0.0-20000101000000-fixture\n");
        $probe = $bot->xrayCoreProbe(true);
        if ($probe['reality'] !== $version || $probe['version'] !== 'Xray 26.9.9 (fixture)') {
            throw new RuntimeException('Неверная версия REALITY после замены бинарника: '
                . json_encode(['version' => $probe['version'], 'reality' => $probe['reality']]));
        }
    }
    file_put_contents($bot->binary, $prefix);
    if ($bot->xrayCoreProbe(true)['reality'] !== '') {
        throw new RuntimeException('Старое значение REALITY осталось после смены бинарника');
    }
    unlink($bot->binary);
    if ($bot->xrayCoreProbe(true)['reality'] !== '') {
        throw new RuntimeException('Несуществующий бинарник получил версию REALITY');
    }
    echo "xray_build_info_test OK (binary input, first match, replacement, missing dependency/file)\n";
} finally {
    foreach (glob($root . '/*') as $file) { unlink($file); }
    rmdir($root);
}
