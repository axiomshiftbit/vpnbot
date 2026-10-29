<?php

// Проверка сайта-маски REALITY против НАСТОЯЩЕГО ядра. Три локальные маски:
// с ALPN, без ALPN и без ALPN, но с подтверждением SNI. Бот проверяет каждую
// своей командой (Bot::realityMaskCommand) и правилом ядра
// (realityAcksServerName); ядро должно принимать клиента ровно тогда, когда
// бот не предупреждает: Xray 26.10.17+ отвергает маску без ALPN и без
// подтверждения SNI (с 26.10.28 так же и форк), ядра до него и форк 26.10.13 принимают все три.
//
// Внешняя сеть не нужна. Нужны VLESS_TEST_XRAY (и/или XRAY_FORK_TEST_BINARY),
// pcntl и openssl.

require_once __DIR__ . '/../app/bot.php';

$binaries = array_values(array_filter([getenv('VLESS_TEST_XRAY'), getenv('XRAY_FORK_TEST_BINARY')]));
if (!$binaries) {
    echo "reality_mask_core_test SKIP: задайте VLESS_TEST_XRAY для проверки настоящим ядром\n";
    exit(0);
}
if (!function_exists('pcntl_fork')) {
    throw new RuntimeException('нужно расширение pcntl');
}
foreach ($binaries as $binary) {
    if (!is_executable($binary)) {
        throw new RuntimeException("не исполняемый файл ядра: $binary");
    }
}

class RealityMaskCoreBot extends Bot
{
    public array $probe = [];
    public function __construct() {}
    public function xrayCoreProbe(bool $fresh = false): array { return $this->probe; }
}

$work = sys_get_temp_dir() . '/vpnbot-reality-mask-' . bin2hex(random_bytes(6));
mkdir($work, 0700);
$children = [];
$pids = [];
$failures = [];
$freePort = static function (): int {
    $s = stream_socket_server('tcp://127.0.0.1:0');
    $port = (int) substr(strrchr(stream_socket_get_name($s, false), ':'), 1);
    fclose($s);
    return $port;
};
$waitPort = static function (int $port): bool {
    for ($i = 0; $i < 60; $i++) {
        if ($c = @fsockopen('127.0.0.1', $port, $e, $s, 0.2)) { fclose($c); return true; }
        usleep(100000);
    }
    return false;
};
$spawn = static function (array $command, string $log) use (&$children) {
    $p = proc_open($command, [0 => ['file', '/dev/null', 'r'], 1 => ['file', $log, 'w'], 2 => ['file', $log, 'a']], $pipes);
    $children[] = $p;
    return $p;
};
$stop = static function ($p): void {
    $status = proc_get_status($p);
    if ($status['running']) { proc_terminate($p, 15); usleep(150000); proc_terminate($p, 9); }
    proc_close($p);
};

try {
    $key = openssl_pkey_new(['private_key_bits' => 2048]);
    $cert = openssl_csr_sign(openssl_csr_new(['commonName' => 'mask.example.test'], $key), null, $key, 1);
    openssl_x509_export($cert, $public);
    openssl_pkey_export($key, $private);
    file_put_contents("$work/cert.pem", $public . $private);
    chmod("$work/cert.pem", 0600);

    // SNI_server_certs ставит обработчик SNI: OpenSSL тогда подтверждает имя
    // пустым расширением server_name — те самые 4 байта, которых не хватает.
    $masks = [
        'alpn'   => ['alpn_protocols' => 'h2,http/1.1'],
        'empty'  => [],
        'sniack' => ['SNI_server_certs' => ['mask.example.test' => "$work/cert.pem"]],
    ];
    $ports = [];
    foreach ($masks as $name => $options) {
        $ports[$name] = $freePort();
        $context = stream_context_create(['ssl' => ['local_cert' => "$work/cert.pem", 'verify_peer' => false] + $options]);
        $mask = stream_socket_server("tcp://127.0.0.1:{$ports[$name]}", $errno, $error, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context);
        $pid = pcntl_fork();
        if ($pid === 0) {
            try {
                while ($conn = @stream_socket_accept($mask, 600)) {
                    stream_set_timeout($conn, 3);
                    if (@stream_socket_enable_crypto($conn, true, STREAM_CRYPTO_METHOD_TLSv1_3_SERVER)) {
                        @fwrite($conn, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nMASK");
                    }
                    @fclose($conn);
                }
            } catch (Throwable $e) {
            }
            exit(0);
        }
        $pids[] = $pid;
        fclose($mask);
    }

    // Вердикт бота по каждой маске — той же командой, что идёт в контейнер xr.
    $verdicts = [];
    foreach ($ports as $name => $port) {
        $verdicts[$name] = Bot::realityMaskVerdict((string) shell_exec(Bot::realityMaskCommand("127.0.0.1:$port", 'mask.example.test')));
    }
    foreach (['alpn' => 'ok', 'empty' => 'short', 'sniack' => 'ok'] as $name => $status) {
        if ($verdicts[$name]['status'] !== $status) {
            $failures[] = "маска $name: бот ждал $status, получил " . json_encode($verdicts[$name]);
        }
    }

    foreach ($binaries as $binary) {
        $keys = []; $versionOut = [];
        exec(escapeshellarg($binary) . ' x25519 2>&1', $keys);
        $keys = implode("\n", $keys);
        if (!preg_match('~Private ?[Kk]ey:\s*(\S+)~', $keys, $priv) || !preg_match('~(?:Password \(PublicKey\)|Public ?[Kk]ey|Password):\s*(\S+)~', $keys, $pub)) {
            throw new RuntimeException('ядро не выдало пару ключей: ' . $keys);
        }
        exec(escapeshellarg($binary) . ' version 2>&1', $versionOut);
        $versionLine = (string) ($versionOut[0] ?? '');
        $version = preg_match('~Xray\s+v?([0-9.]+(?:-\d+)?)~', $versionLine, $vm) ? $vm[1] : '?';
        // Версию REALITY бот берёт из бинаря так же (xrayCoreProbe).
        $reality = preg_match('~github\.com/xtls/reality\s+(v[0-9A-Za-z.+_-]+)~', (string) file_get_contents($binary), $rm) ? $rm[1] : '';
        $bot = new RealityMaskCoreBot();
        $bot->probe = ['ok' => true, 'running' => '', 'active' => $binary === getenv('XRAY_FORK_TEST_BINARY') ? 'fork' : 'origin',
            'reality' => $reality, 'reality_local' => false, 'version' => $versionLine];
        $acks = $bot->realityAcksServerName();
        $uuid = '11111111-1111-4111-8111-111111111111';
        $seen = [];
        foreach ($ports as $name => $maskPort) {
            $serverPort = $freePort();
            file_put_contents("$work/server.json", json_encode(['log' => ['loglevel' => 'warning'], 'inbounds' => [[
                'listen' => '127.0.0.1', 'port' => $serverPort, 'protocol' => 'vless',
                'settings' => ['clients' => [['id' => $uuid, 'flow' => 'xtls-rprx-vision']], 'decryption' => 'none'],
                'streamSettings' => ['network' => 'tcp', 'security' => 'reality', 'realitySettings' => [
                    'dest' => "127.0.0.1:$maskPort", 'serverNames' => ['mask.example.test'], 'privateKey' => $priv[1], 'shortIds' => ['abcd1234']]],
            ]], 'outbounds' => [['protocol' => 'blackhole', 'settings' => ['response' => ['type' => 'http']]]]], JSON_UNESCAPED_SLASHES));
            $server = $spawn([$binary, 'run', '-config', "$work/server.json"], "$work/server.log");
            if (!$waitPort($serverPort)) {
                throw new RuntimeException('сервер REALITY не запустился: ' . substr((string) @file_get_contents("$work/server.log"), -300));
            }
            $socks = $freePort();
            file_put_contents("$work/client.json", json_encode(['log' => ['loglevel' => 'warning'],
                'inbounds' => [['listen' => '127.0.0.1', 'port' => $socks, 'protocol' => 'socks', 'settings' => ['udp' => false]]],
                'outbounds' => [['protocol' => 'vless', 'settings' => ['vnext' => [['address' => '127.0.0.1', 'port' => $serverPort,
                    'users' => [['id' => $uuid, 'flow' => 'xtls-rprx-vision', 'encryption' => 'none']]]]],
                    'streamSettings' => ['network' => 'tcp', 'security' => 'reality', 'realitySettings' => [
                        'serverName' => 'mask.example.test', 'fingerprint' => 'chrome', 'publicKey' => $pub[1], 'shortId' => 'abcd1234']]]],
            ], JSON_UNESCAPED_SLASHES));
            $client = $spawn([$binary, 'run', '-config', "$work/client.json"], "$work/client.log");
            $ok = false;
            if ($waitPort($socks)) {
                for ($try = 0; $try < 2 && !$ok; $try++) {
                    $ch = curl_init('http://through-reality.example.test/');
                    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_PROXY => "socks5h://127.0.0.1:$socks", CURLOPT_TIMEOUT => 4, CURLOPT_CONNECTTIMEOUT => 3]);
                    curl_exec($ch);
                    $ok = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE) === 403;
                }
            }
            $stop($client);
            $stop($server);
            $seen[$name] = $ok;
            $expected = $verdicts[$name]['status'] === 'ok' || !$acks;
            if ($ok !== $expected) {
                $failures[] = "ядро $version (REALITY $reality): маска $name " . ($ok ? 'принята' : 'отвергнута')
                    . ', а бот ожидал ' . ($expected ? 'приёма' : 'отказа');
            }
        }
        echo "ядро $version" . ($acks ? ' (подтверждает SNI)' : '') . ': '
            . implode(', ', array_map(static fn($n, $ok) => "$n " . ($ok ? 'принята' : 'отвергнута'), array_keys($seen), $seen)) . "\n";
    }
} finally {
    foreach ($children as $p) {
        if (is_resource($p)) { @proc_terminate($p, 9); }
    }
    foreach ($pids as $pid) {
        exec('kill ' . (int) $pid . ' 2>/dev/null');
        pcntl_waitpid($pid, $status);
    }
    foreach (glob("$work/*") ?: [] as $file) unlink($file);
    @rmdir($work);
}

foreach ($failures as $failure) echo "FAIL: $failure\n";
if ($failures) exit(1);
echo "reality_mask_core_test OK\n";
