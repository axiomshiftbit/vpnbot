<?php

// Отпечатки REALITY на НАСТОЯЩЕМ ядре Xray.
//
// Какие ClientHello примет сервер REALITY, решает библиотека ядра, и это
// менялось: с выпуска 26.9.8 сервер отвергает приветствие без X25519MLKEM768,
// и клиенты с отпечатками ios, edge и qq перестали подключаться — без единой
// ошибки на сервере, клиент просто получает настоящий сайт-маску. Бот
// раздаёт в профилях только Bot::REALITY_FINGERPRINTS; здесь каждый из них
// проходит настоящее рукопожатие. Если очередное обновление ядра перестанет
// принимать один из них, это покажет сборка, а не жалобы пользователей.
//
// Внешняя сеть не нужна: сайт-маска — локальный сервер TLS 1.3.

require_once __DIR__ . '/../app/bot.php';

// Основное ядро и форк: у них разные версии библиотеки REALITY.
$binaries = array_values(array_filter([getenv('VLESS_TEST_XRAY'), getenv('XRAY_FORK_TEST_BINARY')]));
if (!$binaries) {
    echo "reality_fingerprint_core_test SKIP: задайте VLESS_TEST_XRAY для проверки настоящим ядром\n";
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

$work = sys_get_temp_dir() . '/vpnbot-reality-fp-' . bin2hex(random_bytes(6));
mkdir($work, 0700);
$children = [];
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
    // Сайт-маска: TLS 1.3 с самоподписанным сертификатом (REALITY его не сверяет,
    // ему нужен только настоящий ответ сервера на приветствие клиента).
    $key = openssl_pkey_new(['private_key_bits' => 2048]);
    $cert = openssl_csr_sign(openssl_csr_new(['commonName' => 'mask.example.test'], $key), null, $key, 1);
    openssl_x509_export($cert, $public);
    openssl_pkey_export($key, $private);
    file_put_contents("$work/cert.pem", $public . $private);
    chmod("$work/cert.pem", 0600);
    $maskPort = $freePort();
    $context = stream_context_create(['ssl' => ['local_cert' => "$work/cert.pem", 'verify_peer' => false]]);
    $mask = stream_socket_server("tcp://127.0.0.1:$maskPort", $errno, $error, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context);
    $maskPid = pcntl_fork();
    if ($maskPid === 0) {
        // Дочерний процесс выходит только через exit: исключение ушло бы в
        // общий finally и стёрло рабочий каталог у родителя.
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
    fclose($mask);

  foreach ($binaries as $binary) {
    $keys = []; $versionOut = [];
    exec(escapeshellarg($binary) . ' x25519 2>&1', $keys);
    $keys = implode("\n", $keys);
    if (!preg_match('~Private ?[Kk]ey:\s*(\S+)~', $keys, $priv) || !preg_match('~(?:Password \(PublicKey\)|Public ?[Kk]ey|Password):\s*(\S+)~', $keys, $pub)) {
        throw new RuntimeException('ядро не выдало пару ключей: ' . $keys);
    }
    exec(escapeshellarg($binary) . ' version 2>&1', $versionOut);
    $version = preg_match('~Xray\s+v?([0-9.]+)~', (string) ($versionOut[0] ?? ''), $vm) ? $vm[1] : '?';
    $uuid = '11111111-1111-4111-8111-111111111111';
    // Форк 26.10.13+ проходит ещё раз с requireMlkem: флаг ставит сам бот.
    $fork = $binary === getenv('XRAY_FORK_TEST_BINARY');
    $modes = $fork && version_compare($version, Bot::REALITY_REQUIRE_MLKEM_FORK_MIN, '>=') ? [false, true] : [false];
  foreach ($modes as $requireMlkem) {
    $reality = ['dest' => "127.0.0.1:$maskPort", 'serverNames' => ['mask.example.test'], 'privateKey' => $priv[1], 'shortIds' => ['abcd1234']];
    $policy = (new ReflectionClass(Bot::class))->newInstanceWithoutConstructor();
    $policy->ensureRealityRequireMlkem($reality, ['xray_core' => $fork ? 'fork' : 'origin', 'reality' => ['requireMlkem' => $requireMlkem ? 1 : 0]]);
    if ($requireMlkem !== isset($reality['requireMlkem'])) {
        throw new RuntimeException('бот не поставил requireMlkem так, как ожидалось');
    }
    $serverPort = $freePort();
    file_put_contents("$work/server.json", json_encode(['log' => ['loglevel' => 'warning'], 'inbounds' => [[
        'listen' => '127.0.0.1', 'port' => $serverPort, 'protocol' => 'vless',
        'settings' => ['clients' => [['id' => $uuid, 'flow' => 'xtls-rprx-vision']], 'decryption' => 'none'],
        'streamSettings' => ['network' => 'tcp', 'security' => 'reality', 'realitySettings' => $reality],
        // Выход — заглушка с HTTP-ответом: запрос, дошедший до неё, получает
        // «403» по туннелю. Настоящая цель не нужна (и выход freedom ядра к
        // адресам самой машины не пускает), а ответ возможен только после
        // рукопожатия, которое сервер признал своим.
    ]], 'outbounds' => [['protocol' => 'blackhole', 'settings' => ['response' => ['type' => 'http']]]]], JSON_UNESCAPED_SLASHES));
    $server = $spawn([$binary, 'run', '-config', "$work/server.json"], "$work/server.log");
    if (!$waitPort($serverPort)) {
        throw new RuntimeException('сервер REALITY не запустился: ' . substr((string) @file_get_contents("$work/server.log"), -300));
    }

    $connects = function (string $fingerprint) use ($binary, $work, $uuid, $serverPort, $pub, $freePort, $waitPort, $spawn, $stop): bool {
        $socks = $freePort();
        file_put_contents("$work/client.json", json_encode(['log' => ['loglevel' => 'warning'],
            'inbounds' => [['listen' => '127.0.0.1', 'port' => $socks, 'protocol' => 'socks', 'settings' => ['udp' => false]]],
            'outbounds' => [['protocol' => 'vless', 'settings' => ['vnext' => [['address' => '127.0.0.1', 'port' => $serverPort,
                'users' => [['id' => $uuid, 'flow' => 'xtls-rprx-vision', 'encryption' => 'none']]]]],
                'streamSettings' => ['network' => 'tcp', 'security' => 'reality', 'realitySettings' => [
                    'serverName' => 'mask.example.test', 'fingerprint' => $fingerprint, 'publicKey' => $pub[1], 'shortId' => 'abcd1234']]]],
        ], JSON_UNESCAPED_SLASHES));
        $client = $spawn([$binary, 'run', '-config', "$work/client.json"], "$work/client-$fingerprint.log");
        $ok = false;
        if ($waitPort($socks)) {
            // Отпечаткам, которые обязаны работать, — две попытки (первая может
            // прийтись на ещё не готовый сервер); остальные только
            // перечисляются в выводе, им хватит одной.
            $tries = in_array($fingerprint, Bot::REALITY_FINGERPRINTS, true) ? 2 : 1;
            for ($try = 0; $try < $tries && !$ok; $try++) {
                $ch = curl_init('http://through-reality.example.test/');
                curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_PROXY => "socks5h://127.0.0.1:$socks", CURLOPT_TIMEOUT => 4, CURLOPT_CONNECTTIMEOUT => 3]);
                curl_exec($ch);
                $ok = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE) === 403;
            }
        }
        $stop($client);
        return $ok;
    };

    $bot = (new ReflectionClass(Bot::class))->newInstanceWithoutConstructor();
    $seen = [];
    foreach ($bot->fingerprints() as $fingerprint) {
        $seen[$fingerprint] = $connects($fingerprint);
    }
    foreach (Bot::REALITY_FINGERPRINTS as $fingerprint) {
        if (empty($seen[$fingerprint])) {
            $failures[] = "ядро $version не приняло клиента с отпечатком $fingerprint: "
                . substr(trim((string) @file_get_contents("$work/client-$fingerprint.log")), -200);
        }
    }
    // Форк без флага принимает ClientHello без ML-KEM (ios), с флагом — нет.
    if ($fork && $modes !== [false] && !empty($seen['ios']) === $requireMlkem) {
        $failures[] = "форк $version с requireMlkem=" . ($requireMlkem ? 'true' : 'false')
            . ($requireMlkem ? ' принял' : ' не принял') . ' отпечаток ios';
    }
    $accepted = implode(' ', array_keys(array_filter($seen)));
    $rejected = implode(' ', array_keys(array_filter($seen, static fn($ok) => !$ok)));
    $stop($server);
    echo "ядро $version" . ($requireMlkem ? ' (requireMlkem)' : '') . ": принимает $accepted" . ($rejected === '' ? '' : "; отвергает $rejected") . "\n";
  }
  }
} finally {
    foreach ([$maskPid ?? 0] as $pid) {
        if ($pid > 0) { posix_kill_safe($pid); }
    }
    foreach (glob("$work/*") ?: [] as $file) unlink($file);
    @rmdir($work);
}

function posix_kill_safe(int $pid): void
{
    // posix в образе нет: завершаем дочерний процесс через kill.
    exec('kill ' . $pid . ' 2>/dev/null');
    pcntl_waitpid($pid, $status, WNOHANG);
}

foreach ($failures as $failure) echo "FAIL: $failure\n";
if ($failures) exit(1);
echo "reality_fingerprint_core_test OK\n";
