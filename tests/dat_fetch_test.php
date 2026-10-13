<?php

// Загрузка .dat настоящим HTTPS-запросом к локальному серверу: тело пишется в
// файл, оборванная передача и чужие ответы не считаются удачей, временный
// файл после отказа не остаётся.

require_once __DIR__ . '/../app/bot.php';

if (getenv('VPNBOT_DAT_FETCH_WORKER')) {
    class DatFetchBot extends Bot
    {
        public function __construct() {}
        public function datDir(): string { return getenv('VPNBOT_DAT_FETCH_DIR'); }
        public function safeExtUrlIps(string $url): array
        {
            // Подменяется только выбор адреса; TLS и сама передача — настоящие.
            return parse_url($url, PHP_URL_HOST) === 'audit.example.test' ? ['127.0.0.1'] : [];
        }
    }
    $bot = new DatFetchBot();
    $r = $bot->datFetchRaw(getenv('VPNBOT_DAT_FETCH_WORKER'), ['etag' => '"v1"']);
    if (isset($r['file'])) {
        $r['size'] = filesize($r['file']);
        $r['sha'] = hash_file('sha256', $r['file']);
        $r['peak'] = memory_get_peak_usage(true);
        unlink($r['file']);
    }
    $r['left'] = array_map('basename', glob($bot->datDir() . '/*') ?: []);
    echo json_encode($r);
    exit;
}

$root = sys_get_temp_dir() . '/vpnbot-dat-fetch-' . bin2hex(random_bytes(6));
mkdir($root, 0700);
mkdir("$root/dat", 0700);
$failures = [];
try {
    $key = openssl_pkey_new(['private_key_bits' => 2048]);
    $csr = openssl_csr_new(['commonName' => 'audit.example.test'], $key);
    $cert = openssl_csr_sign($csr, null, $key, 1);
    openssl_x509_export($cert, $public);
    openssl_pkey_export($key, $private);
    file_put_contents("$root/cert.pem", $public);
    file_put_contents("$root/key.pem", $private);
    chmod("$root/key.pem", 0600);
    $context = stream_context_create(['ssl' => ['local_cert' => "$root/cert.pem", 'local_pk' => "$root/key.pem", 'verify_peer' => false]]);
    // 24 МБ: больше, чем прежний код мог удержать в памяти рядом со своими копиями.
    $big = str_repeat(random_bytes(1 << 16), 384);
    foreach (['complete', 'env-proxy', 'truncated', 'not-modified', 'http-error', 'empty', 'redirect-private'] as $scenario) {
        $server = stream_socket_server('tls://127.0.0.1:0', $errno, $error, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context);
        $port = substr(strrchr(stream_socket_get_name($server, false), ':'), 1);
        $pid = pcntl_fork();
        if ($pid === 0) {
            $connection = @stream_socket_accept($server, 10);
            if (!$connection) exit(1);
            stream_set_timeout($connection, 3);
            $request = '';
            while (($line = fgets($connection)) !== false && trim($line) !== '') $request .= $line;
            $body = in_array($scenario, ['empty', 'not-modified'], true) ? '' : ($scenario === 'http-error' ? 'nope' : $big);
            $length = strlen($body) + ($scenario === 'truncated' ? 1000 : 0);
            $code = ['not-modified' => '304 Not Modified', 'http-error' => '503 Unavailable', 'redirect-private' => '302 Found'][$scenario] ?? '200 OK';
            if ($scenario === 'not-modified' && !str_contains($request, 'If-None-Match: "v1"')) $code = '400 Validator Missing';
            $extra = $scenario === 'redirect-private' ? "Location: https://127.0.0.1/private\r\n" : '';
            @fwrite($connection, "HTTP/1.1 $code\r\nContent-Length: $length\r\nETag: \"v2\"\r\n$extra" . "Connection: close\r\n\r\n");
            foreach (str_split($body, 1 << 16) as $part) {
                if (@fwrite($connection, $part) === false) break;
            }
            fclose($connection);
            fclose($server);
            exit(0);
        }
        fclose($server);
        $env = array_merge(getenv(), ['VPNBOT_DAT_FETCH_WORKER' => "https://audit.example.test:$port/list.dat", 'VPNBOT_DAT_FETCH_DIR' => "$root/dat",
            'HTTPS_PROXY' => '', 'https_proxy' => '', 'ALL_PROXY' => '', 'all_proxy' => '']);
        if ($scenario === 'env-proxy') $env['HTTPS_PROXY'] = $env['https_proxy'] = 'http://127.0.0.1:1';
        $process = proc_open([PHP_BINARY, '-d', "curl.cainfo=$root/cert.pem", '-d', 'memory_limit=64M', __FILE__],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, $env);
        $out = stream_get_contents($pipes[1]);
        $error = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $code = proc_close($process);
        pcntl_waitpid($pid, $status);
        $r = json_decode($out, true) ?: [];
        $ok = $code === 0 && $error === '' && ($r['left'] ?? null) === [];
        if (in_array($scenario, ['complete', 'env-proxy'], true)) {
            // Тело целиком в файле, вне памяти процесса: лимит 64 МБ при теле в 24 МБ.
            $ok = $ok && !empty($r['ok']) && ($r['size'] ?? 0) === strlen($big) && ($r['sha'] ?? '') === hash('sha256', $big)
                && ($r['etag'] ?? '') === '"v2"' && !isset($r['body']) && ($r['peak'] ?? PHP_INT_MAX) < 48 << 20;
        } elseif ($scenario === 'not-modified') {
            $ok = $ok && !empty($r['ok']) && !empty($r['not_modified']);
        } else {
            $ok = $ok && empty($r['ok']) && is_string($r['err'] ?? null) && $r['err'] !== '';
        }
        if (!$ok) $failures[] = "$scenario: " . substr($out . $error, 0, 300);
    }
} finally {
    foreach (glob("$root/dat/*") ?: [] as $file) unlink($file);
    rmdir("$root/dat");
    foreach (glob("$root/*") ?: [] as $file) unlink($file);
    rmdir($root);
}
foreach ($failures as $failure) echo "FAIL: dat fetch $failure\n";
if ($failures) exit(1);
echo "dat_fetch_test OK\n";
