<?php
// XDRIVE на настоящем ядре Xray: конфиги бота принимает само ядро, а запрос
// клиента проходит через хранилище и обратно. В CI бинарник проверен по SHA256.
require_once __DIR__ . '/../app/bot.php';
set_error_handler(static function ($level, $message, $file, $line) { if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line); return true; });

$binary = getenv('VLESS_TEST_XRAY');
if (!$binary) {
    echo "xdrive_core_test SKIP: задайте VLESS_TEST_XRAY для проверки ядром\n";
    exit(0);
}
$python = trim((string) shell_exec('command -v python3'));
if (!is_executable($binary) || $python === '' || !extension_loaded('curl')) {
    throw new RuntimeException('Нужны исполняемый Xray, python3 и расширение curl');
}

class XdCoreBot extends Bot
{
    public array $confPac = ['xray_core' => 'origin'];
    public function __construct() {}
    public string $coreVersion = '';
    public function getPacConf() { return $this->confPac; }
    // Версию сообщает сам проверяемый бинарник.
    public function xrayCoreInventory(): array { return ['origin' => $this->coreVersion]; }
    // Хранилище теста живёт на этом же компьютере: проверяется транспорт, а
    // запрет внутренних адресов — в xdrive_test.php.
    public function xdriveHostPublic(string $url): bool { return true; }
    // xdriveHttp закрепляет адреса каждого запроса: тестовой заглушке — только loopback.
    protected function xdrivePublicIps(string $url): array { return trim((string) parse_url($url, PHP_URL_HOST), '[]') === '127.0.0.1' ? ['127.0.0.1'] : []; }
}

function xdAssert(bool $ok, string $message): void
{
    global $checks;
    if (!$ok) throw new RuntimeException('xdrive_core_test: ' . $message);
    $checks++;
}
function xdPort(): int
{
    $socket = stream_socket_server('tcp://127.0.0.1:0');
    $port = (int) substr(strrchr(stream_socket_get_name($socket, false), ':'), 1);
    fclose($socket);
    return $port;
}
function xdStart(array $command, string $log)
{
    $process = proc_open($command, [0 => ['file', '/dev/null', 'r'], 1 => ['file', $log, 'a'], 2 => ['file', $log, 'a']], $pipes);
    if (!is_resource($process)) throw new RuntimeException('не удалось запустить ' . $command[0]);
    return $process;
}
function xdWait(int $port, float $seconds = 8.0): bool
{
    $deadline = microtime(true) + $seconds;
    while (microtime(true) < $deadline) {
        if ($socket = @stream_socket_client("tcp://127.0.0.1:$port", $errno, $error, 0.3)) { fclose($socket); return true; }
        usleep(100000);
    }
    return false;
}
function xdFetch(int $socks, string $url, float $timeout = 20.0): array
{
    $ch = curl_init($url);
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_PROXY => "socks5h://127.0.0.1:$socks", CURLOPT_TIMEOUT_MS => (int) ($timeout * 1000), CURLOPT_NOPROXY => '']);
    $body = curl_exec($ch);
    return [(int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE), $body === false ? '' : (string) $body];
}
function xdConfigOk(string $binary, array $config, string $work): bool
{
    $file = "$work/check-" . bin2hex(random_bytes(4)) . '.json';
    file_put_contents($file, json_encode($config, JSON_UNESCAPED_SLASHES));
    exec(escapeshellarg($binary) . ' run -test -format json -config ' . escapeshellarg($file) . ' >/dev/null 2>&1', $out, $code);
    unlink($file);
    return $code === 0;
}

$checks = 0;
$work = sys_get_temp_dir() . '/vpnbot-xdrive-core-' . bin2hex(random_bytes(6));
mkdir("$work/dav/vpnbot-xdrive", 0700, true);
mkdir("$work/www", 0700);
$processes = [];
try {
    $version = (string) shell_exec(escapeshellarg($binary) . ' version 2>/dev/null | head -n1');
    xdAssert((bool) preg_match('~^Xray\s+v?([0-9][\w.+-]*)~', $version, $v) && version_compare($v[1], Bot::XDRIVE_MIN_CORE, '>='), 'тестовое ядро не старше ' . Bot::XDRIVE_MIN_CORE . ': ' . trim($version));

    // Ключи создаёт само ядро — тем же вызовом, что и в боте.
    $pairs = VlessEncryption::parseOutput((string) shell_exec(escapeshellarg($binary) . ' vlessenc 2>/dev/null'));
    xdAssert(isset($pairs['mlkem768']) && VlessEncryption::pair($pairs['mlkem768']) !== null, 'ядро выдало пару ключей ML-KEM-768');

    $bot = new XdCoreBot();
    $bot->xrayConf = "$work/xray.json";
    $bot->coreVersion = $v[1];
    $dav = xdPort(); $web = xdPort(); $socks = xdPort(); $stranger = xdPort();
    $base = ['enabled' => 1, 'enc' => $pairs['mlkem768']];
    $services = [
        'webdav' => ['service' => 'webdav', 'url' => "http://127.0.0.1:$dav", 'folder' => 'vpnbot-xdrive', 'secrets' => ['disk-user', 'app-pass-9']],
        'gdrive' => ['service' => 'gdrive', 'folder' => '1AbC_dEfGhIjKlMnOpQrStUvWxYz012', 'secrets' => ['id.apps.googleusercontent.com', 'GOCSPX-x', '1//refresh']],
        'template' => ['service' => 'template', 'folder' => 'bucket', 'secrets' => ['k1'], 'template' => json_encode([
            'auth' => ['type' => 'static', 'header' => ['X-Key' => '{secret0}']],
            'put' => ['method' => 'PUT', 'url' => 'https://storage.example.net/{folder}/{name}'], 'get' => ['method' => 'GET', 'url' => 'https://storage.example.net/{folder}/{name}'],
            'delete' => ['method' => 'DELETE', 'url' => 'https://storage.example.net/{folder}/{name}'],
            'list' => ['method' => 'GET', 'url' => 'https://storage.example.net/{folder}?prefix={prefix}', 'namesRegex' => '"name":"([^"]+)"']])],
    ];
    $users = [['id' => '11111111-1111-4111-8111-111111111111', 'email' => 'alice', 'flow' => 'xtls-rprx-vision'], ['id' => '22222222-2222-4222-8222-222222222222', 'email' => 'bob']];
    $server = static function (array $settings) use ($bot, $users, $web): array {
        $bot->confPac['xdrive'] = $settings;
        $config = ['log' => ['loglevel' => 'warning'], 'inbounds' => [['tag' => 'vless_tls', 'listen' => '127.0.0.1', 'port' => xdPort(), 'protocol' => 'vless',
            'settings' => ['clients' => $users, 'decryption' => 'none']]],
            // Цель теста — на этом же компьютере; в боте такие адреса закрыты правилами freedom.
            'outbounds' => [['tag' => 'direct', 'protocol' => 'freedom', 'settings' => ['finalRules' => [['action' => 'allow', 'ip' => ['127.0.0.0/8']]]]]]];
        $bot->ensureXdriveInbound($config);
        return $config;
    };

    // 1. Ядро принимает конфиг сервера и клиента для каждого вида хранилища.
    foreach ($services as $name => $settings) {
        $config = $server($base + $settings);
        xdAssert(count($config['inbounds']) === 2 && $config['inbounds'][1]['tag'] === 'xdrive', "вход XDRIVE собран: $name");
        xdAssert(xdConfigOk($binary, $config, $work), "ядро принимает конфиг сервера: $name");
        $client = $bot->xdriveClientConfig($users[0]);
        xdAssert($client !== null && xdConfigOk($binary, $client, $work), "ядро принимает профиль клиента: $name");
    }
    // Форк-ядро, если оно есть в окружении теста, принимает те же конфиги.
    $fork = getenv('XRAY_FORK_TEST_BINARY');
    if ($fork && is_executable($fork)) {
        $config = $server($base + $services['webdav']);
        xdAssert(xdConfigOk($fork, $config, $work) && xdConfigOk($fork, $bot->xdriveClientConfig($users[0]), $work), 'форк-ядро принимает конфиг сервера и профиль клиента');
    }
    $broken = $server($base + $services['webdav']);
    $broken['inbounds'][1]['streamSettings']['xdriveSettings']['service'] = 'Dropbox';
    xdAssert(!xdConfigOk($binary, $broken, $work), 'проверка ядром отличает негодный конфиг');

    // 2. Запрос клиента проходит через хранилище WebDAV и возвращается.
    $marker = 'vpnbot-xdrive-' . bin2hex(random_bytes(12));
    file_put_contents("$work/www/$marker.txt", str_repeat($marker . "\n", 4000));
    $processes[] = xdStart([$python, __DIR__ . '/integration/fixtures/xdrive/webdav_server.py', "$work/dav", '127.0.0.1', (string) $dav, 'disk-user', 'app-pass-9'], "$work/dav.log");
    $processes[] = xdStart([$python, '-m', 'http.server', (string) $web, '--bind', '127.0.0.1', '--directory', "$work/www"], "$work/www.log");
    xdAssert(xdWait($dav) && xdWait($web), 'хранилище и цель теста запущены');
    $config = $server(['poll' => 500] + $base + $services['webdav']);
    file_put_contents("$work/server.json", json_encode($config, JSON_UNESCAPED_SLASHES));
    $profile = $bot->xdriveClientConfig($users[1]);
    $profile['inbounds'] = [['listen' => '127.0.0.1', 'port' => $socks, 'protocol' => 'socks']];
    file_put_contents("$work/client.json", json_encode($profile, JSON_UNESCAPED_SLASHES));
    $processes[] = xdStart([$binary, 'run', '-c', "$work/server.json"], "$work/server.log");
    $processes[] = xdStart([$binary, 'run', '-c', "$work/client.json"], "$work/client.log");
    xdAssert(xdWait($socks), 'клиент Xray запущен');
    usleep(700000);
    [$code, $body] = xdFetch($socks, "http://127.0.0.1:$web/$marker.txt");
    xdAssert($code === 200 && $body === str_repeat($marker . "\n", 4000), "ответ прошёл через XDRIVE без искажений (код $code, " . strlen($body) . ' байт)');
    for ($n = 1; $n <= 3; $n++) {
        [$code] = xdFetch($socks, "http://127.0.0.1:$web/$marker.txt");
        xdAssert($code === 200, "повторный запрос $n проходит");
    }
    // Сервер для XDRIVE ничего не слушает: соединение только через хранилище.
    xdAssert(@stream_socket_client('tcp://127.0.0.1:10444', $errno, $error, 0.3) === false, 'порт входа XDRIVE не открыт');

    // 3. В хранилище нет открытого текста: ни адреса запроса, ни идентификатора пользователя.
    $stored = '';
    foreach (glob("$work/dav/vpnbot-xdrive/*") as $file) $stored .= file_get_contents($file);
    $seen = false;
    for ($n = 0; $n < 20 && !$seen; $n++) {
        // Файлы обмена удаляются после чтения: ловим их во время запроса.
        $ch = curl_init("http://127.0.0.1:$web/$marker.txt");
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_PROXY => "socks5h://127.0.0.1:$socks", CURLOPT_TIMEOUT => 20, CURLOPT_NOPROXY => '']);
        $multi = curl_multi_init();
        curl_multi_add_handle($multi, $ch);
        do {
            curl_multi_exec($multi, $running);
            foreach (glob("$work/dav/vpnbot-xdrive/*") as $file) {
                $data = @file_get_contents($file);
                if ($data !== false && strlen($data) > 0) { $stored .= $data; $seen = true; }
            }
            usleep(2000);
        } while ($running);
        curl_multi_remove_handle($multi, $ch);
    }
    xdAssert($seen && strlen($stored) > 100, 'файлы обмена в хранилище прочитаны (' . strlen($stored) . ' байт)');
    xdAssert(!str_contains($stored, $marker) && !str_contains($stored, '22222222-2222-4222-8222-222222222222') && !str_contains($stored, "127.0.0.1:$web"),
        'хранилище не видит ни содержимого, ни адреса запроса, ни идентификатора пользователя');

    // 4. Посторонний с доступом к хранилищу, но без ключа и идентификатора, не проходит.
    foreach (['чужой идентификатор' => ['id' => '99999999-9999-4999-8999-999999999999'], 'чужой ключ шифрования' => []] as $name => $override) {
        $other = $bot->xdriveClientConfig($override + $users[1]);
        if (!$override) {
            $foreign = VlessEncryption::parseOutput((string) shell_exec(escapeshellarg($binary) . ' vlessenc 2>/dev/null'))['mlkem768'];
            $other['outbounds'][0]['settings']['vnext'][0]['users'][0]['encryption'] = VlessEncryption::pair($foreign)['encryption'];
        }
        $port = xdPort();
        $other['inbounds'] = [['listen' => '127.0.0.1', 'port' => $port, 'protocol' => 'socks']];
        file_put_contents("$work/stranger.json", json_encode($other, JSON_UNESCAPED_SLASHES));
        $process = xdStart([$binary, 'run', '-c', "$work/stranger.json"], "$work/stranger.log");
        xdAssert(xdWait($port), "клиент запущен: $name");
        [$code, $body] = xdFetch($port, "http://127.0.0.1:$web/$marker.txt", 6.0);
        proc_terminate($process);
        proc_close($process);
        xdAssert($code !== 200 && !str_contains($body, $marker), "отказ: $name (код $code)");
    }
    [$code] = xdFetch($socks, "http://127.0.0.1:$web/$marker.txt");
    xdAssert($code === 200, 'свой клиент продолжает работать после чужих попыток');

    // 5. Хранилище S3 (ядро 26.10.29+): заглушка проверяет подпись SigV4 и ядра, и бота.
    $s3 = xdPort(); $s3socks = xdPort();
    $s3Settings = ['service' => 's3', 'url' => "http://127.0.0.1:$s3", 'bucket' => 'vpnbot-bucket', 'region' => 'ru-central1', 'path_style' => 1,
        'folder' => 'vpnbot-xdrive', 'secrets' => ['AKIDVPNBOTTEST', 'wJalr/K7MDENG+bPxRfiCY']];
    $s3Server = $server(['poll' => 500] + $base + $s3Settings);
    if (version_compare($v[1], Bot::XDRIVE_S3_MIN_CORE, '<')) {
        // 26.9.30 и форк 26.10.28 пропускают такой конфиг через run -test, но
        // хранилища S3 не знают: защищает только порог версии в боте.
        xdAssert(!$bot->xdriveCoreReady(null, 's3'), 'бот не включает S3 на ядре до ' . Bot::XDRIVE_S3_MIN_CORE);
    } else {
        xdAssert($bot->xdriveCoreReady(null, 's3'), 'бот считает ядро готовым к S3');
        xdAssert(xdConfigOk($binary, $s3Server, $work) && xdConfigOk($binary, $bot->xdriveClientConfig($users[0]), $work), 'ядро принимает конфиг S3 сервера и клиента');
        $processes[] = xdStart([$python, __DIR__ . '/integration/fixtures/xdrive/s3_server.py', '127.0.0.1', (string) $s3, 'vpnbot-bucket', 'ru-central1',
            'AKIDVPNBOTTEST', 'wJalr/K7MDENG+bPxRfiCY'], "$work/s3.log");
        xdAssert(xdWait($s3), 'заглушка S3 запущена');
        xdAssert($bot->xdriveProbe($bot->xdriveSettings()) === '', 'проверка бота: подпись принята, запись, чтение, список и удаление');
        $wrong = ['secrets' => ['AKIDVPNBOTTEST', 'other-secret']] + $bot->xdriveSettings();
        xdAssert($bot->xdriveProbe($wrong) === 'xdrive probe auth', 'проверка бота с чужим секретом: отказ подписи');
        file_put_contents("$work/s3-server.json", json_encode($s3Server, JSON_UNESCAPED_SLASHES));
        $profile = $bot->xdriveClientConfig($users[1]);
        $profile['inbounds'] = [['listen' => '127.0.0.1', 'port' => $s3socks, 'protocol' => 'socks']];
        file_put_contents("$work/s3-client.json", json_encode($profile, JSON_UNESCAPED_SLASHES));
        $processes[] = xdStart([$binary, 'run', '-c', "$work/s3-server.json"], "$work/s3-server.log");
        $processes[] = xdStart([$binary, 'run', '-c', "$work/s3-client.json"], "$work/s3-client.log");
        xdAssert(xdWait($s3socks), 'клиент Xray для S3 запущен');
        usleep(700000);
        [$code, $body] = xdFetch($s3socks, "http://127.0.0.1:$web/$marker.txt");
        xdAssert($code === 200 && $body === str_repeat($marker . "\n", 4000), "ответ прошёл через S3 без искажений (код $code, " . strlen($body) . ' байт)');
        xdAssert(!str_contains((string) @file_get_contents("$work/s3-server.log") . @file_get_contents("$work/s3-client.log"), 'SignatureDoesNotMatch'),
            'ядро подписывает запросы так, как ждёт S3');
    }

    echo "xdrive_core_test OK ($checks проверок ядром " . $v[1] . ")\n";
} finally {
    foreach ($processes as $process) { @proc_terminate($process); @proc_close($process); }
    exec('rm -rf ' . escapeshellarg($work));
}
