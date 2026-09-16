<?php

require_once __DIR__ . '/../app/bot.php';

// The real subscription dispatcher runs behind HTTP so Location headers, exits,
// authentication and the browser/HWID boundary are exercised together.
if (getenv('VPNBOT_IMPORT_TEST_SERVER') === '1') {
    class ImportHttpBot extends Bot
    {
        public function getPacConf() { return ['subtoken_strict' => 1]; }
        public function getXray() {
            return ['inbounds' => [['settings' => ['clients' => [[
                'id' => 'credential', 'subtoken' => 'subscription-token', 'email' => "Тест & # + ' <имя>\r\nX-Injected: yes",
                'off' => !empty($_GET['disabled']),
            ]]]]]];
        }
        public function subDomain(array $pac): string { return 'example.test'; }
        public function nginxGetTypeCert() { return 'letsencrypt'; }
        public function getHashBot($notset = false) { return 'testhash'; }
        public function subTemplate(string $template, string $type, array $pac) { return []; }
        public function subRateLimit($sid, $scope = '') {}
        public function subscriptionCompatibilityError(array $xr, array $pac, string $type): string { return ''; }
        public function linkXray($i, $s = false) { return 'trojan://credential@example.test:443'; }
        public function expandClientExt(array $client): array { return []; }
        public function processHwidRequest(array $client, bool $htmlPreview = false) {
            if (($_SERVER['HTTP_X_HWID'] ?? '') === 'test-device') return true;
            http_response_code(403);
            echo 'HWID required';
            return false;
        }
    }
    $bot = (new ReflectionClass(ImportHttpBot::class))->newInstanceWithoutConstructor();
    if (($_GET['t'] ?? '') === 'vl') $bot->subVless();
    else $bot->subscription();
    exit;
}

$failed = 0;
function importAssert(bool $ok, string $message): void
{
    global $failed;
    if (!$ok) { $failed++; echo "FAIL: $message\n"; }
}

$bot = (new ReflectionClass(Bot::class))->newInstanceWithoutConstructor();
$name = "🇷🇺 Тест & # + ' \" <имя>\r\n";
$relay = "Москва / 🇷🇺 & # + '";
$base = 'https://example.test/pactesthash';
$formats = ['v' => 's', 'sr' => 'vl', 'si' => 'si', 'st' => 'vl', 'h' => 'vl', 'k' => 'si', 'c' => 'cl', 'rh' => 'cl'];
$schemes = ['v' => 'v2rayng', 'sr' => 'shadowrocket', 'si' => 'sing-box', 'st' => 'streisand',
    'h' => 'hiddify', 'k' => 'karing', 'c' => 'clash', 'rh' => 'rabbithole'];
foreach (['', $relay] as $via) {
    $token = ['h' => 'testhash', 's' => 'subscription-token'];
    if ($via !== '') $token['relay'] = $via;
    foreach ($formats as $code => $format) {
        $link = $bot->subscriptionImportUrl($code, $base, $token, $name);
        importAssert(parse_url($link, PHP_URL_SCHEME) === $schemes[$code], "$code: registered client scheme");
        importAssert(!preg_match('/[\r\n<>"\x00]/', $link), "$code: no header/HTML injection");
        parse_str((string) parse_url($link, PHP_URL_QUERY), $query);
        if (in_array($code, ['v', 'si', 'k', 'c'], true)) {
            $url = $query['url'] ?? '';
        } elseif ($code === 'sr') {
            $url = base64_decode(explode('?', substr($link, strlen('shadowrocket://add/sub://')))[0], true);
            importAssert(($query['remark'] ?? '') === $name, 'Shadowrocket: subscription title');
        } elseif ($code === 'st') {
            $url = rawurldecode(explode('#', substr($link, strlen('streisand://import/')))[0]);
        } elseif ($code === 'h') {
            $url = explode('#', substr($link, strlen('hiddify://import/')))[0];
        } else {
            $url = substr($link, strlen('rabbithole://add/'));
        }
        importAssert(str_starts_with($url, "$base/"), "$code: exact subscription origin");
        $segment = substr($url, strlen("$base/"));
        importAssert((bool) preg_match('/^[A-Za-z0-9_-]+$/', $segment), "$code: path survives slash/plus decoding");
        $decoded = unserialize(base64_decode(strtr($segment, '-_', '+/'), true), ['allowed_classes' => false]);
        importAssert($decoded === $token + ['t' => $format], "$code: locator, format and relay preserved");
        importAssert(!str_contains($url, 'credential'), "$code: no VPN credential in subscription locator");
        if (in_array($code, ['v', 'si', 'st'], true)) {
            $fragment = rawurldecode((string) parse_url($link, PHP_URL_FRAGMENT));
            if ($code === 'v') {
                importAssert(!preg_match('/[\s<>"#]/u', $fragment), 'v2rayNG: Android-decoded fragment remains valid in java.net.URI');
                $fragment = rawurldecode($fragment);
            }
            importAssert($fragment === $name, "$code: encoded profile title");
        } elseif ($code === 'h') {
            importAssert(parse_url($link, PHP_URL_FRAGMENT) === null, 'Hiddify: title comes from the UTF-8 Profile-Title header');
        } elseif (in_array($code, ['k', 'c'], true)) {
            importAssert(($query['name'] ?? '') === $name, "$code: name is a separate query parameter");
        }
    }
    $links = $bot->subscriptionImportLinks($base, 'subscription-token', $name, $via);
    importAssert(count($links) === 8, 'all eight clients are offered');
    foreach ($links as $link) {
        preg_match('/href="([^"]+)"/', $link, $match);
        $url = html_entity_decode($match[1] ?? '', ENT_QUOTES, 'UTF-8');
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);
        importAssert(($query['relay'] ?? '') === $via, 'Telegram HTML: relay is not truncated');
        importAssert(($query['s'] ?? '') === 'subscription-token' && isset($formats[$query['r'] ?? '']), 'Telegram HTML: client and locator intact');
        importAssert(rawurldecode((string) parse_url($url, PHP_URL_FRAGMENT)) === $name, 'Telegram HTML: complex title intact');
    }
}

$listener = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
$address = stream_socket_get_name($listener, false);
fclose($listener);
$log = tempnam(sys_get_temp_dir(), 'vpnbot-import-');
$proc = proc_open([PHP_BINARY, '-S', $address, __FILE__], [0 => ['pipe', 'r'], 1 => ['file', $log, 'a'], 2 => ['file', $log, 'a']], $pipes,
    null, array_merge(getenv(), ['VPNBOT_IMPORT_TEST_SERVER' => '1']));
try {
    for ($attempt = 0; $attempt < 100; $attempt++) {
        $socket = @stream_socket_client("tcp://$address", $errno, $error, 0.05);
        if ($socket) { fclose($socket); break; }
        usleep(50000);
    }
    foreach (array_keys($formats) as $code) {
        $ch = curl_init("http://$address/?t=s&s=subscription-token&r=$code");
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true, CURLOPT_TIMEOUT => 5]);
        $response = curl_exec($ch);
        importAssert(curl_getinfo($ch, CURLINFO_HTTP_CODE) === 302, "$code: browser gets an app redirect before HWID registration");
        importAssert(str_contains((string) $response, 'Location: ' . $schemes[$code] . '://'), "$code: real HTTP Location");
        importAssert(!str_contains((string) $response, 'credential'), "$code: redirect does not expose VPN credentials");
        curl_close($ch);
    }
    foreach ([['t=s&s=subscription-token', 403], ['t=s&s=subscription-token&r=w', 403],
        ['t=s&s=credential&r=sr', 404], ['t=s&s=subscription-token&r=sr&disabled=1', 404],
        ['t=s&s=unknown&r=v', 404]] as [$query, $status]) {
        $ch = curl_init("http://$address/?$query");
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 5]);
        curl_exec($ch);
        importAssert(curl_getinfo($ch, CURLINFO_HTTP_CODE) === $status, 'HWID and strict/disabled subscription gates remain enforced');
        curl_close($ch);
    }
    $ch = curl_init("http://$address/?t=vl&s=subscription-token");
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true,
        CURLOPT_HTTPHEADER => ['X-HWID: test-device'], CURLOPT_TIMEOUT => 5]);
    $response = curl_exec($ch);
    importAssert(curl_getinfo($ch, CURLINFO_HTTP_CODE) === 200, 'authorized app downloads the share list');
    preg_match('/^Profile-Title: base64:([^\r\n]+)/m', (string) $response, $header);
    importAssert(base64_decode($header[1] ?? '', true) === "Тест & # + ' <имя>\r\nX-Injected: yes",
        'Hiddify receives the original Unicode title through the response header');
    importAssert(!str_contains((string) $response, "\r\nX-Injected:"), 'title cannot inject a response header');
    curl_close($ch);
} finally {
    proc_terminate($proc);
    proc_close($proc);
    unlink($log);
}

if ($failed) { echo "subscription_import_test FAILED: $failed\n"; exit(1); }
echo "subscription_import_test OK\n";
