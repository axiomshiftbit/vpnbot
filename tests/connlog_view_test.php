<?php
// A user's connection log: by time, by site, by device; subscription apps;
// pages; the text export (UTF-8, aligned columns); clearing.
require_once __DIR__ . '/../app/bot.php';

if (!extension_loaded('pdo_sqlite')) {
    echo "connlog_view_test SKIP: нет pdo_sqlite (в CI и образе php он есть)\n";
    exit(0);
}
set_error_handler(static function ($level, $message, $file, $line) {
    if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line);
    return false;
});
$checks = 0;
function clCheck(bool $ok, string $label): void { global $checks; if (!$ok) throw new RuntimeException('FAIL ' . $label); $checks++; }

class ConnLogViewBot extends Bot
{
    public array $screens = []; public array $files = []; public array $xclients = []; public array $online = []; public array $geo = [];
    public function __construct(string $root)
    {
        $this->hwid = "$root/hwid.json";
        $this->input = ['chat' => 1, 'from' => 1, 'message_id' => 2, 'callback_id' => 'cb'];
        $this->language = 'ru';
        require __DIR__ . '/../app/i18n.php'; $this->i18n = $i;
    }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
    public function getXray() { return ['inbounds' => [['settings' => ['clients' => $this->xclients]]]]; }
    public function trackOnline(): array { return []; }
    public function onlineClients(int $window = 60): array { return $this->online; }
    public function getGeoCache(): array { return $this->geo; }
    public function setGeoCache(array $cache) { $this->geo = $cache; }
    public function geoLookup(string $ip, array &$cache, bool $cacheOnly = false): array { return parent::geoLookup($ip, $cache, true); }
    public function resolveHost(string $host, array &$cache, bool $cacheOnly = true): string { return parent::resolveHost($host, $cache, true); }
    public function getHwidStorage() { return []; }
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML') { $this->screens[] = [$text, $button ?: []]; }
    public function sendFile($chat, $file, $caption = false, $to = false) { $this->files[] = [$file->data, $file->postname, $file->mime]; return ['ok' => true]; }
    public function answer($callback_id, $textNotify = false, $notify = false) {}
}

$root = sys_get_temp_dir() . '/vpnbot-connlog-' . bin2hex(random_bytes(6));
mkdir($root, 0700);
try {
    $b = new ConnLogViewBot($root);
    $b->xclients = [['id' => '00000000-0000-4000-8000-000000000001', 'email' => 'ivan'], ['id' => '00000000-0000-4000-8000-000000000002', 'email' => 'other']];
    $day1 = strtotime('-2 days 19:44'); $day2 = strtotime('-1 day 21:11'); $day3 = strtotime('today 09:19');
    $now = time();
    $b->geo = ['203.0.113.17' => ['country' => 'RU', 'org' => 'Example ISP', 'ts' => $now], 'host:courier2.push.apple.com' => ['ip' => '198.51.100.5', 'ts' => $now],
        '198.51.100.5' => ['country' => 'US', 'org' => 'Apple Inc.', 'ts' => $now]];
    // Summary-only history from before the update (no daily rows).
    $b->setConnLog(['ivan' => ['last' => $day1, 'ips' => ['203.0.113.17' => ['first' => $day1 - 600, 'last' => $day1, 'count' => 7,
        'dst' => ['legacy.example.test:443' => ['first' => $day1 - 600, 'last' => $day1 - 300, 'count' => 7]]]]]]);
    $events = [];
    foreach ([[$day1, 'courier2.push.apple.com:443', 3], [$day1 + 60, 'courier2.push.apple.com:5223', 2], [$day2, 'www.youtube.com:443', 4],
              [$day2 + 120, 's.youtube.com:443', 2], [$day2 - 7200, 'range.example.test:443', 1], [$day2 - 7000, 'range.example.test:443', 1], [$day2 - 3600, 'scontent-cdg4-1.cdninstagram.com:443', 5], [$day2 - 3500, 'scontent-cdg6-1.cdninstagram.com:443', 3],
              [$day3, 'i.instagram.com:443', 6], [$day3 + 60, 'aa11-netseer-ipaddr-assoc.xy.fbcdn.net:443', 1], [$day3 + 61, 'bb22-netseer-ipaddr-assoc.xy.fbcdn.net:443', 1],
              [$day3 + 30, '<b>evil</b>.test:443', 1], [$now - 2592000 - 100, 'expired.test:443', 1]] as [$ts, $host, $n]) {
        for ($k = 0; $k < $n; $k++) $events[] = ['email' => 'ivan', 'ip' => $ts > $day3 - 10 ? '198.51.100.40' : '203.0.113.17', 'dst' => $host, 'ts' => $ts + $k];
    }
    $events[] = ['email' => 'other', 'ip' => '203.0.113.99', 'dst' => 'other.test:443', 'ts' => $day3];
    // The access log is chronological: feed the events in time order.
    usort($events, static fn($a, $b) => $a['ts'] <=> $b['ts']);
    $b->recordConnLog($events);
    $days = $b->storeConnLogDays('ivan');
    clCheck(count($days) === 11 && $days[0]['last'] >= $days[1]['last'], 'daily rows recorded newest first, expired event dropped');
    $yt = array_values(array_filter($days, static fn($r) => $r['host'] === 'www.youtube.com:443'))[0];
    clCheck($yt['count'] === 4 && $yt['first'] === $day2 && $yt['last'] === $day2 + 3 && $yt['day'] === date('Y-m-d', $day2), 'daily row keeps first, last and count of the day');

    // Subscription apps: native app headers, a browser page, an anonymous client.
    foreach ([['HTTP_USER_AGENT' => 'Happ/2.6.1/ios CFNetwork/1568.100.1 Darwin/24.0.0', 'HTTP_X_DEVICE_OS' => 'iOS', 'HTTP_X_VER_OS' => '18.1', 'HTTP_X_DEVICE_MODEL' => 'iPhone15,2', 'HTTP_X_REAL_IP' => '198.51.100.40'],
              ['HTTP_USER_AGENT' => 'Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778 Mobile Safari/537.36', 'HTTP_X_REAL_IP' => '203.0.113.17']] as $server) {
        $saved = $_SERVER; $_SERVER = $server + $_SERVER;
        $b->recordSubClient($b->xclients[0]);
        $_SERVER = $saved;
    }
    $saved = $_SERVER; $_SERVER = ['HTTP_USER_AGENT' => 'v2rayNG/1.9.30'] + $_SERVER; $b->recordSubClient(['email' => 'svc', 'exit_relay' => 1]); $_SERVER = $saved;
    clCheck($b->storeSubClients('svc') === [], 'node service account is not recorded as a device');
    $apps = $b->storeSubClients('ivan');
    clCheck(count($apps) === 2 && $apps[0]['ip'] === '203.0.113.17', 'subscription apps recorded with address, newest first');

    $saved = $_SERVER;
    $_SERVER = ['HTTP_USER_AGENT' => 'Happ/4.8.3 (+https://device.example.test/private-fixture)', 'HTTP_X_DEVICE_MODEL' => 'token=private-fixture'];
    $b->recordSubClient(['email' => 'metadata-test']);
    $_SERVER = $saved;
    $record = $b->storeSubClients('metadata-test')[0];
    clCheck($record['ua'] === 'Happ/4.8.3' && $record['model'] === '', 'only product information from private device headers is stored');
    $b->storeSubClientRecord('metadata-test', ['ua' => 'https://device.example.test/private-fixture', 'os' => '', 'osver' => '', 'model' => 'private (Bearer private-fixture)'], '');
    $rows = $b->connLogDevices(['email' => 'metadata-test']);
    clCheck(count($rows) === 2 && !str_contains(json_encode($rows), 'private-fixture'), 'legacy device headers are sanitized for display and export');

    $saved = $_SERVER;
    $opaque = bin2hex(random_bytes(16));
    $_SERVER = ['HTTP_USER_AGENT' => 'Happ/4.8.3 (' . $opaque . ')', 'HTTP_X_DEVICE_OS' => '12345678-1234-4234-9234-123456789012'];
    $b->recordSubClient(['email' => 'opaque-test']);
    $_SERVER = $saved;
    $record = $b->storeSubClients('opaque-test')[0];
    clCheck($record['ua'] === 'Happ/4.8.3' && $record['os'] === '', 'bare subscription tokens and profile UUIDs are excluded from metadata');

    // Device parsing.
    foreach ([[['ua' => 'Happ/2.6.1/ios CFNetwork/1568 Darwin/24.0.0', 'os' => 'iOS', 'osver' => '18.1', 'model' => 'iPhone15,2'], ['📱', 'Happ 2.6.1', 'iOS 18.1', 'iPhone15,2', '']],
              [['ua' => 'v2rayNG/1.9.30'], ['❔', 'v2rayNG 1.9.30', '', '', '']],
              [['ua' => 'HiddifyNext/2.5.7 (android) like ClashMeta v2ray sing-box'], ['📱', 'HiddifyNext 2.5.7', 'Android', '', '']],
              [['ua' => 'Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778 Mobile Safari/537.36'], ['📱', '', 'Android 14', '', 'Chrome 131']],
              [['ua' => 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1'], ['📱', '', 'iOS 18.1', '', 'Safari 18']],
              [['ua' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36 Edg/131.0'], ['💻', '', 'Windows 10/11', '', 'Edge 131']],
              [['ua' => 'Streisand/1.6.40 CFNetwork Darwin'], ['❔', 'Streisand 1.6.40', 'iOS/macOS', '', '']],
              [['ua' => 'curl/8.5.0'], ['❔', '', '', '', '']]] as [$input, $expected]) {
        $d = Bot::connLogDevice($input);
        clCheck([$d['icon'], $d['app'], $d['os'], $d['model'], $d['browser']] === $expected, 'device parsed: ' . $input['ua']);
    }
    clCheck(Bot::connLogSite('scontent-cdg4-1.cdninstagram.com:443') === 'cdninstagram.com' && Bot::connLogSite('a.b.example.co.uk:443') === 'example.co.uk'
        && Bot::connLogSite('203.0.113.5:443') === '203.0.113.5' && Bot::connLogSite('[2001:db8::1]:443') === '2001:db8::1' && Bot::connLogHost('x.test:443') === 'x.test'
        && Bot::connLogHost('x.test:5223') === 'x.test:5223', 'site and host normalisation');

    // Time view (default): days newest first, newest within a day first.
    $b->online = ['ivan' => ['ips' => []]];
    $b->clientLogView(0);
    [$text, $rows] = end($b->screens);
    $plain = html_entity_decode(strip_tags($text), ENT_QUOTES);
    $d3 = strpos($plain, date('d.m.Y', $day3)); $d2 = strpos($plain, date('d.m.Y', $day2)); $d1 = strrpos($plain, date('d.m.Y', $day1) . ',');
    clCheck($d3 !== false && $d2 > $d3 && $d1 > $d2, 'days are listed newest first');
    clCheck(strpos($plain, 's.youtube.com') < strpos($plain, 'www.youtube.com') && strpos($plain, 'www.youtube.com') < strpos($plain, 'scontent-cdg6-1'), 'within a day: by last visit');
    clCheck(str_contains($plain, date('H:i', $day2) . '  www.youtube.com ×4') && str_contains($plain, date('H:i', $day2 - 7200) . '–' . date('H:i', $day2 - 7000) . '  range.example.test ×2'), 'single time within a minute, interval otherwise, and hits');
    clCheck(str_contains($plain, 'courier2.push.apple.com ×3') && str_contains($plain, 'courier2.push.apple.com:5223 ×2'), 'port 443 hidden, other ports shown');
    clCheck(str_contains($plain, '🇺🇸 Apple Inc.'), 'owner of the host from the cache');
    clCheck(str_contains($plain, 'legacy.example.test ×7 ⏳ до обновления'), 'history before the update marked honestly');
    clCheck(str_contains($text, '&lt;b&gt;evil&lt;/b&gt;') && !str_contains($text, '<b>evil'), 'hosts are escaped');
    clCheck(str_contains($plain, '🟢 онлайн сейчас') && str_contains($plain, 'Подключений ') && str_contains($plain, 'Последняя активность: '), 'summary header');
    clCheck(str_contains($plain, 'Устройство: 🌐') || str_contains($plain, 'Устройство: 📱'), 'latest app in the header');
    clCheck(!str_contains($plain, 'expired.test') && !str_contains($plain, 'other.test'), 'expired and other users are not shown');
    $callbacks = array_merge(...array_map(static fn($r) => array_column($r, 'callback_data'), $rows));
    clCheck(in_array('/clientLog 0 s0 0', $callbacks, true) && in_array('/clientLog 0 d0 0', $callbacks, true) && in_array('/clientLog 0 t0 1', $callbacks, true)
        && in_array('/clientLogFile 0', $callbacks, true), 'view, grouping and export buttons');
    foreach ($callbacks as $cb) clCheck(strlen($cb) <= 64 && preg_match('~^/(?:clientLog 0(?: [tsd]\d{1,4} [01])?|clientLogFile 0|clientLogClear 0|userXr 0)$~', $cb) === 1, 'callback valid: ' . $cb);

    // Grouping by site.
    $b->clientLogView(0, 't', 0, true);
    $plain = html_entity_decode(strip_tags(end($b->screens)[0]), ENT_QUOTES);
    clCheck(str_contains($plain, 'cdninstagram.com ×8 (адресов: 2)') && str_contains($plain, 'fbcdn.net ×2 (адресов: 2)') && str_contains($plain, 'youtube.com ×6 (адресов: 2)'), 'same-day hosts of a site merged');

    // Sites and devices.
    $b->clientLogView(0, 's');
    $plain = html_entity_decode(strip_tags(end($b->screens)[0]), ENT_QUOTES);
    clCheck(strpos($plain, '×7  legacy.example.test') < strpos($plain, '×6  i.instagram.com') && strpos($plain, '×6  i.instagram.com') < strpos($plain, '×5  scontent-cdg4-1'), 'sites by hits');
    $b->clientLogView(0, 'd');
    $plain = html_entity_decode(strip_tags(end($b->screens)[0]), ENT_QUOTES);
    clCheck(str_contains($plain, '📱 Happ 2.6.1 · iOS 18.1 · iPhone15,2') && str_contains($plain, 'Chrome 131 (страница подписки в браузере) · Android 14'), 'apps with OS, version and model');
    clCheck(str_contains($plain, '🇷🇺 203.0.113.17 — Example ISP') && str_contains($plain, 'подписку с этого адреса брал: Chrome 131'), 'source addresses linked to apps');
    clCheck(str_contains($plain, 'Браузер и модель внутри VPN не видны'), 'limits stated');

    // Pages instead of truncation.
    $many = [];
    for ($n = 0; $n < 400; $n++) $many[] = ['email' => 'ivan', 'ip' => '198.51.100.40', 'dst' => "host-$n.example.test:443", 'ts' => $day3 + 120 + $n];
    $b->recordConnLog($many);
    $b->clientLogView(0);
    [$text, $rows] = end($b->screens);
    $nav = array_values(array_filter(array_merge(...$rows), static fn($btn) => preg_match('~^\d+/\d+$~', $btn['text'])));
    $total = (int) explode('/', $nav[0]['text'] ?? '1/1')[1];
    clCheck($total > 2, 'long log split into pages');
    $seen = [];
    for ($page = 0; $page < $total; $page++) {
        $b->clientLogView(0, 't', $page);
        $text = end($b->screens)[0];
        clCheck(mb_strlen(html_entity_decode(strip_tags($text), ENT_QUOTES)) < 4096, 'page fits Telegram: ' . $page);
        preg_match_all('~host-(\d+)\.example~', $text, $m);
        foreach ($m[1] as $id) $seen[$id] = ($seen[$id] ?? 0) + 1;
    }
    clCheck(count($seen) === 400 && max($seen) === 1, 'every entry on exactly one page');

    // Export: UTF-8, aligned columns, all entries, no control characters.
    $b->clientLogFile(0);
    [$data, $name, $mime] = end($b->files);
    clCheck(str_ends_with($name, '.txt') && str_contains($mime, 'charset=utf-8') && mb_check_encoding($data, 'UTF-8') && !preg_match('~[\x00-\x09\x0B-\x1F\x7F]~', $data), 'export is clean UTF-8 text');
    clCheck(!preg_match('~ \n~', $data) && !str_contains($data, "\r"), 'no trailing spaces, Unix line ends');
    clCheck(substr_count($data, '.example.test') >= 800 && str_contains($data, 'Happ 2.6.1') && str_contains($data, 'iPhone15,2') && str_contains($data, 'US Apple Inc.'), 'export has every entry, apps and owners');
    $lines = explode("\n", $data);
    $header = array_search(true, array_map(static fn($l) => str_starts_with($l, 'дата'), $lines), true);
    $hostColumn = mb_strwidth(mb_substr($lines[$header], 0, mb_strpos($lines[$header], 'адрес')));
    $aligned = true;
    for ($k = $header + 2; $lines[$k] !== ''; $k++) {
        $cells = preg_split('~ {2,}~', $lines[$k]);
        $start = mb_strwidth(mb_substr($lines[$k], 0, mb_strpos($lines[$k], $cells[4])));
        if ($start !== $hostColumn) $aligned = false;
    }
    clCheck($aligned && str_starts_with($lines[$header + 1], '----------'), 'timeline columns aligned under the header');
    $table = Bot::connLogTable(['имя', 'x'], [['Привет', 'a'], ['😀', 'b'], ['ab', 'c']]);
    $widths = array_map(static fn($l) => mb_strwidth(mb_substr($l, 0, mb_strrpos($l, ' ') + 1)), explode("\n", $table));
    clCheck(count(array_unique($widths)) === 1, 'Cyrillic and emoji padded by display width');
    $bad = ['email' => 'ivan', 'ip' => '198.51.100.40', 'dst' => "bad\xff\xfe.test:443", 'ts' => $day3];
    $b->recordConnLog([$bad]);
    $b->clientLogFile(0);
    clCheck(mb_check_encoding(end($b->files)[0], 'UTF-8'), 'invalid bytes from the access log never break the file');

    // English, clearing.
    $b->language = 'en';
    $b->clientLogView(0, 'd');
    clCheck(str_contains(end($b->screens)[0], 'Apps and devices') && str_contains(end($b->screens)[0], 'subscription page in a browser'), 'English view');
    $b->language = 'ru';
    $b->clientLogClear(0);
    clCheck($b->storeConnLogDays('ivan') === [] && $b->storeConnLogDays('other') !== [], 'clearing one user drops only its daily history');
    $b->setConnLog([]);
    clCheck($b->storeConnLogDays('other') === [], 'clearing the log drops all daily history');
    $b->clientLogView(0, 'd');
    clCheck(str_contains(end($b->screens)[0], 'Happ 2.6.1') && !str_contains(json_encode(end($b->screens)[1]), 'clientLogFile'), 'devices visible without traffic, no empty export');
} finally {
    foreach (glob("$root/*") ?: [] as $file) unlink($file);
    rmdir($root);
}
echo "connlog_view_test OK: $checks checks\n";
