<?php
// php healthcheck = /start marker; nginx, Xray, WireGuard, AdGuard... start only
// after php is healthy. polling() wrote the marker when Telegram answered or was
// unreachable, but never when Telegram answered with an error (401 revoked or
// invalid token, 409 another poller with the same token, 429): after a restart
// the whole VPN stack stayed down because of a Telegram-side error.
require_once __DIR__ . '/../app/bot.php';

class StopPolling extends Exception {}
class PollingBot extends Bot
{
    public array $replies = []; public int $calls = 0;
    public function __construct(public string $marker) { $this->api = 'https://127.0.0.1:9/bot'; if (property_exists($this, 'startMarker')) $this->startMarker = $marker; }
    public function request($method, $data, $json_header = 0)
    {
        if (!$this->replies) throw new StopPolling();
        $this->calls++;
        return array_shift($this->replies);
    }
    public function input($data = false) {}
}
// sleep() inside polling() would slow the test down; the replies queue ends it.
$failed = 0; $count = 0;
$check = static function (bool $ok, string $what) use (&$failed, &$count) { $count++; if (!$ok) { $failed++; echo "FAIL: $what\n"; } };
$root = sys_get_temp_dir() . '/vpnbot-polling-' . bin2hex(random_bytes(4));
mkdir($root, 0700);
ini_set('error_log', "$root/php.log");
try {
    foreach ([
        '401 revoked token' => ['ok' => false, 'error_code' => 401, 'description' => 'Unauthorized'],
        '409 another poller' => ['ok' => false, 'error_code' => 409, 'description' => 'Conflict: terminated by other getUpdates request'],
        'unreachable' => false,
        'answered' => ['ok' => true, 'result' => []],
    ] as $case => $reply) {
        $marker = "$root/start-" . md5($case);
        $b = new PollingBot($marker);
        $b->replies = [$reply];
        try { $b->polling(); } catch (StopPolling $e) {}
        $check(is_file($marker), "$case: php reports alive (/start), the VPN stack can start");
    }
    $check(!str_contains((string) @file_get_contents("$root/php.log"), 'Unauthorized'), 'error text of Telegram is not logged');
} finally {
    exec('rm -rf ' . escapeshellarg($root));
}
echo "polling_start_marker_test: " . ($count - $failed) . "/$count\n";
exit($failed ? 1 : 0);
