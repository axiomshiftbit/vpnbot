<?php
// WEB-03 (аудит A): polling() не пишет в журнал сырой description ответа Bot
// API (там может быть отражённый URL запроса или токен). Как и request(), в
// журнал попадают только код ошибки. Транспорт подменён; маркер синтетический.
require_once __DIR__ . '/../app/bot.php';

class PollingStop extends Exception {}
class PollingLogBot extends Bot {
    public int $n = 0;
    public function __construct() {}
    public function request($method, $data, $json_header = 0) {
        if ($this->n++ === 0) return ['ok' => false, 'error_code' => 502, 'description' => 'SYNTHETIC_PRIVATE_RESPONSE_MARKER bot123:SECRET'];
        throw new PollingStop();
    }
}
$log = sys_get_temp_dir() . '/vpnbot-polling-log-' . bin2hex(random_bytes(6));
ini_set('log_errors', '1'); ini_set('display_errors', '0'); ini_set('error_log', $log);
$failed = 0; $count = 0;
$check = static function (bool $ok, string $what) use (&$failed, &$count) { $count++; if (!$ok) { $failed++; echo "FAIL: $what\n"; } };
// sleep(3) после ошибки: в тесте не ждём.
try { (new PollingLogBot())->polling(); } catch (PollingStop) {}
$text = (string) @file_get_contents($log);
@unlink($log);
$check(!str_contains($text, 'SYNTHETIC_PRIVATE_RESPONSE_MARKER') && !str_contains($text, 'SECRET'), 'description ответа API не попадает в журнал');
$check(str_contains($text, 'getUpdates') && str_contains($text, '502'), 'в журнале остаются метод и код ошибки');
echo "polling_error_logging_test: " . ($count - $failed) . "/$count\n";
exit($failed ? 1 : 0);
