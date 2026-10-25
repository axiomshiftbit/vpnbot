<?php
// Настоящий curl: короткий ответ и обрыв TCP нельзя выдавать за замер скорости.
require_once __DIR__ . '/../app/bot.php';
set_error_handler(static function ($level, $message, $file, $line) {
    if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line);
    return true;
});

class ExitSpeedTransferBot extends Bot
{
    public string $target = '';
    public function __construct() { $this->language = 'ru'; }
    public function getPacConf() { return ['exits' => ['abcdef12' => ['enabled' => 1]]]; }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
    {
        // Подменяется только конечная тестовая цель и локальный SOCKS.
        // Формат команды, curl, коды завершения и разбор — настоящий код бота.
        $cmd = str_replace([self::EXIT_SPEED_URL, '--socks5-hostname 127.0.0.1:10870', '--max-time 20'],
            [$this->target, '', str_ends_with($this->target, '/timeout') ? '--max-time 0.3' : '--max-time 5'], $cmd);
        $p = proc_open(['sh', '-c', $cmd], [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
        $out = stream_get_contents($pipes[1]); fclose($pipes[1]);
        $this->sshFailed = proc_close($p) !== 0;
        return $out;
    }
}

$failures = [];
$bot = new ExitSpeedTransferBot();
foreach (['complete', 'broken', 'short', 'empty', 'timeout', 'http-error'] as $case) {
    $server = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
    $address = stream_socket_get_name($server, false);
    $pid = pcntl_fork();
    if ($pid === -1) throw new RuntimeException('fork failed');
    if ($pid === 0) {
        try {
            for ($n = 0; $n < 2; $n++) {
                $client = @stream_socket_accept($server, 5);
                if (!$client) exit(1);
                stream_set_timeout($client, 1);
                while (($line = fgets($client)) !== false && trim($line) !== '') {}
                $size = match ($case) { 'short' => 1024, 'empty' => 0, default => Bot::EXIT_SPEED_BYTES };
                $status = $case === 'http-error' ? '503 Unavailable' : '200 OK';
                @fwrite($client, "HTTP/1.1 $status\r\nContent-Length: $size\r\nConnection: close\r\n\r\n");
                $remaining = in_array($case, ['broken', 'timeout', 'http-error'], true) ? 8192 : $size;
                while ($remaining > 0) {
                    $written = @fwrite($client, str_repeat('x', min(65536, $remaining)));
                    if (!$written) break;
                    $remaining -= $written;
                }
                if ($case === 'timeout') usleep(400000);
                fclose($client);
            }
        } catch (Throwable $e) { exit(1); }
        exit(0);
    }
    fclose($server);
    try {
        $bot->target = 'http://' . $address . '/' . $case;
        $r = $bot->exitSpeed('abcdef12');
        foreach (['node', 'direct'] as $way) {
            $expected = in_array($case, ['complete', 'timeout'], true);
            if (($r[$way]['ok'] ?? null) !== $expected) $failures[] = "$case/$way: неверный итог реального curl";
            if ($case === 'complete' && !($r[$way]['full'] ?? false)) $failures[] = "$case/$way: полный файл не получен";
            if ($case === 'timeout' && ($r[$way]['full'] ?? true)) $failures[] = "$case/$way: тайм-аут выдан за полный файл";
        }
        if ($case === 'timeout' && str_contains($bot->exitSpeedText($r), 'за 20 с')) $failures[] = 'подставлено выдуманное время загрузки';
    } finally {
        pcntl_waitpid($pid, $status);
        if (pcntl_wexitstatus($status) !== 0) $failures[] = "$case: ошибка тестового сервера";
    }
}
if ($failures) { fwrite(STDERR, implode("\n", $failures) . "\n"); exit(1); }
echo "exit_speed_transfer_test: OK (12 настоящих загрузок)\n";
