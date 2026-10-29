<?php
require_once __DIR__ . '/../app/bot.php';
set_error_handler(static function ($n, $s, $f, $l) { if (error_reporting() & $n) throw new ErrorException($s, 0, $n, $f, $l); return true; });
class ParallelExitBot extends Bot {
    public array $nodes = [], $status = [], $commands = [];
    public string $bin = '';
    public bool $truncate = false;
    public function __construct() {}
    public function getPacConf() { return ['exits' => $this->nodes]; }
    public function exitStatus(): array { return $this->status; }
    protected function exitStatusWrite(string $id, array $status): void { $this->status[$id] = $status; }
    protected function exitIpv6Network(): array { return []; }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') {
        $this->commands[] = $cmd; $this->sshFailed = false;
        if ($this->truncate) return "BEGIN aaaaaaa0\nprobe=204 0.1\n";
        $process = proc_open(['/bin/sh', '-c', 'PATH=' . escapeshellarg($this->bin) . ':"$PATH"; ' . $cmd], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        $out = stream_get_contents($pipes[1]); $err = stream_get_contents($pipes[2]); fclose($pipes[1]); fclose($pipes[2]);
        if (proc_close($process) !== 0 || $err !== '') throw new RuntimeException('fixture shell failed');
        return $out;
    }
}
$checks = 0;
$check = static function ($ok, $message) use (&$checks) { ++$checks; if (!$ok) throw new RuntimeException($message); };
$dir = sys_get_temp_dir() . '/exit-parallel-' . bin2hex(random_bytes(6)); mkdir($dir, 0700);
try {
    file_put_contents($dir . '/curl', <<<'SH'
#!/bin/sh
case " $* " in
 *generate_204*) printf 'probe=204 0.010' ;;
 *cdn-cgi/trace*) printf 'ip=203.0.113.10\nloc=ZZ\n' ;;
 *youtube.com*) printf '"INNERTUBE_CONTEXT_GL":"ZZ"\n' ;;
 *) exit 1 ;;
esac
SH
    ); chmod($dir . '/curl', 0700);
    $bot = new ParallelExitBot(); $bot->bin = $dir;
    $link = 'vless://11111111-1111-4111-8111-111111111111@node.example.org:443?security=tls&sni=node.example.org&type=tcp&encryption=none';
    $requests = [];
    for ($i = 0; $i < 6; ++$i) { $id = 'aaaaaaa' . $i; $bot->nodes[$id] = ['link' => $link]; $requests[$id] = $i % 2 === 0; }
    $out = $bot->exitProbeMany($requests);
    $check(count($bot->commands) === 2, 'Шесть узлов проверяются двумя пакетами, максимум четыре одновременно');
    foreach ($out as $id => $s) {
        $check($s['ok'] && $s['ip'] === '203.0.113.10', 'Результат собственного процесса привязан к узлу');
        $check(isset($s['full']) === $requests[$id] && isset($s['gl']) === $requests[$id], 'Полная и краткая проверка не смешиваются');
        $check(count($bot->status[$id]['hist']) === 1, 'Одна запись истории на пробу');
    }
    $check(substr_count($bot->commands[0], '2>/dev/null & ') === 4, 'Четыре отдельных процесса первой партии');
    $check(!str_contains($bot->commands[0], '11111111-1111'), 'Ключ подключения не передаётся командой');
    $check(!glob('/tmp/vpnbot-exit-probe.*'), 'Временные результаты удалены');
    $bot->truncate = true; $out = $bot->exitProbeMany($requests);
    foreach ($out as $s) $check(!$s['ok'] && $s['error'] === 'xray', 'Оборванный пакет не выдаёт ложный успех');
    foreach ($bot->status as $s) $check(!$s['ok'] && count($s['hist']) === 2, 'Ошибка SSH обновляет историю и не оставляет старый зелёный статус');
} finally { unlink($dir . '/curl'); rmdir($dir); }
echo "exit_probe_parallel_test: $checks OK\n";
