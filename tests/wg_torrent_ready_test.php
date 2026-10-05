<?php
require_once __DIR__ . '/../app/bot.php';

class WgTorrentReadyBot extends Bot
{
    public string $bin;
    public string $rules = '';
    public bool $fail = false;
    public string $service = '';
    public function __construct() {}
    public function getPacConf() { return []; }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
    {
        $this->service = $service;
        $env = getenv(); $env['PATH'] = $this->bin . ':' . $env['PATH'];
        $env['VPNBOT_TEST_RULES'] = $this->rules;
        $p = proc_open(['sh', '-c', $cmd], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'a']], $pipes, null, $env);
        fclose($pipes[0]); $out = stream_get_contents($pipes[1]); fclose($pipes[1]); proc_close($p);
        $this->sshFailed = $this->fail;
        return $out;
    }
}

$tmp = sys_get_temp_dir() . '/vpnbot-ipp2p-' . bin2hex(random_bytes(6)); mkdir($tmp, 0700);
file_put_contents($tmp . '/iptables', "#!/bin/sh\nprintf '%s\n' \"\$VPNBOT_TEST_RULES\"\n"); chmod($tmp . '/iptables', 0700);
$b = new WgTorrentReadyBot(); $b->bin = $tmp; $checks = 0;
$check = function ($ok, $name) use (&$checks) { $checks++; if (!$ok) throw new RuntimeException($name); };
$rules = [];
foreach (['FORWARD', 'OUTPUT'] as $chain) foreach (['tcp', 'udp'] as $protocol) $rules[] = "-A $chain -p $protocol -m ipp2p --bit  -j DROP";
try {
    $check(!$b->wgTorrentRulesReady(), 'Пустая таблица не означает действующую блокировку');
    foreach ([0, 1] as $wg) {
        $b->wg = $wg;
        $b->rules = implode("\n", $rules);
        $check($b->wgTorrentRulesReady(), 'Все четыре правила, включая двойные пробелы ipp2p');
        $check($b->service === ($wg ? 'wg1' : 'wg'), 'Проверяется выбранный контейнер');
        foreach (array_keys($rules) as $missing) {
            $remaining = $rules; unset($remaining[$missing]); $b->rules = implode("\n", $remaining);
            $check(!$b->wgTorrentRulesReady(), 'Отсутствие любого правила обнаруживается');
        }
    }
    foreach (['ACCEPT', 'REJECT'] as $target) {
        $b->rules = str_replace('DROP', $target, implode("\n", $rules));
        $check(!$b->wgTorrentRulesReady(), 'Другие действия не считаются правилами блокировки');
    }
    $b->rules = implode("\n", array_merge($rules, $rules));
    $check($b->wgTorrentRulesReady(), 'Дубли старой версии не скрывают наличие всех правил');
    $b->fail = true;
    $check(!$b->wgTorrentRulesReady(), 'При ошибке SSH нельзя подтверждать готовность');
} finally {
    unlink($tmp . '/iptables'); rmdir($tmp);
}
echo "wg_torrent_ready_test: $checks проверок OK\n";
