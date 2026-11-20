<?php
// Real Xray server/client and payload on loopback in an isolated container.
// SSH is replaced only by a local process transport. No production config.
require '/source/app/bot.php';
class NativeStatsBot extends Bot
{
    public string $fault = '';
    public function __construct() { $this->xrayConf = '/config/xray.json'; $this->language = 'en'; $this->protocolRoot = '/tmp/absent-protocols'; }
    public function getPacConf() { return ['language' => 'en', 'transport' => 'Websocket', 'xray_core' => 'origin'] + self::PAC_DEFAULTS; }
    public function notifyAdmins(string $text): void {}
    public function adguardXrayClients() {}
    public function deleteHwidUser($id) {}
    public function deleteWarpClient($email) {}
    public function xray($page = 0) {}
    public function ensureWgGuard(array &$c): void {} // fixture has only loopback, no WG network
    public function syncXrayNginxRoutes(array $xray): bool { return true; } // raw TCP fixture
    public function writePrivateKey(string $path, string $data): bool
    {
        if ($path === '/config/xray.stats' && $this->fault !== '') {
            $fault = $this->fault; $this->fault = '';
            if ($fault === 'after') parent::writePrivateKey($path, $data);
            return false;
        }
        return parent::writePrivateKey($path, $data);
    }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
    {
        $p = proc_open(['sh', '-c', $cmd], [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['file', '/tmp/native-command-errors', 'a']], $pipes);
        $out = stream_get_contents($pipes[1]); fclose($pipes[1]); $this->sshFailed = proc_close($p) !== 0; return $out;
    }
    protected function sshInputCommand(string $cmd, string $input, string $service): string
    {
        $p = proc_open(['sh', '-c', $cmd], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['file', '/tmp/native-command-errors', 'a']], $pipes);
        fwrite($pipes[0], $input); fclose($pipes[0]); $out = stream_get_contents($pipes[1]); fclose($pipes[1]);
        $this->sshFailed = proc_close($p) !== 0; return $out;
    }
    public function validateXrayConfig(array $config, string $binary = 'xray'): bool
    {
        file_put_contents('/tmp/validate.json', json_encode($config));
        exec('/usr/bin/xray run -test -c /tmp/validate.json >/tmp/validate.log 2>&1', $unused, $code); return $code === 0;
    }
    public function xrayCoreStarted(string $core): bool
    {
        for ($n = 0; $n < 80; $n++) {
            $h = @fsockopen('127.0.0.1', 12345, $errno, $message, .1);
            if ($h) { fclose($h); return true; } usleep(50000);
        }
        return false;
    }
}
function nativeCheck(bool $ok, string $label): void { global $checks; $checks[] = ['test' => $label, 'ok' => $ok]; }
function nativeProcess(array $command) { return proc_open($command, [0 => ['file', '/dev/null', 'r'], 1 => ['file', '/tmp/native-process.log', 'a'], 2 => ['file', '/tmp/native-process.log', 'a']], $pipes); }
function nativePayload(string $id): bool
{
    $profile = ['log' => ['loglevel' => 'error'], 'inbounds' => [['listen' => '127.0.0.1', 'port' => 10801, 'protocol' => 'socks', 'settings' => ['auth' => 'noauth']]],
        'outbounds' => [['protocol' => 'vless', 'settings' => ['vnext' => [['address' => '127.0.0.1', 'port' => 12345, 'users' => [['id' => $id, 'encryption' => 'none']]]]],
            'streamSettings' => ['network' => 'tcp', 'security' => 'none']]]];
    file_put_contents('/tmp/client.json', json_encode($profile));
    $p = nativeProcess(['/tmp/ledger-client', 'run', '-c', '/tmp/client.json']);
    try {
        $ready = false; $deadline = microtime(true) + 3;
        while (microtime(true) < $deadline) {
            if (!proc_get_status($p)['running']) throw new RuntimeException('Synthetic client exited before readiness');
            $socket = @fsockopen('127.0.0.1', 10801, $errno, $message, .05);
            if ($socket) { fclose($socket); $ready = true; break; }
            usleep(20000);
        }
        // A failed client startup must not count as successful access revocation.
        if (!$ready) throw new RuntimeException('Synthetic client readiness timeout');
        $c = curl_init('http://127.0.0.1:18080/payload');
        curl_setopt_array($c, [CURLOPT_RETURNTRANSFER => true, CURLOPT_PROXY => '127.0.0.1:10801', CURLOPT_PROXYTYPE => CURLPROXY_SOCKS5_HOSTNAME,
            CURLOPT_NOPROXY => '', CURLOPT_TIMEOUT => 2]);
        $data = curl_exec($c); curl_close($c); return $data === str_repeat('synthetic-ledger-payload', 256);
    } finally { proc_terminate($p); proc_close($p); usleep(50000); }
}
function nativePid(): string { return trim((string) shell_exec('pgrep -x xray')); }
$checks = []; $http = null; $bot = new NativeStatsBot();
try {
    copy('/usr/bin/xray', '/tmp/ledger-client'); chmod('/tmp/ledger-client', 0700);
    file_put_contents('/tmp/http.php', '<?php $s=stream_socket_server("tcp://127.0.0.1:18080"); while($c=stream_socket_accept($s,-1)){fgets($c);$b=str_repeat("synthetic-ledger-payload",256);fwrite($c,"HTTP/1.1 200 OK\r\nContent-Length: ".strlen($b)."\r\nConnection: close\r\n\r\n".$b);fclose($c);}');
    $http = nativeProcess([PHP_BINARY, '/tmp/http.php']);
    $ids = ['00000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000002'];
    $config = ['log' => ['loglevel' => 'error'], 'inbounds' => [['tag' => 'main', 'listen' => '127.0.0.1', 'port' => 12345, 'protocol' => 'vless',
        'settings' => ['decryption' => 'none', 'clients' => [['id' => $ids[0], 'email' => 'limited', 'traffic' => 1073741824], ['id' => $ids[1], 'email' => 'unlimited']]],
        'streamSettings' => ['network' => 'tcp', 'security' => 'none']]],
        'outbounds' => [['tag' => 'direct', 'protocol' => 'freedom', 'settings' => ['finalRules' => [['action' => 'allow', 'ip' => ['127.0.0.1/32']]]]]], 'routing' => ['rules' => []]];
    file_put_contents('/xray.json', json_encode($config)); $bot->setXrayStats([]);
    $started = $bot->restartXray($config) === true;
    nativeCheck($started, 'actual core accepts synthetic seed');
    if (!$started) throw new RuntimeException('Synthetic seed failed');
    nativeCheck(nativePayload($ids[0]), 'limited profile transfers payload before ledger loss');
    nativeCheck(nativePayload($ids[1]), 'unlimited profile transfers payload before ledger loss');
    $bot->xrayStatsUser();
    nativeCheck($bot->xrUserTraffic($bot->getXrayStats(), 0) > 0, 'actual core counters reach ledger');
    file_put_contents('/config/xray.stats', '{'); $bot->checkTrafficLimits();
    nativeCheck(!nativePayload($ids[0]), 'corrupt ledger revokes limited profile in actual core');
    nativeCheck(nativePayload($ids[1]), 'corrupt ledger preserves independent unlimited profile');
    foreach (['before', 'after'] as $fault) {
        $bot->fault = $fault; $failed = false;
        try { $bot->resetXrStats(true); } catch (Throwable $e) { $failed = true; }
        nativeCheck($failed && !nativePayload($ids[0]), "failed reset $fault rename cannot restore actual access");
    }
    $bot->resetXrStats(true);
    nativeCheck(nativePayload($ids[0]), 'confirmed reset restores original profile payload');
    $bot->time_xray_stats = 0; $bot->xrayStatsUser(); $beforePid = nativePid();
    $bot->resetXrStats(true);
    nativeCheck($beforePid !== '' && nativePid() !== $beforePid, 'active-user reset bypasses hot apply and restarts actual counters');
    $bot->time_xray_stats = 0; $bot->xrayStatsUser();
    nativeCheck($bot->xrUserTraffic($bot->getXrayStats(), 0) === 0, 'new period does not resurrect the old core session');
    unlink('/config/xray.stats');
    nativeCheck($bot->delxr(1, false) === true && !nativePayload($ids[1]), 'missing ledger cannot prevent actual unlimited revocation');
} catch (Throwable $error) { nativeCheck(false, 'fixture failure: ' . get_class($error) . ' line ' . $error->getLine()); }
finally {
    $bot->ssh('pkill xray || true');
    if (is_resource($http)) { proc_terminate($http); proc_close($http); }
}
$passed = count(array_filter($checks, fn($r) => $r['ok']));
echo json_encode(['suite' => 'xray_stats_native', 'passed' => $passed, 'total' => count($checks), 'checks' => $checks]) . "\n";
exit($passed === count($checks) ? 0 : 1);
