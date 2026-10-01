<?php
require_once __DIR__ . '/../app/bot.php';
function stageCheck(bool $ok, string $name): void { if (!$ok) throw new RuntimeException($name); }
class ProxyStagingBot extends Bot {
    public array $commands = [];
    public array $candidates = [];
    public int $chunks = 0;
    public int $failChunk = 0;
    public bool $valid = true;
    public bool $applied = true;
    public function __construct(public string $root) { $this->protocolNginxFile = "$root/nginx.conf"; $this->upstreamFile = "$root/upstream.conf"; }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') {
        $this->commands[] = $cmd;
        if (strlen($cmd) > 32768) throw new RuntimeException('SSH exec exceeded packet size');
        $cmd = str_replace(['/etc/nginx/protocol-validation-', '/tmp/upstream-'], ["$this->root/protocol-validation-", "$this->root/upstream-"], $cmd);
        if (str_contains($cmd, 'VPNBOT_STAGED')) {
            if (++$this->chunks === $this->failChunk) return '';
            $out = []; exec($cmd, $out, $code);
            return $code === 0 ? implode("\n", $out) : '';
        }
        if (preg_match('~nginx -t -c (\S+)~', $cmd, $match)) {
            $this->candidates[] = file_get_contents($match[1]);
            stageCheck((fileperms($match[1]) & 0777) === 0600, 'Временный файл закрыт от посторонних');
            return $this->valid ? 'VPNBOT_VALID' : '';
        }
        if (str_starts_with($cmd, 'rm -f -- ')) { exec($cmd); return ''; }
        return $this->applied ? 'VPNBOT_APPLIED' : '';
    }
}
$root = sys_get_temp_dir() . '/vpnbot-staging-' . bin2hex(random_bytes(6)); mkdir($root, 0700);
try {
    $b = new ProxyStagingBot($root);
    // Больше реального рабочего конфига; кавычки, $, UTF-8 и переводы строк должны сохраниться.
    $original = str_repeat("# Кириллица ' \" \$arg_secret ; `literal`\n", 2500)
        . "http {\n server {\n  listen 10.10.0.2:443 ssl proxy_protocol default_server;\n }\n}\n";
    file_put_contents($b->protocolNginxFile, $original);
    $b->prepareProtocolSelfHost();
    $expected = str_replace("  listen 10.10.0.2:443 ssl proxy_protocol default_server;\n", "  listen 10.10.0.2:443 ssl proxy_protocol default_server;\n  listen 10.10.0.2:10443 ssl default_server;\n", $original);
    stageCheck($b->chunks > 4 && $b->candidates === [$expected] && file_get_contents($b->protocolNginxFile) === $expected, 'Большой конфиг передан целиком без изменения байтов');
    stageCheck(!glob("$root/protocol-validation-*"), 'Успешная проверка удаляет временный файл');
    $calls = count($b->commands); $b->prepareProtocolSelfHost();
    stageCheck(count($b->commands) === $calls, 'Повторная подготовка идемпотентна');
    foreach (['chunk', 'validation', 'reload'] as $failure) {
        $b = new ProxyStagingBot($root);
        file_put_contents($b->protocolNginxFile, $original);
        if ($failure === 'chunk') $b->failChunk = 2;
        if ($failure === 'validation') $b->valid = false;
        if ($failure === 'reload') $b->applied = false;
        try { $b->prepareProtocolSelfHost(); throw new LogicException('Ожидался отказ'); } catch (RuntimeException $e) {}
        stageCheck(file_get_contents($b->protocolNginxFile) === $original, "$failure: рабочий конфиг сохранён");
        stageCheck(!glob("$root/protocol-validation-*"), "$failure: временный файл удалён");
        if ($failure === 'chunk') stageCheck(!$b->candidates, 'Оборванная передача не проходит валидацию');
    }
    $b = new ProxyStagingBot($root);
    file_put_contents($b->upstreamFile, '# old');
    stageCheck($b->editUpstream(fn($old) => $original) && $b->candidates === [$original], 'Upstream использует ту же передачу большого конфига');
    stageCheck(!glob("$root/upstream-*.conf"), 'Временный upstream удалён');
    echo "proxy_config_staging_test OK\n";
} finally {
    foreach (glob("$root/*") as $path) unlink($path);
    rmdir($root);
}
