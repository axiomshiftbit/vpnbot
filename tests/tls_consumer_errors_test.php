<?php
// Ошибки потребителей сертификата доходят до вызывающего кода; runtime отдельно.
require __DIR__ . '/../app/bot.php';

class TlsConsumerBot extends Bot
{
    public array $conf = ['domain' => 'tls.example.test', 'adpswd' => 'synthetic-only', 'telemt_web' => 1];
    public bool $writeOk = true;
    public bool $moduleOn = true;
    public bool $restartOk = true;
    public bool $transportFailed = false;
    public bool $disableWeb = false;
    public int $starts = 0;
    public array $written = [];
    public function __construct(string $path) { $this->pac = $path; }
    public function getPacConf() { return $this->conf; }
    public function setPacConf(array $conf) { $this->conf = $conf; return true; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
    public function nginxGetTypeCert() { return 'letsencrypt'; }
    public function adguardConf(): ?array { return ['dns' => ['upstream_dns' => ['tls://resolver.example.test']], 'tls' => ['enabled' => false]]; }
    public function adguardWrite(array $c): bool { if ($this->writeOk) $this->written = $c; return $this->writeOk; }
    public function stopAd() {}
    public function startAd() { $this->starts++; }
    public function protocolModuleEnabled(string $module): bool { return $this->moduleOn; }
    public function restartTelemt() {
        $this->sshFailed = $this->transportFailed;
        if ($this->disableWeb) $this->conf['telemt_web'] = 0;
        return $this->restartOk ? null : false;
    }
}
$root = sys_get_temp_dir() . '/vpnbot-tls-consumer-' . bin2hex(random_bytes(6));
mkdir($root, 0700);
$bot = new TlsConsumerBot("$root/pac.json");
$checks = 0;
try {
    $bot->adguardSync();
    if ($bot->starts !== 1 || $bot->written['dns']['upstream_dns'] !== ['tls://resolver.example.test']) throw new RuntimeException('DNS control failed');
    $checks++;
    $bot->writeOk = false;
    try { $bot->adguardSync(); throw new LogicException('DNS write failure swallowed'); }
    catch (RuntimeException $error) { $checks++; }
    if ($bot->starts !== 2) throw new RuntimeException('DNS did not restart after write failure');
    $checks++;
    $bot->telemtWebSync(); $checks++;
    foreach (['restartOk', 'transportFailed', 'disableWeb'] as $fault) {
        $bot->conf['telemt_web'] = 1;
        $bot->$fault = $fault !== 'restartOk';
        try { $bot->telemtWebSync(); throw new LogicException('TeleMT failure swallowed'); }
        catch (RuntimeException $error) { $checks++; }
        $bot->$fault = $fault === 'restartOk';
    }
    $bot->moduleOn = false; $bot->transportFailed = true; $bot->conf['telemt_web'] = 1;
    $bot->telemtWebSync(); $checks++;
} finally {
    foreach (glob("$root/*") ?: [] as $file) unlink($file);
    foreach (glob("$root/.*lock") ?: [] as $file) unlink($file);
    rmdir($root);
}
echo "tls_consumer_errors_test: $checks проверок OK\n";
