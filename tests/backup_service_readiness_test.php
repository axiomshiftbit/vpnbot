<?php
require_once __DIR__ . '/../app/bot.php';
class BackupReadinessBot extends Bot {
    public array $commands = [], $pacState = [];
    public bool $ready = true, $transportFailed = false;
    public function __construct() {}
    public function getPacConf() { return $this->pacState; }
    public function protocolModuleEnabled(string $service): bool { return true; }
    public function getStlsConfig() { return ['Enabled' => 1]; }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') {
        $this->commands[] = [$service, $cmd]; $this->sshFailed = $this->transportFailed;
        // A PID without supervisor readiness is not proof of service health.
        return str_contains($cmd, '/service_supervisor.sh status ') && $this->ready ? 'VPNBOT_SERVICE_READY' : '';
    }
}
$b = new BackupReadinessBot();
$input = ['ss' => ['server_port' => 8388], 'sl' => ['local_port' => 1080], 'ad' => ['dns' => []],
    'cloak' => ['Enabled' => 1], 'extra_files' => ['stlsserver.json' => base64_encode('{}')]];
if ($b->verifyBackupServices($input) !== [] || count($b->commands) !== 5) throw new RuntimeException('Supervised protocol readiness is required');
foreach ($b->commands as [$service, $command]) if (str_contains($command, 'pgrep')) throw new RuntimeException('PID-only check must not confirm restore');
$b->ready = false;
if (count($b->verifyBackupServices($input)) !== 5) throw new RuntimeException('Missing listeners must fail all five restores');
$b->ready = true; $b->transportFailed = true;
if (count($b->verifyBackupServices($input)) !== 5) throw new RuntimeException('Marker on failed SSH must not confirm restore');
$b->transportFailed = false; $b->commands = [];
if ($b->verifyBackupServices(['pac' => []]) !== [] || count($b->commands) !== 2) throw new RuntimeException('Empty Naive/DNSTT credentials require confirmed off');
foreach ($b->commands as [$service, $command]) if (!str_contains($command, '-eq 3')) throw new RuntimeException('Unknown status is not intentional off');
echo "backup_service_readiness_test OK\n";
