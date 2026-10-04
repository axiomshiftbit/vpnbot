<?php
require_once __DIR__ . '/../app/bot.php';

class BackupReadinessBot extends Bot
{
    public function __construct(string $root) { $this->protocolRoot = $root; }
    public function getPacConf() { return []; }
    public function protocolModuleEnabled(string $service): bool { return $service === 'snolc'; }
}
class ImmediateBackupReadinessBot extends BackupReadinessBot
{
    protected const BACKUP_APPLY_TIMEOUT = 0;
}
function readinessCheck(bool $ok, string $message): void {
    if (!$ok) throw new RuntimeException($message);
}
function readinessRemove(string $path): void {
    if (is_dir($path)) {
        foreach (scandir($path) as $name) if ($name !== '.' && $name !== '..') readinessRemove("$path/$name");
        rmdir($path);
    } else unlink($path);
}
$root = sys_get_temp_dir() . '/vpnbot-backup-ready-' . bin2hex(random_bytes(6));
mkdir($root, 0700);
$writer = null;
try {
    $bot = new BackupReadinessBot($root);
    $store = $bot->protocolStore('snolc');
    $store->restore($store->snapshot());
    $state = $store->read();
    $runtime = $store->directory() . '/runtime';
    $snapshot = ['managed_protocols' => ['protocols' => ['snolc' => []]]];
    $ready = ['time' => time(), 'running' => true, 'revision' => $state['revision']];
    $usage = ['restored' => $state['restore_usage']['id']];
    ManagedProtocol::writeJson("$runtime/usage.json", $usage);
    // Холодное восстановление: последний контейнер в очереди запускается
    // позже прежнего десятисекундного срока. Нужен настоящий поздний статус.
    $writer = proc_open([PHP_BINARY, '-r',
        'sleep(11); $s=json_decode($argv[2],true); $s["time"]=time(); file_put_contents($argv[1],json_encode($s));',
        "$runtime/status.json", json_encode($ready)], [], $pipes);
    readinessCheck(is_resource($writer), 'Не запущен отложенный supervisor');
    readinessCheck($bot->verifyBackupServices($snapshot) === [], 'Холодный запуск не должен давать преждевременную ошибку');
    readinessCheck(proc_close($writer) === 0, 'Supervisor завершился с ошибкой');
    $writer = null;

    $bot = new ImmediateBackupReadinessBot($root);
    $ready['time'] = time();
    foreach ([
        'старая ревизия' => ['revision' => $state['revision'] - 1],
        'устаревший статус' => ['time' => time() - 30],
        'ошибка ядра' => ['error' => 'synthetic failure'],
        'остановленный процесс' => ['running' => false],
    ] as $name => $changes) {
        ManagedProtocol::writeJson("$runtime/status.json", array_replace($ready, $changes));
        readinessCheck($bot->verifyBackupServices($snapshot) === ['snolc'], "Не замечен отказ: $name");
    }
    ManagedProtocol::writeJson("$runtime/status.json", $ready);
    ManagedProtocol::writeJson("$runtime/usage.json", ['restored' => 'previous-restore']);
    readinessCheck($bot->verifyBackupServices($snapshot) === ['snolc'], 'Расход другого восстановления не подтверждает успех');
    ManagedProtocol::writeJson("$runtime/usage.json", $usage);
    ManagedProtocol::writeJson("$runtime/status.json", array_replace($ready, ['revision' => $state['revision'] + 1]));
    readinessCheck($bot->verifyBackupServices($snapshot) === [], 'Следующая ревизия cron с тем же восстановленным расходом уже применена');
    ManagedProtocol::writeJson("$runtime/status.json", array_replace($ready, ['running' => false, 'phase' => 'idle']));
    readinessCheck($bot->verifyBackupServices($snapshot) === [], 'Пустой протокол может быть применён без рабочего процесса');
    echo "backup_readiness_test OK\n";
} finally {
    if (is_resource($writer)) { proc_terminate($writer); proc_close($writer); }
    readinessRemove($root);
}
