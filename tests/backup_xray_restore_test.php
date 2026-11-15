<?php
require_once __DIR__ . '/../app/bot.php';
define('BACKUP_CORE_ROOT', sys_get_temp_dir() . '/vpnbot-backup-core-' . bin2hex(random_bytes(6)));
mkdir(BACKUP_CORE_ROOT, 0700);
register_shutdown_function(static function () { @unlink(BACKUP_CORE_ROOT . '/xray.json.apply.lock'); @rmdir(BACKUP_CORE_ROOT); });
class BackupCoreBot extends Bot {
    public string $desired = 'origin2';
    public string $active = 'origin';
    public string $marker = 'origin';
    public string $stored = '{"previous":true}';
    public string $fail = '';
    public array $validated = [];
    public function __construct() { $this->xrayConf = BACKUP_CORE_ROOT . '/xray.json'; }
    public function getPacConf() { return ['xray_core'=>$this->desired,'smux'=>['enabled'=>false]]; }
    public function protocolModuleEnabled(string $service): bool { return $this->fail !== 'disabled'; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
    public function xrayCoreProbe(bool $fresh = false): array { return ['ok'=>true,'selection'=>$this->active]; }
    public function validateXrayConfig(array $config, string $binary = 'xray'): bool { $this->validated[]=$binary; return $this->fail !== 'validate'; }
    public function readXrayJson(): string { return $this->stored; }
    public function writeXrayJson(string $json): bool { $this->stored=$json; return true; }
    public function writeCoreMarker(string $core): bool { $this->marker=$core; return true; }
    public function restartXray($c, $norestart = false) { $this->stored=json_encode($c); return $this->fail !== 'restart'; }
    public function xrayCoreStarted(string $core): bool { return $this->fail !== 'start'; }
    public function ssh($cmd, $service='wg', $wait=true, $log='/dev/null') {
        if (preg_match('~^ln -sf (\S+) ~',$cmd,$m)) {
            if ($this->fail==='link') return '';
            $this->active=array_search($m[1],self::XRAY_BINARIES,true); return 'XRAY_LINK_OK';
        }
        return '';
    }
}
function coreBackupCheck(bool $ok,string $name): void { if (!$ok) throw new RuntimeException($name); }
foreach (array_keys(Bot::XRAY_BINARIES) as $core) {
    $b=new BackupCoreBot;$b->desired=$core;
    coreBackupCheck($b->restoreBackupXray(['restored'=>true]),"$core: восстановление");
    coreBackupCheck($b->active===$core && $b->marker===$core && $b->validated===[Bot::XRAY_BINARIES[$core]],"$core: проверено выбранное ядро, выбор сохранён");
    coreBackupCheck($b->getPacConf()['smux']['enabled']===false,'Восстановление не включает SMUX автоматически');
}
foreach (['validate','link','restart','start'] as $failure) {
    $b=new BackupCoreBot;$b->fail=$failure;
    coreBackupCheck(!$b->restoreBackupXray(['restored'=>true]),"$failure: видимый отказ");
    coreBackupCheck($b->active==='origin' && $b->marker==='origin' && $b->stored==='{"previous":true}',"$failure: прежнее ядро и конфигурация сохранены");
}
$b=new BackupCoreBot;$b->fail='disabled';
coreBackupCheck($b->restoreBackupXray(['restored'=>true]) && !$b->validated && $b->marker==='origin2','Выключенный контейнер: настройки сохранены без запуска');
echo "backup_xray_restore_test OK\n";
