<?php
require_once __DIR__ . '/../app/bot.php';
class MetadataSyncBot extends Bot {
    public array $synced = [];
    public function __construct(string $path) { $this->xrayConf = $path; }
    public function ensureWgGuard(array &$c): void {}
    public function ensureFreedomCompat(array &$c): void {}
    protected function tryXrayHotApply(array $previous, array $target, string $action = 'apply'): bool {
        $this->synced[] = [$previous, $target, $action];
        return true;
    }
}
$path = tempnam(sys_get_temp_dir(), 'xray-metadata-');
try {
    $before = ['inbounds' => [['settings' => ['clients' => [['id' => 'fixture', 'hwid_limit' => 1]]]]], 'stats' => new stdClass()];
    file_put_contents($path, json_encode($before));
    $b = new MetadataSyncBot($path);
    $after = $b->getXray(); $after['inbounds'][0]['settings']['clients'][0]['hwid_limit'] = 2;
    $b->saveXray($after);
    if (count($b->synced) !== 1 || $b->synced[0][2] !== 'sync'
        || $b->synced[0][0]['inbounds'][0]['settings']['clients'][0]['hwid_limit'] !== 1
        || $b->synced[0][1]['inbounds'][0]['settings']['clients'][0]['hwid_limit'] !== 2) {
        throw new RuntimeException('Правка HWID оставила маркер горячего применения на старом конфиге');
    }
} finally {
    unlink($path);
    if (is_file($path . '.apply.lock')) unlink($path . '.apply.lock');
}
echo "xray_metadata_sync_test OK\n";
