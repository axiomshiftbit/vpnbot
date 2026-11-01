<?php
require_once __DIR__ . '/../app/bot.php';
class CheckpointBot extends Bot {
    public function __construct(public string $root) {}
    public function telemtQuotaPath(): string { return "$this->root/telemt.limit.json"; }
}
$root = sys_get_temp_dir() . '/telemt-checkpoint-' . bin2hex(random_bytes(6));
mkdir($root, 0700);
try {
    $b = new CheckpointBot($root);
    $native = ['last_reset_epoch_secs' => 10, 'users' => ['alice' => ['used_bytes' => 100, 'last_reset_epoch_secs' => 10,
        'quota_period' => 'daily', 'period_cursor_epoch_secs' => 20]]];
    $b->telemtQuotaWrite($native);
    $saved = $native; $saved['users']['alice']['used_bytes'] = 200;
    $saved['users']['alice']['period_cursor_epoch_secs'] = 15;
    $saved['users']['deleted'] = $saved['users']['alice'];
    file_put_contents("$root/telemt.checkpoint.json", json_encode($saved));
    $merged = $b->telemtQuotaRead([]);
    if ($merged['users']['alice']['used_bytes'] !== 200 || $merged['users']['alice']['period_cursor_epoch_secs'] !== 20 || isset($merged['users']['deleted'])) {
        throw new RuntimeException('Неверное объединение расхода для меню/backup');
    }
    $native['users']['alice']['last_reset_epoch_secs'] = $native['last_reset_epoch_secs'] = 30;
    $native['users']['alice']['used_bytes'] = 0;
    file_put_contents($b->telemtQuotaPath(), json_encode($native));
    if ($b->telemtQuotaRead([]) !== $native) throw new RuntimeException('Старый checkpoint отменил сброс ядра');
    $b->telemtQuotaWrite($native);
    if (file_exists("$root/telemt.checkpoint.json")) throw new RuntimeException('Restore оставил старый checkpoint');
} finally {
    foreach (glob("$root/*") as $file) unlink($file);
    rmdir($root);
}
echo "telemt_checkpoint_test OK (3)\n";
