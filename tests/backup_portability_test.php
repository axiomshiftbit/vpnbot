<?php
require __DIR__ . '/../app/bot.php';

class PortableBackupBot extends Bot {
    public function __construct(string $root) {
        $this->pac = "$root/pac.json";
        $this->managedNodeRoot = "$root/nodes";
        $this->backupWarpRoot = "$root/warp";
        $this->language = 'ru';
    }
}

$root = sys_get_temp_dir() . '/vpnbot-backup-portable-' . bin2hex(random_bytes(6));
mkdir($root, 0700);
function rejectPortable(PortableBackupBot $bot, array $backup): void {
    try { $bot->validateBackup($backup); }
    catch (InvalidArgumentException $error) { return; }
    throw new RuntimeException('Incomplete or oversized backup accepted');
}
try {
    $bot = new PortableBackupBot($root);
    $node = ['pac' => ['managed_nodes' => ['aabbccdd' => ['connected' => true]]]];
    rejectPortable($bot, $node);
    $files = ['nodes/aabbccdd/key' => base64_encode('synthetic-private-material'),
        'nodes/aabbccdd/key.pub' => base64_encode('synthetic-public-material')];
    rejectPortable($bot, $node + ['extra_files' => $files]);
    $disconnected = $node;
    $disconnected['pac']['managed_nodes']['aabbccdd']['connected'] = false;
    $bot->validateBackup($disconnected + ['extra_files' => $files]);
    $files['nodes/aabbccdd/endpoint.json'] = base64_encode('{"synthetic":true}');
    $files['nodes/aabbccdd/snapshot.json'] = base64_encode('{"synthetic":true}');
    $bot->validateBackup($node + ['extra_files' => $files]);
    $large = [];
    foreach (['ss.acl', 'telemt/decoy/index.html', 'telemt/decoy/loading.css', 'webapp/override.html'] as $name) {
        $large[$name] = base64_encode(str_repeat('x', 4 * 1024 * 1024));
    }
    rejectPortable($bot, ['extra_files' => $large]);
    $bot->validateBackup(['pac' => ['language' => 'ru']]);
    echo "backup_portability_test OK\n";
} finally { rmdir($root); }
