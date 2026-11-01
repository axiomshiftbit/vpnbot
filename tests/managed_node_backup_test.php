<?php
require_once __DIR__ . '/../app/bot.php';
class NodeBackupFixture extends Bot {
    public array $state = [];
    public function __construct(string $root) {
        $this->pac = "$root/config/pac.json"; $this->htpasswd = "$root/webapp/.htpasswd";
        $this->telemtDecoyDir = "$root/decoy"; $this->backupWarpRoot = "$root/warp";
        $this->managedNodeRoot = "$root/nodes";
    }
    public function getPacConf() { return $this->state; }
    public function setPacConf(array $state) { $this->state = $state; return true; }
    public function managedNodeBackupRefresh(): void {} // Offline restore must use the last confirmed snapshot.
}
$root = sys_get_temp_dir().'/managed-backup-'.bin2hex(random_bytes(6));
mkdir($root, 0700);
$checks = 0;
$check = static function ($ok, $name) use (&$checks) { $checks++; if (!$ok) throw new RuntimeException('FAIL '.$name); };
$remove = static function ($path) use (&$remove) {
    if (is_dir($path) && !is_link($path)) { foreach (scandir($path) as $name) if ($name !== '.' && $name !== '..') $remove("$path/$name"); rmdir($path); }
    else unlink($path);
};
try {
    $bot = new NodeBackupFixture($root.'/source');
    $bot->state = ['managed_nodes' => ['aabbccdd' => ['name' => 'fixture', 'connected' => true]]];
    $directory = $bot->managedNodeRoot.'/aabbccdd'; mkdir($directory, 0700, true);
    $contents = ['key' => "PRIVATE-TEST-FIXTURE\n", 'key.pub' => "PUBLIC-TEST-FIXTURE\n",
        'endpoint.json' => '{"address":"1.1.1.1","port":22,"host_key":"TEST"}',
        'snapshot.json' => '{"schema":1,"fixture":"confirmed"}'];
    foreach ($contents as $name => $body) { file_put_contents("$directory/$name", $body); chmod("$directory/$name", 0600); }
    $backup = $bot->backupExtraFiles();
    $check(count($backup) === 4, 'all controller and node state files included');
    $destination = new NodeBackupFixture($root.'/restored');
    // Extra files are restored before PAC metadata in the existing importer.
    $destination->restoreBackupExtraFiles($backup);
    foreach ($contents as $name => $body) {
        $path = $destination->managedNodeRoot.'/aabbccdd/'.$name;
        $check(file_get_contents($path) === $body && (fileperms($path) & 0777) === 0600, 'private file restored '.$name);
    }
    $check((fileperms($destination->managedNodeRoot.'/aabbccdd') & 0777) === 0700, 'restored node directory private');
    foreach (['nodes/../key', 'nodes/aabbccdd/authorized_keys', 'nodes/aabbccdd/config', 'nodes/aabbccdd/known_hosts'] as $path) {
        try { $destination->validateBackupExtraFiles([$path => base64_encode('fixture')]); $rejected = false; }
        catch (Throwable $error) { $rejected = true; }
        $check($rejected, 'foreign SSH file rejected');
    }
    unlink("$directory/snapshot.json");
    try { $bot->backupExtraFiles(); $rejected = false; }
    catch (Throwable $error) { $rejected = true; }
    $check($rejected, 'connected node without cached snapshot cannot produce complete backup');
    echo "PASS $checks managed node backup checks\n";
} finally { $remove($root); }
