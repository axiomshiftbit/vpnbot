<?php
require_once __DIR__ . '/../app/bot.php';
class NodeBackupFixture extends Bot {
    public array $state = [];
    public function __construct(string $root) {
        $this->lockDir = dirname($root).'/';
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
    $archiveBot = new NodeBackupFixture($root.'/archive-source');
    $archiveId = str_repeat('a', 32);
    $archive = $archiveBot->managedNodeRoot.'/retired/'.$archiveId;
    mkdir($archive, 0700, true);
    foreach (['key', 'key.pub'] as $name) file_put_contents("$archive/$name", "fixture-$name");
    $backup = $archiveBot->backupExtraFiles();
    $check(count($backup) === 2, 'deleted node keys exported without any live node cards');
    $restored = new NodeBackupFixture($root.'/archive-restored');
    $restored->restoreBackupExtraFiles($backup);
    foreach (['key', 'key.pub'] as $name) {
        $path = $restored->managedNodeRoot."/retired/$archiveId/$name";
        $check(file_get_contents($path) === "fixture-$name" && (fileperms($path) & 0777) === 0600, 'retired key restored privately');
    }
    $check((fileperms(dirname($path)) & 0777) === 0700, 'retired directory private');
    $check($restored->backupExtraFiles() === $backup, 'retired archive round trip');
    // Older releases could leave more than 256 pairs, including after an interrupted eviction.
    for ($i = 0; $i < 256; $i++) {
        $entry = $archiveBot->managedNodeRoot.'/retired/'.sprintf('%032x', $i);
        mkdir($entry, 0700);
        foreach (['key', 'key.pub'] as $name) file_put_contents("$entry/$name", 'fixture');
        touch($entry, 1000 + $i);
    }
    $latest = $archiveBot->backupExtraFiles();
    $check(count($latest) === 512 && isset($latest["nodes/retired/$archiveId/key"]) &&
        !isset($latest['nodes/retired/'.str_repeat('0', 32).'/key']), 'backup selects newest 256 complete pairs from legacy archive');
    $check(count($archiveBot->validateBackupExtraFiles($latest)) === 512, 'bounded legacy archive can be restored');
    // IDs run opposite to age so lexical order cannot replace backup order.
    for ($i = 0; $i < 256; $i++) touch($archiveBot->managedNodeRoot.'/retired/'.sprintf('%032x', $i), 5000 - $i);
    $ordered = $archiveBot->backupExtraFiles();
    $import = new NodeBackupFixture($root.'/ordered');
    $import->restoreBackupExtraFiles(json_decode(json_encode($ordered), true));
    $check(array_keys($import->backupExtraFiles()) === array_keys($ordered), 'restore preserves the complete order of the exported 256 pairs');
    $local = $root.'/merged';
    $merge = new NodeBackupFixture($local);
    $foreign = $merge->managedNodeRoot.'/retired/'.str_repeat('e', 32);
    mkdir($foreign, 0700, true);
    foreach (['key', 'key.pub'] as $name) file_put_contents("$foreign/$name", 'locally retained fixture');
    touch($foreign, 12000);
    $merge->restoreBackupExtraFiles($ordered);
    clearstatcache();
    $check(filemtime($foreign) === 12000 && file_get_contents("$foreign/key") === 'locally retained fixture' &&
        count(glob(dirname($foreign).'/*', GLOB_ONLYDIR)) === 257, 'import keeps other local pairs and their dates');
    $check(filemtime($merge->managedNodeRoot."/retired/$archiveId") < filemtime($foreign), 'import does not displace existing local history');
    $rollback = new class($local) extends NodeBackupFixture {
        public bool $failWrite = true;
        public function writePrivateKey(string $path, string $data): bool {
            if ($this->failWrite && str_ends_with($path, '/key.pub')) { $this->failWrite = false; return false; }
            return parent::writePrivateKey($path, $data);
        }
    };
    try {
        $rollback->restoreBackupExtraFiles(["nodes/retired/".str_repeat('e', 32).'/key' => base64_encode('incoming'),
            "nodes/retired/".str_repeat('e', 32).'/key.pub' => base64_encode('incoming')]);
        $failed = false;
    } catch (Throwable $error) { $failed = true; }
    clearstatcache();
    $check($failed && filemtime($foreign) === 12000 && file_get_contents("$foreign/key") === 'locally retained fixture',
        'failed import restores the original pair and its place in local history');
    $rollback->failWrite = true;
    $missing = str_repeat('f', 32);
    try {
        $rollback->restoreBackupExtraFiles(["nodes/retired/$missing/key" => base64_encode('incoming'),
            "nodes/retired/$missing/key.pub" => base64_encode('incoming')]);
        $failed = false;
    } catch (Throwable $error) { $failed = true; }
    $check($failed && !is_dir(dirname($foreign)."/$missing"), 'failed restore leaves no incomplete pair directory');
    $ties = new NodeBackupFixture($root.'/ties');
    foreach (['a', 'b'] as $prefix) {
        $pair = $ties->managedNodeRoot.'/retired/'.str_repeat($prefix, 32);
        mkdir($pair, 0700, true);
        foreach (['key', 'key.pub'] as $name) file_put_contents("$pair/$name", 'fixture');
        touch($pair, 3);
    }
    $check(array_key_first($ties->backupExtraFiles()) === 'nodes/retired/'.str_repeat('b', 32).'/key', 'equal seconds select greater ID first');
    $check($restored->validateBackupExtraFiles([]) === [], 'older backup without retired keys accepted');
    foreach ([array_slice($backup, 0, 1), array_replace($backup, ["nodes/retired/$archiveId/key" => base64_encode(str_repeat('x', 16385))]),
        ["nodes/retired/$archiveId/endpoint.json" => base64_encode('{}')], ['nodes/retired/../key' => base64_encode('fixture')]] as $bad) {
        try { $restored->validateBackupExtraFiles($bad); $rejected = false; }
        catch (Throwable $error) { $rejected = true; }
        $check($rejected, 'incomplete oversized or foreign archive rejected');
    }
    unlink("$archive/key.pub");
    try { $archiveBot->backupExtraFiles(); $rejected = false; }
    catch (Throwable $error) { $rejected = true; }
    $check($rejected, 'incomplete archive does not silently produce a backup');
    symlink($root.'/archive-restored/nodes/retired/'.$archiveId.'/key.pub', "$archive/key.pub");
    try { $archiveBot->backupExtraFiles(); $rejected = false; }
    catch (Throwable $error) { $rejected = true; }
    $check($rejected, 'archive symlink rejected');
    echo "PASS $checks managed node backup checks\n";
} finally { $remove($root); }
