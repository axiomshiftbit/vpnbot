<?php
require_once __DIR__ . '/../app/bot.php';

class UpdatePermissionBot extends Bot
{
    public string $directory;
    public string $reject = '';
    public function writePrivateKey(string $path, string $data): bool
    {
        $name = basename($path);
        if ($name === $this->reject) return false;
        return parent::writePrivateKey($this->directory . '/' . $name, $data);
    }
}
$dir = sys_get_temp_dir() . '/vpnbot-update-' . bin2hex(random_bytes(8));
mkdir($dir, 0700);
$bot = (new ReflectionClass(UpdatePermissionBot::class))->newInstanceWithoutConstructor();
$bot->directory = $dir;
$bot->key = 'synthetic-update-token';
$bot->input = ['from' => 1, 'chat' => 1];
$failed = 0;
function updatePermAssert(bool $ok, string $message): void {
    global $failed;
    if (!$ok) { $failed++; echo "FAIL: $message\n"; }
}
$mask = umask(0022);
try {
    // Existing files created by old versions must also lose public read access.
    file_put_contents($dir . '/key', 'old-synthetic-token');
    chmod($dir . '/key', 0644);
    updatePermAssert($bot->queueUpdateCommand('2', ['result' => ['message_id' => 2]]), 'restart command is queued');
    foreach (['key', 'curl', 'reload_message', 'pipe'] as $name) {
        clearstatcache(true, $dir . '/' . $name);
        updatePermAssert((fileperms($dir . '/' . $name) & 0777) === 0600, "$name: private from creation and after replacement");
    }
    updatePermAssert(file_get_contents($dir . '/key') === 'synthetic-update-token', 'host worker receives the token');
    updatePermAssert(file_get_contents($dir . '/pipe') === '2', 'host worker receives restart opcode');
    unlink($dir . '/pipe');
    $bot->reject = 'key';
    updatePermAssert(!$bot->queueUpdateCommand('1', ['result' => ['message_id' => 3]]), 'I/O failure is reported');
    updatePermAssert(!file_exists($dir . '/pipe'), 'failed preparation cannot publish an update command');

    // Run the real host worker initialization up to its command loop. A global
    // umask 077 would make files checked out by Git unreadable to nginx.
    mkdir($dir . '/update', 0700);
    file_put_contents($dir . '/update/key', 'synthetic-host-token');
    chmod($dir . '/update/key', 0644);
    file_put_contents($dir . '/.env', "TELEGRAM_API=example.test\n");
    $script = file_get_contents(__DIR__ . '/../update/update.sh');
    $startup = strstr($script, "\nwhile true", true);
    updatePermAssert(is_string($startup), 'host worker command loop is found');
    file_put_contents($dir . '/init-test.sh', $startup . "\numask\ntouch public.txt\n");
    $worker = proc_open(['bash', $dir . '/init-test.sh'], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $dir);
    fclose($pipes[0]);
    $out = stream_get_contents($pipes[1]);
    $err = stream_get_contents($pipes[2]);
    fclose($pipes[1]); fclose($pipes[2]);
    updatePermAssert(proc_close($worker) === 0 && $err === '', 'host worker initialization succeeds');
    updatePermAssert(trim($out) === '0022' && (fileperms($dir . '/public.txt') & 0777) === 0644,
        'Git and make retain the caller umask for readable public files');
    clearstatcache();
    updatePermAssert((fileperms($dir . '/update/key') & 0777) === 0600, 'host worker repairs old token permissions');
    updatePermAssert((fileperms($dir . '/update/pipe') & 0777) === 0600, 'host worker creates a private command file');
} finally {
    umask($mask);
    foreach (glob($dir . '/update/*') ?: [] as $path) unlink($path);
    @unlink($dir . '/update/.lock');
    @rmdir($dir . '/update');
    @unlink($dir . '/.env');
    foreach (glob($dir . '/*') as $path) unlink($path);
    rmdir($dir);
}
if ($failed) exit(1);
echo "update_permissions_test OK\n";
