<?php
require_once __DIR__ . '/../app/bot.php';

class ExternalCacheFixture extends Bot
{
    public bool $storageAvailable = true;
    public function __construct(string $dir) {
        $this->lockDir = $dir . '/';
        $this->extSubCachePath = $dir . '/extsub.cache';
    }
    public function writePrivateKey(string $path, string $data): bool {
        return $this->storageAvailable && parent::writePrivateKey($path, $data);
    }
}

$dir = sys_get_temp_dir() . '/vpnbot-extcache-' . bin2hex(random_bytes(8));
mkdir($dir, 0700);
$file = $dir . '/extsub.cache';
$bot = new ExternalCacheFixture($dir);
$url = 'https://provider.example.test/list';
$link = 'vless://fixture@node.example.test:443';
$row = ['at' => time(), 'links' => [$link]];
$check = static function (bool $ok, string $label) { if (!$ok) throw new RuntimeException($label); };
try {
    file_put_contents($file, 'true');
    $check($bot->readExtSubCache() === [], 'scalar cache does not interrupt subscription delivery');
    $bot->updateExtSubCache($url, $row);
    clearstatcache(true, $file);
    $check((fileperms($file) & 0777) === 0600 && $bot->fetchExtSubLinks($url) === [$link], 'private cache recovers on refresh');
    $invalid = $link . chr(255);
    $check($bot->decodeExtSubBody($link . "\n" . $invalid) === [$link], 'only valid text links are cached');
    $bot->updateExtSubCache($url . '/other', ['at' => time(), 'links' => [$invalid]]);
    $check($bot->readExtSubCache() === [$url => $row], 'encoding failure preserves the previous snapshot');
    $bot->storageAvailable = false;
    $bot->pruneExtSubCache([]);
    $check($bot->readExtSubCache() === [$url => $row], 'failed file replacement preserves the previous snapshot');
    $bot->storageAvailable = true;
    if (function_exists('pcntl_fork')) {
        $children = [];
        for ($i = 0; $i < 4; $i++) {
            $pid = pcntl_fork();
            if ($pid < 0) throw new RuntimeException('fork failed');
            if ($pid === 0) { $bot->updateExtSubCache($url . '/' . $i, $row); exit(0); }
            $children[] = $pid;
        }
        foreach ($children as $pid) { pcntl_waitpid($pid, $status); $check(pcntl_wifexited($status) && pcntl_wexitstatus($status) === 0, 'writer failed'); }
        $check(count($bot->readExtSubCache()) === 5, 'concurrent writers preserve every provider');
    }
    $bot->pruneExtSubCache([$url => true]);
    $check($bot->readExtSubCache() === [$url => $row], 'removed sources are pruned');
} finally {
    foreach ([$file, $dir . '/.lock.extsub_cache'] as $path) if (is_file($path)) unlink($path);
    rmdir($dir);
}
echo "external_cache_test OK\n";
