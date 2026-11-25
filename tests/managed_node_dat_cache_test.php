<?php
// Expanded .dat categories for node lists are cached by file identity; a refreshed file is expanded again.
require_once __DIR__ . '/../app/bot.php';
set_error_handler(static function ($level, $message, $file, $line) { if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line); return true; });

class DatCacheBot extends Bot
{
    public string $dir; public int $runs = 0;
    public function __construct() {}
    public function datDir(): string { return $this->dir; }
    public function datCategoryError(array $entry): ?string { return null; }
    protected function exitRulesetTool(array $command): bool { $this->runs++; return parent::exitRulesetTool($command); }
    public function expand(array $entry): array { return $this->nodePolicyDat($entry); }
}
$check = static function (bool $ok, string $name) { if (!$ok) throw new RuntimeException('FAIL ' . $name); };
$dir = sys_get_temp_dir() . '/vpnbot-dat-cache-test-' . bin2hex(random_bytes(4));
mkdir($dir, 0700);
$started = time();
$make = static function (array $cidrs) use ($dir) {
    $script = 'import sys; sys.path.insert(0, sys.argv[1]); import node_geodat; open(sys.argv[2], "wb").write(node_geodat.geoip({"TEST": sys.argv[3:]}))';
    exec(implode(' ', array_map('escapeshellarg', array_merge(['python3', '-c', $script, __DIR__ . '/../scripts', "$dir/lab.dat"], $cidrs))), $out, $code);
    if ($code !== 0) throw new RuntimeException('dat fixture');
};
try {
    $bot = new DatCacheBot();
    $bot->dir = $dir;
    $make(['198.51.100.0/24', '192.0.2.0/25']);
    $entry = ['kind' => 'extip', 'value' => 'lab.dat:test'];
    $first = $bot->expand($entry);
    $check(count($first) === 2 && in_array('198.51.100.0/24', $first, true), 'category expanded from a real .dat');
    // The bot runs as root; elsewhere the cache is not trusted and every call expands again.
    $probe = tempnam(sys_get_temp_dir(), 'vpnbot-owner-');
    $root = fileowner($probe) === 0;
    unlink($probe);
    $check($bot->expand($entry) === $first && $bot->runs === ($root ? 1 : 2), $root ? 'second expansion comes from the cache' : 'a non-root cache is not trusted');
    sleep(1);
    $make(['203.0.113.0/24']);
    $check($bot->expand($entry) === ['203.0.113.0/24'] && $bot->runs === ($root ? 2 : 3), 'a refreshed .dat is expanded again');
} finally {
    foreach (glob("$dir/*") ?: [] as $file) unlink($file);
    rmdir($dir);
    // Cache entries this run wrote (keyed by the removed fixture path).
    foreach (glob(sys_get_temp_dir() . '/vpnbot-node-dat-*.json') ?: [] as $file) if (filemtime($file) >= $started) @unlink($file);
}
echo "PASS node .dat expansion cache\n";
