<?php
// TeleMT → WEB toggle froze the bot: telemtConfUpdate() holds the "pac" lock,
// the blockers check reaches getHashSubdomain('tw'), which persisted a missing
// label through pacConfUpdate() — a second flock of the same file in the same
// process waits forever, and every later action that needs "pac" hung behind it.
// Each scenario runs in a child process with a timeout: a deadlock is a FAIL.
require_once __DIR__ . '/../app/bot.php';

if (($argv[1] ?? '') === 'child') {
    $root = $argv[2];
    $bot = new class($root) extends Bot {
        public function __construct(public string $root) { $this->pac = "$root/pac.json"; $this->key = '123:abc'; if (property_exists($this, 'lockDir')) $this->lockDir = "$root/"; }
        public function getPacConf() { return json_decode((string) @file_get_contents($this->pac), true) ?: []; }
        public function setPacConf(array $conf) { return file_put_contents($this->pac, json_encode($conf)) !== false; }
    };
    file_put_contents("$root/pac.json", json_encode(['domain' => 'vpn.example']));
    if (!property_exists($bot, 'lockDir')) { echo "nolockdir\n"; exit(3); }
    switch ($argv[3]) {
        case 'label-under-pac':
            $label = '';
            $bot->pacConfUpdate(function (&$p) use ($bot, &$label) { $label = $bot->getHashSubdomain('tw'); });
            $again = $bot->getHashSubdomain('tw');   // outside the lock it is persisted, same value
            echo ($label !== '' && $label === $again && ($bot->getPacConf()['tw_domain'] ?? '') === $label) ? "ok\n" : "bad\n";
            break;
        case 'nested-same-lock':
            try { $bot->withLock('x', fn() => $bot->withLock('x', fn() => 1)); echo "no-error\n"; }
            catch (LogicException $e) { echo "refused\n"; }
            echo $bot->withLock('x', fn() => $bot->withLock('x', fn() => 1, 5, 'busy')) === 'busy' ? "bounded-busy\n" : "bounded-other\n";
            // The lock is usable again afterwards.
            echo $bot->withLock('x', fn() => 'free') === 'free' ? "free\n" : "stuck\n";
            break;
        case 'different-locks':
            echo $bot->withLock('a', fn() => $bot->withLock('b', fn() => 'ok')) . "\n";
            break;
    }
    exit(0);
}

$failed = 0; $count = 0;
$check = static function (bool $ok, string $what) use (&$failed, &$count) { $count++; if (!$ok) { $failed++; echo "FAIL: $what\n"; } };
$run = static function (string $scenario): string {
    $root = sys_get_temp_dir() . '/vpnbot-nested-lock-' . bin2hex(random_bytes(4)); mkdir($root, 0700);
    $p = proc_open(['timeout', '10', PHP_BINARY, __FILE__, 'child', $root, $scenario], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    $out = stream_get_contents($pipes[1]); fclose($pipes[1]); fclose($pipes[2]); $rc = proc_close($p);
    exec('rm -rf ' . escapeshellarg($root));
    return $rc === 124 ? 'DEADLOCK' : trim($out);
};
$check($run('label-under-pac') === 'ok', 'getHashSubdomain() under the pac lock returns the label without a self-deadlock');
$check($run('nested-same-lock') === "refused\nbounded-busy\nfree", 'a nested withLock() of the same name fails fast instead of hanging');
$check($run('different-locks') === 'ok', 'nesting different locks still works');
echo "nested_lock_test: " . ($count - $failed) . "/$count\n";
exit($failed ? 1 : 0);
