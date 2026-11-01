<?php
require_once __DIR__ . '/../app/bot.php';
if (!extension_loaded('pdo_sqlite')) { echo "store_migration_test SKIP: pdo_sqlite\n"; exit(0); }
class MigrationBot extends Bot {
    public function __construct(string $root) { $this->hwid = "$root/hwid.json"; }
}
$checks = 0;
foreach (['hwid', 'connlog'] as $part) {
    $root = sys_get_temp_dir() . '/vpnbot-migrate-' . bin2hex(random_bytes(6));
    mkdir($root, 0700);
    try {
        file_put_contents("$root/$part.json", '{truncated');
        $bot = new MigrationBot($root);
        $failed = false;
        try { $bot->store(); } catch (RuntimeException $e) { $failed = true; }
        if (!$failed) throw new RuntimeException("Повреждённый $part ошибочно отмечен как импортированный");
        $valid = $part === 'hwid' ? ['u' => ['dev' => ['time' => 1]]] :
            ['u' => ['last' => time(), 'ips' => ['192.0.2.1' => ['first' => time(), 'last' => time(), 'count' => 1, 'dst' => []]]]];
        file_put_contents("$root/$part.json", json_encode($valid));
        $data = $part === 'hwid' ? $bot->getHwidStorage() : $bot->getConnLog();
        if ($data != $valid) throw new RuntimeException("Повтор после исправления $part потерял данные");
        $checks += 2;
    } finally {
        unset($bot);
        foreach (glob("$root/*") as $file) unlink($file);
        rmdir($root);
    }
}
echo "store_migration_test OK ($checks)\n";
