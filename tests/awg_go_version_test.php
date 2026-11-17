<?php
// Меню версий показывало только amneziawg-tools («awg v3.1.20260812»), хотя
// протокол реализует amneziawg-go, а его бинарь печатает зашитое
// «0.0.20250522». Версию amneziawg-go образ записывает при сборке; бот
// показывает обе. Команды пробы исполняет настоящий sh с подменными бинарями.
require_once __DIR__ . '/../app/bot.php';

class AwgGoVersionBot extends Bot
{
    public string $dir;
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
    {
        if (!in_array($service, ['wg', 'wg1'], true)) return '';
        $cmd = str_replace('/etc/amneziawg-go_version', "$this->dir/amneziawg-go_version", $cmd);
        $p = proc_open(['/bin/sh', '-c', $cmd], [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes, null, ['PATH' => $this->dir . ':' . getenv('PATH')]);
        $out = stream_get_contents($pipes[1]); fclose($pipes[1]); fclose($pipes[2]); proc_close($p);
        return $out;
    }
    public function getInstanceWG($prefix = false) { return $prefix ? '' : 'wg'; }
}

$failed = 0; $count = 0;
$check = static function (bool $ok, string $what) use (&$failed, &$count) { $count++; if (!$ok) { $failed++; echo "FAIL: $what\n"; } };
$dir = sys_get_temp_dir() . '/vpnbot-awg-go-' . bin2hex(random_bytes(6));
mkdir($dir, 0700);
try {
    file_put_contents("$dir/wg", "#!/bin/sh\necho 'wireguard-tools v1.0.20260223 - https://git.zx2c4.com/wireguard-tools/'\n");
    file_put_contents("$dir/awg", "#!/bin/sh\necho 'amneziawg-tools v3.1.20260812 - https://amnezia.org'\n");
    file_put_contents("$dir/amneziawg-go", "#!/bin/sh\necho 'amneziawg-go 0.0.20250522'\n");
    foreach (['wg', 'awg', 'amneziawg-go'] as $bin) chmod("$dir/$bin", 0700);
    file_put_contents("$dir/amneziawg-go_version", "v3.1.20261116\n");
    $bot = (new ReflectionClass(AwgGoVersionBot::class))->newInstanceWithoutConstructor();
    $bot->dir = $dir;
    $v = $bot->probeServiceVersions();
    $check(($v['awg'] ?? null) === 'v3.1.20260812', 'версия amneziawg-tools по-прежнему определяется');
    $check(($v['awggo'] ?? null) === 'v3.1.20261116', 'версия amneziawg-go берётся из файла сборки, а не из зашитой строки');
    $labels = Bot::MENU_VERSION_LABELS;
    $check(($labels['awggo'] ?? null) === 'awg-go' && ($labels['awg'] ?? null) === 'awg-tools', 'меню подписывает awg-go и awg-tools раздельно');
    $header = $bot->wgVersion();
    $check(str_contains($header, 'v3.1.20261116') && str_contains($header, 'v3.1.20260812'), 'шапка меню WireGuard показывает обе версии');
    // Образ записывает версию amneziawg-go при сборке.
    $dockerfile = file_get_contents(__DIR__ . '/../dockerfile/wireguard.dockerfile');
    $check(str_contains($dockerfile, "printf '%s\\n' \"\$AWG_GO_VERSION\" > /etc/amneziawg-go_version"), 'образ записывает /etc/amneziawg-go_version');
} finally {
    foreach (glob("$dir/*") as $f) unlink($f);
    rmdir($dir);
}
echo "awg_go_version_test: " . ($count - $failed) . "/$count\n";
exit($failed ? 1 : 0);
