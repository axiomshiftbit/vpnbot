<?php

// Разбор версий сервисов из вывода их бинарей.
//
// Каждый *Version() — это ssh в контейнер плюс регексп по stdout, и ошибка в
// регекспе тихая: меню просто показывает «—», как будто контейнер не отвечает.
// Здесь ssh() подменяется, чтобы проверить именно разбор.

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function verAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        echo "FAIL: $msg\n";
        $failed++;
    }
}

class VersionTestBot extends Bot
{
    public array $out = [];

    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
    {
        return $this->out[$service] ?? '';
    }
}

$bot = (new ReflectionClass(VersionTestBot::class))->newInstanceWithoutConstructor();

// ── AdGuardHome ─────────────────────────────────────────────────────────────
putenv('ADGUARD_VERSION=v0.107.78');
$bot->out = ['ad' => "AdGuard Home, version v0.107.78\n"];
$v = $bot->adguardVersion();
verAssert($v['running'] === 'v0.107.78', 'adguard running: ' . json_encode($v));
verAssert($v['pinned'] === 'v0.107.78', 'adguard pinned: ' . json_encode($v));

// Бета-теги тоже должны разбираться.
$bot->out = ['ad' => 'AdGuard Home, version v0.108.0-b.90'];
verAssert($bot->adguardVersion()['running'] === 'v0.108.0-b.90', 'adguard beta: ' . $bot->adguardVersion()['running']);

// Контейнер не ответил — running пустой, но пин остаётся: в меню это два
// разных состояния («не отвечает» против «нужна пересборка»).
$bot->out = ['ad' => ''];
$v = $bot->adguardVersion();
verAssert($v['running'] === '' && $v['pinned'] === 'v0.107.78', 'adguard молчащий контейнер: ' . json_encode($v));

// Мусор в stdout не должен превращаться в версию.
$bot->out = ['ad' => "sh: AdGuardHome: not found\n"];
verAssert($bot->adguardVersion()['running'] === '', 'adguard мусор принят за версию');

// ── ocserv (регрессия соседнего разбора) ────────────────────────────────────
putenv('OCSERV_VERSION=1.5.0');
$bot->out = ['oc' => "ocserv: OpenConnect VPN Server 1.5.0\nGnuTLS version: 3.8.10\n"];
$v = $bot->ocservVersion();
verAssert($v['running'] === '1.5.0', 'ocserv running: ' . json_encode($v));
verAssert($v['gnutls'] === '3.8.10', 'ocserv gnutls: ' . json_encode($v));

// ── caddy ───────────────────────────────────────────────────────────────────
putenv('CADDY_VERSION=v2.11.2');
$bot->out = ['np' => "v2.11.2 h1:abcdef\n"];
$v = $bot->naiveVersion();
verAssert($v['running'] === 'v2.11.2', 'caddy running: ' . json_encode($v));
verAssert($v['pinned'] === 'v2.11.2', 'caddy pinned: ' . json_encode($v));

// Современная сборка strongSwan содержит swanctl без устаревшего ipsec.
// Исполняем именно команду пробы с разными наборами CLI.
class StrongSwanProbeBot extends VersionTestBot
{
    public string $binDir;
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
    {
        if ($service !== 'ipsec') return '';
        $p = proc_open(['/bin/sh', '-c', $cmd], [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes, null, ['PATH' => $this->binDir . ':' . getenv('PATH')]);
        $out = stream_get_contents($pipes[1]);
        fclose($pipes[1]); fclose($pipes[2]); proc_close($p);
        return $out;
    }
}
$dir = sys_get_temp_dir() . '/vpnbot-versions-' . bin2hex(random_bytes(6));
mkdir($dir, 0700);
try {
    $probe = (new ReflectionClass(StrongSwanProbeBot::class))->newInstanceWithoutConstructor();
    $probe->binDir = $dir;
    foreach (['modern', 'legacy', 'missing'] as $case) {
        $commands = [
            'swanctl' => $case === 'modern' ? 'echo "strongSwan swanctl 6.1.0"' : 'exit 127',
            'ipsec' => $case === 'legacy' ? 'echo "Linux strongSwan U6.0.7/K6.8.0"' : 'exit 127',
            'xl2tpd' => 'printf "\nxl2tpd version xl2tpd-1.3.19\n" >&2',
        ];
        foreach ($commands as $name => $body) {
            file_put_contents("$dir/$name", "#!/bin/sh\n$body\n");
            chmod("$dir/$name", 0700);
        }
        $versions = $probe->probeServiceVersions();
        verAssert(($versions['ipsec'] ?? null) === match ($case) { 'modern' => '6.1.0', 'legacy' => '6.0.7', default => null },
            "$case: strongSwan определяется по доступному CLI");
        verAssert(($versions['l2tp'] ?? '') === '1.3.19', "$case: версия xl2tpd остаётся отдельной");
    }
} finally {
    foreach (glob("$dir/*") as $file) unlink($file);
    rmdir($dir);
}

if ($failed) {
    echo "version_parse_test: провалено проверок — $failed\n";
    exit(1);
}
echo "version_parse_test OK\n";
