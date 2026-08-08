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

if ($failed) {
    echo "version_parse_test: провалено проверок — $failed\n";
    exit(1);
}
echo "version_parse_test OK\n";
