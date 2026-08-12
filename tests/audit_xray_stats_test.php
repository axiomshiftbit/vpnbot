<?php

// Учёт трафика xray и целостность xray.json.
// Регрессии из аудита 2026-08-12 (раздел «Xray / подписки»):
//  - delxr(): статистика привязана к клиенту позицией, а restartXray() делает
//    clients = array_values() — удаление клиента из середины списка сдвигало
//    учёт всем, кто ниже, и их квоты считались с нуля;
//  - xrayStatsUser(): session — абсолютный снимок счётчиков ядра, и внешний
//    рестарт (docker restart xr, OOM) терял накопленное;
//  - shutdownClientXr(): switchXr() — тумблер, и по истечении срока он
//    ВКЛЮЧАЛ клиента, отключённого по исчерпанной квоте;
//  - xrayUuid(): id больше не зависит от живого контейнера (пустая строка от
//    ssh сохранялась в конфиг, и ядро с ней не поднималось).

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function xrStatsAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

class XrStatsTestBot extends Bot
{
    public array $xray     = [];
    public array $stats    = [];
    public array $counters = [];
    public bool  $restarted = false;

    public function getXray()
    {
        return $this->xray;
    }

    public function getXrayStats()
    {
        return $this->stats;
    }

    public function setXrayStats($x)
    {
        $this->stats = $x;
    }

    public function getPacConf()
    {
        return [];
    }

    public function xrayStatCounters(): ?array
    {
        return $this->counters;
    }

    public function restartXray($c, $norestart = false)
    {
        // Ровно то, из-за чего расходились индексы: клиенты переиндексируются.
        $c['inbounds'][0]['settings']['clients'] = array_values($c['inbounds'][0]['settings']['clients']);
        $this->xray = $c;
        $this->restarted = true;
    }

    public function switchXr($i, $nm = 0, $time = false)
    {
        $this->switched[] = $i;
    }

    public array $switched = [];

    // Внешние эффекты delxr(), не относящиеся к делу.
    public function deleteHwidUser($id) {}
    public function deleteWarpClient($email) {}
    public function adguardXrayClients() {}
    public function xray($page = 0) {}
    public function menu($type = false, $arg = false, $return = false) {}
}

$bot = (new ReflectionClass(XrStatsTestBot::class))->newInstanceWithoutConstructor();

// ── 1. delxr: статистика не съезжает ────────────────────────────────────────
$bot->xray = ['inbounds' => [[
    'tag'      => 'vless_tls',
    'settings' => ['clients' => [
        ['id' => 'u0', 'email' => 'a@x'],
        ['id' => 'u1', 'email' => 'b@x'],
        ['id' => 'u2', 'email' => 'c@x'],
    ]],
]]];
$bot->stats = ['users' => [
    ['global' => ['download' => 10, 'upload' => 1], 'session' => ['download' => 0, 'upload' => 0]],
    ['global' => ['download' => 20, 'upload' => 2], 'session' => ['download' => 0, 'upload' => 0]],
    ['global' => ['download' => 30, 'upload' => 3], 'session' => ['download' => 0, 'upload' => 0]],
]];
$bot->delxr(1); // удаляем среднего
$clients = $bot->xray['inbounds'][0]['settings']['clients'];
xrStatsAssert(count($clients) === 2, 'клиентов осталось двое');
xrStatsAssert($clients[0]['email'] === 'a@x' && $clients[1]['email'] === 'c@x', 'остались нужные клиенты');
xrStatsAssert(count($bot->stats['users']) === 2, 'записей статистики тоже две');
xrStatsAssert($bot->stats['users'][0]['global']['download'] === 10, 'первому клиенту его трафик');
xrStatsAssert($bot->stats['users'][1]['global']['download'] === 30,
    'третьему клиенту достался ЕГО трафик, а не соседский: '
    . $bot->stats['users'][1]['global']['download']);

// ── 2. foldSession ──────────────────────────────────────────────────────────
$p = Bot::foldSession([
    'global'  => ['download' => 100, 'upload' => 10],
    'session' => ['download' => 5,   'upload' => 1],
    'inbounds' => ['wg-in' => ['download' => 7, 'upload' => 7]],
    'users'   => [
        ['global' => ['download' => 50, 'upload' => 5], 'session' => ['download' => 3, 'upload' => 2]],
    ],
]);
xrStatsAssert($p['global'] === ['download' => 105, 'upload' => 11], 'общий session свёрнут в global');
xrStatsAssert($p['session'] === ['download' => 0, 'upload' => 0], 'общий session обнулён');
xrStatsAssert(!isset($p['inbounds']), 'разбивка по inbound снята');
xrStatsAssert($p['users'][0]['global'] === ['download' => 53, 'upload' => 7], 'клиентский session свёрнут');
xrStatsAssert($p['users'][0]['session'] === ['download' => 0, 'upload' => 0], 'клиентский session обнулён');
// На свежей установке ключей нет вовсе — предупреждений быть не должно.
$p = Bot::foldSession([]);
xrStatsAssert($p['global'] === ['download' => 0, 'upload' => 0], 'пустая статистика переживает свёртку');

// ── 3. Внешний рестарт ядра не теряет накопленное ───────────────────────────
$bot = (new ReflectionClass(XrStatsTestBot::class))->newInstanceWithoutConstructor();
$bot->xray = ['inbounds' => [[
    'tag'      => 'vless_tls',
    'settings' => ['clients' => [['id' => 'u0', 'email' => 'a@x']]],
]]];
$bot->stats = [
    'global'  => ['download' => 1000, 'upload' => 100],
    'session' => ['download' => 500,  'upload' => 50],
    'users'   => [['global' => ['download' => 900, 'upload' => 90], 'session' => ['download' => 400, 'upload' => 40]]],
];
// Ядро перезапустилось мимо нас: счётчики начались заново.
$bot->counters = [
    'inbound>>>vless_tls>>>traffic>>>downlink' => 7,
    'inbound>>>vless_tls>>>traffic>>>uplink'   => 2,
    'user>>>a@x>>>traffic>>>downlink'          => 5,
    'user>>>a@x>>>traffic>>>uplink'            => 1,
];
$bot->time_xray_stats = 0;
$bot->xrayStatsUser();
xrStatsAssert($bot->stats['global']['download'] === 1500,
    'прошлая сессия свёрнута в global: ' . $bot->stats['global']['download']);
xrStatsAssert($bot->stats['session']['download'] === 7, 'применён новый снимок');
xrStatsAssert($bot->stats['users'][0]['global']['download'] === 1300,
    'клиентский трафик не потерян: ' . $bot->stats['users'][0]['global']['download']);
xrStatsAssert($bot->stats['users'][0]['session']['download'] === 5, 'клиентский снимок применён');

// Обычный тик (счётчики выросли) ничего не сворачивает.
$bot->counters['inbound>>>vless_tls>>>traffic>>>downlink'] = 9;
$bot->counters['user>>>a@x>>>traffic>>>downlink']          = 6;
$bot->time_xray_stats = 0;
$bot->xrayStatsUser();
xrStatsAssert($bot->stats['global']['download'] === 1500, 'растущий счётчик не двигает global');
xrStatsAssert($bot->stats['session']['download'] === 9, 'session обновлён снимком');

// ── 4. shutdownClientXr не включает выключенного по квоте ───────────────────
$bot = (new ReflectionClass(XrStatsTestBot::class))->newInstanceWithoutConstructor();
$past = time() - 3600;
$bot->xray = ['inbounds' => [['settings' => ['clients' => [
    ['id' => 'u0', 'email' => 'a@x', 'time' => $past],                              // истёк, активен
    ['id' => 'u1', 'email' => 'b@x', 'time' => $past, 'off' => 'old', 'traffic_off' => 1], // истёк, но уже выключен
    ['id' => 'u2', 'email' => 'c@x', 'time' => time() + 3600],                      // ещё живой
]]]]];
$bot->shutdownClientXr();
xrStatsAssert($bot->switched === [0], 'выключается только истёкший активный клиент: '
    . json_encode($bot->switched));

// ── 5. xrayUuid ─────────────────────────────────────────────────────────────
$u = Bot::xrayUuid();
xrStatsAssert((bool) preg_match('~^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$~', $u),
    "uuid v4 нужной формы: $u");
xrStatsAssert(Bot::xrayUuid() !== Bot::xrayUuid(), 'два вызова дают разные значения');

if ($failed) {
    echo "audit_xray_stats_test FAILED: $failed\n";
    exit(1);
}
echo "audit_xray_stats_test OK\n";
