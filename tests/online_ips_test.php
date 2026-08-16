<?php

// Онлайн-IP из самого ядра: `xray api statsonlineiplist -all` (StatsService,
// GetUsersStats) как второй источник рядом с разбором /logs/xray.
//
// Проверяем то, что стоит дорого и не видно глазом:
//
//  1. Разбор ответа. protojson отдаёт int64 СТРОКОЙ и опускает нулевые поля,
//     поэтому наивное чтение молча даёт мусор. Отдельно: «ядро ответило, живых
//     соединений нет» (пустая карта) обязано отличаться от «прочитать не
//     удалось» (null) — иначе лежащий контейнер выглядит как «все офлайн».
//  2. Клиент считается онлайном, даже когда access-лога нет вовсе (loglevel=
//     none) или в нём после первой строки тишина (SMUX: все потоки в одном
//     несущем коннекте). Ровно ради этого источник и добавлен.
//  3. Троттлинг. trackOnline зовётся на каждый рендер меню и каждый тик крона;
//     без него каждый рендер поднимал бы ssh-сессию, а при лежащем xr — ещё и
//     ждал таймаут.

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function onAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

// Стаб: ядро подменяется выводом ssh, состояние онлайна держим в памяти, чтобы
// тест не трогал /config и /logs.
class OnlineBot extends Bot
{
    public string $out     = '';
    public string $cmd     = '';
    public bool   $failed  = false;
    public int    $calls   = 0;
    public array  $state   = [];
    public array  $roster  = [];

    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
    {
        $this->calls++;
        $this->cmd       = $cmd;
        $this->sshFailed = $this->failed;

        return $this->out;
    }

    public function getOnlineState(): array
    {
        return $this->state;
    }

    public function setOnlineState($s)
    {
        $this->state = $s;
    }

    public function getXray()
    {
        return ['inbounds' => [['settings' => ['clients' => $this->roster]]]];
    }
}

function onBot(string $out, bool $failed = false): OnlineBot
{
    $b = (new ReflectionClass(OnlineBot::class))->newInstanceWithoutConstructor();
    $b->out     = $out;
    $b->failed  = $failed;
    $b->roster = [['email' => 'user1', 'id' => 'x'], ['email' => 'user2', 'id' => 'y']];

    return $b;
}

// Ответ в том виде, в каком его печатает `xray api statsonlineiplist -all`:
// protojson, lastSeen строкой (int64), пустых полей нет.
$live = json_encode([
    'users' => [
        ['email' => 'user1', 'ips' => [
            ['ip' => '203.0.113.7', 'lastSeen' => '1755000000'],
            ['ip' => '2001:db8::1', 'lastSeen' => '1755000001'],
        ]],
        ['email' => 'user2', 'ips' => [['ip' => '198.51.100.4']]],
    ],
]);

// --- 1: разбор ответа ---------------------------------------------------------
$b   = onBot($live);
$map = $b->xrayOnlineIps();
onAssert(is_array($map) && count($map) === 2, 'разобраны оба клиента');
onAssert(($map['user1']['203.0.113.7'] ?? null) === 1755000000, 'lastSeen-строка приведена к числу');
onAssert(isset($map['user1']['2001:db8::1']), 'IPv6 не теряется');
onAssert(($map['user2']['198.51.100.4'] ?? null) === 0, 'опущенный lastSeen читается как 0, запись остаётся');
onAssert(str_contains($b->cmd, 'statsonlineiplist') && str_contains($b->cmd, '-all'),
    'зовётся именно statsonlineiplist -all');
onAssert(str_contains($b->cmd, '--server=127.0.0.1:8080'), 'адрес api тот же, что у statsquery');

// --- 2: «нет живых» ≠ «не прочитали» -----------------------------------------
onAssert(onBot('{}')->xrayOnlineIps() === [], 'пустой ответ ядра — пустая карта, а не null');
onAssert(onBot('failed to dial: connection refused')->xrayOnlineIps() === null,
    'текст ошибки xray — null');
onAssert(onBot('')->xrayOnlineIps() === null, 'пустой вывод — null');
onAssert(onBot('{"users":[{"ips":[{"ip":"1.2.3.4"}]}]}')->xrayOnlineIps() === [],
    'запись без email отбрасывается, а не создаёт клиента с пустым именем');
onAssert(onBot($live, true)->xrayOnlineIps() === null, 'отказ ssh — null (прежние показания не трогаем)');

// --- 3: онлайн без access-лога -----------------------------------------------
// В тестовом окружении /logs/xray не существует — это и есть случай
// loglevel=none. Раньше trackOnline() на нём выходил сразу и возвращал пусто.
onAssert(!is_file('/logs/xray'), 'предпосылка теста: access-лога нет');
$b    = onBot($live);
$seen = $b->trackOnline();
onAssert(isset($seen['user1']['ips']['203.0.113.7']), 'клиент онлайн по данным ядра, без строки в логе');
onAssert(abs(($seen['user1']['ts'] ?? 0) - time()) <= 2,
    'метка времени — «сейчас»: наличие IP в карте ядра и значит «соединение живо»');

$clients = $b->onlineClients(60);
onAssert(isset($clients['user1']) && isset($clients['user2']), 'оба клиента видны в onlineClients');
onAssert(count($clients['user1']['ips']) === 2, 'оба IP клиента доехали до меню');

// Выключенный клиент не онлайн, даже если ядро ещё держит его соединение.
$b->roster = [['email' => 'user1', 'off' => 1]];
onAssert(!isset($b->onlineClients(60)['user1']), 'off-клиент отсеивается сверкой с ростером');

// --- 3b: адрес фронтящего nginx не выдаём за адрес клиента --------------------
// Ядро запоминает источник ФИЗИЧЕСКОГО соединения. За nginx (а за ним весь
// vless: TLS терминирует он) это адрес контейнера upstream — на боевом сервере
// в карте лежит 10.10.0.10, тогда как в access-логе адрес клиента правильный,
// его восстанавливает PROXY-протокол. Такой адрес не должен попадать ни в
// список IP, ни в его счётчик, но живость клиента он подтверждает.
$fronted = json_encode(['users' => [
    ['email' => 'user1', 'ips' => [['ip' => '10.10.0.10', 'lastSeen' => 1755000000]]],
]]);
$b = onBot($fronted);
$b->state = ['seen' => ['user1' => ['ts' => time() - 300, 'ips' => ['203.0.113.7' => time() - 300]]]];
$seen = $b->trackOnline();
onAssert(!isset($seen['user1']['ips']['10.10.0.10']), 'внутренний адрес docker-сети отброшен');
onAssert(abs(($seen['user1']['ts'] ?? 0) - time()) <= 2,
    'живость клиента при этом подтверждена — ради неё источник и нужен');

// Свежих адресов нет (лог молчит, из ядра всё отфильтровано) — показываем
// последние известные, иначе онлайн-клиент выглядел бы как «(0)».
$cl = $b->onlineClients(60);
onAssert(isset($cl['user1']), 'клиент онлайн');
onAssert(array_key_first($cl['user1']['ips'] ?? []) === '203.0.113.7',
    'вместо пустого списка показан последний известный адрес из лога');

// Публичный адрес из карты ядра (прямой inbound, без nginx) — берём как есть.
$direct = json_encode(['users' => [
    ['email' => 'user1', 'ips' => [['ip' => '203.0.113.9', 'lastSeen' => 1755000000]]],
]]);
$b = onBot($direct);
onAssert(isset($b->trackOnline()['user1']['ips']['203.0.113.9']),
    'публичный адрес из ядра попадает в список');

// --- 4: троттлинг -------------------------------------------------------------
$b = onBot($live);
$b->trackOnline();
onAssert($b->calls === 1, 'первый вызов идёт в ядро');
onAssert(($b->state['api_next'] ?? 0) > time(), 'следующий опрос отложен');
$b->trackOnline();
$b->trackOnline();
onAssert($b->calls === 1, 'в окне троттлинга ssh-сессия не поднимается повторно');

// Данные из прошлого удачного опроса при этом не теряются.
onAssert(isset($b->state['seen']['user1']['ips']['203.0.113.7']),
    'состояние онлайна пережило троттлинг');

// Отказ откладывает следующую попытку заметно дольше удачи: лежащий xr не
// должен стоять таймаутом ssh в каждом рендере меню.
$okNext = $b->state['api_next'];
$f = onBot($live, true);
$f->trackOnline();
onAssert(($f->state['api_next'] - time()) > ($okNext - time()) + 60,
    'после отказа бэкофф длиннее, чем обычный интервал');

// --- 5: политика ядра ---------------------------------------------------------
// Без statsUserOnline ядро карту не ведёт вовсе (app/dispatcher/default.go),
// и команда штатно отдаёт пусто — тогда весь источник молча мёртв.
$src = (string) file_get_contents(__DIR__ . '/../app/bot.php');
onAssert(str_contains($src, '"statsUserOnline"   => true'),
    'saveXray включает statsUserOnline в policy.levels');

echo $failed ? "online_ips_test FAILED ($failed)\n" : "online_ips_test OK\n";
exit($failed ? 1 : 0);
