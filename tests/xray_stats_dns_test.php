<?php

// Счётчики xray одним statsquery + DNS-домены для AdGuard/подписки.
//
// 1) xrayStatCounters() обязан ОТЛИЧАТЬ «прочитать не удалось» (null) от
//    «счётчиков ещё нет» (пустая карта). Раньше оба случая давали нули, и
//    xrayStatsUser() затирал ими накопленный session при лежащем контейнере.
// 2) Тег пользовательского inbound берётся из конфига, а не из литерала
//    'vless_tls': после restore бэкапа тег бывает другим, и счётчик молча
//    отдавал ноль.
// 3) dnsDomains() — главный домен плюс алиасы, без пустых и дублей: на нём
//    держатся вывод DoH/DoT, SAN сертификата и dns.nameserver в подписке.

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function t(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        echo "FAIL: $msg\n";
        $failed++;
    }
}

class XrayStatsTestBot extends Bot
{
    public string $sshOut     = '';
    public bool   $sshFail    = false;
    public array  $xrayFake   = [];
    public array  $statsFake  = [];
    public ?array $statsSaved = null;
    public array  $pacFake    = [];
    public array  $sshCmds    = [];

    protected function withXrayApplyLock(callable $fn) { return $fn(); }

    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
    {
        $this->sshCmds[]   = $cmd;
        $this->sshFailed   = $this->sshFail;
        return $this->sshFail ? '' : $this->sshOut;
    }

    public function getXray()
    {
        return $this->xrayFake;
    }

    public function getXrayStats()
    {
        return $this->statsFake;
    }

    public function setXrayStats($x)
    {
        $this->statsSaved = $x;
    }

    public function getPacConf()
    {
        return $this->pacFake;
    }
}

$bot = (new ReflectionClass(XrayStatsTestBot::class))->newInstanceWithoutConstructor();

// ── xrayStatCounters ────────────────────────────────────────────────────────

// Штатный ответ. Формат сверен с исходниками Xray-core v26.7.28:
// main/commands/all/api/stats_query.go → showJSONResponse → common/reflect
// MarshalToJson. Маршалер там САМОПИСНЫЙ (не protojson): имена полей берутся
// из protobuf-тега json= (то есть stat/name/value), value — обычное JSON-число
// (int64 через encoding/json), а нулевое значение ВЫБРАСЫВАЕТСЯ по omitempty.
// Строковый вариант тоже принимаем — на случай смены маршалера в ядре.
$bot->sshFail = false;
$bot->sshOut  = json_encode(['stat' => [
    ['name' => 'inbound>>>vless_tls>>>traffic>>>downlink', 'value' => 123456],
    ['name' => 'inbound>>>vless_tls>>>traffic>>>uplink'],
    ['name' => 'user>>>bob>>>traffic>>>downlink', 'value' => '77'],
]]);
$m = $bot->xrayStatCounters();
t(is_array($m), 'валидный statsquery → массив');
t(($m['inbound>>>vless_tls>>>traffic>>>downlink'] ?? null) === 123456, 'value-число разобрано в int');
t(($m['inbound>>>vless_tls>>>traffic>>>uplink'] ?? null) === 0, 'опущенный по omitempty value = 0');
t(($m['user>>>bob>>>traffic>>>downlink'] ?? null) === 77, 'value-строка тоже разобрана в int');

// name у пустой строки тоже выбрасывается omitempty — запись без имени
// не должна попасть в карту под ключом ''.
$bot->sshOut = json_encode(['stat' => [['value' => 5], ['name' => 'ok', 'value' => 1]]]);
$m = $bot->xrayStatCounters();
t($m === ['ok' => 1], 'счётчик без имени пропущен');

// Простаивающий сервер: счётчиков ещё нет. protojson отдаёт "{}" — это ВАЛИДНОЕ
// состояние, а не отказ, иначе статистика никогда не запишется после рестарта.
$bot->sshOut = '{}';
t($bot->xrayStatCounters() === [], 'пустой {} → пустая карта, не null');

// Ядро без statsquery / api выключен: на stdout приезжает текст ошибки.
$bot->sshOut = "failed to dial 127.0.0.1:8080: connection refused\n";
t($bot->xrayStatCounters() === null, 'не-JSON → null');

// Оборванный ответ: в лог НЕ должен уехать кусок JSON — имена счётчиков несут
// email'ы клиентов. Ловим то, что реально пишется в error_log.
$bot->sshOut = '{"stat": [{"name": "user>>>secret@example.com>>>traffic';
$logFile = tempnam(sys_get_temp_dir(), 'xrlog');
$prevLog = ini_get('error_log');
ini_set('error_log', $logFile);
t($bot->xrayStatCounters() === null, 'битый JSON → null');
ini_set('error_log', (string) $prevLog);
$logged = (string) file_get_contents($logFile);
unlink($logFile);
t(!str_contains($logged, 'secret@example.com'), 'обрывок JSON не утёк в лог');
t(str_contains($logged, 'malformed JSON'), 'факт битого ответа записан');

// Контейнер лежит.
$bot->sshOut  = '';
$bot->sshFail = true;
t($bot->xrayStatCounters() === null, 'ssh упал → null');
$bot->sshFail = false;
$bot->sshOut  = '';
t($bot->xrayStatCounters() === null, 'пустой вывод → null');

// Единственный вызов на цикл — в этом весь смысл замены 2+2N вызовов stats.
$bot->sshCmds = [];
$bot->sshOut  = '{}';
$bot->xrayStatCounters();
t(count($bot->sshCmds) === 1, 'один ssh-вызов на снятие всех счётчиков');
t(str_contains($bot->sshCmds[0], 'statsquery'), 'используется statsquery');

// ── xrayStatsUser ───────────────────────────────────────────────────────────

$mkXray = fn (string $tag) => [
    'inbounds' => [
        ['tag' => $tag, 'settings' => ['clients' => [
            ['email' => 'bob'],
            ['email' => 'new_client'],
        ]]],
        ['tag' => 'api'],
        ['tag' => 'wg-in'],
    ],
];

// Тег НЕ 'vless_tls' — так бывает после restore бэкапа или правки xray.json из
// webapp. Прежний код брал литерал и писал в session ноль.
$bot->xrayFake  = $mkXray('vless_restored');
$bot->statsFake = [
    'global'  => ['download' => 10, 'upload' => 20],
    'session' => ['download' => 1, 'upload' => 2],
    'users'   => [0 => ['global' => ['download' => 5, 'upload' => 6], 'session' => ['download' => 0, 'upload' => 0]]],
];
$bot->sshOut = json_encode(['stat' => [
    ['name' => 'inbound>>>vless_restored>>>traffic>>>downlink', 'value' => '1000'],
    ['name' => 'inbound>>>vless_restored>>>traffic>>>uplink',   'value' => '2000'],
    ['name' => 'inbound>>>wg-in>>>traffic>>>downlink',          'value' => '333'],
    ['name' => 'inbound>>>api>>>traffic>>>downlink',            'value' => '9'],
    ['name' => 'user>>>bob>>>traffic>>>downlink',               'value' => '44'],
]]);
$bot->statsSaved       = null;
$bot->time_xray_stats  = null;
$bot->xrayStatsUser();
$s = $bot->statsSaved;
t(is_array($s), 'статистика записана');
t($s['session'] === ['download' => 1000, 'upload' => 2000], 'session взят по тегу из конфига');
t(($s['inbounds']['wg-in'] ?? null) === ['download' => 333, 'upload' => 0], 'wg-in попал в разбивку');
t(!isset($s['inbounds']['api']), 'служебный api в разбивку не попал');
t(($s['users'][0]['session']['download'] ?? null) === 44, 'session клиента прочитан');
t(($s['users'][0]['global']['download'] ?? null) === 5, 'global клиента сохранён');
// У нового клиента записи в xraystats.json ещё нет — прежний код сыпал сюда
// «Undefined array key» на каждый цикл крона.
t(($s['users'][1]['global'] ?? null) === ['download' => 0, 'upload' => 0], 'новый клиент → global 0 без warning');
t(($s['users'][1]['session'] ?? null) === ['download' => 0, 'upload' => 0], 'новый клиент → session 0');

// Контейнер лежит: НИЧЕГО не пишем. Прежний код клал в session нули, и в меню,
// панели подписки и проверке квот трафик на цикл схлопывался.
$bot->statsSaved      = null;
$bot->time_xray_stats = null;
$bot->sshFail         = true;
$bot->xrayStatsUser();
t($bot->statsSaved === null, 'при отказе statsquery прежние показания не трогаем');
$bot->sshFail = false;

// Простаивающий сервер (счётчиков нет) — это НЕ отказ, нули записать надо.
$bot->statsSaved      = null;
$bot->time_xray_stats = null;
$bot->sshOut          = '{}';
$bot->xrayStatsUser();
t(($bot->statsSaved['session'] ?? null) === ['download' => 0, 'upload' => 0], 'пустая карта → нули пишутся');

// Троттлинг раз в 60с не сломан.
$bot->statsSaved = null;
$bot->xrayStatsUser();
t($bot->statsSaved === null, 'повторный вызов в пределах 60с ничего не делает');

// collectSession() зовётся из restartXray(), а рестарт обнуляет счётчики ядра.
// Разбивка по inbound'ам — снимок этих счётчиков, поэтому она обязана уйти
// вместе с session, иначе меню до минуты показывает несуществующие цифры.
$bot->statsFake = [
    'global'   => ['download' => 10, 'upload' => 20],
    'session'  => ['download' => 3, 'upload' => 4],
    'users'    => [],
    'inbounds' => ['wg-in' => ['download' => 333, 'upload' => 0]],
];
$bot->statsSaved = null;
$bot->collectSession();
t(!isset($bot->statsSaved['inbounds']), 'collectSession убирает разбивку по inbound');
t($bot->statsSaved['global'] === ['download' => 13, 'upload' => 24], 'session свёрнут в global как раньше');
t($bot->statsSaved['session'] === ['download' => 0, 'upload' => 0], 'session обнулён');

// ── dnsDomains ──────────────────────────────────────────────────────────────

// Внешний restart при простое основного inbound не теряет трафик проб узла.
$bot->pacFake = ['exits' => ['aaaaaaaa' => []]];
$bot->statsFake = ['session' => ['upload' => 0, 'download' => 0], 'exits' => ['aaaaaaaa' => [
    'global' => ['up' => 100, 'down' => 200], 'session' => ['up' => 50, 'down' => 70], 'base' => ['up' => 10, 'down' => 20], 'since' => 123]]];
$bot->time_xray_stats = null;
$bot->sshOut = json_encode(['stat' => [['name' => 'outbound>>>vpnbot-exit-aaaaaaaa>>>traffic>>>uplink', 'value' => 3]]]);
$bot->xrayStatsUser();
t($bot->statsSaved['exits']['aaaaaaaa']['global'] === ['up' => 140, 'down' => 250], 'трафик узла свёрнут независимо от основного inbound');
t($bot->statsSaved['exits']['aaaaaaaa']['base'] === ['up' => 0, 'down' => 0], 'отметка сброса узла обнулена после смены ядра');
t($bot->statsSaved['exits']['aaaaaaaa']['session'] === ['up' => 3, 'down' => 0], 'новая сессия узла сохранена');
$bot->statsFake = $bot->statsSaved; $bot->time_xray_stats = null; $bot->xrayStatsUser();
t($bot->statsSaved['exits']['aaaaaaaa']['global'] === ['up' => 140, 'down' => 250], 'повторный снимок не начисляет узел дважды');
$bot->statsFake['session']['download'] = 100; $bot->statsFake['exits']['aaaaaaaa']['session']['down'] = 80;
$bot->time_xray_stats = null; $bot->xrayStatsUser();
t($bot->statsSaved['exits']['aaaaaaaa']['global'] === ['up' => 143, 'down' => 330], 'общий fold и отдельный выход не начисляют дважды');

t($bot->dnsDomains(['domain' => 'a.com']) === ['a.com'], 'только главный домен');
t(
    $bot->dnsDomains(['domain' => 'a.com', 'domain_aliases' => ['b.com', 'c.com']]) === ['a.com', 'b.com', 'c.com'],
    'главный домен впереди алиасов'
);
t($bot->dnsDomains(['domain' => '']) === [], 'без домена — пустой список');
t($bot->dnsDomains([]) === [], 'пустой конфиг — пустой список');
t(
    $bot->dnsDomains(['domain' => 'a.com', 'domain_aliases' => [' b.com ', 'a.com', 'b.com', '']]) === ['a.com', 'b.com'],
    'пробелы обрезаны, дубли и пустые убраны'
);
// delDomainAlias оставляет дырявые ключи до array_values — список не должен
// зависеть от индексов.
t(
    $bot->dnsDomains(['domain' => 'a.com', 'domain_aliases' => [2 => 'b.com', 5 => 'c.com']]) === ['a.com', 'b.com', 'c.com'],
    'разреженные ключи алиасов'
);
// Без аргумента берётся текущий pac-конфиг.
$bot->pacFake = ['domain' => 'x.org', 'domain_aliases' => ['y.org']];
t($bot->dnsDomains() === ['x.org', 'y.org'], 'без аргумента читается pac-конфиг');

echo $failed ? "\n$failed FAILED\n" : "OK\n";
exit($failed ? 1 : 0);
