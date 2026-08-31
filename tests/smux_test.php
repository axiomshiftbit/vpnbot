<?php

// SMUX (sing-mux форк-ядра Jolymmiles/Xray-core).
//
// Проверяем инварианты, нарушение которых стоит дорого и НЕ видно глазом:
//
//  1. SMuxConfig.Build() (infra/conf/xray.go форка) отвергает конфиг на СТАРТЕ
//     ядра: неизвестный protocol, отрицательные лимиты, и — главное —
//     maxStreams вместе с maxConnections/minStreams. Цена ошибки: xray не
//     поднимается вовсе.
//  2. У трёх клиентов три разных диалекта одних и тех же полей — camelCase у
//     форка, snake_case у sing-box, kebab-case у mihomo. Опечатка в имени не
//     ломает конфиг громко: клиент молча игнорирует ключ и мультиплекс
//     выключается, а в меню он «включён».
//  3. Апстримное ядро несущий коннект sing-mux не распознаёт. Если блок уедет
//     клиенту при xray_core != fork — перестанут ходить ВСЕ, кто обновил
//     подписку. Значит блока при апстримном ядре быть не должно ни в одном из
//     трёх форматов.
//  4. Brutal: ставка обязана попадать в грамматику parseSMuxRate и быть не
//     ниже 65536 байт/с, иначе Build() снова роняет старт.

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function smAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

// Конструктор Bot тянет токен/окружение — он тут не нужен: все методы smux
// принимают pac-конфиг аргументом и в файлы не ходят.
$bot = (new ReflectionClass(Bot::class))->newInstanceWithoutConstructor();

// Повтор parseSMuxRate() форка: число + опциональная единица [K|M|G|T](b|B)ps,
// голое число = Mbps, биты делятся на 8. Возвращает байты в секунду.
function smRateBytes(string $v): ?int
{
    if (!preg_match('~^(\d+)\s?(([KMGT])?([bB])ps)?$~', trim($v), $m)) {
        return null;
    }
    $rate = (int) $m[1];
    if (empty($m[2])) {
        return intdiv($rate * 1000000, 8);
    }
    $mult = match ($m[3] ?? '') {
        'K' => 1000, 'M' => 1000000, 'G' => 1000000000, 'T' => 1000000000000,
        default => 1,
    };

    return $m[4] === 'b' ? intdiv($rate * $mult, 8) : $rate * $mult;
}

// Собирает pac с нужным ядром и настройками smux поверх дефолтов.
function smPac(string $core, array $over = []): array
{
    $s = Bot::smuxDefaults();
    $s['enabled'] = 1;
    foreach ($over as $k => $v) {
        if ($k === 'brutal') {
            $s['brutal'] = $v + $s['brutal'];
            continue;
        }
        $s[$k] = $v;
    }

    return ['xray_core' => $core, 'smux' => $s];
}

// --- 1: дефолты проходят валидацию форка -------------------------------------
$d = Bot::smuxDefaults();
smAssert(in_array($d['protocol'], ['smux', 'h2mux'], true),
    'protocol из набора форка (yamux сервер отвергает)');
smAssert($d['max_connections'] >= 0 && $d['min_streams'] >= 0 && $d['max_streams'] >= 0,
    'лимиты неотрицательны');
smAssert(!($d['max_streams'] > 0 && ($d['max_connections'] > 0 || $d['min_streams'] > 0)),
    'maxStreams не задан вместе с maxConnections/minStreams');
smAssert(empty($d['enabled']) && empty($d['configured']) && empty($d['brutal']['enabled']),
    'по умолчанию всё выключено');
smAssert(smRateBytes($d['brutal']['up']) >= 65536 && smRateBytes($d['brutal']['down']) >= 65536,
    'дефолтные полки Brutal не ниже порога 65536 B/s');

// --- 2: три диалекта несут одни и те же значения -----------------------------
$pac = smPac('fork', ['max_connections' => 3, 'min_streams' => 4, 'max_streams' => 0,
    'padding' => 1, 'only_tcp' => 1, 'protocol' => 'smux']);

$x = ['outbounds' => [['tag' => 'proxy', 'mux' => ['enabled' => false]]]];
$bot->applyClientSmux($x, 0, $pac, 's');
$si = ['outbounds' => [['tag' => 'proxy']]];
$bot->applyClientSmux($si, 0, $pac, 'si');
$cl = ['proxies' => [['name' => 'proxy']]];
$bot->applyClientSmux($cl, 0, $pac, 'cl');

$xs = $x['outbounds'][0]['smux']      ?? null;
$ss = $si['outbounds'][0]['multiplex'] ?? null;
$cs = $cl['proxies'][0]['smux']        ?? null;

smAssert(is_array($xs) && is_array($ss) && is_array($cs), 'блок появился во всех трёх форматах');

// Точный набор ключей: лишний ключ клиент проигнорирует, недостающий —
// молча уронит настройку в дефолт.
smAssert($xs !== null && array_keys($xs) === ['enabled', 'protocol', 'maxConnections', 'minStreams', 'maxStreams', 'padding', 'onlyTcp'],
    'xray-диалект: camelCase, набор полей SMuxConfig');
smAssert($ss !== null && array_keys($ss) === ['enabled', 'protocol', 'max_connections', 'min_streams', 'max_streams', 'padding'],
    'sing-box-диалект: snake_case, без only_tcp (такого поля у него нет)');
smAssert($cs !== null && array_keys($cs) === ['enabled', 'protocol', 'max-connections', 'min-streams', 'max-streams', 'only-tcp', 'padding', 'statistic'],
    'mihomo-диалект: kebab-case, набор полей SingMuxOption');

$triples = [
    ['maxConnections', 'max_connections', 'max-connections', 3],
    ['minStreams',     'min_streams',     'min-streams',     4],
    ['maxStreams',     'max_streams',     'max-streams',     0],
];
foreach ($triples as [$kx, $ksi, $kcl, $want]) {
    smAssert(($xs[$kx] ?? null) === $want && ($ss[$ksi] ?? null) === $want && ($cs[$kcl] ?? null) === $want,
        "$kx/$ksi/$kcl совпадают и равны $want");
}
smAssert(($xs['protocol'] ?? '') === 'smux' && ($ss['protocol'] ?? '') === 'smux' && ($cs['protocol'] ?? '') === 'smux',
    'protocol одинаков во всех трёх');
smAssert(($xs['padding'] ?? null) === true && ($ss['padding'] ?? null) === true && ($cs['padding'] ?? null) === true,
    'padding одинаков во всех трёх');
smAssert(($xs['onlyTcp'] ?? null) === true && ($cs['only-tcp'] ?? null) === true,
    'only-tcp доезжает до xray и mihomo');
smAssert(!array_key_exists('mux', $x['outbounds'][0]),
    'mux.cool снят: Build() запрещает mux и smux на одном outbound');

// --- 3: при апстримном ядре блока нет ни в одном формате ---------------------
$pacOrigin = smPac('origin');
foreach ([['s', ['outbounds' => [['tag' => 'proxy']]]],
          ['si', ['outbounds' => [['tag' => 'proxy']]]],
          ['cl', ['proxies' => [['name' => 'proxy']]]]] as [$t, $conf]) {
    $bot->applyClientSmux($conf, 0, $pacOrigin, $t);
    smAssert(!str_contains(json_encode($conf), 'multiplex') && !str_contains(json_encode($conf), 'smux'),
        "t=$t: при xray_core=origin блок не уезжает клиенту");
}
// Выключенный smux при форковом ядре — тоже пусто.
$pacOff = smPac('fork', []);
$pacOff['smux']['enabled'] = 0;
$conf = ['outbounds' => [['tag' => 'proxy']]];
$bot->applyClientSmux($conf, 0, $pacOff, 'si');
smAssert(!isset($conf['outbounds'][0]['multiplex']), 'smux off — блока нет');

// --- 1 (продолжение): взаимоисключающие лимиты нормализуются -----------------
// Даже если в pac.json лежит невалидная пара (правка руками, старый конфиг),
// наружу обязана уехать валидная: цена — не поднявшееся ядро у клиента.
$pacBad = smPac('fork', ['max_streams' => 8, 'max_connections' => 3, 'min_streams' => 4]);
$conf = ['outbounds' => [['tag' => 'proxy']]];
$bot->applyClientSmux($conf, 0, $pacBad, 's');
$b = $conf['outbounds'][0]['smux'];
smAssert($b['maxStreams'] === 8 && $b['maxConnections'] === 0 && $b['minStreams'] === 0,
    'maxStreams > 0 обнуляет maxConnections/minStreams');

$pacNeg = smPac('fork', ['max_connections' => -5, 'min_streams' => -1, 'max_streams' => -3]);
$conf = ['outbounds' => [['tag' => 'proxy']]];
$bot->applyClientSmux($conf, 0, $pacNeg, 's');
$b = $conf['outbounds'][0]['smux'];
smAssert($b['maxConnections'] >= 0 && $b['minStreams'] >= 0 && $b['maxStreams'] >= 0,
    'отрицательные лимиты режутся по нулю');

$pacProto = smPac('fork', ['protocol' => 'yamux']);
$conf = ['outbounds' => [['tag' => 'proxy']]];
$bot->applyClientSmux($conf, 0, $pacProto, 'si');
smAssert(($conf['outbounds'][0]['multiplex']['protocol'] ?? '') === 'smux',
    'yamux (его форк-сервер не принимает) заменяется на smux');

// --- 5: logicalHalfClose ------------------------------------------------------
// Поле форка 26.8.25+: живёт ТОЛЬКО в xray-диалекте и ТОЛЬКО при smux. С h2mux
// Build() отвергает конфиг («logicalHalfClose is only supported by SMUX»), а
// неизвестное значение — тоже: обе ошибки видны как «ядро не поднялось».
smAssert(Bot::smuxDefaults()['half_close'] === 'off',
    'по умолчанию half-close выключен — байты несущего коннекта прежние');
foreach (['off', 'auto', 'require'] as $ok) {
    smAssert(Bot::smuxHalfClose($ok) === $ok, "политика «{$ok}» принимается как есть");
}
foreach (['', 'on', '1', 'yes', 'REQUIRE '] as $raw) {
    $want = trim(strtolower($raw)) === 'require' ? 'require' : 'off';
    smAssert(Bot::smuxHalfClose($raw) === $want, "значение «{$raw}» нормализуется в {$want}");
}

$pacHc = smPac('fork', ['protocol' => 'smux', 'half_close' => 'auto']);
$conf  = ['outbounds' => [['tag' => 'proxy']]];
$bot->applyClientSmux($conf, 0, $pacHc, 's');
smAssert(($conf['outbounds'][0]['smux']['logicalHalfClose'] ?? '') === 'auto',
    'xray-диалект несёт logicalHalfClose');
foreach (['si' => 'multiplex', 'cl' => 'smux'] as $t => $key) {
    $conf = $t === 'cl' ? ['proxies' => [['name' => 'proxy']]] : ['outbounds' => [['tag' => 'proxy']]];
    $bot->applyClientSmux($conf, 0, $pacHc, $t);
    smAssert(!str_contains(json_encode($conf), 'logicalHalfClose'),
        "t=$t: у sing-box/mihomo такого ключа нет — не подсовываем");
}

// h2mux: поле обязано исчезнуть, иначе ядро у клиента не стартует.
$pacH2 = smPac('fork', ['protocol' => 'h2mux', 'half_close' => 'require']);
$conf  = ['outbounds' => [['tag' => 'proxy']]];
$bot->applyClientSmux($conf, 0, $pacH2, 's');
smAssert(!isset($conf['outbounds'][0]['smux']['logicalHalfClose']),
    'h2mux + logicalHalfClose Build() отвергает — поля быть не должно');

// Тот же инвариант через плейсхолдер шаблона с пер-шаблонным протоколом.
$conf = ['outbounds' => [['tag' => 'proxy', 'smux' => '~smux:h2mux~']]];
$bot->applyClientSmux($conf, 0, smPac('fork', ['half_close' => 'auto']), 's');
smAssert(($conf['outbounds'][0]['smux']['protocol'] ?? '') === 'h2mux'
    && !isset($conf['outbounds'][0]['smux']['logicalHalfClose']),
    '~smux:h2mux~ в шаблоне тоже не получает logicalHalfClose');

// off — ключа нет вовсе: пустая строка/«off» для форка равнозначны, но лишний
// ключ в подписке — лишний повод для расхождения диалектов.
$conf = ['outbounds' => [['tag' => 'proxy']]];
$bot->applyClientSmux($conf, 0, smPac('fork', ['half_close' => 'off']), 's');
smAssert(!isset($conf['outbounds'][0]['smux']['logicalHalfClose']),
    'half-close off — ключа в конфиге нет');

// --- 4: грамматика и порог Brutal -------------------------------------------
foreach (['100 Mbps', '1 Gbps', '50Mbps', '1000', '512 KBps'] as $ok) {
    smAssert(Bot::smuxRate($ok) === $ok, "ставка «{$ok}» принимается как есть");
    smAssert(smRateBytes($ok) !== null, "ставка «{$ok}» разбирается парсером форка");
}
foreach (['fast', '1 Gb', '-5 Mbps', '', '100 mbps'] as $bad) {
    smAssert(Bot::smuxRate($bad) === '100 Mbps', "мусорная ставка «{$bad}» заменяется дефолтом");
}
// Грамматике соответствуют, но ниже порога 65536 B/s — Build() отвергает такой
// конфиг на СТАРТЕ ядра, поэтому наружу они уходить не должны.
foreach (['1 Kbps', '100 Kbps', '1 KBps', '0'] as $low) {
    smAssert(smRateBytes($low) < 65536, "ставка «{$low}» действительно ниже порога");
    smAssert(Bot::smuxRate($low) === '100 Mbps', "слишком низкая ставка «{$low}» заменяется дефолтом");
}
// Реализация в bot.php и независимый повтор парсера в тесте обязаны сходиться.
foreach (['100 Mbps', '1 Gbps', '50Mbps', '1000', '512 KBps', '1 Kbps', '8 bps'] as $r) {
    smAssert(Bot::smuxRateBytes($r) === smRateBytes($r), "парсер ставки «{$r}» совпадает с эталоном");
}
smAssert(Bot::smuxRateBytes('fast') === null, 'мусор не разбирается в число');

$pacBrutal = smPac('fork', ['brutal' => ['enabled' => 1, 'up' => '200 Mbps', 'down' => 'мусор']]);
$conf = ['proxies' => [['name' => 'proxy']]];
$bot->applyClientSmux($conf, 0, $pacBrutal, 'cl');
$bo = $conf['proxies'][0]['smux']['brutal-opts'] ?? null;
smAssert(is_array($bo) && $bo['up'] === '200 Mbps' && $bo['down'] === '100 Mbps',
    'mihomo: brutal-opts с нормализованными ставками');
$conf = ['outbounds' => [['tag' => 'proxy']]];
$bot->applyClientSmux($conf, 0, $pacBrutal, 'si');
smAssert(isset($conf['outbounds'][0]['multiplex']['brutal']),
    'sing-box: ключ называется brutal, а не brutal-opts');
// Мало назвать блок правильно: внутри у sing-box СВОИ имена и типы. На строки
// «200 Mbps» ядро отвечает `unknown field "up"` и не импортирует конфиг целиком
// — проверено на 1.14.0. Ставка нормализуется до мегабит: «мусор» → 100 Mbps.
$sbBrutal = $conf['outbounds'][0]['multiplex']['brutal'];
smAssert(($sbBrutal['up_mbps'] ?? null) === 200 && ($sbBrutal['down_mbps'] ?? null) === 100,
    'sing-box: ставки брутала целыми мегабитами в up_mbps/down_mbps');
smAssert(!isset($sbBrutal['up']) && !isset($sbBrutal['down']),
    'sing-box: строковых up/down в блоке нет');
$conf = ['outbounds' => [['tag' => 'proxy']]];
$bot->applyClientSmux($conf, 0, $pacBrutal, 's');
smAssert(isset($conf['outbounds'][0]['smux']['brutal-opts']),
    'xray-форк: ключ называется brutal-opts');

// --- серверная часть: в xray.json пишется ТОЛЬКО brutal ----------------------
$mk = fn() => ['inbounds' => [['tag' => 'vless_tls', 'protocol' => 'vless'], ['tag' => 'api']]];

$c = $mk();
$bot->ensureSmuxInbound($c, smPac('fork'));
smAssert(!isset($c['inbounds'][0]['smux']),
    'smux без Brutal серверу не нужен — блок в inbound не пишется');

$c = $mk();
$bot->ensureSmuxInbound($c, $pacBrutal);
smAssert(($c['inbounds'][0]['smux']['brutal-opts']['enabled'] ?? null) === true
    && ($c['inbounds'][0]['smux']['brutal-opts']['up'] ?? '') === '200 Mbps',
    'Brutal пишется на клиентский inbound');
smAssert(!isset($c['inbounds'][1]['smux']),
    'служебные inbound (api/wg-in) не трогаются');

// Снятие: блок обязан УХОДИТЬ из конфига, а не оставаться от прошлого раза.
$c = $mk();
$c['inbounds'][0]['smux'] = ['brutal-opts' => ['enabled' => true, 'up' => '1 Gbps', 'down' => '1 Gbps']];
$bot->ensureSmuxInbound($c, smPac('origin'));
smAssert(!isset($c['inbounds'][0]['smux']),
    'переключение на апстримное ядро снимает brutal-opts из xray.json');

$c = $mk();
$c['inbounds'][0]['smux'] = ['brutal-opts' => ['enabled' => true, 'up' => '1 Gbps', 'down' => '1 Gbps']];
$pacNoBrutal = $pacBrutal;
$pacNoBrutal['smux']['brutal']['enabled'] = 0;
$bot->ensureSmuxInbound($c, $pacNoBrutal);
smAssert(!isset($c['inbounds'][0]['smux']), 'выключенный Brutal снимает блок');

// Пустой/битый конфиг не должен ронять генерацию.
$c = [];
$bot->ensureSmuxInbound($c, $pacBrutal);
smAssert($c === [], 'конфиг без inbounds остаётся нетронутым');

// --- плейсхолдер ~smux~ в шаблоне --------------------------------------------
// Пошаблонный контроль: где стоит маркер — туда блок, где не стоит — ничего.
// При неактивном smux ключ обязан ИСЧЕЗНУТЬ: статический блок при апстримном
// ядре означает клиента, который шлёт несущий коннект в никуда.
$pacFork = smPac('fork');

$tpl = ['outbounds' => [
    ['tag' => 'proxy', 'type' => 'vless', 'multiplex' => '~smux~'],
    ['tag' => 'second', 'type' => 'vless'],
]];
$c = $tpl;
$bot->applyClientSmux($c, 0, $pacFork, 'si');
smAssert(is_array($c['outbounds'][0]['multiplex'] ?? null), 'плейсхолдер заменён блоком');
smAssert(!isset($c['outbounds'][1]['multiplex']), 'узел без маркера не трогается');

$c = $tpl;
$bot->applyClientSmux($c, 0, $pacOrigin, 'si');
smAssert(!array_key_exists('multiplex', $c['outbounds'][0]),
    'при апстримном ядре ключ с маркером удаляется целиком');

// Протокол на шаблон: ~smux:h2mux~ перебивает глобальный smux.
$c = ['outbounds' => [['tag' => 'proxy', 'multiplex' => '~smux:h2mux~']]];
$bot->applyClientSmux($c, 0, $pacFork, 'si');
smAssert(($c['outbounds'][0]['multiplex']['protocol'] ?? '') === 'h2mux',
    'протокол из маркера перебивает глобальный');

// Несуществующий протокол в маркере не совпадает с шаблоном вовсе — строка
// осталась бы как есть, поэтому такой маркер обязан ловиться валидатором.
require_once __DIR__ . '/../app/ClashTemplateValidator.php';
$ref = new ReflectionMethod(ClashTemplateValidator::class, 'scanUnknownPlaceholders');
$ref->setAccessible(true);
$w = [];
$ref->invokeArgs(null, [['a' => '~smux~', 'b' => '~smux:h2mux~', 'c' => '~smux:yamux~', 'd' => '~nosuch~'], '', &$w]);
smAssert(count($w) === 2, 'валидатор ругается ровно на yamux и на неизвестный маркер: ' . json_encode($w, JSON_UNESCAPED_UNICODE));
smAssert(str_contains(implode(' ', $w), 'yamux'), 'yamux помечен как неподдерживаемый протокол');

// Маркер в mihomo-шаблоне — свой диалект.
$c = ['proxies' => [['name' => 'proxy', 'smux' => '~smux~']]];
$bot->applyClientSmux($c, 0, $pacFork, 'cl');
smAssert(($c['proxies'][0]['smux']['max-connections'] ?? null) === 3,
    'mihomo: маркер разворачивается в kebab-диалект');

// Маркер снимает mux.cool на том же узле (xray-формат).
$c = ['outbounds' => [['tag' => 'proxy', 'mux' => ['enabled' => true], 'smux' => '~smux~']]];
$bot->applyClientSmux($c, 0, $pacFork, 's');
smAssert(!array_key_exists('mux', $c['outbounds'][0]), 'маркер снимает mux.cool с узла');

// Шаблон БЕЗ маркера продолжает получать блок автоматически — старое поведение
// не должно сломаться от появления новой возможности.
$c = ['outbounds' => [['tag' => 'proxy']]];
$bot->applyClientSmux($c, 0, $pacFork, 'si');
smAssert(isset($c['outbounds'][0]['multiplex']), 'шаблон без маркера: автовставка как раньше');

// Маркер есть, но не на главном узле — автовставка НЕ добавляет второй блок.
$c = ['outbounds' => [['tag' => 'proxy'], ['tag' => 'other', 'multiplex' => '~smux~']]];
$bot->applyClientSmux($c, 0, $pacFork, 'si');
smAssert(!isset($c['outbounds'][0]['multiplex']) && isset($c['outbounds'][1]['multiplex']),
    'шаблон с маркером управляет мультиплексом сам');

// --- проба контейнера: «xr молчит» ≠ «форка нет» -----------------------------
// Разница принципиальна: во втором случае авторемонт сносит настройку ядра и
// гасит smux, и если спутать её с недоступным на минуту контейнером — рабочая
// конфигурация умрёт от рестарта xr.
class SmuxProbeBot extends Bot
{
    public string $out    = '';
    public string $cmd    = '';
    public bool   $failed = false;

    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
    {
        $this->cmd       = $cmd;
        $this->sshFailed = $this->failed;

        return $this->out;
    }
}

$probeBot = (new ReflectionClass(SmuxProbeBot::class))->newInstanceWithoutConstructor();

$probeBot->out    = '1|/usr/bin/xray-smux|reno cubic brutal|/usr/bin/xray-smux|Xray 26.8.20 (Xray, Penetrates Everything.(jesus))';
$probeBot->failed = false;
$pr = $probeBot->xrayCoreProbe(true);
smAssert($pr['ok'] && $pr['fork'] && $pr['active'] === 'fork' && $pr['brutal'] && $pr['running'] === 'fork',
    'форк на месте, симлинк на него, он же и работает, brutal доступен');
smAssert($probeBot->getXrayVersion() === '26.8.20', 'версия достаётся из той же пробы');

$probeBot->out = '|/usr/bin/xray|reno cubic|/usr/bin/xray|Xray 26.7.28 (Xray, Penetrates Everything.)';
$pr = $probeBot->xrayCoreProbe(true);
smAssert($pr['ok'] && !$pr['fork'] && $pr['active'] === 'origin' && !$pr['brutal'] && $pr['running'] === 'origin',
    'апстримный образ: форка нет, brutal нет');

// Симлинк уже поправлен, а обслуживает всё ещё старый процесс: `ln -sf` без
// рестарта. Поля обязаны разойтись — на этом различии стоит вся починка.
$probeBot->out = '1|/usr/bin/xray-smux|brutal|/usr/bin/xray|Xray 26.7.28 (Xray, Penetrates Everything.)';
$pr = $probeBot->xrayCoreProbe(true);
smAssert($pr['active'] === 'fork' && $pr['running'] === 'origin',
    'симлинк и запущенный процесс читаются раздельно');

// Пустой pid обязан отсекаться в самой команде: `readlink -f /proc//exe` не
// возвращает пустоту, а печатает существующий /proc/exe — и незапущенное ядро
// поехало бы в running как чужой бинарь.
smAssert(str_contains($probeBot->cmd, 'test -n "$p" && readlink -f /proc/$p/exe'),
    'проба не зовёт readlink с пустым pid');
// Шаблон pgrep записан так, чтобы не найти шелл, который эту же команду и
// выполняет: в его argv лежит "[x]ray run", а ищется "xray run".
smAssert(str_contains($probeBot->cmd, '[x]ray run'), 'шаблон pgrep не матчит сам себя');

// Ядро не поднято (нет клиентов — start_xray.sh не запускает xray). Это НЕ
// «работает апстрим»: иначе свежая установка выглядела бы как расхождение.
$probeBot->out = '1|/usr/bin/xray-smux|brutal||Xray 26.8.20 (Xray, Penetrates Everything.(jesus))';
$pr = $probeBot->xrayCoreProbe(true);
smAssert($pr['active'] === 'fork' && $pr['running'] === '',
    'xray не запущен — running пустой, а не origin');

// Разделитель в строке версии портит только саму версию, но не поля до неё.
$probeBot->out = '1|/usr/bin/xray-smux|brutal|/usr/bin/xray-smux|Xray 26.8.20 (a|b)';
$pr = $probeBot->xrayCoreProbe(true);
smAssert($pr['fork'] && $pr['active'] === 'fork' && $pr['version'] === 'Xray 26.8.20 (a|b)',
    'версия идёт последней и склеивается обратно целиком');

$probeBot->out    = '';
$probeBot->failed = true;
$pr = $probeBot->xrayCoreProbe(true);
smAssert(!$pr['ok'] && !$pr['fork'] && $pr['running'] === '',
    'контейнер не ответил — ok=false, а не «форка нет»');

// Кеш пробы: повторный вызов без $fresh не ходит в ssh заново.
$probeBot->out    = '1|/usr/bin/xray-smux|brutal|/usr/bin/xray-smux';
$probeBot->failed = false;
$probeBot->xrayCoreProbe(true);
$probeBot->out = 'мусор';
smAssert($probeBot->xrayCoreProbe()['fork'], 'проба кешируется на время запроса');
smAssert(!$probeBot->xrayCoreProbe(true)['fork'], '$fresh=true перечитывает состояние');

// --- автопочинка симлинка ----------------------------------------------------
// Расхождение «форк в образе есть, а работает апстрим» чинится возвратом
// симлинка, а не откатом настройки: smux уже уехал клиентам, и гасить его —
// значит ждать, пока каждый перечитает подписку. Но чинить бесконечно тоже
// нельзя: рестарт рвёт живые сессии.
class SmuxFixBot extends Bot
{
    public array  $probe   = [];
    public array  $cmds    = [];
    public array  $restart = [];
    public string $marker  = '';
    public array  $pacConf = [];
    public bool   $sshFail = false;

    public function xrayCoreProbe(bool $fresh = false): array
    {
        return $this->probe;
    }

    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
    {
        $this->cmds[]    = $cmd;
        $this->sshFailed = $this->sshFail;

        return '';
    }

    public function getPacConf()
    {
        return $this->pacConf;
    }

    public function setPacConf(array $conf)
    {
        $this->pacConf = $conf;

        return true;
    }

    public function getXray()
    {
        return [];
    }

    public function restartXray($c, $norestart = false)
    {
        $this->restart[] = $norestart;
    }

    // Маркер живёт в /logs — в тесте туда писать некуда, но ЧТО именно ушло бы
    // в файл, проверить надо: разъехавшийся маркер и есть причина, по которой
    // симлинк возвращается к апстриму на каждом пересоздании контейнера.
    public function writeCoreMarker(string $core): bool
    {
        $this->marker = $core;

        return true;
    }
}

function smFixBot(array $probe): SmuxFixBot
{
    $b = (new ReflectionClass(SmuxFixBot::class))->newInstanceWithoutConstructor();
    $b->probe     = $probe + ['ok' => true, 'fork' => true, 'active' => 'fork', 'running' => 'fork', 'brutal' => false, 'version' => ''];
    $b->cmds      = [];
    $b->restart   = [];
    $b->marker    = '';
    $b->pacConf   = smPac('fork');
    $b->sshFail   = false;
    $b->xrLinkFix = 0;

    return $b;
}

// Симлинк уехал на апстрим — возвращаем его и рестартуем ядро.
$b = smFixBot(['active' => 'origin', 'running' => 'origin']);
$b->checkXrayCore();
smAssert(count($b->cmds) === 1 && str_contains($b->cmds[0], 'ln -sf /usr/bin/xray-smux /usr/local/bin/xray'),
    'расхождение симлинка: ссылка возвращается на форк');
smAssert($b->marker === 'fork', 'маркер переписывается вместе с симлинком');
smAssert(count($b->restart) === 1, 'после возврата симлинка ядро перезапускается');
smAssert($b->xrayCore($b->pacConf) === 'fork' && !empty($b->pacConf['smux']['enabled']),
    'настройка и smux при этом НЕ трогаются — чинить есть чем');

// Симлинк на месте, но обслуживает старый процесс — тоже расхождение.
$b = smFixBot(['active' => 'fork', 'running' => 'origin']);
$b->checkXrayCore();
smAssert(count($b->restart) === 1, 'старый процесс на апстриме: ядро перезапускается');

// Всё сходится — не трогаем ничего.
$b = smFixBot([]);
$b->checkXrayCore();
smAssert($b->cmds === [] && $b->restart === [], 'консистентное состояние: починка не запускается');

// Ядро ещё не поднято — это не повод рестартовать пустоту.
$b = smFixBot(['running' => '']);
$b->checkXrayCore();
smAssert($b->cmds === [] && $b->restart === [], 'xray не запущен — расхождением не считаем');

// Контейнер молчит — состояние неизвестно, чинить нельзя.
$b = smFixBot(['ok' => false, 'active' => 'origin', 'running' => 'origin']);
$b->checkXrayCore();
smAssert($b->cmds === [] && $b->restart === [] && $b->xrayCore($b->pacConf) === 'fork',
    'xr недоступен — ни починки, ни отката настройки');

// Форка нет в образе — чинить нечем, откатываем настройку и гасим smux.
$b = smFixBot(['fork' => false, 'active' => 'origin', 'running' => 'origin']);
$b->checkXrayCore();
smAssert($b->xrayCore($b->pacConf) === 'origin' && empty($b->pacConf['smux']['enabled']) && $b->marker === 'origin',
    'форка нет в образе — откат на апстрим и smux off');

// ssh отвалился между пробой и починкой — рестартовать вслепую нечего.
$b = smFixBot(['active' => 'origin', 'running' => 'origin']);
$b->sshFail = true;
$b->checkXrayCore();
smAssert(count($b->cmds) === 1 && $b->restart === [] && $b->marker === '',
    'ssh упал — ни рестарта, ни записи маркера');

// Починка не приживается: после трёх попыток уходим на апстрим штатным путём,
// иначе рестарт ядра встал бы на вечный пятиминутный круг.
$b = smFixBot(['active' => 'origin', 'running' => 'origin']);
for ($i = 0; $i < 4; $i++) {
    $b->time_xraycore = 0;
    $b->checkXrayCore();
}
smAssert(count($b->restart) === 4, 'четвёртая попытка не чинит симлинк заново');
smAssert($b->xrayCore($b->pacConf) === 'origin' && empty($b->pacConf['smux']['enabled']),
    'после трёх безуспешных попыток — откат на апстрим и smux off');

// Успешная починка обнуляет счётчик: следующая поломка снова получит три
// попытки, а не остаток от прошлой.
$b = smFixBot(['active' => 'origin', 'running' => 'origin']);
$b->time_xraycore = 0;
$b->checkXrayCore();
$b->probe = ['ok' => true, 'fork' => true, 'active' => 'fork', 'running' => 'fork', 'brutal' => false, 'version' => ''];
$b->time_xraycore = 0;
$b->checkXrayCore();
smAssert($b->xrLinkFix === 0, 'консистентное состояние обнуляет счётчик попыток');

// --- гейт half-close по версии ядра ------------------------------------------
// require запрещает откат на прежний несущий коннект: со старым форком на той
// стороне соединение не поднимется вовсе. Поэтому крайнее значение доступно
// только когда сервер точно умеет договариваться (форк 26.8.25+).
$b = smFixBot(['version' => 'Xray 26.8.24 (Xray, Penetrates Everything.)']);
smAssert(!$b->smuxHalfCloseReady(), 'форк 26.8.24 договориться не умеет');
$b = smFixBot(['version' => 'Xray 26.8.25-1457 (Xray, Penetrates Everything.)']);
smAssert($b->smuxHalfCloseReady(), 'форк 26.8.25-1457 умеет (суффикс — время сборки, не pre-release)');
$b = smFixBot(['version' => 'Xray 26.8.26-0855 (Xray, Penetrates Everything.)']);
smAssert($b->smuxHalfCloseReady(), 'форк 26.8.26-0855 умеет');
$b = smFixBot(['version' => 'Xray 26.8.27-1556 (Xray, Penetrates Everything.)']);
smAssert($b->smuxHalfCloseReady(), 'форк 26.8.27-1556 (текущий пин) умеет');
// Версия относится к АКТИВНОМУ ядру: пока по симлинку отвечает апстрим (или
// проба молчит), про форк она не говорит ничего — запрещать нечего.
$b = smFixBot(['active' => 'origin', 'running' => 'origin', 'version' => 'Xray 26.7.28 (Xray, Penetrates Everything.)']);
smAssert($b->smuxHalfCloseReady(), 'активен апстрим — версия про форк ничего не говорит');
$b = smFixBot(['ok' => false, 'version' => '']);
smAssert($b->smuxHalfCloseReady(), 'xr недоступен — настройку не блокируем');
$b = smFixBot(['version' => '']);
smAssert($b->smuxHalfCloseReady(), 'пустой вывод version — тоже «неизвестно»');

// Пин форк-ядра в .env не ниже v26.8.25. Гейт выше умеет понижать require до
// auto САМ, поэтому старое ядро в образе не ломает клиентов — оно тихо отнимает
// у пользователя крайний режим half-close, и заметить это в меню нельзя ничем.
// Собранный нами образ обязан ехать с ядром, которое договариваться умеет.
$env = (string) @file_get_contents(__DIR__ . '/../.env');
if (preg_match('~^XRAY_FORK_VERSION=v?(\d+)\.(\d+)\.(\d+)~m', $env, $m)) {
    $ver = sprintf('%04d%04d%04d', $m[1], $m[2], $m[3]);
    smAssert($ver >= sprintf('%04d%04d%04d', 26, 8, 25),
        "XRAY_FORK_VERSION={$m[0]}: договорённость о half-close появилась в v26.8.25");
} else {
    smAssert(false, 'XRAY_FORK_VERSION в .env не найден');
}

// Откат образа на форк старее 26.8.25: require в подписке = тишина у клиента,
// поэтому периодическая проверка понижает его до auto сама.
$b = smFixBot(['version' => 'Xray 26.8.24 (Xray, Penetrates Everything.)']);
$b->pacConf['smux']['half_close'] = 'require';
$b->checkXrayCore();
smAssert(($b->pacConf['smux']['half_close'] ?? '') === 'auto',
    'старое ядро понижает require до auto');
// auto и off трогать нечего — они на старом ядре работают как раньше.
foreach (['auto', 'off'] as $keep) {
    $b = smFixBot(['version' => 'Xray 26.8.24 (Xray, Penetrates Everything.)']);
    $b->pacConf['smux']['half_close'] = $keep;
    $b->checkXrayCore();
    smAssert(($b->pacConf['smux']['half_close'] ?? '') === $keep, "«{$keep}» не трогаем");
}
// Ядро умеет — настройку не понижаем.
$b = smFixBot(['version' => 'Xray 26.8.26-0855 (Xray, Penetrates Everything.)']);
$b->pacConf['smux']['half_close'] = 'require';
$b->checkXrayCore();
smAssert(($b->pacConf['smux']['half_close'] ?? '') === 'require',
    'ядро 26.8.26 — require остаётся');
// Молчащий контейнер: состояние неизвестно, понижать вслепую нельзя.
$b = smFixBot(['ok' => false, 'version' => '']);
$b->pacConf['smux']['half_close'] = 'require';
$b->checkXrayCore();
smAssert(($b->pacConf['smux']['half_close'] ?? '') === 'require',
    'xr недоступен — настройку не трогаем');

// Троттлинг: без него cron дёргал бы ssh каждые 10 секунд.
$b = smFixBot(['active' => 'origin', 'running' => 'origin']);
$b->time_xraycore = time();
$b->checkXrayCore();
smAssert($b->cmds === [], 'проверка не чаще раза в 5 минут');

if ($failed) {
    echo "smux_test FAILED: $failed\n";
    exit(1);
}
echo "smux_test OK\n";
