<?php

// Разделение инстансов wg/wg1. Проверяются ровно те места, из-за которых
// действие уезжало в чужой инстанс:
//  - getInstanceWG()/wgNum(): пер-запросный $this->wg имеет приоритет над
//    глобальным wg_instance, а на свежей установке (pac.json = {}) работает
//    фолбэк в нулевой инстанс;
//  - cbWG()/разбор префикса «wgN:»: кнопка несёт инстанс сама и не зависит от
//    LRU-карты wg_msg, а команды без префикса разбираются как раньше;
//  - promptInstWG(): ответ на промпт применяется к инстансу, зафиксированному
//    в момент показа промпта, а легаси-стэш (без инстанса) сохраняет прежнее
//    поведение;
//  - LRU-отсечка карты «сообщение → инстанс»;
//  - peerIndexByClient(): пир ищется по адресу, а не по индексу — включая
//    выключенного пира с закомментированными ключами;
//  - PORT_FALLBACK: у wg1 внешний порт по умолчанию НЕ совпадает с wg;
//  - ensureWgGuard(): клиентам wg/awg закрыта docker-сеть, кроме внутреннего
//    DNS, и правила стоят раньше пользовательских.

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function wgAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

// pac.json подменяем массивом в памяти: тесты не должны трогать /config.
class WgInstTestBot extends Bot
{
    public array $pacFake = [];

    public function getPacConf()
    {
        return $this->pacFake;
    }

    public function setPacConf(array $conf)
    {
        $this->pacFake = $conf;
        return true;
    }
}

$bot = (new ReflectionClass(WgInstTestBot::class))->newInstanceWithoutConstructor();

// ── 1. getInstanceWG / wgNum ────────────────────────────────────────────────
$bot->pacFake = [];
unset($bot->wg);
wgAssert($bot->getInstanceWG() === 'wg', 'свежая установка: сервис по умолчанию wg');
wgAssert($bot->getInstanceWG(1) === '', 'свежая установка: префикс пустой');
wgAssert($bot->wgNum() === 0, 'свежая установка: wgNum = 0');

$bot->pacFake = ['wg_instance' => 1];
wgAssert($bot->getInstanceWG() === 'wg1', 'глобальный wg_instance=1 → сервис wg1');
wgAssert($bot->getInstanceWG(1) === 'wg1_', 'глобальный wg_instance=1 → префикс wg1_');

// Пер-запросный инстанс сильнее глобального — на этом держатся export/import,
// trackWgOnline и ответы на промпты.
$bot->wg = 0;
wgAssert($bot->getInstanceWG() === 'wg', '$this->wg=0 перекрывает wg_instance=1');
$bot->pacFake = ['wg_instance' => 0];
$bot->wg = 1;
wgAssert($bot->getInstanceWG(1) === 'wg1_', '$this->wg=1 перекрывает wg_instance=0');
unset($bot->wg);
wgAssert($bot->getInstanceWG(1) === '', 'unset($this->wg) возвращает к глобальному');

// Легаси-строка "1" в pac.json не должна читаться как нулевой инстанс.
$bot->pacFake = ['wg_instance' => '1'];
wgAssert($bot->wgNum() === 1, 'wg_instance строкой "1" — это первый инстанс');

// selectWG нормализует и пишет только при реальной смене.
$bot->pacFake = [];
$bot->selectWG('1');
wgAssert(($bot->pacFake['wg_instance'] ?? null) === 1, 'selectWG приводит к int');
wgAssert($bot->wgNum() === 1, 'selectWG выставляет и пер-запросный инстанс');
$bot->selectWG(0);
wgAssert(($bot->pacFake['wg_instance'] ?? null) === 0, 'selectWG(0) снимает пин');

// ── 2. cbWG + разбор префикса «wgN:» ────────────────────────────────────────
$bot->pacFake = [];
$bot->wg = 1;
wgAssert($bot->cbWG('/delete 3_0') === 'wg1:/delete 3_0', 'cbWG вшивает инстанс');
$bot->wg = 0;
wgAssert($bot->cbWG('/delete 3_0') === 'wg0:/delete 3_0', 'cbWG для нулевого инстанса');

// Тот же разбор, что в action(). Кнопка старого сообщения (без префикса)
// обязана проходить дальше нетронутой — иначе сломались бы все уже
// отрисованные меню.
$strip = function (string $cb): array {
    if (preg_match('~^wg(?P<inst>[01]):(?P<cb>.+)$~s', $cb, $m)) {
        return [(int) $m['inst'], $m['cb']];
    }
    return [null, $cb];
};
wgAssert($strip('wg1:/delete 3_0') === [1, '/delete 3_0'], 'префикс снимается, команда цела');
wgAssert($strip('wg0:/menu client 2_0') === [0, '/menu client 2_0'], 'нулевой инстанс');
wgAssert($strip('/delete 3_0') === [null, '/delete 3_0'], 'легаси-кнопка проходит как есть');
wgAssert($strip('wg2:/x') === [null, 'wg2:/x'], 'посторонний префикс не съедается');
// Имя relay уезжает в callback_data последним аргументом — оно не должно
// ломать разбор.
wgAssert($strip('wg1:/setWgRelay 0 my.relay-1') === [1, '/setWgRelay 0 my.relay-1'],
    'аргумент с точками/дефисами переживает разбор');

// ── 3. promptInstWG ─────────────────────────────────────────────────────────
$bot->pacFake = ['wg_instance' => 1];
unset($bot->wg);
$bot->promptInstWG(null);
wgAssert($bot->wgNum() === 1, 'легаси-стэш (null) не меняет инстанс');
$bot->promptInstWG(0);
wgAssert($bot->wgNum() === 0, 'инстанс из стэша перекрывает глобальный');
// Ровно тот сценарий, ради которого это делалось: промпт открыт в нулевом
// инстансе, сообщение перерисовано первым, ответ обязан лечь в нулевой.
$bot->pacFake = ['wg_instance' => 1];
$bot->wg = 1;
$bot->promptInstWG(0);
wgAssert($bot->getInstanceWG(1) === '', 'ответ на промпт применяется к инстансу промпта');

// ── 4. LRU карты «сообщение → инстанс» ──────────────────────────────────────
$cap = Bot::WG_MSG_MAX;
wgAssert($cap >= 100, 'кап карты не меньше прежнего');
$m = [];
for ($i = 0; $i < $cap + 50; $i++) {
    $m["1:$i"] = $i % 2;
    $m = array_slice($m, -$cap, null, true);
}
wgAssert(count($m) === $cap, 'карта не растёт сверх капа');
wgAssert(array_key_exists('1:' . ($cap + 49), $m), 'последняя запись на месте');
wgAssert(!array_key_exists('1:0', $m), 'самая старая запись вытеснена');
// Пере-вставка существующего ключа двигает его в конец (иначе активное меню
// вытеснялось бы наравне с забытыми).
$m2 = ['a' => 0, 'b' => 1, 'c' => 0];
unset($m2['a']);
$m2['a'] = 1;
wgAssert(array_key_last($m2) === 'a', 'пере-вставка двигает запись в конец');

// ── 5. peerIndexByClient ────────────────────────────────────────────────────
$conf = ['peers' => [
    ['PublicKey' => 'A', 'AllowedIPs' => '10.0.1.2/32', '## name' => 'first'],
    ['# PublicKey' => 'B', '# AllowedIPs' => '10.0.1.3/32', '# ## name' => 'off'],
    ['PublicKey' => 'C', 'AllowedIPs' => '10.0.1.4/32', '## name' => 'third'],
]];
$cl = fn(string $addr) => ['interface' => ['Address' => $addr]];
wgAssert($bot->peerIndexByClient($conf, $cl('10.0.1.2/32')) === 0, 'первый пир по адресу');
wgAssert($bot->peerIndexByClient($conf, $cl('10.0.1.4/32')) === 2, 'третий пир по адресу');
wgAssert($bot->peerIndexByClient($conf, $cl('10.0.1.3/32')) === 1,
    'выключенный пир находится по закомментированному AllowedIPs');
wgAssert($bot->peerIndexByClient($conf, $cl('10.0.1.9/32')) === null,
    'отсутствующий адрес — null, а не случайный индекс');
wgAssert($bot->peerIndexByClient($conf, ['interface' => []]) === null, 'клиент без адреса — null');
wgAssert($bot->peerIndexByClient([], $cl('10.0.1.2/32')) === null, 'пустой конфиг — null');
// Смысл всей правки: индекс клиента и индекс пира разошлись, и удаление «по
// индексу» снесло бы чужого.
wgAssert($bot->peerIndexByClient($conf, $cl('10.0.1.4/32')) !== 1,
    'адрес третьего клиента не резолвится во второго пира');

// ── 6. Фолбэк портов ────────────────────────────────────────────────────────
wgAssert((Bot::PORT_FALLBACK['wg1'] ?? null) === '51821', 'у wg1 свой внешний порт по умолчанию');
wgAssert((Bot::PORT_FALLBACK['wg'] ?? '51820') !== (Bot::PORT_FALLBACK['wg1'] ?? null),
    'фолбэки портов wg и wg1 не совпадают');

// ── 7. ensureWgGuard ────────────────────────────────────────────────────────
$x = [
    'outbounds' => [['protocol' => 'freedom', 'tag' => 'direct']],
    'routing'   => ['rules' => [
        ['type' => 'field', 'outboundTag' => 'block', 'domain' => ['example.com']],
    ]],
];
$bot->ensureWgGuard($x);
$tags = array_column($x['outbounds'], 'tag');
wgAssert(in_array('block', $tags, true), 'blackhole-outbound добавлен, если его не было');
$r = $x['routing']['rules'];
wgAssert(count($r) === 3, 'к существующим правилам добавлены ровно два');
wgAssert(($r[0]['outboundTag'] ?? '') === 'direct' && ($r[0]['port'] ?? '') === '53'
    && $r[0]['ip'] === [Bot::INTERNAL_DNS],
    'первым идёт allow внутреннего DNS');
wgAssert(($r[1]['outboundTag'] ?? '') === 'block' && $r[1]['ip'] === [Bot::DOCKER_NET],
    'вторым — блок docker-сети');
wgAssert($r[0]['inboundTag'] === ['wg-in'] && $r[1]['inboundTag'] === ['wg-in'],
    'оба правила привязаны к inbound клиентов wg');
wgAssert(($r[2]['domain'] ?? null) === ['example.com'], 'пользовательское правило сохранено и ушло вниз');

// Идемпотентность: повторный вызов (а он идёт на каждый restartXray) не должен
// плодить копии.
$bot->ensureWgGuard($x);
wgAssert(count($x['routing']['rules']) === 3, 'повторный вызов не дублирует правила');
wgAssert(count(array_filter($x['outbounds'], fn($o) => ($o['tag'] ?? '') === 'block')) === 1,
    'повторный вызов не дублирует outbound');

// xrayUpdateRules() переписывает routing.rules целиком — гейт обязан
// восстановиться следующим restartXray и снова оказаться первым.
$x['routing']['rules'] = [['type' => 'field', 'outboundTag' => 'warp', 'ip' => ['1.1.1.1']]];
$bot->ensureWgGuard($x);
wgAssert(($x['routing']['rules'][0]['inboundTag'] ?? null) === ['wg-in'],
    'после перезаписи правил гейт снова впереди пользовательских');

// Клиентские подсети wg/awg (по умолчанию 10.0.1.0/24 и 10.0.3.0/24) не входят
// в блокируемый диапазон — иначе поломали бы сам туннель.
wgAssert(Bot::DOCKER_NET === '10.10.0.0/16', 'блокируется именно подсеть сборки');

// ── 8. sanitizeConfValue ────────────────────────────────────────────────────
wgAssert(Bot::sanitizeConfValue("Home\nPC") === 'Home PC', 'перевод строки схлопывается');
wgAssert(Bot::sanitizeConfValue("a\r\n\r\nb") === 'a b', 'CRLF-подряд схлопываются в один пробел');
wgAssert(Bot::sanitizeConfValue("  spaced  ") === 'spaced', 'края обрезаются');
wgAssert(mb_strlen(Bot::sanitizeConfValue(str_repeat('x', 500))) === 256, 'длина ограничена');
// Ради чего всё: имя пира уезжает строкой «## name = ...» в серверный wg0.conf.
wgAssert(!str_contains(Bot::sanitizeConfValue("ok\n[Peer]\nPublicKey = evil"), "\n"),
    'инъекция строк конфига через имя пира невозможна');

if ($failed) {
    echo "wg_instance_test FAILED ($failed)\n";
    exit(1);
}
echo "wg_instance_test OK\n";
