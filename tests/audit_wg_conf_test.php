<?php

// Целостность серверного и клиентского конфигов WireGuard.
// Регрессии из аудита 2026-08-12 (K1, K2 и соседи):
//  - readConfig(): «[…]» в ИМЕНИ пира расщепляло его на пустую секцию, конфиг
//    терял пира и awg-quick падал на setconf;
//  - sanitizeConfValue(): скобки проходили в конфиг наравне с переводами строк;
//  - sanitizeAllowedIps(): список подсетей резался посреди CIDR;
//  - switchAmnezia(): readConfig() === null давал заглушку из одной секции
//    [Interface] — без ключей и без единого пира;
//  - presharedKey(): пустой ответ ssh сохранялся в pac.json навсегда;
//  - peerIndexByClient(): строгая сигнатура роняла вызов на null-конфиге.

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function wgConfAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

class WgConfTestBot extends Bot
{
    public array $pacFake   = [];
    public array $sshReply  = [];   // подстрока команды => ответ
    public string $sshDefault = '';
    public array $saved     = [];   // что ушло в saveClients()
    public array $sent      = [];   // сообщения пользователю
    public bool  $restarted = false;

    public function getPacConf()
    {
        return $this->pacFake;
    }

    public function setPacConf(array $conf)
    {
        $this->pacFake = $conf;
        return true;
    }

    public function ssh($cmd, $service = '', $sudo = false, $log = false)
    {
        foreach ($this->sshReply as $needle => $out) {
            if (str_contains((string) $cmd, $needle)) {
                return $out;
            }
        }
        return $this->sshDefault;
    }

    public function readClients(): array
    {
        return $this->saved;
    }

    public function saveClients(array $clients)
    {
        $this->saved = $clients;
        return true;
    }

    public function getPorts()
    {
        return ['wg' => ['port' => 51820], 'wg1' => ['port' => 51821]];
    }

    public function restartWG($conf, $norestart = false)
    {
        $this->restarted = true;
        return true;
    }

    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false)
    {
        $this->sent[] = $text;
        return ['result' => ['message_id' => 1]];
    }

    public function menu($type = false, $arg = false, $return = false)
    {
        return null;
    }
}

$bot = (new ReflectionClass(WgConfTestBot::class))->newInstanceWithoutConstructor();
$bot->pacFake = [];

// ── 1. sanitizeConfValue ────────────────────────────────────────────────────
wgConfAssert(Bot::sanitizeConfValue("Home [PC]") === 'Home  PC',
    'скобки в имени вырезаются');
wgConfAssert(Bot::sanitizeConfValue("a\nPrivateKey = x") === 'a PrivateKey = x',
    'перевод строки схлопывается в пробел');
wgConfAssert(mb_strlen(Bot::sanitizeConfValue(str_repeat('щ', 400))) === 256,
    'длина режется по умолчанию на 256');

// ── 2. sanitizeAllowedIps ───────────────────────────────────────────────────
$list = implode(',', array_fill(0, 500, '10.0.0.0/24')); // заведомо длиннее лимита
$cut  = Bot::sanitizeAllowedIps($list);
wgConfAssert(mb_strlen($cut) <= Bot::WG_ALLOWEDIPS_MAX, 'список не длиннее лимита');
wgConfAssert(!str_ends_with($cut, ',') && preg_match('~/24$~', $cut),
    "обрезка по границе элемента, а не посреди CIDR: ..." . mb_substr($cut, -12));
foreach (explode(',', $cut) as $e) {
    wgConfAssert($e === '10.0.0.0/24', "элемент списка цел: $e");
}
wgConfAssert(Bot::sanitizeAllowedIps('10.0.0.0/24, 192.168.0.0/16') === '10.0.0.0/24, 192.168.0.0/16',
    'короткий список не трогаем');

// ── 3. readConfig: имя со скобками не рвёт конфиг ───────────────────────────
$conf = implode(PHP_EOL, [
    '[Interface]',
    'PrivateKey = SERVERKEY',
    'Address = 10.8.0.1/24',
    'ListenPort = 51820',
    '',
    '[Peer]',
    '## name = Home [PC]',
    'PublicKey = PEER1',
    'AllowedIPs = 10.8.0.2/32',
    '',
    '# [Peer]',
    '# ## name = Off client',
    '# PublicKey = PEER2',
    '# AllowedIPs = 10.8.0.3/32',
]);
$bot->sshReply = ['cat /etc/wireguard/wg0.conf' => $conf];
$r = $bot->readConfig();
wgConfAssert(($r['interface']['PrivateKey'] ?? '') === 'SERVERKEY', 'секция [Interface] прочитана');
wgConfAssert(($r['interface']['ListenPort'] ?? '') === '51820', 'ListenPort на месте');
wgConfAssert(count($r['peers'] ?? []) === 2, 'ровно два пира, имя со скобками не создало третьего: '
    . count($r['peers'] ?? []));
wgConfAssert(($r['peers'][0]['## name'] ?? '') === 'Home [PC]', 'имя пира прочитано целиком');
wgConfAssert(($r['peers'][0]['PublicKey'] ?? '') === 'PEER1', 'ключ остался у своего пира');
wgConfAssert(($r['peers'][1]['# PublicKey'] ?? '') === 'PEER2', 'выключенный пир («# [Peer]») распознан');

// Пустой ответ (контейнер не отвечает) — по-прежнему null.
$bot->sshReply = [];
$bot->sshDefault = '';
wgConfAssert($bot->readConfig() === null, 'недоступный контейнер → null');

// ── 4. peerIndexByClient на null-конфиге ────────────────────────────────────
wgConfAssert($bot->peerIndexByClient(null, ['interface' => ['Address' => '10.8.0.2/32']]) === null,
    'null-конфиг не роняет поиск пира');

// ── 5. presharedKey: мусор и пустой ответ не сохраняются ────────────────────
$bot->pacFake = [];
$bot->sshDefault = '';
wgConfAssert($bot->presharedKey() === '', 'пустой ответ ssh → пустой ключ');
wgConfAssert(!isset($bot->pacFake['presharedkey']), 'пустой ключ не сохранён в pac.json');
$bot->sshReply = ['genpsk' => "cannot connect to container\n"];
wgConfAssert($bot->presharedKey() === '', 'мусор от stderr ключом не считается');
wgConfAssert(!isset($bot->pacFake['presharedkey']), 'мусор не сохранён в pac.json');
$psk = base64_encode(random_bytes(32));
$bot->sshReply = ['genpsk' => "$psk\n"];
wgConfAssert($bot->presharedKey() === $psk, 'валидный ключ возвращается');
wgConfAssert(($bot->pacFake['presharedkey'] ?? '') === $psk, 'валидный ключ сохранён');

// ── 6. switchAmnezia при недоступном конфиге ────────────────────────────────
$bot = (new ReflectionClass(WgConfTestBot::class))->newInstanceWithoutConstructor();
$bot->pacFake   = ['amnezia' => 0];
$bot->saved     = [['interface' => ['## name' => 'c1', 'Address' => '10.8.0.2/32'], 'peers' => [[]]]];
$before         = $bot->saved;
$bot->sshDefault = '';           // и cat, и genpsk отвечают пустым
$bot->input     = ['chat' => 1, 'message_id' => 2];
$bot->switchAmnezia();
wgConfAssert($bot->restarted === false, 'при недоступном конфиге wg0.conf не переписывается');
wgConfAssert($bot->saved === $before, 'clients.json не тронут');
wgConfAssert(($bot->pacFake['amnezia'] ?? null) === 0, 'флаг amnezia в pac.json не переключён');
wgConfAssert(count($bot->sent) === 1, 'пользователь получил сообщение об ошибке');

// Контейнер отвечает на cat, но не на genpsk — конфиги тоже не трогаем.
$bot->sent      = [];
$bot->restarted = false;
$bot->pacFake   = ['amnezia' => 0];
$bot->sshReply  = ['cat /etc/wireguard/wg0.conf' => implode(PHP_EOL, [
    '[Interface]', 'PrivateKey = SERVERKEY', 'Address = 10.8.0.1/24', 'ListenPort = 51820',
    '', '[Peer]', 'PublicKey = PEER1', 'AllowedIPs = 10.8.0.2/32',
])];
$bot->switchAmnezia();
wgConfAssert($bot->restarted === false, 'без presharedkey конфиг не переписывается');
wgConfAssert(($bot->pacFake['amnezia'] ?? null) === 0, 'pac.json откачен к исходному состоянию');
wgConfAssert(count($bot->sent) === 1, 'сообщение о недоступном presharedkey');

// ── 7. Мелочи раздела WireGuard (аудит 2026-08-12) ──────────────────────────
// getName(): у выключенного пира ключи закомментированы, у клиентской записи
// нет AllowedIPs — раньше это давало по два «Undefined array key» на строку
// меню.
wgConfAssert(Bot::sanitizeConfValue('x') === 'x', 'sanitizeConfValue проходной случай');
$bot = (new ReflectionClass(WgConfTestBot::class))->newInstanceWithoutConstructor();
wgConfAssert($bot->getName(['## name' => 'Home']) === 'Home', 'имя берётся из ## name');
wgConfAssert($bot->getName(['AllowedIPs' => '10.8.0.2/32']) === '10.8.0.2/32', 'фолбэк на AllowedIPs');
wgConfAssert($bot->getName(['Address' => '10.8.0.3/32']) === '10.8.0.3/32', 'фолбэк на Address');
wgConfAssert($bot->getName(['# AllowedIPs' => '10.8.0.4/32']) === '10.8.0.4/32', 'выключенный пир');
wgConfAssert($bot->getName([]) === '', 'пустая запись не роняет меню');

// getStatusPeer(): промах отдаёт массив, а не null — вызывающий читает поля
// результата сразу.
wgConfAssert($bot->getStatusPeer('nope', []) === [], 'пустой статус при промахе');
wgConfAssert($bot->getStatusPeer('nope', [['peer' => 'other']]) === [], 'промах по чужому пиру');
$peer = ['peer' => 'KEY', 'latest handshake' => '5 seconds ago'];
wgConfAssert($bot->getStatusPeer('KEY', [$peer]) === $peer, 'найденный пир возвращается целиком');
wgConfAssert(($bot->getStatusPeer('nope', [])['latest handshake'] ?? '') === '',
    'чтение поля у промаха не падает');

// ── MTU серверного интерфейса ───────────────────────────────────────────────
// Без строки MTU в [Interface] awg-quick считает его сам как «внешний MTU минус
// 80» (set_mtu_up), то есть 1420 — величина для ВАНИЛЬНОГО WireGuard с 32
// байтами накладных. AmneziaWG добавляет сверху junk S4 и
// ContentPaddingAddition, и при 1420 внутри пакет на проводе доходил до 1540
// при пути 1500: крупный UDP без PMTUD уходил негабаритным и молча гиб.
// Держим серверный MTU равным клиентскому — это согласовано по построению и не
// разъезжается при ротации ключей и правке параметров обфускации.
$b = (new ReflectionClass(WgConfTestBot::class))->newInstanceWithoutConstructor();
$b->mtu = 1350;
$b->dns = '10.0.0.1';
$b->pacFake = [];

$srvData = ['interface' => ['Address' => '10.0.0.1/24', 'ListenPort' => 51820, 'PrivateKey' => 'aaa='], 'peers' => []];
$cliData = ['interface' => ['Address' => '10.0.0.2/32', 'PrivateKey' => 'bbb='], 'peers' => []];

$srv = $b->createConfig($srvData);
$cli = $b->createConfig($cliData);
wgConfAssert(str_contains($srv, "\nMTU = 1350"), 'серверный [Interface] получает MTU');
wgConfAssert(str_contains($cli, "\nMTU = 1350"), 'клиентский тоже');
// Равенство двух сторон — суть правки: несимметричный MTU и создавал дыру.
preg_match('~^MTU = (\d+)$~m', $srv, $ms);
preg_match('~^MTU = (\d+)$~m', $cli, $mc);
wgConfAssert(($ms[1] ?? 'x') === ($mc[1] ?? 'y'), 'MTU сервера и клиента совпадают');
// Серверу DNS не нужен: wg-quick попытался бы править resolv.conf на сервере.
wgConfAssert(!str_contains($srv, 'DNS = '), 'в серверный конфиг DNS не уезжает');
wgConfAssert(str_contains($cli, 'DNS = '), 'а в клиентский — уезжает');

// Инстансная настройка MTU ведёт за собой обе стороны.
$b->pacFake = ['mtu' => 1280];
wgConfAssert(str_contains($b->createConfig($srvData), "\nMTU = 1280"), 'сервер следует настройке инстанса');
wgConfAssert(str_contains($b->createConfig($cliData), "\nMTU = 1280"), 'клиент следует ей же');

// MTU — директива awg-quick, а не ключ wg(8): quick забирает её себе и в
// setconf не передаёт. Значение обязано быть голым числом, иначе `ip link set
// mtu` получит мусор.
wgConfAssert((bool) preg_match('~^MTU = \d+$~m', $srv), 'MTU — голое число без единиц и кавычек');

if ($failed) {
    echo "audit_wg_conf_test FAILED: $failed\n";
    exit(1);
}
echo "audit_wg_conf_test OK\n";
