<?php

// Mux.Cool поверх XHTTP (форк 26.10.5+). Цена ошибки здесь — не «опция не
// работает», а «клиенты не ходят»: апстрим и старый форк TCP-сессию Mux.Cool
// на XHTTP рвут, поэтому блок не должен уехать клиенту ни при каком другом
// ядре или транспорте, а включение обязано проверять версию ядра в образе.

require_once __DIR__ . '/../app/bot.php';

$checks = 0;
function xmAssert(bool $ok, string $message): void
{
    global $checks;
    $checks++;
    if (!$ok) {
        throw new RuntimeException('xhttp_mux_test: ' . $message);
    }
}

class XhttpMuxTestBot extends Bot
{
    public array $p = [];
    public array $x = [];
    public array $versions = ['origin' => '26.9.30', 'fork' => '26.10.5-1858'];
    public array $answers = [];
    public int $restarts = 0;
    public bool $restartOk = true;
    public function __construct() { $this->input = ['callback_id' => 1, 'chat' => 1, 'message_id' => 1]; }
    public function getPacConf() { return $this->p; }
    public function setPacConf(array $p) { $this->p = $p; return true; }
    public function getXray() { return $this->x; }
    public function restartXray($c, $save = true) { $this->restarts++; if ($this->restartOk) { $this->x = $c; } return $this->restartOk; }
    public function xrayCoreInventory(): array { return $this->versions; }
    public function answer($callback_id, $textNotify = false, $notify = false) { $this->answers[] = $textNotify; }
    public function smuxMenu() {}
    public function i18n(string $key): string { return $key; }
}

function xmServer(array $extra = ['xPaddingBytes' => '100-1000', 'scStreamUpServerSecs' => '20-80']): array
{
    return ['inbounds' => [['streamSettings' => ['network' => 'xhttp',
        'xhttpSettings' => ['mode' => 'auto', 'path' => '/ws'] + ($extra ? ['extra' => $extra] : [])]]]];
}

$on = ['transport' => 'xhttp', 'xray_core' => 'fork', 'xhttp_mux' => ['enabled' => 1]];
$bot = new XhttpMuxTestBot();

// ── Когда блок вообще допустим ───────────────────────────────────────────────
xmAssert($bot->xhttpMuxActive($on), 'форк + xhttp + включено');
foreach ([['xray_core' => 'origin'], ['xray_core' => 'origin2'], ['transport' => 'Reality'],
    ['transport' => 'Websocket'], ['xhttp_mux' => ['enabled' => 0]], ['xhttp_mux' => null]] as $change) {
    $p = array_merge($on, $change);
    xmAssert(!$bot->xhttpMuxActive($p), 'не активен при ' . json_encode($change));
    xmAssert($bot->xhttpMuxClient($p) === null, 'клиентского блока нет при ' . json_encode($change));
}
xmAssert($bot->xhttpMuxClient($on) === ['enabled' => true, 'concurrency' => 8, 'xudpConcurrency' => 16,
    'xudpProxyUDP443' => 'allow'], 'клиентский блок Mux.Cool: TCP одной сессией, UDP как без mux');

// ── Серверный KeepAlive: только нужные ключи, чужие не тронуты ───────────────
$c = xmServer();
$bot->ensureXhttpMuxInbound($c, $on);
$extra = $c['inbounds'][0]['streamSettings']['xhttpSettings']['extra'];
xmAssert($extra === ['xPaddingBytes' => '100-1000', 'scStreamUpServerSecs' => '20-80']
    + Bot::XHTTP_MUX_KEEPALIVE, 'KeepAlive добавлен к существующим настройкам');
$again = $c;
$bot->ensureXhttpMuxInbound($again, $on);
xmAssert($again === $c, 'повторное применение ничего не меняет');
$bot->ensureXhttpMuxInbound($c, ['xray_core' => 'origin'] + $on);
xmAssert($c === xmServer(), 'при другом ядре KeepAlive снят, остальное как было');
$bare = xmServer([]);
$bot->ensureXhttpMuxInbound($bare, ['xhttp_mux' => ['enabled' => 0]] + $on);
xmAssert(!array_key_exists('extra', $bare['inbounds'][0]['streamSettings']['xhttpSettings']),
    'пустой extra не появляется (в JSON он стал бы массивом)');
$other = ['inbounds' => [['streamSettings' => ['network' => 'ws', 'wsSettings' => ['path' => '/ws']]]]];
$copy = $other;
$bot->ensureXhttpMuxInbound($other, $on);
xmAssert($other === $copy, 'вход с другим транспортом не трогается');

// ── Переключатель ────────────────────────────────────────────────────────────
$refusals = [
    'smux select fork'      => [['xray_core' => 'origin'], null],
    'xhttp mux needs xhttp' => [['transport' => 'Reality'], null],
    'xhttp mux old fork'    => [[], ['origin' => '26.9.30', 'fork' => '26.9.5-0936']],
];
foreach ($refusals as $message => [$change, $versions]) {
    $bot = new XhttpMuxTestBot();
    $bot->p = array_merge($on, $change, ['xhttp_mux' => ['enabled' => 0]]);
    $bot->x = xmServer();
    if ($versions) { $bot->versions = $versions; }
    $bot->xhttpMuxToggle();
    xmAssert($bot->answers === [$message] && empty($bot->p['xhttp_mux']['enabled']) && $bot->restarts === 0,
        "включение отклонено: $message");
}
$bot = new XhttpMuxTestBot();
$bot->versions = [];
$bot->p = ['xhttp_mux' => ['enabled' => 0]] + $on;
$bot->x = xmServer();
$bot->xhttpMuxToggle();
xmAssert($bot->answers === ['xhttp mux old fork'], 'неизвестная версия ядра (xr недоступен) не считается подходящей');

$bot = new XhttpMuxTestBot();
$bot->p = ['xhttp_mux' => ['enabled' => 0]] + $on;
$bot->x = xmServer();
$bot->xhttpMuxToggle();
xmAssert(!empty($bot->p['xhttp_mux']['enabled']) && $bot->restarts === 1 && $bot->answers === ['xhttp mux enabled'],
    'включение сохраняет настройку и один раз перезапускает ядро');
xmAssert(isset($bot->x['inbounds'][0]['streamSettings']['xhttpSettings']['extra']['muxKeepAliveSecs']),
    'после включения KeepAlive в серверном конфиге');
$bot->xhttpMuxToggle();
xmAssert(empty($bot->p['xhttp_mux']['enabled']) && $bot->x === xmServer() && $bot->answers[1] === 'xhttp mux disabled',
    'выключение возвращает серверный конфиг к исходному');

$bot = new XhttpMuxTestBot();
$bot->p = ['xhttp_mux' => ['enabled' => 0]] + $on;
$bot->x = xmServer();
$bot->restartOk = false;
$bot->xhttpMuxToggle();
xmAssert(empty($bot->p['xhttp_mux']['enabled']) && $bot->answers === ['smux apply failed'],
    'при неудачном перезапуске ядра настройка откатывается');

// ── Смена ядра гасит настройку (ищем в коде обе ветки) ───────────────────────
$source = (string) file_get_contents(__DIR__ . '/../app/bot.php');
xmAssert(substr_count($source, "\$p['xhttp_mux'] = ['enabled' => 0];") + substr_count($source, "\$p['xhttp_mux']                 = ['enabled' => 0];") === 2,
    'переключение на апстрим и авторемонт ядра выключают Mux.Cool');
xmAssert(preg_match('~ensureSmuxInbound\(\$c\);\s*\$this->ensureXhttpMuxInbound\(\$c, \$pac\);~', $source) === 1,
    'серверный KeepAlive пересчитывается при каждой сборке конфига');

echo "xhttp_mux_test OK ($checks проверок)\n";
