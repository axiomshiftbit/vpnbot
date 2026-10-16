<?php

// realitySettings.requireMlkem (форк 26.10.13+). Ошибка здесь отрезает клиентов:
// флаг не должен уехать в конфиг оригинального ядра или старого форка, а бот
// обязан считать REALITY «требующим ML-KEM» ровно тогда, когда флаг действует.

require_once __DIR__ . '/../app/bot.php';

$checks = 0;
function rmAssert(bool $ok, string $message): void
{
    global $checks;
    $checks++;
    if (!$ok) {
        throw new RuntimeException('reality_require_mlkem_test: ' . $message);
    }
}

class RequireMlkemTestBot extends Bot
{
    public array $p = [];
    public array $x = [];
    public array $versions = ['origin' => '26.10.10', 'fork' => '26.10.13-2347'];
    public array $probe = [];
    public array $answers = [];
    public array $screens = [];
    public int $restarts = 0;
    public function __construct() { $this->input = ['callback_id' => 1, 'chat' => 1, 'message_id' => 1]; $this->language = 'ru'; }
    public function getPacConf() { return $this->p; }
    public function setPacConf(array $p) { $this->p = $p; return true; }
    public function getXray() { return $this->x; }
    public function restartXray($c, $save = true) { $this->restarts++; $this->x = $c; return true; }
    public function xrayCoreInventory(): array { return $this->versions; }
    public function xrayCoreProbe(bool $fresh = false): array { return $this->probe; }
    public function answer($callback_id, $textNotify = false, $notify = false) { $this->answers[] = $textNotify; }
    public function update($chat, $message_id, $text, $data = false, $reply = false, $mode = 'HTML', $disable_preview = true)
    {
        $this->screens[] = [$text, $data];
    }
    public function i18n(string $key): string { return $key; }
}

function rmServer(): array
{
    return ['inbounds' => [['streamSettings' => ['network' => 'raw', 'security' => 'reality', 'realitySettings' => [
        'dest' => 'www.example.com:443', 'serverNames' => ['www.example.com'], 'privateKey' => 'k', 'shortIds' => [''],
        'maxTimeDiff' => 5000, 'minClientVer' => '0.0.0', 'maxClientVer' => '', 'xver' => 0]]]]];
}

$on = ['transport' => 'Reality', 'xray_core' => 'fork', 'reality' => ['requireMlkem' => 1]];
$bot = new RequireMlkemTestBot();

// ── Когда флаг действует ─────────────────────────────────────────────────────
rmAssert($bot->realityRequireMlkemActive($on), 'форк + флаг');
foreach ([['xray_core' => 'origin'], ['xray_core' => 'origin2'], ['reality' => ['requireMlkem' => 0]], ['reality' => []]] as $change) {
    rmAssert(!$bot->realityRequireMlkemActive(array_merge($on, $change)), 'не действует при ' . json_encode($change));
}

// ── Конфиг: только поле requireMlkem, остальное как было ─────────────────────
$c = rmServer();
$rs = $c['inbounds'][0]['streamSettings']['realitySettings'];
$bot->ensureRealityRequireMlkem($rs, $on);
rmAssert($rs === $c['inbounds'][0]['streamSettings']['realitySettings'] + ['requireMlkem' => true], 'флаг добавлен, прочее не тронуто');
$bot->ensureRealityRequireMlkem($rs, ['xray_core' => 'origin'] + $on);
rmAssert($rs === $c['inbounds'][0]['streamSettings']['realitySettings'], 'на оригинальном ядре флаг снят');
$extras = $c['inbounds'][0]['streamSettings']['realitySettings'];
$bot->applyRealityServerExtras($extras, $on);
rmAssert(($extras['requireMlkem'] ?? null) === true, 'applyRealityServerExtras ставит флаг');
$bot->applyRealityServerExtras($extras, ['reality' => ['requireMlkem' => 0]] + $on);
rmAssert(!array_key_exists('requireMlkem', $extras), 'applyRealityServerExtras снимает флаг');

// ── Переключатель ────────────────────────────────────────────────────────────
foreach ([
    'reality mlkem select fork' => [['transport' => 'Reality', 'xray_core' => 'origin'], null],
    'reality mlkem old fork' => [['transport' => 'Reality', 'xray_core' => 'fork'], '26.10.6-2241'],
    'reality mlkem old fork ' => [['transport' => 'Reality', 'xray_core' => 'fork'], ''],
] as $expected => [$pac, $fork]) {
    $bot->p = $pac; $bot->x = rmServer(); $bot->answers = []; $bot->restarts = 0;
    $bot->versions = $fork === null ? ['origin' => '26.10.10', 'fork' => '26.10.13-2347'] : ($fork === '' ? [] : ['fork' => $fork]);
    $bot->dpiToggle('requireMlkem');
    rmAssert($bot->answers === [trim($expected)], 'отказ: ' . trim($expected));
    rmAssert(empty($bot->p['reality']['requireMlkem']) && $bot->restarts === 0, 'отказ ничего не меняет: ' . trim($expected));
}
$bot->p = ['transport' => 'Reality', 'xray_core' => 'fork'];
$bot->x = rmServer(); $bot->versions = ['fork' => '26.10.13-2347']; $bot->restarts = 0; $bot->screens = [];
$bot->dpiToggle('requireMlkem');
rmAssert($bot->p['reality']['requireMlkem'] === 1, 'включено в настройках');
rmAssert(($bot->x['inbounds'][0]['streamSettings']['realitySettings']['requireMlkem'] ?? null) === true && $bot->restarts === 1,
    'включено в конфиге ядра и применено перезапуском');
$bot->dpiToggle('requireMlkem');
rmAssert($bot->p['reality']['requireMlkem'] === 0, 'выключено в настройках');
rmAssert(!array_key_exists('requireMlkem', $bot->x['inbounds'][0]['streamSettings']['realitySettings']) && $bot->restarts === 2,
    'снято из конфига ядра');
// Выключить можно и на оригинальном ядре: флаг там всё равно не действует.
$bot->p = ['transport' => 'Reality', 'xray_core' => 'origin', 'reality' => ['requireMlkem' => 1]]; $bot->answers = [];
$bot->dpiToggle('requireMlkem');
rmAssert($bot->answers === [] && $bot->p['reality']['requireMlkem'] === 0, 'выключение без проверки ядра');

// ── Бот считает требование ML-KEM ровно по действующему флагу ────────────────
$forkProbe = ['ok' => true, 'running' => 'fork', 'active' => 'fork', 'reality' => 'v0.0.0-20260908062103-8cdf7bf9c7f0',
    'reality_local' => true, 'version' => 'Xray 26.10.13-2347'];
$bot->probe = $forkProbe;
$bot->p = ['transport' => 'Reality', 'xray_core' => 'fork'];
rmAssert(!$bot->realityRequiresMlkem(), 'форк без флага принимает ClientHello без ML-KEM (sing-box)');
$bot->p['reality']['requireMlkem'] = 1;
rmAssert($bot->realityRequiresMlkem(), 'форк с флагом требует ML-KEM');
rmAssert($bot->subscriptionCompatibilityError(['inbounds' => [[]]], $bot->p, 'si') === 'reality singbox mlkem',
    'с флагом подписка sing-box отклоняется заранее');
$bot->probe = ['ok' => true, 'running' => 'origin', 'active' => 'origin', 'reality' => 'v0.0.0-20261014101318-aaaaaaaaaaaa',
    'reality_local' => false, 'version' => 'Xray 26.10.10'];
$bot->p = ['transport' => 'Reality', 'xray_core' => 'origin'];
rmAssert($bot->realityRequiresMlkem(), 'оригинальное ядро требует ML-KEM всегда');

// ── Меню ─────────────────────────────────────────────────────────────────────
$bot->x = rmServer(); $bot->screens = [];
$bot->p = ['transport' => 'Reality', 'xray_core' => 'fork', 'reality' => ['requireMlkem' => 1]];
$bot->dpiMenu();
[$text, $data] = end($bot->screens);
$buttons = array_merge(...$data);
rmAssert(in_array('/dpiToggle requireMlkem', array_column($buttons, 'callback_data'), true), 'на форке кнопка есть');
rmAssert(str_contains($text, 'reality require mlkem hint'), 'на форке есть пояснение');
$bot->p = ['transport' => 'Reality', 'xray_core' => 'origin'];
$bot->dpiMenu();
[$text, $data] = end($bot->screens);
rmAssert(!in_array('/dpiToggle requireMlkem', array_column(array_merge(...$data), 'callback_data'), true), 'на оригинальном ядре кнопки нет');
rmAssert(str_contains($text, 'reality mlkem origin always'), 'на оригинальном ядре объяснено, что правило действует всегда');
$bot->p = ['transport' => 'Websocket', 'xray_core' => 'fork'];
$bot->dpiMenu();
[$text, $data] = end($bot->screens);
rmAssert(!in_array('/dpiToggle requireMlkem', array_column(array_merge(...$data), 'callback_data'), true), 'без REALITY кнопки нет');

echo "reality_require_mlkem_test: $checks OK\n";
