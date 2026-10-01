<?php
require_once __DIR__ . '/../app/bot.php';

class NoiseSettingsBot extends Bot
{
    public array $conf = [], $config = ['inbounds' => [['streamSettings' => []]]], $messages = [], $restarts = [];
    public array $versions = ['origin' => '26.9.9', 'origin2' => '26.9.30', 'origin3' => '26.7.28', 'fork' => '26.9.5'];
    public bool $failStart = false, $failSave = false, $throwStart = false;
    public function __construct() { $this->admin = true; $this->language = 'ru'; $this->input = ['callback_id' => 'test']; }
    public function getPacConf() { return $this->conf; }
    public function setPacConf($p) { if ($this->failSave) return false; $this->conf = $p; return true; }
    public function getXray() { return $this->config; }
    public function xrayCoreInventory(): array { return $this->versions; }
    public function xrayCoreStarted(string $core): bool { return !$this->failStart; }
    public function restartXray($config, $norestart = false) {
        $this->restarts[] = $config; $this->config = $config;
        if ($this->throwStart) { $this->throwStart = false; throw new RuntimeException('launch failed'); }
        return true;
    }
    public function answer($id, $text = '', $alert = false) { $this->messages[] = $text; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
}
$checks = 0;
$check = static function (bool $ok, string $message) use (&$checks): void { $checks++; if (!$ok) throw new RuntimeException($message); };
$reject = static function (callable $call) use ($check): void {
    try { $call(); } catch (InvalidArgumentException $e) { $check(true, 'отказ'); return; }
    throw new RuntimeException('Некорректная маска принята');
};
foreach (['<b 00 ff><r 1-2><rc 3><rd 4><t><c><n>' => 27, '<b 0X0001>' => 2, '<r 0-1400>' => 1400] as $exp => $size) {
    $check(XrayNoise::expression($exp) === $size, 'Размер выражения');
}
foreach (['', 'hello', '<b zz>', '<b 0>', '<b>', '<r -1>', '<r 10-1>', '<r 65535>', '<r 1400><n>', '<t 1>', '<unknown>', '<r 0>', '<R 20>', '<n>garbage'] as $exp) {
    $reject(fn() => XrayNoise::expression($exp));
}
foreach ([['type' => 'hex', 'packet' => '0'], ['type' => 'base64', 'packet' => '!'], ['type' => 'rand', 'packet' => '0'],
    ['type' => 'rand', 'packet' => '20-10'], ['type' => 'str', 'packet' => str_repeat('a', 1401)],
    ['type' => 'str', 'packet' => 'ok', 'delay' => '1001'], ['type' => 'exp', 'packet' => '<c>', 'delay' => '-1'],
    ['type' => 'exec', 'packet' => 'x'], ['type' => []]] as $packet) $reject(fn() => XrayNoise::settings([], [$packet]));
foreach (['0', '-1', '9-2', '86401'] as $reset) $reject(fn() => XrayNoise::settings(['reset' => $reset], []));
$reject(fn() => XrayNoise::settings([], array_fill(0, 9, ['type' => 'rand', 'packet' => '1'])));
$zero = XrayNoise::settings([], [['type' => 'exp', 'packet' => '<n><c>', 'delay' => '0']]);
$check($zero['noise'][0]['delay'] === '0' && !isset($zero['noise'][0]['rand']), 'Нулевая задержка и взаимоисключающие поля');
$bot = new NoiseSettingsBot(); $settings = Bot::finalmaskDefaults();
$settings['enabled'] = $settings['noise']['enabled'] = 1; $settings['noise']['list'] = XrayNoise::dynamicPackets();
$before = $bot->conf;
$check(!$bot->applyFinalmaskSettings($settings) && $bot->conf === $before && !$bot->restarts, 'Старое ядро не меняет PAC/процесс');
$bot->conf = ['xray_core' => 'origin2', 'unrelated' => 'keep'];
$check($bot->applyFinalmaskSettings($settings), 'Совместимое ядро принимает выражения');
$check($bot->conf['unrelated'] === 'keep' && $bot->config['inbounds'][0]['streamSettings']['finalmask']['udp'][0]['settings']['noise'][0]['type'] === 'exp', 'Валидная маска и прочие настройки сохранены');
foreach (['origin', 'origin3', 'fork'] as $slot) $check(!$bot->finalmaskCoreCompatible($bot->conf, $slot), 'Переход на старое ядро запрещён при активном exp');
$before = $bot->conf; $bad = $settings; $bad['noise']['list'][0]['packet'] = '<r 65535>';
$check(!$bot->applyFinalmaskSettings($bad) && $bot->conf === $before, 'Ошибка выражения сохраняет PAC');
$bot->failSave = true; $bad = $settings; $bad['noise']['reset'] = '100'; $count = count($bot->restarts);
$check(!$bot->applyFinalmaskSettings($bad) && count($bot->restarts) === $count, 'Ошибка записи не перезапускает Xray');
$bot->failSave = false; $bot->failStart = true; $old = $bot->config;
$check(!$bot->applyFinalmaskSettings($bad) && $bot->conf === $before && $bot->config === $old, 'Ошибка запуска восстанавливает предыдущие настройки');
$check(str_contains(end($bot->messages), 'не подтверждено'), 'Неудачная проверка отката видна');
$bot->failStart = false; $bot->throwStart = true;
$check(!$bot->applyFinalmaskSettings($bad) && $bot->conf === $before && $bot->config === $old, 'Исключение запуска тоже восстанавливает PAC и конфигурацию');
$check(str_contains(end($bot->messages), 'прежние настройки восстановлены'), 'Успешный откат после исключения подтверждён');
$bot->failStart = false; $settings['noise']['enabled'] = 0;
$check($bot->applyFinalmaskSettings($settings) && $bot->finalmaskCoreCompatible($bot->conf, 'origin'), 'Выключение позволяет использовать старое ядро');
$check(!isset($bot->noisePresets()['dynamic']) && isset($bot->finalmaskNoisePresets()['dynamic']), 'exp не попадает в старый freedom noise');
$check(str_contains($bot->finalmaskNoiseHint(), '&lt;rc') && !str_contains($bot->finalmaskNoiseHint(), '<rc'), 'Выражения экранированы для Telegram');
echo "xray_noise_test: $checks OK\n";
