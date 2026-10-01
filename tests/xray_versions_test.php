<?php

require_once __DIR__ . '/../app/bot.php';

function versionAssert(bool $ok, string $message): void
{
    if (!$ok) throw new RuntimeException($message);
}

class VersionSwitchBot extends Bot
{
    public array $settings = ['xray_core' => 'origin3', 'smux' => ['enabled' => 0]];
    public array $config = ['inbounds' => [['settings' => ['decryption' => 'none']]]];
    public array $commands = [];
    public array $restarts = [];
    public array $locks = [];
    public array $available = ['origin' => '26.9.9', 'origin2' => '26.9.30', 'origin3' => '26.7.28', 'fork' => '26.9.5-0936'];
    public string $marker = 'origin3';
    public bool $reachable = true;
    public bool $markerFails = false;
    public bool $saveFails = false;
    public bool $linkFails = false;
    public bool $configValid = true;
    public array $starts = [true];
    public function __construct() {}
    public function getPacConf() { return $this->settings; }
    public function setPacConf(array $conf)
    {
        if ($this->saveFails) return false;
        $this->settings = $conf;
        return true;
    }
    public function getXray() { return $this->config; }
    public function xrayCoreInventory(): array { return $this->available; }
    public function xrayCoreProbe(bool $fresh = false): array
    {
        return ['ok' => $this->reachable, 'fork' => isset($this->available['fork']), 'brutal' => false];
    }
    public function writeCoreMarker(string $core): bool
    {
        if ($this->markerFails) return false;
        $this->marker = $core;
        return true;
    }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
    {
        $this->commands[] = $cmd;
        $this->sshFailed = $this->linkFails;
        return $this->linkFails ? '' : 'XRAY_LINK_OK';
    }
    public function restartXray($conf, $norestart = false)
    {
        $this->restarts[] = [$this->settings['xray_core'], $conf];
        return $this->configValid;
    }
    public function xrayCoreStarted(string $core): bool { return array_shift($this->starts) ?? false; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null)
    {
        $this->locks[] = $name;
        return $fn();
    }
}

foreach (['origin', 'origin2', 'origin3', 'fork'] as $core) {
    $b = new VersionSwitchBot();
    $r = $b->applyXrayCore($core);
    versionAssert($r['ok'] && $b->settings['xray_core'] === $core && $b->marker === $core, 'выбранный слот сохранён: ' . $core);
    versionAssert($b->xrayCore() === ($core === 'fork' ? 'fork' : 'origin'), 'официальные версии не включают SMUX');
    versionAssert($b->xrayCoreSelection() === $core, 'номер слота не теряется');
    versionAssert($b->locks === ['xray', 'pac'], 'переключатели используют порядок блокировок VLESS Encryption');
    versionAssert(str_contains($b->commands[0], Bot::XRAY_BINARIES[$core]), 'выбран правильный бинарник');
}

foreach (['unknown', 'origin2; touch /tmp/unsafe', '../fork'] as $core) {
    $b = new VersionSwitchBot(); $old = $b->settings;
    versionAssert(!$b->applyXrayCore($core)['ok'] && $old === $b->settings && !$b->commands, 'неизвестный выбор отклонён');
}
foreach ([[], 5, false, null] as $invalid) {
    $b = new VersionSwitchBot(); $b->settings['xray_core'] = $invalid;
    versionAssert($b->xrayCoreSelection() === 'origin', 'некорректный тип сохранённого слота не ломает меню');
}
class VersionInventoryFailureBot extends VersionSwitchBot
{
    public function xrayCoreInventory(): array { $this->sshFailed = true; return []; }
}
$b = new VersionInventoryFailureBot(); $old = $b->settings;
versionAssert($b->applyXrayCore('origin2')['note'] === ['xr unreachable'] && $b->settings === $old,
    'сбой SSH при инвентаризации отличается от отсутствующего бинарника');
foreach (['unavailable', 'unreachable', 'save', 'marker', 'link', 'validation'] as $failure) {
    $b = new VersionSwitchBot(); $old = $b->settings;
    if ($failure === 'unavailable') unset($b->available['origin2']);
    if ($failure === 'unreachable') $b->reachable = false;
    if ($failure === 'save') $b->saveFails = true;
    if ($failure === 'marker') $b->markerFails = true;
    if ($failure === 'link') $b->linkFails = true;
    if ($failure === 'validation') $b->configValid = false;
    versionAssert(!$b->applyXrayCore('origin2')['ok'] && $b->settings === $old && $b->marker === 'origin3', 'сбой сохраняет прежний слот: ' . $failure);
    if (in_array($failure, ['unavailable', 'unreachable', 'save', 'marker'], true)) {
        versionAssert(!$b->commands && !$b->restarts, 'до сохранения состояния процесс не меняется');
    }
    if ($failure === 'validation') {
        versionAssert(count($b->restarts) === 1 && str_contains(end($b->commands), Bot::XRAY_BINARIES['origin3']), 'отказ парсера не перезапускает прежний процесс, симлинк восстановлен');
    }
}
$b = new VersionSwitchBot(); $old = $b->settings; $b->starts = [false, true];
$r = $b->applyXrayCore('origin2');
versionAssert(!$r['ok'] && $old === $b->settings && $b->marker === 'origin3', 'сбой запуска возвращает старый выбор');
versionAssert(array_column($b->restarts, 0) === ['origin2', 'origin3'], 'прежний процесс запущен снова');
versionAssert(in_array('previous core restored', $r['note'], true), 'откат подтверждён проверкой процесса');
$b = new VersionSwitchBot(); $b->starts = [false, false];
versionAssert(in_array('rollback failed', $b->applyXrayCore('origin2')['note'], true), 'неудачный откат сообщается явно');

class VersionWriteFailureBot extends VersionSwitchBot
{
    public string $json = '{"inbounds":[{"settings":{"decryption":"none"}}]}';
    public bool $restoreFails = false;
    public function readXrayJson(): string { return $this->json; }
    public function writeXrayJson(string $json): bool
    {
        if ($this->restoreFails) return false;
        $this->json = $json;
        return true;
    }
    public function restartXray($conf, $norestart = false)
    {
        $this->json = '{"inbounds":';
        return false;
    }
}
$b = new VersionWriteFailureBot(); $json = $b->json;
versionAssert(!$b->applyXrayCore('origin2')['ok'] && $b->json === $json, 'обрезанный при записи файл восстановлен до следующего старта');
$b = new VersionWriteFailureBot(); $b->restoreFails = true;
versionAssert(in_array('rollback failed', $b->applyXrayCore('origin2')['note'], true), 'отказ восстановления файла не выдаётся за успешный откат');

class VersionCronBot extends VersionSwitchBot
{
    public function xrayCoreProbe(bool $fresh = false): array
    {
        return parent::xrayCoreProbe($fresh) + ['active' => 'fork', 'running' => 'fork', 'version' => 'Xray 26.9.5-0936'];
    }
}
$b = new VersionCronBot(); $b->settings['xray_core'] = 'fork';
$b->checkXrayCore();
versionAssert($b->locks === ['xray', 'pac'], 'авторемонт cron сериализован с ручным переключением');

class VersionProbeBot extends Bot
{
    public string $output = '';
    public bool $fail = false;
    public function __construct() {}
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
    {
        $this->sshFailed = $this->fail;
        return $this->output;
    }
}
$b = new VersionProbeBot();
$b->output = "origin|Xray 26.9.9 (Xray)\norigin2|Xray 26.9.30 (Xray)\norigin3|not found\nfork|Xray 26.9.5-0936 (fork)\nunknown|Xray 1.2.3 (invalid)\n";
versionAssert($b->xrayCoreInventory() === ['origin' => '26.9.9', 'origin2' => '26.9.30', 'fork' => '26.9.5-0936'], 'инвентаризация исключает отсутствующие и неизвестные бинарники');
$b->output = '1|/usr/bin/xray-2|cubic|/usr/bin/xray-3|Xray 26.9.30 (Xray)';
$probe = $b->xrayCoreProbe(true);
versionAssert($probe['selection'] === 'origin2' && $probe['running_selection'] === 'origin3'
    && $probe['active'] === 'origin' && $probe['running'] === 'origin', 'разные официальные версии различаются без изменения семейства');
$b->fail = true;
versionAssert($b->xrayCoreInventory() === [] && !$b->xrayCoreProbe(true)['ok'], 'недоступный xr не выдаёт старый список версий');

require __DIR__ . '/../app/i18n.php';
class VersionMenuBot extends VersionSwitchBot
{
    public array $buttons = [];
    public string $text = '';
    public array $notifications = [];
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML')
    {
        $this->buttons = $button;
        $this->text = $text;
    }
    public function answer($callback_id, $textNotify = false, $notify = false)
    {
        $this->notifications[] = [$textNotify, $notify];
    }
}
foreach (['ru', 'en'] as $language) {
    $b = new VersionMenuBot(); $b->language = $language; $b->i18n = $i;
    $b->input = ['chat' => 1, 'message_id' => 1, 'callback_id' => 'test'];
    $b->xrayCoreMenu();
    versionAssert(count($b->buttons) === 5 && $b->buttons[2][0]['text'] === '✓ XTLS 26.7.28', 'меню показывает четыре реальных версии и выбранный слот');
    foreach (array_keys($b->available) as $n => $slot) {
        versionAssert($b->buttons[$n][0]['callback_data'] === '/selectXrayCore ' . $slot, 'кнопка выбирает конкретный слот');
    }
    unset($b->available['origin2']);
    $b->selectXrayCore('origin2');
    versionAssert($b->notifications[0] === [$b->i18n('xray version missing'), true], 'устаревшая кнопка сообщает об отсутствующем слоте');
    versionAssert(mb_strlen($b->notifications[0][0]) <= 200, 'уведомление помещается в Telegram alert');
    versionAssert(count($b->buttons) === 4, 'отсутствующий слот не предлагается');
}

echo "xray_versions_test OK\n";
