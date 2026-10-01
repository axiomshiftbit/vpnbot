<?php

require_once __DIR__ . '/../app/bot.php';
require __DIR__ . '/../app/i18n.php';

function muxNoticeAssert(bool $ok, string $message): void
{
    if (!$ok) throw new RuntimeException($message);
}

class SmuxNoticeBot extends Bot
{
    public array $settings = ['xray_core' => 'fork'];
    public array $config = ['inbounds' => [['protocol' => 'vless', 'settings' => ['decryption' => 'none']]]];
    public array $calls = [];
    public bool $saveFails = false;
    public bool $restartFails = false;
    public int $restarts = 0;
    public int $menus = 0;
    public bool $renderMenu = false;
    public int $sshCalls = 0;
    public function __construct(array $translations)
    {
        $this->i18n = $translations;
        $this->language = 'ru';
        $this->input = ['callback_id' => 'callback-test', 'chat' => 1, 'message_id' => 1];
    }
    public function getPacConf() { return $this->settings; }
    public function setPacConf(array $conf)
    {
        if ($this->saveFails) return false;
        $this->settings = $conf;
        return true;
    }
    public function getXray() { return $this->config; }
    public function restartXray($conf, $norestart = false)
    {
        $this->restarts++;
        if ($this->restartFails) return false;
        $this->config = $conf;
        return true;
    }
    public function request($method, $data, $json_header = 0)
    {
        $this->calls[] = [$method, $data];
        return ['ok' => true];
    }
    public function smuxMenu()
    {
        $this->menus++;
        if ($this->renderMenu) parent::smuxMenu();
    }
    public function brutalAvailable(): bool { return false; }
    public function writeCoreMarker(string $core): bool { return true; }
    public function xrayCoreStarted(string $core): bool { return true; }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
    {
        $this->sshCalls++;
        $this->sshFailed = false;
        return str_contains($cmd, 'XRAY_LINK_OK') ? 'XRAY_LINK_OK' : '';
    }
    public function xrayCoreProbe(bool $fresh = false): array
    {
        return ['ok' => true, 'fork' => true, 'active' => $this->settings['xray_core'],
            'running' => $this->settings['xray_core'], 'version' => 'Xray 26.9.5-0936'];
    }
}

function muxNotice(SmuxNoticeBot $b, string $text): void
{
    muxNoticeAssert(count($b->calls) === 1 && $b->calls[0][0] === 'answerCallbackQuery', 'ровно одно уведомление');
    $data = $b->calls[0][1];
    muxNoticeAssert($data['show_alert'] === true, 'уведомление требует ОК, как VLESS Encryption');
    muxNoticeAssert($data['text'] === $text && mb_strlen($text) <= 200, 'текст отражает исход операции и помещается в alert');
    muxNoticeAssert($b->callback === true && $b->menus === 1, 'callback отмечен отвеченным, меню обновлено');
}

foreach (['ru', 'en'] as $lang) {
    foreach ([0, 1] as $enabled) {
        $b = new SmuxNoticeBot($i); $b->language = $lang;
        $b->settings['smux'] = ['enabled' => $enabled];
        $b->smuxToggle('enabled');
        muxNoticeAssert($b->settings['smux']['enabled'] === 1 - $enabled, 'SMUX переключён');
        muxNotice($b, $b->i18n($enabled ? 'smux disabled' : 'smux enabled'));
        muxNoticeAssert($b->restarts === 0, 'переключение клиентского multiplex не перезапускает сервер без необходимости');
    }
}

foreach (['save', 'restart'] as $failure) {
    $b = new SmuxNoticeBot($i);
    $b->settings['smux'] = ['enabled' => 0, 'h2mux_frame' => 16384];
    $old = $b->settings;
    $b->saveFails = $failure === 'save';
    $b->restartFails = $failure === 'restart';
    $b->smuxToggle('enabled');
    muxNoticeAssert($b->settings === $old, 'при отказе состояние SMUX сохранено');
    muxNotice($b, $b->i18n('smux apply failed'));
}

$b = new SmuxNoticeBot($i);
$b->settings['xray_core'] = 'origin';
$old = $b->settings;
$b->smuxToggle('enabled');
muxNoticeAssert($b->settings === $old, 'устаревшая кнопка не включает SMUX на XTLS');
muxNotice($b, $b->i18n('smux select fork'));

$b = new SmuxNoticeBot($i);
$b->settings = ['xray_core' => 'origin', 'transport' => 'Reality'];
$b->renderMenu = true;
$b->smuxMenu();
muxNoticeAssert(str_contains($b->calls[0][1]['text'], $b->i18n('smux sing compatibility')), 'SMUX показывает совместимость sing-box для текущего транспорта');

foreach (['origin', 'fork'] as $core) {
    $b = new SmuxNoticeBot($i); $b->settings['xray_core'] = $core;
    $b->switchXrayCore();
    muxNoticeAssert($b->settings['xray_core'] !== $core, 'ядро переключено');
    muxNoticeAssert($b->calls[0][1]['show_alert'] === true, 'выбор форка/XTLS тоже подтверждается кнопкой ОК');
    muxNoticeAssert(str_contains($b->calls[0][1]['text'], $core === 'origin' ? 'fork' : 'XTLS'), 'указано выбранное ядро');
}
foreach (['save', 'restart'] as $failure) {
    $b = new SmuxNoticeBot($i); $b->settings['xray_core'] = 'origin';
    $old = $b->settings;
    $b->saveFails = $failure === 'save';
    $b->restartFails = $failure === 'restart';
    $b->switchXrayCore();
    muxNoticeAssert($b->settings === $old, 'неудачный выбор ядра не меняет настройки');
    muxNotice($b, $b->i18n('smux apply failed'));
    if ($failure === 'save') muxNoticeAssert($b->sshCalls === 0, 'ошибка сохранения не переключает бинарник');
}

echo "smux_notifications_test OK\n";
