<?php
// Настоящие меню и уведомления, только синтетические администраторы и файлы.
$dir = sys_get_temp_dir() . '/vpnbot-xray-menu-' . bin2hex(random_bytes(6));
mkdir($dir, 0700);
foreach (glob(__DIR__ . '/../app/*.php') as $source) {
    if (!in_array(basename($source), ['config.php', 'debug.php'], true)) copy($source, $dir . '/' . basename($source));
}
register_shutdown_function(static function () use ($dir) {
    foreach (glob($dir . '/*') as $file) unlink($file);
    rmdir($dir);
});
file_put_contents("$dir/config.php", '<?php $c = ["admin" => [123, 456]];');
file_put_contents("$dir/clients.json", '[]');
require "$dir/bot.php";
require "$dir/i18n.php";

class XrayMenuAlertFixture extends Bot
{
    public array $settings;
    public array $buttons = [];
    public array $sent = [];
    public array $selected = [];
    public function __construct(array $translations, string $dir)
    {
        $this->i18n = $translations;
        $this->language = 'ru';
        $this->admin = true;
        $this->limit = 10;
        $this->input = ['chat' => 123, 'message_id' => 1, 'callback' => '', 'message' => ''];
        $this->settings = self::PAC_DEFAULTS;
        $this->clients = $this->clients1 = "$dir/clients.json";
    }
    public function getPacConf() { return $this->settings; }
    public function getXray() { return ['inbounds' => [['settings' => ['clients' => []]]]]; }
    public function getXrayVersion() { return 'test'; }
    public function getXrayStats() { return []; }
    public function onlineClients(int $window = 60): array { return []; }
    public function xrayCoreProbe(bool $fresh = false): array { return ['ok' => true, 'active' => 'origin', 'running' => 'origin']; }
    public function realityRequiresMlkem(): bool { return false; }
    public function getWgMsg() { return null; }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') { throw new RuntimeException('Unexpected remote call'); }
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML') { $this->buttons = $button; return []; }
    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false)
    { $this->sent[] = [$chat, $text, $button]; return []; }
    public function switchXr($i, $nm = 0, $time = false) { $this->selected[] = (int) $i; }
    public function notifyLimit(int $client): void { $this->ipLimitAlert('synthetic limit', $client); }
}

$checks = 0;
foreach (['ru', 'en'] as $language) {
    foreach (['Reality', 'Websocket', 'xhttp'] as $transport) {
        $bot = new XrayMenuAlertFixture($i, $dir);
        $bot->language = $language;
        $bot->settings['transport'] = $transport;
        $bot->xray();
        $relay = array_values(array_filter($bot->buttons, static fn($row) => in_array('/relayMenu', array_column($row, 'callback_data'), true)));
        $all = array_column(array_merge(...$bot->buttons), 'callback_data');
        if (count($relay) !== 1 || in_array('/selfFakeDomain', $all, true) !== ($transport === 'Reality')) {
            throw new RuntimeException('Own cover must appear only for Reality');
        }
        if ($transport === 'Reality' && !in_array('/selfFakeDomain', array_column($relay[0], 'callback_data'), true)) {
            throw new RuntimeException('Own cover must share the relay row');
        }
        $checks++;
    }
    $bot = new XrayMenuAlertFixture($i, $dir);
    $bot->language = $language;
    $bot->notifyLimit(7);
    if (array_column($bot->sent, 0) !== [123, 456]) throw new RuntimeException('Limit notification must reach every administrator');
    foreach ($bot->sent as [$chat, $text, $buttons]) {
        $bot->input['callback'] = $buttons[0][0]['callback_data'];
        $bot->action();
    }
    if ($bot->selected !== [7, 7]) throw new RuntimeException('Limit notification must select the affected client');
    $checks++;
}
echo "PASS $checks main Xray menu and alert dispatch scenarios\n";
