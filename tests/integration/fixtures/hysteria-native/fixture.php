<?php
// Конфигурации и ссылки ровно те, что выдаёт бот: их проверяет настоящее ядро.
ob_start();
require '/src/app/bot.php';
require '/src/app/i18n.php';
class HysteriaNativeBot extends Bot {
    public array $conf = [];
    public function __construct($strings) { $this->i18n = $strings; $this->language = 'ru'; $this->ip = '198.18.77.2'; $this->admin = true;
        $this->hysteriaConf = '/tmp/hysteria.yaml'; $this->hysteriaUsersRoot = '/tmp/hysteria'; }
    public function getPacConf() { return $this->conf; }
    public function setPacConf(array $conf) { $this->conf = $conf; return true; }
    public function getPorts() { return ['hy' => ['enable' => true, 'port' => 443]]; }
    public function getDomain($cdn = false) { return 'hy.example.test'; }
    public function protocolModuleEnabled(string $key): bool { return true; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') { return str_contains($cmd, 'printf managed') ? 'managed' : "Version:\t" . getenv('HYSTERIA_CORE'); }
    public function flagName(string $name, string|array $hosts, bool $cacheOnly = true): string { return $name; }
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML') {}
}
$base = ['hysteria_pass' => 'shared-pass', 'hysteria_insecure' => 1];
$brutal = ['hysteria_bw_up' => '100 mbps', 'hysteria_bw_down' => '100 mbps'];
$variants = [
    'default' => [],
    'salamander' => ['hysteria_obfs' => 'obfs-secret'],
    'gecko' => ['hysteria_obfs' => 'obfs-secret', 'hysteria_obfs_type' => 'gecko'],
    'bbr-conservative' => ['hysteria_cc' => 'bbr-conservative'],
    'bbr-aggressive' => ['hysteria_cc' => 'bbr-aggressive'],
    'reno' => ['hysteria_cc' => 'reno'],
    'brutal' => $brutal,
    'brutal-no-loss-compensation' => $brutal + ['hysteria_no_loss_comp' => 1],
    'ignore-client-bandwidth' => ['hysteria_ignore_client_bw' => 1],
    'sniff' => ['hysteria_sniff' => 1],
    'everything' => $brutal + ['hysteria_obfs' => 'obfs-secret', 'hysteria_obfs_type' => 'gecko', 'hysteria_cc' => 'bbr-aggressive',
        'hysteria_no_loss_comp' => 1, 'hysteria_ignore_client_bw' => 1, 'hysteria_sniff' => 1],
];
$out = [];
foreach ($variants as $name => $extra) {
    $bot = new HysteriaNativeBot($i);
    $bot->conf = $base + $extra;
    copy('/src/config/hysteria.yaml', '/tmp/hysteria.yaml');
    $out[$name] = $bot->restartHysteria() ? ['yaml' => file_get_contents('/tmp/hysteria.yaml'), 'link' => $bot->linkHysteria()] : null;
}
// Переключение типа обфускации кнопкой меню: бот сам узнаёт версию ядра.
$bot = new HysteriaNativeBot($i);
$bot->conf = $base + ['hysteria_obfs' => 'obfs-secret'];
copy('/src/config/hysteria.yaml', '/tmp/hysteria.yaml');
$bot->input = ['chat' => 1, 'message_id' => 1, 'callback_id' => 'cb'];
$bot->hyTune('obfs');
$out['menu-switch-to-gecko'] = ['yaml' => file_get_contents('/tmp/hysteria.yaml'), 'link' => $bot->linkHysteria(), 'type' => $bot->hyObfsType($bot->conf)];
ob_end_clean();
echo json_encode($out, JSON_UNESCAPED_SLASHES);
