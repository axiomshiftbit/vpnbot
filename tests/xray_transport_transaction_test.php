<?php
require_once __DIR__ . '/../app/bot.php';

class TransportTransactionBot extends Bot
{
    public array $settings;
    public array $server;
    public array $answers = [];
    public array $upstreams = [];
    public int $starts = 0;
    public int $probes = 0;
    public string $fail = '';
    public function __construct()
    {
        $this->input = ['callback_id' => 'fixture'];
        $this->settings = self::PAC_DEFAULTS;
        $this->settings['xray'] = 'fixture-public-key';
        $this->settings['transport'] = 'Websocket';
        $this->settings['reality'] = ['domain' => 'example.test', 'destination' => 'example.test:443', 'shortId' => '1234', 'privateKey' => 'fixture-private-key'];
        $this->server = ['inbounds' => [['port' => 443, 'protocol' => 'vless', 'settings' => ['clients' => [['id' => 'fixture', 'email' => 'fixture']]], 'streamSettings' => ['network' => 'ws']]]];
    }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
    public function getPacConf() { return $this->settings; }
    public function setPacConf(array $conf) { $this->settings = $conf; return true; }
    public function getXray() { return $this->server; }
    public function getHashBot($notset = false) { return 'abcdef01'; }
    public function restartXray($config, $norestart = false)
    {
        $this->starts++;
        $this->settings['parallel'] = 'preserved';
        if ($this->fail === 'nginx' && $this->starts === 1) return false;
        $this->server = $config;
        return true;
    }
    public function xrayCoreStarted(string $core): bool { return !($this->fail === 'core' && ++$this->probes === 1); }
    public function setUpstreamDomain($domain) { $this->upstreams[] = $domain; return $this->fail !== 'upstream'; }
    public function answer($callback_id, $textNotify = false, $notify = false) { $this->answers[] = $textNotify; }
    public function xray($page = 0) {}
}

foreach (['Websocket', 'trojan-grpc', 'xhttp'] as $transport) {
    foreach (['', 'nginx', 'core', 'upstream'] as $failure) {
        $bot = new TransportTransactionBot(); $before = $bot->server; $bot->fail = $failure;
        $bot->changeTransport($transport);
        if (($bot->settings['parallel'] ?? '') !== 'preserved') throw new RuntimeException('Параллельная правка PAC потеряна');
        if ($failure !== '') {
            if ($bot->server !== $before || $bot->settings['transport'] !== 'Websocket' || !$bot->answers) {
                throw new RuntimeException("$transport/$failure: конфиг, меню или уведомление не восстановлены");
            }
            if ($failure === 'nginx' && ($bot->starts !== 1 || $bot->upstreams)) throw new RuntimeException('Отказ NGINX не должен менять остальные сервисы');
        } elseif ($bot->settings['transport'] !== $transport || $bot->answers || $bot->starts !== 1 || $bot->upstreams !== ['t']) {
            throw new RuntimeException("$transport: корректная смена транспорта отклонена");
        }
    }
}
echo "xray_transport_transaction: 12 сценариев OK\n";
