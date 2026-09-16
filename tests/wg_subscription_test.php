<?php
require_once __DIR__ . '/../app/bot.php';

class WgSubscriptionBot extends Bot
{
    public array $settings = [];
    public function __construct() {}
    public function getPacConf() { return $this->settings; }
    public function awgSupports3Cached(string $prefix = ''): ?bool { return true; }
    public function awgSupports31Cached(string $prefix = ''): ?bool { return true; }
}
$b = new WgSubscriptionBot();
$b->clients = tempnam(sys_get_temp_dir(), 'wg-sub-');
$b->clients1 = tempnam(sys_get_temp_dir(), 'wg1-sub-');
$b->mtu = 1350;
$peer = ['interface' => ['PrivateKey' => 'test-private-0', 'Address' => '10.0.1.2/32'],
    'peers' => [['PublicKey' => 'test-public', 'Endpoint' => '192.0.2.1:51820']]];
try {
    file_put_contents($b->clients, json_encode([$peer]));
    $peer['interface']['PrivateKey'] = 'test-private-1';
    $peer['peers'][0]['PresharedKey'] = 'active-peer-psk';
    file_put_contents($b->clients1, json_encode([$peer]));
    $b->settings = ['amnezia' => 0, 'amnezia_keys' => ['Jc' => 4, 'H1' => 100],
        'presharedkey' => 'stale-psk', 'wg1_amnezia' => 1,
        'wg1_amnezia_keys' => ['Jc' => 7, 'H1' => 200], 'wg1_presharedkey' => 'stale-psk-1'];
    $plain = $b->getAwgClient('test-private-0');
    if ($plain['amnezia-wg-option'] !== [] || $plain['pre-shared-key'] !== '') {
        throw new RuntimeException('Обычный WireGuard получил старые параметры Amnezia');
    }
    $awg = $b->getAwgClient('test-private-1');
    if ((int) ($awg['amnezia-wg-option']['Jc'] ?? 0) !== 7
        || $awg['pre-shared-key'] !== 'active-peer-psk') {
        throw new RuntimeException('Экспорт второго инстанса не совпадает с его peer');
    }
} finally {
    unlink($b->clients);
    unlink($b->clients1);
}
echo "wg_subscription_test OK\n";
