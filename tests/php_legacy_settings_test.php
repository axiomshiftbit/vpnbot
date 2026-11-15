<?php
// Старые/импортированные настройки без необязательных полей: E_ALL на PHP 8.5.
$root = sys_get_temp_dir() . '/vpnbot-legacy-settings-' . bin2hex(random_bytes(6));
mkdir($root, 0700);
mkdir("$root/app", 0700);
mkdir("$root/config", 0700);
mkdir("$root/certs", 0700);
foreach (glob(__DIR__ . '/../app/*.php') as $source) {
    if (in_array(basename($source), ['config.php', 'debug.php'], true)) continue;
    $body = file_get_contents($source);
    if (basename($source) === 'bot.php') $body = str_replace(['/config/', '/certs/'], ["$root/config/", "$root/certs/"], $body);
    file_put_contents("$root/app/" . basename($source), $body);
}
require "$root/app/bot.php";
require __DIR__ . '/../app/i18n.php';

class LegacySettingsBot extends Bot
{
    public array $updates = [];
    public array $peer = ['PublicKey' => 'synthetic-public-key', 'AllowedIPs' => '10.0.0.2/32', '## name' => 'Legacy'];
    public array $clientsFake = [['interface' => ['Address' => '10.0.0.2/32']]];
    public function __construct(string $root, array $translations) {
        $this->pac = "$root/config/pac.json";
        $this->clients = "$root/config/clients.json";
        $this->clients1 = "$root/config/clients1.json";
        $this->i18n = $translations; $this->language = 'ru'; $this->limit = 5;
    }
    public function readConfig() { return ['interface' => ['Address' => '10.0.0.1/24'], 'peers' => [$this->peer]]; }
    public function readStatus() { return ['peers' => []]; }
    public function realStatus() { return parent::readStatus(); }
    public function readClients(): array { return $this->clientsFake; }
    public function getPorts() { return ['wg' => ['port' => 51820], 'wg1' => ['port' => 51821]]; }
    public function saveClients(array $clients) { $this->clientsFake = $clients; return true; }
    public function restartWG($conf, $norestart = false) {
        $parsed = (new ReflectionMethod(Bot::class, 'parseWireGuardConfig'))->invoke($this, $conf);
        $this->peer = $parsed['peers'][0];
        return true;
    }
    protected function verifyWireguardPeers(string $config): bool { return true; }
    public function menu($type = false, $arg = false, $return = false) {}
    public function realMenu($type) { return parent::menu($type); }
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML') {
        $this->updates[] = ['text' => $text, 'buttons' => $button];
    }
    public function getClients(int $page, int $count = 5) { return []; }
    public function onlineClients(int $window = 60): array { return []; }
    public function getXray() { return []; }
    public function ovpnPaths() { return ['status' => dirname($this->pac) . '/ovpn-status']; }
    public function wgVersion(): string { return ''; }
    public function maybeRotateAmnezia(): void {}
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') {
        foreach (['VPNBOT_STAGED', 'VPNBOT_VALID', 'VPNBOT_APPLIED', 'VPNBOT_NGINX_READY'] as $marker) {
            if (str_contains($cmd, $marker)) return $marker;
        }
        return '';
    }
}

set_error_handler(function ($level, $message, $file, $line) {
    if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line);
    return false;
});
try {
    $b = new LegacySettingsBot($root, $i);
    $b->protocolCertRoot = "$root/certs";
    if ($b->expireCert() !== false || $b->domainsCert() !== false) throw new RuntimeException('Без сертификата TLS ещё не настроен');
    file_put_contents("$root/certs/cert_public", 'invalid certificate');
    if ($b->expireCert() !== false || $b->domainsCert() !== false) throw new RuntimeException('Повреждённый сертификат не считается действующим');
    $key = openssl_pkey_new(['private_key_bits' => 2048]);
    $csr = openssl_csr_new(['commonName' => 'legacy.example.test'], $key);
    $cert = openssl_csr_sign($csr, null, $key, 1);
    openssl_x509_export($cert, $pem);
    file_put_contents("$root/certs/cert_public", $pem);
    if ($b->expireCert() <= time() || $b->domainsCert() !== false) throw new RuntimeException('Сертификат без SAN имеет срок, но не список SAN');
    $b->trackWgOnline();
    unset($b->wg);
    $b->rotateAmneziaCron();
    $b->setPacConf(['domain' => 'legacy.example.test', 'hashbot' => 'legacy']);
    if ($b->realStatus() !== null) throw new RuntimeException('Недоступный контейнер WG ещё не имеет статуса');
    $b->input = ['chat' => 1, 'from' => 1, 'message_id' => 1, 'callback_id' => false];
    $b->realMenu('pac');
    if (count($b->updates) !== 1 || !str_contains($b->updates[0]['text'], 'Menu -> pac')) {
        throw new RuntimeException('Меню ещё не созданных PAC показывает настройки один раз');
    }
    $withoutDate = $b->statusWg()['text'];
    if (!str_contains($withoutDate, 'Legacy') || !str_contains($withoutDate, '♾')) {
        throw new RuntimeException('Клиент без даты должен показываться без ограничения срока');
    }
    $b->peer['## time'] = date('Y-m-d H:i:s', time() + 86400);
    if (str_contains($b->statusWg()['text'], '♾')) throw new RuntimeException('Заданный срок клиента сохранён');
    $b->switchClient(0);
    if (empty($b->clientsFake[0]['# off']) || !isset($b->peer['# PublicKey'])) throw new RuntimeException('Клиент выключен');
    $b->switchClient(0);
    if (!empty($b->clientsFake[0]['# off']) || !isset($b->peer['PublicKey'])) throw new RuntimeException('Клиент включён повторно');
    $b->timerClient('+1 day', 0);
    if (empty($b->clientsFake[0]['interface']['## time'])) throw new RuntimeException('Клиенту без флага выключения можно назначить срок');
    file_put_contents($b->ovpnPaths()['status'], "HEADER,CLIENT_LIST,Common Name\nCLIENT_LIST,alice,192.0.2.2:1234,10.8.0.2,,123,456,2026-10-04 12:00:00,1791115200,UNDEF,3\nCLIENT_LIST,UNDEF\n");
    $status = $b->getOvpnStatus();
    if (array_keys($status) !== ['alice'] || $status['alice']['rx'] !== 123 || $status['alice']['tx'] !== 456 || $status['alice']['cid'] !== '3') {
        throw new RuntimeException('Настоящий разбор статуса OpenVPN сохраняет адреса, трафик и идентификатор сессии');
    }

    copy(__DIR__ . '/../config/nginx_default.conf', "$root/config/nginx_default.conf");
    file_put_contents("$root/config/nginx.conf", "events {}\nhttp {}\n");
    if (!$b->cloakNginx()) throw new RuntimeException('NGINX принимает настройки без letsencrypt');
    $config = file_get_contents("$root/config/nginx.conf");
    if (!str_contains($config, '*.legacy.example.test legacy.example.test')) throw new RuntimeException('Домен сохранён');
    $pac = $b->getPacConf(); $pac['letsencrypt'] = 1; $b->setPacConf($pac);
    if (!$b->cloakNginx() || file_get_contents("$root/config/nginx.conf") === $config) {
        throw new RuntimeException('Явное включение сертификата по-прежнему меняет конфигурацию');
    }
    echo "php_legacy_settings_test OK\n";
} finally {
    restore_error_handler();
    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($files as $file) $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
    rmdir($root);
}
