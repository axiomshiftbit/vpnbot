<?php
require __DIR__ . '/../app/bot.php';
set_error_handler(static function ($level, $message, $file, $line) {
    if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line);
    return true;
});

class CertificateBundleBot extends Bot
{
    public array $conf = ['letsencrypt' => 'letsencrypt'];
    public int $reloads = 0;
    public string $failFile = '';
    public bool $failRename = false;
    public bool $failSettings = false;
    public bool $nginxOk = true;
    public bool $ttOk = true;
    public function __construct(string $root) { $this->protocolCertRoot = $root; $this->pac = "$root/pac.json"; }
    public function getPacConf() { return $this->conf; }
    public function setPacConf(array $conf) { if ($this->failSettings) return false; $this->conf = $conf; return true; }
    public function writePrivateKey(string $path, string $data): bool {
        if (str_contains($path, '/.restore-') && basename($path) === $this->failFile) return false;
        return parent::writePrivateKey($path, $data);
    }
    protected function backupRename(string $from, string $to): bool {
        if ($this->failRename && basename($to) === 'cert_public') return false;
        return parent::backupRename($from, $to);
    }
    public function adguardSync() { $this->reloads++; }
    public function cloakNginx() { return $this->nginxOk; }
    public function restartTt() { return $this->ttOk; }
    public function telemtWebSync(): void {}
}

function certificateBundlePair(): array
{
    $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
    $csr = openssl_csr_new(['commonName' => 'certificate.example.org'], $key, ['digest_alg' => 'sha256']);
    $certificate = openssl_csr_sign($csr, null, $key, 1, ['digest_alg' => 'sha256']);
    openssl_pkey_export($key, $private);
    openssl_x509_export($certificate, $public);
    return [$private, $public];
}

$root = sys_get_temp_dir() . '/vpnbot-certificate-' . bin2hex(random_bytes(6));
mkdir($root, 0700);
register_shutdown_function(static function () use ($root) {
    foreach (glob($root . '/*') as $file) unlink($file);
    if (file_exists("$root/.backup.lock")) unlink("$root/.backup.lock");
    rmdir($root);
});
$bot = new CertificateBundleBot($root);
[$oldKey, $oldCertificate] = certificateBundlePair();
[$key, $certificate] = certificateBundlePair();
file_put_contents("$root/cert_private", $oldKey);
file_put_contents("$root/cert_public", $oldCertificate);
$checks = 0;
foreach ([
    $oldKey . $certificate,
    "-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----\n" . $certificate,
    $key . "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n",
    $key . $certificate . "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n",
    $key . $certificate . "-----BEGIN CERTIFICATE-----\ntruncated\n",
] as $bundle) {
    if ($bot->applyCertificateBundle($bundle, ['letsencrypt' => 'self'])
        || file_get_contents("$root/cert_private") !== $oldKey
        || file_get_contents("$root/cert_public") !== $oldCertificate
        || $bot->conf !== ['letsencrypt' => 'letsencrypt'] || $bot->reloads !== 0) {
        throw new RuntimeException('Неверная пара/цепочка изменила рабочий SSL или настройки');
    }
    $checks++;
}
foreach (['settings', 'cert_private', 'cert_public', 'rename'] as $failure) {
    $bot->failSettings = $failure === 'settings';
    $bot->failFile = $failure;
    $bot->failRename = $failure === 'rename';
    try {
        $applied = $bot->applyCertificateBundle($key . $certificate, ['letsencrypt' => 'self']);
    } catch (RuntimeException $error) {
        // Checked PAC storage reports an explicit write failure by exception.
        if ($failure !== 'settings') throw $error;
        $applied = false;
    }
    if ($applied
        || file_get_contents("$root/cert_private") !== $oldKey
        || file_get_contents("$root/cert_public") !== $oldCertificate
        || $bot->conf !== ['letsencrypt' => 'letsencrypt'] || $bot->reloads !== 0) {
        throw new RuntimeException("Ошибка $failure не сохранила прежнюю пару и настройки");
    }
    $checks++;
}
$bot->failSettings = $bot->failRename = false;
$bot->failFile = '';
$bot->acmeInstallLockWait = 0;
$lock = fopen("$root/.backup.lock", 'c');
flock($lock, LOCK_EX);
try {
    $bot->applyCertificateBundle($key . $certificate, ['letsencrypt' => 'self']);
    throw new LogicException('Установка прошла во время бэкапа');
} catch (RuntimeException $error) {
    if ($bot->conf !== ['letsencrypt' => 'letsencrypt'] || $bot->reloads !== 0
        || file_get_contents("$root/cert_public") !== $oldCertificate) throw $error;
    $checks++;
} finally { flock($lock, LOCK_UN); fclose($lock); }
foreach ([$key . $certificate, $key . $certificate . $oldCertificate] as $bundle) {
    if (!$bot->applyCertificateBundle($bundle, ['letsencrypt' => 'self'])
        || !openssl_x509_check_private_key(file_get_contents("$root/cert_public"), file_get_contents("$root/cert_private"))
        || $bot->conf !== ['letsencrypt' => 'self']) {
        throw new RuntimeException('Корректная пара/цепочка не установлена');
    }
    $checks++;
}
foreach (['nginxOk', 'ttOk'] as $consumer) {
    $bot->$consumer = false;
    if ($bot->applyCertificateBundle($key . $certificate, ['letsencrypt' => 'self']) !== false
        || !openssl_x509_check_private_key(file_get_contents("$root/cert_public"), file_get_contents("$root/cert_private"))) {
        throw new RuntimeException('Отказ потребителя SSL должен сообщаться, сохраняя новую валидную пару');
    }
    $bot->$consumer = true;
    if (!$bot->applyCertificateBundle($key . $certificate, ['letsencrypt' => 'self'])) {
        throw new RuntimeException('Повторное применение той же пары должно восстанавливаться');
    }
    $checks++;
}
$receiptBot = new class($root) extends CertificateBundleBot {
    public int $installs = 0;
    public string $next = '';
    public bool $throwInstall = false;
    public function installLetsencrypt(string $domain, array $expectedNames = [], ?array $expectedState = null): bool {
        $this->installs++;
        file_put_contents($this->protocolCertRoot . '/cert_public', $this->next);
        if ($this->throwInstall) throw new RuntimeException('synthetic reload failure');
        return false;
    }
};
$receiptBot->next = $oldCertificate;
$fingerprint = hash_file('sha256', "$root/cert_public");
$stale = $receiptBot->installLetsencryptReceipt('certificate.example.org', [], str_repeat('0', 64), null);
if (empty($stale['stale']) || $receiptBot->installs !== 0) throw new RuntimeException('Restore того же домена нельзя перезаписать старым pending');
$checks++;
foreach ([false, true] as $throw) {
    $receiptBot->throwInstall = $throw;
    $receipt = $receiptBot->installLetsencryptReceipt('certificate.example.org', [], $fingerprint, null);
    if ($receipt['installed'] !== false || $receipt['certificate'] !== hash('sha256', $oldCertificate)) {
        throw new RuntimeException('Receipt обязан сохранить fingerprint нашей записи при отказе reload');
    }
    $fingerprint = $receipt['certificate'];
    $checks++;
}
$bot->conf['domain'] = 'certificate.example.org';
if (!$bot->applyCertificateBundle($key . $certificate, ['domain' => 'certificate.example.org', 'letsencrypt' => 'letsencrypt'])) {
    throw new RuntimeException('Текущий домен должен принять совпадающую пару сертификата');
}
$fingerprint = hash_file('sha256', "$root/cert_public");
$receipt = $bot->reapplyCertificateReceipt($fingerprint);
if (!$receipt['installed'] || !openssl_x509_check_private_key(file_get_contents("$root/cert_public"), $key)) {
    throw new RuntimeException('Миграция должна применять текущую пару без обращения к lineage');
}
$checks++;
$bot->conf['letsencrypt'] = 'self';
if (empty($bot->reapplyCertificateReceipt($receipt['certificate'])['stale'])) {
    throw new RuntimeException('Миграция не должна трогать восстановленный собственный сертификат');
}
$checks++;
echo "certificate_bundle_test: $checks проверок OK\n";
