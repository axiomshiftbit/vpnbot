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
    public function cloakNginx() {}
    public function restartTt() {}
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
    if ($bot->applyCertificateBundle($key . $certificate, ['letsencrypt' => 'self'])
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
echo "certificate_bundle_test: $checks проверок OK\n";
