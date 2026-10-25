<?php
// Загрузка/удаление SSL не должны обходить блокировку бэкапа и откатывать настройки.
require_once __DIR__ . '/../app/bot.php';
set_error_handler(static function ($level, $message, $file, $line) {
    if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line);
    return true;
});
$checks = 0;
function sslCheck(bool $ok, string $message): void {
    global $checks; $checks++;
    if (!$ok) throw new RuntimeException($message);
}
class SslLifecycleBot extends Bot {
    public ?Closure $duringDownload = null;
    public array $reply = [];
    public array $messages = [];
    public function __construct(string $root) {
        $this->pac = "$root/pac.json"; $this->protocolCertRoot = "$root/certs";
        $this->language = 'en'; Lang::$en = true; $this->acmeInstallLockWait = 1;
        $this->input = ['chat' => 1, 'message_id' => 2, 'file_id' => 'synthetic'];
        $this->file = 'file://';
    }
    public function request($method, $data, $json_header = 0) {
        if ($this->duringDownload) ($this->duringDownload)($this);
        return $this->reply;
    }
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML') { $this->messages[] = $text; }
    public function menu($type = false, $arg = false, $return = false) {}
    public function adguardSync() {} public function cloakNginx() {} public function restartTt() {} public function telemtWebSync(): void {}
}
$root = sys_get_temp_dir() . '/ssl-lifecycle-' . bin2hex(random_bytes(6));
mkdir("$root/certs", 0700, true);
register_shutdown_function(static fn() => exec('rm -rf ' . escapeshellarg($root)));
$pair = static function (): array {
    $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
    $csr = openssl_csr_new(['commonName' => 'vpn.example.org'], $key, ['digest_alg' => 'sha256']);
    $cert = openssl_csr_sign($csr, null, $key, 1, ['digest_alg' => 'sha256'], random_int(1, 1000000));
    openssl_pkey_export($key, $private); openssl_x509_export($cert, $public);
    return [$private, $public];
};
[$oldKey, $oldCert] = $pair(); [$newKey, $newCert] = $pair();
file_put_contents("$root/upload.pem", $newKey . $newCert);
$b = new SslLifecycleBot($root);
$reset = static function () use ($b, $root, $oldKey, $oldCert): void {
    $b->setPacConf(['domain' => 'vpn.example.org', 'letsencrypt' => 'letsencrypt', 'limitpage' => 5]);
    file_put_contents("$root/certs/cert_private", $oldKey); file_put_contents("$root/certs/cert_public", $oldCert);
    $b->duringDownload = null; $b->reply = ['result' => ['file_path' => "$root/upload.pem"]]; $b->messages = [];
};
foreach (['domain', 'other', 'certificate', 'missing-download', 'api-error', 'normal'] as $change) {
    $reset();
    $b->duringDownload = static function ($b) use ($change, $root, $newKey, $newCert) {
        $c = $b->getPacConf();
        if ($change === 'domain') $c['domain'] = 'restored.example.org';
        if ($change === 'other') $c['limitpage'] = 17;
        if ($change === 'certificate') {
            file_put_contents("$root/certs/cert_private", $newKey);
            file_put_contents("$root/certs/cert_public", $newCert);
        }
        $b->setPacConf($c);
    };
    if ($change === 'missing-download') $b->reply['result']['file_path'] = "$root/FAKE_BOT_TOKEN/nonexistent.pem";
    if ($change === 'api-error') $b->reply = ['ok' => false];
    $b->setSSL('self');
    $c = $b->getPacConf();
    if (in_array($change, ['other', 'normal'], true)) {
        sslCheck($c['letsencrypt'] === 'self' && openssl_x509_fingerprint(file_get_contents("$root/certs/cert_public")) === openssl_x509_fingerprint($newCert), "$change: uploaded pair installed");
        if ($change === 'other') sslCheck($c['limitpage'] === 17, 'parallel setting preserved');
    } else {
        sslCheck($c['letsencrypt'] === 'letsencrypt', "$change: changed state or failed download rejected");
        sslCheck(file_get_contents("$root/certs/cert_public") === ($change === 'certificate' ? $newCert : $oldCert), "$change: previous pair preserved");
        sslCheck(count($b->messages) === 1 && !str_contains($b->messages[0], 'FAKE_BOT_TOKEN'), "$change: generic error without download credentials");
        if ($change === 'domain') sslCheck($c['domain'] === 'restored.example.org', 'restored domain preserved');
    }
}
$reset();
$held = fopen("$root/.backup.lock", 'c'); flock($held, LOCK_EX);
$blocked = false;
try { $b->deleteSSL(true); } catch (RuntimeException $e) { $blocked = true; }
sslCheck($blocked && file_get_contents("$root/certs/cert_public") === $oldCert && file_get_contents("$root/certs/cert_private") === $oldKey,
    'deletion waits for backup and leaves both files intact on lock timeout');
flock($held, LOCK_UN); fclose($held);
$b->deleteSSL(true);
sslCheck(!is_file("$root/certs/cert_public") && !is_file("$root/certs/cert_private") && !isset($b->getPacConf()['letsencrypt']), 'deletion removes pair and SSL mode');
$b->deleteSSL(true);
sslCheck(!is_file("$root/certs/cert_public"), 'repeated deletion succeeds without warnings');
echo "ssl_lifecycle_test OK ($checks checks)\n";
