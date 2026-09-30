<?php
require_once __DIR__ . '/../app/bot.php';
function diagnosticCheck(bool $ok, string $name): void { if (!$ok) throw new RuntimeException($name); }
class DiagnosticsBot extends Bot
{
    public function __construct(string $root) {
        $this->hysteriaUsersRoot = "$root/hy"; $this->hysteriaConf = "$root/hysteria.yaml";
        $this->protocolRoot = "$root/protocols"; $this->protocolCertRoot = "$root/certs";
        $this->protocolModulesFile = "$root/modules.json";
    }
    public function getXrayStats() { return ['users' => [0 => ['global' => ['upload' => 10, 'download' => 20]]]]; }
    public function xrayProtocolUsage(array $client): array { return ['upload' => 30, 'download' => 40]; }
}
$root = sys_get_temp_dir() . '/vpnbot-diagnostics-' . bin2hex(random_bytes(6)); mkdir($root, 0700);
try {
    mkdir("$root/certs", 0700); $b = new DiagnosticsBot($root); $store = $b->hysteriaUsersStore(); $store->add('test');
    mkdir("$root/hy/runtime", 0700);
    $key = openssl_pkey_new(['private_key_bits' => 2048]);
    $csr = openssl_csr_new(['commonName' => 'test.example'], $key);
    $cert = openssl_csr_sign($csr, null, $key, 1); openssl_x509_export($cert, $pem); file_put_contents("$root/certs/test.pem", $pem);
    file_put_contents("$root/hysteria.yaml", "tls:\n  cert: /certs/test.pem\n");
    ManagedProtocol::writeJson("$root/hy/runtime/status.json", ['time' => time(), 'running' => true,
        'revision' => $store->read()['revision'], 'error' => 'port_in_use', 'last_success' => 1770000000, 'last_validation' => 1770000001]);
    $text = implode("\n", $b->serviceDiagnosticLines('hy'));
    diagnosticCheck(str_contains($text, 'порт уже занят') && str_contains($text, 'TLS: действует'), 'Конкретная ошибка и срок TLS');
    diagnosticCheck(str_contains($text, gmdate('Y-m-d H:i:s', 1770000000)), 'Последнее применение показано в UTC');
    diagnosticCheck(!str_contains(Bot::serviceErrorText('unknown-with-password'), 'password'), 'Неизвестная ошибка не раскрывает вывод ядра');
    foreach (['tls_expired', 'tls_name_mismatch', 'core_unavailable', 'configuration_rejected'] as $code) diagnosticCheck(Bot::serviceErrorText($code) !== Bot::serviceErrorText('unknown'), 'Категория ошибки: ' . $code);
    unlink("$root/certs/test.pem");
    diagnosticCheck(str_contains(implode("\n", $b->serviceDiagnosticLines('hy')), 'сертификат не найден'), 'Пропавший TLS-файл виден');
    $client = ['traffic' => 150, 'time' => 0];
    $text = implode("\n", $b->subscriptionCardSummary($client, 0));
    diagnosticCheck(str_contains($text, '100 B') && str_contains($text, '50 B'), 'Карточка учитывает общий трафик новых протоколов');
    diagnosticCheck(str_contains(implode('', $b->subscriptionCardSummary($client + ['off' => 'disabled'], 0)), 'выключен'), 'Ручное отключение видно');
    diagnosticCheck(str_contains(implode('', $b->subscriptionCardSummary(['traffic' => 50, 'time' => 0], 0)), 'квота исчерпана'), 'Причина блокировки по квоте');
    diagnosticCheck($b->getBytes(1099511627776) === '1 TB', 'Большая групповая квота отображается полностью');
} finally {
    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($files as $f) $f->isDir() ? rmdir($f->getPathname()) : unlink($f->getPathname()); rmdir($root);
}
echo "access_diagnostics_test OK\n";
