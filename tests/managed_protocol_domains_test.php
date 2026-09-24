<?php
require_once __DIR__ . '/../app/bot.php';

class ProtocolDomainsBot extends Bot
{
    public function __construct() {}
    public function request($method, $data = [], $json = 0) { throw new RuntimeException('Меню не должно обращаться к сети'); }
}

$checks = 0;
function domainCheck(bool $ok, string $message): void
{
    global $checks;
    $checks++;
    if (!$ok) throw new RuntimeException($message);
}

$root = sys_get_temp_dir() . '/vpnbot-domains-' . bin2hex(random_bytes(6));
mkdir($root, 0700);
$timezone = date_default_timezone_get();
date_default_timezone_set('Etc/GMT-4');
try {
    $bot = new ProtocolDomainsBot();
    $bot->protocolRoot = "$root/protocols";
    $bot->protocolCertRoot = "$root/certs";
    mkdir($bot->protocolCertRoot, 0700);
    $key = openssl_pkey_new(['private_key_bits' => 2048]);
    $certificate = static function (string $path, string $san, int $days) use ($root, $key): string {
        file_put_contents("$root/openssl.cnf", "[req]\ndistinguished_name=dn\n[dn]\n[ext]\nsubjectAltName=$san\n");
        $options = ['config' => "$root/openssl.cnf", 'x509_extensions' => 'ext', 'digest_alg' => 'sha256'];
        $csr = openssl_csr_new(['commonName' => 'cn-only.example.test'], $key, $options);
        $cert = openssl_csr_sign($csr, null, $key, $days, $options);
        openssl_x509_export($cert, $pem);
        file_put_contents($path, $pem);
        return ' (ssl: ' . date('Y-m-d H:i:s', openssl_x509_parse($cert)['validTo_time_t']) . ')';
    };
    $san = 'DNS:site.example.test,DNS:at.site.example.test,DNS:tc.site.example.test,DNS:*.wild.example.test,IP:192.0.2.5,IP:2001:db8::5';
    $expiry = $certificate("$root/certs/cert_public", $san, 2);
    $any = $bot->protocolStore('anytls');
    $tuic = $bot->protocolStore('tuic');
    $shadow = $bot->protocolStore('shadowtls');
    $any->configure(['host' => 'at.site.example.test', 'sni' => 'at.site.example.test', 'self_hosted' => true, 'cover_host' => 'site.example.test']);
    $tuic->configure(['host' => 'tc.site.example.test', 'sni' => 'tc.site.example.test']);
    $shadow->configure(['host' => 'site.example.test', 'sni' => 'site.example.test', 'self_hosted' => true]);
    $before = [];
    foreach ([$any, $tuic, $shadow] as $store) $before[$store->directory()] = file_get_contents($store->directory() . '/desired.json');
    $lines = $bot->managedProtocolDomainLines();
    foreach ([
        'AnyTLS: <code>at.site.example.test</code>',
        'AnyTLS сайт прикрытия: <code>site.example.test</code>',
        'TUIC v5: <code>tc.site.example.test</code>',
        'ShadowTLS: <code>site.example.test</code>',
        'ShadowTLS сайт прикрытия (SNI): <code>site.example.test</code>',
    ] as $line) domainCheck(in_array($line . $expiry, $lines, true), 'Срок сертификата: ' . $line);
    domainCheck(in_array('tc.site.example.test', $bot->managedCertificateNames(), true), 'SSL-обновление включает сохранённый поддомен TUIC');
    foreach ($before as $path => $state) domainCheck(file_get_contents($path . '/desired.json') === $state, 'Отображение не изменяет настройки');

    // The same long-lived bot must see the renewed file on its next render.
    $renewed = $certificate("$root/certs/cert_public", $san, 4);
    $lines = $bot->managedProtocolDomainLines();
    domainCheck($renewed !== $expiry && in_array('AnyTLS: <code>at.site.example.test</code>' . $renewed, $lines, true), 'Дата меняется после замены сертификата без перезапуска бота');
    domainCheck(in_array('TUIC v5: <code>tc.site.example.test</code>' . $renewed, $lines, true), 'TUIC показывает обновлённый сертификат');
    domainCheck(in_array('ShadowTLS: <code>site.example.test</code>' . $renewed, $lines, true), 'ShadowTLS показывает обновлённый сертификат сайта');

    $custom = $certificate("$root/certs/custom.pem", $san, 7);
    $any->configure(['host' => '192.0.2.1', 'certificate' => '/certs/custom.pem']);
    $tuic->configure(['host' => '192.0.2.2', 'certificate' => '/certs/custom.pem']);
    $lines = $bot->managedProtocolDomainLines();
    foreach (['AnyTLS' => 'at', 'TUIC v5' => 'tc'] as $label => $prefix) {
        domainCheck(in_array("$label SNI: <code>$prefix.site.example.test</code>" . $custom, $lines, true), 'Дата собственного файла сертификата относится к SNI');
    }
    domainCheck(in_array('AnyTLS: <code>192.0.2.1</code>', $lines, true), 'Сертификат SNI не приписывается IP подключения');
    domainCheck(in_array('AnyTLS сайт прикрытия: <code>site.example.test</code>' . $renewed, $lines, true), 'Сайт прикрытия использует свой сертификат, а не отдельный сертификат AnyTLS');
    $shadow->configure(['sni' => 'external.example.test', 'self_hosted' => false]);
    $lines = $bot->managedProtocolDomainLines();
    domainCheck(in_array('ShadowTLS: <code>site.example.test</code>', $lines, true)
        && in_array('ShadowTLS сайт прикрытия (SNI): <code>external.example.test</code>', $lines, true), 'Чужому сайту ShadowTLS не приписывается локальный сертификат');

    foreach (['ONE.WILD.EXAMPLE.TEST' => true, 'two.one.wild.example.test' => false, 'wild.example.test' => false,
        'cn-only.example.test' => false, '192.0.2.5' => true, '192.0.2.6' => false, '2001:db8:0:0::5' => true] as $name => $covered) {
        $tuic->configure(['host' => $name, 'sni' => $name]);
        $lines = $bot->managedProtocolDomainLines();
        domainCheck(in_array("TUIC v5: <code>$name</code>" . $custom, $lines, true) === $covered, 'Соответствие SAN: ' . $name);
    }

    $tuic->configure(['host' => 'tc.site.example.test', 'sni' => 'tc.site.example.test']);
    copy("$root/certs/custom.pem", "$root/outside.pem");
    foreach (['missing.pem', 'broken.pem', 'large.pem', 'outside.pem', 'reference.pem'] as $file) {
        if ($file === 'broken.pem') file_put_contents("$root/certs/$file", 'not a certificate');
        if ($file === 'large.pem') file_put_contents("$root/certs/$file", str_repeat('x', 1024 * 1024 + 1));
        if ($file === 'outside.pem') symlink("$root/outside.pem", "$root/certs/$file");
        if ($file === 'reference.pem') file_put_contents("$root/certs/$file", "file://$root/certs/custom.pem");
        $tuic->configure(['certificate' => '/certs/' . $file]);
        $lines = $bot->managedProtocolDomainLines();
        domainCheck(in_array('TUIC v5: <code>tc.site.example.test</code> (ssl: нет сертификата для домена)', $lines, true)
            && !str_contains(implode("\n", $lines), '1970-01-01'), 'Недоступный сертификат не ломает меню: ' . $file);
    }
    file_put_contents($tuic->directory() . '/desired.json', '{broken');
    domainCheck(in_array('TUIC v5: ошибка состояния', $bot->managedProtocolDomainLines(), true), 'Повреждённые настройки TUIC не ломают остальные домены');
    $bot->protocolRoot = "$root/unconfigured";
    domainCheck(in_array('TUIC v5: не настроен', $bot->managedProtocolDomainLines(), true) && !is_dir($bot->protocolRoot), 'Меню не создаёт домен и настройки самостоятельно');
    echo "managed_protocol_domains_test: $checks OK\n";
} finally {
    date_default_timezone_set($timezone);
    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($files as $file) $file->isDir() && !$file->isLink() ? rmdir($file->getPathname()) : unlink($file->getPathname());
    rmdir($root);
}
