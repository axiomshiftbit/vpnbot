<?php
require_once __DIR__ . '/../app/ManagedProtocol.php';
require_once __DIR__ . '/../app/ProtocolModules.php';
require_once __DIR__ . '/managed_protocol_fixture.php';

$checks = 0;
function snolcCheck(bool $value, string $name): void {
    global $checks;
    if (!$value) throw new RuntimeException($name);
    $checks++;
}
function snolcDenied(callable $call): void {
    try { $call(); } catch (InvalidArgumentException | RuntimeException $e) { snolcCheck(true, 'Отказ'); return; }
    throw new RuntimeException('Недопустимая операция принята');
}
$root = sys_get_temp_dir() . '/vpnbot-snolc-' . bin2hex(random_bytes(6));
mkdir($root, 0700);
try {
    $store = new ManagedProtocol('snolc', $root);
    snolcCheck(!$store->read()['enabled'] && !ProtocolModules::DEFAULTS['snolc'], 'Модуль выключен по умолчанию');
    snolcCheck($store->read()['settings']['port'] === 24448, 'Отдельный порт 24448');
    snolcDenied(fn() => $store->configure([], true));
    $store->configure(['host' => 'vpn.example.test'], true);
    $id = managedProtocolFixtureUser($store, 'Клиент < & >');
    $state = $store->read();
    $profile = $store->profile($id, 'native');
    snolcCheck(array_keys($store->formats()) === ['native'], 'Только поддерживаемый нативный архив');
    foreach (['mihomo', 'singbox', 'uri', 'native-uri'] as $format) snolcDenied(fn() => $store->profile($id, $format));
    snolcDenied(fn() => $store->connectionUri($id));
    snolcCheck(!str_contains(json_encode($profile), $state['settings']['server_seed']), 'Корневой секрет сервера не выдаётся клиенту');
    snolcCheck(strlen($profile['credential']) === 64 && $profile['credential'] !== $state['users'][$id]['token'], 'Отдельный ключ policy-local');
    $seed = hex2bin($state['settings']['server_seed']);
    if (extension_loaded('sodium')) {
        $derive = static fn($key) => hash_hmac('sha256', 'vpnbot/snolc/' . $key . '/v1', $seed, true);
        $public = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($derive('ssh')));
        snolcCheck($profile['server']['ssh_public_key'] === 'ssh-ed25519 ' . base64_encode(pack('N', 11) . 'ssh-ed25519' . pack('N', 32) . $public), 'OpenSSL и sodium: одинаковый SSH pin');
        snolcCheck($profile['server']['noise_public_key'] === bin2hex(sodium_crypto_scalarmult_base($derive('noise'))), 'OpenSSL и sodium: одинаковый Noise pin');
    }
    $relay = $store->profile($id, 'native', endpoint: ['host' => 'relay.example.test', 'port' => 24449]);
    snolcCheck($relay['server']['host'] === 'relay.example.test' && $relay['server']['port'] === 24449, 'Адрес relay');
    snolcCheck(array_diff_assoc($profile['server'], $relay['server']) === ['host' => 'vpn.example.test', 'port' => 24448], 'Relay сохраняет оба pin и пароль транспорта');
    $doc = $store->profileDocument($id, 'native');
    snolcCheck($doc['extension'] === 'zip' && $doc['mime'] === 'application/zip', 'Тип ZIP');
    file_put_contents("$root/client.zip", $doc['body']);
    $zip = new ZipArchive();
    snolcCheck($zip->open("$root/client.zip") === true, 'Архив открывается');
    snolcCheck(json_decode($zip->getFromName('profile.json'), true) === $profile, 'Профиль в архиве без изменений');
    snolcCheck($zip->getFromName('client-patches.zip') === 'synthetic client bundle', 'Исправленный нативный клиент включён в ZIP');
    foreach (['client.py', 'snolc_config.py', 'releases.json', 'module-options.json', 'README.txt'] as $file) snolcCheck($zip->getFromName($file) === file_get_contents(__DIR__ . '/../app/snolc/' . $file), 'Полный комплект: ' . $file);
    $zip->close();
    unlink($store->directory() . '/runtime/client-patches.zip');
    snolcDenied(fn() => $store->profileDocument($id, 'native'));
    file_put_contents($store->directory() . '/runtime/client-patches.zip', 'synthetic client bundle');
    foreach ([['sni' => 'example.com'], ['egress' => 'warp'], ['listen_port' => 22], ['port' => 22], ['server_seed' => 'wrong'], ['options' => ['client' => ['udp' => false]]]] as $bad) {
        snolcDenied(fn() => $store->configure($bad));
        snolcCheck($store->read() === $state, 'Неверные настройки не изменяют рабочее состояние');
    }
    $snapshot = $store->snapshot();
    $store->user($id, [], 'rotate');
    $rotated = $store->profile($id, 'native');
    snolcCheck($rotated['credential'] !== $profile['credential'], 'Ротация личного доступа');
    snolcCheck($rotated['server'] === $profile['server'], 'Ротация не меняет серверные ключи');
    $store->configure([], false);
    snolcDenied(fn() => $store->profileDocument($id, 'native'));
    $store->configure([], true);
    snolcCheck($store->profile($id, 'native') === $rotated, 'Выключатель сохраняет ключи');
    $other = new ManagedProtocol('snolc', "$root/restore");
    $other->restore($snapshot);
    snolcCheck($other->profile($id, 'native') === $profile, 'Перенос резервной копии сохраняет оба pin');
    $store->user($id, ['enabled' => false]);
    snolcDenied(fn() => $store->profile($id, 'native'));
    $store->user($id, ['enabled' => true, 'expires' => time() - 1]);
    snolcDenied(fn() => $store->profile($id, 'native'));
    $store->user($id, ['expires' => null, 'quota' => 100]);
    ManagedProtocol::writeJson($store->directory() . '/runtime/usage.json', ['users' => [$id => ['reset' => $state['users'][$id]['reset'], 'upload' => 50, 'download' => 50]]]);
    snolcDenied(fn() => $store->profile($id, 'native'));
    $store->user($id, [], 'reset');
    snolcCheck($store->profile($id, 'native')['credential'] === $rotated['credential'], 'Сброс расхода сохраняет личный ключ');
    $store->user($id, [], 'delete');
    snolcDenied(fn() => $store->profile($id, 'native'));
    echo "snolc_test: $checks OK\n";
} finally {
    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($files as $file) $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
    rmdir($root);
}
