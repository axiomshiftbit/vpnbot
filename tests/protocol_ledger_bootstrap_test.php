<?php
require_once __DIR__ . '/../app/ManagedProtocol.php';
require_once __DIR__ . '/managed_protocol_fixture.php';

function ledgerCheck(bool $ok, string $label): void {
    if (!$ok) throw new RuntimeException($label);
}
function ledgerRemove(string $path): void {
    if (is_dir($path)) {
        foreach (scandir($path) as $name) if ($name !== '.' && $name !== '..') ledgerRemove($path . '/' . $name);
        rmdir($path);
    } else unlink($path);
}
$root = sys_get_temp_dir() . '/protocol-ledger-' . bin2hex(random_bytes(6));
mkdir($root, 0700);
try {
    foreach (['anytls', 'mieru', 'tuic', 'shadowtls', 'masque'] as $protocol) {
        $store = new ManagedProtocol($protocol, $root);
        $store->configure(['host' => 'vpn.example.test', 'sni' => 'vpn.example.test'], true);
        $path = $store->directory() . '/runtime/usage.json';
        ledgerCheck(is_file($path) && $store->usage()['users'] === [], "$protocol: чистый ledger создан до пользователей");
        ledgerCheck((fileperms($path) & 0777) === 0600, "$protocol: закрытые права ledger");
        $id = managedProtocolFixtureUser($store, 'Synthetic client');
        $snapshot = $store->snapshot();
        unlink($path);
        $store->user($id, ['name' => 'Edited client']);
        ledgerCheck(!file_exists($path), "$protocol: правка не обнуляет потерянные счётчики");
        $rejected = false;
        try { $store->snapshot(); } catch (RuntimeException $error) { $rejected = true; }
        ledgerCheck($rejected, "$protocol: потеря ledger не попадает в backup как нулевой расход");
        $store->restore($snapshot);
        ledgerCheck(isset($store->read()['restore_usage']), "$protocol: явное восстановление доступно");
        ledgerCheck($store->snapshot()['usage']['users'] === [], "$protocol: ожидающее восстановление сохраняется в backup");
    }
    echo "PASS: bootstrap, loss, backup refusal and explicit restore for 5 protocols\n";
} finally { ledgerRemove($root); }
