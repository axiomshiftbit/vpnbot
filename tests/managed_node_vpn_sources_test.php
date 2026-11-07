<?php
// VPN-only servers: public addresses only, deduplicated, bounded; they live in
// node options next to the other network settings and reach the node by Apply.
require_once __DIR__ . '/../app/bot.php';
$checks = 0;
$check = static function ($ok, $name) use (&$checks) { $checks++; if (!$ok) throw new RuntimeException('FAIL '.$name); };
$field = ManagedNodeFields::all()['vpn_sources'] ?? null;
$check($field && $field[0] === 'network' && $field[3] === 'list', 'field is a list in the IPv4 / IPv6 group');
$options = ['transport' => 'reality', 'family' => 4, 'core' => 'origin', 'domain' => '', 'mask' => 'www.example.test'];
$changed = ManagedNodeFields::change($options, 'vpn_sources', ['11.77.0.200', '2606:4700:4700:0::1001', '11.77.0.200']);
$check($changed['vpn_sources'] === ['11.77.0.200', '2606:4700:4700::1001'], 'deduplicated and canonical');
$check(ManagedNodeFields::change($changed, 'vpn_sources', [])['vpn_sources'] === [], 'list can be cleared');
// Exactly the node's reserved ranges (scripts/node_config.py): bot and node must agree.
foreach (['100.64.0.1', '192.0.0.8', '192.0.2.5', '192.88.99.0', '198.18.0.1', '198.51.100.7', '203.0.113.9', '224.0.0.1', '240.0.0.1',
          '2001:db8::1', '2002::1', '64:ff9b::1', '2001::1', '100::1', '3fff::1', '::ffff:8.8.8.8', '4000::1'] as $reserved) {
    try { ManagedNodeFields::vpnSources([$reserved]); $rejected = false; } catch (InvalidArgumentException $error) { $rejected = true; }
    $check($rejected, 'reserved '.$reserved);
}
$check(count(ManagedNodeFields::RESERVED) === 27, 'reserved list mirrors PRIVATE4 + PRIVATE6');
foreach ([['10.0.0.1'], ['192.168.1.1'], ['127.0.0.1'], ['11.77.0.0/24'], ['fe80::1'], ['fd00::1'], ['ff02::1'], ['node.example.test'], [''],
          array_map(static fn($i) => "11.77.0.$i", range(1, 33))] as $bad) {
    try { ManagedNodeFields::change($options, 'vpn_sources', $bad); $rejected = false; }
    catch (InvalidArgumentException $error) { $rejected = true; }
    $check($rejected, 'rejected '.json_encode(array_slice($bad, 0, 2)));
}
echo "PASS $checks managed node VPN-only server checks\n";
