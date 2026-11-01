<?php
require_once __DIR__ . '/../app/bot.php';
class Node6TestBot extends Bot {
    public bool $attached = true;
    public function __construct() {}
    protected function exitIpv6Network(): array { return $this->attached ? ['enabled' => true, 'public' => '2606:4700:4700::1111'] : []; }
    public function xrayCoreInventory(): array { return ['origin' => '26.10.31']; }
}
$b = new Node6TestBot();
$base = ['inbounds' => [['tag' => 'vless_reality', 'port' => 443, 'protocol' => 'vless',
    'settings' => ['clients' => [['id' => '11111111-1111-4111-8111-111111111111', 'email' => 'synthetic', 'flow' => 'xtls-rprx-vision']], 'decryption' => 'none'],
    'streamSettings' => ['network' => 'tcp', 'security' => 'reality',
        'tcpSettings' => ['acceptProxyProtocol' => true], 'sockopt' => ['acceptProxyProtocol' => true],
        'realitySettings' => ['dest' => '127.0.0.1:8443', 'serverNames' => ['mask.example.test'], 'shortIds' => ['abcd1234']]]]]];
$p = ['transport' => 'Reality', 'xray_core' => 'origin'];
if (!method_exists($b, 'ensureNode6Inbound')) { fwrite(STDERR, "FAIL: direct IPv6 ingress has no listener without PROXY protocol\n"); exit(1); }
$b->ensureNode6Inbound($base, $p);
$checks = 0;
$check = function ($ok, $name) use (&$checks) { $checks++; if (!$ok) throw new RuntimeException($name); };
$six = array_values(array_filter($base['inbounds'], fn($i) => ($i['tag'] ?? '') === 'node6-reality'))[0] ?? [];
$check(($six['listen'] ?? '') === Bot::EXIT_IPV6_SOURCE && ($six['port'] ?? 0) === 443, 'IPv6 socket is bound only to the dedicated container address');
$check(empty($six['streamSettings']['tcpSettings']['acceptProxyProtocol']) && empty($six['streamSettings']['sockopt']['acceptProxyProtocol']), 'direct IPv6 does not require or trust a PROXY header');
$check(($base['inbounds'][0]['listen'] ?? '') === '0.0.0.0' && $base['inbounds'][0]['streamSettings']['sockopt']['acceptProxyProtocol'], 'IPv4 upstream retains PROXY protocol');
$check($six['settings'] === $base['inbounds'][0]['settings'], 'client authorization is identical');
$first = $base; $b->ensureNode6Inbound($base, $p); $check($first === $base, 'repeat is idempotent');
$guarded = $base;
$guarded['outbounds'] = [['tag' => 'direct', 'protocol' => 'freedom']];
$guarded['routing'] = ['rules' => []];
$b->ensureTorrentBlock($guarded, ['xray_blocktorrent' => 1]);
$b->ensureWgGuard($guarded);
$protected = array_filter($guarded['routing']['rules'], fn($r) => in_array('node6-reality', $r['inboundTag'] ?? [], true));
$check(count($protected) >= 3, 'direct IPv6 receives private-network and torrent policy gates');
$base['inbounds'][0]['settings']['clients'][0]['id'] = '22222222-2222-4222-8222-222222222222';
$b->ensureNode6Inbound($base, $p);
$check($base['inbounds'][1]['settings']['clients'][0]['id'] === '22222222-2222-4222-8222-222222222222', 'credential rotation reaches the direct IPv6 listener');
$base['inbounds'][0]['settings']['clients'] = [];
$b->ensureNode6Inbound($base, $p);
$check($base['inbounds'][1]['settings']['clients'] === [], 'revoked clients cannot remain in the IPv6 listener');
$b->attached = false; $b->ensureNode6Inbound($base, $p);
$check(count($base['inbounds']) === 1 && !isset($base['inbounds'][0]['listen']), 'disable removes IPv6 and restores original bind');
$b->attached = true; $base['inbounds'][0]['streamSettings']['security'] = 'none'; $b->ensureNode6Inbound($base, ['transport' => 'xhttp']);
$check(count($base['inbounds']) === 1, 'other transports do not open direct IPv6');
echo "OK $checks IPv6 ingress checks\n";
