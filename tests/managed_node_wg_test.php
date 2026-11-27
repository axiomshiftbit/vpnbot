<?php
require __DIR__ . '/managed_nodes_test.php';
$bot = new ManagedFixtureBot();
$profile = $bot->profile;
$profile['channel'] = 'wireguard';
$profile['outbound'] = ['tag' => 'node', 'protocol' => 'wireguard', 'settings' => [
    'secretKey' => base64_encode(str_repeat('a', 32)), 'mtu' => 1280, 'noKernelTun' => true,
    'address' => ['10.77.77.2/32'], 'remoteDNS' => ['1.1.1.1', '9.9.9.9'],
    'peers' => [['publicKey' => base64_encode(str_repeat('b', 32)), 'preSharedKey' => base64_encode(str_repeat('c', 32)),
        'endpoint' => '1.1.1.1:51820', 'allowedIPs' => ['0.0.0.0/0', '::/0'], 'keepAlive' => 25]],
]];
$count = 0;
foreach (['origin', 'origin2', 'origin3', 'fork'] as $core) {
    $parsed = ManagedNodeProfile::parse($profile, $core);
    if ($parsed['managed_outbound']['protocol'] !== 'wireguard') throw new RuntimeException('FAIL backup selects WireGuard');
    $count++;
}
foreach (['endpoint', 'dns', 'address', 'kernel', 'key', 'extra', 'channel'] as $field) {
    $bad = $profile;
    if ($field === 'endpoint') $bad['outbound']['settings']['peers'][0]['endpoint'] = '127.0.0.1:22';
    if ($field === 'dns') $bad['outbound']['settings']['remoteDNS'] = ['127.0.0.1'];
    if ($field === 'address') $bad['outbound']['settings']['address'] = ['127.0.0.1'];
    if ($field === 'kernel') $bad['outbound']['settings']['noKernelTun'] = false;
    if ($field === 'key') $bad['outbound']['settings']['secretKey'] = base64_encode(str_repeat("\0", 32));
    if ($field === 'extra') $bad['outbound']['proxySettings'] = ['tag' => 'direct'];
    if ($field === 'channel') $bad['channel'] = 'arbitrary';
    try { ManagedNodeProfile::parse($bad, 'origin'); throw new RuntimeException('FAIL unsafe WireGuard profile accepted'); }
    catch (InvalidArgumentException $e) { $count++; }
}
$bot->profile = $profile;
$bot->managedNodePoll('aabbccdd');
if ($bot->exitNodeOutbound($bot->exitNodes()['aabbccdd'])['protocol'] !== 'wireguard' || $bot->managedNodes()['aabbccdd']['job'] !== null) throw new RuntimeException('FAIL WireGuard main route not confirmed');
$count++;
$method = new ReflectionMethod(Bot::class, 'exitProbeCommand');
$cmd = $method->invoke($bot, $bot->exitNodes()['aabbccdd'], 10875, false, 'aabbccdd');
if (str_contains($cmd, 'nc -z') || !str_contains($cmd, '--socks5-hostname')) throw new RuntimeException('FAIL WireGuard diagnosis must test tunnel traffic');
$count++;
$bot->events = [];
if ($bot->managedNodeUseProfile('aabbccdd', $profile) !== '' || !in_array('core', $bot->events)) {
    throw new RuntimeException('FAIL unchanged WireGuard profile must renew client session after remote restore');
}
$count++;
$bot->remoteJob = ['state' => 'done', 'result' => ['restarted' => true]];
$bot->pacState['managed_nodes']['aabbccdd']['job'] = ['id' => str_repeat('d',32), 'before' => ['link' => $profile['link'], 'managed_profile' => $profile], 'phase' => 'waiting', 'started' => time()];
$bot->events = [];
$bot->managedNodePoll('aabbccdd');
if (!in_array('core', $bot->events) || array_search('core', $bot->events) > array_search('probe', $bot->events)) {
    throw new RuntimeException('FAIL remote WireGuard restart must renew session before probe');
}
$count++;
echo "PASS $count WireGuard main profile checks\n";
