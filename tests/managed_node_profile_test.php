<?php
require_once __DIR__ . '/../app/ManagedNodeProfile.php';
$checks = 0;
function nodeProfileCheck(bool $ok, string $name): void {
    global $checks;
    $checks++;
    if (!$ok) throw new RuntimeException('FAIL '.$name);
}
function nodeProfileReject(array $profile, string $name, string $core = 'fork'): void {
    try { ManagedNodeProfile::parse($profile, $core); }
    catch (InvalidArgumentException $e) { nodeProfileCheck(true, $name); return; }
    throw new RuntimeException('FAIL '.$name);
}
$uuid = '11111111-1111-4111-8111-111111111111';
$base = ['link' => "vless://$uuid@1.1.1.1:443?security=tls&type=ws&path=%2Fnode&sni=node.example.test&fp=firefox",
    'outbound' => ['protocol' => 'vless', 'settings' => [], 'streamSettings' => []]];
$out = ManagedNodeProfile::parse($base, 'origin')['managed_outbound'];
nodeProfileCheck($out['streamSettings']['tlsSettings']['fingerprint'] === 'firefox', 'link identity reused');
nodeProfileCheck($out['streamSettings']['sockopt']['tcpMptcp'] === false, 'MPTCP remains disabled');
$wrong = $base;
$wrong['outbound']['settings'] = ['address' => '127.0.0.1', 'port' => 22];
$wrong['outbound']['streamSettings']['tlsSettings'] = ['allowInsecure' => true];
$out = ManagedNodeProfile::parse($wrong, 'origin')['managed_outbound'];
nodeProfileCheck($out['settings']['vnext'][0]['address'] === '1.1.1.1' && !isset($out['streamSettings']['tlsSettings']['allowInsecure']), 'raw target and insecure flags ignored');
$smux = ['enabled' => true, 'protocol' => 'smux', 'maxConnections' => 3, 'minStreams' => 4, 'maxStreams' => 0,
    'padding' => true, 'onlyTcp' => false, 'logicalHalfClose' => 'require'];
$profile = $base;
$profile['outbound']['smux'] = $smux;
nodeProfileCheck(ManagedNodeProfile::parse($profile, 'fork')['managed_outbound']['smux'] === $smux, 'fork SMUX retained');
nodeProfileReject($profile, 'SMUX original core rejected', 'origin');
$wrong = $profile; $wrong['outbound']['smux']['protocol'] = 'h2mux';
nodeProfileReject($wrong, 'h2mux halfclose rejected');
$wrong = $profile; $wrong['outbound']['smux']['maxStreams'] = 4;
nodeProfileReject($wrong, 'SMUX conflicting limits rejected');
$mask = ['tcp' => [['type' => 'fragment', 'settings' => ['packets' => 'tlshello', 'length' => '100-200', 'delay' => '10-20']]],
    'udp' => [['type' => 'noise', 'settings' => ['reset' => '5-10', 'noise' => [
        ['type' => 'exp', 'packet' => '<b 0102><r 10-20>', 'delay' => '1-2']]]]]];
$profile = $base; $profile['outbound']['streamSettings']['finalmask'] = $mask;
nodeProfileCheck(ManagedNodeProfile::parse($profile, 'origin')['managed_outbound']['streamSettings']['finalmask'] === $mask, 'shared noise expression validation');
$wrong = $profile; $wrong['outbound']['streamSettings']['finalmask']['udp'][0]['settings']['noise'][0]['packet'] = '<r 99999>';
nodeProfileReject($wrong, 'unbounded noise rejected');
$wrong = $base; $wrong['outbound']['streamSettings']['sockopt'] = ['dialerProxy' => 'direct'];
nodeProfileReject($wrong, 'arbitrary dialer rejected');
$wrong = $base; $wrong['outbound']['proxySettings'] = ['tag' => 'direct'];
nodeProfileReject($wrong, 'arbitrary outbound chaining rejected');
echo "PASS $checks managed node profile checks\n";
