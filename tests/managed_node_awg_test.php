<?php
require __DIR__ . '/managed_nodes_test.php';
$bot = new ManagedFixtureBot();
$profile = $bot->profile;
$profile['channel'] = 'amnezia';
$profile['amnezia'] = ['endpoint'=>'1.1.1.1', 'port'=>51821, 'private'=>base64_encode(str_repeat('p',32)),
    'public'=>base64_encode(str_repeat('q',32)), 'psk'=>base64_encode(str_repeat('r',32)), 'mtu'=>1280,
    'parameters'=>['Jc'=>4,'Jmin'=>64,'Jmax'=>1024,'S1'=>12,'S2'=>13,'S3'=>14,'S4'=>15,
        'H1'=>'100-200','H2'=>'300-400','H3'=>'500-600','H4'=>'700-800',
        'HeaderProtectionKey'=>base64_encode(str_repeat('h',32)), 'ContentPaddingAddition'=>'10-40',
        'RekeyAfterTime'=>'110-130','RekeyTimeout'=>'5-10','RejectAfterTime'=>'170-190',
        'KeepaliveTimeout'=>'10-15','MaxHandshakeAttempts'=>'15-25']];
$count = 0;
foreach (['origin','origin2','origin3','fork'] as $core) {
    $parsed = ManagedNodeProfile::parse($profile, $core);
    if ($parsed['managed_outbound']['protocol'] !== 'vless' || $parsed['managed_amnezia'] !== $profile['amnezia']) throw new RuntimeException('FAIL carrier retains VLESS');
    $count++;
}
foreach (['endpoint','key','port','mtu','header','padding','injection','extra'] as $field) {
    $bad = $profile;
    if ($field === 'endpoint') $bad['amnezia']['endpoint'] = '127.0.0.1';
    if ($field === 'key') $bad['amnezia']['private'] = base64_encode(str_repeat("\0",32));
    if ($field === 'port') $bad['amnezia']['port'] = 22;
    if ($field === 'mtu') $bad['amnezia']['mtu'] = true;
    if ($field === 'header') $bad['amnezia']['parameters']['H2'] = '100-200';
    if ($field === 'padding') $bad['amnezia']['parameters']['S1'] = 11;
    if ($field === 'injection') $bad['amnezia']['parameters']['H1'] = "100-200\nPostUp = id";
    if ($field === 'extra') $bad['amnezia']['PostUp'] = 'id';
    try { ManagedNodeProfile::parse($bad, 'origin'); throw new RuntimeException('FAIL unsafe carrier profile accepted'); }
    catch (InvalidArgumentException $e) { $count++; }
}
$bot->profile = $profile;
$bot->managedNodePoll('aabbccdd');
$c = $bot->getXray();
$bot->ensureExitNodes($c);
$out = array_values(array_filter($c['outbounds'], fn($o)=>($o['tag']??'')==='exit-aabbccdd'));
if (count($c['_vpnbot_amnezia']??[]) !== 1) throw new RuntimeException('FAIL carrier metadata missing');
$out = array_values(array_filter($c['outbounds'], fn($o)=>isset($o['settings']['vnext'][0]) && $o['settings']['vnext'][0]['address']==='127.0.0.1'));
if (count($out)!==1 || $out[0]['settings']['vnext'][0]['port']!==10920) throw new RuntimeException('FAIL carrier target is not fixed loopback');
$count++;
$before=$c['_vpnbot_amnezia'][0]['session'];
$bot->managedNodeUseProfile('aabbccdd',$profile);
$bot->ensureExitNodes($c);
if ($c['_vpnbot_amnezia'][0]['session']===$before) throw new RuntimeException('FAIL remote reapply must renew carrier session');
$count++;
$bot->pacState['exits']['aabbccdd']['enabled']=0;
$bot->ensureExitNodes($c);
if (isset($c['_vpnbot_amnezia'])) throw new RuntimeException('FAIL disabled carrier kept alive');
$count++;
echo "PASS $count Amnezia main profile checks\n";
