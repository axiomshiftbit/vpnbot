<?php
require __DIR__.'/managed_node_awg_test.php';
foreach (['1.5','2.0','3.0','3.1'] as $version) {
    $p=$profile; $p['amnezia']['version']=$version; $p['amnezia']['slot']=1;
    $p['amnezia']['keepalive']=str_starts_with($version,'3.')?'18-24':'25';
    if (!str_starts_with($version,'3.')) {
        foreach (['HeaderProtectionKey','ContentPaddingAddition','RekeyAfterTime','RekeyTimeout','RejectAfterTime','KeepaliveTimeout','MaxHandshakeAttempts'] as $key) unset($p['amnezia']['parameters'][$key]);
    }
    if ($version==='1.5') {
        unset($p['amnezia']['parameters']['S3'],$p['amnezia']['parameters']['S4']);
        foreach (['H1','H2','H3','H4'] as $key) $p['amnezia']['parameters'][$key]=explode('-',$p['amnezia']['parameters'][$key])[0];
    }
    $panel=ManagedNodeProfile::panel($p,'origin','panel');
    [$vless,$awg]=$panel['outbounds'];
    $check($awg['protocol']==='amneziawg' && $awg['tag']==='panel-awg','native panel AWG outbound');
    $check($vless['streamSettings']['sockopt']['dialerProxy']===$awg['tag'],'VLESS uses selected AWG carrier');
    $check($vless['settings']['vnext'][0]['address']==='10.77.78.1' && $vless['settings']['vnext'][0]['port']===443,'carrier reaches only fixed VLESS listener');
    $check($vless['streamSettings']['tlsSettings']['serverName']==='node.example.test','TLS name retained through the carrier');
    $check($awg['settings']['peers'][0]['allowedIPs']===['10.77.78.1/32'],'panel carrier route stays narrow');
    $check($awg['settings']['address']===['10.77.78.3/32'],'external client gets its own tunnel address');
    $check($awg['settings']['disableCookies']===false,'panel cookie defenses stay enabled');
    $check($awg['settings']['randomTrailers']===false,'broad headers do not enable lossy trailers');
    $check(isset($awg['settings']['headerProtectionKey'])===str_starts_with($version,'3.'),'only compatible header protection exported');
}
foreach ([-1,33,true,'1'] as $slot) {
    $p=$profile;$p['amnezia']['slot']=$slot;$rejected=false;
    try {ManagedNodeProfile::panel($p,'origin','panel');} catch(InvalidArgumentException $e){$rejected=true;}
    $check($rejected,'unsafe external slot rejected');
}
echo "PASS separate panel carrier profiles and protocol versions\n";
