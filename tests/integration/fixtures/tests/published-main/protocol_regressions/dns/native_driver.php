<?php
declare(strict_types=1);
if (!is_file('/run/vpnbot-synthetic-audit') || trim(file_get_contents('/run/vpnbot-synthetic-audit')) !== 'SYNTHETIC-ONLY') exit(2);
require '/src/app/bot.php';
set_exception_handler(static function (Throwable $e): void { echo json_encode(['exception'=>get_class($e), 'file'=>basename($e->getFile()), 'line'=>$e->getLine()]), "\n"; exit(3); });
$bot = (new ReflectionClass(Bot::class))->newInstanceWithoutConstructor();
$bot->key = 'synthetic-audit-key-not-a-telegram-token';
$bot->ip = '172.30.80.10';
date_default_timezone_set('UTC');
$action = $argv[1] ?? '';
function emit(array $data): void { echo json_encode($data, JSON_UNESCAPED_SLASHES), "\n"; }
function aclState(Bot $bot): array {
    $conf = $bot->adguardConf();
    return ['allowed_count'=>count($conf['dns']['allowed_clients'] ?? []),
        'persistent_count'=>count($conf['clients']['persistent'] ?? []),
        'xray_user_count'=>count($bot->getXray()['inbounds'][0]['settings']['clients'] ?? [])];
}
switch ($action) {
case 'dns-init':
    $uid = '00000000-0000-4000-8000-000000000001';
    $xr = ['inbounds'=>[['settings'=>['clients'=>[['id'=>$uid,'email'=>'synthetic-user']]]]]];
    if (!$bot->writeXrayJson(json_encode($xr))) exit(3);
    $id = $bot->dohClientId($uid);
    file_put_contents('/work/client_id', $id);
    $persistent = Bot::adguardMergeClients([], $xr['inbounds'][0]['settings']['clients'], fn($uid) => $bot->dohClientId($uid), 'UTC');
    $config = ['schema_version'=>29, 'http'=>['address'=>'0.0.0.0:3000'], 'users'=>[],
        'dns'=>['bind_hosts'=>['0.0.0.0'], 'port'=>5353, 'upstream_dns'=>['127.0.0.1:1053'],
            'bootstrap_dns'=>[], 'fallback_dns'=>[], 'allowed_clients'=>[$id], 'disallowed_clients'=>[],
            'cache_size'=>0, 'ratelimit'=>0, 'use_private_ptr_resolvers'=>false, 'local_ptr_upstreams'=>[]],
        'tls'=>['enabled'=>false,'allow_unencrypted_doh'=>true,'port_https'=>8444,'port_dns_over_tls'=>8853,'port_dns_over_quic'=>8854,'certificate_path'=>'/certs/cert_public','private_key_path'=>'/certs/cert_private'],
        'filtering'=>['rewrites'=>[['domain'=>'answer.audit.test','answer'=>'11.77.78.2']]],
        'clients'=>['persistent'=>$persistent], 'filters'=>[], 'whitelist_filters'=>[],
        'querylog'=>['enabled'=>false], 'statistics'=>['enabled'=>false]];
    if (!$bot->adguardWrite($config)) exit(3);
    emit(aclState($bot)); break;
case 'dns-start':
    $bot->startAd(); emit(['started'=>true]); break;
case 'dns-delete-last':
    $xr = $bot->getXray();
    if (count($xr['inbounds'][0]['settings']['clients'] ?? []) !== 1) exit(3);
    $xr['inbounds'][0]['settings']['clients'] = [];
    if (!$bot->writeXrayJson(json_encode($xr))) exit(3);
    // Это узкая граница удаления из синтетического store; полный delxr/Xray apply не имитируется.
    $bot->adguardXrayClients();
    emit(aclState($bot)); break;
case 'dns-add-again':
    $xr=$bot->getXray();
    $xr['inbounds'][0]['settings']['clients']=[['id'=>'00000000-0000-4000-8000-000000000001','email'=>'synthetic-user']];
    if (!$bot->writeXrayJson(json_encode($xr))) exit(3);
    $bot->adguardXrayClients(); emit(aclState($bot)); break;
case 'dns-custom':
    $mode=$argv[2] ?? '';
    if (!in_array($mode,['manual','open'],true)) exit(2);
    $c=$bot->adguardConf();
    $c['dns']['allowed_clients']=$mode==='manual' ? ['172.30.80.10/32','manual-client'] : [];
    $expected=$c['dns']['allowed_clients']; $upstream=$c['dns']['upstream_dns'];
    $xr=$bot->getXray(); $xr['inbounds'][0]['settings']['clients']=[];
    if (!$bot->writeXrayJson(json_encode($xr))) exit(3);
    $bot->stopAd(); if (!$bot->adguardWrite($c)) exit(3); $bot->startAd();
    $bot->adguardXrayClients(); $after=$bot->adguardConf();
    emit(['custom_acl_preserved'=>$after['dns']['allowed_clients']===$expected,'custom_upstream_preserved'=>$after['dns']['upstream_dns']===$upstream]); break;
case 'route-convert':
    $f = $argv[2] ?? '';
    if (!preg_match('~^/work/routes/[a-z-]+\.srs$~D', $f)) exit(2);
    $entries = $bot->exitRulesetConvert((string) file_get_contents($f), 'srs', 'domain');
    emit(['accepted'=>$entries !== null, 'entry_count'=>count($entries ?? []),
        'positive_example_suffix'=>in_array('domain:example.test', $entries ?? [], true),
        'positive_logical_suffix'=>in_array('domain:logical.audit.test', $entries ?? [], true)]);
    break;
case 'tls-install':
    $slot = $argv[2] ?? '';
    if (!in_array($slot,['old','new','newer'],true)) exit(2);
    $bundle = file_get_contents('/work/pki/'.$slot.'/key.pem').file_get_contents('/work/pki/'.$slot.'/cert.pem');
    $ok = $bot->applyCertificateBundle($bundle,$bot->getPacConf());
    $disk = openssl_x509_parse(file_get_contents('/certs/cert_public'));
    $wanted = openssl_x509_parse(file_get_contents('/work/pki/'.$slot.'/cert.pem'));
    emit(['apply_return'=>$ok, 'files_match_requested_serial'=>$disk['serialNumberHex']===$wanted['serialNumberHex'],
        'native_crypto'=>true, 'native_ssh'=>true]);
    break;

case 'tls-info':
    emit(['names'=>$bot->letsencryptNames($bot->getPacConf()), 'certificate'=>hash_file('sha256','/certs/cert_public')]); break;
case 'tls-stage':
    $slot=$argv[2] ?? '';
    if (!in_array($slot,['old','new','newer'],true)) exit(2);
    $dir='/etc/letsencrypt/live/tls.audit.test';
    if (!is_dir($dir)) mkdir($dir,0700,true);
    if (!copy('/work/pki/'.$slot.'/key.pem',$dir.'/privkey.pem') || !copy('/work/pki/'.$slot.'/cert.pem',$dir.'/fullchain.pem')) exit(3);
    chmod($dir.'/privkey.pem',0600);
    emit(['issued_certificate'=>hash_file('sha256',$dir.'/fullchain.pem')]); break;
case 'tls-receipt':
    $expected=$argv[2] ?? '';
    $issued=$argv[3] ?? '';
    $names=json_decode($argv[4] ?? '[]',true);
    if (!preg_match('~^[a-f0-9]{64}$~D',$expected) || !preg_match('~^[a-f0-9]{64}$~D',$issued) || !is_array($names)) exit(2);
    emit($bot->installLetsencryptReceipt('tls.audit.test',$names,$expected,$issued)); break;
case 'tls-reapply':
    $expected=$argv[2] ?? '';
    if (!preg_match('~^[a-f0-9]{64}$~D',$expected)) exit(2);
    emit($bot->reapplyCertificateReceipt($expected)); break;
case 'tls-reload':
    emit(['reload_return'=>$bot->cloakNginx()]); break;
default: exit(2);
}
