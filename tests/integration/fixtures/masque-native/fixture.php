<?php
require '/src/app/ManagedProtocol.php';
require '/src/tests/managed_protocol_fixture.php';
$root = '/lab';
@mkdir($root, 0700);
function masqueNativeState(ManagedProtocol $store, string $path): void
{
 $state = $store->read();
 $state['config'] = $store->serverConfig($state);
 // Xray finalRules блокируют TEST-NET и 2001:db8 даже после routing ACL.
 // Исключения только для эхо/DNS фикстуры в контейнере --network none.
 foreach ($state['config']['outbounds'] as &$outbound) if ($outbound['tag'] === 'direct') {
  $outbound['settings']['finalRules'] = [
   ['action'=>'allow', 'ip'=>['198.51.100.23/32', '2001:db8::23/128'], 'port'=>'18080,18081'],
   ['action'=>'allow', 'ip'=>['198.51.100.23/32'], 'port'=>53, 'network'=>'udp'],
  ];
 }
 ManagedProtocol::writeJson($path, $state);
}
$s = new ManagedProtocol('masque', $root);
$s->configure(['host'=>'127.0.0.1', 'sni'=>'masque.example.test'], true);
$ids = array_keys($s->read()['users']);
$s->configureOption('noise.enabled',false);
$a=$ids[0] ?? managedProtocolFixtureUser($s,'Native A'); $b=$ids[1] ?? managedProtocolFixtureUser($s,'Native B');
ManagedProtocol::writeJson($root.'/users.json', ['a'=>$a,'b'=>$b]);
masqueNativeState($s, $root.'/desired.json');
foreach (['h3','h2'] as $http) {
 $s->configureOption('client.http',$http);
 ManagedProtocol::writeJson($root.'/client-'.$http.'.json',$s->profile($a,'native'));
}
// XMUX (26.10.17+): три туннеля, срок 60 с — профиль из бота как есть.
$s->configureOption('client.http','h3'); $s->configureOption('client.connections',3); $s->configureOption('client.reuse','60');
ManagedProtocol::writeJson($root.'/client-xmux.json',$s->profile($a,'native'));
$s->configureOption('client.connections',null); $s->configureOption('client.reuse',null);
$s->configureOption('client.http','h3'); $s->configureOption('noise.enabled',true);
$s->configureOption('noise.reset','1');
masqueNativeState($s, $root.'/desired-noise.json');
ManagedProtocol::writeJson($root.'/client-noise.json', $s->profile($a,'native'));
echo "Синтетические данные созданы\n";
