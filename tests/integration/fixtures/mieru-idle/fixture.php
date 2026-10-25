<?php
require $argv[1] . '/app/bot.php';
require $argv[1] . '/tests/managed_protocol_fixture.php';
$store = new ManagedProtocol('mieru', $argv[2] . '/state');
$store->configure(['host' => '127.0.0.1', 'port' => 24445, 'transport' => 'TCP'], true);
$id = managedProtocolFixtureUser($store, 'Idle timeout fixture');
$store->configureOption('server.advancedSettings.tcpIdleTimeout', '1m');
file_put_contents($argv[2] . '/server.json', json_encode($store->read()['config']));
file_put_contents($argv[2] . '/client.json', json_encode($store->profile($id, 'native')));
$snapshot = $store->snapshot();
copy($store->directory() . '/desired.json', $argv[2] . '/initial-state.json');
$store->configureOption('server.advancedSettings.tcpIdleTimeout', null);
copy($store->directory() . '/desired.json', $argv[2] . '/reset-state.json');
$store->restore($snapshot);
// First edit before the supervisor has consumed the pending restore.
$store->configureOption('server.advancedSettings.tcpIdleTimeout', '1m');
copy($store->directory() . '/desired.json', $argv[2] . '/restored-state.json');
