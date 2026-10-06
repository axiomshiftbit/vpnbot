<?php
umask(0077);
require '/app/config.php'; require '/app/bot.php'; require '/app/i18n.php';
require '/tmp/managed_protocol_fixture.php';
$warnings = [];
set_error_handler(function ($l, $m) use (&$warnings) { if (error_reporting() & $l) $warnings[] = $l; return true; });
$b = new Bot($c['key'], $i); $b->admin = true; $b->language = 'ru';
$m = $b->protocolStore($argv[1]); $action = $argv[2];
if ($action === 'prepare') {
    $id = managedProtocolFixtureUser($m, 'WARP native matrix');
    $settings = ['egress' => 'warp'];
    if ($argv[1] === 'mieru') $settings['transport'] = $argv[3];
    if ($argv[1] === 'shadowtls') $settings['udp_over_tcp'] = true;
    $m->configure($settings, true);
    $source = ['anytls'=>'10.10.0.22','mieru'=>'10.10.0.23','tuic'=>'10.10.0.24','shadowtls'=>'10.10.0.25','masque'=>'10.10.0.27'][$argv[1]];
    if (!str_contains($b->ssh(Bot::warpSocksAllowCmd($source, true), 'wp'), Bot::SS_ACL_PRESENT)) throw new RuntimeException('WARP ACL not applied');
    $result = ['id' => $id];
} elseif ($action === 'transport') { $m->configure(['transport' => $argv[3]]); $result = ['changed' => true];
} elseif ($action === 'udp' && $argv[1] === 'shadowtls') { $m->configure(['udp_over_tcp' => $argv[3] === 'on']); $result = ['changed' => true];
} elseif ($action === 'profile') $result = $m->profile($argv[3], $argv[4]);
else throw new RuntimeException('unknown action');
if ($warnings) exit(91);
echo json_encode($result, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
