<?php
// WARP has its own settings screen, not IPv4 / IPv6; the node DNS filter is gone.
ob_start(); require __DIR__.'/managed_node_vpn_sources_menu_test.php'; ob_end_clean();

$checks = 0;
$check = static function (bool $ok, string $name) use (&$checks): void { $checks++; if (!$ok) throw new RuntimeException('FAIL '.$name); };
$id = 'aabbccdd';
foreach (['ru', 'en'] as $lang) foreach ([true, false] as $supported) {
    $bot = new VpnSourcesMenuFixture();
    $bot->language = $lang;
    $bot->pacState['managed_nodes'][$id]['status']['warp_egress'] = $supported;
    $bot->click("/nodeSettings $id");
    $root = $bot->callbacks();
    $check(in_array("/nodeSettings $id warp", $root, true) === $supported, "warp screen visibility $lang");
    $check(!in_array("/nodeSettings $id adguard", $root, true), "no DNS filter group $lang");
    $bot->click("/nodeSettings $id network");
    $network = $bot->callbacks();
    $check(!in_array("/nodeField $id adguard.enabled", $network, true) && !in_array("/nodeField $id warp_mode", $network, true), "network has no DNS filter or WARP $lang");
    // The WARP group opens the WARP screen, which returns to the settings hub.
    $bot->click("/nodeSettings $id warp");
    $check(in_array("/nwMode $id wireguard", $bot->callbacks(), true) === $supported, "WARP screen $lang");
}
echo "PASS $checks node settings group checks\n";
