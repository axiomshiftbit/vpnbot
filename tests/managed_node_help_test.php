<?php
require __DIR__ . '/managed_nodes_test.php';
$checks = 0;
$check = static function ($ok, $name) use (&$checks) { $checks++; if (!$ok) throw new RuntimeException('FAIL '.$name); };
foreach (['ru', 'en'] as $lang) {
    $bot = new ManagedFixtureBot(); $bot->language = $lang;
    $bot->screens = [];
    for ($page = 0; $page <= 6; $page++) $bot->menuHelp('managednodes', $page, 'aabbccdd');
    $check(count($bot->screens) === 7, 'all managed help pages rendered');
    $body = '';
    foreach ($bot->screens as [$text, $rows]) {
        $body .= $text;
        $check(mb_strlen($text) < 4096, 'help fits Telegram message');
        foreach ($rows as $row) foreach ($row as $button) $check(strlen($button['callback_data']) <= 64, 'help callback fits Telegram');
    }
    foreach (['.dat', '.srs', '.mrs', 'AmneziaWG', 'AdGuard', 'SSH', 'SMUX', 'GeoIP', 'GeoSite'] as $term) {
        $check(str_contains($body, $term), 'help covers '.$term);
    }
    $before = count($bot->screens);
    $bot->menuHelp('managednodes', 0, '../invalid');
    $check(count($bot->screens) === $before, 'invalid help context rejected');
}
echo "PASS $checks managed node help checks\n";
