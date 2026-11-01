<?php
require __DIR__ . '/managed_nodes_test.php';
class ManagedRouteEditFixture extends ManagedFixtureBot {
    public int $fetches = 0;
    public function exitSubFetch(string $url): array { $this->fetches++; return ['link' => str_replace('1.1.1.1', '8.8.8.8', $this->profile['link'])]; }
    public function getXrayStats() { return []; }
}
$checks = 0;
$check = static function ($ok, $name) use (&$checks) { $checks++; if (!$ok) throw new RuntimeException('FAIL '.$name); };
foreach (['ru','en'] as $lang) {
    $bot = new ManagedRouteEditFixture(); $bot->language = $lang;
    $bot->pacState['managed_nodes']['aabbccdd']['job'] = null;
    $bot->managedNodeUseProfile('aabbccdd', $bot->profile);
    $before = $bot->exitNodes()['aabbccdd'];
    $bot->saveExitLink(str_replace('1.1.1.1', '8.8.8.8', $bot->profile['link']), 'aabbccdd');
    $check($bot->exitNodes()['aabbccdd'] === $before, 'manual link cannot disagree with SSH-managed profile');
    $bot->saveExitSub('https://example.com/node', 'aabbccdd');
    $check($bot->fetches === 0 && $bot->exitNodes()['aabbccdd'] === $before, 'managed route cannot adopt external subscription');
    $bot->pacState['exits']['aabbccdd']['sub'] = 'https://example.com/node';
    $check(!$bot->exitSubRefresh('aabbccdd') && $bot->fetches === 0, 'cron ignores stale subscription on managed route');
    $bot->exitSettingsMenu('aabbccdd');
    $buttons = array_merge(...array_map(fn($row) => array_column($row, 'callback_data'), end($bot->screens)[1]));
    $check(!in_array('/exitLink aabbccdd', $buttons) && !in_array('/exitSub aabbccdd', $buttons), 'managed route shows only applicable settings');
    unset($bot->pacState['managed_nodes']['aabbccdd'], $bot->pacState['exits']['aabbccdd']['managed_profile']);
    $bot->saveExitLink(str_replace('1.1.1.1', '8.8.8.8', $bot->profile['link']), 'aabbccdd');
    $check(str_contains($bot->exitNodes()['aabbccdd']['link'], '8.8.8.8'), 'ordinary external route still accepts manual replacement');
}
echo "PASS $checks managed route ownership checks\n";
