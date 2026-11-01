<?php
require __DIR__ . '/managed_nodes_test.php';
$failed = 0;
$check = static function (bool $ok, string $name) use (&$failed) { echo ($ok ? 'PASS ' : 'FAIL ').$name.PHP_EOL; $failed += !$ok; };
$bot = new ManagedFixtureBot();
$bot->pacState['exits']['aabbccdd']['routes'] = ['geosite:youtube' => 1, 'geoip:ru' => 1,
    'ext:services.dat:video' => 1, 'extip:networks.dat:ru' => 1, 'ext:disabled.dat:video' => 0];
$files = $bot->coreDatNeeded($bot->pacState); sort($files);
$check($files === ['geoip.dat', 'geosite.dat'], 'node-only built-in DAT sources are refreshed');
$check($bot->datSourcesPresent($bot->pacState), 'node-only DAT schedule is active');
$check($bot->datRefCount($bot->pacState, 'services.dat') === 1, 'domain DAT node references counted');
$check($bot->datRefCount($bot->pacState, 'networks.dat') === 1, 'IP DAT node references counted');
$check($bot->datRefCount($bot->pacState, 'disabled.dat') === 0, 'disabled DAT route not counted');
$check(method_exists($bot, 'exitDatMenu'), 'node DAT menu available');
class DatNodeFixture extends ManagedFixtureBot
{
    public array $categories = ['services.dat' => ['video', 'ads'], 'networks.dat' => ['ru'], 'geosite.dat' => ['youtube'], 'geoip.dat' => ['ru']];
    public function datDownloadedFiles(): array { $files = []; foreach ($this->categories as $file => $_) $files[$file] = $this->datFileKey($file); return $files; }
    public function datCategories(string $file): ?array { return $this->categories[$file] ?? null; }
    public function datFileReady(string $value): bool { return isset($this->categories[explode(':', $value)[0]]); }
}
if (method_exists($bot, 'exitDatMenu')) {
    foreach (['ru', 'en'] as $language) {
        $bot = new DatNodeFixture(); $bot->language = $language;
        $id = 'aabbccdd'; $key = $bot->datFileKey('services.dat'); $cat = Bot::exitEntryKey('video');
        $bot->exitSetsMenu($id); $bot->exitDatMenu($id); $bot->exitDatCats($id, $key, 'd', 99999);
        $bot->exitDatToggle($id, $key, 'd', 0, $cat);
        $check(!empty($bot->pacState['exits'][$id]['routes']['ext:services.dat:video']), "$language domain category enabled");
        $bot->exitDatToggle($id, $key, 'd', 0, $cat);
        $check(empty($bot->pacState['exits'][$id]['routes']['ext:services.dat:video']), "$language domain category disabled");
        $bot->exitDatToggle($id, $key, 'd', 0, $cat);
        $check(!empty($bot->pacState['exits'][$id]['routes']['ext:services.dat:video']), "$language domain category re-enabled");
        $bot->exitDatToggle($id, $bot->datFileKey('networks.dat'), 'i', 0, Bot::exitEntryKey('ru'));
        $check(!empty($bot->pacState['exits'][$id]['routes']['extip:networks.dat:ru']), "$language IP category enabled");
        $bot->exitDatToggle($id, $bot->datFileKey('geosite.dat'), 'd', 0, Bot::exitEntryKey('youtube'));
        $bot->exitDatToggle($id, $bot->datFileKey('geoip.dat'), 'i', 0, Bot::exitEntryKey('ru'));
        $check(!empty($bot->pacState['exits'][$id]['routes']['geosite:youtube']) && !empty($bot->pacState['exits'][$id]['routes']['geoip:ru']), "$language built-in categories enabled");
        $before = $bot->pacState;
        $bot->exitDatToggle($id, $bot->datFileKey('geosite.dat'), 'i', 0, Bot::exitEntryKey('youtube'));
        $bot->exitDatToggle($id, 'k000000000000', 'd', 0, $cat);
        $bot->exitDatToggle($id, $key, 'd', 0, Bot::exitEntryKey('removed'));
        $check($before === $bot->pacState, "$language stale and mismatched callbacks cannot change routes");
        $bot->corePass = false;
        $bot->exitDatToggle($id, $key, 'd', 0, Bot::exitEntryKey('ads'));
        $check($before === $bot->pacState, "$language rejected core configuration restores routes");
        $bot->categories['services.dat'] = array_map(static fn($i) => 'category-'.$i, range(1, 50));
        $bot->exitDatCats($id, $key, 'd', 1);
        $check(count(end($bot->screens)[1]) <= Bot::EXIT_PAGE + 2, "$language category pages are bounded");
        $valid = true;
        foreach ($bot->screens as [$text, $rows]) foreach ($rows as $row) foreach ($row as $button) $valid = $valid && strlen($button['callback_data']) <= 64;
        $check($valid, "$language callbacks fit Telegram limit");
        $bot = new DatNodeFixture();
        $bot->pacState['exits'][$id]['routes'] = ['ext:services.dat:VIDEO' => 1];
        $bot->exitDatCats($id, $key, 'd');
        $shown = false;
        foreach (end($bot->screens)[1] as $row) foreach ($row as $button) if (($button['text'] ?? '') === '✅ video') $shown = true;
        $check($shown, "$language existing equivalent route shown as enabled");
        $bot->exitDatToggle($id, $key, 'd', 0, $cat);
        $check(empty($bot->pacState['exits'][$id]['routes']['ext:services.dat:VIDEO']), "$language existing equivalent route can be disabled");
    }
}
exit($failed ? 1 : 0);
