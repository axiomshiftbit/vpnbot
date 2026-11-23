<?php
require __DIR__ . '/managed_nodes_test.php';

// Shared Block and WARP lists of a managed node.
class RoutesFixtureBot extends ManagedFixtureBot
{
    public array $submitted = []; public array $files = []; public array $refreshed = []; public array $sets = []; public array $dat = [];
    protected function managedNodeRpc(string $id, array $request): array {
        if ($request['action'] === 'submit') $this->submitted[] = $request['request'];
        return parent::managedNodeRpc($id, $request);
    }
    public function exitRulesetCache(string $key): array { return isset($this->sets[$key]) ? ['key' => $key, 'time' => time(), 'entries' => $this->sets[$key]] : []; }
    public function exitRulesetRefresh(string $url, array $set): string { $this->refreshed[] = $url; return 'download'; }
    protected function nodePolicyDat(array $entry): array { return $this->dat[$entry['value'] ?? ''] ?? throw new RuntimeException('no dat'); }
    public function sendFile($chat, $file, $caption = false, $to = false) { $this->files[] = $file; return ['ok' => true]; }
    public function compactNodePoliciesForTest(array $pac): array { return self::compactNodePolicies($pac); }
    // The controller core judges patterns; PCRE stands in for it here.
    public function exitRulesetCoreAccepts(array $entries): bool { foreach ($entries as $e) if (str_starts_with($e, 'regexp:') && @preg_match('~' . substr($e, 7) . '~', '') === false) return false; return true; }
    protected function nodeRoutesProbeAddresses(string $host): array { return ['198.51.100.200']; }
}
$id = 'aabbccdd';
$check = static function ($ok, $text) { if (!$ok) throw new RuntimeException('FAIL ' . $text); };
$bot = new RoutesFixtureBot();
$node = &$bot->pacState['managed_nodes'][$id];
$node['job'] = null;
$node['status']['shared_routes'] = true;
unset($node);
$cb = static fn(RoutesFixtureBot $b) => array_column(array_merge(...end($b->screens)[1]), 'callback_data');

// Card buttons and an empty list.
$bot->managedNodeMenu($id);
$check(in_array("/nlist $id block 0", $cb($bot), true) && in_array("/nlist $id warp 0", $cb($bot), true), 'card opens both lists');
$check(!preg_grep('~^/(np|nad|nodeAd)~', $cb($bot)), 'card has no removed node menus');
$bot->nodeRoutesMenu($id, 'block');
$check(!in_array("/nlApply $id block", $cb($bot), true), 'nothing to apply for an untouched list');

// Main-bot CSV export, route export lines and sets in one import.
$bot->saveNodeRoutes("full:ads.example;1\ndomain:off.example;0\n203.0.113.0/24\n# off: keyword:tracker\nset: https://lists.example/block.srs\nfull:bad..example;1", $id, 'block');
$lists = $bot->pacState['managed_nodes'][$id]['lists'];
$check($lists['block']['routes'] === ['full:ads.example' => 1, 'domain:off.example' => 0, '203.0.113.0/24' => 1, 'keyword:tracker' => 0],
    'CSV and route lines keep their state');
$check(($lists['block']['rulesets']['https://lists.example/block.srs']['on'] ?? 0) === 1 && $lists['warp']['routes'] === [], 'set imported into its list only');
$check(str_contains(end($bot->screens)[0], 'пропущено'), 'invalid line reported');
$bot->saveNodeRoutes("full:ads.example\nfull:ADS.example", $id, 'block');
$check(count($bot->pacState['managed_nodes'][$id]['lists']['block']['routes']) === 4, 'duplicates skipped');
$check(in_array("/nlApply $id block", $cb($bot), true), 'edited list offers apply');

// Toggle and delete by key; a stale key changes nothing.
$key = Bot::exitEntryKey('domain:off.example');
$bot->nodeRoutesToggle($id, 'block', $key, 'E', 0);
$check($bot->pacState['managed_nodes'][$id]['lists']['block']['routes']['domain:off.example'] === 1, 'toggle on');
$bot->nodeRoutesToggle($id, 'block', $key, 'D', 0);
$bot->nodeRoutesToggle($id, 'block', $key, 'D', 0);
$check(!isset($bot->pacState['managed_nodes'][$id]['lists']['block']['routes']['domain:off.example']), 'delete and stale delete');

// Export is importable back, including into the other list.
$bot->nodeRoutesExport($id, 'block');
$file = end($bot->files);
$check($file instanceof CURLStringFile && str_contains($file->data, '# off: keyword:tracker') && str_contains($file->data, 'set: '), 'export file');
$copy = new RoutesFixtureBot();
$copy->pacState['managed_nodes'][$id]['status']['shared_routes'] = true;
$copy->saveNodeRoutes($file->data, $id, 'warp');
$check($copy->pacState['managed_nodes'][$id]['lists']['warp']['routes'] === array_diff_key($bot->pacState['managed_nodes'][$id]['lists']['block']['routes'], [])
    && isset($copy->pacState['managed_nodes'][$id]['lists']['warp']['rulesets']['https://lists.example/block.srs']), 'export round trip');

// Apply: enabled entries, a cached set and dat categories are expanded for the node.
$bot->saveNodeRoutes("geosite:media\n198.51.100.7", $id, 'warp');
$bot->sets['https://lists.example/block.srs'] = ['domain:set.example', '192.0.2.0/24'];
$bot->dat['media'] = ['domain:media.example'];
$bot->nodeRoutesApply($id, 'block');
$routes = end($bot->submitted)['value']['policy']['routes'] ?? [];
$check(end($bot->submitted)['operation'] === 'configure' && end($bot->submitted)['generation'] === $bot->remoteStatus['generation'], 'apply submits a configure job');
sort($routes['block']['domain']);
$check($routes['block']['domain'] === ['domain:set.example', 'full:ads.example'], 'block domains with the set');
$check($routes['block']['ip'] === ['203.0.113.0/24', '192.0.2.0/24'] && !str_contains(json_encode($routes), 'tracker'), 'disabled entries stay home');
ksort($routes['warp']);
$check($routes['warp'] === ['domain' => ['domain:media.example'], 'ip' => ['198.51.100.7']], 'warp list and dat expansion');
$saved = $bot->pacState['managed_nodes'][$id]['job']['lists_sent'] ?? '';
$check($saved === hash('sha256', json_encode($bot->pacState['managed_nodes'][$id]['lists'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)), 'job remembers the sent lists');
$bot->pacState['managed_nodes'][$id]['job'] = null;
$bot->nodeRoutesMenu($id, 'block');
$check(in_array("/nlApply $id block", $cb($bot), true), 'lists stay pending until confirmation');

// An unavailable set must not become a smaller list.
$broken = new RoutesFixtureBot();
$broken->pacState['managed_nodes'][$id]['job'] = null;
$broken->pacState['managed_nodes'][$id]['status']['shared_routes'] = true;
$broken->saveNodeRoutes("full:a.example\nset: https://lists.example/missing.srs", $id, 'block');
$broken->nodeRoutesApply($id, 'block');
$check(!$broken->submitted && $broken->refreshed === ['https://lists.example/missing.srs'] && str_contains(end($broken->screens)[0], 'Набор .srs/.mrs недоступен'), 'missing set is fetched and blocks apply');
$check($bot->refreshed === [], 'a fresh cached set is not downloaded again');

// Older node code: only blocks, in the earlier format; no node policy support at all: no policy.
$old = new RoutesFixtureBot();
$old->pacState['managed_nodes'][$id]['job'] = null;
$old->pacState['managed_nodes'][$id]['status']['named_policy'] = true;
$old->saveNodeRoutes("full:a.example\n10.0.0.0/8", $id, 'block');
$old->saveNodeRoutes("full:w.example", $id, 'warp');
$old->nodeRoutesMenu($id, 'warp');
$check(str_contains(end($old->screens)[0], 'Обновите код ноды'), 'warp list warns about old node code');
$old->nodeRoutesApply($id, 'block');
$policy = end($old->submitted)['value']['policy'];
$check($policy === ['lists' => ['block' => ['domain' => ['full:a.example'], 'ip' => ['10.0.0.0/8']]], 'bindings' => ['all' => [['list' => 'block', 'action' => 'block']]]], 'legacy block policy');
$none = new RoutesFixtureBot();
$none->pacState['managed_nodes'][$id]['job'] = null;
$none->managedNodeSubmit($id, 'configure', $none->remoteStatus['options'] + ['policy' => ['lists' => [], 'bindings' => []]]);
$check(!isset(end($none->submitted)['value']['policy']), 'node without policy support gets no policy');

// Shared blocks from the earlier per-node policy become the Block list.
$migrated = new RoutesFixtureBot();
$migrated->pacState['managed_nodes'][$id]['status']['options']['policy'] = ['lists' => ['ads' => ['domain' => ['full:old.example'], 'ip' => ['10.1.0.0/16']], 'p' => ['domain' => ['full:personal.example']]],
    'bindings' => ['all' => [['list' => 'ads', 'action' => 'block']], 'bot-0123456789abcdef0123' => [['list' => 'p', 'action' => 'warp']]]];
$migrated->nodeRoutesMenu($id, 'block');
$check(str_contains(json_encode(end($migrated->screens)[1], JSON_UNESCAPED_UNICODE), 'full:old.example') && !str_contains(json_encode(end($migrated->screens)), 'personal.example'), 'legacy shared blocks shown');

// Clear asks first.
$bot->nodeRoutesClear($id, 'warp', false);
$check(isset($bot->pacState['managed_nodes'][$id]['lists']['warp']['routes']['198.51.100.7']), 'clear asks first');
$bot->pacState['managed_nodes'][$id]['job'] = null;
$bot->nodeRoutesClear($id, 'warp', true);
$check($bot->pacState['managed_nodes'][$id]['lists']['warp']['routes'] === [], 'clear');
foreach ($bot->screens as [, $rows]) foreach ($rows as $row) foreach ($row as $button) $check(strlen($button['callback_data']) <= 64, 'callback fits Telegram');

// pac.json keeps only a digest of the expanded lists.
$compact = $bot->compactNodePoliciesForTest(['exits' => [$id => ['policy' => ['routes' => ['block' => ['domain' => ['full:x.example']]]]]]]);
$check(!isset($compact['exits'][$id]['policy']['routes']) && preg_match('~^[a-f0-9]{64}$~', $compact['exits'][$id]['policy']['routes_digest']), 'expanded routes compacted');
// Audit fixes. A disabled entry of an older main-bot export ("entry;") stays disabled.
$csv = new RoutesFixtureBot();
$csv->pacState['managed_nodes'][$id]['status']['shared_routes'] = true;
$csv->saveNodeRoutes("full:off.example;\nfull:on.example;1", $id, 'block');
$check($csv->pacState['managed_nodes'][$id]['lists']['block']['routes'] === ['full:off.example' => 0, 'full:on.example' => 1], 'empty CSV flag means disabled');
// A pattern the core rejects never reaches the list; valid ones in the same batch do.
$csv->saveNodeRoutes("regexp:([a-z\nregexp:^cdn[0-9]+\\.example$", $id, 'warp');
$check(array_keys($csv->pacState['managed_nodes'][$id]['lists']['warp']['routes']) === ['regexp:^cdn[0-9]+\\.example$']
    && str_contains(end($csv->screens)[0], 'пропущено'), 'invalid regexp rejected at save');
// Blocking the probe host would roll back every apply: refuse it with a clear reason.
foreach (["domain:gstatic.com", "keyword:gstatic", "regexp:^www\\.gst", "198.51.100.128/25"] as $entry) {
    $probe = new RoutesFixtureBot();
    $probe->pacState['managed_nodes'][$id]['job'] = null;
    $probe->pacState['managed_nodes'][$id]['status']['shared_routes'] = true;
    $probe->saveNodeRoutes($entry, $id, 'block');
    $probe->nodeRoutesApply($id, 'block');
    $check(!$probe->submitted && str_contains(end($probe->screens)[0], 'www.gstatic.com'), "probe host block refused: $entry");
    // The WARP list may carry it: the probe then checks the node WARP.
    $probe->nodeRoutesClear($id, 'block', true);
    $probe->saveNodeRoutes($entry, $id, 'warp');
    $probe->nodeRoutesApply($id, 'warp');
    $check(count($probe->submitted) === 1, "probe host allowed in WARP: $entry");
}
// The settings screen names a list failure instead of SSH.
$draft = new RoutesFixtureBot();
$draft->pacState['managed_nodes'][$id]['job'] = null;
$draft->pacState['managed_nodes'][$id]['status']['shared_routes'] = true;
$draft->saveNodeRoutes("set: https://lists.example/missing.srs", $id, 'warp');
$draft->pacState['managed_nodes'][$id]['draft'] = ['mask' => 'new.example.test'] + $draft->pacState['managed_nodes'][$id]['status']['options'];
$draft->pacState['managed_nodes'][$id]['draft_generation'] = $draft->remoteStatus['generation'];
$draft->managedNodeApply($id);
$check(!$draft->submitted && str_contains(end($draft->screens)[0], 'Набор .srs/.mrs недоступен') && isset($draft->pacState['managed_nodes'][$id]['draft']), 'settings apply names the list failure');
// A restored snapshot is not the controller copy of the lists.
$restored = new RoutesFixtureBot();
$restored->pacState['managed_nodes'][$id]['status']['shared_routes'] = true;
$restored->pacState['managed_nodes'][$id]['lists'] = ['block' => ['routes' => ['full:a.example' => 1], 'rulesets' => []], 'warp' => ['routes' => [], 'rulesets' => []]];
$restored->pacState['managed_nodes'][$id]['lists_sent'] = hash('sha256', json_encode($restored->pacState['managed_nodes'][$id]['lists'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
$restored->pacState['managed_nodes'][$id]['job']['operation'] = 'restore';
$restored->checkManagedNodes();
$restored->nodeRoutesMenu($id, 'block');
$check($restored->pacState['managed_nodes'][$id]['job'] === null && in_array("/nlApply $id block", $cb($restored), true), 'restore marks the lists as not applied');

$legacyPac = ['node_policy_lists' => ['ads' => ['domain' => ['full:old.example']]], 'managed_nodes' => [$id => ['status' => ['options' => ['policy' => [
    'lists' => ['ads' => ['domain' => ['full:old.example']]], 'bindings' => ['all' => [['list' => 'ads', 'action' => 'block']]]]]]]]];
$moved = $bot->compactNodePoliciesForTest($legacyPac);
$check(!isset($moved['node_policy_lists']) && $moved['managed_nodes'][$id]['lists']['block']['routes'] === ['full:old.example' => 1]
    && $moved['managed_nodes'][$id]['lists']['warp'] === ['routes' => [], 'rulesets' => []], 'pac migration keeps shared blocks');
$check($bot->compactNodePoliciesForTest($moved) === $moved, 'pac migration is idempotent');
echo "PASS node Block and WARP lists\n";

$policy = ['revision'=>str_repeat('a',32), 'lists'=>['media'=>['domain'=>['full:media.example']]], 'bindings'=>['all'=>[['list'=>'media','action'=>'block']]]];
// A changed controller list is applied through the normal generation-checked job.
class GuardFixtureBot extends ManagedFixtureBot
{
    public array $submitted = [];
    protected function managedNodeRpc(string $id, array $request): array {
        if ($request['action'] === 'submit') $this->submitted[] = $request['request'];
        return parent::managedNodeRpc($id,$request);
    }
}
$guardBot = new GuardFixtureBot();
$guardBot->remoteStatus['controller_ip_guard'] = true;
$guardBot->remoteStatus['pending'] = null;
$guardBot->pacState['managed_nodes'][$id]['job'] = null;
$guardBot->xrayState['routing']['rules'] = [
    ['ruleTag'=>'vpnbot:routes:block:domain','domain'=>['full:private.example']],
    ['ruleTag'=>'vpnbot:routes:block:ip','ip'=>['11.77.1.0/24']]
];
$guardBot->checkManagedNodes();
$job = $guardBot->submitted[0] ?? [];
$guard = $job['value']['policy'] ?? [];
$check(($job['generation'] ?? '') === $guardBot->remoteStatus['generation']
    && ($guard['controller_ips'] ?? []) === ['11.77.1.0/24'] && !str_contains(json_encode($guard),'private.example'), 'sync copies only active IP entries');
$rev = $guard['revision'];
$guardBot->pacState['managed_nodes'][$id]['job'] = null;
$guardBot->managedNodeSubmit($id,'configure',$job['value']);
$check($guardBot->submitted[1]['value']['policy']['revision'] === $rev, 'unchanged controller list preserves revision');
$guardBot->pacState['managed_nodes'][$id]['job'] = null;
$guardBot->xrayState['routing']['rules'] = [];
$guardBot->managedNodeSubmit($id,'configure',$job['value']);
$check(!isset($guardBot->submitted[2]['value']['policy']), 'cleared controller list removes the empty policy');
echo "PASS controller IP synchronization, revision and removal\n";

foreach ([true, false] as $healthy) {
    $rejoined = new GuardFixtureBot();
    $rejoined->probePass = $healthy;
    $rejoined->pacState['managed_nodes'][$id]['job'] = null;
    $rejoined->pacState['exits'][$id]['policy'] = $guard;
    $rejoined->remoteStatus['controller_ip_guard'] = true;
    $rejoined->remoteStatus['pending'] = null;
    $actual = $guard;
    $actual['revision'] = str_repeat('c',32);
    $rejoined->remoteStatus['options']['policy'] = $actual;
    $rejoined->xrayState['routing']['rules'] = [['ruleTag'=>'vpnbot:routes:block:ip','ip'=>$actual['controller_ips']]];
    $rejoined->checkManagedNodes();
    $check($rejoined->submitted === [] && in_array('probe',$rejoined->events,true)
        && $rejoined->pacState['exits'][$id]['policy'] === ($healthy ? $actual : $guard),
        'reconcile a restored remote revision through a traffic check');
}

foreach ([true,false] as $healthy) {
    $rejoined = new GuardFixtureBot();
    $rejoined->probePass = $healthy;
    $rejoined->pacState['managed_nodes'][$id]['job'] = null;
    $rejoined->pacState['exits'][$id]['policy'] = $policy;
    $rejoined->remoteStatus['controller_ip_guard'] = true;
    $rejoined->remoteStatus['pending'] = null;
    $actual = $policy;
    $actual['revision'] = str_repeat('d',32);
    $rejoined->remoteStatus['options']['policy'] = $actual;
    $rejoined->xrayState['routing']['rules'] = [];
    $rejoined->checkManagedNodes();
    $check($rejoined->submitted === [] && in_array('probe',$rejoined->events,true)
        && $rejoined->pacState['exits'][$id]['policy'] === ($healthy ? $actual : $policy),
        'reconcile named policy without a controller IP list and roll back on failure');
}

echo "PASS reconcile a restored legacy node policy
";
