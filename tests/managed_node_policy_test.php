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
    public array $messages = []; public array $replyState = [];
    public function request($method, $data, $json_header = 0) {
        if ($method !== 'sendMessage') throw new RuntimeException('Unexpected Telegram request');
        $this->messages[] = $data;
        return ['ok' => true, 'result' => ['message_id' => 6]];
    }
    public function stashReply($r, array $state) { $this->replyState = $state; }
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

// Telegram copies the contents of one code span, including the colon needed for input.
foreach (['ru', 'en'] as $lang) {
    $bot->language = $lang;
    foreach (['block', 'warp'] as $kind) {
        $bot->messages = [];
        $bot->nodeRoutesPrompt($id, $kind, false);
        $check(count($bot->messages) === 1, 'one reply prompt per list');
        $message = $bot->messages[0];
        $check($message['parse_mode'] === 'HTML' && json_decode($message['reply_markup'], true)['force_reply'], 'HTML reply prompt');
        preg_match_all('~<code>([^<]+)</code>~', $message['text'], $spans);
        $prefixes = ['domain:', 'full:', 'keyword:', 'regexp:', 'geosite:', 'geoip:', 'ext:', 'extip:', 'set:', 'set: ipcidr'];
        $check(!array_diff($prefixes, $spans[1]), "$lang $kind add prompt has separately copyable prefixes");
        $check($bot->replyState['callback'] === 'saveNodeRoutes' && $bot->replyState['args'] === [$id, $kind], 'reply saves to the selected list');
    }
}
$bot->language = 'ru';

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

// An edit made after submission stays pending when the earlier generation is confirmed.
$race = new RoutesFixtureBot();
$race->pacState['managed_nodes'][$id]['job'] = null;
$race->pacState['managed_nodes'][$id]['status']['shared_routes'] = true;
$race->saveNodeRoutes('full:first.example', $id, 'block');
$race->nodeRoutesApply($id, 'block');
$sent = $race->pacState['managed_nodes'][$id]['job']['lists_sent'];
$race->saveNodeRoutes('full:second.example', $id, 'block');
$race->managedNodePoll($id);
$race->nodeRoutesMenu($id, 'block');
$check($race->pacState['managed_nodes'][$id]['lists_sent'] === $sent && in_array("/nlApply $id block", $cb($race), true), 'confirmation preserves a later edit');

$limits = new RoutesFixtureBot();
$limits->pacState['managed_nodes'][$id]['job'] = null;
$limits->pacState['managed_nodes'][$id]['status']['shared_routes'] = true;
$lines = [];
for ($i = 0; $i <= 2000; $i++) $lines[] = "full:r$i.example";
for ($i = 0; $i <= 20; $i++) $lines[] = "set: https://lists.example/r$i.srs";
$limits->saveNodeRoutes(implode("\n", $lines), $id, 'block');
$list = $limits->pacState['managed_nodes'][$id]['lists']['block'];
$check(count($list['routes']) === 2000 && count($list['rulesets']) === 20, 'source list entry and set count limits');
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
$exitList = ['routes' => [], 'fallback' => 'direct'];
[$accepted, $ignored] = $csv->exitMergeRoutes($exitList, ['regexp:([a-z' => 1, 'domain:kept.example' => 1]);
$check($accepted === 1 && $ignored === 1 && $exitList['routes'] === ['domain:kept.example' => 1], 'exit import validates patterns with the selected core');
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

// IP synchronization must keep the rules of the running generation, even when
// an admin has removed a block or added a WARP entry without pressing Apply.
$sync = new GuardFixtureBot();
$confirmedRoutes = ['block' => ['domain' => ['full:blocked.example']], 'warp' => ['ip' => ['192.0.2.0/24']]];
$sync->remoteStatus['shared_routes'] = $sync->remoteStatus['controller_ip_guard'] = true;
$sync->remoteStatus['pending'] = null;
$sync->remoteStatus['options']['policy'] = ['routes' => $confirmedRoutes];
$sync->pacState['managed_nodes'][$id]['job'] = null;
$sync->pacState['managed_nodes'][$id]['lists'] = ['block' => ['routes'=>[], 'rulesets'=>[]],
    'warp' => ['routes'=>['full:draft.example'=>1], 'rulesets'=>[]]];
$sync->pacState['managed_nodes'][$id]['lists_sent'] = str_repeat('a', 64);
$sync->xrayState['routing']['rules'] = [['ruleTag'=>'vpnbot:routes:block:ip', 'ip'=>['198.51.100.7']]];
$sync->checkManagedNodes();
$sent = $sync->submitted[0]['value']['policy'] ?? [];
$check(($sent['routes'] ?? null) === $confirmedRoutes && ($sent['controller_ips'] ?? []) === ['198.51.100.7'],
    'automatic IP sync preserves confirmed routes and sends only the IP change');
$check(!isset($sync->pacState['managed_nodes'][$id]['job']['lists_sent']), 'an automatic job cannot acknowledge list edits');

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

// A node that reports digests keeps its running lists when the request names them:
// automatic IP sync and an apply without list changes do not resend megabytes.
class DigestNodeFixtureBot extends GuardFixtureBot
{
    public int $rejectDigest = 0; public array $backup = []; public string $rejectAs = 'lists';
    public array $runningRoutes = [];
    protected function managedNodeRpc(string $id, array $request): array {
        if ($request['action'] === 'backup') { $this->events[] = 'backup'; return $this->backup; }
        if ($request['action'] === 'routes') { $this->events[] = 'routes'; return ['routes' => $this->runningRoutes]; }
        if ($request['action'] === 'submit' && isset($request['request']['value']['policy']['routes_digest']) && $this->rejectDigest-- > 0) {
            $this->submitted[] = $request['request'];
            throw $this->rejectAs === 'generic' ? new RuntimeException('Node transport timeout') : new NodeListsDigestException('lists_missing');
        }
        return parent::managedNodeRpc($id, $request);
    }
}
$routesDigest = hash('sha256', json_encode($confirmedRoutes, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
// The node computes the same bytes in Python: the reference also sits in node_policy_test.py.
$check(Closure::bind(fn() => self::nodeRoutesDigest(['block' => ['domain' => ['regexp:^a\.b/c$', "full:\u{e9}.test", "keyword:x\u{2028}"], 'ip' => ['192.0.2.0/24']],
    'warp' => ['domain' => ["keyword:\u{432}\u{438}\u{434}\u{435}\u{43e}"]]]), null, Bot::class)()
    === '1b9cc32f8cc9a41b6eeaa1a804bedfb185c719f660c3237d40672ff040d077c2', 'controller and node routes digests match');
foreach ([0, 1] as $reject) {
    $digestBot = new DigestNodeFixtureBot();
    $digestBot->rejectDigest = $reject;
    $digestBot->remoteStatus['shared_routes'] = $digestBot->remoteStatus['controller_ip_guard'] = $digestBot->remoteStatus['policy_summary'] = true;
    $digestBot->remoteStatus['pending'] = null;
    $digestBot->remoteStatus['options']['policy'] = ['routes_digest' => $routesDigest, 'counts' => ['block' => ['domain' => 1], 'controller' => 0]];
    $digestBot->backup = ['options' => ['policy' => ['routes' => $confirmedRoutes]]];
    $digestBot->pacState['managed_nodes'][$id]['status']['policy_summary'] = true;
    $digestBot->pacState['managed_nodes'][$id]['job'] = null;
    $digestBot->pacState['managed_nodes'][$id]['lists'] = ['block' => ['routes' => [], 'rulesets' => []], 'warp' => ['routes' => ['full:draft.example' => 1], 'rulesets' => []]];
    $digestBot->xrayState['routing']['rules'] = [['ruleTag' => 'vpnbot:routes:block:ip', 'ip' => ['198.51.100.7']]];
    $digestBot->checkManagedNodes();
    $first = $digestBot->submitted[0]['value']['policy'] ?? [];
    $check(($first['routes_digest'] ?? '') === $routesDigest && !isset($first['routes']) && !isset($first['counts'])
        && ($first['controller_ips'] ?? []) === ['198.51.100.7'], 'IP sync names the running lists by digest and sends the changed IPs');
    if ($reject) {
        $retry = $digestBot->submitted[1]['value']['policy'] ?? [];
        $check(count($digestBot->submitted) === 2 && in_array('backup', $digestBot->events, true) && ($retry['routes'] ?? null) === $confirmedRoutes
            && !isset($retry['routes_digest']), 'a rejected digest is resent once with the node snapshot lists, not local edits');
    } else $check(count($digestBot->submitted) === 1, 'accepted digest is sent once');
}

// A timeout may have queued the first request: only an explicit lists_missing is resent.
$generic = new DigestNodeFixtureBot();
$generic->rejectDigest = 1; $generic->rejectAs = 'generic';
$generic->remoteStatus['shared_routes'] = $generic->remoteStatus['controller_ip_guard'] = $generic->remoteStatus['policy_summary'] = true;
$generic->remoteStatus['pending'] = null;
$generic->remoteStatus['options']['policy'] = ['routes_digest' => $routesDigest];
$generic->pacState['managed_nodes'][$id]['status']['policy_summary'] = true;
$generic->pacState['managed_nodes'][$id]['job'] = null;
$generic->xrayState['routing']['rules'] = [['ruleTag' => 'vpnbot:routes:block:ip', 'ip' => ['198.51.100.7']]];
$generic->checkManagedNodes();
$check(count($generic->submitted) === 1 && !in_array('backup', $generic->events, true), 'a generic failure is not resent');

// Apply with lists the node already runs: the expanded routes travel as a digest.
$same = new DigestNodeFixtureBot();
$same->remoteStatus['pending'] = null;
$node = &$same->pacState['managed_nodes'][$id];
$node['job'] = null;
$node['status']['shared_routes'] = $node['status']['policy_summary'] = true;
$node['lists'] = ['block' => ['routes' => ['full:blocked.example' => 1], 'rulesets' => []], 'warp' => ['routes' => ['192.0.2.0/24' => 1], 'rulesets' => []]];
$node['status']['options']['policy'] = ['routes_digest' => $routesDigest];
unset($node);
$same->nodeRoutesApply($id, 'warp');
$applied = $same->submitted[0]['value']['policy'] ?? [];
$check(($applied['routes_digest'] ?? '') === $routesDigest && !isset($applied['routes']), 'unchanged lists apply by digest');
$same->pacState['managed_nodes'][$id]['job'] = null;
$same->pacState['managed_nodes'][$id]['lists']['warp']['routes']['full:new.example'] = 1;
$same->nodeRoutesApply($id, 'warp');
$changed = $same->submitted[1]['value']['policy'] ?? [];
$check(isset($changed['routes']['warp']['domain']) && !isset($changed['routes_digest']), 'edited lists are sent in full');
// Confirming a change: the direct fallback gets the node's running blocks, never a stale copy.
foreach ([true, false] as $matching) {
    $use = new DigestNodeFixtureBot();
    $use->runningRoutes = $matching ? $confirmedRoutes : ['block' => ['domain' => ['full:other.example']]];
    $use->managedNodeUseProfile($id, $use->profile, $use->remoteStatus['options'] + ['policy' => ['routes_digest' => $routesDigest]]);
    $stored = $use->pacState['exits'][$id]['policy'] ?? [];
    $check(in_array('routes', $use->events, true) && (($stored['routes'] ?? null) === $confirmedRoutes) === $matching,
        $matching ? 'running lists fetched for the fallback' : 'lists with another digest are not used');
}
echo "PASS lists by digest: IP sync, rejected digest, unchanged apply\n";

// Expansion stops as soon as the lists can no longer fit, before large sets exhaust PHP memory.
$budgetBot = new RoutesFixtureBot();
$budgetBot->dat = ['ru' => array_map(static fn($i) => "198.51.100.$i/32", range(1, 50))];
$parts = Closure::bind(function (array $list, int $budget) { return $this->nodeRoutesParts($list, $budget); }, $budgetBot, Bot::class);
$list = ['routes' => ['full:a.example' => 1, 'geoip:ru' => 1], 'rulesets' => []];
$check(count($parts($list, 51)['ip']) === 50, 'expansion within the budget: the category reference is not charged');
try { $parts($list, 50); $stopped = false; } catch (NodeRoutesException $e) { $stopped = $e->getMessage() === 'size'; }
$check($stopped, 'a category past the budget stops with the size error');
$check(Bot::NODE_ROUTES_MAX_ENTRIES * 15 > 3 * 1024 * 1024, 'the early stop never rejects lists that fit 3 MiB');
// Overlapping categories count once.
$budgetBot->dat['ru2'] = array_merge($budgetBot->dat['ru'], ['203.0.113.1/32']);
$check(count($parts(['routes' => ['geoip:ru' => 1, 'geoip:ru2' => 1], 'rulesets' => []], 51)['ip']) === 51, 'overlapping categories are charged once');
echo "PASS expansion budget\n";

// A refreshed .dat changes the expanded list of an applied source: the node gets it hourly.
$syncBot = new RoutesFixtureBot();
$sync = Closure::bind(function (string $id) { $this->syncNodeRoutes($id); }, $syncBot, Bot::class);
$node = &$syncBot->pacState['managed_nodes'][$id];
$node['job'] = null; $node['status']['shared_routes'] = true; $node['status']['pending'] = null;
$node['lists'] = ['block' => ['routes' => ['geoip:lab' => 1], 'rulesets' => []], 'warp' => ['routes' => [], 'rulesets' => []]];
$node['lists_sent'] = Closure::bind(fn() => self::nodeRoutesDigest($this->nodeRoutesSource($node)), $syncBot, Bot::class)();
$node['status']['options']['policy'] = ['routes_digest' => hash('sha256', json_encode(['block' => ['ip' => ['192.0.2.0/24']]], JSON_UNESCAPED_SLASHES))];
unset($node);
$syncBot->dat = ['lab' => ['192.0.2.0/24']];
$sync($id);
$check($syncBot->submitted === [], 'unchanged expansion is not resent');
$syncBot->dat = ['lab' => ['192.0.2.0/24', '203.0.113.0/24']];
$sync($id);
$check($syncBot->submitted === [], 'checked at most hourly');
$syncBot->pacState['managed_nodes'][$id]['lists_checked'] = 0;
$syncBot->pacState['managed_nodes'][$id]['lists']['block']['routes']['full:draft.example'] = 1;
$sync($id);
$check($syncBot->submitted === [], 'unapplied edits wait for Apply');
unset($syncBot->pacState['managed_nodes'][$id]['lists']['block']['routes']['full:draft.example']);
$syncBot->pacState['managed_nodes'][$id]['lists_checked'] = 0;
$sync($id);
$sent = $syncBot->submitted[0]['value']['policy']['routes'] ?? [];
$check(count($syncBot->submitted) === 1 && ($sent['block']['ip'] ?? []) === ['192.0.2.0/24', '203.0.113.0/24'], 'refreshed source resent through a normal job');
// A refused automatic resend is not repeated for the same expansion: the poll of the
// failed job records it (audit 26.11.2026: a busy or unreachable node is retried hourly).
$refused = $syncBot->pacState['managed_nodes'][$id]['job']['lists_auto'] ?? null;
$check(is_string($refused), 'the automatic job carries the expansion it sends');
$syncBot->pacState['managed_nodes'][$id]['job'] = null;
$syncBot->pacState['managed_nodes'][$id]['lists_auto'] = ['digest' => $refused, 'time' => time()];
$syncBot->pacState['managed_nodes'][$id]['lists_checked'] = 0;
$syncBot->submitted = [];
$sync($id);
$check($syncBot->submitted === [], 'the same refused expansion is not resent every hour');
$syncBot->dat = ['lab' => ['192.0.2.0/24', '203.0.113.0/25']];
$syncBot->pacState['managed_nodes'][$id]['lists_checked'] = 0;
$sync($id);
$check(count($syncBot->submitted) === 1, 'a changed source is tried again');
echo "PASS hourly resync of refreshed sources\n";
