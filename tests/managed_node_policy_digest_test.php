<?php
// The expanded controller IP list (geoip/ext categories) reaches tens of thousands of
// CIDRs. pac.json stores only its digest; the node still receives the full list.
ini_set('memory_limit', '128M');
require __DIR__ . '/managed_nodes_test.php';

$check = static function ($ok, $text) { if (!$ok) throw new RuntimeException($text); };
$id = 'aabbccdd';
$ips = [];
for ($i = 0; $i < 65682; $i++) $ips[] = sprintf('10.%d.%d.%d/32', $i >> 16, ($i >> 8) & 255, $i & 255);
sort($ips, SORT_STRING);
$digest = hash('sha256', implode("\n", $ips));

class DigestFixtureBot extends ManagedFixtureBot
{
    public array $submitted = [];
    public int $largestPac = 0;
    public function setPacConf(array $conf)
    {
        // The real setPacConf compacts before encoding.
        $conf = self::compactNodePolicies($conf);
        $this->largestPac = max($this->largestPac, strlen(json_encode($conf)));
        $this->pacState = json_decode(json_encode($conf), true);
        return true;
    }
    protected function managedNodeRpc(string $id, array $request): array
    {
        if ($request['action'] === 'submit') $this->submitted[] = $request['request'];
        return parent::managedNodeRpc($id, $request);
    }
}

$compact = Closure::bind(static fn(array $pac) => Bot::compactNodePolicies($pac), null, Bot::class);
$withIps = Closure::bind(fn(array $options, array $ips) => $this->withControllerIps($options, $ips), new DigestFixtureBot(), Bot::class);

// Every stored copy is reduced to the digest; other fields stay in place.
$policy = ['lists' => ['ads' => ['domain' => ['full:ads.example']]], 'bindings' => ['all' => [['list' => 'ads', 'action' => 'block']]],
    'revision' => str_repeat('a', 32), 'controller_ips' => $ips];
$pac = ['managed_nodes' => [$id => ['status' => ['options' => ['policy' => $policy, 'transport' => 'ws']], 'draft' => ['policy' => $policy],
    'job' => ['before' => ['policy' => $policy, 'link' => 'x'], 'draft' => ['draft' => ['policy' => $policy]]]]],
    'exits' => [$id => ['policy' => $policy, 'name' => 'node']]];
$small = $compact($pac);
$encoded = json_encode($small);
$expected = array_diff_key($policy, ['controller_ips' => 0]) + ['controller_ips_digest' => $digest];
$check(!str_contains($encoded, 'controller_ips"') && strlen($encoded) < 4096, 'pac.json keeps no expanded copy');
foreach ([$small['managed_nodes'][$id]['status']['options']['policy'], $small['managed_nodes'][$id]['draft']['policy'],
          $small['managed_nodes'][$id]['job']['before']['policy'], $small['managed_nodes'][$id]['job']['draft']['draft']['policy'],
          $small['exits'][$id]['policy']] as $stored) {
    $check($stored === $expected, 'each copy keeps lists, bindings and revision with the digest');
}
$check($small['managed_nodes'][$id]['status']['options']['transport'] === 'ws' && $small['exits'][$id]['name'] === 'node', 'unrelated fields untouched');
$check($compact($small) === $small, 'compaction is idempotent');
$check($compact(['managed_nodes' => [$id => ['job' => null, 'status' => []]], 'exits' => [$id => []]])
    === ['managed_nodes' => [$id => ['job' => null, 'status' => []]], 'exits' => [$id => []]], 'nodes without a policy are unchanged');

// Submission expands the stored digest back into the list without a new revision.
$sent = $withIps(['policy' => $expected], $ips);
$check($sent['policy']['controller_ips'] === $ips && $sent['policy']['revision'] === $policy['revision']
    && !isset($sent['policy']['controller_ips_digest']), 'unchanged list keeps the revision and the node receives it in full');
$changed = $withIps(['policy' => $expected], array_slice($ips, 1));
$check($changed['policy']['revision'] !== $policy['revision'] && count($changed['policy']['controller_ips']) === count($ips) - 1, 'a changed list gets a new revision');
$cleared = $withIps(['policy' => ['lists' => [], 'bindings' => [], 'revision' => $policy['revision'], 'controller_ips_digest' => $digest]], []);
$check(!isset($cleared['policy']), 'clearing the list removes the empty policy');
echo "PASS controller IP digest storage and expansion\n";

// A full job with the real-size list: profile, traffic check and confirmation.
$bot = new DigestFixtureBot();
$bot->xrayState['routing']['rules'] = [['ruleTag' => 'vpnbot:routes:block:ip', 'ip' => $ips]];
$remote = ['lists' => [], 'bindings' => [], 'revision' => str_repeat('e', 32), 'controller_ips' => $ips];
$bot->remoteStatus['controller_ip_guard'] = true;
$bot->remoteStatus['options']['policy'] = $remote;
$bot->pacState['managed_nodes'][$id]['status']['controller_ip_guard'] = true;
$bot->pacState['managed_nodes'][$id]['status']['options']['policy'] = $remote;
$bot->pacState['exits'][$id]['policy'] = $remote;
$bot->setPacConf($bot->pacState);
$bot->managedNodePoll($id);
$check(in_array('confirm', $bot->events, true) && $bot->pacState['managed_nodes'][$id]['job'] === null, 'job with the large list is confirmed');
$check($bot->pacState['exits'][$id]['policy']['controller_ips_digest'] === $digest && $bot->pacState['exits'][$id]['policy']['revision'] === $remote['revision']
    && !str_contains(json_encode($bot->pacState), 'controller_ips"'), 'confirmed route stores only the digest');
$check($bot->largestPac < 65536, 'pac.json stays small: ' . $bot->largestPac);
$tags = array_column($bot->xrayState['outbounds'], 'tag');
$check(in_array(Bot::EXIT_TAG . 'health-check-' . $id, $tags, true), 'a digest-confirmed node enforces the controller list');
$check(memory_get_peak_usage() < 100 * 1024 * 1024, 'peak memory stays below the PHP limit: ' . memory_get_peak_usage());

// The card treats the digest as confirmation.
$line = Closure::bind(fn() => $this->managedNodeIpGuardLine($this->managedNodes()[$id], $this->exitNodes()[$id]), $bot, Bot::class)();
$check($line === '', 'card shows a confirmed list');

// Periodic synchronization compares digests: no resubmission of an unchanged list.
$bot->remoteStatus['pending'] = null;
$bot->pacState['managed_nodes'][$id]['status_attempt'] = 0;
$bot->events = [];
$bot->checkManagedNodes();
$check(in_array('status', $bot->events, true) && $bot->submitted === [], 'unchanged list is not resubmitted');
foreach ($bot->xrayState['routing']['rules'] as &$rule) {
    if (($rule['ruleTag'] ?? '') === 'vpnbot:routes:block:ip') $rule['ip'] = array_slice($ips, 2);
}
unset($rule);
$bot->pacState['managed_nodes'][$id]['job'] = null;
$bot->pacState['managed_nodes'][$id]['status_attempt'] = 0;
Closure::bind(fn() => $this->managedNodeCronAt = 0, $bot, Bot::class)();
$bot->checkManagedNodes();
$submitted = $bot->submitted[0]['value']['policy'] ?? [];
$check(count($submitted['controller_ips'] ?? []) === count($ips) - 2 && !isset($submitted['controller_ips_digest'])
    && $submitted['revision'] !== $remote['revision'], 'a changed list is sent in full with a new revision');
$check(!str_contains(json_encode($bot->pacState), 'controller_ips"'), 'the pending job stores only digests');
echo "PASS large controller IP list: confirmation, card and synchronization\n";

// A node without the guard never receives the digest.
$plain = new DigestFixtureBot();
$plain->pacState['managed_nodes'][$id]['job'] = null;
$plain->managedNodeSubmit($id, 'configure', ['transport' => 'ws', 'policy' => ['lists' => [], 'bindings' => [], 'revision' => str_repeat('a', 32), 'controller_ips_digest' => $digest]]);
$check(!isset($plain->submitted[0]['value']['policy']), 'digest is removed for a node without the guard');
echo "PASS digest stays local for nodes without the guard\n";

// Expanding categories takes seconds: the digest is cached by the rule and the asset files.
class DatDigestFixtureBot extends DigestFixtureBot
{
    public string $dir; public array $tools = []; public array $categories = [];
    public function datResolve(string $file): string { return $file; }
    public function datPath(string $name): string { return $this->dir . '/' . $name; }
    public function datCategoryError(array $c): ?string { return null; }
    protected function exitRulesetTool(array $command): bool
    {
        $this->tools[] = $command;
        if (!is_file($command[3])) return false;
        file_put_contents($command[4], json_encode($this->categories[end($command)] ?? []));
        return true;
    }
}
$dat = new DatDigestFixtureBot();
$dat->dir = sys_get_temp_dir() . '/node-digest-' . getmypid();
@mkdir($dat->dir);
file_put_contents($dat->dir . '/cat.dat', 'v1');
@unlink(sys_get_temp_dir() . '/vpnbot-controller-ips.json');
$dat->categories = ['ru' => ['10.1.0.0/16', '10.0.0.0/16']];
$config = ['routing' => ['rules' => [['ruleTag' => 'vpnbot:routes:block:ip', 'ip' => ['ext:cat.dat:ru', '10.9.0.0/16']]]]];
$digestOf = Closure::bind(fn(array $config) => $this->controllerBlockedIpsDigest($config), $dat, Bot::class);
$full = Closure::bind(fn(array $config) => $this->controllerBlockedIps($config), $dat, Bot::class);
$first = $digestOf($config);
$check($first === hash('sha256', implode("\n", $full($config))) && count($dat->tools) === 2, 'digest matches the expanded list');
$dat->tools = [];
$cacheOwnedByRoot = fileowner(sys_get_temp_dir() . '/vpnbot-controller-ips.json') === 0;
$check($digestOf($config) === $first && count($dat->tools) === ($cacheOwnedByRoot ? 0 : 1), 'only a root-owned cache skips the expansion');
$cacheFile = sys_get_temp_dir() . '/vpnbot-controller-ips.json';
if (@chown($cacheFile, 65534)) {
    // Running as root: a cache file of another owner is ignored, never trusted.
    $dat->tools = [];
    $check($digestOf($config) === $first && count($dat->tools) === 1, 'foreign cache file is not trusted');
}
file_put_contents($cacheFile, json_encode(['key' => 'x', 'digest' => 'not-a-digest']));
$dat->tools = [];
$check($digestOf($config) === $first && count($dat->tools) === 1, 'malformed cache entry is ignored');
$dat->tools = [];
$dat->categories = ['ru' => ['10.2.0.0/16']];
file_put_contents($dat->dir . '/cat.dat.new', 'v2-longer');
rename($dat->dir . '/cat.dat.new', $dat->dir . '/cat.dat');
$second = $digestOf($config);
$check($second !== $first && count($dat->tools) === 1 && $second === hash('sha256', implode("\n", ['10.2.0.0/16', '10.9.0.0/16'])), 'updated asset invalidates the cache');
$config['routing']['rules'][0]['ip'][] = '10.8.0.0/16';
$check($digestOf($config) !== $second, 'changed rule invalidates the cache');
unlink($dat->dir . '/cat.dat');
$failed = false;
try { $digestOf($config); } catch (Throwable $e) { $failed = true; }
$check($failed, 'a missing asset is an error, never a cached or empty list');
$check($digestOf(['routing' => ['rules' => []]]) === null, 'no controller blocks');
@unlink(sys_get_temp_dir() . '/vpnbot-controller-ips.json');
@rmdir($dat->dir);
echo "PASS cached controller IP digest\n";
