<?php
require __DIR__ . '/managed_nodes_test.php';

$bot = new ManagedFixtureBot();
$id = 'aabbccdd';
$other = 'bbccddaa';
$bot->pacState['managed_nodes'][$id]['status']['named_policy'] = true;
$bot->pacState['managed_nodes'][$id]['job'] = null;
$bot->pacState['managed_nodes'][$other] = $bot->pacState['managed_nodes'][$id];
$bot->pacState['managed_nodes'][$other]['name'] = 'second';
$check = static function ($ok, $text) { if (!$ok) throw new RuntimeException($text); };
$version = static fn() => hash('sha256', serialize($bot->pacState['node_policy_lists'] ?? []));
$bot->saveNodePolicyList("Реклама\nfull:ads.example\n203.0.113.0/24", $id, 'all', $version());
$key = Bot::exitEntryKey('Реклама');
$check(isset($bot->pacState['node_policy_lists']['Реклама']), 'catalog created');
foreach ([$other,$id] as $node) $bot->nodePolicyAssign($node, 'all', $key, 'off');
$bot->nodePolicyAssign($id, 'all', $key, 'off');
$check(count($bot->pacState['managed_nodes'][$id]['draft']['policy']['bindings']['all']) === 1, 'stale tap');
$old = $version();
$bot->saveNodePolicyList("Реклама\nfull:new.example", $id, 'all', $old);
$bot->saveNodePolicyList("Реклама\nfull:stale.example", $other, 'all', $old);
$check($bot->pacState['node_policy_lists']['Реклама']['domain'] === ['full:new.example'], 'stale catalog edit');
$bot->nodePolicySync($other,'all');
$check($bot->pacState['managed_nodes'][$other]['draft']['policy']['lists']['Реклама']['domain'] === ['full:new.example'], 'sync');
$check($bot->pacState['managed_nodes'][$id]['draft']['policy']['lists']['Реклама']['domain'] === ['full:ads.example'], 'generation pinned');
$bot->saveNodePolicyList('Реклама',$id,'all',$version());
$check(isset($bot->pacState['node_policy_lists']['Реклама']), 'assigned list protected');
$bot->saveNodePolicyTest('new.example',$other,'all');
$check(str_contains(end($bot->screens)[0], 'Реклама → block'), 'preview');
foreach ([$id,$other] as $node) $bot->nodePolicyAssign($node,'all',$key,'block');
$bot->saveNodePolicyList('Реклама',$id,'all',$version());
$check(!isset($bot->pacState['node_policy_lists']['Реклама']), 'unbound list removed');
echo "PASS named list catalog, ordered assignments and preview\n";

$bot->saveNodePolicyList("Сайты\nfull:one.example", $id, 'all', $version());
$user = ['id'=>'11111111-1111-4111-8111-111111111111', 'email'=>'alice', 'exit_full'=>$id];
$bot->xrayState['inbounds'] = [['tag'=>'vpn', 'settings'=>['clients'=>[$user]]]];
$key = Bot::exitFullKey($user);
$list = Bot::exitEntryKey('Сайты');
$bot->exitMainSelect($id,$key,$list,false,0);
$bot->exitMainSelect($id,$key,$list,false,0);
$check($bot->xrayState['inbounds'][0]['settings']['clients'][0]['exit_main'] === ['Сайты'], 'selection and stale tap');
$bot->saveNodePolicyList('Сайты',$id,'all',$version());
$check(isset($bot->pacState['node_policy_lists']['Сайты']), 'controller binding protects shared list');
$bot->corePass = false;
$bot->saveNodePolicyList("Сайты\nfull:two.example", $id, 'all', $version());
$check($bot->pacState['node_policy_lists']['Сайты']['domain'] === ['full:one.example'], 'rename contents rollback');
$bot->corePass = true;
$bot->saveNodePolicyList("Сайты\nfull:two.example", $id, 'all', $version());
$compiled = $bot->xrayState;
$bot->ensureExitNodes($compiled, $bot->pacState);
$check($compiled === $bot->xrayState && $compiled['dns']['servers'][0]['domains'] === ['full:two.example'], 'idempotent catalog refresh');
$bot->saveNodePolicyTest('two.example',$id,'bot-'.$key);
$check(str_contains(end($bot->screens)[0], 'Основной сервер · Сайты'), 'node preview shows controller exception');
$bot->pacState['blocklist'] = ['full:two.example'=>1];
$bot->saveNodePolicyTest('two.example',$id,'bot-'.$key);
$check(str_contains(end($bot->screens)[0], 'Блокировка основного сервера'), 'controller deny overrides exception in preview');
$bot->exitMainSelect($id,$key,$list,true,0);
$check(!isset($bot->xrayState['dns'], $bot->xrayState['_vpnbot_main_implicit_dns']), 'restore implicit main resolver');
$check(!isset($bot->xrayState['inbounds'][0]['settings']['clients'][0]['exit_main']), 'clear last exception');
echo "PASS controller list assignment, stale edit, catalog update and rollback\n";

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

class RenamedPolicyFixtureBot extends ManagedFixtureBot
{
    protected function userXrLocked($i) {}
    public function adguardXrayClients() {}
}

$subject = ['id'=>'11111111-1111-4111-8111-111111111111', 'email'=>'alice', 'exit_full'=>$id];
$scope = 'bot-' . Bot::exitFullKey($subject);
$lists = ['media'=>['domain'=>['full:media.example']]];
$policy = ['revision'=>str_repeat('a',32), 'lists'=>$lists, 'bindings'=>[$scope=>[['list'=>'media','action'=>'block']]]];
$renamed = new RenamedPolicyFixtureBot();
$renamed->pacState['managed_nodes'][$id]['job'] = null;
$renamed->pacState['managed_nodes'][$id]['status']['named_policy'] = true;
$renamed->pacState['managed_nodes'][$id]['status']['options']['policy'] = $policy;
$renamed->pacState['exits'][$id]['policy'] = $policy;
$renamed->xrayState['inbounds'] = [['tag'=>'vpn','settings'=>['clients'=>[$subject]]]];
foreach (['alice-new', 'alice-final'] as $name) {
    $renamed->renXrUs($name,0);
    $renamed->nodePolicyMenu($id,$scope);
    $check(str_contains(end($renamed->screens)[0], $name), 'renamed client keeps its existing node subject');
}
// Re-import the saved client and create a different client under the old name.
$clients = json_decode(json_encode($renamed->xrayState['inbounds'][0]['settings']['clients']), true);
$copy = $clients[0];
$copy['id'] = '22222222-2222-4222-8222-222222222222';
$copy['email'] = 'alice';
$clients[] = $copy;
$renamed->xrayState['inbounds'][0]['settings']['clients'] = $clients;
$compiled = $renamed->xrayState;
$renamed->ensureExitNodes($compiled, $renamed->pacState);
$denies = array_values(array_filter($compiled['routing']['rules'], static fn($r) =>
    ($r['domain'] ?? []) === ['full:media.example'] && ($r['outboundTag'] ?? '') === 'block'));
$check(count($denies) === 1 && $denies[0]['user'] === ['alice-final'], 'restored policy belongs to the renamed identity only');
$renamed->pacState['blocklist'] = ['full:blocked.example'=>1];
$renamed->saveNodePolicyTest('blocked.example',$id,$scope);
$check(str_contains(end($renamed->screens)[0], 'Блокировка основного сервера'), 'main deny preview without an exception');

$key = Bot::exitEntryKey('media');
$node = &$renamed->pacState['managed_nodes'][$id];
$renamed->pacState['node_policy_lists'] = $lists;
$node['status']['options']['policy']['controller_ips'] = ['192.0.2.0/24'];
$renamed->nodePolicyAssign($id,$scope,$key,'off');
$renamed->nodePolicySync($id,$scope);
$check(!isset($node['draft']), 'a stale button and unchanged refresh leave the node ready for automatic updates');
$node['status']['options']['policy']['bindings'] = ['all'=>[['list'=>'media','action'=>'block']]];
$renamed->nodePolicyAssign($id,'all',$key,'block');
$check($node['draft']['policy']['controller_ips'] === ['192.0.2.0/24'], 'unbinding the last list keeps the shared IPs in the draft');
unset($node['draft'], $node['draft_generation']);
$node['status']['options']['policy']['bindings'] = [];
$renamed->saveNodePolicyList('media',$id,'all',hash('sha256',serialize($lists)));
$rows = end($renamed->screens)[1];
$check(!in_array('○ media',array_column(array_merge(...$rows),'text'),true), 'removing an unused list survives a stale copy on the node');
$renamed->nodePolicySync($id,'all');
$check($node['draft']['policy']['lists'] === [] && $node['draft']['policy']['controller_ips'] === ['192.0.2.0/24'],
    'refresh removes a stale cached list and preserves the shared IPs');
unset($node);

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

$restored = new ManagedFixtureBot();
$restored->pacState['managed_nodes'][$id]['job'] = null;
$restored->pacState['managed_nodes'][$id]['status']['named_policy'] = true;
$restored->pacState['managed_nodes'][$id]['status']['options']['policy'] = $policy;
$restored->xrayState['inbounds'] = [['tag'=>'vpn','settings'=>['clients'=>[$subject]]]];
$restored->exitMainSelect($id,Bot::exitFullKey($subject),Bot::exitEntryKey('media'),false,0);
$check($restored->pacState['node_policy_lists'] === $lists, 'a controller assignment pins a list discovered in a restored node');
unset($restored->pacState['managed_nodes'][$id]['status']['options']['policy']);
$compiled = $restored->xrayState;
$restored->ensureExitNodes($compiled,$restored->pacState);
$check($compiled['dns']['servers'][0]['domains'] === ['full:media.example'], 'controller exception survives removal of its remote copy');

$node = &$restored->pacState['managed_nodes'][$id];
$node['status']['options']['policy'] = $policy;
$restored->xrayState['inbounds'][0]['settings']['clients'] = [];
$restored->nodePolicyMenu($id,'all');
$rows = end($restored->screens)[1];
$callbacks = array_column(array_merge(...$rows),'callback_data');
$clean = array_values(array_filter($callbacks, static fn($c) => str_starts_with($c, "/npClean $id ")));
$check(count($clean) === 1, 'allow explicit draft cleanup of a deleted client');
$fingerprint = explode(' ', $clean[0])[2];
$elsewhere = $subject;
unset($elsewhere['exit_full']);
$restored->xrayState['inbounds'][0]['settings']['clients'] = [$elsewhere];
$restored->nodePolicyClean($id,$fingerprint);
$check(!isset($node['draft']), 'stale cleanup keeps an existing client, including one routed elsewhere');
$restored->xrayState['inbounds'][0]['settings']['clients'] = [];
$node['status']['options']['policy']['bindings']['all'] = [['list'=>'media','action'=>'block']];
$restored->nodePolicyClean($id,$fingerprint);
$check(!isset($node['draft']['policy']['bindings'][$scope]) && isset($node['status']['options']['policy']['bindings'][$scope])
    && $node['draft']['policy']['lists'] === $lists, 'cleanup is a draft and preserves lists shared by another subject');
unset($node);
