<?php
// Аудит 26.11.2026: списки и черновики ноды, секреты в группах, карточки, проба, наборы.
require __DIR__ . '/managed_nodes_test.php';

class AuditListsBot extends ManagedFixtureBot
{
    public array $submitted = []; public array $messages = []; public array $transports = [];
    public array $lockNames = []; public ?Closure $onLock = null; public bool $submitFails = false;
    public array $dat = []; public array $backupRoutes = [];
    protected function managedNodeRpc(string $id, array $request): array
    {
        if ($request['action'] === 'submit') {
            if ($this->submitFails) throw new RuntimeException('node busy');
            $this->submitted[] = $request['request'];
        }
        if ($request['action'] === 'backup') return ['options' => ['policy' => ['routes' => $this->backupRoutes]]];
        return parent::managedNodeRpc($id, $request);
    }
    protected function managedNodeTransport(string $id, string $action, $value = null): array
    {
        $this->transports[] = $action;
        if (in_array($action, ['import-clear', 'restore-source', 'import'], true)) return ['cleared' => true];
        return parent::managedNodeTransport($id, $action, $value);
    }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null)
    {
        $this->lockNames[] = $name;
        if ($this->onLock && str_starts_with($name, 'managed-node-')) { $hook = $this->onLock; $this->onLock = null; $hook($this); }
        return $fn();
    }
    protected function nodePolicyDat(array $entry): array { return $this->dat[$entry['value'] ?? ''] ?? throw new RuntimeException('no dat'); }
    public function request($method, $data, $json_header = 0)
    {
        $this->messages[] = [$method, $data];
        return ['ok' => true, 'result' => ['message_id' => 9]];
    }
    public function stashReply($r, array $state) {}
    protected function nodeRoutesProbeAddresses(string $host): array { return ['198.51.100.200']; }
    public function exitRulesetCoreAccepts(array $entries): bool { return true; }
}

$id = 'aabbccdd';
$digest = static fn(array $v) => hash('sha256', json_encode($v, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
$fresh = static function (?callable $edit = null) use ($id, $digest): AuditListsBot {
    $bot = new AuditListsBot();
    $node = &$bot->pacState['managed_nodes'][$id];
    $node['job'] = null;
    $node['status']['pending'] = null;
    $node['status']['shared_routes'] = true;
    $node['status']['policy_summary'] = true;
    // The node runs Block lists this card has never applied.
    $node['status']['options']['policy'] = ['routes_digest' => $digest(['block' => ['domain' => ['full:ads.example']]]),
        'counts' => ['block' => ['domain' => 1]]];
    unset($node);
    if ($edit) $edit($bot->pacState['managed_nodes'][$id]);
    return $bot;
};
$call = static fn(Bot $bot, string $method, ...$args) => Closure::bind(fn() => $this->$method(...$args), $bot, Bot::class)();
$cb = static fn(AuditListsBot $b) => array_column(array_merge(...end($b->screens)[1]), 'callback_data');

// Each finding runs on its own: on the code before the fix every section fails by itself.
$failed = [];
$run = static function (string $name, callable $section) use (&$failed) {
    try { $section(); }
    catch (Throwable $error) { $failed[] = $name; fwrite(STDERR, "FAIL $name: " . $error->getMessage() . "\n"); }
};
// В01: a reconnected node keeps its running lists; only an explicit apply replaces them.
$run('В01:', static function () use ($id, $digest, $fresh, $call, $cb, $check) {
    $bot = $fresh();
    $call($bot, 'syncNodeRoutes', $id);
    $check($bot->submitted === [], 'B01: hourly sync does not send empty lists over the node lists');
    $bot->managedNodeChoice($id, 'transport', 'xhttp');
    $bot->managedNodeApply($id);
    $sent = $bot->submitted[0]['value']['policy'] ?? [];
    $check(count($bot->submitted) === 1 && !array_key_exists('routes', $sent)
        && ($sent['routes_digest'] ?? null) === $digest(['block' => ['domain' => ['full:ads.example']]]),
        'B01: a settings change names the running lists by digest instead of replacing them');
    $bot = $fresh();
    $bot->nodeRoutesMenu($id, 'block');
    $check(str_contains(end($bot->screens)[0], 'которых нет в этой карточке') && in_array("/nlApply $id block", $cb($bot), true),
        'B01: the card names lists of unknown origin and offers the explicit apply');
    $bot->nodeRoutesApply($id, 'block');
    $sent = $bot->submitted[0]['value']['policy'] ?? [];
    // Empty card lists: the request carries no lists at all, so the node runs none.
    $check(count($bot->submitted) === 1 && empty($sent['routes']) && !isset($sent['routes_digest']),
        'B01: the explicit apply sends the card lists (here: empty)');
    // After a restore the controller copy is not on the node either.
    $bot = $fresh(static function (&$node) use ($digest) {
        $node['lists'] = ['block' => ['routes' => [], 'rulesets' => []], 'warp' => ['routes' => [], 'rulesets' => []]];
    });
    $call($bot, 'syncNodeRoutes', $id);
    $check($bot->submitted === [], 'B01: empty local lists after a restore do not wipe the restored lists');
    // A node whose lists the card applied is synchronised as before.
    $bot = $fresh(static function (&$node) use ($digest) {
        $node['lists'] = ['block' => ['routes' => ['geoip:lab' => 1], 'rulesets' => []], 'warp' => ['routes' => [], 'rulesets' => []]];
        $node['lists_sent'] = $digest($node['lists']);
    });
    $bot->dat = ['lab' => ['192.0.2.0/24']];
    $call($bot, 'syncNodeRoutes', $id);
    $check(count($bot->submitted) === 1, 'B01: applied lists are still resent after a source refresh');
    echo "PASS B01 lists of unknown origin\n";
});

// С15: a busy node is retried next hour; a refused expansion is retried daily.
$run('С15:', static function () use ($id, $digest, $fresh, $call, $cb, $check) {
    $bot = $fresh(static function (&$node) use ($digest) {
        $node['lists'] = ['block' => ['routes' => ['geoip:lab' => 1], 'rulesets' => []], 'warp' => ['routes' => [], 'rulesets' => []]];
        $node['lists_sent'] = $digest($node['lists']);
    });
    $bot->dat = ['lab' => ['192.0.2.0/24']];
    $bot->submitFails = true;
    try { $call($bot, 'syncNodeRoutes', $id); } catch (RuntimeException $e) {}
    $bot->submitFails = false;
    $bot->pacState['managed_nodes'][$id]['lists_checked'] = 0;
    $call($bot, 'syncNodeRoutes', $id);
    $check(count($bot->submitted) === 1, 'C15: a temporary failure does not suppress the next attempt');
    $job = $bot->pacState['managed_nodes'][$id]['job'];
    $check(($job['lists_auto'] ?? '') !== '', 'C15: the automatic job is marked');
    $bot->remoteJob = ['state' => 'failed', 'error' => 'operation_failed'];
    $bot->remoteStatus['pending'] = null; $bot->remoteStatus['generation'] = str_repeat('b', 32);
    $bot->remoteStatus['shared_routes'] = true; $bot->remoteStatus['policy_summary'] = true;
    $bot->remoteStatus['options']['policy'] = $bot->pacState['managed_nodes'][$id]['status']['options']['policy'];
    $bot->managedNodePoll($id);
    $check(($bot->pacState['managed_nodes'][$id]['lists_auto']['digest'] ?? '') === $job['lists_auto'], 'C15: the refusal is recorded');
    $bot->pacState['managed_nodes'][$id]['lists_checked'] = 0;
    $call($bot, 'syncNodeRoutes', $id);
    $check(count($bot->submitted) === 1, 'C15: the refused expansion is not resent within a day');
    $bot->nodeRoutesMenu($id, 'block');
    $check(str_contains(end($bot->screens)[0], 'нода отклонила изменение'), 'C15: the card shows the lag');
    $bot->pacState['managed_nodes'][$id]['lists_auto']['time'] = time() - 90000;
    $bot->pacState['managed_nodes'][$id]['lists_checked'] = 0;
    $call($bot, 'syncNodeRoutes', $id);
    $check(count($bot->submitted) === 2, 'C15: the refused expansion is retried after a day');
    echo "PASS C15 retry of refreshed lists\n";
});

// С16: the field order of a mixed list matches the node's sorted JSON.
$run('С16:', static function () use ($id, $digest, $fresh, $call, $cb, $check) {
    $bot = $fresh();
    $parts = $call($bot, 'nodeRoutesParts', ['routes' => ['192.0.2.0/24' => 1, 'full:a.example' => 1], 'rulesets' => []]);
    $check(array_keys($parts) === ['domain', 'ip'], 'C16: IP first still gives domain, ip');
    echo "PASS C16 canonical order\n";
});

// С13: Apply sends the draft as it is under the node lock and keeps no stale copy.
$run('С13:', static function () use ($id, $digest, $fresh, $call, $cb, $check) {
    $bot = $fresh(static function (&$node) { $node['lists_sent'] = 'x'; });
    $bot->managedNodeChoice($id, 'transport', 'xhttp');
    $bot->onLock = static function (AuditListsBot $b) use ($id) { $b->pacState['managed_nodes'][$id]['draft']['transport'] = 'grpc'; };
    $bot->managedNodeApply($id);
    $check(($bot->submitted[0]['value']['transport'] ?? '') === 'grpc', 'C13: the draft edited while waiting for the lock is the one applied');
    // A WARP change does not take or discard a draft saved meanwhile.
    $bot = $fresh(static function (&$node) {
        $node['lists_sent'] = 'x'; $node['status']['warp_egress'] = true; $node['status']['options']['warp_mode'] = 'masque';
    });
    $bot->onLock = static function (AuditListsBot $b) use ($id) {
        $b->pacState['managed_nodes'][$id]['draft'] = ['transport' => 'grpc'] + $b->pacState['managed_nodes'][$id]['status']['options'];
    };
    $bot->managedNodeWarpHttp($id, 'h2');
    $check($bot->submitted === [] && ($bot->pacState['managed_nodes'][$id]['draft']['transport'] ?? '') === 'grpc',
        'C13: a draft saved before the WARP change is neither sent nor lost');
    echo "PASS C13 drafts under the node lock\n";
});

// С14: a status check of a deleted node writes nothing.
$run('С14:', static function () use ($id, $digest, $fresh, $call, $cb, $check) {
    $bot = $fresh();
    unset($bot->pacState['managed_nodes'][$id]);
    try { $call($bot, 'managedNodeCheckStatus', $id); } catch (Throwable $e) {}
    $check(!isset($bot->pacState['managed_nodes'][$id]), 'C14: a deleted card is not recreated by a status check');
    echo "PASS C14 deleted card stays deleted\n";
});

// Н01: two parallel additions cannot pass the limit.
$run('Н01:', static function () use ($id, $digest, $fresh, $call, $cb, $check) {
    $bot = $fresh();
    foreach (range(1, 6) as $n) $bot->pacState['managed_nodes'][sprintf('%08x', 0xabc00000 + $n)] = ['name' => "n$n", 'connected' => false];
    $check(count($bot->managedNodes()) === 7, 'H01: seven nodes before the race');
    $nested = false;
    $racing = new class extends AuditListsBot {
        public ?Closure $during = null;
        protected function managedNodeTransport(string $id, string $action, $value = null): array
        {
            if ($action === 'public' && $this->during) { $hook = $this->during; $this->during = null; $hook($this); }
            return parent::managedNodeTransport($id, $action, $value);
        }
    };
    $racing->pacState = $bot->pacState;
    $racing->during = static function (Bot $b) { $b->saveManagedNodeAdd('parallel'); };
    $racing->saveManagedNodeAdd('first');
    $check(count($racing->pacState['managed_nodes']) <= Bot::EXIT_MAX, 'H01: at most eight nodes after two parallel additions');
    echo "PASS H01 node limit\n";
});

// В02: snapshot files and WARP+ keys are asked for and read only in a private chat.
$run('В02:', static function () use ($id, $digest, $fresh, $call, $cb, $check) {
    $bot = $fresh(static function (&$node) { $node['status']['warp_egress'] = true; $node['status']['warp_account'] = true; $node['status']['options']['warp_mode'] = 'masque'; });
    $bot->input['chat'] = -1001234; $bot->input['from'] = 1;
    $bot->managedNodeImportPrompt($id);
    $bot->managedNodeWarpKeyPrompt($id);
    $check(!array_filter($bot->messages, static fn($m) => $m[0] === 'sendMessage'), 'B02: no secret prompt is sent to a group');
    $bot->input['file_id'] = 'fixture';
    $bot->managedNodeImportFile('', $id);
    $bot->saveNodeWarpKey('ABCDEFGH-12345678', $id);
    $check(!in_array('import', $bot->transports, true) && !in_array('public', $bot->transports, true) && $bot->submitted === [],
        'B02: a reply in a group is neither downloaded nor sent to the node');
    $check(str_contains(end($bot->screens)[0], 'личном чате'), 'B02: the admin is told to use the private chat');
    $bot->input['chat'] = 1;
    $bot->managedNodeWarpKeyPrompt($id);
    $check((bool) array_filter($bot->messages, static fn($m) => $m[0] === 'sendMessage'), 'B02: the private chat still gets the prompt');
    echo "PASS B02 private chat only\n";
});

// С21: restoring a snapshot with WARP warns that the registration is not in it.
$run('С21:', static function () use ($id, $digest, $fresh, $call, $cb, $check) {
    $restoring = new class extends AuditListsBot {
        protected function managedNodeTransport(string $id, string $action, $value = null): array
        {
            if ($action === 'restore-source') return ['snapshot' => ['options' => ['warp_mode' => 'masque']], 'hash' => str_repeat('a', 16)];
            return parent::managedNodeTransport($id, $action, $value);
        }
    };
    $restoring->pacState['managed_nodes'][$id]['job'] = null;
    $restoring->managedNodeRestore($id);
    $check(str_contains(end($restoring->screens)[0], 'Регистрация WARP хранится на самой ноде'), 'C21: restore names the WARP registration');
    echo "PASS C21 WARP registration warning\n";
});

// С17: the probe inbound authenticates its node; a neighbour's port does not answer for it.
$run('С17:', static function () use ($id, $digest, $fresh, $call, $cb, $check) {
    $probe = $fresh();
    $config = ['inbounds' => [], 'outbounds' => [['tag' => 'direct', 'protocol' => 'freedom']], 'routing' => ['rules' => []]];
    $probe->pacState['exits'] = ['aabbccdd' => ['name' => 'a', 'link' => $probe->profile['link'], 'enabled' => 1, 'fallback' => 'block', 'kind' => 'remote', 'routes' => [], 'rulesets' => []]
        + Bot::exitNodeDefaults()];
    $probe->ensureExitNodes($config, $probe->pacState);
    $inbound = array_values(array_filter($config['inbounds'], static fn($i) => ($i['tag'] ?? '') === Bot::EXIT_PROBE_TAG . 'aabbccdd'))[0] ?? [];
    $check(($inbound['settings']['auth'] ?? '') === 'password' && ($inbound['settings']['accounts'][0]['user'] ?? '') === 'probe-aabbccdd',
        'C17: the probe inbound has an account bound to the node ID');
    $command = $call($probe, 'exitProbeCommand', $probe->pacState['exits']['aabbccdd'], 10870, false, 'aabbccdd');
    $check(str_contains($command, "--proxy-user 'probe-aabbccdd:" . $inbound['settings']['accounts'][0]['pass'] . "'"), 'C17: the probe sends that account');
    echo "PASS C17 probe identity\n";
});

// С18: a node disabled between copy and removal takes nothing out of WARP.
$run('С18:', static function () use ($id, $digest, $fresh, $call, $cb, $check) {
    $moving = new class extends AuditListsBot {
        public function saveExitRoutes($text, $id, array $preset = []): bool
        {
            foreach ($preset as $entry) $this->pacState['exits'][$id]['routes'][$entry] = 1;
            // Another admin disables the node right after the copy.
            $this->pacState['exits'][$id]['enabled'] = 0;
            return true;
        }
        public function exitRoutesMenu(string $id, int $page = 0, string $notice = ''): void { $this->screens[] = [$notice, []]; }
        // The real list change runs its edit under the PAC lock; Xray and .dat are out of scope here.
        public function changeRouteList(string $type, callable $edit): bool
        {
            $list = $this->pacState[$type] ?? [];
            $edit($list);
            $this->pacState[$type] = $list;
            return true;
        }
    };
    $moving->pacState['warplist'] = ['moved.example' => 1];
    $moving->pacState['exits']['aabbccdd'] += ['routes' => [], 'rulesets' => [], 'kind' => 'remote'] + Bot::exitNodeDefaults();
    $moving->exitCopyRoutes('aabbccdd', 'move');
    $check(($moving->pacState['warplist']['moved.example'] ?? 0) === 1, 'C18: WARP keeps the entry of a node disabled meanwhile');
    echo "PASS C18 move checks the node in the same snapshot\n";
});

// С26 и Н08: one refresh per cache key; a lost write is an error, not a success.
$run('С26', static function () use ($id, $digest, $fresh, $call, $cb, $check) {
    $sets = new class extends AuditListsBot {
        public array $cacheState = []; public int $downloads = 0; public string $dir = '/proc/vpnbot-audit-no-such-dir';
        public ?Closure $whileWaiting = null;
        protected function exitRulesetDir(): string { return $this->dir; }
        public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null)
        {
            // Another worker finishes its refresh while this one waits for the lock.
            if ($this->whileWaiting && str_starts_with($name, 'exit-ruleset-')) { $hook = $this->whileWaiting; $this->whileWaiting = null; $hook($this); }
            return parent::withLock($name, $fn, $timeout, $busy);
        }
        public function exitRulesetCache(string $key): array { return $this->cacheState; }
        protected function exitRulesetDownload(string $url): ?string { $this->downloads++; return 'payload'; }
    };
    $parser = Bot::EXIT_RULESET_PARSER . ':srs:domain';
    $sets->cacheState = ['key' => 'https://lists.example/a.srs', 'time' => 1, 'error' => '', 'entries' => ['full:a.example'],
        'hash' => hash('sha256', 'payload'), 'parser' => $parser];
    $result = $sets->exitRulesetRefresh('https://lists.example/a.srs', ['behavior' => 'domain']);
    $check($result === 'save', 'H08: a cache that could not be written is reported');
    $check((bool) preg_grep('~^exit-ruleset-[a-f0-9]{32}$~', $sets->lockNames), 'C26: the refresh holds a lock of its cache key');
    $sets->whileWaiting = static function ($b) { $b->cacheState['time'] = time() + 5; };
    $sets->downloads = 0;
    $check($sets->exitRulesetRefresh('https://lists.example/a.srs', ['behavior' => 'domain']) === '' && $sets->downloads === 0,
        'C26: a copy refreshed while waiting is not downloaded again');
    echo "PASS C26/H08 rule set cache\n";
});

if ($failed) { fwrite(STDERR, "FAILED: " . implode(", ", $failed) . "\n"); exit(1); }
echo "node_audit_lists_test OK\n";
