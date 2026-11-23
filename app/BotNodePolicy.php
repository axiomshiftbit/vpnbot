<?php

trait BotNodePolicy
{
    /** Expand only active controller IP rules. A broken asset must never become an empty allow list. */
    private function controllerBlockedIps(array $config): array
    {
        $ips = [];
        foreach ($config['routing']['rules'] ?? [] as $rule) {
            if (($rule['ruleTag'] ?? '') !== 'vpnbot:routes:block:ip') continue;
            foreach ($rule['ip'] as $raw) {
                $entry = $this->classifyRouteEntry($raw);
                if ($entry['kind'] === 'ext') $entry['kind'] = 'extip';
                if (in_array($entry['kind'], ['extip', 'geoip'], true)) {
                    $expanded = $this->nodePolicyDat($entry);
                    if (!$expanded) throw new RuntimeException('Empty IP category');
                    foreach ($expanded as $ip) $ips[$ip] = true;
                } elseif ($entry['kind'] === 'ip' && $entry['value'] !== '') {
                    $ips[$entry['value']] = true;
                } else {
                    throw new RuntimeException('Unsupported controller IP rule');
                }
            }
        }
        $list = array_keys($ips);
        sort($list, SORT_STRING);
        return $list;
    }

    /**
     * Digest of controllerBlockedIps() (null: no blocks). Expanding the categories takes
     * seconds, so the digest is cached by the rule entries and their asset files.
     */
    private function controllerBlockedIpsDigest(array $config): ?string
    {
        $entries = [];
        foreach ($config['routing']['rules'] ?? [] as $rule) {
            if (($rule['ruleTag'] ?? '') === 'vpnbot:routes:block:ip') $entries[] = $rule['ip'];
        }
        if (!$entries) return null;
        $assets = [];
        foreach (array_merge(...$entries) as $raw) {
            $entry = $this->classifyRouteEntry($raw);
            if (!in_array($entry['kind'], ['ext', 'extip', 'geoip'], true)) continue;
            $file = isset(self::CORE_DAT[$entry['kind']]) ? self::CORE_DAT[$entry['kind']] : explode(':', $entry['value'], 2)[0];
            if (!preg_match('~^[a-zA-Z0-9_.-]+\.dat$~D', $file)) return self::controllerIpsDigest($this->controllerBlockedIps($config));
            $path = $this->datPath($this->datResolve($file));
            clearstatcache(true, $path);
            $stat = @stat($path);
            if ($stat === false) return self::controllerIpsDigest($this->controllerBlockedIps($config));
            $assets[$path] = [$stat['size'], $stat['mtime'], $stat['ctime'], $stat['ino']];
        }
        $encoded = json_encode([$entries, $assets]);
        // Without a key the cache could answer for different rules.
        if ($encoded === false) return self::controllerIpsDigest($this->controllerBlockedIps($config));
        $key = hash('sha256', $encoded);
        $cache = sys_get_temp_dir() . '/vpnbot-controller-ips.json';
        // The digest decides whether a node enforces the list: trust only a root-owned regular
        // file (the bot runs as root; elsewhere the cache is simply skipped).
        clearstatcache(true, $cache);
        $owned = is_file($cache) && !is_link($cache) && @fileowner($cache) === 0;
        $saved = $owned ? @json_decode((string) @file_get_contents($cache), true) : null;
        if (is_array($saved) && ($saved['key'] ?? '') === $key && array_key_exists('digest', $saved)
            && ($saved['digest'] === null || (is_string($saved['digest']) && preg_match('~^[a-f0-9]{64}$~D', $saved['digest'])))) return $saved['digest'];
        $digest = self::controllerIpsDigest($this->controllerBlockedIps($config));
        $tmp = @tempnam(sys_get_temp_dir(), 'vpnbot-controller-ips-');
        if ($tmp !== false) {
            if (@file_put_contents($tmp, json_encode(['key' => $key, 'digest' => $digest])) === false || !@rename($tmp, $cache)) @unlink($tmp);
        }
        return $digest;
    }

    /** Expanded IP categories reach tens of thousands of CIDRs; pac.json keeps only this digest. */
    private static function controllerIpsDigest(array $ips): ?string
    {
        return $ips ? hash('sha256', implode("\n", $ips)) : null;
    }

    private static function policyIpsDigest(array $policy): ?string
    {
        return $policy['controller_ips_digest'] ?? self::controllerIpsDigest($policy['controller_ips'] ?? []);
    }

    private static function compactNodePolicy(array $policy): array
    {
        if (array_key_exists('controller_ips', $policy)) {
            $digest = self::controllerIpsDigest((array) $policy['controller_ips']);
            unset($policy['controller_ips']);
            if ($digest !== null) $policy['controller_ips_digest'] = $digest;
        }
        // Expanded geodata and sets can be as large as the controller list; the source stays in managed_nodes[*].lists.
        if (array_key_exists('routes', $policy)) {
            $policy['routes_digest'] = hash('sha256', json_encode($policy['routes'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
            unset($policy['routes']);
        }
        return $policy;
    }

    /** Several copies of the expanded list (status, draft, route, job) exhausted PHP memory. */
    protected static function compactNodePolicies(array $pac): array
    {
        // The named list library and per-user node rules are gone; shared blocks move to the node Block list.
        unset($pac['node_policy_lists']);
        foreach ($pac['managed_nodes'] ?? [] as $id => $node) {
            if (!is_array($node)) continue;
            if (!isset($node['lists'])) {
                $legacy = self::nodeRoutesLegacy($node);
                if ($legacy['block']['routes']) $pac['managed_nodes'][$id]['lists'] = $legacy + ['warp' => ['routes' => [], 'rulesets' => []]];
            }
            foreach ([['status', 'options'], ['draft'], ['job', 'before'], ['job', 'draft', 'draft']] as $path) {
                $target = &$pac['managed_nodes'][$id];
                foreach ($path as $key) {
                    if (!is_array($target[$key] ?? null)) { unset($target); continue 2; }
                    $target = &$target[$key];
                }
                if (is_array($target['policy'] ?? null)) $target['policy'] = self::compactNodePolicy($target['policy']);
                unset($target);
            }
        }
        foreach ($pac['exits'] ?? [] as $id => $exit) {
            if (is_array($exit['policy'] ?? null)) $pac['exits'][$id]['policy'] = self::compactNodePolicy($exit['policy']);
        }
        return $pac;
    }

    private function withControllerIps(array $options, array $ips): array
    {
        $policy = $options['policy'] ?? ['lists' => [], 'bindings' => []];
        $same = self::policyIpsDigest($policy) === self::controllerIpsDigest($ips);
        // The node needs the expanded list itself; the stored digest only identifies it.
        unset($policy['controller_ips_digest']);
        if ($ips) $policy['controller_ips'] = $ips;
        else unset($policy['controller_ips']);
        if (!$same) $policy['revision'] = bin2hex(random_bytes(16));
        if ($ips || !empty($policy['bindings']) || !empty($policy['lists']) || !empty($policy['routes'])) $options['policy'] = $policy;
        else unset($options['policy']);
        return $options;
    }

    private function syncControllerIps(string $id): void
    {
        $this->managedNodeLocked($id, function () use ($id) {
            $node = $this->managedNodes()[$id] ?? [];
            if (empty($node['connected']) || empty($node['status']['controller_ip_guard']) || !empty($node['job'])
                || isset($node['draft']) || !empty($node['recovery_required']) || !empty($node['status']['pending'])) return;
            $options = $node['status']['options'];
            $config = $this->getXray();
            if (!is_array($config) || !isset($config['routing']['rules'])) return;
            if (self::policyIpsDigest($options['policy'] ?? []) !== $this->controllerBlockedIpsDigest($config)) {
                // The PAC contains only digests. Take the applied rules from the node:
                // an IP refresh must neither publish local edits nor mark them as applied.
                $running = $this->managedNodeRpc($id, ['action' => 'status']);
                if (!empty($running['pending']) || !is_array($running['options'] ?? null)
                    || ($running['generation'] ?? null) !== $node['status']['generation']) return;
                $this->managedNodeSubmitLocked($id, 'configure', $running['options'], $running['generation'], false);
                return;
            }
            // A restored node can accept a different policy identity, even with no shared IP blocks.
            $before = $this->exitNodes()[$id] ?? null;
            $remote = $options['policy'] ?? [];
            $local = $before['policy'] ?? [];
            if ($remote !== $local) {
                $profile = $this->managedNodeRpc($id, ['action' => 'profile', 'peer' => null]);
                if ($this->managedNodeUseProfile($id, $profile, $options) !== '') return;
                try {
                    if (!$this->managedNodeTrafficReady($id)) throw new RuntimeException('Node traffic probe failed');
                } catch (Throwable $error) {
                    $this->managedNodeRestoreClient($id, $before);
                    throw $error;
                }
            }
        });
    }

    protected function nodePolicyDat(array $entry): array
    {
        $ip = in_array($entry['kind'], ['geoip', 'extip'], true);
        if (isset(self::CORE_DAT[$entry['kind']])) {
            $file = self::CORE_DAT[$entry['kind']];
            $category = $entry['value'];
        } else {
            [$file, $category] = array_pad(explode(':', $entry['value'], 2), 2, '');
        }
        if (!preg_match('~^[a-zA-Z0-9_.-]+\.dat$~D', $file) || !preg_match('~^[a-zA-Z0-9_-]+$~D', $category)
            || $this->datCategoryError($entry) !== null) throw new InvalidArgumentException();
        $path = $this->datPath($this->datResolve($file));
        $tmp = tempnam(sys_get_temp_dir(), 'node-list-');
        if ($tmp === false) throw new RuntimeException();
        try {
            $cmd = ['python3', __DIR__.'/exit_ruleset.py', 'dat', $path, $tmp, $ip ? 'ip' : 'domain', $category];
            if (!$this->exitRulesetTool($cmd)) throw new InvalidArgumentException();
            return json_decode(file_get_contents($tmp), true, 32, JSON_THROW_ON_ERROR);
        } finally { unlink($tmp); }
    }

}
