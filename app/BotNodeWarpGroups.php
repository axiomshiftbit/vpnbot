<?php

trait BotNodeWarpGroups
{
    private function exitWarpAvailable(array $node, array $nodes): bool
    {
        if (($node['kind'] ?? '') !== 'group') return isset($node['managed_profile']['warp_uuid']);
        foreach ($node['members'] as $member) if (isset($nodes[$member]['managed_profile']['warp_uuid'])) return true;
        return false;
    }

    /** Return a first-choice verified WARP egress or a blackhole. Never inherit the ordinary group fallback. */
    public function exitWarpGroupTarget(array $group, array $nodes, array $status, int $now): string
    {
        $recovering = null;
        foreach ($group['members'] as $member) {
            $node = $nodes[$member] ?? [];
            $uuid = $node['managed_profile']['warp_uuid'] ?? '';
            $probe = $status[$member]['warp_health'] ?? [];
            $age = $now - (int) ($probe['time'] ?? 0);
            if (!$uuid || empty($node['enabled']) || !empty($group['warp_drained'][$member]) || $age < 0 || $age > 2 * self::EXIT_CRON_PERIOD
                || ($probe['profile'] ?? '') !== hash('sha256', $uuid) || ($probe['https'] ?? '') !== 'ok' || ($probe['udp'] ?? '') !== 'ok') continue;
            try {
                $normal = $this->exitNodeOutbound($node);
                if (!$normal) continue;
                ManagedNodeProfile::warpOutbound($normal, $uuid);
            } catch (InvalidArgumentException $e) { continue; }
            $target = self::EXIT_TAG . 'warp-' . $member;
            if (empty($probe['recovered']) || $now - $probe['recovered'] >= 2 * self::EXIT_CRON_PERIOD) return $target;
            $recovering ??= $target;
        }
        return $recovering ?? 'block';
    }

    public function exitGroupWarpOrder(string $id, string $member, string $action): void
    {
        $error = $this->exitEditNode($id, static function (&$node) use ($member, $action) {
            if ($node['kind'] !== 'group' || !in_array($member, $node['members'], true)) return 'exit stale';
            if ($action === 'first') $node['members'] = [$member, ...array_values(array_diff($node['members'], [$member]))];
            elseif ($action === 'pause') $node['warp_drained'][$member] = true;
            elseif ($action === 'resume') unset($node['warp_drained'][$member]);
            return '';
        });
        $this->exitGroupMenu($id, $error === '' ? '' : $this->exitError($error));
    }

    private function exitGroupWarpChanged(): bool
    {
        $live = $this->getXray();
        if (!is_array($live)) return false;
        $nodes = $this->exitNodes();
        $groups = array_keys(array_filter($nodes, static fn($node) => $node['kind'] === 'group'));
        $used = [];
        foreach ($live['inbounds'][0]['settings']['clients'] ?? [] as $client) {
            foreach (array_intersect((array) ($client['exit_warp'] ?? []), $groups) as $id) $used[(string) $id] = true;
        }
        if (!$used) return false;
        $extract = static function ($x) use ($used) {
            $result = [];
            foreach ($x['routing']['rules'] ?? [] as $r) {
                $tag = $r['ruleTag'] ?? '';
                if (preg_match('~^vpnbot:exit:(?:warp-([0-9a-f]{8}):|([0-9a-f]{8}):warp-)~', $tag, $m) && isset($used[$m[1] ?: $m[2]])) {
                    $result[$tag] = $r['outboundTag'] ?? '';
                }
            }
            return $result;
        };
        $next = $live;
        $this->ensureExitNodes($next);
        return $extract($next) !== $extract($live);
    }
}
