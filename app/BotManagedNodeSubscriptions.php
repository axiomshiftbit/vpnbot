<?php

/** HTTPS credentials belong to one external peer, never to the controller. */
trait BotManagedNodeSubscriptions
{
    private function managedNodeSubscriptionUrl(string $id, string $key): string
    {
        $domain = $this->getDomain();
        if (!$domain || !$this->nginxGetTypeCert()) throw new RuntimeException('Configure controller HTTPS first');
        $token = '';
        $this->managedNodeWrite($id, function (&$node) use ($id, $key, &$token) {
            $peer = $this->managedNodePeer($id, $key);
            if (!$peer || !$peer['enabled'] || ($peer['channel'] ?? 'vless') !== 'vless' || !empty($node['job'])) throw new RuntimeException('Peer unavailable');
            // Remove retired identities so repeated rotations cannot grow the backup indefinitely.
            $keys = array_map(static fn($p) => self::exitEntryKey($p['id']), $this->managedNodePeers($id));
            $node['subscriptions'] = array_intersect_key($node['subscriptions'] ?? [], array_flip($keys));
            $record = $node['subscriptions'][$key] ?? [];
            if (($record['peer'] ?? '') !== $peer['id'] || !preg_match('~^[a-f0-9]{64}$~D', $record['token'] ?? '')) {
                $record = ['peer' => $peer['id'], 'token' => bin2hex(random_bytes(32))];
            }
            $node['subscriptions'][$key] = $record;
            $token = $record['token'];
        });
        return 'https://' . $domain . '/pac' . $this->getHashBot() . "/node/$id/$token/sub";
    }

    /** Return null for every invalid capability before making an SSH request. */
    public function managedNodeSubscriptionDocument(string $id, string $token, string $format): ?array
    {
        if (!preg_match('~^[a-f0-9]{8}$~D', $id) || !preg_match('~^[a-f0-9]{64}$~D', $token)
            || !in_array($format, ['sub', 'json'], true)) return null;
        $node = $this->managedNodes()[$id] ?? null;
        if (!$node || !$node['connected']) return null;
        $peer = null;
        foreach ($this->managedNodePeers($id) as $candidate) {
            $record = $node['subscriptions'][self::exitEntryKey($candidate['id'])] ?? [];
            if ($candidate['enabled'] && ($candidate['channel'] ?? 'vless') === 'vless' && ($record['peer'] ?? '') === $candidate['id']
                && is_string($record['token'] ?? null) && hash_equals($record['token'], $token)) { $peer = $candidate; break; }
        }
        if (!$peer) return null;
        $this->subRateLimit('node:' . $id . ':' . self::exitEntryKey($peer['id']));
        $document = null;
        $this->managedNodeLocked($id, function () use ($id, $peer, $format, &$document) {
            $node = $this->managedNodes()[$id] ?? [];
            if (!empty($node['job']) || !empty($node['recovery_required'])) throw new RuntimeException('Node change pending');
            // Check the remote generation before and after profile retrieval. Never publish an unconfirmed profile.
            $status = $this->managedNodeRpc($id, ['action' => 'status']);
            if (!empty($status['pending']) || empty($status['generation']) || $status['generation'] !== ($node['status']['generation'] ?? '')) {
                throw new RuntimeException('Node state not confirmed');
            }
            $remote = array_filter($this->managedNodePeers($id, $status), static fn($p) => $p['id'] === $peer['id'] && $p['enabled'] && ($p['channel'] ?? 'vless') === 'vless');
            if (!$remote) throw new RuntimeException('Peer no longer available');
            $profile = $this->managedNodeRpc($id, ['action' => 'profile', 'peer' => $peer['id']]);
            if (($profile['channel'] ?? 'vless') !== 'vless') throw new RuntimeException('Peer channel changed');
            $parsed = ManagedNodeProfile::parse($profile, (string) ($status['options']['core'] ?? 'origin'));
            if (($parsed['outbound']['settings']['vnext'][0]['users'][0]['id'] ?? '') !== $peer['id']) throw new RuntimeException('Wrong peer');
            $after = $this->managedNodeRpc($id, ['action' => 'status']);
            if (!empty($after['pending']) || ($after['generation'] ?? '') !== $status['generation']) throw new RuntimeException('Node changed during export');
            $document = ['mime' => $format === 'sub' ? 'text/plain' : 'application/json', 'name' => $peer['name'],
                'body' => $format === 'sub' ? base64_encode($profile['link'] . "\n")
                    : json_encode($parsed['managed_outbound'] + ['tag' => $peer['name']], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)];
        });
        return $document;
    }

    public function managedNodeSubscription(string $id, string $token, string $format): void
    {
        $this->subSecurityHeaders();
        try {
            if (!in_array($_SERVER['REQUEST_METHOD'] ?? 'GET', ['GET', 'HEAD'], true)) { http_response_code(405); return; }
            $document = $this->managedNodeSubscriptionDocument($id, $token, $format);
            if ($document === null) { $this->subRateLimit('', 'miss'); http_response_code(404); return; }
            header('Content-Type: ' . $document['mime'] . '; charset=utf-8');
            header('Profile-Title: base64:' . base64_encode($document['name']));
            header('Profile-Update-Interval: 12');
            if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'HEAD') echo $document['body'];
        } catch (Throwable $e) {
            http_response_code(503); header('Retry-After: 30');
            echo 'Subscription temporarily unavailable';
        }
    }
}
