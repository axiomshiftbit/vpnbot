<?php

class XrayStatsUnavailable extends RuntimeException {}

trait BotXrayStats
{
    private int $xrayStatsLockDepth = 0;
    private bool $xrayStatsResetting = false;

    // Re-entry belongs to this instance and this one fixed lock only. The outer
    // xray/apply locks must precede it; no restart or RPC while holding it.
    private function withXrayStatsLock(callable $fn)
    {
        if ($this->xrayStatsLockDepth) return $fn();
        $entered = false;
        $result = $this->withLock('xray-stats', function () use ($fn, &$entered) {
            $entered = true;
            $this->xrayStatsLockDepth++;
            try { return $fn(); }
            finally { $this->xrayStatsLockDepth--; }
        }, 30);
        if (!$entered) throw new XrayStatsUnavailable('Xray statistics lock is unavailable');
        return $result;
    }

    private static function normalizeXrayStats(array $stats): array
    {
        $fail = static function () { throw new XrayStatsUnavailable('Xray statistics schema is invalid'); };
        if (array_diff_key($stats, array_flip(['_schema', 'global', 'session', 'users', 'inbounds', 'exits', 'group_epochs']))) $fail();
        if (array_key_exists('group_epochs', $stats)) {
            if (!is_array($stats['group_epochs'])) $fail();
            foreach ($stats['group_epochs'] as $source => $epoch) {
                if (($source !== 'all' && !preg_match('/^[a-f0-9]{32}$/D', (string) $source)) || !is_string($epoch) || !preg_match('/^[a-f0-9]{16}$/D', $epoch)) $fail();
            }
        }
        $versioned = array_key_exists('_schema', $stats);
        if ($versioned && ($stats['_schema'] !== 1 || !isset($stats['global'], $stats['session'], $stats['users']))) $fail();
        $pair = static function ($value, array $keys) use ($fail): void {
            if (!is_array($value) || count($value) !== count($keys)) $fail();
            foreach ($keys as $key) if (!is_int($value[$key] ?? null) || $value[$key] < 0) $fail();
        };
        foreach (['global', 'session'] as $key) if (array_key_exists($key, $stats)) $pair($stats[$key], ['upload', 'download']);
        foreach (['users', 'inbounds', 'exits'] as $key) if (array_key_exists($key, $stats) && !is_array($stats[$key])) $fail();
        foreach ($stats['users'] ?? [] as $index => $row) {
            if (!is_int($index) || $index < 0 || !is_array($row) || array_diff_key($row, array_flip(['global', 'session']))) $fail();
            if (!$row) $fail();
            foreach (['global', 'session'] as $key) {
                if (array_key_exists($key, $row)) $pair($row[$key], ['upload', 'download']);
                elseif ($versioned) $fail();
                else $row[$key] = ['upload' => 0, 'download' => 0];
            }
            $stats['users'][$index] = $row;
        }
        foreach ($stats['inbounds'] ?? [] as $row) $pair($row, ['upload', 'download']);
        foreach ($stats['exits'] ?? [] as $row) {
            if (!is_array($row) || array_diff_key($row, array_flip(['global', 'session', 'base', 'since', 'modes']))
                || !is_int($row['since'] ?? null) || $row['since'] < 0) $fail();
            if (array_key_exists('modes', $row)) {
                $modes = $row['modes'];
                if (!is_array($modes) || count($modes) !== 4 || !is_int($modes['since'] ?? null) || $modes['since'] < 0
                    || !is_array($modes['raw'] ?? null) || count($modes['raw']) !== 2) $fail();
                foreach (['node', 'warp'] as $mode) {
                    $pair($modes[$mode] ?? null, ['up', 'down']);
                    $pair($modes['raw'][$mode] ?? null, ['up', 'down']);
                }
            }
            foreach (['global', 'session', 'base'] as $key) $pair($row[$key] ?? null, ['up', 'down']);
        }
        return $stats + ['_schema' => 1, 'global' => ['upload' => 0, 'download' => 0],
            'session' => ['upload' => 0, 'download' => 0], 'users' => []];
    }

    public function getXrayStats()
    {
        return $this->withXrayStatsLock(function () {
            $path = dirname($this->xrayConf) . '/xray.stats'; $marker = $path . '.initialized';
            if (is_link($path) || is_link($marker) || (file_exists($marker) && !is_file($marker))) {
                throw new XrayStatsUnavailable('Xray statistics storage is invalid');
            }
            $raw = @file_get_contents($path);
            if ($raw === false) {
                $clients = $this->getXray()['inbounds'][0]['settings']['clients'] ?? null;
                if (file_exists($path) || is_file($marker) || $clients !== []) {
                    throw new XrayStatsUnavailable('Xray statistics are unavailable');
                }
                // Only an empty installation may bootstrap without a ledger.
                $stats = [];
            } else {
                try { $stats = json_decode($raw, true, 512, JSON_THROW_ON_ERROR); }
                catch (JsonException $error) { throw new XrayStatsUnavailable('Xray statistics JSON is invalid', 0, $error); }
                if (!is_array($stats) || ($stats === [] && trim($raw) !== '[]')
                    || (is_file($marker) && (($stats['_schema'] ?? null) !== 1 || @file_get_contents($marker) !== "1\n"))) {
                    throw new XrayStatsUnavailable('Xray statistics are not initialized');
                }
            }
            $normalized = self::normalizeXrayStats($stats);
            if (!is_file($marker) || $normalized !== $stats) {
                if ($this->setXrayStats($normalized) === false) throw new XrayStatsUnavailable('Xray statistics initialization failed');
            }
            return $normalized;
        });
    }

    public function setXrayStats($stats)
    {
        if (!is_array($stats)) throw new XrayStatsUnavailable('Xray statistics must be an array');
        $stats = self::normalizeXrayStats($stats);
        return $this->withXrayStatsLock(function () use ($stats) {
            $path = dirname($this->xrayConf) . '/xray.stats'; $marker = $path . '.initialized';
            if (is_link($path) || is_link($marker) || (file_exists($marker) && !is_file($marker))) return false;
            // A failed or interrupted publication remains unknown, including
            // failure after the ledger rename. Readers share this lock.
            if (!$this->writePrivateKey($marker, "pending\n")) return false;
            if (!$this->writePrivateKey($path, json_encode($stats, JSON_THROW_ON_ERROR))) return false;
            return $this->writePrivateKey($marker, "1\n");
        });
    }

    private function guardXrayUnknownStats(array $config): array
    {
        try { $this->getXrayStats(); return $config; }
        catch (XrayStatsUnavailable $error) {}
        foreach ($config['inbounds'][0]['settings']['clients'] as &$client) {
            if ((int) ($client['traffic'] ?? 0) <= 0 || !empty($client['off'])) continue;
            $client['off'] = $client['id']; $client['id'] = self::xrayUuid();
            if (isset($client['password'])) { $client['off_pwd'] = $client['password']; $client['password'] = self::xrayUuid(); }
            $client['traffic_off'] = 1; $client['traffic_usage_unavailable'] = 1;
        }
        unset($client);
        return $config;
    }

    private function xrayQuotaUnavailableOrExhausted(array $client, int|string $index): bool
    {
        $limit = (int) ($client['traffic'] ?? 0);
        if ($limit <= 0) return false;
        try { return $this->xrUserTraffic($this->getXrayStats(), $index) + array_sum($this->xrayProtocolUsage($client)) >= $limit; }
        catch (Throwable $error) { return true; }
    }

    private function restoreBackupXraySnapshot(array $config, ?array $stats): bool
    {
        return $this->withLock('xray', fn() => $this->withXrayApplyLock(function () use ($config, $stats) {
            $beforeClients = $this->getXray()['inbounds'][0]['settings']['clients'] ?? null;
            try { $before = $this->getXrayStats(); }
            catch (XrayStatsUnavailable $error) { $before = null; }
            $applied = false;
            try {
                if ($stats === null) {
                    // A config-only restore changes the index-to-client map;
                    // the previous ledger cannot authorize the new clients.
                    if (!$this->writePrivateKey(dirname($this->xrayConf) . '/xray.stats.initialized', "unavailable\n")) return false;
                } elseif ($this->setXrayStats($stats) === false) return false;
                // Restored session counters must not meet the old live session.
                $this->xrayStatsResetting = true;
                return $applied = $this->restoreBackupXrayLocked($config);
            } finally {
                $this->xrayStatsResetting = false;
                if (!$applied) {
                    $restored = $this->rollbackXrayStats($before, $beforeClients);
                    if (!$restored) throw new RuntimeException('Xray statistics rollback failed', self::BACKUP_PARTIAL);
                }
            }
        }), 30, false) === true;
    }

    // Caller owns xray. Pin apply while comparing the published client order
    // and restoring its counters: restart may return false AFTER writing it.
    private function rollbackXrayStats(?array $stats, ?array $clients): bool
    {
        return $this->withXrayApplyLock(function () use ($stats, $clients) {
            try { $current = $this->getXray()['inbounds'][0]['settings']['clients'] ?? null; }
            catch (Throwable $error) { $current = null; }
            if ($stats !== null && $clients !== null && $current === $clients) return $this->setXrayStats($stats) !== false;
            return $this->withXrayStatsLock(fn() => $this->writePrivateKey(dirname($this->xrayConf) . '/xray.stats.initialized', "unavailable\n"));
        }) === true;
    }
}
