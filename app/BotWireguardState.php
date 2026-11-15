<?php

trait BotWireguardState
{
    private bool $wireguardApplyCommit = false;

    protected function wireguardPendingPath(): string
    {
        return ($this->getInstanceWG() === 'wg1' ? $this->clients1 : $this->clients) . '.wg-apply.pending.json';
    }

    public function hasWireguardPending(): bool
    {
        $path = $this->wireguardPendingPath();
        return file_exists($path) || is_link($path);
    }

    private function readWireguardPending(): ?array
    {
        if (!$this->hasWireguardPending()) return null;
        $path = $this->wireguardPendingPath();
        if (is_link($path) || !is_file($path)) throw new RuntimeException('WireGuard pending state is unavailable');
        $intent = json_decode((string) file_get_contents($path), true);
        if (!is_array($intent) || ($intent['version'] ?? null) !== 1 || ($intent['service'] ?? '') !== $this->getInstanceWG()
            || !preg_match('~^[a-f0-9]{32}$~D', $intent['id'] ?? '') || !is_string($intent['config'] ?? null)
            || !in_array($intent['phase'] ?? '', ['pending', 'applied'], true) || !is_bool($intent['switch'] ?? null)
            || !array_key_exists('clients', $intent) || ($intent['clients'] !== null && !is_array($intent['clients']))
            || !is_array($intent['remap'] ?? null)) throw new RuntimeException('WireGuard pending state is invalid');
        return $intent;
    }

    // Никаких скрытых повторных SSH-команд: незаконченный apply блокирует
    // новый RMW до явного retry из cron или оператора.
    public function withWireguardUpdate(callable $fn, ?string $service = null)
    {
        return $this->withWireguardLock(function () use ($fn) {
            if (!$this->wireguardApplyCommit && $this->hasWireguardPending()) {
                throw new RuntimeException($this->t('WireGuard: предыдущая операция ожидает подтверждения; cron повторит её', 'WireGuard: the previous operation is awaiting confirmation; cron will retry it'));
            }
            return $fn();
        }, $service);
    }

    private function writeWireguardPending(array $intent): bool
    {
        $json = json_encode($intent, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        return $json !== false && $this->writePrivateKey($this->wireguardPendingPath(), $json);
    }

    private function clearWireguardPending(): bool
    {
        $path = $this->wireguardPendingPath();
        if (!@unlink($path)) return false;
        $dir = @fopen(dirname($path), 'r');
        if ($dir === false) return false;
        try { return fsync($dir); } finally { fclose($dir); }
    }

    protected function verifyWireguardPeers(string $config): bool
    {
        $parsed = $this->parseWireGuardConfig($config);
        if (empty($parsed['interface'])) return false;
        $expected = [];
        foreach ($parsed['peers'] ?? [] as $peer) {
            if (isset($peer['PublicKey'])) $expected[] = $peer['PublicKey'];
        }
        $out = $this->ssh($this->getWGType() . " show wg0 peers && printf '\\nVPNBOT_WG_PEERS_READY\\n'", $this->getInstanceWG());
        if ($this->sshFailed) return false;
        $lines = preg_split('~\s+~', trim((string) $out), -1, PREG_SPLIT_NO_EMPTY);
        if (!$lines || array_pop($lines) !== 'VPNBOT_WG_PEERS_READY') return false;
        sort($expected); sort($lines);
        return $expected === $lines;
    }

    private function applyWireguardPendingLocked(array $intent): bool
    {
        if ($intent['phase'] !== 'applied') {
            if ($this->restartWG($intent['config'], $intent['switch']) === false || !$this->verifyWireguardPeers($intent['config'])) return false;
            $this->wireguardApplyCommit = true;
            try {
                if ($intent['clients'] !== null && $this->saveClients($intent['clients']) === false) return false;
            } finally { $this->wireguardApplyCommit = false; }
            $intent['phase'] = 'applied';
            if (!$this->writeWireguardPending($intent)) return false;
        }
        return $intent['remap'] ? true : $this->clearWireguardPending();
    }

    public function applyWgConfig(string $conf, ?array $clients = null, bool $switch = false, array $remap = []): bool
    {
        return $this->withWireguardLock(function () use ($conf, $clients, $switch, $remap) {
            if ($this->hasWireguardPending() || empty($this->parseWireGuardConfig($conf)['interface'])) return false;
            $intent = ['version' => 1, 'id' => bin2hex(random_bytes(16)), 'service' => $this->getInstanceWG(),
                'phase' => 'pending', 'config' => $conf, 'clients' => $clients, 'switch' => $switch, 'remap' => $remap];
            // Intent появляется раньше SSH и раньше изменения clients.json.
            if (!$this->writeWireguardPending($intent)) return false;
            return $this->applyWireguardPendingLocked($intent);
        }, null, 20, false) === true;
    }

    // Вызывать вне WG-lock: привязки Xray обновляются в порядке без WG→xray.
    public function completeWireguardRemap(?string $service = null): bool
    {
        if ($this->wireguardLockService !== null) return false;
        $service ??= $this->getInstanceWG();
        $intent = $this->withWireguardLock(fn() => $this->readWireguardPending(), $service);
        if ($intent === null) return true;
        if (!is_array($intent) || $intent['phase'] !== 'applied') return false;
        if ($intent['remap']) $this->xrayConfUpdate(function (&$xr) use ($intent) {
            $xr = $this->remapVlessAwgLinks($xr, $intent['remap']);
        }, true);
        return $this->withWireguardLock(function () use ($intent) {
            $current = $this->readWireguardPending();
            if ($current === null) return true;
            return hash_equals($current['id'], $intent['id']) && $this->clearWireguardPending();
        }, $service, 20, false) === true;
    }

    public function retryWireguardApply(): bool
    {
        $service = $this->getInstanceWG(); $needsRemap = false;
        $ok = $this->withWireguardLock(function () use (&$needsRemap) {
            $intent = $this->readWireguardPending();
            $needsRemap = !empty($intent['remap']);
            return $intent === null || $this->applyWireguardPendingLocked($intent);
        }, $service, 20, false);
        if ($ok !== true) return false;
        return !$needsRemap || $this->completeWireguardRemap($service);
    }
}
