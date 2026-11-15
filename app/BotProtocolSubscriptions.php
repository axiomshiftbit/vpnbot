<?php

trait BotProtocolSubscriptions
{
    private function xrayProtocolUsageRows(ManagedProtocol $store, array $state): array
    {
        $usage = $store->usage();
        if ($usage === [] && !$state['users']) return [];
        if (!is_array($usage['users'] ?? null)) throw new RuntimeException('Protocol usage is unavailable');
        foreach ($usage['users'] as $row) {
            if (!is_array($row) || !is_int($row['upload'] ?? null) || !is_int($row['download'] ?? null)
                || $row['upload'] < 0 || $row['download'] < 0 || !is_string($row['reset'] ?? null)) {
                throw new RuntimeException('Protocol usage is invalid');
            }
        }
        return $usage['users'];
    }

    public function xrayProtocolUsage(array $client): array
    {
        $source = ManagedProtocol::xraySource($client); $total = ['upload' => 0, 'download' => 0];
        foreach (array_keys(ManagedProtocol::NAMES) as $protocol) {
            $store = $this->protocolStore($protocol);
            if (!file_exists($store->directory() . '/desired.json') && !is_link($store->directory() . '/desired.json')) continue;
            $state = $store->read(); $usage = null;
            foreach ($state['users'] as $id => $user) {
                if (($user['xray_source'] ?? '') !== $source) continue;
                $usage ??= $this->xrayProtocolUsageRows($store, $state);
                $bytes = $usage[$id] ?? [];
                if (($bytes['reset'] ?? '') !== $user['reset']) throw new RuntimeException($this->t('Общий расход недоступен; дождитесь подтверждения счётчиков', 'Shared usage is unavailable; wait for confirmed counters'));
                foreach ($total as $direction => $_) $total[$direction] += $bytes[$direction];
            }
        }
        return $total;
    }

    public function syncXrayProtocolUsers(): void
    {
        if (!is_dir($this->protocolRoot)) return;
        // Snapshot config and its indexed ledger only outside an in-flight
        // reset/delete/restore. Order: apply -> xray-sync -> xray-stats.
        $entered = false;
        $this->withXrayApplyLock(function () use (&$entered) {
            $entered = true;
            $this->syncXrayProtocolUsersWithApplyLock();
        });
        if (!$entered) throw new RuntimeException('Could not lock the Xray protocol snapshot');
    }

    private function syncXrayProtocolUsersWithApplyLock(): void
    {
        // Serialize the snapshot AND its application across cron and UI workers.
        // Per-protocol write locks alone let an older snapshot undo a revocation.
        $old = umask(0077);
        $lock = @fopen($this->protocolRoot . '/xray-sync.lock', 'c');
        umask($old);
        if (!$lock) throw new RuntimeException($this->t('Не удалось открыть блокировку синхронизации протоколов', 'Could not open the protocol sync lock'));
        try {
            if (!flock($lock, LOCK_EX)) throw new RuntimeException($this->t('Не удалось заблокировать синхронизацию протоколов', 'Could not lock the protocol sync'));
            $this->syncXrayProtocolUsersLocked();
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    private function syncXrayProtocolUsersLocked(): void
    {
        $stores = [];
        foreach (array_keys(ManagedProtocol::NAMES) as $protocol) {
            $store = $this->protocolStore($protocol);
            if (file_exists($store->directory() . '/desired.json') || is_link($store->directory() . '/desired.json')) $stores[$protocol] = $store;
        }
        if (!$stores) return;
        // The trusted source snapshot is independent of every derived store.
        // xray-sync.lock still covers this read AND every following update.
        $xray = $this->getXray();
        if (!is_array($xray) || !is_array($xray['inbounds'][0]['settings']['clients'] ?? null)) {
            throw new RuntimeException($this->t('Не удалось прочитать пользователей VLESS для синхронизации', 'Could not read VLESS users for the sync'));
        }
        $states = []; $usage = []; $totals = []; $unknown = []; $unknownAll = false; $errors = []; $failed = false;
        foreach ($stores as $protocol => $store) {
            try { $states[$protocol] = $store->read(); }
            catch (Throwable $error) {
                $unknownAll = true; $failed = true; $errors[$protocol] = 'state_unavailable';
                try { $store->quarantineXraySync(); } catch (Throwable $failure) { $errors[$protocol] = 'quarantine_unconfirmed'; }
                continue;
            }
            try { $usage[$protocol] = $this->xrayProtocolUsageRows($store, $states[$protocol]); }
            catch (Throwable $error) { $usage[$protocol] = []; $errors[$protocol] = 'usage_unavailable'; }
            foreach ($states[$protocol]['users'] as $id => $user) {
                if (!isset($user['xray_source'])) continue;
                $bytes = $usage[$protocol][$id] ?? [];
                if (($bytes['reset'] ?? '') !== $user['reset']) { $unknown[$user['xray_source']] = true; continue; }
                $totals[$user['xray_source']] = ($totals[$user['xray_source']] ?? 0) + $bytes['upload'] + $bytes['download'];
            }
        }
        try { $stats = $this->getXrayStats(); if (!is_array($stats)) throw new RuntimeException('Xray usage unavailable'); }
        catch (Throwable $error) { $stats = []; $unknownAll = true; $errors['xray'] = 'usage_unavailable'; }
        foreach ($stores as $protocol => $store) {
            if (!isset($states[$protocol])) continue;
            try {
                $entries = []; $state = $states[$protocol];
                $active = $state['enabled'] && $this->protocolModuleEnabled($protocol);
                $previous = [];
                foreach ($state['users'] as $id => $user) if (isset($user['xray_source'])) $previous[$user['xray_source']] = [$id, $user];
                foreach ($xray['inbounds'][0]['settings']['clients'] as $index => $client) {
                    if (empty($client['id'])) continue;
                    $source = ManagedProtocol::xraySource($client);
                    if (!$active && !isset($previous[$source])) continue;
                    $known = !$unknownAll && !isset($unknown[$source]);
                    $total = $this->xrUserTraffic($stats, $index) + ($totals[$source] ?? 0);
                    $limit = max(0, (int) ($client['traffic'] ?? 0)); $own = 0;
                    if (isset($previous[$source])) {
                        [$id, $user] = $previous[$source]; $bytes = $usage[$protocol][$id] ?? [];
                        if (($bytes['reset'] ?? '') === $user['reset']) $own = $bytes['upload'] + $bytes['download'];
                    }
                    $name = trim((string) ($client['email'] ?? '')) ?: 'VLESS';
                    $name = mb_substr(preg_replace('/[\x00-\x1f\x7f]/', ' ', $name), 0, 100);
                    $entries[$source] = ['name' => $name, 'enabled' => $active && empty($client['off'])
                        && ($client['managed_protocols'][$protocol] ?? true) !== false && (!$limit || ($known && $total < $limit)),
                        'expires' => (int) ($client['time'] ?? 0) > 0 ? (int) $client['time'] : null,
                        // Unknown aggregate never grants a fresh quota. Disabled
                        // entries use a positive sentinel until counters recover.
                        'quota' => $limit ? ($known ? max(1, $own + max(0, $limit - $total)) : 1) : null,
                        'xray_credential' => ManagedProtocol::xrayCredential($client)];
                }
                $store->syncXrayUsers($entries);
                $store->clearXraySyncQuarantine();
            } catch (Throwable $error) {
                $failed = true; $errors[$protocol] = 'apply_unavailable';
                try { $store->quarantineXraySync(); } catch (Throwable $failure) { $errors[$protocol] = 'quarantine_unconfirmed'; }
            }
        }
        ManagedProtocol::writeJson($this->protocolRoot . '/xray-sync.status.json', ['time' => time(), 'complete' => !$errors && !$unknownAll && !$unknown,
            'access_applied' => !$failed, 'errors' => $errors, 'quota_unknown' => $unknownAll || (bool) $unknown]);
        if ($failed) throw new RuntimeException($this->t('Часть протоколов ожидает восстановления состояния; остальные обновлены', 'Some protocols await state recovery; the others have been updated'));
    }

    public function resetXrayProtocolUsage(?array $client = null): void
    {
        $source = $client === null ? null : ManagedProtocol::xraySource($client);
        foreach (array_keys(ManagedProtocol::NAMES) as $protocol) {
            $store = $this->protocolStore($protocol);
            if (!is_file($store->directory() . '/desired.json')) continue;
            $store->change(static function (&$state) use ($source) {
                $changed = false;
                foreach ($state['users'] as &$user) if (isset($user['xray_source']) && ($source === null || $source === $user['xray_source'])) {
                    $user['reset'] = bin2hex(random_bytes(8)); $changed = true;
                }
                return $changed;
            });
        }
    }

    public function xrayProtocolClient(string $source): ?array
    {
        foreach ($this->getXray()['inbounds'][0]['settings']['clients'] ?? [] as $index => $client) {
            if (hash_equals(ManagedProtocol::xraySource($client), $source)) return [$index, $client];
        }
        return null;
    }

    public function xrayProtocolsMenu(string $source, string $toggle = ''): void
    {
        if (!$this->admin) return;
        try {
            $found = $this->xrayProtocolClient($source);
            if ($found === null) { $this->protocolError($this->t('Пользователь удалён.', 'User deleted.'), '/xray'); return; }
            [$index, $client] = $found;
            if ($toggle !== '') {
                if (!isset(ManagedProtocol::NAMES[$toggle])) throw new InvalidArgumentException($this->t('Неизвестный протокол', 'Unknown protocol'));
                $this->xrayConfUpdate(static function (&$xray) use ($source, $toggle) {
                    foreach ($xray['inbounds'][0]['settings']['clients'] as &$user) if (ManagedProtocol::xraySource($user) === $source) {
                        $user['managed_protocols'][$toggle] = ($user['managed_protocols'][$toggle] ?? true) === false;
                    }
                }, true);
                $this->syncXrayProtocolUsers();
                [$index, $client] = $this->xrayProtocolClient($source);
            }
            $text = [$this->t('Протоколы в подписке · ', 'Protocols in the subscription · ') . self::esc($client['email']),
                $this->t('Используются прежние ссылки и выбранные шаблоны Mihomo / sing-box: DNS, Fake IP, правила и rule-set сохраняются. В группе основного подключения можно выбрать VLESS или новый протокол; по умолчанию остаётся прежнее подключение.', 'The previous links and the selected Mihomo / sing-box templates are used: DNS, Fake IP, rules and rule-set stay. In the main connection group you can choose VLESS or a new protocol; the previous connection stays the default.'),
                $this->t('Новые протоколы доступны после включения сервиса. Mieru доступен только в Mihomo; MASQUE выдаётся JSON для Xray 26.9.30+, snolc — отдельным ZIP в карточке подключений. Связанные пользователи имеют общий срок, выключатель и лимит трафика; секреты у каждого протокола свои.', 'New protocols are available after their service is enabled. Mieru is available only in Mihomo; MASQUE is issued as JSON for Xray 26.9.30+, snolc as a separate ZIP in the connections card. Linked users share the expiry, switch and traffic limit; each protocol has its own secrets.'),
                $this->t('После изменения обновите подписку в клиенте. Учёт общего лимита обновляется службой бота примерно раз в 10 секунд.', 'After a change refresh the subscription in the client. The shared limit accounting is updated by the bot service about every 10 seconds.'),
                $this->t('Если VLESS несовместим с обычным sing-box (XHTTP, новый REALITY или VLESS Encryption), в его подписке останутся только совместимые новые протоколы. Шаблон с цепочкой через такой VLESS требует совместимого транспорта VLESS.', 'If VLESS is incompatible with ordinary sing-box (XHTTP, new REALITY or VLESS Encryption), its subscription keeps only the compatible new protocols. A template chaining through such VLESS needs a compatible VLESS transport.')];
            $buttons = [];
            foreach (ManagedProtocol::NAMES as $protocol => $label) {
                $selected = ($client['managed_protocols'][$protocol] ?? true) !== false;
                $state = $this->protocolStore($protocol)->read();
                $enabled = $state['enabled'] && $this->protocolModuleEnabled($protocol);
                $buttons[] = [['text' => ($selected ? '🟢 ' : '🔴 ') . $label . ($enabled ? '' : $this->t(' · сервис выключен', ' · service off')), 'callback_data' => "/xp $source $protocol"]];
            }
            $buttons[] = [['text' => $this->i18n('back'), 'callback_data' => "/userXr $index"]];
            $this->update($this->input['chat'], $this->input['message_id'], implode("\n\n", $text), $buttons);
        } catch (RuntimeException | InvalidArgumentException $e) { $this->protocolError($e->getMessage(), '/xray'); }
    }

    public function appendXrayProtocols(array &$config, array $client, string $type, int $index, ?array $relay = null, bool $keepPrimary = true): bool
    {
        if (!in_array($type, ['cl', 'si'], true) || !empty($client['off']) || ((int) ($client['time'] ?? 0) > 0 && $client['time'] <= time())) return false;
        $source = ManagedProtocol::xraySource($client); $nodes = []; $choices = [];
        $key = $type === 'cl' ? 'proxies' : 'outbounds'; $tag = $type === 'cl' ? 'name' : 'tag';
        $primary = $config[$key][$index] ?? null;
        if (!is_array($primary) || !is_string($primary[$tag] ?? null)) return false;
        $chainedGroups = [];
        if ($type === 'si') {
            $dependencies = array_values(array_filter(array_column(array_merge($config['outbounds'], $config['endpoints'] ?? []), 'detour')));
            $visited = [];
            while ($dependencies) {
                $dependency = array_pop($dependencies);
                if (isset($visited[$dependency])) continue;
                $visited[$dependency] = true;
                foreach ($config['outbounds'] as $i => $node) {
                    if ($node['tag'] !== $dependency || !in_array($node['type'], ['selector', 'urltest'], true)) continue;
                    $chainedGroups[] = $i;
                    array_push($dependencies, ...($node['outbounds'] ?? []));
                }
            }
            if (!$keepPrimary && isset($visited[$primary[$tag]])) return false;
        }
        // A chain through the original transport cannot be replaced safely:
        // new servers may intentionally deny the chain's private destination.
        if (!$keepPrimary) foreach ($config[$key] as $node) {
            if (($node['detour'] ?? null) === $primary[$tag]) return false;
        }
        $used = array_fill_keys(array_merge(array_column($config[$key], $tag), array_column($config['proxy-groups'] ?? [], 'name'),
            array_column($config['endpoints'] ?? [], 'tag'), array_column($config['dns']['servers'] ?? [], 'tag')), true);
        $unique = static function (string $name) use (&$used): string {
            $base = $name; $n = 2;
            while (isset($used[$name])) $name = $base . ' ' . $n++;
            $used[$name] = true; return $name;
        };
        $resolver = $primary['domain_resolver'] ?? $config['route']['default_domain_resolver'] ?? null;
        $bootstrap = null;
        foreach (ManagedProtocol::NAMES as $protocol => $label) {
            if (in_array($protocol, ['snolc', 'masque'], true)) continue; // Separate native profiles; bundled Mihomo/sing-box do not support them.
            if (($client['managed_protocols'][$protocol] ?? true) === false || ($type === 'si' && $protocol === 'mieru') || !$this->protocolModuleEnabled($protocol)) continue;
            $store = $this->protocolStore($protocol); $state = $store->read();
            if (!$state['enabled'] || !$this->protocolPortApplied($protocol, $state)) continue;
            $endpoint = null;
            if ($relay !== null) {
                if (empty($relay[$protocol . '_address']) || empty($relay[$protocol . '_port'])) continue;
                $endpoint = ['host' => $relay[$protocol . '_address'], 'port' => (int) $relay[$protocol . '_port']];
                ManagedProtocol::validateClientEndpoint($endpoint);
            }
            foreach ($state['users'] as $id => $user) {
                if (($user['xray_source'] ?? '') !== $source || !$store->allowed($user, $id)) continue;
                $epoch = ManagedProtocol::xrayCredential($client);
                if (!hash_equals($user['xray_credential'], $epoch)) continue;
                $profile = $store->profile($id, $type === 'cl' ? 'mihomo' : 'singbox', $state, $endpoint);
                $names = [];
                foreach ($profile[$key] as $node) $names[$node[$tag]] = $unique($label . ($node[$tag] === 'VPN' ? '' : ' · TLS'));
                foreach ($profile[$key] as $node) {
                    $node[$tag] = $names[$node[$tag]];
                    if (isset($node['detour'], $names[$node['detour']])) $node['detour'] = $names[$node['detour']];
                    if (($node['domain_resolver'] ?? null) === 'bootstrap') {
                        if ($resolver === null) {
                            $bootstrap ??= $unique('VPNBot bootstrap');
                            $node['domain_resolver'] = $bootstrap;
                        } else $node['domain_resolver'] = $resolver;
                    }
                    $nodes[] = $node;
                }
                $choices[] = $names['VPN'];
                break;
            }
        }
        if (!$choices) return false;
        $name = $primary[$tag]; $original = $unique($name . ' · ' . strtoupper($primary['type'] ?? 'VLESS'));
        $primary[$tag] = $original;
        // Preserve existing chained outbounds (including WARP SOCKS): their
        // transport must not silently change when the user selects another node.
        $detour = $type === 'cl' ? 'dialer-proxy' : 'detour';
        foreach ($config[$key] as &$node) if (($node[$detour] ?? null) === $name) $node[$detour] = $original;
        unset($node);
        if ($type === 'si') {
            foreach ($config['endpoints'] ?? [] as $i => $endpoint) {
                if (($endpoint['detour'] ?? null) === $name) $config['endpoints'][$i]['detour'] = $original;
            }
            foreach ($chainedGroups as $i) {
                foreach ($config['outbounds'][$i]['outbounds'] ?? [] as $j => $member) {
                    if ($member === $name) $config['outbounds'][$i]['outbounds'][$j] = $original;
                }
                if (($config['outbounds'][$i]['default'] ?? null) === $name) $config['outbounds'][$i]['default'] = $original;
            }
        }
        if ($type === 'cl') {
            $dependencies = array_values(array_filter(array_column($config[$key], 'dialer-proxy')));
            foreach ($config['proxy-groups'] ?? [] as $group) if (($group['type'] ?? '') === 'relay') $dependencies[] = $group['name'];
            $visited = [];
            while ($dependencies) {
                $dependency = array_pop($dependencies);
                if (isset($visited[$dependency])) continue;
                $visited[$dependency] = true;
                foreach ($config['proxy-groups'] ?? [] as $i => $group) if (($group['name'] ?? '') === $dependency) {
                    foreach ($group['proxies'] ?? [] as $j => $member) {
                        if ($member === $name) $config['proxy-groups'][$i]['proxies'][$j] = $original;
                        else $dependencies[] = $member;
                    }
                    if (!empty($group['include-all']) || !empty($group['include-all-proxies'])) {
                        $exclude = '^(' . implode('|', array_map(static fn($v) => preg_quote($v, '~'), $choices)) . ')$';
                        $config['proxy-groups'][$i]['exclude-filter'] = ($group['exclude-filter'] ?? '') !== ''
                            ? '(' . $group['exclude-filter'] . ')|' . $exclude : $exclude;
                    }
                }
            }
            $config[$key][$index] = $primary;
            $config['proxy-groups'][] = ['name' => $name, 'type' => 'select', 'proxies' => array_merge([$original], $choices)];
        } else {
            $config[$key][$index] = ['type' => 'selector', 'tag' => $name, 'outbounds' => $keepPrimary ? array_merge([$original], $choices) : $choices, 'default' => $keepPrimary ? $original : $choices[0]];
            if ($keepPrimary) $nodes[] = $primary;
            if ($bootstrap !== null) $config['dns']['servers'][] = ['type' => 'local', 'tag' => $bootstrap];
            // Native sing-box needs the local Clash API to switch a selector.
            // Existing GUI/controller settings from the template take precedence.
            if (!isset($config['experimental']['clash_api']['external_controller'])) {
                $config['experimental']['clash_api']['external_controller'] = '127.0.0.1:9090';
            }
        }
        array_push($config[$key], ...$nodes);
        return true;
    }
}
