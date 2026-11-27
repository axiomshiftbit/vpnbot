<?php

/**
 * WARP of a managed node, as the main bot's WARP section: status, mode, official ports,
 * MASQUE transport, a new account or a WARP+ key, and the configuration with secrets
 * masked by the node itself. Every change is an ordinary node job: probe, then confirm
 * or automatic rollback.
 */
trait BotManagedNodeWarp
{
    /** Cloudflare's published ingress ports (scripts/node_config.py WARP_PORTS). */
    public const NODE_WARP_PORTS = ['wireguard' => [2408, 500, 1701, 4500], 'masque' => [443, 500, 1701, 4500, 4443, 8443, 8095]];

    /** Fields of Cloudflare's trace through the node's WARP, or [] when it does not answer. */
    protected function managedNodeWarpTrace(string $id): array
    {
        $port = $this->exitProbePort($id);
        $uuid = $this->exitNodes()[$id]['managed_profile']['warp_uuid'] ?? '';
        if ($port === null || !$uuid) return [];
        $answer = $this->sshInputCommand('python3 /node_warp_probe.py ' . ($port + self::EXIT_MAX) . ' --trace',
            self::exitWarpProbePassword($id, $uuid) . "\n", 'xr');
        if ($this->sshFailed) return [];
        $fields = [];
        foreach (explode(' ', trim((string) $answer)) as $pair) {
            [$key, $value] = array_pad(explode('=', $pair, 2), 2, '');
            if (in_array($key, ['warp', 'ip', 'colo', 'loc'], true) && preg_match('~^[0-9A-Za-z:.]{1,45}$~D', $value)) $fields[$key] = $value;
        }
        return $fields;
    }

    private function managedNodeWarpModeName(string $mode, string $http): string
    {
        return match ($mode) {
            'wireguard' => 'WireGuard',
            'masque' => 'MASQUE · ' . ($http === 'h2' ? 'HTTP/2' : 'HTTP/3'),
            default => $this->t('выключен', 'off'),
        };
    }

    /** $back: the card, or the settings hub when opened from Xray and connection. */
    public function managedNodeWarp(string $id, string $notice = '', string $back = ''): void
    {
        $back = $back !== '' ? $back : "/node $id";
        $node = $this->managedNodes()[$id] ?? null;
        if (!$node || empty($node['connected'])) { $this->managedNodesMenu(); return; }
        if (empty($node['status']['warp_egress'])) { $this->managedNodeMenu($id); return; }
        $options = $node['draft'] ?? $node['status']['options'] ?? [];
        $mode = (string) ($options['warp_mode'] ?? 'off');
        $http = (string) ($options['warp_http'] ?? 'h3');
        $port = $options['warp_port'] ?? null;
        $accounts = !empty($node['status']['warp_account']);
        $text = [$this->t('Ноды → ', 'Nodes → ') . self::esc($node['name']) . ' → ' . $this->t(...ManagedNodeFields::GROUPS['warp'])];
        if ($notice !== '') $text[] = self::esc($notice);
        if ($node['job']) $text[] = $this->managedNodeOperationLabel($node['job']) . ': ' . $this->t('⏳ выполняется изменение, экран обновится после подтверждения.', '⏳ a change is in progress; the screen updates after confirmation.');
        if ($mode === 'off') {
            $text[] = $this->t('Состояние: ⚪ выключен. Весь трафик ноды выходит напрямую.', 'State: ⚪ off. All node traffic exits directly.');
        } else {
            $trace = $node['job'] ? [] : $this->managedNodeWarpTrace($id);
            $state = in_array($trace['warp'] ?? '', ['on', 'plus'], true)
                ? '🟢 ' . (($trace['warp'] ?? '') === 'plus' ? 'WARP+' : 'WARP') . (isset($trace['ip']) ? ' · IP <code>' . self::esc($trace['ip']) . '</code>' : '')
                    . (isset($trace['colo']) ? ' · ' . self::esc($trace['colo']) : '') . (isset($trace['loc']) ? ' · ' . self::esc($trace['loc']) : '')
                : ($node['job'] ? '⏳' : $this->t('🔴 нет ответа через WARP', '🔴 no answer through WARP'));
            $text[] = $this->t('Состояние: ', 'State: ') . $state;
            $text[] = $this->exitWarpHealthLine($id);
        }
        $text[] = $this->t('Режим: ', 'Mode: ') . '<b>' . self::esc($this->managedNodeWarpModeName($mode, $http)) . '</b>';
        if ($mode !== 'off') {
            $default = self::NODE_WARP_PORTS[$mode][0] ?? 0;
            $text[] = $this->t('Порт: ', 'Port: ') . ($port === null ? $default . $this->t(' (по умолчанию)', ' (default)') : (int) $port)
                . ($http === 'h2' ? ' TCP' : ' UDP');
        }
        $info = [];
        if ($mode !== 'off' && $accounts && !$node['job']) {
            try { $info = $this->managedNodeRpc($id, ['action' => 'warp_info']); } catch (Throwable $error) { $info = []; }
        }
        if ($info) {
            $device = is_array($info['device'] ?? null) ? $info['device'] : [];
            $text[] = $this->t('Аккаунт: ', 'Account: ') . '<code>' . self::esc(($info['account'] ?? '') === 'legacy' ? $this->t('первый', 'initial') : (string) ($info['account'] ?? '')) . '</code>'
                . (!empty($device['account_type']) ? $this->t(' · тариф ', ' · plan ') . '<code>' . self::esc((string) $device['account_type']) . '</code>' : '')
                . (!empty($device['id']) ? $this->t(' · устройство ', ' · device ') . '<code>' . self::esc((string) $device['id']) . '…</code>' : '');
            $lines = [];
            foreach ([['[Account]', $info['account_fields'] ?? []], ['[Profile]', $info['profile'] ?? []]] as [$title, $rows]) {
                if (!is_array($rows) || !$rows) continue;
                $lines[] = $title;
                foreach ($rows as $row) if (is_array($row) && count($row) === 2 && is_string($row[0]) && is_scalar($row[1])) $lines[] = $row[0] . ' = ' . $row[1];
            }
            foreach (['endpoint_v4', 'address_v4'] as $key) if (!empty($device[$key]) && is_string($device[$key])) $lines[] = "$key = " . $device[$key];
            if ($lines) {
                $text[] = $this->t('Конфигурация (секреты скрыты на ноде, показаны последние 4 символа):', 'Configuration (the node hides secrets, showing their last 4 characters):');
                $text[] = '<pre>' . self::esc(implode("\n", $lines)) . '</pre>';
            }
        }
        $data = [];
        $busy = (bool) $node['job'];
        if (!$busy) {
            $modes = [];
            foreach (['off', 'wireguard', 'masque'] as $choice) if ($choice !== $mode) $modes[] = ['text' => $this->managedNodeWarpModeName($choice, 'h3'), 'callback_data' => "/nwMode $id $choice"];
            $data[] = $modes;
            // Ports, the MASQUE transport and accounts need node code that knows them.
            if ($mode !== 'off' && $accounts) {
                $row = [['text' => $this->t('🔌 Порт', '🔌 Port'), 'callback_data' => "/nwPorts $id"]];
                if ($mode === 'masque') $row[] = ['text' => $http === 'h2' ? 'HTTP/2 → HTTP/3' : 'HTTP/3 → HTTP/2', 'callback_data' => "/nwHttp $id " . ($http === 'h2' ? 'h3' : 'h2')];
                $data[] = $row;
                $data[] = [['text' => $this->t('🔑 Ключ WARP+', '🔑 WARP+ key'), 'callback_data' => "/nwKey $id"],
                    ['text' => $this->t('🔄 Новый аккаунт', '🔄 New account'), 'callback_data' => "/nwReg $id"]];
            } elseif ($mode !== 'off') {
                $text[] = $this->t('Порты, транспорт MASQUE и аккаунт меняются после обновления кода ноды.', 'Ports, the MASQUE transport and the account can be changed after a node code update.');
            }
        }
        $data[] = [['text' => 'WARP · ' . $this->t('список', 'list'), 'callback_data' => "/nlist $id warp 0"],
            ['text' => $this->t('🔄 Обновить', '🔄 Refresh'), 'callback_data' => "/nodeWarp $id"]];
        $data[] = $this->menuHelpButton('nodeconfig', $id . '_warp');
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => $back]];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $text), $data);
    }

    public function managedNodeWarpPorts(string $id): void
    {
        $node = $this->managedNodes()[$id] ?? null;
        if (!$node || empty($node['connected']) || empty($node['status']['warp_egress'])) { $this->managedNodesMenu(); return; }
        $options = $node['draft'] ?? $node['status']['options'] ?? [];
        $mode = (string) ($options['warp_mode'] ?? 'off');
        if (!isset(self::NODE_WARP_PORTS[$mode])) { $this->managedNodeWarp($id); return; }
        $h2 = ($options['warp_http'] ?? 'h3') === 'h2';
        $current = $options['warp_port'] ?? null;
        $text = [$this->t('Ноды → ', 'Nodes → ') . self::esc($node['name']) . ' → WARP → ' . $this->t('Порт', 'Port'),
            $this->t('Официальные порты Cloudflare WARP. Если хостер режет порт по умолчанию, выберите другой: при отказе пробы нода вернёт прежний.',
                'Official Cloudflare WARP ports. If the host blocks the default port, choose another: the node restores the previous one if the probe fails.')];
        if ($h2) $text[] = $this->t('MASQUE по HTTP/2 работает только через TCP 443.', 'MASQUE over HTTP/2 uses TCP 443 only.');
        $buttons = [['text' => ($current === null ? '✓ ' : '') . $this->t('По умолчанию', 'Default') . ' (' . self::NODE_WARP_PORTS[$mode][0] . ')', 'callback_data' => "/nwPort $id default"]];
        if (!$h2) foreach (self::NODE_WARP_PORTS[$mode] as $port) $buttons[] = ['text' => ($current === $port ? '✓ ' : '') . $port, 'callback_data' => "/nwPort $id $port"];
        $data = array_chunk($buttons, 3);
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => "/nodeWarp $id"]];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $text), $data);
    }

    /** Mode, port and transport go through the usual configure job with the current lists. */
    private function managedNodeWarpConfigure(string $id, callable $edit): void
    {
        try {
            $draft = false;
            // Checked under the node lock: a draft saved meanwhile is neither sent nor discarded.
            $this->managedNodeLocked($id, function () use ($id, $edit, &$draft) {
                $node = $this->managedNodes()[$id] ?? null;
                if (!$node || empty($node['connected']) || $node['job'] || empty($node['status']['warp_egress'])) throw new RuntimeException('Node is not ready');
                // A settings draft must not ride along with a WARP change.
                if (isset($node['draft'])) { $draft = true; return; }
                $options = $node['status']['options'];
                $edit($options);
                if (($options['warp_mode'] ?? 'off') === 'off') unset($options['warp_port'], $options['warp_http']);
                if (($options['warp_http'] ?? 'h3') === 'h3') unset($options['warp_http']);
                $this->managedNodeSubmitLocked($id, 'configure', $options);
            });
            if ($draft) {
                $this->managedNodeWarp($id, $this->t('Есть черновик настроек: сначала примените или отмените его в «⚙️ Xray и подключение».',
                    'A settings draft is pending: apply or discard it in ⚙️ Xray and connection first.'));
                return;
            }
            $this->managedNodeWarp($id);
        } catch (Throwable $error) {
            $this->managedNodeWarp($id, $this->nodeRoutesError($error) ?: $this->t('Не применено: нода занята, не на связи или отклонила изменение.',
                'Not applied: the node is busy, offline or rejected the change.'));
        }
    }

    public function managedNodeWarpMode(string $id, string $mode): void
    {
        if (!in_array($mode, ['off', 'wireguard', 'masque'], true)) return;
        $this->managedNodeWarpConfigure($id, static function (array &$options) use ($mode) {
            // A port belongs to its mode: the other mode starts from its default.
            if (($options['warp_mode'] ?? 'off') !== $mode) unset($options['warp_port'], $options['warp_http']);
            $options['warp_mode'] = $mode;
        });
    }

    public function managedNodeWarpPort(string $id, string $port): void
    {
        $this->managedNodeWarpConfigure($id, static function (array &$options) use ($port) {
            $mode = (string) ($options['warp_mode'] ?? 'off');
            if ($port === 'default') { unset($options['warp_port']); return; }
            if (!in_array((int) $port, self::NODE_WARP_PORTS[$mode] ?? [], true)) throw new InvalidArgumentException('Not an official WARP port');
            $options['warp_port'] = (int) $port;
        });
    }

    public function managedNodeWarpHttp(string $id, string $http): void
    {
        if (!in_array($http, ['h3', 'h2'], true)) return;
        $this->managedNodeWarpConfigure($id, static function (array &$options) use ($http) {
            if (($options['warp_mode'] ?? 'off') !== 'masque') throw new InvalidArgumentException('HTTP/2 needs MASQUE');
            $options['warp_http'] = $http;
            // HTTP/2 runs over TCP 443 only.
            if ($http === 'h2') unset($options['warp_port']);
        });
    }

    public function managedNodeWarpKeyPrompt(string $id): void
    {
        if (!$this->managedNodePrivateChat()) { $this->managedNodeWarp($id, $this->managedNodePrivateOnly()); return; }
        $this->exitPrompt($this->t('пришлите ключ WARP+ (буквы, цифры и дефисы). Нода зарегистрирует новый аккаунт с этим ключом; если ключ не примется или WARP не ответит, останется прежний аккаунт. Сообщение с ключом бот сразу удалит.',
            'send the WARP+ key (letters, digits and hyphens). The node registers a new account with it; if the key is rejected or WARP does not answer, the previous account stays. The bot deletes the message with the key right away.'),
            'saveNodeWarpKey', [$id]);
    }

    public function saveNodeWarpKey($key, $id): void
    {
        $id = (string) $id;
        if (!$this->managedNodePrivateChat()) { $this->managedNodeWarp($id, $this->managedNodePrivateOnly()); return; }
        $key = trim((string) $key);
        if (!preg_match('~^[A-Za-z0-9-]{8,64}$~D', $key)) { $this->managedNodeWarp($id, $this->t('Ключ не подходит: нужны 8–64 буквы, цифры или дефисы.', 'The key does not fit: 8–64 letters, digits or hyphens are needed.')); return; }
        $this->managedNodeWarpAccount($id, ['action' => 'license', 'key' => $key]);
    }

    public function managedNodeWarpRegister(string $id, bool $confirmed): void
    {
        if (!$confirmed) {
            $node = $this->managedNodes()[$id] ?? null;
            if (!$node) { $this->managedNodesMenu(); return; }
            $this->update($this->input['chat'], $this->input['message_id'], implode("\n", [
                $this->t('Ноды → ', 'Nodes → ') . self::esc($node['name']) . ' → WARP',
                $this->t('Зарегистрировать новый бесплатный аккаунт WARP? Ключ WARP+ прежнего аккаунта к нему не переносится. Если новый аккаунт не ответит, нода вернёт прежний.',
                    'Register a new free WARP account? The previous account’s WARP+ key is not carried over. If the new account does not answer, the node restores the previous one.')]),
                [[['text' => $this->t('🔄 Зарегистрировать', '🔄 Register'), 'callback_data' => "/nwRegYes $id"], ['text' => $this->i18n('back'), 'callback_data' => "/nodeWarp $id"]]]);
            return;
        }
        $this->managedNodeWarpAccount($id, ['action' => 'register']);
    }

    private function managedNodeWarpAccount(string $id, array $request): void
    {
        try {
            $node = $this->managedNodes()[$id] ?? null;
            if (!$node || empty($node['connected']) || $node['job'] || isset($node['draft']) || empty($node['status']['warp_account'])
                || (($node['status']['options']['warp_mode'] ?? 'off') === 'off')) throw new RuntimeException('Node is not ready');
            $this->managedNodeSubmit($id, 'warp_account', $request);
            $this->managedNodeWarp($id);
        } catch (Throwable $error) {
            $this->managedNodeWarp($id, $this->t('Не выполнено: нода занята, не на связи, есть черновик настроек или WARP выключен.',
                'Not done: the node is busy, offline, has a settings draft or WARP is off.'));
        }
    }
}
