<?php

require_once __DIR__ . '/ManagedNodeProfile.php';
require_once __DIR__ . '/ManagedNodeFields.php';
require_once __DIR__ . '/BotManagedNodePeers.php';
require_once __DIR__ . '/BotManagedNodeSubscriptions.php';
require_once __DIR__ . '/BotManagedNodeNavigation.php';
require_once __DIR__ . '/BotManagedNodeMenus.php';
require_once __DIR__ . '/BotManagedNodeTools.php';
require_once __DIR__ . '/BotManagedNodePresets.php';

/** Host management is separate from the existing exit routing and user menus. */
trait BotManagedNodes
{
    use BotManagedNodePeers;
    use BotManagedNodeSubscriptions;
    use BotManagedNodeNavigation;
    use BotManagedNodeMenus;
    use BotManagedNodeTools;
    use BotManagedNodePresets;
    public string $managedNodeRoot = '/ssh/nodes';
    private int $managedNodeCronAt = 0;

    private function managedNodeLocked(string $id, callable $callback): void
    {
        if (!preg_match('~^[a-f0-9]{8}$~D', $id)) throw new RuntimeException('Invalid node');
        $done = $this->withLock('managed-node-' . $id, static function () use ($callback) {
            $callback();
            return true;
        }, 1, false);
        if (!$done) throw new RuntimeException('Node controller busy');
    }

    public function managedNodeBackupPaths(bool $includeRetired = true): array
    {
        $paths = [];
        foreach ($this->managedNodes() as $id => $_) {
            foreach (['key', 'key.pub', 'endpoint.json', 'snapshot.json'] as $name) {
                $paths["nodes/$id/$name"] = $this->managedNodeRoot . "/$id/$name";
            }
        }
        if (!$includeRetired) return $paths;
        $root = $this->managedNodeRoot . '/retired';
        for ($parent = $root; $parent !== dirname($parent); $parent = dirname($parent)) {
            if (is_link($parent)) throw new RuntimeException('Unsafe retired node directory');
        }
        if (is_dir($root)) {
            $count = 0;
            foreach (new DirectoryIterator($root) as $entry) {
                if ($entry->isDot()) continue;
                $id = $entry->getFilename();
                if (++$count > 256 || !preg_match('~^[a-f0-9]{32}$~D', $id) || $entry->isLink() || !$entry->isDir()) {
                    throw new RuntimeException('Invalid retired node archive');
                }
                foreach (['key', 'key.pub'] as $name) {
                    $path = "$root/$id/$name";
                    if (is_link($path) || !is_file($path) || filesize($path) === 0 || filesize($path) > 16384) {
                        throw new RuntimeException('Incomplete retired node archive');
                    }
                    $paths["nodes/retired/$id/$name"] = $path;
                }
            }
        }
        return $paths;
    }

    public function managedNodeBackupRefresh(): void
    {
        foreach ($this->managedNodes() as $id => $node) {
            try {
                $this->managedNodeLocked((string) $id, function () use ($id) {
                    $node = $this->managedNodes()[$id] ?? null;
                    if (empty($node['connected']) || !empty($node['job']) || !empty($node['recovery_required'])) return;
                    $this->managedNodeTransport((string) $id, 'snapshot');
                    $this->managedNodeWrite((string) $id, static function (&$node) { $node['backup_time'] = time(); });
                });
            } catch (Throwable $error) { /* Preserve the last confirmed snapshot while the node is offline. */ }
        }
    }

    public function managedNodeBackupCheck(): void
    {
        foreach ($this->managedNodes() as $id => $node) {
            $required = !empty($node['connected']) ? ['key', 'key.pub', 'endpoint.json', 'snapshot.json'] : ['key', 'key.pub'];
            foreach ($required as $name) {
                $path = $this->managedNodeRoot . "/$id/$name";
                if (!is_file($path) || is_link($path) || filesize($path) === 0) {
                    throw new RuntimeException($this->t('Бэкап ноды неполон: отсутствует обязательный файл. Переподключите ноду и повторите резервное копирование.',
                        'Node backup is incomplete: a required file is missing. Reconnect the node and retry the backup.'));
                }
            }
        }
    }

    public function managedNodes(?array $pac = null): array
    {
        $result = [];
        foreach (($pac ?? $this->getPacConf())['managed_nodes'] ?? [] as $id => $node) {
            if (!preg_match('~^[a-f0-9]{8}$~D', (string) $id) || !is_array($node) || count($result) >= self::EXIT_MAX) continue;
            $result[(string) $id] = $node + ['name' => (string) $id, 'connected' => false, 'status' => [], 'checked' => 0, 'job' => null];
        }
        return $result;
    }

    protected function managedNodeTransport(string $id, string $action, $value = null): array
    {
        if (!preg_match('~^[a-f0-9]{8}$~D', $id)) throw new RuntimeException('Invalid node');
        $body = json_encode(['id' => $id, 'action' => $action, 'value' => $value], JSON_THROW_ON_ERROR);
        if (strlen($body) > 65536) throw new RuntimeException('Node request too large');
        $process = proc_open(['python3', '-I', __DIR__ . '/node_ssh.py'],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
        if (!is_resource($process)) throw new RuntimeException('Node transport unavailable');
        try {
            for ($offset = 0; $offset < strlen($body); $offset += $written) {
                $written = fwrite($pipes[0], substr($body, $offset));
                if ($written === false || $written === 0) throw new RuntimeException('Node transport write failed');
            }
            fclose($pipes[0]);
            stream_set_timeout($pipes[1], 25);
            $response = stream_get_contents($pipes[1], 65537);
            if (stream_get_meta_data($pipes[1])['timed_out'] || !is_string($response) || strlen($response) > 65536) {
                throw new RuntimeException('Node transport timeout');
            }
            $reply = json_decode($response, true, 64, JSON_THROW_ON_ERROR);
            if (!is_array($reply) || ($reply['ok'] ?? false) !== true || !is_array($reply['result'] ?? null)) throw new RuntimeException('Node request failed');
            return $reply['result'];
        } finally {
            foreach ($pipes as $pipe) if (is_resource($pipe)) fclose($pipe);
            $status = proc_get_status($process);
            if ($status['running']) proc_terminate($process);
            proc_close($process);
        }
    }

    protected function managedNodeRpc(string $id, array $request): array
    {
        // Associative json_decode loses the distinction between {} and [].
        // Restore only the schema's empty maps; lists and invalid values keep
        // their types so the node's strict validator can reject them.
        if (($request['action'] ?? '') === 'submit') {
            $operation = $request['request']['operation'] ?? '';
            if ($operation === 'configure' || $operation === 'restore') {
                if ($operation === 'configure') $options = &$request['request']['value'];
                else $options = &$request['request']['value']['options'];
                if (($options['amnezia']['parameters'] ?? null) === []) $options['amnezia']['parameters'] = (object) [];
                unset($options);
                if ($operation === 'restore' && ($request['request']['value']['tls'] ?? null) === []) $request['request']['value']['tls'] = (object) [];
            }
        }
        return $this->managedNodeTransport($id, 'rpc', $request);
    }

    protected function managedNodeWrite(string $id, callable $edit): void
    {
        $saved = $this->withLock('pac', function () use ($id, $edit) {
            $pac = $this->getPacConf();
            $nodes = $this->managedNodes($pac);
            $node = $nodes[$id] ?? null;
            $edit($node);
            if ($node === null) unset($pac['managed_nodes'][$id]);
            else $pac['managed_nodes'][$id] = $node;
            return $this->setPacConf($pac) !== false;
        }, 20, false);
        if (!$saved) throw new RuntimeException('Node state not saved');
    }

    public function managedNodeUseProfile(string $id, array $profile): string
    {
        $pac = $this->getPacConf();
        $parsed = ManagedNodeProfile::parse($profile, (string) ($pac['xray_core'] ?? 'origin'));
        if ($this->exitAddressProblem($parsed['address']) !== '') throw new RuntimeException('Node endpoint is not allowed');
        return $this->applyExitNodes(function (array &$p) use ($id, $profile) {
            if (!isset($this->managedNodes($p)[$id])) return 'exit not found';
            if (!isset($p['exits'][$id]) && count($this->exitNodes($p)) >= self::EXIT_MAX) return 'exit too many';
            $node = $p['exits'][$id] ?? ['name' => $p['managed_nodes'][$id]['name'], 'fallback' => 'block', 'created' => time()] + self::exitNodeDefaults();
            $node['link'] = $profile['link'];
            $node['managed_profile'] = $profile;
            if (($profile['channel'] ?? '') === 'amnezia') $node['managed_session'] = bin2hex(random_bytes(8));
            $node['kind'] = 'remote';
            $node['sub'] = '';
            $p['exits'][$id] = $node;
            return '';
        }, ($profile['channel'] ?? '') === 'wireguard');
    }

    private function managedNodeRestoreClient(string $id, ?array $before): void
    {
        $error = $this->applyExitNodes(function (array &$pac) use ($id, $before) {
            if ($before === null) { unset($pac['exits'][$id]); return ''; }
            if (!isset($pac['exits'][$id])) return 'exit not found';
            $pac['exits'][$id]['link'] = $before['link'];
            if (isset($before['managed_profile'])) $pac['exits'][$id]['managed_profile'] = $before['managed_profile'];
            else unset($pac['exits'][$id]['managed_profile']);
            if (($before['managed_profile']['channel'] ?? '') === 'amnezia') $pac['exits'][$id]['managed_session'] = bin2hex(random_bytes(8));
            return '';
        }, ($before['managed_profile']['channel'] ?? '') === 'wireguard');
        if ($error !== '') throw new RuntimeException('Node client rollback failed');
    }

    private function managedNodeTrafficReady(string $id): bool
    {
        // Restarting the remote core invalidates VLESS Encryption's in-memory
        // 0-RTT ticket. The first request can require a fresh handshake. Allow
        // one real retry; a persistent failure still prevents confirmation.
        return !empty($this->exitProbe($id, false)['ok']) || !empty($this->exitProbe($id, false)['ok']);
    }

    public function managedNodeSubmit(string $id, string $operation, $value, ?string $expectedGeneration = null): void
    {
        $this->managedNodeLocked($id, fn() => $this->managedNodeSubmitLocked($id, $operation, $value, $expectedGeneration));
    }

    private function managedNodeSubmitLocked(string $id, string $operation, $value, ?string $expectedGeneration = null): void
    {
        $node = $this->managedNodes()[$id] ?? null;
        if (!$node || !$node['connected'] || $node['job']) throw new RuntimeException('Node is not ready');
        if ($operation === 'configure' && $this->managedNodeNetworkProblem($value, $node) !== '') throw new RuntimeException('Node connection family is not prepared');
        if (isset($node['draft']) && $operation !== 'configure') throw new RuntimeException('Apply or discard the settings draft first');
        if (!empty($node['recovery_required']) && $operation !== 'restore') throw new RuntimeException('Restore the saved node first');
        $exit = $this->exitNodes()[$id] ?? null;
        if (!$exit) throw new RuntimeException('Node route is missing');
        $generation = $expectedGeneration ?? ($operation === 'configure' ? ($node['draft_generation'] ?? $node['status']['generation'] ?? '') : ($node['status']['generation'] ?? ''));
        if (!preg_match('~^[a-f0-9]{32}$~D', $generation)) throw new RuntimeException('Refresh the node before changing it');
        $job = $this->managedNodeRpc($id, ['action' => 'submit', 'request' => ['operation' => $operation, 'value' => $value, 'generation' => $generation]]);
        if (!preg_match('~^[a-f0-9]{32}$~D', (string) ($job['job'] ?? ''))) throw new RuntimeException('Invalid node job');
        $before = array_intersect_key($exit, array_flip(['link', 'managed_profile']));
        $draft = $operation === 'configure' ? array_intersect_key($node, array_flip(['draft', 'draft_generation'])) : [];
        $origin = array_intersect_key($this->input ?? [], array_flip(['chat','message_id']));
        $subject = $operation === 'rotate' && is_string($value) ? $value : '';
        $this->managedNodeWrite($id, static function (&$node) use ($job, $before, $operation, $origin, $subject, $draft) {
            $node['job'] = ['id' => $job['job'], 'operation' => $operation, 'before' => $before, 'phase' => 'waiting', 'started' => time(), 'origin' => $origin, 'subject' => $subject, 'draft' => $draft];
            unset($node['draft'], $node['draft_generation'], $node['error']);
        });
    }

    /** Confirm only after real traffic passes through the main bot's Xray. */
    public function managedNodePoll(string $id): void
    {
        $this->managedNodeLocked($id, fn() => $this->managedNodePollLocked($id));
    }

    private function managedNodePollLocked(string $id): void
    {
        $node = $this->managedNodes()[$id] ?? null;
        if (!$node || !$node['job']) return;
        $saved = $node['job'];
        if (!empty($node['recovery_required']) && ($saved['operation'] ?? '') !== 'restore') return;
        $job = $this->managedNodeRpc($id, ['action' => 'job', 'id' => $saved['id']]);
        if (in_array($job['state'] ?? '', ['queued', 'running'], true)) return;
        $status = $this->managedNodeRpc($id, ['action' => 'status']);
        if (($job['state'] ?? '') === 'missing') {
            // After restoring an older main-bot backup, adopt only the current
            // confirmed generation; never confirm somebody else's transaction.
            if (!empty($status['pending'])) return;
            if (!empty($node['recovery_required'])) {
                $this->managedNodeWrite($id, static function (&$node) use ($status) {
                    $node['job'] = null; $node['status'] = $status; $node['checked'] = time(); $node['error'] = 'restore_required';
                });
                return;
            }
            $profile = $this->managedNodeRpc($id, ['action' => 'profile', 'peer' => null]);
            if ($this->managedNodeUseProfile($id, $profile) !== '' || !$this->managedNodeTrafficReady($id)) {
                $this->managedNodeRestoreClient($id, $saved['before']);
                throw new RuntimeException('Current node generation is not reachable');
            }
            $this->managedNodeTransport($id, 'snapshot');
            $this->managedNodeWrite($id, static function (&$node) use ($status) {
                $node['job'] = null; $node['status'] = $status; $node['checked'] = time(); $node['backup_time'] = time(); unset($node['error']);
            });
            return;
        }
        $pending = $job['result']['pending'] ?? null;
        if (($job['state'] ?? '') !== 'done' || ($pending && empty($status['pending']) && ($status['generation'] ?? '') !== $pending['after'])) {
            $this->managedNodeRestoreClient($id, $saved['before']);
            // The code phase of a full update stopped before any image change.
            $stage = ($job['error'] ?? '') === 'code_upgrade_failed' ? (preg_match('~^[a-z_]{1,24}$~D', (string) ($job['stage'] ?? '')) ? $job['stage'] : 'unexpected') : '';
            $this->managedNodeFinish($id, $saved, static function (&$node) use ($status, $saved, $stage) {
                foreach (($saved['draft'] ?? []) as $key=>$value) $node[$key] = $value;
                $node['job'] = null; $node['status'] = $status; $node['checked'] = time(); $node['error'] = $stage === '' ? 'rolled_back' : 'code_upgrade_failed';
                if ($stage === '') unset($node['error_stage']); else $node['error_stage'] = $stage;
            });
            return;
        }
        if ($pending) {
            if ($saved['phase'] === 'wait_rollback' && !empty($status['pending'])) return;
            $profile = $this->managedNodeRpc($id, ['action' => 'profile', 'peer' => null]);
            try {
                if ($this->managedNodeUseProfile($id, $profile) !== '') throw new RuntimeException('Client configuration rejected');
                if (!$this->managedNodeTrafficReady($id)) throw new RuntimeException('Node traffic probe failed');
                if (isset($job['result']['certificate_result']) && $this->managedNodeCertificateResult($job, $status) === 'unverified') throw new RuntimeException('Installed certificate not verified');
            } catch (Throwable $error) {
                $this->managedNodeRestoreClient($id, $saved['before']);
                $this->managedNodeWrite($id, static function (&$node) {
                    $node['job']['phase'] = 'wait_rollback'; $node['error'] = 'probe_failed';
                });
                return;
            }
            // A lost confirmation reply is ambiguous. Keep the job: the next
            // poll distinguishes confirmed generation from an automatic rollback.
            if (!empty($status['pending'])) $this->managedNodeRpc($id, ['action' => 'confirm', 'nonce' => $pending['nonce']]);
        }
        if (!$pending) {
            // A remote restart discards WireGuard's ephemeral session even
            // when its long-term keys and exported profile stay unchanged.
            if (in_array($this->exitNodes()[$id]['managed_profile']['channel'] ?? '', ['wireguard', 'amnezia'], true)) {
                $profile = $this->managedNodeRpc($id, ['action' => 'profile', 'peer' => null]);
                if ($this->managedNodeUseProfile($id, $profile) !== '') throw new RuntimeException('Client configuration rejected');
            }
            if (!$this->managedNodeTrafficReady($id)) throw new RuntimeException('Restarted node traffic probe failed');
        }
        $status = $this->managedNodeRpc($id, ['action' => 'status']);
        $this->managedNodeTransport($id, 'snapshot');
        $certificateResult = isset($job['result']['certificate_result']) || in_array($saved['operation'] ?? '', ['renew','renew_force','certificate_delete'], true) ? $this->managedNodeCertificateResult($job, $status) : '';
        // Full update: whether the node's Git clone advanced or kept local edits.
        $checkout = ($saved['operation'] ?? '') === 'upgrade' && in_array($job['checkout'] ?? '', ['updated', 'current', 'kept'], true) ? $job['checkout'] : '';
        $this->managedNodeFinish($id, $saved, static function (&$node) use ($status, $saved, $certificateResult, $checkout) {
            $node['job'] = null; $node['status'] = $status; $node['checked'] = time(); $node['backup_time'] = time(); unset($node['error'], $node['error_stage']);
            $node['last_operation'] = ['operation'=>$saved['operation'] ?? '', 'subject'=>$saved['subject'] ?? '', 'time'=>time(), 'ok'=>true, 'certificate_result'=>$certificateResult];
            if ($checkout !== '') $node['last_operation']['checkout'] = $checkout;
            if (($saved['operation'] ?? '') === 'restore') unset($node['recovery_required']);
        });
    }

    private function managedNodeFinish(string $id, array $saved, callable $edit): void
    {
        // SSH and traffic probes have finished. Serialize only the final state
        // write and Telegram redraw with navigation of this origin message.
        $this->managedNodeScreenLocked($saved['origin'] ?? [], function () use ($id, $saved, $edit) {
            $this->managedNodeWrite($id, static function (&$node) use (&$saved, $edit) {
                $saved['origin'] = $node['job']['origin'] ?? $saved['origin'] ?? [];
                $edit($node);
            });
            $this->managedNodeOperationScreen($id, $saved);
        });
    }

    public function checkManagedNodes(): void
    {
        if ($this->managedNodeCronAt && time() - $this->managedNodeCronAt < 15) return;
        $this->managedNodeCronAt = time();
        foreach ($this->managedNodes() as $id => $node) {
            try {
                if ($node['job']) $this->managedNodePoll((string) $id);
                else {
                    $this->managedNodeAutoAmnezia((string) $id);
                    $current=$this->managedNodes()[$id];
                    if ($current['connected'] && !$current['job'] && time()-(int)($current['status_attempt'] ?? 0)>=60) $this->managedNodeCheckStatus((string)$id);
                }
            }
            catch (Throwable $error) { /* Retry without logging private requests or responses. */ }
        }
    }

    public function managedNodesMenu(string $notice = ''): void
    {
        $text = [$this->t('Menu → Ноды', 'Menu → Nodes'), $this->t('Управление отдельными серверами по SSH. Маршруты, наборы и пользователей настраивает основной бот.',
            'Manage separate servers over SSH. The main bot controls routes, rule sets and users.')];
        $data = [];
        foreach ($this->managedNodes() as $id => $node) $data[] = [['text' => ($node['job'] ? '⏳ ' : ($node['connected'] ? '🖥 ' : '➕ ')) . $node['name'], 'callback_data' => "/node $id"]];
        if (count($data) < self::EXIT_MAX) $data[] = [['text' => $this->t('➕ Добавить ноду', '➕ Add node'), 'callback_data' => '/nodeAdd']];
        $data[] = [['text' => $this->t('🌍 Узлы выхода и локальный IPv6', '🌍 Exit nodes and local IPv6'), 'callback_data' => '/exits']];
        $data[] = $this->menuHelpButton('managednodes');
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => '/menu']];
        if ($notice !== '') $text[] = self::esc($notice);
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n\n", $text), $data);
    }

    public function managedNodeAddPrompt(): void
    {
        $this->exitPrompt($this->t('введите название новой ноды.', 'enter the name of the new node.'), 'saveManagedNodeAdd', []);
    }

    public function saveManagedNodeAdd($name): void
    {
        $name = trim((string) $name);
        if ($name === '' || mb_strlen($name) > 40 || preg_match('~[\x00-\x1f\x7f]~', $name) || count($this->managedNodes()) >= self::EXIT_MAX) {
            $this->managedNodesMenu($this->t('Введите название длиной 1–40 символов; допускается не более 8 нод.', 'Use a name of 1–40 characters; at most 8 nodes are supported.')); return;
        }
        $id = self::exitNewId();
        try {
            $this->managedNodeTransport($id, 'public');
            $this->managedNodeWrite($id, static function (&$node) use ($name) { $node = ['name' => $name, 'connected' => false]; });
            $this->managedNodeMenu($id);
        } catch (Throwable $error) { $this->managedNodesMenu($this->t('Не удалось подготовить ключ ноды.', 'Could not prepare the node key.')); }
    }

    public function managedNodeMenu(string $id, string $notice = ''): void
    {
        $node = $this->managedNodes()[$id] ?? null;
        if (!$node) { $this->managedNodesMenu(); return; }
        $text = [$this->t('Menu → Ноды → ', 'Menu → Nodes → ') . self::esc($node['name'])];
        $data = [];
        if (!$node['connected']) {
            try { $key = $this->managedNodeTransport($id, 'public')['public_key']; }
            catch (Throwable $error) { $key = ''; }
            $text[] = $this->t('Установите на отдельном сервере режим ноды: <code>bash init.sh --mode node</code>. Введите этот публичный ключ и публичные адреса основного бота:',
                'Install node mode on a separate server: <code>bash init.sh --mode node</code>. Supply this public key and the main bot’s public addresses:');
            $text[] = '<code>' . self::esc($key) . '</code>';
            $text[] = $this->t('Приватный ключ остаётся в основном боте. После установки скопируйте публичный ключ сервера ноды из вывода установщика.',
                'The private key stays on the main bot. After installation copy the node server’s public key from the installer output.');
            $data[] = [['text' => $this->t('🔗 Подключить по SSH', '🔗 Connect over SSH'), 'callback_data' => "/nodeConnect $id"]];
        } else {
            $status = $node['status'];
            $options = $status['options'] ?? [];
            $fresh = !empty($node['checked']) && time()-(int)$node['checked']<=180;
            $failed = !empty($node['status_error']) || ($fresh && empty($status['running']));
            $text[] = $this->t('Состояние: ', 'State: ') . ($failed ? $this->t('🔴 не отвечает или остановлена', '🔴 unavailable or stopped')
                : ($fresh ? $this->t('🟢 работает', '🟢 running') : $this->t('⚪ проверка устарела', '⚪ stale check')));
            $text[] = $this->t('Проверка состояния — каждую минуту; последняя: ', 'Status checked every minute; last check: ')
                . (!empty($node['status_attempt']) ? date('Y-m-d H:i:s', (int)$node['status_attempt']) : $this->t('ожидается', 'pending'));
            $text[] = self::esc(strtoupper((string) ($options['transport'] ?? '')) . ' · ' . $this->managedNodeValueLabel($id, 'core', $options['core'] ?? 'origin')
                . ' · VPN IPv' . ($options['connect_family'] ?? '?') . ' → IPv' . ($options['family'] ?? '?'));
            if (!empty($options['wireguard']['enabled'])) $text[] = !empty($options['wireguard']['active'])
                ? $this->t('Связь с основным ботом: WireGuard UDP/51820.', 'Main bot link: WireGuard UDP/51820.')
                : str_replace('VLESS', self::managedNodeDirectLabel($options), $this->t('Резерв WireGuard разрешён; основной бот использует VLESS.', 'WireGuard backup enabled; the main bot uses VLESS.'));
            if (!empty($options['amnezia']['enabled'])) $text[] = !empty($options['amnezia']['active'])
                ? str_replace('VLESS', self::managedNodeDirectLabel($options), $this->t('Связь с основным ботом: VLESS через AmneziaWG UDP/51821.', 'Main bot link: VLESS over AmneziaWG UDP/51821.'))
                : $this->t('Резерв AmneziaWG разрешён.', 'AmneziaWG backup enabled.');
            array_push($text, ...$this->managedNodeCardDetails($id, $node));
            array_push($text, ...$this->managedNodeDomainSummary($node));
            $text[] = $this->t('Копия состояния ноды: ', 'Node state snapshot: ') . (!empty($node['backup_time'])
                ? date('Y-m-d H:i', (int) $node['backup_time']) : $this->t('ещё не создана', 'not created yet'));
            if (!empty($node['recovery_required'])) {
                $text[] = $this->t('Запрошено восстановление после переустановки. Проверьте SSH и восстановите сохранённую копию ноды: до этого её автоматическое обновление и остальные изменения заблокированы.',
                    'Recovery after reinstall was requested. Verify SSH and restore the saved node snapshot: automatic snapshot refresh and other changes are blocked until then.');
                $data[] = [['text' => $this->t('Восстановить копию ноды', 'Restore node snapshot'), 'callback_data' => "/nodeRestore $id"]];
            }
            if (isset($node['draft'])) $text[] = $this->t('Есть черновик настроек. Перед обслуживанием или изменением внешних подключений примените либо отмените его в «Xray и подключение».', 'A settings draft is pending. Apply or discard it in Xray and connection before maintenance or external peer changes.');
            if (!empty($node['last_operation']) && empty($node['error']) && !$node['job']) {
                $last = $node['last_operation'];
                if (!empty($last['certificate_result']) && empty($node['error']) && !$node['job']) $text[] = $this->managedNodeCertificateNotice($last['certificate_result']);
                else $text[] = $this->t('✅ Последнее подтверждённое изменение: ', '✅ Last confirmed change: ') . self::esc($this->managedNodeOperationLabel($last))
                    . ' · ' . date('Y-m-d H:i', (int) ($last['time'] ?? 0));
                if (($last['operation'] ?? '') === 'rotate') $text[] = $this->t('Основной бот получил обновлённый профиль автоматически. После смены общих ключей REALITY, Encryption или ML-DSA обновите профили во внешних панелях. Секретные ключи в карточке не публикуются.',
                    'The main bot received the updated profile automatically. After rotating shared REALITY, Encryption or ML-DSA keys, update profiles in external panels. Secret keys are not published in this card.');
            }
            if ($node['job']) $text[] = $this->managedNodeOperationLabel($node['job']) . ': ' . $this->t('⏳ Выполняется изменение. Подтверждение — после проверки трафика; при отказе нода откатится автоматически.',
                '⏳ A change is in progress. It is confirmed after a traffic test; the node rolls back automatically on failure.');
            if (($node['error'] ?? '') === 'code_upgrade_failed') $text[] = $this->managedNodeUpgradeFailure((string) ($node['error_stage'] ?? ''));
            elseif (!empty($node['error'])) $text[] = $this->t('Последнее изменение не подтверждено; проверьте связь и состояние отката.', 'The last change was not confirmed; check connectivity and rollback status.');
            if (($node['last_operation']['checkout'] ?? '') === 'kept' && empty($node['error']) && !$node['job']) $text[] = $this->t('Код ноды обновлён. Каталог /root/vpnbot на ноде оставлен без изменений: в нём локальные правки, другая ветка или более новый коммит.',
                'Node code was updated. The /root/vpnbot directory on the node was left unchanged: it has local edits, another branch or a newer commit.');
            $data[] = [['text' => $this->t('⚙️ Xray и подключение', '⚙️ Xray and connection'), 'callback_data' => "/nodeSettings $id"]];
            $data[] = [['text' => $this->t('🧭 Маршруты и наборы', '🧭 Routes and rule sets'), 'callback_data' => "/nr $id"],
                ['text' => $this->t('👥 Пользователи', '👥 Users'), 'callback_data' => "/nuUsers $id 0"]];
            $data[] = [['text' => $this->t('📊 Диагностика', '📊 Diagnostics'), 'callback_data' => "/ndDiag $id"],
                ['text' => $this->t('🔄 Обновить состояние', '🔄 Refresh status'), 'callback_data' => "/nodeRefresh $id"]];
            $data[] = [['text' => $this->t('🔧 Обслуживание', '🔧 Maintenance'), 'callback_data' => "/nodeMaintenance $id"]];
            $data[] = [['text' => $this->t('🔐 SSH-адрес и порт', '🔐 SSH address and port'), 'callback_data' => "/nodeSsh $id"]];
            $data[] = [['text' => $this->t('🛡 Серверы для VPN (без SSH)', '🛡 VPN servers (no SSH)'), 'callback_data' => "/nodeVpn $id"]];
            $data[] = [['text' => $this->t('🔗 Внешние панели и подключения', '🔗 External panels and connections'), 'callback_data' => "/nodePeers $id"]];
        }
        $data[] = [['text' => $this->t('🗑 Удалить из основного бота', '🗑 Remove from main bot'), 'callback_data' => "/ndDel $id"]];
        $data[] = $this->menuHelpButton('managednodes', $id);
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => '/nodes']];
        if ($notice !== '') $text[] = self::esc($notice);
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n\n", $text), $data);
    }

    public function managedNodeConnectPrompt(string $id): void
    {
        if (!isset($this->managedNodes()[$id])) return;
        $this->exitPrompt($this->t('введите через пробел: публичный IPv4 или IPv6 ноды, порт SSH, публичный ключ сервера <code>ssh-ed25519 …</code>. Ключ берётся из установщика или доверенной консоли сервера.',
            'enter, separated by spaces: the node’s public IPv4 or IPv6, SSH port, and server public key <code>ssh-ed25519 …</code>. Obtain the key from the installer or a trusted server console.'), 'saveManagedNodeEndpoint', [$id]);
    }

    public function managedNodeSshPrompt(string $id): void
    {
        $node = $this->managedNodes()[$id] ?? null;
        if (!$node || !$node['connected'] || $node['job']) { $this->managedNodeMenu($id); return; }
        $this->exitPrompt($this->t('введите публичный IPv4 или IPv6 этой же ноды и порт SSH через пробел. Сохранённый ключ сервера будет проверен; при отказе останется прежний адрес. Это меняет только SSH-управление. Семейство VPN задаётся отдельно в настройках Xray.',
            'enter this same node’s public IPv4 or IPv6 and SSH port, separated by a space. The saved server key will be checked; failure keeps the old address. This changes SSH management only. Select the VPN address family separately in Xray settings.'), 'saveManagedNodeSsh', [$id]);
    }

    public function saveManagedNodeSsh($text, $id): void
    {
        try {
            $this->managedNodeLocked($id, function () use ($text, $id) {
                $node = $this->managedNodes()[$id] ?? null;
                if (!$node || !$node['connected'] || $node['job']) throw new RuntimeException('Node busy');
                $parts = preg_split('~\s+~', trim((string) $text));
                if (count($parts) !== 2 || !preg_match('~^[0-9]{1,5}$~D', $parts[1]) || $this->exitAddressProblem($parts[0]) !== '') throw new RuntimeException('Invalid endpoint');
                if (str_contains($parts[0], ':') && !$this->exitIpv6Network()) throw new RuntimeException('IPv6 is not prepared');
                $reply = $this->managedNodeTransport($id, 'reconnect', ['address' => $parts[0], 'port' => (int) $parts[1]]);
                $this->managedNodeWrite($id, static function (&$node) use ($reply) { $node['status'] = $reply['status']; $node['checked'] = time(); });
            });
            $this->managedNodeMenu($id, $this->t('SSH-соединение проверено, адрес сохранён.', 'SSH connection verified, address saved.'));
        } catch (Throwable $error) {
            $this->managedNodeMenu($id, $this->t('Не удалось изменить SSH-подключение. Проверьте доступность адреса, порт, ключ сервера и IPv6 основного бота; дождитесь окончания изменений на ноде.',
                'Could not change the SSH connection. Check address, port, server key and the main bot’s IPv6; wait for any node changes to finish.'));
        }
    }

    public function saveManagedNodeEndpoint($text, $id): void
    {
        try {
            $this->managedNodeLocked($id, function () use ($text, $id) {
                $node = $this->managedNodes()[$id] ?? null;
                if (!$node || $node['connected'] || $node['job']) throw new RuntimeException('Node is not awaiting enrollment');
                $parts = preg_split('~\s+~', trim((string) $text));
                if (count($parts) !== 4 || !preg_match('~^[0-9]{1,5}$~D', $parts[1]) || $this->exitAddressProblem($parts[0]) !== '') throw new RuntimeException('Invalid endpoint');
                if (str_contains($parts[0], ':') && !$this->exitIpv6Network()) throw new RuntimeException('IPv6 is not prepared');
                $this->managedNodeTransport($id, 'connect', ['address' => $parts[0], 'port' => (int) $parts[1], 'host_key' => $parts[2] . ' ' . $parts[3]]);
                $status = $this->managedNodeRpc($id, ['action' => 'status']);
                if (!empty($status['pending'])) throw new RuntimeException('Node change awaits confirmation');
                $profile = $this->managedNodeRpc($id, ['action' => 'profile', 'peer' => null]);
                $this->managedNodeTransport($id, 'snapshot');
                $before = $this->exitNodes()[$id] ?? null;
                if ($this->managedNodeUseProfile($id, $profile) !== '') throw new RuntimeException('Client rejected');
                try {
                    if (!$this->managedNodeTrafficReady($id)) throw new RuntimeException('Node traffic probe failed');
                    $this->managedNodeWrite($id, static function (&$node) use ($status) {
                        $node['connected'] = true; $node['status'] = $status; $node['checked'] = time(); $node['backup_time'] = time();
                    });
                } catch (Throwable $error) {
                    $this->managedNodeRestoreClient($id, $before);
                    throw $error;
                }
            });
            $this->managedNodeMenu($id, $this->t('Нода подключена. Выберите маршруты и пользователей.', 'Node connected. Select routes and users.'));
        } catch (Throwable $error) {
            $this->managedNodeMenu($id, $this->t('Подключение не завершено. Проверьте адрес, ключ сервера и разрешённые источники SSH. Для IPv6 сначала настройте IPv6 основного бота; для SMUX нужно fork-ядро с обеих сторон.',
                'Connection did not complete. Check address, server key and permitted SSH sources. Prepare the main bot’s IPv6 first; SMUX needs the fork on both sides.'));
        }
    }

    public function managedNodeRebindPrompt(string $id): void
    {
        $node = $this->managedNodes()[$id] ?? null;
        if (!$node || !$node['connected']) return;
        try { $key = $this->managedNodeTransport($id, 'public')['public_key']; }
        catch (Throwable $error) { $this->managedNodeMenu($id, $this->t('Ключ управления недоступен.', 'Controller key unavailable.')); return; }
        $this->exitPrompt($this->t('после переустановки ноды передайте её установщику этот публичный ключ управления:',
            'after reinstalling the node, supply its installer with this public controller key:') . "\n<code>" . self::esc($key) . "</code>\n\n"
            . $this->t('Сверьте новый публичный ключ SSH сервера через доверенную консоль. Введите через пробел: публичный IP ноды, порт SSH, <code>ssh-ed25519 …</code>. После привязки потребуется восстановить сохранённую копию ноды; старые настройки и ключи клиентов сохранятся в ней.',
                'Verify the new SSH server public key using a trusted console. Enter separated by spaces: public node IP, SSH port, <code>ssh-ed25519 …</code>. Then restore the saved node snapshot; its original settings and client identities will be preserved.'),
            'saveManagedNodeRebind', [$id]);
    }

    public function saveManagedNodeRebind($text, $id): void
    {
        try {
            $this->managedNodeLocked($id, function () use ($text, $id) {
                $before = $this->managedNodes()[$id] ?? null;
                if (!$before || !$before['connected']) throw new RuntimeException('Node not enrolled');
                $parts = preg_split('~\s+~', trim((string) $text));
                if (count($parts) !== 4 || !preg_match('~^[0-9]{1,5}$~D', $parts[1]) || $this->exitAddressProblem($parts[0]) !== '') throw new RuntimeException('Invalid endpoint');
                if (str_contains($parts[0], ':') && !$this->exitIpv6Network()) throw new RuntimeException('IPv6 is not prepared');
                $this->managedNodeTransport($id, 'saved');
                // Persist protection before changing the endpoint. A crash must
                // never let cron overwrite the recovery source with defaults.
                $this->managedNodeWrite($id, static function (&$node) { $node['recovery_required'] = true; });
                // A lost helper reply is ambiguous: the endpoint may already
                // have changed. Keep recovery protection even on failure.
                $reply = $this->managedNodeTransport($id, 'rebind', ['address' => $parts[0], 'port' => (int) $parts[1], 'host_key' => $parts[2] . ' ' . $parts[3]]);
                $this->managedNodeWrite($id, static function (&$node) use ($reply) {
                    $node['status'] = $reply['status']; $node['checked'] = time(); $node['job'] = null;
                    unset($node['draft'], $node['draft_generation'], $node['error']);
                });
            });
            $this->managedNodeMenu($id, $this->t('SSH проверен. Теперь восстановите сохранённую копию ноды.', 'SSH verified. Now restore the saved node snapshot.'));
        } catch (Throwable $error) {
            $this->managedNodeMenu($id, $this->t('Привязка не завершена. Проверьте публичный ключ SSH, адрес, разрешённые источники и наличие сохранённой копии; дождитесь завершения операций на ноде.',
                'Rebinding did not complete. Check the SSH public key, address, permitted sources and saved snapshot; wait for node operations to finish.'));
        }
    }

    private function managedNodeCheckStatus(string $id): void
    {
        $this->managedNodeWrite($id, static function (&$node) { $node['status_attempt']=time(); });
        try {
            $status=$this->managedNodeRpc($id, ['action'=>'status']);
            $this->managedNodeWrite($id, static function (&$node) use ($status) {
                $node['status']=$status; $node['checked']=time(); unset($node['status_error']);
            });
        } catch (Throwable $error) {
            $this->managedNodeWrite($id, static function (&$node) { $node['status_error']=true; });
            throw $error;
        }
    }

    public function managedNodeRefresh(string $id): void
    {
        try {
            $this->managedNodePoll($id);
            $this->managedNodeCheckStatus($id);
            $this->managedNodeMenu($id);
        } catch (Throwable $error) { $this->managedNodeMenu($id, $this->t('SSH недоступен или нода занята. Состояние пока не обновлено.', 'SSH unavailable or node busy. Status has not been refreshed.')); }
    }

    private function managedNodeOperationLabel(array $operation): string
    {
        $name = ($operation['operation'] ?? '') === 'rotate' ? 'rotate_' . ($operation['subject'] ?? '') : ($operation['operation'] ?? '');
        $labels = ['restart'=>['ru'=>'перезапуск','en'=>'restart'], 'configure'=>['ru'=>'настройки','en'=>'settings'], 'peers'=>['ru'=>'внешние подключения','en'=>'external connections'],
            'update'=>['ru'=>'обновление комплекта','en'=>'bundle update'], 'upgrade'=>['ru'=>'обновление кода и образов','en'=>'code and image update'], 'renew'=>['ru'=>'сертификат','en'=>'certificate'], 'rollback'=>['ru'=>'откат','en'=>'rollback'], 'restore'=>['ru'=>'восстановление','en'=>'restore'],
            'renew_force'=>['ru'=>'принудительный выпуск сертификата','en'=>'forced certificate issuance'], 'certificate_delete'=>['ru'=>'удаление сертификата','en'=>'certificate deletion'],
            'rotate_controller'=>['ru'=>'ключ клиента основного бота','en'=>'main bot client identity'], 'rotate_reality'=>['ru'=>'ключи REALITY','en'=>'REALITY keys'],
            'rotate_encryption'=>['ru'=>'ключи VLESS Encryption','en'=>'VLESS Encryption keys'], 'rotate_mldsa'=>['ru'=>'ключи ML-DSA','en'=>'ML-DSA keys'],
            'rotate_wireguard'=>['ru'=>'ключи WireGuard','en'=>'WireGuard keys'], 'rotate_amnezia'=>['ru'=>'ключи AmneziaWG','en'=>'AmneziaWG keys']];
        return $this->t(...($labels[$name] ?? ['ru'=>'изменение ноды','en'=>'node change']));
    }

    private function managedNodeOperationScreen(string $id, array $job): void
    {
        if (empty($job['origin']['chat']) || empty($job['origin']['message_id'])) return;
        $input = $this->input;
        try {
            $this->input = array_replace($input ?? [], array_intersect_key($job['origin'], array_flip(['chat', 'message_id'])));
            $node=$this->managedNodes()[$id];
            if (!empty($job['origin']['moved'])) {
                // The admin opened another screen in this message: report by a
                // notice instead of replacing the menu they are working in.
                $this->send($this->input['chat'], self::esc($node['name'])."\n".(empty($node['error'])
                    ? $this->t('✅ Завершено: ', '✅ Completed: ').self::esc($this->managedNodeOperationLabel($job))
                    : (($node['error'] ?? '') === 'code_upgrade_failed' ? $this->managedNodeUpgradeFailure((string) ($node['error_stage'] ?? ''))
                    : $this->t('↩️ Не применено, нода вернула прежнее состояние: ', '↩️ Not applied, the node restored its previous state: ').self::esc($this->managedNodeOperationLabel($job)))));
            } else {
                $this->managedNodeMenu($id);
            }
            if (!empty($node['error']) && in_array($job['operation'] ?? '', ['renew','renew_force','certificate_delete'],true)) {
                $this->send($this->input['chat'], self::esc($node['name'])."\n".$this->t('❌ Операция с сертификатом не подтверждена. Проверьте состояние ноды; сообщение об успешном обновлении не выдано.',
                    '❌ Certificate operation was not confirmed. Check node status; renewal success was not reported.'));
            } elseif (empty($node['error']) && !empty($node['last_operation']['certificate_result'])) {
                $this->send($this->input['chat'], self::esc($node['name'])."\n".$this->managedNodeCertificateNotice($node['last_operation']['certificate_result']));
            }
        } catch (Throwable $e) { /* Confirmed state is durable even if Telegram is unavailable. */ }
        finally { $this->input = $input; }
    }

    public function managedNodeMaintenance(string $id, string $notice = ''): void
    {
        if (!isset($this->managedNodes()[$id])) return;
        $data = [];
        foreach (['restart' => ['ru' => 'Перезапустить', 'en' => 'Restart'], 'update_latest' => ['ru' => 'Обновить с ветки master', 'en' => 'Update stable bundle'],
            'update_dev' => ['ru' => 'Обновить с ветки dev', 'en' => 'Update dev bundle'], 'rollback' => ['ru' => 'Откатить последнее изменение', 'en' => 'Roll back last change'],
            'rotate_controller' => ['ru' => 'Сменить ключ клиента основного бота', 'en' => 'Rotate the main bot client identity'],
            'rotate_reality' => ['ru' => 'Сменить ключи REALITY', 'en' => 'Rotate REALITY keys'], 'rotate_encryption' => ['ru' => 'Сменить ключи VLESS Encryption', 'en' => 'Rotate VLESS Encryption keys'],
            'rotate_mldsa' => ['ru' => 'Сменить ключи ML-DSA', 'en' => 'Rotate ML-DSA keys'],
            'rotate_wireguard' => ['ru' => 'Сменить ключи WireGuard', 'en' => 'Rotate WireGuard keys'],
            'rotate_amnezia' => ['ru' => 'Сменить ключи AmneziaWG', 'en' => 'Rotate AmneziaWG keys']] as $action => $label) {
            $data[] = [['text' => $this->t(...$label), 'callback_data' => "/nodeRun $id $action"]];
        }
        $data[] = [['text'=>$this->t('Сертификат: выпуск, обновление, удаление','Certificate: issue, renew, delete'), 'callback_data'=>"/nodeCert $id"]];
        $data[] = [['text'=>$this->t('Создать копию ноды','Create node snapshot'), 'callback_data'=>"/nodeBackup $id"]];
        $data[] = [['text' => $this->t('Восстановить сохранённую копию ноды', 'Restore saved node snapshot'), 'callback_data' => "/nodeRestore $id"]];
        $data[] = [['text' => $this->t('📥 Скачать копию ноды', '📥 Download node snapshot'), 'callback_data' => "/nodeExport $id"],
                   ['text' => $this->t('📤 Загрузить копию ноды', '📤 Upload node snapshot'), 'callback_data' => "/nodeImport $id"]];
        $data[] = [['text' => $this->t('Привязать SSH после переустановки', 'Rebind SSH after reinstall'), 'callback_data' => "/nodeRebind $id"]];
        $data[] = $this->menuHelpButton('nodemaint', $id);
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => "/node $id"]];
        $status = $this->managedNodes()[$id]['status'] ?? [];
        if ((($status['code'] ?? [])['upgrade'] ?? false) !== true) $line = $this->managedNodeManualCode();
        else $line = $this->managedNodeVersionLine(is_array($status) ? $status : []) . "\n" . $this->t('Кнопки обновления обновляют и код, и образы.', 'The update buttons update both code and images.');
        $this->update($this->input['chat'], $this->input['message_id'], $this->t('Ноды → Обслуживание', 'Nodes → Maintenance') . "\n\n" . $line . ($notice === '' ? '' : "\n\n" . self::esc($notice)), $data);
    }

    public function managedNodeRun(string $id, string $action, bool $confirmed = false): void
    {
        $operations = ['restart' => ['restart', null], 'rollback' => ['rollback', null], 'renew' => ['renew', null], 'renew_force'=>['renew_force', null], 'certificate_delete'=>['certificate_delete', null],
            'update_latest' => ['update', 'latest'], 'update_dev' => ['update', 'dev'],
            'rotate_controller' => ['rotate', 'controller'], 'rotate_reality' => ['rotate', 'reality'],
            'rotate_encryption' => ['rotate', 'encryption'], 'rotate_mldsa' => ['rotate', 'mldsa'], 'rotate_wireguard' => ['rotate', 'wireguard'],
            'rotate_amnezia' => ['rotate', 'amnezia']];
        if (!isset($operations[$action]) || !isset($this->managedNodes()[$id])) return;
        // A node with the upgrade unit updates its code and then its images.
        $upgrade = ($this->managedNodes()[$id]['status']['code']['upgrade'] ?? false) === true;
        if ($upgrade && $operations[$action][0] === 'update') $operations[$action][0] = 'upgrade';
        $options = $this->managedNodes()[$id]['status']['options'] ?? [];
        $active = match ($action) {
            'rotate_wireguard' => !empty($options['wireguard']['enabled']),
            'rotate_amnezia' => !empty($options['amnezia']['enabled']),
            'rotate_encryption' => ($options['xray']['encryption']['auth'] ?? 'off') !== 'off',
            'rotate_mldsa' => !empty($options['xray']['reality']['mldsa']),
            default => true,
        };
        if (!$active) { $this->managedNodeMaintenance($id, $this->t('Этот протокол или вид шифрования отключён. Сначала включите и примените его настройки. Ключи не менялись.',
            'This protocol or encryption feature is disabled. Enable and apply it first. No keys were changed.')); return; }
        if (!$confirmed) {
            $imagesOnly = !$upgrade && $operations[$action][0] === 'update';
            $help = $this->managedNodeActionHelp($imagesOnly ? 'images_' . $operations[$action][1] : $action);
            if ($imagesOnly) $help .= "\n\n" . $this->managedNodeManualCode();
            $this->update($this->input['chat'], $this->input['message_id'], $help . "\n\n" . $this->t('Выполнить?', 'Proceed?'),
                [[['text' => $this->t('Выполнить', 'Proceed'), 'callback_data' => "/nodeRun $id $action yes"]],
                 [['text' => $this->i18n('back'), 'callback_data' => "/nodeMaintenance $id"]]]);
            return;
        }
        try { $this->managedNodeSubmit($id, ...$operations[$action]); $this->managedNodeMenu($id); }
        catch (Throwable $error) { $this->managedNodeMenu($id, $this->t('Операция не запущена: нода недоступна или занята.', 'Operation not started: node unavailable or busy.')); }
    }

    public function managedNodeRestore(string $id, string $hash = ''): void
    {
        try {
            $this->managedNodeLocked($id, function () use ($id, $hash) {
                $node = $this->managedNodes()[$id] ?? null;
                if (!$node || !$node['connected'] || $node['job']) throw new RuntimeException('Node not ready');
                // Read the chosen backup before asking the remote for current
                // state. Refreshing a backup here would destroy the restore source.
                $saved = $this->managedNodeTransport($id, 'saved');
                if (!is_array($saved['snapshot'] ?? null) || !preg_match('~^[a-f0-9]{16}$~D', (string) ($saved['hash'] ?? ''))) {
                    throw new RuntimeException('Invalid saved snapshot');
                }
                if ($hash === '') {
                    $text = $this->t('Восстановить сохранённую копию ноды? Будут заменены настройки Xray, сертификат и ключи подключений, включая внешние панели. SSH и адреса сервера остаются прежними. Возможен краткий обрыв соединений. Основной бот проверит трафик до подтверждения.',
                        'Restore the saved node snapshot? This replaces Xray settings, certificate and connection identities, including external panels. SSH and server addresses stay as they are. Connections may briefly drop. The main bot tests traffic before confirming.');
                    if (!empty($node['backup_time'])) $text .= "\n\n" . date('Y-m-d H:i', (int) $node['backup_time']);
                    $this->update($this->input['chat'], $this->input['message_id'], $text,
                        [[['text' => $this->t('Восстановить эту копию', 'Restore this snapshot'), 'callback_data' => "/nodeRestore $id {$saved['hash']}"]],
                         [['text' => $this->i18n('back'), 'callback_data' => "/nodeMaintenance $id"]]]);
                    return;
                }
                if (!hash_equals($saved['hash'], $hash)) throw new RuntimeException('Snapshot changed');
                $status = $this->managedNodeRpc($id, ['action' => 'status']);
                if (!empty($status['pending'])) throw new RuntimeException('Node awaits confirmation');
                $this->managedNodeSubmitLocked($id, 'restore', $saved['snapshot'], (string) ($status['generation'] ?? ''));
                $this->managedNodeMenu($id);
            });
        } catch (Throwable $error) {
            $this->managedNodeMenu($id, $this->t('Восстановление не запущено: копия изменилась или недоступна, либо нода занята. Заново откройте восстановление после проверки SSH.',
                'Restore not started: snapshot changed or unavailable, or node busy. Check SSH and open restore again.'));
        }
    }
}
