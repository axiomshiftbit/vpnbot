<?php

/**
 * Node card details and the node snapshot file.
 *
 * Every value in the card comes from a measurement: the node status (read by
 * the node from /proc and its own state at the last check) or the main bot's
 * own probes and counters. A missing source is shown as unknown, never guessed.
 */
trait BotManagedNodeCard
{
    public const NODE_FILE_TYPE = 'vpnbot-node-snapshot';
    public const NODE_FILE_MAX_BYTES = 262144;
    public const NODE_CARD_SERVERS = 12;
    public const NODE_CARD_USERS = 8;

    /** Lines for a connected node's card, below its state and transport. */
    public function managedNodeCardDetails(string $id, array $node): array
    {
        $status = is_array($node['status'] ?? null) ? $node['status'] : [];
        // No successful status check yet: nothing is known about the node.
        if (!isset($status['running'])) return [];
        $lines = [$this->managedNodeVersionLine($status)];
        $host = is_array($status['host'] ?? null) ? $status['host'] : null;
        $checked = !empty($node['checked']) ? date('H:i:s', (int) $node['checked']) : '';
        if ($host === null) {
            $lines[] = $this->t('Состояние сервера ноды: нет данных — код ноды их ещё не сообщает.', 'Node server state: no data — the node code does not report it yet.');
        } else {
            if (($server = $this->managedNodeServerLine($host)) !== '') $lines[] = $server . ($checked !== '' ? $this->t(' (проверка ', ' (check ') . $checked . ')' : '');
            $lines[] = $this->managedNodeConnectionsBlock($host);
        }
        $exit = $this->exitNodes()[$id] ?? null;
        if ($exit !== null) {
            $lines[] = $this->t('Проверка трафика основным ботом: ', 'Main bot traffic check: ') . $this->exitStatusLine($id, $exit)
                . (($history = $this->exitHistoryLine($this->exitStatus()[$id] ?? [])) !== '' ? "\n" . $history : '');
            $lines[] = $this->exitTrafficLine($id);
            if (isset($exit['managed_profile']['warp_uuid'])) $lines[] = $this->exitWarpHealthLine($id);
            $lines[] = $this->managedNodeUsersLine($id);
        }
        return array_values(array_filter($lines, static fn($line) => $line !== ''));
    }

    private function managedNodeVersionLine(array $status): string
    {
        $code = is_array($status['code'] ?? null) ? $status['code'] : [];
        if (($code['upgrade'] ?? false) !== true) {
            return $this->t('Версия ноды: код старше обновления кнопкой, коммит не сообщается.', 'Node version: code predates button updates, no commit reported.');
        }
        $commit = static fn($value) => is_string($value) && preg_match('~^[a-f0-9]{40}$~D', $value) ? '<code>' . substr($value, 0, 7) . '</code>' : null;
        $source = $commit($code['source'] ?? null);
        if ($source !== null) $text = $this->t('код ', 'code ') . $source . (($code['origin'] ?? '') === 'manual' ? $this->t(' (вручную)', ' (manual)') : '');
        elseif (($code['origin'] ?? '') === 'manual') $text = $this->t('код установлен вручную, коммит не определён (локальные правки или не Git-клон)', 'code installed manually, commit unknown (local edits or not a Git clone)');
        else $text = $this->t('коммит кода неизвестен', 'code commit unknown');
        if (($code['verified'] ?? null) === false) $text .= $this->t(' ⚠️ файлы кода на ноде изменены после установки', ' ⚠️ node code files changed after installation');
        if (!array_key_exists('images', $code)) $text .= $this->t(' · образы: нет данных', ' · images: no data');
        elseif (($images = $commit($code['images'])) !== null) $text .= $this->t(' · образы ', ' · images ') . $images;
        else $text .= $this->t(' · образы не из последнего скачанного комплекта', ' · images not from the last downloaded bundle');
        $core = (string) ($status['options']['core'] ?? '');
        $version = (string) ($status['cores'][$core] ?? '');
        if (preg_match('~^[0-9][A-Za-z0-9.+_-]{0,47}$~D', $version)) $text .= ' · Xray ' . self::esc($version);
        return $this->t('Версия ноды: ', 'Node version: ') . $text;
    }

    private function managedNodeServerLine(array $host): string
    {
        $parts = [];
        if (is_int($host['uptime'] ?? null)) $parts[] = $this->t('работает ', 'up ') . $this->managedNodeDuration($host['uptime']);
        if (is_array($host['load'] ?? null) && is_numeric($host['load'][0] ?? null)) {
            $parts[] = $this->t('нагрузка ', 'load ') . number_format((float) $host['load'][0], 2, $this->language === 'en' ? '.' : ',', '')
                . (!empty($host['cpus']) ? ' / ' . (int) $host['cpus'] . ' CPU' : '');
        }
        $labels = ['memory' => ['available', $this->t('память: свободно ', 'memory: free ')], 'disk' => ['free', $this->t('диск: свободно ', 'disk: free ')]];
        foreach ($labels as $name => [$field, $label]) {
            $value = $host[$name] ?? null;
            if (is_array($value) && is_int($value[$field] ?? null) && is_int($value['total'] ?? null) && $value['total'] > 0) {
                $parts[] = $label . $this->getBytes($value[$field]) . $this->t(' из ', ' of ') . $this->getBytes($value['total']);
            }
        }
        $network = $host['network'] ?? null;
        if (is_array($network) && is_int($network['rx'] ?? null) && is_int($network['tx'] ?? null)) {
            $parts[] = $this->t('сеть с загрузки: ↓', 'network since boot: ↓') . $this->getBytes($network['rx']) . ' ↑' . $this->getBytes($network['tx']);
        }
        return $parts ? $this->t('Сервер ноды: ', 'Node server: ') . implode(' · ', $parts) : '';
    }

    private function managedNodeDuration(int $seconds): string
    {
        $days = intdiv($seconds, 86400); $hours = intdiv($seconds % 86400, 3600); $minutes = intdiv($seconds % 3600, 60);
        if ($days > 0) return $days . $this->t(' д ', ' d ') . $hours . $this->t(' ч', ' h');
        if ($hours > 0) return $hours . $this->t(' ч ', ' h ') . $minutes . $this->t(' мин', ' min');
        return $minutes . $this->t(' мин', ' min');
    }

    /** Servers the node lets connect and their connections at the last check. */
    private function managedNodeConnectionsBlock(array $host): string
    {
        $servers = array_values(array_filter((array) ($host['servers'] ?? []), static fn($s) => is_array($s)
            && filter_var($s['address'] ?? '', FILTER_VALIDATE_IP) && in_array($s['role'] ?? '', ['main', 'vpn'], true)));
        $lines = [$this->t('Подключённые серверы (соединения с нодой при проверке):', 'Connected servers (connections to the node at the check):')];
        foreach (array_slice($servers, 0, self::NODE_CARD_SERVERS) as $server) {
            $tcp = $server['tcp'] ?? null; $udp = $server['udp'] ?? null;
            $online = (is_int($tcp) && $tcp > 0) || $udp === true;
            $unknown = !is_int($tcp) && !is_bool($udp);
            $state = [];
            if (is_int($tcp) && $tcp > 0) $state[] = 'TCP ' . $tcp;
            if ($udp === true) $state[] = 'UDP WG/AWG';
            // No TCP and an unreadable UDP table: a WireGuard/AmneziaWG peer may still be connected.
            $partial = !$online && !$unknown && $udp === null;
            $lines[] = ($unknown || $partial ? '⚪ ' : ($online ? '🟢 ' : '⚫ '))
                . ($server['role'] === 'main' ? $this->t('основной бот ', 'main bot ') : $this->t('VPN-сервер ', 'VPN server '))
                . '<code>' . self::esc($server['address']) . '</code> — '
                . ($unknown ? $this->t('нет данных', 'no data') : ($online ? implode(', ', $state)
                    : ($partial ? $this->t('TCP-соединений нет; UDP: нет данных', 'no TCP connections; UDP: no data') : $this->t('нет соединений', 'no connections'))));
        }
        if (count($servers) > self::NODE_CARD_SERVERS) $lines[] = $this->t('…и ещё ', '…and ') . (count($servers) - self::NODE_CARD_SERVERS) . $this->t(' (список — в «Серверы для VPN»)', ' more (see VPN servers)');
        if (!empty($host['local'])) $lines[] = $this->t('Внутри AmneziaWG (локально): TCP ', 'Inside AmneziaWG (local): TCP ') . (int) $host['local'];
        if (!empty($host['other'])) $lines[] = '⚠️ ' . $this->t('Соединения с адресов вне списка: ', 'Connections from addresses outside the list: ') . (int) $host['other'];
        return implode("\n", $lines);
    }

    /** Main bot users routed through this node and online on the main bot now. */
    private function managedNodeUsersLine(string $id): string
    {
        $assigned = $this->exitNodeEmails($this->getXray() ?: [], $id);
        if (!$assigned) return $this->t('Пользователи основного бота с маршрутом через ноду: нет.', 'Main bot users routed through the node: none.');
        $online = $this->managedNodeOnlineUsers();
        $text = $this->t('Пользователи основного бота с маршрутом через ноду: ', 'Main bot users routed through the node: ') . count($assigned);
        if ($online === null) return $text . $this->t(', онлайн: нет данных', ', online: no data');
        $now = array_values(array_filter($assigned, static fn($email) => isset($online[$email])));
        $text .= $this->t(', онлайн сейчас: ', ', online now: ') . count($now);
        if ($now) {
            $text .= ' — ' . implode(', ', array_map(static fn($email) => self::esc(mb_substr($email, 0, 32)), array_slice($now, 0, self::NODE_CARD_USERS)))
                . (count($now) > self::NODE_CARD_USERS ? '…' : '');
        }
        return $text . $this->t(' (онлайн на основном боте)', ' (online on the main bot)');
    }

    /** Online emails of the main bot, or null when they cannot be read. */
    protected function managedNodeOnlineUsers(): ?array
    {
        try { return $this->onlineClients(); }
        catch (Throwable $error) { return null; }
    }

    /**
     * Caption of the full backup: which node snapshots it holds and whether
     * each was refreshed by this export or is the last one saved earlier.
     */
    public function managedNodeBackupCaption(int $started): string
    {
        $lines = [];
        foreach ($this->managedNodes() as $id => $node) {
            $path = $this->managedNodeRoot . "/$id/snapshot.json";
            if (count($lines) >= 10) { $lines[] = '…'; break; }
            $name = self::esc(mb_substr((string) $node['name'], 0, 32));
            if (empty($node['connected']) || !is_file($path) || is_link($path)) { $lines[] = "• $name: " . $this->t('без копии (нода не подключена)', 'no snapshot (node not connected)'); continue; }
            $time = (int) ($node['backup_time'] ?? 0);
            $lines[] = "• $name: " . $this->t('копия от ', 'snapshot from ') . ($time ? date('Y-m-d H:i', $time) : '—')
                . ($time >= $started ? $this->t(' (свежая)', ' (fresh)') : $this->t(' ⚠️ прежняя: нода не ответила или была занята', ' ⚠️ earlier one: the node did not answer or was busy'));
        }
        return $lines ? $this->t('Копии нод в бэкапе:', 'Node snapshots in the backup:') . "\n" . implode("\n", $lines) : '';
    }

    // ── Node snapshot file ──────────────────────────────────────────────────

    /** Saved snapshot as JSON objects: {} and [] survive unchanged. */
    private function managedNodeSnapshotObject(string $id): ?object
    {
        $path = $this->managedNodeRoot . "/$id/snapshot.json";
        if (is_link($path) || !is_file($path)) return null;
        $raw = @file_get_contents($path, false, null, 0, 65537);
        if (!is_string($raw) || strlen($raw) > 65536) return null;
        try { $value = json_decode($raw, false, 64, JSON_THROW_ON_ERROR); }
        catch (JsonException $error) { return null; }
        return self::managedNodeSnapshotValid($value) ? $value : null;
    }

    public static function managedNodeSnapshotValid($value): bool
    {
        if (!$value instanceof stdClass) return false;
        $fields = array_keys(get_object_vars($value));
        sort($fields);
        return $fields === ['identity', 'images', 'options', 'peers', 'schema', 'tls'] && $value->schema === 1
            && $value->options instanceof stdClass && $value->identity instanceof stdClass && is_array($value->peers)
            && $value->images instanceof stdClass && $value->tls instanceof stdClass;
    }

    public static function managedNodeSnapshotHash(object $snapshot): string
    {
        return hash('sha256', json_encode($snapshot, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR));
    }

    public function managedNodeExport(string $id, bool $confirmed = false): void
    {
        $node = $this->managedNodes()[$id] ?? null;
        if (!$node) return;
        if (!$confirmed) {
            $this->update($this->input['chat'], $this->input['message_id'], $this->managedNodeActionHelp('export'),
                [[['text' => $this->t('📥 Отправить файл в личный чат', '📥 Send the file to my private chat'), 'callback_data' => "/nodeExport $id yes"]],
                 [['text' => $this->i18n('back'), 'callback_data' => "/nodeMaintenance $id"]]]);
            return;
        }
        try {
            if ((int) ($this->input['from'] ?? 0) <= 0) throw new RuntimeException('Private chat unavailable');
            $fresh = false;
            $this->managedNodeLocked($id, function () use ($id, &$fresh) {
                $node = $this->managedNodes()[$id] ?? null;
                // A ready node gives a fresh confirmed snapshot; otherwise the
                // last saved one is sent and the message says how old it is.
                if (!$node || empty($node['connected']) || $node['job'] || !empty($node['recovery_required'])) return;
                try {
                    $status = $this->managedNodeRpc($id, ['action' => 'status']);
                    if (!empty($status['pending']) || ($this->managedNodeTransport($id, 'snapshot')['saved'] ?? false) !== true) return;
                    $this->managedNodeWrite($id, static function (&$node) { $node['backup_time'] = time(); });
                    $fresh = true;
                } catch (Throwable $error) { /* Keep the last saved snapshot. */ }
            });
            $node = $this->managedNodes()[$id] ?? $node;
            $snapshot = $this->managedNodeSnapshotObject($id);
            if ($snapshot === null) throw new RuntimeException('No saved snapshot');
            $key = (string) ($this->managedNodeTransport($id, 'public')['public_key'] ?? '');
            if (!preg_match('~^ssh-ed25519 [A-Za-z0-9+/]{68}$~D', $key)) throw new RuntimeException('No controller key');
            $time = (int) ($node['backup_time'] ?? 0);
            $file = ['type' => self::NODE_FILE_TYPE, 'version' => 1, 'node' => ['id' => $id, 'name' => (string) $node['name']],
                'created' => time(), 'snapshot_time' => $time, 'controller_key' => $key,
                'sha256' => self::managedNodeSnapshotHash($snapshot), 'snapshot' => $snapshot];
            $body = json_encode($file, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
            $name = 'node-' . (preg_replace('~[^A-Za-z0-9_-]+~', '_', (string) $node['name']) ?: $id) . '-' . date('Ymd-Hi') . '.json';
            $sent = $this->sendFile($this->input['from'], new CURLStringFile($body, $name, 'application/json'), $this->t(
                '🔐 Копия ноды «' . self::esc($node['name']) . '» от ' . ($time ? date('Y-m-d H:i', $time) : '—') . '. Внутри ключи подключений, REALITY и сертификат ноды — храните как пароль. Восстановление: Обслуживание → «Загрузить копию ноды».',
                '🔐 Snapshot of node “' . self::esc($node['name']) . '” from ' . ($time ? date('Y-m-d H:i', $time) : '—') . '. It holds the node connection keys, REALITY keys and certificate — keep it like a password. Restore: Maintenance → Upload node snapshot.'));
            if (empty($sent['ok'])) throw new RuntimeException('Private delivery failed');
            $this->managedNodeMaintenance($id, $fresh
                ? $this->t('✅ Свежая копия ноды создана и отправлена в личный чат.', '✅ A fresh node snapshot was created and sent to your private chat.')
                : $this->t('⚠️ Нода недоступна или занята: в личный чат отправлена последняя сохранённая копия от ', '⚠️ The node is unavailable or busy: the last saved snapshot was sent to your private chat, from ')
                    . ($time ? date('Y-m-d H:i', $time) : '—') . '.');
        } catch (Throwable $error) {
            $this->managedNodeMaintenance($id, $this->t('❌ Файл не отправлен: нет сохранённой копии этой ноды или нет личного чата с ботом. Откройте личный чат командой /start и повторите.',
                '❌ File not sent: this node has no saved snapshot or there is no private chat with the bot. Open a private chat with /start and retry.'));
        }
    }

    public function managedNodeImportPrompt(string $id): void
    {
        if (!isset($this->managedNodes()[$id])) return;
        $this->exitPrompt($this->t('пришлите файл копии этой ноды (.json из «Скачать копию ноды»). Он заменит сохранённую копию; ноду бот изменит только после вашего подтверждения восстановления. Сообщение с файлом будет удалено.',
            'send this node’s snapshot file (.json from Download node snapshot). It replaces the saved snapshot; the node changes only after you confirm the restore. The message with the file is deleted.'), 'managedNodeImportFile', [$id]);
    }

    // The file from Telegram; tests replace it.
    protected function managedNodeImportDownload(): ?string
    {
        if (empty($this->input['file_id'])) return null;
        $r = $this->request('getFile', ['file_id' => $this->input['file_id']]);
        if (empty($r['ok']) || !is_string($r['result']['file_path'] ?? null) || ($r['result']['file_size'] ?? 0) > self::NODE_FILE_MAX_BYTES) return null;
        // The file URL contains the bot token: no PHP warning may reach the log.
        $data = @file_get_contents($this->file . $r['result']['file_path'], false, null, 0, self::NODE_FILE_MAX_BYTES + 1);
        return is_string($data) && strlen($data) <= self::NODE_FILE_MAX_BYTES ? $data : null;
    }

    /** Validated file contents, or an error code. */
    public function managedNodeImportParse(?string $raw, string $key): array
    {
        if ($raw === null) return ['error' => 'read'];
        try { $file = json_decode($raw, false, 64, JSON_THROW_ON_ERROR); }
        catch (JsonException $error) { return ['error' => 'format']; }
        if (!$file instanceof stdClass || ($file->type ?? null) !== self::NODE_FILE_TYPE || ($file->version ?? null) !== 1
            || !is_string($file->controller_key ?? null) || !is_string($file->sha256 ?? null) || !isset($file->snapshot)) return ['error' => 'format'];
        // The controller key binds the file to this node's enrollment: it
        // survives an OS reinstall, a different node never has it.
        if ($key === '' || !hash_equals($key, $file->controller_key)) return ['error' => 'foreign'];
        if (!self::managedNodeSnapshotValid($file->snapshot)) return ['error' => 'format'];
        if (!hash_equals(self::managedNodeSnapshotHash($file->snapshot), $file->sha256)) return ['error' => 'damaged'];
        $time = is_int($file->snapshot_time ?? null) && $file->snapshot_time > 0 ? $file->snapshot_time : 0;
        $name = is_string($file->node->name ?? null) ? mb_substr($file->node->name, 0, 64) : '';
        return ['snapshot' => $file->snapshot, 'time' => $time, 'name' => $name];
    }

    public function managedNodeImportFile($text, $id): void
    {
        $id = (string) $id;
        if (!isset($this->managedNodes()[$id])) return;
        $notice = '';
        try {
            $key = (string) ($this->managedNodeTransport($id, 'public')['public_key'] ?? '');
            // A document wins over its caption; plain text is never read as a path.
            $parsed = $this->managedNodeImportParse(!empty($this->input['file_id']) ? $this->managedNodeImportDownload() : null, $key);
            if (isset($parsed['error'])) {
                $notice = $this->t(...match ($parsed['error']) {
                    'read' => ['ru' => '❌ Файл не прочитан: пришлите документ .json до 256 КБ.', 'en' => '❌ File not read: send a .json document up to 256 KB.'],
                    'damaged' => ['ru' => '❌ Файл повреждён или изменён: контрольная сумма копии не совпала.', 'en' => '❌ The file is damaged or edited: the snapshot checksum does not match.'],
                    'foreign' => ['ru' => '❌ Это копия другой ноды: ключ управления в файле не совпадает с ключом этой ноды.', 'en' => '❌ This is another node’s snapshot: its controller key differs from this node’s key.'],
                    default => ['ru' => '❌ Это не файл копии ноды VPNBot.', 'en' => '❌ This is not a VPNBot node snapshot file.'],
                });
            } else {
                $this->managedNodeLocked($id, function () use ($id, $parsed) {
                    $node = $this->managedNodes()[$id] ?? null;
                    if (!$node || $node['job']) throw new RuntimeException('Node busy');
                    $saved = $this->managedNodeTransport($id, 'import', ['snapshot' => $parsed['snapshot']]);
                    if (!preg_match('~^[a-f0-9]{16}$~D', (string) ($saved['hash'] ?? ''))) throw new RuntimeException('Import not confirmed');
                    $this->managedNodeWrite($id, static function (&$node) use ($parsed) { $node['backup_time'] = $parsed['time'] ?: time(); });
                });
                $node = $this->managedNodes()[$id];
                if (!empty($node['connected']) && !$node['job']) { $this->managedNodeRestore($id); return; }
                $notice = $this->t('✅ Копия загружена. Привяжите SSH после переустановки и восстановите сохранённую копию.', '✅ Snapshot uploaded. Rebind SSH after reinstall, then restore the saved snapshot.');
            }
        } catch (Throwable $error) {
            $notice = $this->t('❌ Копия не загружена: нода занята или помощник SSH недоступен. Повторите после завершения операции.', '❌ Snapshot not uploaded: the node is busy or the SSH helper is unavailable. Retry after the operation finishes.');
        }
        $this->managedNodeMaintenance($id, $notice);
    }
}
