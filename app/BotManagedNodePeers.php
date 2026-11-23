<?php

/** Separate credentials for other panels; the main bot's identity is never exported here. */
trait BotManagedNodePeers
{
    private function managedNodePeers(string $id, ?array $status = null): array
    {
        $peers = ($status ?? ($this->managedNodes()[$id]['status'] ?? []))['peers'] ?? [];
        if (!is_array($peers) || count($peers) > 32) return [];
        return array_values(array_filter($peers, static fn($p) => is_array($p)
            && is_string($p['id'] ?? null) && preg_match('~^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$~D', $p['id'])
            && is_string($p['name'] ?? null) && preg_match('~^[A-Za-z0-9_.-]{1,40}$~D', $p['name']) && is_bool($p['enabled'] ?? null)));
    }

    private function managedNodePeer(string $id, string $key): ?array
    {
        foreach ($this->managedNodePeers($id) as $peer) if (self::exitEntryKey($peer['id']) === $key) return $peer;
        return null;
    }

    public function managedNodePeersMenu(string $id, string $notice = ''): void
    {
        $node = $this->managedNodes()[$id] ?? null;
        if (!$node || !$node['connected']) { $this->managedNodesMenu(); return; }
        $text = [$this->t('Ноды → Внешние подключения', 'Nodes → External connections'),
            $this->t('Отдельный ключ для каждой панели или сервера. Сервер панели должен быть в my_server ноды; правила и пользователей панели настраивайте в самой панели.',
                'A separate identity for each panel or server. The panel server must be in the node’s my_server; configure its routing and users in that panel.')];
        $data = [];
        foreach ($this->managedNodePeers($id) as $peer) $data[] = [['text' => ($peer['enabled'] ? '✅ ' : '⏸ ') . $peer['name'],
            'callback_data' => "/nodePeer $id " . self::exitEntryKey($peer['id'])]];
        if (count($data) < 32) $data[] = [['text' => $this->t('➕ Создать подключение', '➕ Create connection'), 'callback_data' => "/nodePeerAdd $id"]];
        $data[] = $this->menuHelpButton('nodepeers', $id);
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => "/node $id"]];
        if ($notice !== '') $text[] = self::esc($notice);
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n\n", $text), $data);
    }

    public function managedNodePeerMenu(string $id, string $key, string $notice = ''): void
    {
        $peer = $this->managedNodePeer($id, $key);
        if (!$peer) { $this->managedNodePeersMenu($id); return; }
        $text = [$this->t('Внешнее подключение: ', 'External connection: ') . self::esc($peer['name']),
            $this->t('Смена ключа и удаление отключают старую ссылку. Изменение применяется после проверки связи основным ботом.',
                'Rotating the identity and deleting the connection revoke the old link. Changes are applied after the main bot checks connectivity.')];
        $channel=$peer['channel'] ?? 'vless';
        $direct=self::managedNodeDirectLabel($this->managedNodes()[$id]['status']['options'] ?? []);
        $text[]=$this->t('Протокол подключения: ','Connection protocol: ').strtoupper($channel==='vless' ? $direct : $channel);
        if ($channel==='amnezia') $text[]=str_replace('VLESS',$direct,$this->t('Для 3x-ui 3.11.0 импортируйте оба outbound из JSON. Маршруты панели направляйте в первый, VLESS: он использует защищённый канал Amnezia. Обычная VLESS-ссылка этот канал не включает.',
            'For 3x-ui 3.11.0 import both JSON outbounds. Route panel traffic to the first, VLESS, which uses the Amnezia carrier. A plain VLESS link does not include this carrier.'));
        $data = [];
        foreach (['vless'=>$direct,'wireguard'=>'WireGuard','amnezia'=>'AmneziaWG'] as $kind=>$title) {
            $data[]=[['text'=>($channel===$kind?'✓ ':'').$title,'callback_data'=>"/nodePeerDo $id $key $kind"]];
        }
        if ($peer['enabled']) foreach (['https' => ['ru' => '🌐 HTTPS-подписка (3x-ui)', 'en' => '🌐 HTTPS subscription (3x-ui)'], 'link' => ['ru' => '🔗 Ссылка подключения', 'en' => '🔗 Connection link'], 'json' => ['ru' => '📄 JSON для панели', 'en' => '📄 Panel JSON'],
            'sub' => ['ru' => '📄 Подписка файлом', 'en' => '📄 Subscription file']] as $format => $label) {
            $data[] = [['text' => $this->t(...$label), 'callback_data' => "/nodePeerOut $id $key $format"]];
        }
        if ($channel!=='vless') $data=array_values(array_filter($data,static fn($row)=>(!str_starts_with($row[0]['callback_data'],"/nodePeerOut $id $key ") || str_ends_with($row[0]['callback_data'],' json'))));
        $data[] = [['text' => $peer['enabled'] ? $this->t('⏸ Отключить', '⏸ Disable') : $this->t('▶️ Включить', '▶️ Enable'),
            'callback_data' => "/nodePeerDo $id $key " . ($peer['enabled'] ? 'off' : 'on')]];
        $data[] = [['text' => $this->t('🔑 Сменить ключ', '🔑 Rotate identity'), 'callback_data' => "/nodePeerDo $id $key rotate"],
            ['text' => $this->t('✖ Удалить', '✖ Delete'), 'callback_data' => "/nodePeerDo $id $key delete"]];
        $data[] = $this->menuHelpButton('nodepeers', $id.'_'.$key);
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => "/nodePeers $id"]];
        if ($notice !== '') $text[] = self::esc($notice);
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n\n", $text), $data);
    }

    public function managedNodePeerAddPrompt(string $id, bool $paused = false): void
    {
        if (empty($this->managedNodes()[$id]['connected'])) return;
        $this->exitPrompt($this->t('имя подключения: 1–40 латинских букв, цифр, точек, дефисов или подчёркиваний.',
            'connection name: 1–40 Latin letters, digits, dots, hyphens or underscores.'), 'saveManagedNodePeerAdd', $paused ? [$id, true] : [$id]);
    }

    public function saveManagedNodePeerAdd($name, string $id, bool $paused = false): void
    {
        $status = $this->managedNodes()[$id]['status'] ?? [];
        $name = trim((string) $name); $peers = $this->managedNodePeers($id, $status);
        if (!preg_match('~^[A-Za-z0-9_.-]{1,40}$~D', $name) || count($peers) >= 32 || in_array(strtolower($name), ['controller', ...array_map('strtolower', array_column($peers, 'name'))], true)) {
            $this->managedNodePeersMenu($id, $this->t('Недопустимое или занятое имя, либо уже есть 32 подключения.', 'Invalid or duplicate name, or there are already 32 connections.')); return;
        }
        $peers[] = ['id' => self::xrayUuid(), 'name' => $name, 'enabled' => !$paused];
        try { $this->managedNodeSubmit($id, 'peers', $peers, (string) ($status['generation'] ?? '')); $this->managedNodeMenu($id); }
        catch (Throwable $e) { $this->managedNodePeersMenu($id, $this->t('Не удалось создать подключение. Обновите состояние ноды и повторите.', 'Could not create the connection. Refresh the node status and retry.')); }
    }

    public function managedNodePeerAction(string $id, string $key, string $action, bool $confirmed = false): void
    {
        $peer = $this->managedNodePeer($id, $key);
        if (!$peer || !in_array($action, ['on', 'off', 'rotate', 'delete', 'vless', 'wireguard', 'amnezia'], true)) { $this->managedNodePeersMenu($id); return; }
        if (!$confirmed) {
            $label = $this->t(...['on' => ['включить', 'enable'], 'off' => ['отключить', 'disable'],
                'rotate' => ['сменить ключ', 'rotate identity'], 'delete' => ['удалить', 'delete'],
                'vless'=>['использовать VLESS','use VLESS'], 'wireguard'=>['использовать WireGuard','use WireGuard'], 'amnezia'=>['использовать AmneziaWG','use AmneziaWG']][$action]);
            $this->update($this->input['chat'], $this->input['message_id'],
                $this->t('Применить изменение к подключению ', 'Apply this change to connection ') . '<b>' . self::esc($peer['name']) . '</b> (' . $label . ')?',
                [[['text' => $this->t('Применить', 'Apply'), 'callback_data' => "/nodePeerDo $id $key $action yes"]],
                 [['text' => $this->i18n('back'), 'callback_data' => "/nodePeer $id $key"]]]);
            return;
        }
        $peers = [];
        $status = $this->managedNodes()[$id]['status'] ?? [];
        foreach ($this->managedNodePeers($id, $status) as $item) {
            if ($item['id'] === $peer['id']) {
                if ($action === 'delete') continue;
                if ($action === 'rotate') $item['id'] = self::xrayUuid();
                elseif (in_array($action,['vless','wireguard','amnezia'],true)) $item['channel']=$action;
                else $item['enabled'] = $action === 'on';
            }
            $peers[] = $item;
        }
        try { $this->managedNodeSubmit($id, 'peers', $peers, (string) ($status['generation'] ?? '')); $this->managedNodeMenu($id); }
        catch (Throwable $e) { $this->managedNodePeersMenu($id, $this->t('Операция не запущена. Обновите состояние ноды и повторите.', 'Operation not started. Refresh the node status and retry.')); }
    }

    public function managedNodePeerExport(string $id, string $key, string $format): void
    {
        $peer = $this->managedNodePeer($id, $key);
        if (!$peer || !$peer['enabled'] || !in_array($format, ['link', 'json', 'sub', 'https'], true)) { $this->managedNodePeersMenu($id); return; }
        try {
            if (!empty($this->managedNodes()[$id]['job'])) throw new RuntimeException('Node busy');
            if ((int) ($this->input['from'] ?? 0) <= 0) throw new RuntimeException('Private chat unavailable');
            $profile = $this->managedNodeRpc($id, ['action' => 'profile', 'peer' => $peer['id']]);
            if (($profile['channel']??'vless')!==($peer['channel']??'vless') || (($peer['channel']??'vless')!=='vless' && $format!=='json')) throw new RuntimeException('Wrong channel or export format');
            $core = (string) ($this->managedNodes()[$id]['status']['options']['core'] ?? 'origin');
            $parsed = ManagedNodeProfile::parse($profile, $core);
            if (ManagedNodeProfile::credential($parsed['outbound']) !== $peer['id']) throw new RuntimeException('Wrong peer');
            if ($format === 'https') {
                $url = $this->managedNodeSubscriptionUrl($id, $key);
                $sent = $this->send($this->input['from'], $this->t('HTTPS-подписка для импорта в панели, поддерживающие VLESS-подписки:', 'HTTPS subscription for panels supporting VLESS subscriptions:')
                    . "\n<code>" . self::esc($url) . "</code>\n\n"
                    . $this->t('URL обслуживает основной бот. При изменении транспорта обновите подписку в панели. После смены ключа внешнего подключения получите новый URL. Для SMUX и других расширений используйте совместимое ядро и JSON-профиль.',
                        'The main bot serves this URL. Refresh the panel subscription after transport changes. After rotating the external identity, obtain a new URL. SMUX and other extensions require a compatible core and the JSON profile.'));
                if (empty($sent['ok'])) throw new RuntimeException('Private delivery failed');
                $this->managedNodePeerMenu($id, $key, $this->t('HTTPS-подписка отправлена в личный чат.', 'HTTPS subscription sent to your private chat.'));
                return;
            }
            if ($format === 'link') {
                $sent = $this->send($this->input['from'], '<code>' . self::esc($profile['link']) . '</code>');
                if (empty($sent['ok'])) throw new RuntimeException('Private delivery failed');
                $this->managedNodePeerMenu($id, $key, $this->t('Ссылка отправлена в личный чат.', 'Link sent to your private chat.'));
                return;
            }
            $body = $format === 'sub' ? base64_encode($profile['link'] . "\n") : json_encode(ManagedNodeProfile::panel($profile,$core,$peer['name']), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            $sent = $this->sendFile($this->input['from'], new CURLStringFile($body, 'node-' . $key . ($format === 'sub' ? '.txt' : '.json'), $format === 'sub' ? 'text/plain' : 'application/json'),
                $this->t('Личный профиль подключения. Требуются совместимое ядро и разрешённый IP сервера панели в my_server ноды.', 'Private connection profile. A compatible core and the panel server IP in the node’s my_server are required.'));
            if (empty($sent['ok'])) throw new RuntimeException('Private delivery failed');
            $this->managedNodePeerMenu($id, $key, $this->t('Файл отправлен в личный чат.', 'File sent to your private chat.'));
        } catch (Throwable $e) { $this->managedNodePeerMenu($id, $key, $this->t('Профиль не отправлен. Для HTTPS-подписки настройте домен и SSL основного бота. Проверьте состояние ноды и откройте личный чат с ботом командой /start.', 'Profile was not sent. An HTTPS subscription needs the main bot’s domain and SSL. Check the node status and start a private chat with the bot using /start.')); }
    }
}
