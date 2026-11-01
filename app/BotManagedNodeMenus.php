<?php

/** Typed, hierarchical settings screens for remote nodes. */
trait BotManagedNodeMenus
{
    private function managedNodeDraftWrite(string $id, callable $edit): void
    {
        $this->managedNodeLocked($id, function () use ($id, $edit) {
            $this->managedNodeWrite($id, static function (&$node) use ($edit) {
                if (!$node || !empty($node['job'])) throw new RuntimeException('Node unavailable');
                $edit($node);
            });
        });
    }

    public function managedNodeSettingsMenu(string $id, string $group = 'root', string $notice = ''): void
    {
        $node = $this->managedNodes()[$id] ?? null;
        if (!$node || !$node['connected']) { $this->managedNodesMenu(); return; }
        if ($group !== 'root' && !isset(ManagedNodeFields::GROUPS[$group])) { $this->managedNodeMenu($id); return; }
        $options = $node['draft'] ?? $node['status']['options'] ?? [];
        $title = $group === 'root' ? ['ru'=>'Настройки ноды', 'en'=>'Node settings'] : ManagedNodeFields::GROUPS[$group];
        $text = [$this->t('Ноды → ', 'Nodes → ') . self::esc($node['name']) . ' → ' . $this->t(...$title)];
        $buttons = [];
        foreach (ManagedNodeFields::all() as $path => $field) {
            if ($field[0] !== $group) continue;
            $awgVersion=$options['amnezia']['version'] ?? '3.1';
            if (str_starts_with($path,'amnezia.parameters.')) {
                $name=substr($path,strlen('amnezia.parameters.'));
                if ($awgVersion==='1.5' && in_array($name,['S3','S4'],true)) continue;
                if (!str_starts_with($awgVersion,'3.') && in_array($name,['ContentPaddingAddition','RekeyAfterTime','RekeyTimeout','RejectAfterTime','KeepaliveTimeout','MaxHandshakeAttempts'],true)) continue;
            }
            $value = ManagedNodeFields::get($options, $path);
            $display = $this->managedNodeValueLabel($id, $path, $value);
            $buttons[] = ['text' => $this->t($field[1], $field[2]) . ': ' . mb_substr($display, 0, 28), 'callback_data' => "/nodeField $id $path"];
        }
        $data = array_chunk($buttons, 2);
        $groups = [];
        if ($group === 'root') foreach (ManagedNodeFields::GROUPS as $name => $label) $groups[] = ['text' => $this->t(...$label), 'callback_data' => "/nodeSettings $id $name"];
        array_push($data, ...array_chunk($groups, 2));
        if ($group === 'network') {
            $text[] = $this->t('Первая часть — соединение основного бота с нодой. Вторая — выход ноды в интернет. Это не адреса телефона или телевизора. SSH настраивается отдельно в карточке ноды.',
                'The first family is the main bot’s connection to the node. The second is the node’s internet egress. These are not your phone or TV addresses. SSH has separate settings in the node card.');
            $data = [];
            foreach (['44', '46', '64', '66'] as $pair) $data[] = [['text' =>
                (((int) ($options['connect_family'] ?? 4) === (int) $pair[0] && (int) ($options['family'] ?? 4) === (int) $pair[1]) ? '✓ ' : '')
                . "IPv{$pair[0]} → IPv{$pair[1]}", 'callback_data' => "/nodeNetwork $id $pair"]];
            foreach ([4,6] as $family) {
                $address=$node['status']['public'.$family] ?? '';
                $text[]='IPv'.$family.': <code>'.self::esc($address ?: $this->t('не настроен на ноде','not configured on the node')).'</code>';
            }
            $text[]=$this->t('Выход строгий: IPv6 не переключается на IPv4 при ошибке, и наоборот. Домену для выхода IPv6 нужна AAAA-запись; IPv4-адрес не преобразуется в IPv6. Семейство соединения с нодой не зависит от выбранного выхода.',
                'Egress is strict: failure never silently switches between IPv6 and IPv4. IPv6 destinations need AAAA records; IPv4 literals are not translated. The bot–node connection family is independent of egress.');
            $text[] = $this->t('Для IPv6 нужны настроенные адреса и разрешённый источник в firewall. При недоступности нового пути нода автоматически вернёт прежние настройки.',
                'IPv6 needs configured addresses and an allowed source in the firewall. If the new path fails, the node automatically restores the previous settings.');
        }
        if ($group === 'reserve') {
            $selected = !empty($options['amnezia']['active']) ? 'amnezia' : (!empty($options['wireguard']['active']) ? 'wireguard' : 'direct');
            foreach (['direct'=>'VLESS', 'wireguard'=>'WireGuard', 'amnezia'=>'AmneziaWG'] as $channel=>$label) {
                $data[] = [['text'=>($selected === $channel ? '✓ ' : '') . $label, 'callback_data'=>"/nodeChannel $id $channel"]];
            }
            $data[] = [['text'=>$this->t('Настройки WireGuard', 'WireGuard settings'), 'callback_data'=>"/nodeSettings $id wireguard"],
                ['text'=>$this->t('Настройки AmneziaWG', 'AmneziaWG settings'), 'callback_data'=>"/nodeSettings $id amnezia"]];
        }
        if ($group === 'amnezia') {
            $data[] = [['text'=>$this->t('Шаблоны и генерация','Templates and generation'), 'callback_data'=>"/nodePreset $id amnezia"]];
            $row=[];
            for ($n=1;$n<=5;$n++) $row[]=['text'=>"I$n: " . $this->t('пресеты','presets'), 'callback_data'=>"/nodePreset $id cps$n"];
            array_push($data, ...array_chunk($row, 3));
            $text[] = $this->t('Шаблон: ', 'Template: ') . self::esc($options['amnezia']['template'] ?? 'standard_3');
            if (!empty($options['amnezia']['generated_at'])) $text[]=$this->t('Генерация: ', 'Generated: ').date('Y-m-d H:i', $options['amnezia']['generated_at']);
        }
        if (in_array($group,['dpi','finalmask'],true)) $data[] = [
            ['text'=>$this->t('📋 Шаблоны Fragment','📋 Fragment templates'), 'callback_data'=>"/nodePreset $id {$group}_fragment"],
            ['text'=>$this->t('📋 Шаблоны UDP noise','📋 UDP noise templates'), 'callback_data'=>"/nodePreset $id {$group}_noise"]];
        if ($group === 'dpi') $text[]=$this->t('Те же шаблоны, что в VLESS → Маскировка DPI основного бота. Они изменяют исходящее соединение основного бота с нодой. Начните с умеренного шаблона и проверьте задержку и скорость; для прямого WireGuard эти параметры VLESS не применяются.', 'The same templates as the main bot’s VLESS → DPI masking. They affect the outbound bot–node connection. Start with a moderate template and test latency and speed; these VLESS settings do not affect direct WireGuard.');
        if ($group === 'basic' && self::managedNodeFingerprintRejected($options, (string) ($options['xray']['fingerprint'] ?? 'chrome'))) {
            $text[] = $this->t('⚠ Клиент с этим отпечатком не подключится при выбранных транспорте и ядре, и нода не примет такие настройки. Варианты с ⚠ в списке отпечатков несовместимы.',
                '⚠ A client with this fingerprint cannot connect with the selected transport and core, so the node rejects these settings. Options marked ⚠ in the fingerprint list are incompatible.');
        }
        if ($group === 'domains') $data[] = [['text'=>$this->t('Управление сертификатом','Manage certificate'), 'callback_data'=>"/nodeCert $id"]];
        if (in_array($group,['reality','domains'],true)) $data[]=[['text'=>$this->t('Проверить TLS / ALPN h2','Check TLS / ALPN h2'),'callback_data'=>"/nodeTls $id $group"]];
        if ($group === 'finalmask') $text[]=$this->t('Шаблоны Fragment и UDP noise применяются на стороне ноды. Это отдельные настройки от DPI клиента: включайте их после проверки совместимости и скорости. UDP noise не маскирует TCP-соединения.', 'Fragment and UDP noise templates apply on the node side. These are separate from client DPI settings; test compatibility and speed. UDP noise does not mask TCP connections.');
        if (in_array($group,['wireguard','amnezia'],true)) {
            $text[]=$this->t('Это защищённый канал между основным ботом и нодой. Маршруты, DNS клиентов, лимиты пользователей и подписки настраиваются на основном боте. Доступ клиентов к локальным подсетям ноды и обмен между ними не разрешаются.',
                'This is the protected bot–node channel. Client routes, DNS, user limits and subscriptions belong to the main bot. Access to node private subnets and peer-to-peer forwarding is not permitted.');
            $data[]=[['text'=>$this->t('Торренты и sniffing','Torrents and sniffing'), 'callback_data'=>"/nodeSettings $id torrent"],
                ['text'=>$this->t('Выбор канала','Select channel'), 'callback_data'=>"/nodeSettings $id reserve"]];
        }
        if ($group === 'domains') $text = array_merge($text, $this->managedNodeDomainSummary($node));
        if (isset($node['draft'])) {
            $text[] = $this->t('Есть неприменённые изменения. Нода проверит конфигурацию и сертификат, основной бот — прохождение трафика. Если проверка не пройдёт, сохранится предыдущая конфигурация.',
                'There are unapplied changes. The node checks configuration and certificate; the main bot tests traffic. Failed checks preserve the previous configuration.');
            $data[] = [['text' => $this->t('✅ Применить', '✅ Apply'), 'callback_data' => "/nodeApply $id"],
                ['text' => $this->t('Отменить правки', 'Discard edits'), 'callback_data' => "/nodeDiscard $id"]];
        }
        if ($group === 'domains') $text[] = $this->t('Свой сайт — та же заглушка с неизвестным случайным паролем. Домен должен указывать на ноду. TCP/80 открывается только для ACME; SSH и VPN остаются ограничены списками доступа.',
            'Own site uses a cover with an unknown random password. The domain must point to the node. TCP/80 opens only for ACME; SSH and VPN retain their access lists.');
        if ($group === 'crypto') $text[] = $this->t('ML-DSA требует подходящего сертификата сайта маскировки. Отпечаток задаётся клиенту — основному боту.',
            'ML-DSA needs a suitable camouflage site certificate. The fingerprint belongs to the client: the main bot.');
        if ($group === 'reserve') $text[] = $this->t('WireGuard работает внутри Xray; AmneziaWG использует отдельный минимальный контейнер и передаёт VLESS с выбранным транспортом и шифрованием. Сначала разрешите канал, затем выберите его для связи основного бота. Одновременно активен один канал. UDP/51820 и UDP/51821 доступны только из MyServer. Переключение подтверждается проверкой трафика. Протокол каждого внешнего подключения выбирается отдельно.',
            'WireGuard runs inside Xray; AmneziaWG uses a separate minimal container and carries VLESS with the selected transport and encryption. Enable a channel, then select it for the main bot link. One channel can be active. UDP/51820 and UDP/51821 are restricted to MyServer. A traffic test confirms the switch. Each external peer selects its own protocol.');
        if ($group === 'smux') $text[] = $this->t('SMUX требует fork на ноде и основном боте. При maxStreams > 0 maxConnections и minStreams не используются. Для h2mux половинное закрытие должно быть off.',
            'SMUX requires the fork on both servers. maxStreams > 0 disables maxConnections and minStreams. h2mux requires half-close off.');
        if ($notice !== '') $text[] = self::esc($notice);
        if ($group !== 'root') $data[] = $this->menuHelpButton('nodeconfig', $id.'_'.$group);
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => $group === 'root' ? "/node $id" : "/nodeSettings $id"]];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n\n", $text), $data);
    }

    public function managedNodeField(string $id, string $path): void
    {
        $node = $this->managedNodes()[$id] ?? null;
        $field = ManagedNodeFields::all()[$path] ?? null;
        if (!$node || !$node['connected'] || !$field) return;
        if ($node['job']) { $this->managedNodeMenu($id, $this->t('Дождитесь завершения текущего изменения.', 'Wait for the current change to finish.')); return; }
        $options = $node['draft'] ?? $node['status']['options'] ?? [];
        if ($field[3] === 'bool') {
            $this->managedNodeDraft($id, $path, !ManagedNodeFields::get($options, $path));
            return;
        }
        if ($field[3] === 'choice') {
            $data = [];
            foreach ($field[4] as $value) $data[] = [['text' => (ManagedNodeFields::get($options, $path) === $value ? '✓ ' : '')
                . $this->managedNodeValueLabel($id, $path, $value) . ($path === 'xray.fingerprint' && self::managedNodeFingerprintRejected($options, (string) $value) ? ' ⚠' : ''),
                'callback_data' => "/nodeChoice $id $path $value"]];
            $data[] = [['text' => $this->i18n('back'), 'callback_data' => "/nodeSettings $id {$field[0]}"]];
            $this->update($this->input['chat'], $this->input['message_id'], $this->managedNodeFieldTitle($node, $field), $data);
            return;
        }
        $data = [[['text' => $this->t('✏️ Изменить', '✏️ Edit'), 'callback_data' => "/nodeEdit $id $path"]]];
        if ($path === 'mask') $data[] = [['text' => $this->t('🏠 Использовать свой домен', '🏠 Use own domain'), 'callback_data' => "/nodeDomain $id own"]];
        if ($path === 'domain') $data[] = [['text' => $this->t('🌐 Домен nip.io по IP ноды', '🌐 nip.io domain from node IP'), 'callback_data' => "/nodeDomain $id auto"]];
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => "/nodeSettings $id {$field[0]}"]];
        $value = ManagedNodeFields::get($options, $path);
        $display = is_array($value) ? implode("\n", array_map(static fn($v) => is_string($v) ? $v : json_encode($v), $value)) : (string) ($value ?? '—');
        $this->update($this->input['chat'], $this->input['message_id'], $this->managedNodeFieldTitle($node, $field)
            . "\n\n<code>" . self::esc(mb_substr($display, 0, 1800)) . '</code>', $data);
    }

    public function managedNodeEditPrompt(string $id, string $path): void
    {
        $node = $this->managedNodes()[$id] ?? null;
        $field = ManagedNodeFields::all()[$path] ?? null;
        if (!$node || !$field || $node['job'] || in_array($field[3], ['choice', 'bool'], true)) return;
        $hint = match ($field[3]) {
            'int' => $this->t('целое неотрицательное число', 'a non-negative integer'),
            'list' => $this->t('значения через пробел; <code>-</code> очищает список', 'space-separated values; <code>-</code> clears the list'),
            'json' => $this->t('JSON-массив пакетов: поля type, packet, delay. <code>[]</code> — список по умолчанию', 'a JSON array of packets with type, packet, delay. <code>[]</code> uses the default list'),
            default => $this->t('значение; <code>-</code> означает пустое поле', 'a value; <code>-</code> means an empty field'),
        };
        $this->exitPrompt($this->t($field[1], $field[2]) . ': ' . $hint, 'saveManagedNodeField', [$id, $path]);
    }

    /** Same rule as the node's validator and the main bot's fingerprintRejected(). */
    private static function managedNodeFingerprintRejected(array $options, string $fingerprint): bool
    {
        $transport = $options['transport'] ?? '';
        if (in_array($transport, ['grpc', 'xhttp'], true)) return in_array($fingerprint, self::FINGERPRINTS_NO_H2, true);
        if ($transport !== 'reality') return false;
        if (in_array($fingerprint, self::REALITY_NO_TLS13, true)) return true;
        $mlkem = in_array($options['core'] ?? 'origin', ['origin', 'origin2'], true) || !empty($options['xray']['reality']['requireMlkem']);
        return $mlkem && !in_array($fingerprint, self::REALITY_FINGERPRINTS, true);
    }

    private function managedNodeFieldTitle(array $node, array $field): string
    {
        return $this->t('Ноды → ', 'Nodes → ') . self::esc($node['name']) . ' → '
            . $this->t(...ManagedNodeFields::GROUPS[$field[0]]) . ' → ' . $this->t($field[1], $field[2]);
    }

    private function managedNodeValueLabel(string $id, string $path, $value): string
    {
        if ($path === 'amnezia.version') return $value ?? '3.1';
        if ($path === 'core') {
            $version = $this->managedNodes()[$id]['status']['cores'][$value] ?? '';
            if (!is_string($version) || !preg_match('~^[0-9][A-Za-z0-9.+_-]{0,47}$~D', $version)) $version = $this->t('версия неизвестна — обновите состояние', 'version unknown — refresh status');
            return ($value === 'fork' ? 'fork (SMUX) ' : 'XTLS ') . $version;
        }
        if (in_array($path, ['family', 'connect_family'], true)) return 'IPv' . $value;
        if ($path === 'transport') return ['reality'=>'REALITY', 'ws'=>'WebSocket + TLS', 'grpc'=>'gRPC + TLS', 'xhttp'=>'XHTTP + TLS'][$value] ?? '—';
        return is_bool($value) ? ($value ? '✅' : '❌') : (is_array($value) ? (string) count($value) : (string) ($value ?? '—'));
    }

    private function managedNodeDomainSummary(array $node): array
    {
        $options = $node['status']['options'] ?? [];
        $result = [];
        $domains = array_values(array_unique(array_filter([$options['domain'] ?? '', ...($options['domain_aliases'] ?? [])])));
        foreach (array_slice($domains, 0, 4) as $domain) {
            $result[] = '🌐 <code>' . self::esc((string) $domain) . '</code>';
        }
        if (count($domains) > 4) $result[] = $this->t('Все домены — в настройках доменов.', 'All domains are listed in domain settings.');
        $expiry = $node['status']['certificate']['expires'] ?? null;
        if (is_int($expiry) && $expiry > 0) $result[] = $this->t('Сертификат до: ', 'Certificate expires: ')
            . date('Y-m-d H:i', $expiry) . ' · ' . max(0, (int) floor(($expiry-time())/86400)) . $this->t(' дн.', ' days');
        elseif ($options['domain'] ?? '') $result[] = $this->t('Срок сертификата: обновите состояние ноды.', 'Certificate expiry: refresh node status.');
        return $result;
    }

    public function managedNodeChannel(string $id, string $channel): void
    {
        if (!in_array($channel, ['direct', 'wireguard', 'amnezia'], true)) return;
        $this->managedNodeDraftWrite($id, static function (&$node) use ($channel) {
            if (!$node || empty($node['connected']) || !empty($node['job'])) throw new RuntimeException('Node unavailable');
            if (!isset($node['draft'])) $node['draft_generation'] = $node['status']['generation'] ?? '';
            $options = $node['draft'] ?? $node['status']['options'];
            foreach (['wireguard','amnezia'] as $name) {
                $options[$name]['active'] = $channel === $name;
                if ($channel === $name) $options[$name]['enabled'] = true;
            }
            $node['draft'] = $options;
        });
        $this->managedNodeSettingsMenu($id, 'reserve');
    }

    private function managedNodeNetworkProblem(array $options, array $node): string
    {
        if (($options['connect_family'] ?? 4) !== 6) return '';
        $network=$this->exitIpv6Network();
        if (empty($network['enabled']) || !filter_var($network['public'] ?? '',FILTER_VALIDATE_IP,FILTER_FLAG_IPV6)) {
            return $this->t('IPv6 для связи с нодой не подготовлен на основном сервере. Нужны публичный IPv6, маршрут и сеть контейнера Xray. Выберите IPv4 → IPv4 или IPv4 → IPv6; выход ноды по IPv6 от этого не зависит.',
                'IPv6 for the node link is not prepared on the main server. A public IPv6, route and Xray container network are required. Use IPv4 → IPv4 or IPv4 → IPv6; node IPv6 egress is independent.');
        }
        $source=inet_pton($network['public']);
        foreach ($node['status']['sources'] ?? [] as $allowed) {
            if (filter_var($allowed,FILTER_VALIDATE_IP,FILTER_FLAG_IPV6) && inet_pton($allowed)===$source) return '';
        }
        return $this->t('Публичный IPv6 основного сервера отсутствует в разрешённых источниках ноды (MyServer). Добавьте его в настройки установки ноды и обновите состояние. Firewall автоматически не открывается.',
            'The main server’s public IPv6 is absent from the node’s allowed sources (MyServer). Add it to node enrollment settings and refresh status. The firewall is not opened automatically.');
    }

    public function managedNodeNetwork(string $id, string $pair): void
    {
        if (!in_array($pair, ['44', '46', '64', '66'], true)) return;
        $this->managedNodeDraftWrite($id, static function (&$node) use ($pair) {
            if (!$node || empty($node['connected']) || !empty($node['job'])) throw new RuntimeException('Node unavailable');
            if (!isset($node['draft'])) $node['draft_generation'] = $node['status']['generation'] ?? '';
            $options = $node['draft'] ?? $node['status']['options'];
            $options['connect_family'] = (int) $pair[0]; $options['family'] = (int) $pair[1];
            $node['draft'] = $options;
        });
        $this->managedNodeSettingsMenu($id, 'network');
    }

    public function managedNodeOwnDomain(string $id, string $action): void
    {
        $node = $this->managedNodes()[$id] ?? null;
        if (!$node || !$node['connected'] || $node['job']) return;
        $options = $node['draft'] ?? $node['status']['options'] ?? [];
        if ($action === 'auto') {
            $ip = $node['status']['public4'] ?? '';
            if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) { $this->managedNodeSettingsMenu($id, 'domains', $this->t('Для автоматического домена нужен публичный IPv4 ноды.', 'An automatic domain needs the node’s public IPv4.')); return; }
            $this->managedNodeDraft($id, 'domain', str_replace('.', '-', $ip) . '.nip.io');
        } elseif ($action === 'own') {
            if (empty($options['domain'])) { $this->managedNodeSettingsMenu($id, 'domains', $this->t('Сначала задайте собственный домен ноды.', 'Set the node’s own domain first.')); return; }
            $this->managedNodeDraftWrite($id, static function (&$node) {
                if (!$node || empty($node['connected']) || !empty($node['job'])) throw new RuntimeException('Node unavailable');
                if (!isset($node['draft'])) $node['draft_generation'] = $node['status']['generation'] ?? '';
                $options = $node['draft'] ?? $node['status']['options'];
                $options['mask'] = $options['domain']; $options['cover'] = true;
                $node['draft'] = $options;
            });
            $this->managedNodeSettingsMenu($id, 'reality');
        }
    }

    public function managedNodeChoice(string $id, string $path, string $value): void
    {
        $field = ManagedNodeFields::all()[$path] ?? null;
        if (!$field || $field[3] !== 'choice') return;
        if ($path==='amnezia.version' && in_array($value,$field[4],true)) {
            $this->managedNodeDraftWrite($id, function (&$node) use ($value) {
                $options=$node['draft'] ?? $node['status']['options'];
                if (!isset($node['draft'])) $node['draft_generation']=$node['status']['generation'] ?? '';
                $options['amnezia']['version']=$value;
                $template=self::awgTemplateForVer($options['amnezia']['template'] ?? 'standard_3',(int)$value);
                $params=$this->amneziaKeysForVersion($options['amnezia']['parameters'] ?? [],(int)$value,$template,static fn()=>'remote');
                unset($params['HeaderProtectionKey']);
                foreach (['H1','H2','H3','H4'] as $name) if (isset($params[$name])) {
                    $header=(string)$params[$name];
                    // The legacy generator accepts all uint32 headers; modern
                    // node ranges are bounded to signed int32 for clients.
                    if ($value!=='1.5' && !str_contains($header,'-') && (int)$header>2147483647) {
                        $fresh=$this->generateAmneziaKeys($template,static fn()=>'remote');
                        foreach (['H1','H2','H3','H4'] as $headerName) $params[$headerName]=(string)$fresh[$headerName];
                        break;
                    }
                    $params[$name]=$header;
                }
                $options['amnezia']['parameters']=$params;
                $options['amnezia']['template']=$template;
                $options['amnezia']['enabled']=true;
                if (!str_starts_with($value,'3.')) $options['amnezia']['keepalive']=(string)(int)($options['amnezia']['keepalive']??25);
                $node['draft']=$options;
            });
            $this->managedNodeSettingsMenu($id,'amnezia',$this->t('Версия и совместимый шаблон подготовлены. Ключи сохраняются; нажмите «Применить» для переключения обоих концов канала.',
                'Version and compatible template prepared. Keys stay unchanged; Apply switches both ends.'));
            return;
        }
        foreach ($field[4] as $choice) if ((string) $choice === $value) { $this->managedNodeDraft($id, $path, $choice); return; }
    }

    public function saveManagedNodeField($text, $id, $path): void
    {
        $field = ManagedNodeFields::all()[$path] ?? null;
        if (!$field || !is_string($text) || strlen($text) > 8192) return;
        $text = trim($text);
        try {
            $value = match ($field[3]) {
                'int' => preg_match('~^[0-9]{1,8}$~D', $text) ? (int) $text : null,
                'list' => $text === '-' ? [] : preg_split('~\s+~', $text),
                'json' => json_decode($text, true, 8, JSON_THROW_ON_ERROR),
                'string' => $text === '-' ? '' : $text,
                default => null,
            };
            $this->managedNodeDraft($id, $path, $value);
        } catch (Throwable $error) { $this->managedNodeSettingsMenu($id, $field[0], $this->t('Некорректное значение. Настройки не изменены.', 'Invalid value. Settings were not changed.')); }
    }

    private function managedNodeDraft(string $id, string $path, $value): void
    {
        $this->managedNodeDraftWrite($id, static function (&$node) use ($path, $value) {
            if (!$node || empty($node['connected']) || !empty($node['job'])) throw new RuntimeException('Node unavailable');
            if (!isset($node['draft'])) $node['draft_generation'] = $node['status']['generation'] ?? '';
            $node['draft'] = ManagedNodeFields::change($node['draft'] ?? $node['status']['options'] ?? [], $path, $value);
        });
        $this->managedNodeSettingsMenu($id, ManagedNodeFields::all()[$path][0]);
    }

    public function managedNodeDiscard(string $id): void
    {
        $this->managedNodeDraftWrite($id, static function (&$node) { unset($node['draft'], $node['draft_generation']); });
        $this->managedNodeSettingsMenu($id);
    }

    public function managedNodeApply(string $id): void
    {
        try {
            $node = $this->managedNodes()[$id] ?? null;
            if (!$node || !isset($node['draft'])) return;
            $problem=$this->managedNodeNetworkProblem($node['draft'],$node);
            if ($problem !== '') { $this->managedNodeSettingsMenu($id,'network',$problem); return; }
            $this->managedNodeSubmit($id, 'configure', $node['draft']);
            $this->managedNodeMenu($id);
        } catch (Throwable $error) { $this->managedNodeSettingsMenu($id, 'root', $this->t('Изменение не принято. Проверьте совместимость настроек и доступность SSH; черновик сохранён.',
            'The change was not accepted. Check option compatibility and SSH availability; the draft is kept.')); }
    }

}
