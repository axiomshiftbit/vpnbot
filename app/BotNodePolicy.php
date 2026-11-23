<?php

trait BotNodePolicy
{
    private static function nodePolicyPeerScope(string $id): string
    {
        return 'peer-' . substr(hash('sha256', $id), 0, 20);
    }

    private static function nodePolicyBotScope(array $client): string
    {
        $saved = $client['node_policy_identity'] ?? [];
        if (($saved['source'] ?? null) === ManagedProtocol::xraySource($client)
            && is_string($saved['scope'] ?? null) && preg_match('~^bot-[a-f0-9]{20}$~D', $saved['scope'])) {
            return $saved['scope'];
        }
        return 'bot-' . self::exitFullKey($client);
    }

    private function nodePolicySubject(string $id, string $scope): ?string
    {
        if ($scope === 'all') return $this->t('Все клиенты ноды', 'All node clients');
        if (str_starts_with($scope, 'peer-')) {
            foreach ($this->managedNodePeers($id) as $peer) {
                if (self::nodePolicyPeerScope($peer['id']) === $scope) return $peer['name'];
            }
        } else {
            foreach ($this->getXray()['inbounds'][0]['settings']['clients'] ?? [] as $client) {
                if (self::exitFullId($client) === $id && self::nodePolicyBotScope($client) === $scope) return $client['email'];
            }
        }
        return null;
    }

    private function nodePolicyCatalog(?array $pac = null): array
    {
        $pac ??= $this->getPacConf();
        $catalog = $pac['node_policy_lists'] ?? [];
        foreach ($this->managedNodes($pac) as $node) {
            $options = $node['draft'] ?? $node['status']['options'] ?? [];
            $policy = $options['policy'] ?? [];
            if (!isset($pac['node_policy_lists'])) {
                $catalog += $policy['lists'] ?? [];
                continue;
            }
            // A restored node can introduce a live assignment. A spare cached
            // copy left by a removed peer must not undo a catalog deletion.
            foreach ($policy['bindings'] ?? [] as $rows) {
                foreach ($rows as $row) {
                    $name = $row['list'];
                    if (isset($policy['lists'][$name])) $catalog[$name] ??= $policy['lists'][$name];
                }
            }
        }
        return $catalog;
    }

    private static function exitMainClient(array $x, string $id, string $key): ?int
    {
        foreach ($x['inbounds'][0]['settings']['clients'] ?? [] as $i => $client) {
            if (empty($client['exit_relay']) && !empty($client['email']) && self::exitFullId($client) === $id
                && self::exitFullKey($client) === $key) return $i;
        }
        return null;
    }

    public function exitMainMenu(string $id, string $key, int $page, string $notice = ''): void
    {
        $x = $this->getXray();
        $index = self::exitMainClient($x, $id, $key);
        if ($index === null) { $this->xray(); return; }
        $client = $x['inbounds'][0]['settings']['clients'][$index];
        $names = array_keys($this->nodePolicyCatalog());
        $last = max(0, (int) ceil(count($names) / 8) - 1);
        $page = min($last, max(0, $page));
        $rows = [];
        foreach (array_slice($names, $page * 8, 8) as $name) {
            $on = in_array($name, $client['exit_main'] ?? [], true);
            $rows[] = [['text' => ($on ? '✅ ' : '⬜ ') . $name,
                'callback_data' => "/xmSet $id $key " . self::exitEntryKey($name) . ' ' . (int)$on . " $page"]];
        }
        if ($last) $rows[] = [['text' => '←', 'callback_data' => "/xm $id $key " . max(0, $page-1)],
            ['text' => '→', 'callback_data' => "/xm $id $key " . min($last, $page+1)]];
        if (!empty($this->managedNodes()[$id]['status']['named_policy'])) {
            $rows[] = [['text' => $this->t('Библиотека списков', 'List library'), 'callback_data' => "/np $id all"]];
        }
        $rows[] = [['text' => $this->i18n('back'), 'callback_data' => "/exitUser $index"]];
        $message = self::esc($client['email']) . "\n" . $this->t(
            'Отметьте списки для выхода с IP основного сервера. Запреты основного бота имеют приоритет. Остальное идёт через выбранную ноду и подчиняется её правилам. Изменение действует для новых соединений.',
            'Select lists for egress from the main server IP. Main-server blocks take priority. Other traffic uses the selected node and its rules. Changes apply to new connections.');
        if (!$names) $message .= "\n" . $this->t('Библиотека списков пуста.', 'The list library is empty.');
        $this->update($this->input['chat'], $this->input['message_id'], $message . ($notice === '' ? '' : "\n" . self::esc($notice)), $rows);
    }

    public function exitMainSelect(string $id, string $key, string $listKey, bool $expected, int $page): void
    {
        $error = $this->applyExitNodes(function (&$pac, &$x) use ($id, $key, $listKey, $expected) {
            $index = self::exitMainClient($x, $id, $key);
            if ($index === null) return 'exit stale';
            $client =& $x['inbounds'][0]['settings']['clients'][$index];
            $selected = $client['exit_main'] ?? [];
            $catalog = $this->nodePolicyCatalog($pac);
            foreach ($catalog as $name => $parts) {
                if (self::exitEntryKey($name) !== $listKey) continue;
                if (in_array($name, $selected, true) !== $expected) return 'exit stale';
                if ($expected) $selected = array_values(array_diff($selected, [$name]));
                else {
                    $selected[] = $name;
                    // A list discovered in a restored node now has a controller-side owner.
                    $pac['node_policy_lists'] = $catalog;
                }
                if ($selected) $client['exit_main'] = $selected;
                else unset($client['exit_main']);
                return '';
            }
            return 'exit stale';
        });
        $this->exitMainMenu($id, $key, $page, $error === '' ? '' : $this->exitError($error));
    }

    private function nodePolicyUsage(string $name, array $pac): array
    {
        $used = [];
        foreach ($this->getXray()['inbounds'][0]['settings']['clients'] ?? [] as $client) {
            if (in_array($name, $client['exit_main'] ?? [], true)) {
                $used[] = $this->t('Основной сервер', 'Main server') . ' · ' . $client['email'];
            }
        }
        foreach ($this->managedNodes($pac) as $id => $node) {
            foreach ([$node['status']['options'] ?? [], $node['draft'] ?? []] as $options) {
                foreach ($options['policy']['bindings'] ?? [] as $scope => $rows) {
                    if (in_array($name, array_column($rows, 'list'), true)) {
                        $owner = $this->nodePolicySubject((string)$id, $scope) ?? $this->t('Отозванное подключение', 'Revoked connection');
                        $used[$id . '/' . $scope] = ($node['name'] ?? $id) . ' · ' . $owner;
                    }
                }
            }
        }
        return array_values($used);
    }

    public function nodePolicySync(string $id, string $scope): void
    {
        $this->nodePolicyDraft($id, function (&$policy) {
            $catalog = $this->nodePolicyCatalog();
            foreach ($policy['lists'] as $name => $_) {
                if (isset($catalog[$name])) $policy['lists'][$name] = $catalog[$name];
                else unset($policy['lists'][$name]);
            }
        });
        $this->nodePolicyMenu($id, $scope);
    }

    private function nodePolicyDeletedClients(array $policy): array
    {
        $missing = array_filter($policy['bindings'] ?? [], static fn($scope) => str_starts_with($scope, 'bot-'), ARRAY_FILTER_USE_KEY);
        if (!$missing) return [];
        $clients = $this->getXray()['inbounds'][0]['settings']['clients'] ?? null;
        if (!is_array($clients)) return [];
        foreach ($clients as $client) unset($missing[self::nodePolicyBotScope($client)]);
        return $missing;
    }

    public function nodePolicyClean(string $id, string $expected): void
    {
        $this->nodePolicyDraft($id, function (&$policy) use ($expected) {
            $missing = $this->nodePolicyDeletedClients($policy);
            if (!$missing || self::exitEntryKey(serialize($missing)) !== $expected) return;
            $unused = [];
            foreach ($missing as $scope => $rows) {
                unset($policy['bindings'][$scope]);
                foreach ($rows as $row) $unused[$row['list']] = true;
            }
            foreach ($policy['bindings'] as $rows) {
                foreach ($rows as $row) unset($unused[$row['list']]);
            }
            $policy['lists'] = array_diff_key($policy['lists'], $unused);
        });
        $this->nodePolicyMenu($id, 'all');
    }

    private function nodePolicyDraft(string $id, callable $edit): void
    {
        $this->managedNodeDraftWrite($id, static function (&$node) use ($edit) {
            if (empty($node['status']['named_policy'])) throw new RuntimeException('Node upgrade required');
            $options = $node['draft'] ?? $node['status']['options'];
            $policy = $options['policy'] ?? ['lists' => [], 'bindings' => []];
            $previous = $policy;
            $edit($policy);
            if ($policy === $previous) return;
            $policy['revision'] = bin2hex(random_bytes(16));
            if ($policy['lists'] || !empty($policy['controller_ips'])) $options['policy'] = $policy;
            else unset($options['policy']);
            if (!isset($node['draft'])) $node['draft_generation'] = $node['status']['generation'];
            $node['draft'] = $options;
        });
    }

    public function nodePolicyMenu(string $id, string $scope = 'all', int $page = 0, string $notice = ''): void
    {
        $node = $this->managedNodes()[$id] ?? [];
        $name = $this->nodePolicySubject($id, $scope);
        if (empty($node['status']['named_policy']) || $name === null) { $this->managedNodeMenu($id); return; }
        $options = $node['draft'] ?? $node['status']['options'];
        $policy = $options['policy'] ?? [];
        $rows = $policy['bindings'][$scope] ?? [];
        $order = array_flip(array_column($rows, 'list'));
        $actions = array_column($rows, 'action', 'list');
        $labels = ['block' => '⛔', 'warp' => 'WARP', 'direct' => $this->t('Нода', 'Node')];
        $text = [self::esc($name),
            isset($node['draft']) ? $this->t('Показан черновик. Действующая версия на ноде изменится после применения.', 'Showing the draft. Apply to replace the active version.')
                : $this->t('Показана последняя подтверждённая конфигурация ноды.', 'Showing the last confirmed node configuration.'), $this->t('Запрет старше выбора выхода. Кнопка меняет действие. Отключите и добавьте список снова, чтобы переместить его в конец очереди.',
            'Deny takes priority over exit selection. Tap to change the action. Disable and re-add a list to move it to the end.')];
        if (str_starts_with($scope, 'bot-') && ($this->exitNodes()[$id]['managed_profile']['channel'] ?? '') === 'wireguard') {
            $text[] = $this->t('Общий канал WireGuard не передаёт личность пользователя. При активных персональных правилах соединения этого пользователя через канал блокируются. Для персональных правил используйте VLESS или VLESS внутри AmneziaWG.',
                'The shared WireGuard channel does not carry the user identity. Active personal rules block this user on that channel. Use VLESS or VLESS inside AmneziaWG for personal rules.');
        }
        $buttons = [];
        $catalog = $this->nodePolicyCatalog();
        $names = array_keys($catalog);
        foreach ($policy['lists'] ?? [] as $list => $active) {
            if (($catalog[$list] ?? null) !== $active) {
                $text[] = $this->t('В библиотеке обновлены списки этой ноды.', 'Updated lists are available for this node.');
                $buttons[] = [['text' => $this->t('Обновить черновик', 'Refresh draft'), 'callback_data' => "/npSync $id $scope"]];
                break;
            }
        }
        $pages = max(1, (int)ceil(count($names) / 8));
        $page = min($pages - 1, max(0, $page));
        foreach (array_slice($names, $page * 8, 8) as $list) {
            $action = $actions[$list] ?? 'off';
            $key = self::exitEntryKey($list);
            $buttons[] = [['text' => ($action === 'off' ? '○' : ($order[$list]+1) . ' ' . $labels[$action]) . ' ' . $list,
                'callback_data' => "/npSet $id $scope $key $action"]];
        }
        if ($pages > 1) $buttons[] = [['text' => '←', 'callback_data' => "/np $id $scope " . max(0,$page-1)],
            ['text' => '→', 'callback_data' => "/np $id $scope " . min($pages-1,$page+1)]];
        $buttons[] = [['text' => $this->t('Создать / изменить список', 'Create / edit list'), 'callback_data' => "/npEdit $id $scope"]];
        $buttons[] = [['text' => $this->t('Проверить маршрут', 'Preview route'), 'callback_data' => "/npTest $id $scope"]];
        if ($scope === 'all' && ($missing = $this->nodePolicyDeletedClients($policy))) {
            $buttons[] = [['text' => $this->t('Снять в черновике назначения удалённых клиентов', 'Remove deleted clients’ assignments in draft') . ' (' . count($missing) . ')',
                'callback_data' => "/npClean $id " . self::exitEntryKey(serialize($missing))]];
        }
        if (isset($node['draft'])) $buttons[] = [['text' => $this->t('Применить черновик', 'Apply draft'), 'callback_data' => "/nodeApply $id"],
            ['text' => $this->t('К настройкам', 'Settings'), 'callback_data' => "/nodeSettings $id"]];
        $buttons[] = [['text' => $this->i18n('back'), 'callback_data' => "/node $id"]];
        if ($notice !== '') $text[] = self::esc($notice);
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n\n", $text), $buttons);
    }

    public function nodePolicyAssign(string $id, string $scope, string $key, string $expected): void
    {
        if ($this->nodePolicySubject($id, $scope) === null) { $this->managedNodeMenu($id); return; }
        $this->nodePolicyDraft($id, function (&$policy) use ($scope, $key, $expected) {
            foreach ($this->nodePolicyCatalog() as $list => $parts) {
                if (self::exitEntryKey($list) !== $key) continue;
                $rows = $policy['bindings'][$scope] ?? [];
                $index = array_search($list, array_column($rows, 'list'), true);
                $old = $index === false ? 'off' : $rows[$index]['action'];
                if ($old !== $expected) return;
                $next = ($scope === 'all' ? ['off'=>'block','block'=>'off'] : ['off'=>'block','block'=>'warp','warp'=>'direct','direct'=>'off'])[$old];
                if ($next === 'off') array_splice($rows, $index, 1);
                elseif ($index === false) $rows[] = ['list'=>$list, 'action'=>$next];
                else $rows[$index]['action'] = $next;
                if ($next !== 'off') $policy['lists'][$list] = $parts;
                if ($rows) $policy['bindings'][$scope] = $rows;
                else unset($policy['bindings'][$scope]);
                foreach ($policy['bindings'] as $bound) {
                    if (in_array($list,array_column($bound,'list'),true)) return;
                }
                unset($policy['lists'][$list]);
                break;
            }
        });
        $this->nodePolicyMenu($id, $scope);
    }

    public function nodePolicyPrompt(string $id, string $scope, bool $test): void
    {
        $node = $this->managedNodes()[$id] ?? [];
        if (empty($node['status']['named_policy']) || $this->nodePolicySubject($id, $scope) === null) return;
        if ($test) {
            $this->exitPrompt($this->t('Введите домен или IP назначения.', 'Enter the destination domain or IP.'), 'saveNodePolicyTest', [$id, $scope]);
            return;
        }
        $options = $node['draft'] ?? $node['status']['options'];
        $version = hash('sha256', serialize($this->nodePolicyCatalog()));
        $this->exitPrompt($this->t('Первая строка — название списка. Далее по одной записи на строку: IP/CIDR, domain:, full:, keyword:, regexp: или set: domain/ipcidr HTTPS-URL. Повтор названия заменяет содержимое для всех его назначений после применения. Одно название без записей удаляет свободный список.',
            'First line: list name. Enter one IP/CIDR, domain:, full:, keyword:, regexp: or set: domain/ipcidr HTTPS URL per line. Reusing a name replaces it in all assignments upon apply. A name alone deletes an unused list.'),
            'saveNodePolicyList', [$id, $scope, $version]);
    }

    /** Expand only active controller IP rules. A broken asset must never become an empty allow list. */
    private function controllerBlockedIps(array $config): array
    {
        $ips = [];
        foreach ($config['routing']['rules'] ?? [] as $rule) {
            if (($rule['ruleTag'] ?? '') !== 'vpnbot:routes:block:ip') continue;
            foreach ($rule['ip'] as $raw) {
                $entry = $this->classifyRouteEntry($raw);
                if ($entry['kind'] === 'ext') $entry['kind'] = 'extip';
                if (in_array($entry['kind'], ['extip', 'geoip'], true)) {
                    $expanded = $this->nodePolicyDat($entry);
                    if (!$expanded) throw new RuntimeException('Empty IP category');
                    foreach ($expanded as $ip) $ips[$ip] = true;
                } elseif ($entry['kind'] === 'ip' && $entry['value'] !== '') {
                    $ips[$entry['value']] = true;
                } else {
                    throw new RuntimeException('Unsupported controller IP rule');
                }
            }
        }
        $list = array_keys($ips);
        sort($list, SORT_STRING);
        return $list;
    }

    private function withControllerIps(array $options, array $ips): array
    {
        if (($options['policy']['controller_ips'] ?? []) === $ips) return $options;
        $policy = $options['policy'] ?? ['lists' => [], 'bindings' => []];
        if ($ips) $policy['controller_ips'] = $ips;
        else unset($policy['controller_ips']);
        $policy['revision'] = bin2hex(random_bytes(16));
        if ($ips || $policy['bindings'] || $policy['lists']) $options['policy'] = $policy;
        else unset($options['policy']);
        return $options;
    }

    private function syncControllerIps(string $id): void
    {
        $this->managedNodeLocked($id, function () use ($id) {
            $node = $this->managedNodes()[$id] ?? [];
            if (empty($node['connected']) || empty($node['status']['controller_ip_guard']) || !empty($node['job'])
                || isset($node['draft']) || !empty($node['recovery_required']) || !empty($node['status']['pending'])) return;
            $options = $node['status']['options'];
            $config = $this->getXray();
            if (!is_array($config) || !isset($config['routing']['rules'])) return;
            $updated = $this->withControllerIps($options, $this->controllerBlockedIps($config));
            if ($updated !== $options) {
                $this->managedNodeSubmitLocked($id, 'configure', $updated, $node['status']['generation']);
                return;
            }
            // A restored node can accept a different policy identity, even with no shared IP blocks.
            $before = $this->exitNodes()[$id] ?? null;
            $remote = $options['policy'] ?? [];
            $local = $before['policy'] ?? [];
            if ($remote !== $local) {
                $profile = $this->managedNodeRpc($id, ['action' => 'profile', 'peer' => null]);
                if ($this->managedNodeUseProfile($id, $profile, $options) !== '') return;
                try {
                    if (!$this->managedNodeTrafficReady($id)) throw new RuntimeException('Node traffic probe failed');
                } catch (Throwable $error) {
                    $this->managedNodeRestoreClient($id, $before);
                    throw $error;
                }
            }
        });
    }

    private function nodePolicyDat(array $entry): array
    {
        $ip = in_array($entry['kind'], ['geoip', 'extip'], true);
        if (isset(self::CORE_DAT[$entry['kind']])) {
            $file = self::CORE_DAT[$entry['kind']];
            $category = $entry['value'];
        } else {
            [$file, $category] = array_pad(explode(':', $entry['value'], 2), 2, '');
        }
        if (!preg_match('~^[a-zA-Z0-9_.-]+\.dat$~D', $file) || !preg_match('~^[a-zA-Z0-9_-]+$~D', $category)
            || $this->datCategoryError($entry) !== null) throw new InvalidArgumentException();
        $path = $this->datPath($this->datResolve($file));
        $tmp = tempnam(sys_get_temp_dir(), 'node-list-');
        if ($tmp === false) throw new RuntimeException();
        try {
            $cmd = ['python3', __DIR__.'/exit_ruleset.py', 'dat', $path, $tmp, $ip ? 'ip' : 'domain', $category];
            if (!$this->exitRulesetTool($cmd)) throw new InvalidArgumentException();
            return json_decode(file_get_contents($tmp), true, 32, JSON_THROW_ON_ERROR);
        } finally { unlink($tmp); }
    }

    public function saveNodePolicyList($text, string $id, string $scope, string $version): void
    {
        try {
            [$name, $body] = array_pad(preg_split('~\R~u', trim((string)$text), 2), 2, '');
            if (!preg_match('~^(?![0-9]+$)[\pL\pN_. -]{1,64}$~uD', $name)) throw new InvalidArgumentException();
            [$entries,$sets,$bad] = $this->exitImportParse($body);
            if ($bad) throw new InvalidArgumentException();
            foreach ($sets as $url => $set) {
                if (!$set['on']) continue;
                $bin = $this->exitRulesetDownload($url);
                $fmt = strtolower(pathinfo(parse_url($url, PHP_URL_PATH), PATHINFO_EXTENSION));
                $unsupported = false;
                $items = $bin === null ? null : $this->exitRulesetConvert($bin, $fmt, $set['behavior'], $unsupported, true);
                if (!$items) throw new InvalidArgumentException();
                foreach ($items as $entry) $entries[$entry] = 1;
            }
            foreach (array_keys(array_filter($entries)) as $raw) {
                $entry = $this->classifyRouteEntry((string)$raw);
                if (!in_array($entry['kind'], ['ext','extip','geosite','geoip'],true)) continue;
                foreach ($this->nodePolicyDat($entry) as $value) $entries[$value] = 1;
                unset($entries[$raw]);
            }
            $parts = [];
            foreach (array_keys(array_filter($entries)) as $entry) {
                $c = $this->classifyRouteEntry((string)$entry);
                if (!$this->routeEntryUsable($c)) throw new InvalidArgumentException();
                if ($c['kind'] === 'ip') $parts['ip'][] = $c['value'];
                elseif (in_array($c['kind'], ['full','suffix','domain','regexp','keyword'], true)) {
                    $token = $this->xrayDomainToken($c);
                    $parts['domain'][] = ($c['kind'] === 'keyword' ? 'keyword:' : '') . $token;
                } else throw new InvalidArgumentException();
            }
            if ($body !== '' && !$parts) throw new InvalidArgumentException();
            if (strlen(json_encode($parts, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR)) > 3 * 1024 * 1024) throw new InvalidArgumentException();
            $pac = $this->getPacConf();
            $used = $this->nodePolicyUsage($name, $pac);
            if (!$parts && $used) throw new RuntimeException();
            $saved = $this->applyExitTransaction(function (&$pac) use ($name,$parts,$version,$id) {
                if (empty($pac['managed_nodes'][$id]['status']['named_policy'])) return 'exit stale';
                $catalog = $this->nodePolicyCatalog($pac);
                if (hash('sha256',serialize($catalog)) !== $version) return 'exit stale';
                if ($parts) $catalog[$name] = $parts;
                else {
                    if ($this->nodePolicyUsage($name,$pac)) return 'exit stale';
                    unset($catalog[$name]);
                }
                $pac['node_policy_lists'] = $catalog;
                return '';
            }, false, static function ($x) use ($name) {
                foreach ($x['inbounds'][0]['settings']['clients'] ?? [] as $client) {
                    if (in_array($name, $client['exit_main'] ?? [], true)) return true;
                }
                return false;
            });
            if ($saved !== '') throw new RuntimeException();
            if ($used) {
                $this->nodePolicyMenu($id,$scope,0,$this->t('Список обновлён. На нодах примените черновик. Назначения: ', 'List updated. Apply the draft on each node. Assignments: ') . implode(', ',$used));
                return;
            }
            $this->nodePolicyMenu($id,$scope);
        } catch (Throwable $e) {
            $this->nodePolicyMenu($id,$scope,0,$this->t('Список не сохранён. Проверьте формат, доступность набора и актуальность черновика.', 'List not saved. Check the entries, source availability and draft revision.'));
        }
    }

    public function saveNodePolicyTest($text, string $id, string $scope): void
    {
        $node = $this->managedNodes()[$id] ?? [];
        $options = $node['draft'] ?? $node['status']['options'] ?? [];
        $policy = $options['policy'] ?? [];
        $rows = array_merge($policy['bindings']['all'] ?? [], $scope === 'all' ? [] : ($policy['bindings'][$scope] ?? []));
        usort($rows, static fn($a,$b) => ($a['action'] !== 'block') <=> ($b['action'] !== 'block'));
        $target = strtolower(trim((string)$text, " \r\n\t."));
        $ip = filter_var($target,FILTER_VALIDATE_IP) !== false;
        $unknown = false;
        if (!$ip && !filter_var($target, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
            $this->nodePolicyMenu($id,$scope,0,$this->t('Введите корректный домен или IP.', 'Enter a valid domain or IP.'));
            return;
        }
        $default = 'direct';
        if (str_starts_with($scope,'bot-')) {
            foreach ($this->getXray()['inbounds'][0]['settings']['clients'] ?? [] as $client) {
                if (self::exitFullId($client) !== $id || self::nodePolicyBotScope($client) !== $scope) continue;
                if (self::exitWarpSelected($client,$id)) $default = 'warp';
                $pac = $this->getPacConf();
                $blocked = $this->exitTraceEntry($target, array_keys(array_filter($pac['blocklist'] ?? [])));
                if (!empty($blocked['exact'])) {
                    $this->nodePolicyMenu($id,$scope,0,$this->t('Блокировка основного сервера', 'Blocked by the main server'));
                    return;
                }
                if (empty($client['exit_main'])) break;
                $catalog = $this->nodePolicyCatalog($pac);
                foreach ($client['exit_main'] as $list) {
                    $parts = $catalog[$list] ?? [];
                    $hit = $this->exitTraceEntry($target, array_merge($parts['domain'] ?? [], $parts['ip'] ?? []));
                    if (!$hit) continue;
                    $result = $this->t('Основной сервер', 'Main server') . ' · ' . $list
                        . $this->t(' (с учётом глобальных блокировок, DNS и проверки конечного IP)', ' (subject to global blocks, DNS and final IP checks)');
                    $this->nodePolicyMenu($id,$scope,0,$result);
                    return;
                }
                break;
            }
        }
        $result = $scope === 'all' ? $this->t('Общего запрета нет. Выход определяется правилами клиента.', 'No node-wide deny. Client rules select the exit.')
            : $this->t('Выход по умолчанию', 'Default exit') . ' → ' . $default;
        foreach ($rows as $row) {
            $parts = $policy['lists'][$row['list']];
            $matched = $this->exitTraceEntry($target, array_merge($parts['domain'] ?? [], $parts['ip'] ?? [])) !== null;
            if ($matched) { $result = $row['list'].' → '.$row['action']; break; }
            if (!$ip && !empty($parts['ip'])) $unknown = true;
        }
        if ($unknown) $result .= $this->t(' · зависит от IP после DNS на ноде', ' · depends on the IP resolved at the node');
        $this->nodePolicyMenu($id,$scope,0,$result);
    }
}
