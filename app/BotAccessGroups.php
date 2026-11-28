<?php

/** Administrative groups are keyed by the access identity, independently of its display name or Xray index. */
require_once __DIR__ . '/BotGroupXrayBatch.php';

trait BotAccessGroups
{
    use BotGroupXrayBatch;
    public static function validateAccessGroups(mixed $state): void
    {
        $invalid = static function () { throw new InvalidArgumentException(Lang::t('Повреждены данные групп пользователей', 'Invalid user group data')); };
        if (!is_array($state) || !is_array($state['members'] ?? null) || !is_array($state['groups'] ?? null) || count($state['groups']) > 64) $invalid();
        foreach ($state['groups'] as $id => $g) {
            if (!preg_match('/^[a-f0-9]{10}$/D', (string) $id) || !is_array($g) || !is_string($g['name'] ?? null)
                || !preg_match('/\A[^\p{C}]{1,40}\z/uD', $g['name']) || !is_int($g['bytes'] ?? null) || $g['bytes'] < 0) $invalid();
        }
        $access = '/^(?:xr[.][a-f0-9]{32}|(?:hy|anytls|mieru|tuic|shadowtls|snolc|masque)[.][a-f0-9]{16})$/D';
        foreach ($state['members'] as $key => $m) {
            if (!preg_match($access, (string) $key) || !is_array($m) || !is_string($m['group'] ?? null)
                || !isset($state['groups'][$m['group']]) || !is_array($m['last'] ?? null) || !is_array($m['waiting'] ?? [])) $invalid();
            foreach ($m['last'] as $counter => $epochs) {
                if (($counter !== 'xr' && !preg_match($access, (string) $counter)) || !is_array($epochs)) $invalid();
                foreach ($epochs as $epoch => $bytes) if (($epoch !== 'initial' && !preg_match('/^[a-f0-9]{16}$/D', (string) $epoch)) || !is_int($bytes) || $bytes < 0) $invalid();
            }
        }
    }

    protected function accessGroupAccounts(): array
    {
        $accounts = [];
        $clients = $this->getXray()['inbounds'][0]['settings']['clients'] ?? [];
        try { $xr = $clients ? $this->getXrayStats() : []; }
        catch (RuntimeException $e) { $xr = null; }
        foreach ($clients as $index => $client) {
            $source = ManagedProtocol::xraySource($client);
            $epoch = $xr['group_epochs'][$source] ?? $xr['group_epochs']['all'] ?? 'initial';
            $accounts['xr.' . $source] = ['name' => $client['name'] ?? $client['email'] ?? (string) $index,
                'back' => "/userXr $index !" . rtrim(strtr(base64_encode(hex2bin($source)), '+/', '-_'), '='), 'meters' => ['xr' => $xr === null ? null : [$epoch, $this->xrUserTraffic($xr, $index)]]];
        }
        foreach (['hy', ...array_keys(ManagedProtocol::NAMES)] as $scope) {
            $store = $this->accessStore($scope);
            try { $users = $store->read()['users']; }
            catch (RuntimeException | InvalidArgumentException $e) {
                if ($scope !== 'hy') foreach ($accounts as $key => &$row) {
                    if (str_starts_with($key, 'xr.')) $row['meters'][$scope] = null;
                }
                unset($row);
                continue;
            }
            if (!$users) continue;
            try { $usage = $store->usage()['users'] ?? []; }
            catch (RuntimeException | InvalidArgumentException $e) { $usage = []; }
            foreach ($users as $id => $user) {
                $key = "$scope.$id";
                $bytes = AccessPolicy::bytes($user, $usage[$id] ?? null);
                $meter = $bytes === null ? null : [$user['reset'], $bytes];
                if (isset($user['xray_source'])) {
                    $parent = 'xr.' . $user['xray_source'];
                    if (isset($accounts[$parent])) $accounts[$parent]['meters'][$key] = $meter;
                } else $accounts[$key] = ['name' => $user['name'], 'back' => $this->accessBack($scope, (string) $id), 'meters' => [$key => $meter]];
            }
        }
        return $accounts;
    }

    /** Observe under the group lock so a slower request cannot apply its older readings after a move. */
    private function accessGroupWork(?callable $edit = null): array
    {
        $work = function () use ($edit) {
            $before = $this->getPacConf()['access_groups'] ?? ['groups' => [], 'members' => []];
            self::validateAccessGroups($before);
            $state = $before;
            $rows = $this->accessGroupAccounts();
            foreach ($state['members'] as $key => &$member) {
                foreach ($rows[$key]['meters'] ?? [] as $component => $meter) {
                    if ($meter === null) continue;
                    [$epoch, $bytes] = $meter;
                    $last = $member['last'][$component][$epoch] ?? null;
                    // An unreadable counter at join starts at its first confirmed reading.
                    $family = explode('.', $component, 2)[0];
                    $waiting = isset($member['waiting'][$component]) || isset($member['waiting'][$family]);
                    $base = $last ?? ($waiting ? $bytes : 0);
                    $state['groups'][$member['group']]['bytes'] += max(0, $bytes - $base);
                    $member['last'][$component][$epoch] = max($base, $bytes);
                    unset($member['waiting'][$component]);
                }
                if (isset($rows[$key])) foreach (array_keys($member['waiting'] ?? []) as $counter) {
                    if (!str_contains($counter, '.') && !array_key_exists($counter, $rows[$key]['meters'])) unset($member['waiting'][$counter]);
                }
            }
            unset($member);
            if ($edit) $edit($state, $rows);
            if ($state !== $before) $this->pacConfUpdate(static function (&$pac) use ($before, $state) {
                if (($pac['access_groups'] ?? ['groups' => [], 'members' => []]) !== $before) throw new RuntimeException(Lang::t('Состав групп изменился. Повторите действие.', 'Group membership changed. Retry.'));
                $pac['access_groups'] = $state;
            });
            return [$state, $rows];
        };
        // Xray ledgers use numeric indices. Hold the same lock as client deletion
        // while reading identities and stats, then take the group lock in that order.
        $locked = fn() => $this->withLock('access-groups', $work, 15);
        $result = isset($this->heldLocks['xray']) ? $locked() : $this->withLock('xray', $locked, 20);
        if ($result === null) throw new RuntimeException($this->t('Группы временно заняты', 'Groups are temporarily busy'));
        return $result;
    }

    public function captureAccessGroupUsage(): void
    {
        if (!empty($this->getPacConf()['access_groups']['members'])) $this->accessGroupWork();
    }

    public function accessGroupCommand(string $action = 'list', string $id = '', string $key = '', int $page = 0): void
    {
        if (!$this->admin) return;
        try {
            if ($action === 'new' || $action === 'rename') {
                $this->exitPrompt($this->t('Название группы, 1–40 символов', 'Group name, 1–40 characters'), 'accessGroupName', [$id]);
                return;
            }
            $edit = null;
            if ($action === 'move') $edit = function (&$state, $rows) use ($key, $id) {
                if ($id !== '-' && (!isset($state['groups'][$id], $rows[$key]))) throw new InvalidArgumentException($this->t('Группа или доступ удалены', 'Group or access deleted'));
                $previous = $state['members'][$key]['group'] ?? '-';
                if ($previous === $id) return;
                if ($previous !== '-' && (!isset($rows[$key]) || in_array(null, $rows[$key]['meters'], true))) {
                    $state['groups'][$previous]['incomplete'] = true;
                }
                unset($state['members'][$key]);
                if ($id === '-') return;
                $member = ['group' => $id, 'last' => []];
                foreach ($rows[$key]['meters'] as $component => $meter) {
                    if ($meter === null) $member['waiting'][$component] = true;
                    else $member['last'][$component][$meter[0]] = $meter[1];
                }
                $state['members'][$key] = $member;
            };
            [$state, $rows] = $this->accessGroupWork($edit);
            if ($action === 'move') $action = $id === '-' ? 'list' : 'show';
            $buttons = [];
            $lines = [$this->t('Группы пользователей', 'User groups')];
            if ($action === 'pick') {
                if (!isset($rows[$key]) && !isset($state['members'][$key])) throw new InvalidArgumentException($this->t('Доступ удалён', 'Access deleted'));
                $lines[] = self::esc($rows[$key]['name'] ?? $this->t('Удалённый доступ', 'Deleted access'));
                $current = $state['members'][$key]['group'] ?? '-';
                foreach ($state['groups'] as $group => $item) $buttons[] = [['text' => ((string) $current === (string) $group ? '✓ ' : '') . $item['name'], 'callback_data' => "/agmove $group $key"]];
                if ($current !== '-') $buttons[] = [['text' => $this->t('Убрать из группы', 'Remove from group'), 'callback_data' => "/agmove - $key"]];
                if (isset($rows[$key])) $buttons[] = [['text' => $this->t('Карточка доступа', 'Access details'), 'callback_data' => $rows[$key]['back']]];
            } elseif ($action === 'show' || $action === 'members') {
                $group = $state['groups'][$id] ?? null;
                if (!$group) throw new InvalidArgumentException($this->t('Группа удалена', 'Group deleted'));
                $members = array_filter($state['members'], static fn($m) => $m['group'] === $id);
                $missing = 0; $scopes = [];
                foreach ($members as $k => $m) {
                    if (!isset($rows[$k]) || in_array(null, $rows[$k]['meters'], true)) $missing++;
                    if (isset($rows[$k])) $scopes[explode('.', $k, 2)[0]] = true;
                }
                $lines[] = self::esc($group['name']);
                $lines[] = $this->t('Учтено с момента включения в группу: ', 'Counted since joining the group: ') . $this->getBytes($group['bytes']);
                if (!empty($group['incomplete'])) $lines[] = $this->t('Итог частичный: при изменении состава часть показаний отсутствовала.', 'Partial total: some readings were unavailable when membership changed.');
                $lines[] = $this->t('Участников: ', 'Members: ') . count($members) . $this->t(' · без полных показаний: ', ' · incomplete readings: ') . $missing;
                $list = $action === 'members' ? array_keys($rows) : array_keys($members);
                $page = min(max(0, $page), max(0, intdiv(max(0, count($list)-1), 8)));
                foreach (array_slice($list, $page*8, 8) as $k) $buttons[] = [['text' => (isset($members[$k]) ? '✓ ' : '') . strtoupper(explode('.', $k, 2)[0]) . ' · ' . ($rows[$k]['name'] ?? $this->t('Удалён или недоступен', 'Deleted or unavailable')), 'callback_data' => "/agpick $k"]];
                if (count($list) > 8) $buttons[] = [['text' => '←', 'callback_data' => "/ag $action $id " . max(0, $page-1)], ['text' => '→', 'callback_data' => "/ag $action $id " . ($page+1)]];
                $buttons[] = [['text' => $this->t('Выбрать участников', 'Choose members'), 'callback_data' => "/ag members $id"], ['text' => $this->t('Переименовать', 'Rename'), 'callback_data' => "/ag rename $id"]];
                if (isset($scopes['xr'])) {
                    $count = count(array_filter(array_keys($members), static fn($k) => str_starts_with($k, 'xr.') && isset($rows[$k])));
                    for ($i = 0; $i*20 < $count; $i++) $buttons[] = [['text' => $this->t('Срок и квота VLESS · ', 'VLESS expiry and quota · ') . ($i*20+1) . '–' . min($count, ($i+1)*20), 'callback_data' => "/agxr $id $i"]];
                }
                foreach (array_keys($scopes) as $scope) if ($scope !== 'xr') $buttons[] = [['text' => $this->t('Групповые действия · ', 'Bulk actions · ') . strtoupper($scope), 'callback_data' => "/abstart $scope $id"]];
            } else {
                foreach ($state['groups'] as $group => $item) $buttons[] = [['text' => $item['name'], 'callback_data' => "/ag show $group"]];
                $buttons[] = [['text' => $this->t('Создать группу', 'Create group'), 'callback_data' => '/ag new']];
            }
            $buttons[] = [['text' => $this->i18n('back'), 'callback_data' => $action === 'list' ? '/menu xray' : '/ag']];
            $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $lines), $buttons);
        } catch (RuntimeException | InvalidArgumentException $e) { $this->protocolError($e->getMessage(), '/ag'); }
    }

    public function accessGroupName(string $name, string $id = ''): void
    {
        if (!$this->admin) return;
        try {
            $name = trim($name);
            if (!preg_match('/\A[^\p{C}\r\n]{1,40}\z/uD', $name)) throw new InvalidArgumentException($this->t('Нужно от 1 до 40 печатных символов', 'Enter 1 to 40 printable characters'));
            $this->accessGroupWork(function (&$state) use (&$id, $name) {
                if ($id === '') {
                    if (count($state['groups']) >= 64) throw new InvalidArgumentException($this->t('Достигнут предел в 64 группы', 'The limit of 64 groups has been reached'));
                    $id = bin2hex(random_bytes(5));
                } elseif (!isset($state['groups'][$id])) throw new InvalidArgumentException($this->t('Группа удалена', 'Group deleted'));
                foreach ($state['groups'] as $other => $group) if ((string) $other !== $id && mb_strtolower($group['name']) === mb_strtolower($name)) throw new InvalidArgumentException($this->t('Это название уже используется', 'This name is already used'));
                $state['groups'][$id] ??= ['bytes' => 0];
                $state['groups'][$id]['name'] = $name;
            });
            $this->accessGroupCommand('show', $id);
        } catch (RuntimeException | InvalidArgumentException $e) { $this->protocolError($e->getMessage(), '/ag'); }
    }
}
