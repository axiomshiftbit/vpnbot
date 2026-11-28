<?php

trait BotGroupXrayBatch
{
    private function groupedXrayUsers(array $x, string $group): array
    {
        $state = $this->getPacConf()['access_groups'] ?? [];
        $users = [];
        foreach ($x['inbounds'][0]['settings']['clients'] ?? [] as $i => $client) {
            $source = ManagedProtocol::xraySource($client);
            if (($state['members']["xr.$source"]['group'] ?? null) !== $group) continue;
            $users[$source] = ['name' => $client['name'] ?? $client['email'] ?? (string) $i,
                'expires' => $client['time'] ?? null, 'quota' => $client['traffic'] ?? null,
                'fingerprint' => AccessBatch::fingerprint($client), 'index' => $i];
        }
        return $users;
    }

    public function groupXrayPrompt(string $group, int $page): void
    {
        if (!$this->admin) return;
        $this->exitPrompt($this->t('Введите quota и квоту в ГиБ или extend и число дней. Для снятия лимита введите quota 0.', 'Enter quota and a GiB limit, or extend and a number of days. Enter quota 0 to remove the limit.'),
            'groupXrayReply', [$group, $page]);
    }

    public function groupXrayReply(string $text, string $group, int $page): void
    {
        if (!$this->admin) return;
        try {
            if (!preg_match('/\A(quota|extend)\s+(\S+)\z/D', trim($text), $m)) throw new InvalidArgumentException($this->t('Нужно quota или extend и значение', 'Enter quota or extend and a value'));
            $x = $this->getXray(); $users = $this->groupedXrayUsers($x, $group);
            $ids = array_slice(array_keys($users), max(0, $page)*20, 20);
            $preview = AccessBatch::preview($users, $ids, $m[1], AccessBatch::value($m[1], $m[2]), time());
            $rows = $this->accessGroupAccounts();
            $token = bin2hex(random_bytes(8));
            $this->sessionApply(function () use ($preview, $token, $group) {
                $_SESSION['group_xray'][$this->input['chat']] = compact('preview', 'token', 'group');
            });
            $lines = [$this->t('Предварительный просмотр · VLESS', 'Preview · VLESS')];
            foreach ($preview['rows'] as $row) {
                $change = $row['skip'];
                if ($change === '') $change = $m[1] === 'extend' ? gmdate('Y-m-d H:i:s', $row['after']['expires']-1) . ' UTC'
                    : ($row['after']['quota'] === null ? $this->t('без лимита', 'unlimited') : $this->getBytes($row['after']['quota']));
                $meters = $rows['xr.' . $row['id']]['meters'] ?? [null];
                $bytes = in_array(null, $meters, true) ? null : array_sum(array_column($meters, 1));
                $lines[] = self::esc(mb_substr($row['name'], 0, 40)) . ' → ' . self::esc($change) . $this->t(' · расход ', ' · usage ')
                    . ($bytes === null ? $this->t('недоступен', 'unavailable') : $this->getBytes($bytes));
            }
            $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $lines), [[
                ['text' => $this->t('Применить', 'Apply'), 'callback_data' => "/agxrapply $token yes"],
                ['text' => $this->t('Отмена', 'Cancel'), 'callback_data' => "/agxrapply $token no"]]]);
        } catch (RuntimeException | InvalidArgumentException $e) { $this->protocolError($e->getMessage(), "/ag show $group"); }
    }

    public function groupXrayFinish(string $token, bool $apply): void
    {
        if (!$this->admin) return;
        $plan = null;
        $this->sessionApply(function () use ($token, &$plan) {
            $saved = $_SESSION['group_xray'][$this->input['chat']] ?? [];
            if (hash_equals($saved['token'] ?? '', $token)) {
                $plan = $saved; unset($_SESSION['group_xray'][$this->input['chat']]);
            }
        });
        try {
            if (!$plan) throw new InvalidArgumentException($this->t('Предварительный просмотр устарел', 'The preview is outdated'));
            if ($apply) {
                $saved = $this->withLock('xray', fn() => $this->withLock('access-groups', function () use ($plan) {
                    $x = $this->getXray(); $users = $this->groupedXrayUsers($x, $plan['group']);
                    if (!AccessBatch::apply($users, $plan['preview'], time())) return true;
                    $restart = false;
                    foreach ($plan['preview']['rows'] as $row) {
                        if ($row['skip'] !== '') continue;
                        $id = $users[$row['id']]['index'];
                        $field = $plan['preview']['action'] === 'quota' ? 'traffic' : 'time';
                        $value = reset($row['after']);
                        if ($value === null) unset($x['inbounds'][0]['settings']['clients'][$id][$field]);
                        else $x['inbounds'][0]['settings']['clients'][$id][$field] = $value;
                        $client = $x['inbounds'][0]['settings']['clients'][$id];
                        if ($field === 'traffic' && !empty($client['traffic_off']) && ($value === null || !$this->xrayQuotaUnavailableOrExhausted($client, $id))) {
                            $x = $this->reenableTrafficClients($x, $id); $restart = true;
                        }
                    }
                    return $this->restartXray($x, !$restart) !== false;
                }, 15), 20);
                if (!$saved) throw new RuntimeException($this->t('Не удалось применить изменения Xray', 'Could not apply Xray changes'));
            }
            $this->accessGroupCommand('show', $plan['group']);
        } catch (RuntimeException | InvalidArgumentException $e) { $this->protocolError($e->getMessage(), '/ag'); }
    }
}
