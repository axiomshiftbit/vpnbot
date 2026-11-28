<?php

/** Short-lived admin confirmations contain only the proposed field and a digest of the reviewed record. */
trait BotAccessPreview
{
    private function accessPreviewFingerprint(array $record, string $scope): string
    {
        if ($scope === 'xr') $record['_monthly'] = !empty($this->getPacConf()['reset_monthly']);
        return AccessBatch::fingerprint($record);
    }

    public function previewXrayEdit(string $text, $index, string $field): void
    {
        if (!$this->admin) return;
        if (!$this->xrayClientMatches((int) $index)) { $this->staleXrayAction(); return; }
        try {
            if ($field === 'expires') {
                $value = trim($text) === '0' ? null : strtotime($text);
                if ($value === false || ($value !== null && $value < 1)) throw new InvalidArgumentException($this->t('Неверная дата', 'Invalid date'));
            } else $value = AccessBatch::value('quota', trim($text));
            $this->accessEditPreview('xr', (string) $index, $field, $value);
        } catch (RuntimeException | InvalidArgumentException $e) { $this->protocolError($e->getMessage(), '/menu xray'); }
    }

    public function accessEditPreview(string $scope, string $id, string $field, int|array|null $value): void
    {
        if (!$this->admin) return;
        if ($scope === 'xr') {
            $record = $this->getXray()['inbounds'][0]['settings']['clients'][$id] ?? null;
            if (!$record) { $this->staleXrayAction(); return; }
            $user = ['expires' => $record['time'] ?? null, 'quota' => $record['traffic'] ?? null,
                'enabled' => empty($record['off']) || !empty($record['traffic_off']), 'name' => $record['email'] ?? $id];
            try { $used = $this->xrUserTraffic($this->getXrayStats(), $id) + array_sum($this->xrayProtocolUsage($record)); }
            catch (RuntimeException $e) { $used = null; }
        } else {
            $store = $this->accessStore($scope);
            $record = $store->read()['users'][$id] ?? null;
            if (!$record || isset($record['xray_source'])) throw new InvalidArgumentException($this->t('Состав доступов изменился', 'The access list has changed'));
            $user = $record;
            try { $used = AccessPolicy::bytes($user, $store->usage()['users'][$id] ?? null); }
            catch (RuntimeException $e) { $used = null; }
        }
        $user[$field] = $value;
        $plan = ['token' => bin2hex(random_bytes(12)), 'created' => time(), 'owner' => $this->input['from'] ?? $this->input['chat'], 'scope' => $scope, 'id' => $id,
            'field' => $field, 'value' => $value, 'before' => $this->accessPreviewFingerprint($record, $scope)];
        $this->sessionApply(function () use ($plan) { $_SESSION['access_review'][$this->input['chat']] = $plan; });
        $unlimited = $this->t('без ограничения', 'unlimited');
        $lines = [$this->t('Предварительный просмотр · ', 'Preview · ') . self::esc($user['name']),
            $this->t('Последняя секунда доступа (UTC): ', 'Last valid second (UTC): ') . ($user['expires'] ? gmdate('Y-m-d H:i:s', $user['expires'] - 1) : $unlimited),
            $this->t('Квота: ', 'Quota: ') . ($user['quota'] === null ? $unlimited : $this->getBytes($user['quota'])),
            $this->t('Текущий расход сохраняется: ', 'Existing usage is kept: ') . ($used === null ? $this->t('нет показаний', 'unavailable') : $this->getBytes($used)),
            $this->t('Доступ с этими настройками: ', 'Access with these settings: ') . AccessPolicy::reason($user, $used, time())];
        $dates = [];
        if ($scope === 'xr' && !empty($this->getPacConf()['reset_monthly'])) {
            $next = strtotime('first day of next month midnight');
            for ($i = 0; $i < 3; $i++) { $dates[] = gmdate('Y-m-d H:i', $next); $next = strtotime('first day of next month midnight', $next); }
        } elseif ($s = $user['quota_schedule'] ?? null) {
            $next = $s['next'];
            for ($i = 0; $i < 3 && $next <= 4102444800; $i++) {
                $dates[] = gmdate('Y-m-d H:i', $next);
                $next = AccessPolicy::next($s['period'], $s['anchor'], max($next, time()));
            }
        }
        $lines[] = $this->t('Сбросы расхода (UTC): ', 'Usage resets (UTC): ') . ($dates ? implode(', ', $dates) : $this->t('выключены', 'off'));
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $lines), [[
            ['text' => $this->t('Применить', 'Apply'), 'callback_data' => '/areview ' . $plan['token'] . ' apply'],
            ['text' => $this->t('Отмена', 'Cancel'), 'callback_data' => '/areview ' . $plan['token'] . ' cancel']]]);
    }

    public function accessEditFinish(string $token, bool $apply): void
    {
        if (!$this->admin) return;
        $plan = null;
        $this->sessionApply(function () use ($token, &$plan) {
            $current = $_SESSION['access_review'][$this->input['chat']] ?? null;
            if ($current && $current['owner'] === ($this->input['from'] ?? $this->input['chat']) && hash_equals($current['token'], $token)) {
                unset($_SESSION['access_review'][$this->input['chat']]);
                if ($current['created'] >= time() - 600) $plan = $current;
            }
        });
        $stale = $this->t('Предварительный просмотр устарел. Откройте новый.', 'The preview has expired. Open a new one.');
        $back = '/menu';
        try {
            if (!$plan) throw new InvalidArgumentException($stale);
            ['scope' => $scope, 'id' => $id, 'value' => $value, 'field' => $field] = $plan;
            $back = $scope === 'xr' ? '/menu xray' : $this->accessBack($scope, $id);
            $check = function ($record) use ($plan, $scope, $field, $value, $stale) {
                if (!$record || !hash_equals($plan['before'], $this->accessPreviewFingerprint($record, $scope))
                    || ($field === 'quota_schedule' && $value !== null && $value['next'] <= time())) throw new InvalidArgumentException($stale);
            };
            if ($scope === 'xr') {
                $done = $this->withLock('xray', function () use ($id, $field, $value, $check, $apply) {
                    $x = $this->getXray();
                    $check($x['inbounds'][0]['settings']['clients'][$id] ?? null);
                    if ($apply && $field === 'quota') $this->writeTrafficXrLocked($value, $id);
                    else {
                        if ($apply) {
                            if ($value === null) unset($x['inbounds'][0]['settings']['clients'][$id]['time']);
                            else $x['inbounds'][0]['settings']['clients'][$id]['time'] = $value;
                            if ($this->restartXray($x, 1) === false) throw new RuntimeException($this->t('Не удалось сохранить срок', 'Could not save expiry'));
                        }
                        $this->userXrLocked($id);
                    }
                    return true;
                });
                if (!$done) throw new RuntimeException($this->t('Не удалось заблокировать Xray', 'Could not lock Xray'));
                return;
            }
            if ($apply) $this->accessStore($scope)->change(static function (&$state) use ($id, $field, $value, $check) {
                $check($state['users'][$id] ?? null);
                if ($field === 'quota_schedule' && $value === null) unset($state['users'][$id][$field]);
                else $state['users'][$id][$field] = $value;
            });
            if ($field === 'quota_schedule') $this->accessPolicyMenu($scope, $id);
            elseif ($scope === 'hy') $this->hyUserMenu($id);
            else $this->protocolMenu($scope, $id);
        } catch (RuntimeException | InvalidArgumentException $e) { $this->protocolError($e->getMessage(), $back); }
    }
}
