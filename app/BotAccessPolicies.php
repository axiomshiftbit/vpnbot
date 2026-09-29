<?php

trait BotAccessPolicies
{
    public function subscriptionCardSummary(array $client, int|string $index): array
    {
        $used = $this->xrUserTraffic($this->getXrayStats(), $index) + array_sum($this->xrayProtocolUsage($client));
        $limit = (int) ($client['traffic'] ?? 0); $expires = (int) ($client['time'] ?? 0);
        $status = !empty($client['off']) ? (!empty($client['traffic_off']) ? 'квота исчерпана' : 'выключен')
            : ($expires && $expires <= time() ? 'срок истёк' : ($limit && $used >= $limit ? 'квота исчерпана' : 'доступен'));
        return ['<b>Доступ: ' . $status . '</b>',
            'Срок (UTC): ' . ($expires ? gmdate('Y-m-d H:i', $expires) : 'без ограничения'),
            'Общий расход: ' . $this->getBytes($used) . '; осталось: ' . ($limit ? $this->getBytes(max(0, $limit - $used)) : 'без лимита')];
    }

    public function accessStore(string $scope): HysteriaUsers|ManagedProtocol
    {
        return $scope === 'hy' ? $this->hysteriaUsersStore() : $this->protocolStore($scope);
    }

    private function accessBack(string $scope, string $id = ''): string
    {
        return $scope === 'hy' ? ($id === '' ? '/hyUsers' : "/hyUser $id")
            : "/protocol $scope" . ($id === '' ? '' : " user $id");
    }

    public function accessPolicyMenu(string $scope, string $id, string $action = ''): void
    {
        if (!$this->admin) return;
        try {
            $store = $this->accessStore($scope); $user = $store->read()['users'][$id] ?? null;
            if (!$user) throw new InvalidArgumentException('Пользователь удалён');
            if (isset($user['xray_source'])) {
                $this->xrayProtocolsMenu($user['xray_source']); return;
            }
            if (in_array($action, ['schedule', 'alerts'], true)) {
                $example = (new DateTimeImmutable('first day of next month', new DateTimeZone('UTC')))->format('Y-m-01 00:00');
                $prompt = $action === 'schedule'
                    ? 'Введите период и первую дату сброса UTC: day, week или month, затем YYYY-MM-DD HH:MM. Например: month ' . $example . '. Значение 0 отключает расписание. Ручной выключатель и срок доступа сохраняются.'
                    : 'Введите пороги уведомлений администратору: процент расхода и дни до окончания срока, например 80 3. Для отключения соответствующего предупреждения укажите 0. Диапазоны: 0–100 и 0–365.';
                $r = $this->send($this->input['chat'], $prompt, $this->input['message_id'], reply: 'Введите значение');
                $this->stashReply($r, ['start_message' => $this->input['message_id'], 'callback' => 'accessPolicyReply', 'args' => [$scope, $id, $action]]);
                return;
            }
            $text = ['Квота и уведомления → ' . self::esc($user['name']), ...$this->accessPolicySummary($user),
                'Сброс расхода не продлевает срок и не включает доступ, выключенный вручную. После простоя пропущенные периоды выполняются одним сбросом. Все даты в UTC.',
                'Уведомления получает администратор. Проверка — в периодическом цикле бота; временная недоступность статистики откладывает предупреждение о трафике.'];
            $this->update($this->input['chat'], $this->input['message_id'], implode("\n\n", $text), [
                [['text' => 'Расписание сброса', 'callback_data' => "/ap $scope $id schedule"]],
                [['text' => 'Пороги уведомлений', 'callback_data' => "/ap $scope $id alerts"]],
                [['text' => $this->i18n('back'), 'callback_data' => $this->accessBack($scope, $id)]],
            ]);
        } catch (RuntimeException | InvalidArgumentException $e) { $this->protocolError($e->getMessage(), $this->accessBack($scope)); }
    }

    public function accessPolicyReply(string $text, string $scope, string $id, string $action): void
    {
        if (!$this->admin) return;
        try {
            $text = trim($text);
            if ($action === 'schedule') $value = AccessPolicy::schedule($text, time());
            elseif ($action === 'alerts' && preg_match('/\A([0-9]{1,3}) ([0-9]{1,3})\z/D', $text, $m)) {
                $value = ['percent' => (int) $m[1], 'days' => (int) $m[2]];
                AccessPolicy::validate(['alerts' => $value]);
            } else throw new InvalidArgumentException('Неверное значение');
            $this->accessStore($scope)->change(static function (&$state) use ($id, $action, $value) {
                if (!isset($state['users'][$id])) throw new InvalidArgumentException('Пользователь удалён');
                if (isset($state['users'][$id]['xray_source'])) throw new InvalidArgumentException('Этот доступ использует общий лимит VLESS');
                $field = $action === 'schedule' ? 'quota_schedule' : 'alerts';
                if ($value === null) unset($state['users'][$id][$field]);
                else $state['users'][$id][$field] = $value;
            });
            $this->accessPolicyMenu($scope, $id);
        } catch (RuntimeException | InvalidArgumentException $e) { $this->protocolError($e->getMessage(), $this->accessBack($scope, $id)); }
    }

    public function accessPolicySummary(array $user): array
    {
        $s = $user['quota_schedule'] ?? null; $a = $user['alerts'] ?? ['percent' => 0, 'days' => 0];
        return [
            $s ? 'Сброс: ' . AccessPolicy::PERIODS[$s['period']] . '; следующий (UTC): ' . gmdate('Y-m-d H:i', $s['next']) : 'Автоматический сброс: выключен',
            'Предупреждения: ' . ($a['percent'] ? $a['percent'] . '% расхода' : 'трафик — выкл.')
                . '; ' . ($a['days'] ? 'за ' . $a['days'] . ' дн. до окончания' : 'срок — выкл.'),
        ];
    }

    public function accessAlertAdmins(): array
    {
        require __DIR__ . '/config.php';
        return array_values(array_unique($c['admin'] ?? []));
    }

    public function checkAccessPolicies(?int $now = null): void
    {
        $now ??= time();
        $this->withLock('access-policies', function () use ($now) {
            $file = dirname($this->protocolModulesFile) . '/access-alerts.json';
            $seen = is_file($file) ? ManagedProtocol::readJson($file) : [];
            $keep = []; $admins = null;
            foreach (['hy', ...array_keys(ManagedProtocol::NAMES)] as $scope) {
                $store = $this->accessStore($scope);
                $exists = $scope === 'hy' ? $store->root . '/users.json' : $store->directory() . '/desired.json';
                if (!is_file($exists)) continue;
                // A broken service must not prevent maintenance of other services.
                try {
                    $state = $store->change(static function (&$state) use ($now) { return (bool) AccessPolicy::resetDue($state, $now); });
                    $usage = $store->usage(); $status = $store->status();
                    $fresh = ($status['time'] ?? 0) >= $now - 15 && !empty($status['running']) && empty($status['error']);
                    $fresh = $fresh && ($status['stats_time'] ?? 0) >= $now - 15;
                    foreach ($state['users'] as $id => $user) {
                        $row = $fresh ? ($usage['users'][$id] ?? null) : null;
                        if (!empty($user['alerts']) && !isset($user['xray_source'])) {
                            $admins ??= $this->accessAlertAdmins();
                            foreach (['quota', 'expires'] as $kind) foreach ($admins as $admin) {
                                $key = "$scope:$id:$kind:$admin";
                                if (isset($seen[$key])) $keep[$key] = $seen[$key];
                            }
                        }
                        foreach (AccessPolicy::events($user, $row, $now) as $kind => $signature) {
                            $admins ??= $this->accessAlertAdmins();
                            foreach ($admins as $admin) {
                                $key = "$scope:$id:$kind:$admin";
                                if (($seen[$key] ?? null) === $signature) continue;
                                $label = $scope === 'hy' ? 'Hysteria' : ManagedProtocol::NAMES[$scope];
                                $message = self::esc($label . ' → ' . $user['name']) . "\n";
                                $message .= $kind === 'quota'
                                    ? 'Расход: ' . $this->getBytes(AccessPolicy::bytes($user, $row)) . ' из ' . $this->getBytes($user['quota'])
                                    : 'Срок (UTC): ' . gmdate('Y-m-d H:i', $user['expires']);
                                $message .= "\nДоступ: " . AccessPolicy::reason($user, AccessPolicy::bytes($user, $row), $now);
                                $sent = $this->send($admin, $message);
                                if (!empty($sent['result']['message_id'])) {
                                    $keep[$key] = $signature;
                                    // Record each successful recipient before attempting the next.
                                    ManagedProtocol::writeJson($file, $seen = array_replace($seen, [$key => $signature]));
                                }
                            }
                        }
                    }
                } catch (RuntimeException | InvalidArgumentException $e) {
                    // Retain delivery markers on transient storage failures.
                    foreach ($seen as $key => $value) if (str_starts_with($key, $scope . ":")) $keep[$key] = $value;
                    error_log('access policies: ' . $scope . ' state unavailable');
                }
            }
            // One marker per user/kind/recipient; removed users do not accumulate.
            if ($keep !== $seen) ManagedProtocol::writeJson($file, $keep);
        });
    }
}
