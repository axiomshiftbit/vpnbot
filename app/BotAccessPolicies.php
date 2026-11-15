<?php

trait BotAccessPolicies
{
    public function subscriptionCardSummary(array $client, int|string $index): array
    {
        try { $used = $this->xrUserTraffic($this->getXrayStats(), $index) + array_sum($this->xrayProtocolUsage($client)); }
        catch (Throwable $error) { $used = null; }
        $limit = (int) ($client['traffic'] ?? 0); $expires = (int) ($client['time'] ?? 0);
        $status = !empty($client['traffic_usage_unavailable']) || ($used === null && $limit) ? $this->t('общий расход недоступен', 'shared usage unavailable') : (!empty($client['off']) ? (!empty($client['traffic_off']) ? $this->t('квота исчерпана', 'quota used up') : $this->t('выключен', 'disabled'))
            : ($expires && $expires <= time() ? $this->t('срок истёк', 'expired') : ($limit && $used >= $limit ? $this->t('квота исчерпана', 'quota used up') : $this->t('доступен', 'available'))));
        return [$this->t('<b>Доступ: ', '<b>Access: ') . $status . '</b>',
            $this->t('Срок (UTC): ', 'Expiry (UTC): ') . ($expires ? gmdate('Y-m-d H:i', $expires) : $this->t('без ограничения', 'unlimited')),
            $this->t('Общий расход: ', 'Total usage: ') . ($used === null ? $this->t('недоступен', 'unavailable') : $this->getBytes($used)) . $this->t('; осталось: ', '; remaining: ') . ($limit ? ($used === null ? $this->t('неизвестно', 'unknown') : $this->getBytes(max(0, $limit - $used))) : $this->t('без лимита', 'no limit'))];
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
            if (!$user) throw new InvalidArgumentException($this->t('Пользователь удалён', 'User deleted'));
            if (isset($user['xray_source'])) {
                $this->xrayProtocolsMenu($user['xray_source']); return;
            }
            if (in_array($action, ['schedule', 'alerts'], true)) {
                $example = (new DateTimeImmutable('first day of next month', new DateTimeZone('UTC')))->format('Y-m-01 00:00');
                $prompt = $action === 'schedule'
                    ? $this->t('Введите период и первую дату сброса UTC: day, week или month, затем YYYY-MM-DD HH:MM. Например: month ', 'Enter the period and the first UTC reset date: day, week or month, then YYYY-MM-DD HH:MM. For example: month ') . $example . $this->t('. Значение 0 отключает расписание. Ручной выключатель и срок доступа сохраняются.', '. 0 disables the schedule. The manual switch and the access expiry stay.')
                    : $this->t('Введите пороги уведомлений администратору: процент расхода и дни до окончания срока, например 80 3. Для отключения соответствующего предупреждения укажите 0. Диапазоны: 0–100 и 0–365.', 'Enter the admin notification thresholds: usage percent and days before expiry, e.g. 80 3. Enter 0 to disable the corresponding warning. Ranges: 0–100 and 0–365.');
                $r = $this->send($this->input['chat'], $prompt, $this->input['message_id'], reply: $this->t('Введите значение', 'Enter a value'));
                $this->stashReply($r, ['start_message' => $this->input['message_id'], 'callback' => 'accessPolicyReply', 'args' => [$scope, $id, $action]]);
                return;
            }
            $text = [$this->t('Квота и уведомления → ', 'Quota and notifications → ') . self::esc($user['name']), ...$this->accessPolicySummary($user),
                $this->t('Сброс расхода не продлевает срок и не включает доступ, выключенный вручную. После простоя пропущенные периоды выполняются одним сбросом. Все даты в UTC.', 'A usage reset does not extend the expiry and does not enable access disabled by hand. After downtime missed periods are done in a single reset. All dates are UTC.'),
                $this->t('Уведомления получает администратор. Проверка — в периодическом цикле бота; временная недоступность статистики откладывает предупреждение о трафике.', 'The administrator receives the notifications. The check runs in the bot\'s periodic loop; temporarily unavailable statistics postpone the traffic warning.')];
            $this->update($this->input['chat'], $this->input['message_id'], implode("\n\n", $text), [
                [['text' => $this->t('Расписание сброса', 'Reset schedule'), 'callback_data' => "/ap $scope $id schedule"]],
                [['text' => $this->t('Пороги уведомлений', 'Notification thresholds'), 'callback_data' => "/ap $scope $id alerts"]],
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
            } else throw new InvalidArgumentException($this->t('Неверное значение', 'Invalid value'));
            $this->accessStore($scope)->change(static function (&$state) use ($id, $action, $value) {
                if (!isset($state['users'][$id])) throw new InvalidArgumentException(Lang::t('Пользователь удалён', 'User deleted'));
                if (isset($state['users'][$id]['xray_source'])) throw new InvalidArgumentException(Lang::t('Этот доступ использует общий лимит VLESS', 'This access uses the shared VLESS limit'));
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
            $s ? $this->t('Сброс: ', 'Reset: ') . AccessPolicy::periodLabel($s['period']) . $this->t('; следующий (UTC): ', '; next (UTC): ') . gmdate('Y-m-d H:i', $s['next']) : $this->t('Автоматический сброс: выключен', 'Automatic reset: off'),
            $this->t('Предупреждения: ', 'Warnings: ') . ($a['percent'] ? $a['percent'] . $this->t('% расхода', '% of usage') : $this->t('трафик — выкл.', 'traffic: off'))
                . '; ' . ($a['days'] ? $this->t('за ', '') . $a['days'] . $this->t(' дн. до окончания', ' d before expiry') : $this->t('срок — выкл.', 'expiry: off')),
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
                                    ? $this->t('Расход: ', 'Usage: ') . $this->getBytes(AccessPolicy::bytes($user, $row)) . $this->t(' из ', ' of ') . $this->getBytes($user['quota'])
                                    : $this->t('Срок (UTC): ', 'Expiry (UTC): ') . gmdate('Y-m-d H:i', $user['expires']);
                                $message .= $this->t("\nДоступ: ", "\nAccess: ") . AccessPolicy::reason($user, AccessPolicy::bytes($user, $row), $now);
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
