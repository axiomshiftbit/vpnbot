<?php

require_once __DIR__ . '/AccessBatch.php';

trait BotAccessBatch
{
    private function accessBatchSession(string $token, ?callable $edit = null): array
    {
        $out = []; $error = null;
        $this->sessionApply(function () use ($token, $edit, &$out, &$error) {
            try {
            $key = (string) $this->input['chat'];
            $value = $_SESSION['access_batch'][$key] ?? null;
            if (!$value || !hash_equals($value['token'], $token) || $value['created'] < time() - 600) throw new InvalidArgumentException('Выбор устарел. Откройте групповые действия заново');
            if ($edit) $edit($value);
            if ($value === null) unset($_SESSION['access_batch'][$key]);
            else $_SESSION['access_batch'][$key] = $value;
            $out = $value ?? [];
            } catch (Throwable $e) { $error = $e; }
        });
        if ($error) throw $error;
        return $out;
    }

    public function accessBatchStart(string $scope): void
    {
        if (!$this->admin) return;
        try {
            $this->accessStore($scope)->read();
            $token = bin2hex(random_bytes(6));
            $this->sessionApply(function () use ($scope, $token) {
                $_SESSION['access_batch'][(string) $this->input['chat']] = ['scope' => $scope, 'token' => $token,
                    'created' => time(), 'selected' => [], 'page' => 0];
            });
            $this->accessBatch($token);
        } catch (RuntimeException | InvalidArgumentException $e) { $this->protocolError($e->getMessage(), $this->accessBack($scope)); }
    }

    public function accessBatch(string $token, string $action = 'show', string $arg = ''): void
    {
        if (!$this->admin) return;
        $scope = 'hy';
        try {
            $pending = $this->accessBatchSession($token); $scope = $pending['scope'];
            if ($action === 'cancel') {
                $this->accessBatchSession($token, static function (&$s) { $s = null; });
                if ($scope === 'hy') $this->hyUsers(); else $this->protocolMenu($scope);
                return;
            }
            if ($action === 'apply') {
                $this->accessBatchSession($token, static function (&$s) use ($arg, &$pending) {
                    if (!isset($s['confirm']) || !hash_equals($s['confirm'], $arg)) throw new InvalidArgumentException('Подтверждение устарело. Откройте текущий предварительный просмотр');
                    $pending = $s; $s = null;
                });
                if (!isset($pending['preview'])) throw new InvalidArgumentException('Сначала откройте предварительный просмотр');
                $changed = 0;
                $this->accessStore($scope)->change(static function (&$state) use ($pending, &$changed) {
                    $changed = AccessBatch::apply($state['users'], $pending['preview'], time());
                    return $changed > 0;
                });
                $this->update($this->input['chat'], $this->input['message_id'], 'Изменено пользователей: ' . $changed
                    . '. Пропущено: ' . (count($pending['preview']['rows']) - $changed) . '.', [
                    [['text' => $this->i18n('back'), 'callback_data' => $this->accessBack($scope)]],
                ]);
                return;
            }
            if (in_array($action, ['extend', 'quota'], true)) {
                if (!$pending['selected']) throw new InvalidArgumentException('Сначала выберите пользователей');
                $this->accessBatchSession($token, static function (&$s) { unset($s['preview'], $s['confirm']); });
                $prompt = $action === 'extend' ? 'На сколько дней продлить срок? 1–3660. Доступы без срока будут пропущены.'
                    : 'Общая квота каждого выбранного доступа в ГиБ, например 10 или 0.5. Значение 0 снимает лимит. Расход сохраняется.';
                $r = $this->send($this->input['chat'], $prompt, $this->input['message_id'], reply: 'Введите значение');
                $this->stashReply($r, ['start_message' => $this->input['message_id'], 'callback' => 'accessBatchReply', 'args' => [$token, $action]]);
                return;
            }
            if (in_array($action, ['reset', 'disable'], true)) { $this->accessBatchReply('', $token, $action); return; }
            $users = $this->accessStore($scope)->read()['users'];
            if ($action === 'pick') {
                if (!isset($users[$arg])) throw new InvalidArgumentException('Пользователь удалён');
                $pending = $this->accessBatchSession($token, static function (&$s) use ($arg) {
                    $index = array_search($arg, $s['selected'], true);
                    if ($index !== false) array_splice($s['selected'], $index, 1);
                    elseif (count($s['selected']) < 20) $s['selected'][] = $arg;
                    else throw new InvalidArgumentException('За один раз можно выбрать до 20 пользователей');
                    unset($s['preview'], $s['confirm']);
                });
            } elseif ($action === 'page') {
                $pending = $this->accessBatchSession($token, static function (&$s) use ($arg) { $s['page'] = max(0, (int) $arg); });
            } elseif ($action !== 'show') throw new InvalidArgumentException('Неизвестное действие');
            $page = min($pending['page'], max(0, (int) ceil(count($users) / 8) - 1)); $buttons = [];
            foreach (array_slice($users, $page * 8, 8, true) as $id => $user) {
                $buttons[] = [['text' => (in_array((string) $id, $pending['selected'], true) ? '☑ ' : '☐ ') . mb_substr($user['name'], 0, 40),
                    'callback_data' => "/ab $token pick $id"]];
            }
            if (count($users) > 8) $buttons[] = [
                ['text' => '←', 'callback_data' => "/ab $token page " . max(0, $page - 1)],
                ['text' => '→', 'callback_data' => "/ab $token page " . ($page + 1)],
            ];
            $buttons[] = [['text' => 'Продлить срок', 'callback_data' => "/ab $token extend"], ['text' => 'Изменить квоту', 'callback_data' => "/ab $token quota"]];
            $buttons[] = [['text' => 'Отключить', 'callback_data' => "/ab $token disable"], ['text' => 'Сбросить расход', 'callback_data' => "/ab $token reset"]];
            $buttons[] = [['text' => 'Отмена', 'callback_data' => "/ab $token cancel"]];
            $this->update($this->input['chat'], $this->input['message_id'], 'Групповые действия · выбрано: ' . count($pending['selected'])
                . " из 20.\nИзменения будут показаны перед применением. Связанные доступы VLESS управляются общей карточкой и будут пропущены.", $buttons);
        } catch (RuntimeException | InvalidArgumentException $e) { $this->protocolError($e->getMessage(), $this->accessBack($scope)); }
    }

    public function accessBatchReply(string $text, string $token, string $action): void
    {
        if (!$this->admin) return;
        $scope = 'hy';
        try {
            $pending = $this->accessBatchSession($token); $scope = $pending['scope'];
            $preview = AccessBatch::preview($this->accessStore($scope)->read()['users'], $pending['selected'], $action, AccessBatch::value($action, trim($text)), time());
            $confirmation = bin2hex(random_bytes(6));
            $this->accessBatchSession($token, static function (&$s) use ($preview, $confirmation) { $s['preview'] = $preview; $s['confirm'] = $confirmation; });
            $text = ['Предварительный просмотр', 'Изменится только выбранный доступ. Ручное отключение сохраняется при продлении и сбросе расхода.'];
            foreach ($preview['rows'] as $row) {
                $change = $row['skip'] !== '' ? 'пропуск: ' . $row['skip'] : match ($action) {
                    'extend' => 'срок → ' . gmdate('Y-m-d H:i', $row['after']['expires']) . ' UTC',
                    'quota' => 'квота → ' . ($row['after']['quota'] === null ? 'без ограничения' : $this->getBytes($row['after']['quota'])),
                    'disable' => 'доступ → выключен',
                    'reset' => 'расход → 0',
                };
                $text[] = self::esc(mb_substr($row['name'], 0, 40) . ': ' . $change);
            }
            $buttons = [];
            if (array_filter($preview['rows'], static fn($r) => $r['skip'] === '')) $buttons[] = [['text' => 'Применить изменения', 'callback_data' => "/ab $token apply $confirmation"]];
            $buttons[] = [['text' => 'Вернуться к выбору', 'callback_data' => "/ab $token show"], ['text' => 'Отмена', 'callback_data' => "/ab $token cancel"]];
            $this->update($this->input['chat'], $this->input['message_id'], implode("\n\n", $text), $buttons);
        } catch (RuntimeException | InvalidArgumentException $e) { $this->protocolError($e->getMessage(), $this->accessBack($scope)); }
    }
}
