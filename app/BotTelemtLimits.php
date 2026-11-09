<?php

trait BotTelemtLimits
{
    // Периодический сброс квоты ([access.user_quota_periods], telemt 3.5.15+):
    // по UTC — полночь, понедельник, первое число месяца. Ядро требует
    // положительную квоту, поэтому период без квоты в конфиг не попадает.
    public const TELEMT_QUOTA_PERIODS = ['daily', 'weekly', 'monthly'];
    public const TELEMT_QUOTA_PERIOD_MIN = '3.5.15';
    // Запрет подсетей источника ([access.user_source_deny], telemt 3.5.17+):
    // ядро отклоняет подключение после проверки секрета, как неверный секрет.
    // Строгий разбор ключей старого ядра отверг бы таблицу целиком.
    public const TELEMT_SOURCE_DENY_MIN = '3.5.17';
    public const TELEMT_SOURCE_DENY_MAX = 32;

    /** Канонический CIDR: адрес без хостовых битов; одиночный адрес — /32 или /128. */
    public static function telemtCidr(string $text): ?string
    {
        if (!preg_match('~^([0-9A-Fa-f:.]+)(?:/(\d{1,3}))?$~D', $text, $m)) return null;
        $packed = @inet_pton($m[1]);
        if ($packed === false) return null;
        $bits = strlen($packed) * 8;
        $prefix = isset($m[2]) ? (int) $m[2] : $bits;
        if ($prefix < 1 || $prefix > $bits || strlen($packed) === 16 && str_contains($m[1], '.')) return null;
        for ($i = 0; $i < strlen($packed); $i++) {
            $keep = max(0, min(8, $prefix - 8 * $i));
            $packed[$i] = chr(ord($packed[$i]) & (0xff << (8 - $keep)) & 0xff);
        }
        return inet_ntop($packed) . '/' . $prefix;
    }

    public function telemtParseDeny(string $text): array
    {
        $text = trim($text);
        if ($text === '-') return [];
        $result = [];
        foreach (preg_split('~[\s,]+~', $text, -1, PREG_SPLIT_NO_EMPTY) as $item) {
            $net = self::telemtCidr($item);
            if ($net === null) throw new RuntimeException($this->i18n('telemt limits input deny'));
            $result[$net] = true;
        }
        if (!$result || count($result) > self::TELEMT_SOURCE_DENY_MAX) throw new RuntimeException($this->i18n('telemt limits input deny'));
        return array_keys($result);
    }

    public function telemtLimitsOf(array $conf): array
    {
        $limits = $conf['telemt_user_limits'] ?? [];
        if (!is_array($limits)) throw new RuntimeException($this->i18n('telemt limits invalid'));
        $result = [];
        foreach ($limits as $name => $row) {
            if (!isset($conf['telemt_users'][$name])) continue;
            if (!is_array($row)) throw new RuntimeException($this->i18n('telemt limits invalid'));
            foreach (['quota' => 1073741824000000, 'ips' => 1000] as $field => $max) {
                $value = $row[$field] ?? 0;
                if (!is_int($value) || $value < 0 || $value > $max) throw new RuntimeException($this->i18n('telemt limits invalid'));
                if ($value > 0) $result[$name][$field] = $value;
            }
            $deny = $row['deny'] ?? [];
            if (!is_array($deny) || !array_is_list($deny) || count($deny) > self::TELEMT_SOURCE_DENY_MAX
                || count(array_unique($deny, SORT_REGULAR)) !== count($deny)) throw new RuntimeException($this->i18n('telemt limits invalid'));
            foreach ($deny as $net) {
                if (!is_string($net) || self::telemtCidr($net) !== $net) throw new RuntimeException($this->i18n('telemt limits invalid'));
            }
            if ($deny) $result[$name]['deny'] = $deny;
            $period = $row['period'] ?? null;
            if ($period !== null && !in_array($period, self::TELEMT_QUOTA_PERIODS, true)) throw new RuntimeException($this->i18n('telemt limits invalid'));
            if ($period !== null && !empty($result[$name]['quota'])) $result[$name]['period'] = $period;
        }
        return $result;
    }

    public function telemtParseLimit(string $field, string $text): int
    {
        $text = trim($text);
        if ($field === 'ips' && preg_match('~^\d{1,4}$~D', $text) && (int) $text <= 1000) return (int) $text;
        if ($field === 'quota' && preg_match('~^(\d{1,7})(?:[.,](\d{1,6}))?$~D', $text, $m)) {
            $bytes = (int) $m[1] * 1073741824;
            if (isset($m[2])) $bytes += (int) round((int) $m[2] * 1073741824 / (10 ** strlen($m[2])));
            if ($bytes <= 1073741824000000) return $bytes;
        }
        throw new RuntimeException($this->i18n('telemt limits input ' . ($field === 'ips' ? 'ips' : 'quota')));
    }

    // Вызывается под общей блокировкой telemt. API остаётся только для чтения.
    public function telemtStateRun(string $action, string $name = '', bool $required = true): void
    {
        if (!in_array($action, ['version', 'prepare', 'ready', 'checkpoint', 'stop', 'reset'], true)) throw new LogicException('TeleMT state action');
        $command = 'python3 /telemt_state.py ' . $action;
        if ($action === 'reset') $command .= ' ' . escapeshellarg(base64_encode($name));
        $command .= ' 2>>/logs/telemt';
        if (!$required) {
            $command = 'if command -v python3 >/dev/null && [ -f /telemt_state.py ]; then ' . $command
                . '; else printf "TELEMT_STATE_OK\\n"; fi';
        }
        $out = $this->ssh($command, 'telemt');
        if ($this->sshFailed || trim((string) $out) !== 'TELEMT_STATE_OK') {
            throw new RuntimeException($this->i18n($action === 'version' ? 'telemt limits need image' : 'telemt limits state error'));
        }
    }

    public function telemtStop(): void
    {
        $out = $this->ssh(<<<'SH'
            if command -v python3 >/dev/null && [ -f /telemt_state.py ]; then
                python3 /telemt_state.py stop 2>>/logs/telemt
            else
                pkill -TERM -x telemt 2>/dev/null || true
                i=0; while pgrep -x telemt >/dev/null && [ "$i" -lt 150 ]; do sleep 0.2; i=$((i+1)); done
                if ! pgrep -x telemt >/dev/null; then printf 'TELEMT_STATE_OK\n'; fi
            fi
            SH, 'telemt');
        if ($this->sshFailed || trim((string) $out) !== 'TELEMT_STATE_OK') throw new RuntimeException($this->i18n('telemt limits stop error'));
    }

    public function telemtQuotaPath(): string { return '/config/telemt/data/telemt.limit.json'; }

    public function telemtValidateQuotaState($state, array $conf): array
    {
        if (!is_array($state) || !is_int($state['last_reset_epoch_secs'] ?? null) || $state['last_reset_epoch_secs'] < 0
            || !is_array($state['users'] ?? null) || count($state['users']) > 65536) {
            throw new RuntimeException($this->i18n('telemt limits state error'));
        }
        foreach ($state['users'] as $row) {
            if (!is_array($row) || !is_int($row['used_bytes'] ?? null) || $row['used_bytes'] < 0
                || !is_int($row['last_reset_epoch_secs'] ?? null) || $row['last_reset_epoch_secs'] < 0
                // Календарь TeleMT 3.5.15+ в той же записи: ядро с периодами не
                // запускается на неверном состоянии, поэтому ловим это заранее.
                || (array_key_exists('quota_period', $row) && !in_array($row['quota_period'], self::TELEMT_QUOTA_PERIODS, true))
                || !is_int($row['period_cursor_epoch_secs'] ?? 0) || ($row['period_cursor_epoch_secs'] ?? 0) < 0) {
                throw new RuntimeException($this->i18n('telemt limits state error'));
            }
        }
        foreach ($this->telemtLimitsOf($conf) as $name => $limits) {
            if (!empty($limits['quota']) && !isset($state['users'][$name])) throw new RuntimeException($this->i18n('telemt limits state error'));
        }
        return $state;
    }

    public function telemtQuotaRead(array $conf): array
    {
        $path = $this->telemtQuotaPath();
        if (is_link($path) || (is_file($path) && filesize($path) > 16 * 1024 * 1024)) throw new RuntimeException($this->i18n('telemt limits state error'));
        $state = is_file($path) ? json_decode(file_get_contents($path), true) : ['last_reset_epoch_secs' => 0, 'users' => []];
        $state = $this->telemtValidateQuotaState($state, $conf);
        // Помощник не перезаписывает файл работающего ядра: его календарные
        // сбросы не используют flock бота. Для меню и backup объединяем расход.
        $checkpoint = dirname($path) . '/telemt.checkpoint.json';
        if (is_link($checkpoint) || (is_file($checkpoint) && filesize($checkpoint) > 16 * 1024 * 1024)) throw new RuntimeException($this->i18n('telemt limits state error'));
        if (is_file($checkpoint)) {
            $saved = $this->telemtValidateQuotaState(json_decode(file_get_contents($checkpoint), true), []);
            foreach ($state['users'] as $name => &$row) {
                $extra = $saved['users'][$name] ?? null;
                if ($extra === null) continue;
                if ($extra['last_reset_epoch_secs'] > $row['last_reset_epoch_secs']) $row = $extra;
                elseif ($extra['last_reset_epoch_secs'] === $row['last_reset_epoch_secs']) $row['used_bytes'] = max($row['used_bytes'], $extra['used_bytes']);
                $state['last_reset_epoch_secs'] = max($state['last_reset_epoch_secs'], $row['last_reset_epoch_secs']);
            }
            unset($row);
        }
        return $this->telemtValidateQuotaState($state, $conf);
    }

    public function telemtQuotaWrite(array $state): void
    {
        $state = $this->telemtValidateQuotaState($state, []);
        $state['users'] = (object) $state['users'];
        $payload = json_encode($state, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR) . "\n";
        if (strlen($payload) > 16 * 1024 * 1024) throw new RuntimeException($this->i18n('telemt limits state error'));
        @mkdir(dirname($this->telemtQuotaPath()), 0755, true);
        if (!$this->writePrivateKey($this->telemtQuotaPath(), $payload)) {
            throw new RuntimeException($this->i18n('telemt limits state error'));
        }
        $checkpoint = dirname($this->telemtQuotaPath()) . '/telemt.checkpoint.json';
        if ((is_file($checkpoint) || is_link($checkpoint)) && !unlink($checkpoint)) {
            throw new RuntimeException($this->i18n('telemt limits state error'));
        }
    }

    public function telemtBackupSnapshot(): array
    {
        return $this->withLock('telemt', function () {
            $conf = $this->getPacConf();
            // При выключенном сервисе последний штатный SIGTERM уже сохранил расход.
            if ($this->protocolModuleEnabled('telemt') && $this->telemtLimitsOf($conf)) {
                $this->telemtStateRun('checkpoint');
            }
            return ['pac' => $conf, 'telemt_quota' => $this->telemtQuotaRead($conf)];
        });
    }

    public function telemtQuotaRestore(?array $state, array $conf): void
    {
        $this->withLock('telemt', function () use ($state, $conf) {
            if ($state !== null) $this->telemtValidateQuotaState($state, $conf);
            if ($this->protocolModuleEnabled('telemt')) {
                $this->telemtWriteServiceState(false);
                $this->telemtStop();
            }
            if ($state !== null) $this->telemtQuotaWrite($state);
            $this->telemtSave(static function (&$current) use ($conf) { $current = $conf; });
            $this->applyTelemt();
        });
    }

    public function telemtChangeLimit(string $name, string $field, int|string|array $value, string $fingerprint): void
    {
        if (!$this->admin) return;
        $this->withLock('telemt', function () use ($name, $field, $value, $fingerprint) {
            if (!in_array($field, ['quota', 'ips', 'reset', 'period', 'deny'], true)) throw new LogicException('TeleMT limit field');
            if (($field === 'period') !== is_string($value) || ($field === 'period' && !in_array($value, ['', ...self::TELEMT_QUOTA_PERIODS], true))
                || ($field === 'deny') !== is_array($value)) {
                throw new LogicException('TeleMT limit value');
            }
            $conf = $this->getPacConf();
            if (!isset($conf['telemt_users'][$name]) || !hash_equals($fingerprint, hash('sha256', $conf['telemt_users'][$name]))) {
                throw new RuntimeException($this->i18n('telemt limits stale'));
            }
            if (!$this->protocolModuleEnabled('telemt')) throw new RuntimeException($this->i18n('telemt limits service off'));
            $old = $conf['telemt_user_limits'][$name] ?? [];
            if ($field === 'period') {
                if (($old['period'] ?? '') === $value) return;
                if ($value !== '' && empty($old['quota'])) throw new RuntimeException($this->i18n('telemt limits period needs quota'));
                if ($value !== '' && !$this->telemtVersionAtLeast(self::TELEMT_QUOTA_PERIOD_MIN)) throw new RuntimeException($this->i18n('telemt limits period need core'));
            } elseif ($field === 'deny') {
                if (($old['deny'] ?? []) === $value) return;
                if ($value && !$this->telemtVersionAtLeast(self::TELEMT_SOURCE_DENY_MIN)) throw new RuntimeException($this->i18n('telemt limits deny need core'));
            } elseif ($field !== 'reset' && ($old[$field] ?? 0) === $value) return;
            $this->telemtStateRun('version');
            $new = $old;
            if ($field === 'period' && $value === '' || $field === 'deny' && $value === []) unset($new[$field]);
            elseif ($field !== 'reset') $new[$field] = $value;
            $candidate = $conf; $candidate['telemt_user_limits'][$name] = $new;
            $this->telemtLimitsOf($candidate); // Запрещаем обход валидации через прямой вызов.
            $reset = $field === 'reset' || ($field === 'quota' && $value > 0 && empty($old['quota']));
            $this->telemtSave(static function (&$c) use ($name, $new) { $c['telemt_user_limits'][$name] = $new; });
            try {
                $this->applyTelemt($reset ? $name : null);
            } catch (Throwable $error) {
                $this->telemtSave(static function (&$c) use ($name, $old) {
                    if ($old) $c['telemt_user_limits'][$name] = $old;
                    else unset($c['telemt_user_limits'][$name]);
                });
                try { $this->applyTelemt(); } catch (Throwable $ignored) { /* Флаг запуска остаётся закрытым. */ }
                throw $error;
            }
        });
    }

    public function telemtLimitPrompt(string $name, int $page, string $relay, string $field): void
    {
        $conf = $this->getPacConf();
        if (!isset($conf['telemt_users'][$name]) || !in_array($field, ['quota', 'ips', 'deny'], true)) return;
        $hint = $this->i18n('telemt limits input ' . $field) . "\n" . $this->i18n('telemt limits apply note');
        $r = $this->send($this->input['chat'], $hint, $this->input['message_id'], reply: $this->i18n('telemt limits ' . $field));
        $this->stashReply($r, ['start_message' => $this->input['message_id'], 'callback' => 'telemtLimitReply',
            'args' => [$name, $page, $relay, $field, hash('sha256', $conf['telemt_users'][$name])]]);
    }

    public function telemtLimitReply($text, string $name, int $page, string $relay, string $field, string $fingerprint): void
    {
        try {
            $value = $field === 'deny' ? $this->telemtParseDeny((string) $text) : $this->telemtParseLimit($field, (string) $text);
            $this->telemtChangeLimit($name, $field, $value, $fingerprint);
            $message = $this->i18n('telemt limits saved');
        } catch (Throwable $error) { $message = '❌ ' . $error->getMessage(); }
        $this->telemtUserLimits($name, $page, $relay, $message);
    }

    public function telemtResetQuota(string $name, int $page, string $relay, string $key = ''): void
    {
        $secret = $this->getPacConf()['telemt_users'][$name] ?? '';
        if ($secret === '') return;
        $fingerprint = hash('sha256', $secret);
        if ($key !== '') {
            try {
                if (!hash_equals(substr($fingerprint, 0, 8), $key)) throw new RuntimeException($this->i18n('telemt limits stale'));
                $this->telemtChangeLimit($name, 'reset', 0, $fingerprint);
                $message = $this->i18n('telemt limits saved');
            } catch (Throwable $error) { $message = '❌ ' . $error->getMessage(); }
            $this->telemtUserLimits($name, $page, $relay, $message);
            return;
        }
        $this->update($this->input['chat'], $this->input['message_id'], '<b>' . self::esc($name) . "</b>\n\n" . $this->i18n('telemt limits reset confirm'), [
            [['text' => $this->i18n('telemt limits reset'), 'callback_data' => $this->telemtUserCallback($name, $page, $relay, 'qreset-' . substr($fingerprint, 0, 8))]],
            [['text' => $this->i18n('back'), 'callback_data' => $this->telemtUserCallback($name, $page, $relay, 'limits')]],
        ]);
    }

    // Выбор периода: отпечаток секрета в кнопке не даёт устаревшему сообщению
    // поменять период пересозданному под тем же именем пользователю.
    public function telemtQuotaPeriod(string $name, int $page, string $relay, string $choice = '', string $key = ''): void
    {
        $conf = $this->getPacConf();
        $secret = $conf['telemt_users'][$name] ?? '';
        if ($secret === '') { $this->telemtUsers($relay, $page); return; }
        $fingerprint = hash('sha256', $secret);
        if ($choice !== '') {
            try {
                if (!hash_equals(substr($fingerprint, 0, 8), $key)) throw new RuntimeException($this->i18n('telemt limits stale'));
                $this->telemtChangeLimit($name, 'period', $choice === 'off' ? '' : $choice, $fingerprint);
                $message = $this->i18n('telemt limits saved');
            } catch (Throwable $error) { $message = '❌ ' . $error->getMessage(); }
            $this->telemtUserLimits($name, $page, $relay, $message);
            return;
        }
        $current = $this->telemtLimitsOf($conf)[$name]['period'] ?? 'off';
        $data = [];
        foreach (['off', ...self::TELEMT_QUOTA_PERIODS] as $option) {
            $label = $option === 'off' ? $this->i18n('off') : $this->i18n('telemt limits period ' . $option);
            $data[] = [['text' => ($option === $current ? '✅ ' : '') . $label,
                'callback_data' => $this->telemtUserCallback($name, $page, $relay, 'period-' . $option . '-' . substr($fingerprint, 0, 8))]];
        }
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => $this->telemtUserCallback($name, $page, $relay, 'limits')]];
        $this->update($this->input['chat'], $this->input['message_id'],
            'TeleMT → <b>' . self::esc($name) . '</b> → ' . $this->i18n('telemt limits period') . "\n\n" . $this->i18n('telemt limits period about'), $data);
    }

    public function telemtUserLimits(string $name, int $page = 0, string $relay = '', string $message = ''): void
    {
        $conf = $this->getPacConf();
        if (!isset($conf['telemt_users'][$name])) { $this->telemtUsers($relay, $page); return; }
        $limits = $this->telemtLimitsOf($conf)[$name] ?? [];
        $quota = $limits['quota'] ?? 0; $ips = $limits['ips'] ?? 0;
        $text = ['TeleMT → <b>' . self::esc($name) . '</b> → ' . $this->i18n('telemt limits')];
        if ($message !== '') $text[] = self::esc($message);
        $text[] = $this->i18n('telemt limits quota') . ': ' . ($quota ? $this->fmtBytes($quota) : $this->i18n('off'));
        $usage = null; $active = null; $live = false;
        if ($quota || $ips) {
            $api = $this->telemtApiFetch(['/v1/stats/users/quota', '/v1/stats/users/active-ips']);
            foreach ($api['/v1/stats/users/quota']['users'] ?? [] as $row) {
                if (($row['username'] ?? null) === $name) { $usage = $row; $live = true; break; }
            }
            if (is_array($api['/v1/stats/users/active-ips'] ?? null)) {
                $active = 0;
                foreach ($api['/v1/stats/users/active-ips'] as $row) if (($row['username'] ?? null) === $name) $active = count($row['active_ips'] ?? []);
            }
        }
        if ($quota) {
            if ($usage === null) {
                try { $usage = $this->telemtQuotaRead($conf)['users'][$name] ?? null; } catch (Throwable $error) {}
            }
            $text[] = $this->i18n('telemt limits used') . ': ' . ($usage === null ? '—' : $this->fmtBytes($usage['used_bytes']))
                . ($live ? '' : ' · ' . $this->i18n('telemt limits snapshot'));
            if (!empty($usage['last_reset_epoch_secs'])) $text[] = $this->i18n('telemt limits since') . ': ' . gmdate('Y-m-d H:i:s', $usage['last_reset_epoch_secs']) . ' UTC';
            if (($usage['used_bytes'] ?? 0) >= $quota) $text[] = $this->i18n('telemt limits exhausted');
            $period = $limits['period'] ?? '';
            $line = $this->i18n('telemt limits period') . ': ' . ($period === '' ? $this->i18n('off') : $this->i18n('telemt limits period ' . $period));
            $state = $live ? (string) ($usage['quota_schedule_state'] ?? '') : '';
            if ($period !== '' && $state === 'active' && is_int($usage['quota_next_reset_epoch_secs'] ?? null)) {
                $line .= ' · ' . $this->i18n('telemt limits period next') . ': ' . gmdate('Y-m-d H:i', $usage['quota_next_reset_epoch_secs']) . ' UTC';
            } elseif ($period !== '' && in_array($state, ['pending', 'overdue', 'error'], true)) {
                $line .= ' · ' . $this->i18n('telemt limits period state ' . $state);
            }
            $text[] = $line;
        }
        $text[] = 'Limit IP: ' . ($ips ?: $this->i18n('off')) . ' · ' . $this->i18n('telemt limits active') . ': ' . ($active ?? '—');
        $deny = $limits['deny'] ?? [];
        $text[] = $this->i18n('telemt limits deny list') . ': ' . ($deny ? "\n<code>" . self::esc(implode("\n", $deny)) . '</code>' : $this->i18n('off'));
        if ($deny && !$this->telemtVersionAtLeast(self::TELEMT_SOURCE_DENY_MIN)) $text[] = '⚠️ ' . $this->i18n('telemt limits deny need core');
        $text[] = $this->i18n('telemt limits apply note');
        $data = [];
        foreach ($quota ? ['quota', 'period', 'ips', 'deny', 'reset'] : ['quota', 'ips', 'deny', 'reset'] as $action) {
            $data[] = [['text' => $this->i18n('telemt limits ' . ($action === 'period' ? 'period button' : $action)), 'callback_data' => $this->telemtUserCallback($name, $page, $relay, $action)]];
        }
        $data[] = [['text' => $this->i18n('refresh'), 'callback_data' => $this->telemtUserCallback($name, $page, $relay, 'limits')]];
        $context = substr(hash('sha256', $name), 0, 12) . '.' . $page . '.' . ($relay === '' ? 'direct' : substr(hash('sha256', $relay), 0, 12));
        $data[] = $this->menuHelpButton('telemt_limits', $context);
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => $this->telemtUserCallback($name, $page, $relay)]];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n\n", $text), $data);
    }
}
