<?php

trait BotTelemtLimits
{
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
                || !is_int($row['last_reset_epoch_secs'] ?? null) || $row['last_reset_epoch_secs'] < 0) {
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

    public function telemtChangeLimit(string $name, string $field, int $value, string $fingerprint): void
    {
        if (!$this->admin) return;
        $this->withLock('telemt', function () use ($name, $field, $value, $fingerprint) {
            if (!in_array($field, ['quota', 'ips', 'reset'], true)) throw new LogicException('TeleMT limit field');
            $conf = $this->getPacConf();
            if (!isset($conf['telemt_users'][$name]) || !hash_equals($fingerprint, hash('sha256', $conf['telemt_users'][$name]))) {
                throw new RuntimeException($this->i18n('telemt limits stale'));
            }
            if (!$this->protocolModuleEnabled('telemt')) throw new RuntimeException($this->i18n('telemt limits service off'));
            $old = $conf['telemt_user_limits'][$name] ?? [];
            if ($field !== 'reset' && ($old[$field] ?? 0) === $value) return;
            $this->telemtStateRun('version');
            $new = $old;
            if ($field !== 'reset') $new[$field] = $value;
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
        if (!isset($conf['telemt_users'][$name]) || !in_array($field, ['quota', 'ips'], true)) return;
        $hint = $this->i18n('telemt limits input ' . $field) . "\n" . $this->i18n('telemt limits apply note');
        $r = $this->send($this->input['chat'], $hint, $this->input['message_id'], reply: $this->i18n('telemt limits ' . $field));
        $this->stashReply($r, ['start_message' => $this->input['message_id'], 'callback' => 'telemtLimitReply',
            'args' => [$name, $page, $relay, $field, hash('sha256', $conf['telemt_users'][$name])]]);
    }

    public function telemtLimitReply($text, string $name, int $page, string $relay, string $field, string $fingerprint): void
    {
        try {
            $this->telemtChangeLimit($name, $field, $this->telemtParseLimit($field, (string) $text), $fingerprint);
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
        }
        $text[] = 'Limit IP: ' . ($ips ?: $this->i18n('off')) . ' · ' . $this->i18n('telemt limits active') . ': ' . ($active ?? '—');
        $text[] = $this->i18n('telemt limits apply note');
        $data = [];
        foreach (['quota', 'ips', 'reset'] as $action) $data[] = [['text' => $this->i18n('telemt limits ' . $action), 'callback_data' => $this->telemtUserCallback($name, $page, $relay, $action)]];
        $data[] = [['text' => $this->i18n('refresh'), 'callback_data' => $this->telemtUserCallback($name, $page, $relay, 'limits')]];
        $context = substr(hash('sha256', $name), 0, 12) . '.' . $page . '.' . ($relay === '' ? 'direct' : substr(hash('sha256', $relay), 0, 12));
        $data[] = $this->menuHelpButton('telemt_limits', $context);
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => $this->telemtUserCallback($name, $page, $relay)]];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n\n", $text), $data);
    }
}
