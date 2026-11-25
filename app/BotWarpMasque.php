<?php

// WARP через MASQUE — второй режим контейнера wp рядом с WireGuard.
//
// Остальному боту режим безразличен: Xray и протоколы с выходом через WARP
// ходят в тот же SOCKS на wp:1080, списки маршрутизации «warp» и личные
// WireGuard-профили клиентов в шаблонах не меняются. Отличается только то, чем
// контейнер держит туннель до Cloudflare: интерфейсом WireGuard или самим
// прокси по HTTP/3 (HTTP/2) на порт 443. Устройство режима и защита от утечки
// описаны в scripts/warp_masque.sh и scripts/start_wp.sh.
//
// Бот здесь только меняет флаги в pac.json (warp_mode, warp_masque_h2) и будит
// сторож контейнера; переключает режим сторож. Перед переходом на MASQUE идёт
// пробное подключение, не затрагивающее работающий режим: если MASQUE с этого
// сервера недоступен, ничего не меняется.
trait BotWarpMasque
{
    public function warpMode(?array $p = null): string
    {
        return (($p ?? $this->getPacConf())['warp_mode'] ?? '') === 'masque' ? 'masque' : 'wireguard';
    }

    public function warpMasqueH2(?array $p = null): bool
    {
        return !empty(($p ?? $this->getPacConf())['warp_masque_h2']);
    }

    // Отметка, которую сторож пишет в /run/warp-mode, запустив прокси.
    public static function warpModeMark(string $mode, bool $h2): string
    {
        return $mode === 'masque' ? 'masque ' . ($h2 ? 'h2' : 'h3') : 'wireguard';
    }

    public function warpModeName(string $mode, bool $h2): string
    {
        return $mode === 'masque' ? 'MASQUE (' . ($h2 ? 'HTTP/2' : 'HTTP/3') . ')' : 'WireGuard';
    }

    // Пауза между опросами сторожа; в тестах подменяется.
    protected function warpPause(int $seconds): void
    {
        sleep($seconds);
    }

    // Дождаться, пока сторож запустит прокси в нужном режиме. Для WireGuard
    // отметка ставится только после настоящего рукопожатия. В MASQUE туннель
    // устанавливается при первом запросе, поэтому там нужен ещё и ответ пробы.
    public function warpAwait(string $mode, bool $h2, int $attempts = 30): bool
    {
        $ready = '[ "$(cat /run/warp-mode 2>/dev/null)" = ' . escapeshellarg(self::warpModeMark($mode, $h2)) . ' ]'
            . ($mode === 'masque' ? ' && sh /warp_probe.sh' : '');
        for ($attempt = 0; $attempt < $attempts; $attempt++) {
            if ($this->warpCommand($ready)) {
                return true;
            }
            $this->warpPause(2);
        }
        return false;
    }

    // Пусто — режим доступен; иначе готовый текст причины.
    public function warpMasqueSupported(): string
    {
        $out = trim((string) $this->ssh(
            'if [ -f /warp_masque.sh ]; then sh /warp_masque.sh supported 2>/dev/null; else echo missing:script; fi',
            'wp'
        ));
        if ($this->sshFailed || $out === '') {
            return $this->i18n('warp masque no container');
        }
        if ($out === 'ok') {
            return '';
        }
        if (str_starts_with($out, 'core:')) {
            return $this->i18n('warp masque old core') . ' <code>' . htmlspecialchars(substr($out, 5), ENT_QUOTES) . '</code>';
        }
        return $this->i18n('warp masque old image');
    }

    // Ключ WARP+ для скрипта режима. null — в настройках лежит не ключ.
    private static function warpLicenseEnv(string $key): ?string
    {
        return preg_match('~^[A-Za-z0-9-]*$~D', $key) ? "WARP_LICENSE_KEY='$key'" : null;
    }

    private function warpSaveMode(string $mode, ?bool $h2 = null): void
    {
        $this->pacConfUpdate(function (&$p) use ($mode, $h2) {
            if ($mode === 'masque') {
                $p['warp_mode'] = 'masque';
            } else {
                unset($p['warp_mode']);
            }
            if ($h2 === true) {
                $p['warp_masque_h2'] = 1;
            } elseif ($h2 === false) {
                unset($p['warp_masque_h2']);
            }
        });
    }

    // Шаг с отображением хода в черновике сообщения, как в addWarpPlus().
    private function warpStep(string &$log, string $label, callable $run): bool
    {
        $chat = $this->input['chat'];
        $log .= "$label...";
        $this->sendDraft($chat, 1, $log);
        $ok = (bool) $run();
        $log .= $ok ? " ok\n" : " failed\n";
        $this->sendDraft($chat, 1, $log);
        return $ok;
    }

    // Кнопка «режим»: WireGuard ↔ MASQUE.
    public function warpSwitchMode()
    {
        $this->withLock('warp-control', function () {
            $chat = $this->input['chat'];
            $p    = $this->getPacConf();
            $off  = !empty($p['warpoff']);
            $from = $this->warpMode($p);
            $to   = $from === 'masque' ? 'wireguard' : 'masque';
            $h2   = $this->warpMasqueH2($p);
            $log  = '';
            if ($to === 'masque') {
                $reason = $this->warpMasqueSupported();
                if ($reason !== '') {
                    $this->send($chat, '❌ ' . $reason);
                    return;
                }
                $license = self::warpLicenseEnv((string) ($p['warp'] ?? ''));
                if ($license === null) {
                    $this->send($chat, $this->i18n('warp key format'));
                    return;
                }
                // Устройство MASQUE заводится один раз и перерегистрируется,
                // только если с тех пор сменили ключ WARP+.
                $registered = false;
                if (!$this->warpCommand("$license sh /warp_masque.sh current")) {
                    if (!$this->warpStep($log, 'registering MASQUE device',
                        fn() => $this->warpCommand("$license WARP_LICENSE_STRICT=1 sh /warp_masque.sh register"))) {
                        $this->send($chat, $log . '❌ ' . $this->i18n('warp masque register failed'));
                        return;
                    }
                    $registered = true;
                }
                if (!$this->warpStep($log, 'checking MASQUE connection',
                    fn() => $this->warpCommand('sh /warp_masque.sh check ' . ($h2 ? 'h2' : 'h3 ' . ($this->warpSelectedPort(['warp_mode' => 'masque'] + $p) ?? 443))))) {
                    if ($registered) {
                        $this->warpCommand('sh /warp_masque.sh rollback');
                    }
                    $this->send($chat, $log . '❌ ' . $this->i18n('warp masque unreachable'));
                    return;
                }
                // Проба прошла — устройство подтверждено, в том числе оставшееся
                // неподтверждённым от прошлой оборванной попытки: иначе отметка
                // жила бы дальше, и чужой откат убрал бы рабочее устройство.
                $this->warpCommand('sh /warp_masque.sh commit');
            }
            $this->warpSaveMode($to);
            $this->warpKick();
            // Выключенный WARP переключается только флагом: проверять нечего.
            if (!$off && !$this->warpStep($log, 'switching to ' . $this->warpModeName($to, $h2),
                fn() => $this->warpAwait($to, $h2))) {
                $this->warpSaveMode($from);
                $this->warpKick();
                $this->send($chat, $log . '❌ ' . $this->i18n('warp mode reverted'));
                return;
            }
            $this->send($chat, $log . '✅ ' . $this->i18n('warp mode switched') . ' ' . $this->warpModeName($to, $h2));
        });
        $this->warp();
    }

    // Кнопка транспорта MASQUE: HTTP/3 (UDP 443) ↔ HTTP/2 (TCP 443).
    public function warpMasqueHttp()
    {
        $this->withLock('warp-control', function () {
            $chat = $this->input['chat'];
            $p    = $this->getPacConf();
            if ($this->warpMode($p) !== 'masque') {
                return;
            }
            $off = !empty($p['warpoff']);
            $was = $this->warpMasqueH2($p);
            $h2  = !$was;
            $log = '';
            if (!$this->warpStep($log, 'checking MASQUE over ' . ($h2 ? 'HTTP/2' : 'HTTP/3'),
                fn() => $this->warpCommand('sh /warp_masque.sh check ' . ($h2 ? 'h2' : 'h3 ' . ($this->warpSelectedPort(['warp_masque_h2' => 0] + $p) ?? 443))))) {
                $this->send($chat, $log . '❌ ' . $this->i18n('warp masque transport unreachable'));
                return;
            }
            $this->warpSaveMode('masque', $h2);
            $this->warpKick();
            if (!$off && !$this->warpStep($log, 'switching to ' . $this->warpModeName('masque', $h2),
                fn() => $this->warpAwait('masque', $h2))) {
                $this->warpSaveMode('masque', $was);
                $this->warpKick();
                $this->send($chat, $log . '❌ ' . $this->i18n('warp mode reverted'));
                return;
            }
            $this->send($chat, $log . '✅ ' . $this->i18n('warp mode switched') . ' ' . $this->warpModeName('masque', $h2));
        });
        $this->warp();
    }

    /** Cloudflare's published WARP ingress ports: the default first. MASQUE over HTTP/2: TCP 443 only. */
    public const WARP_PORTS = ['wireguard' => [2408, 500, 1701, 4500], 'masque' => [443, 500, 1701, 4500, 4443, 8443, 8095]];

    private static function warpPortKey(string $mode): string
    {
        return $mode === 'masque' ? 'warp_masque_port' : 'warp_port';
    }

    /** The port the admin chose for the current mode; null: automatic (WireGuard) or the default. */
    public function warpSelectedPort(?array $p = null): ?int
    {
        $p ??= $this->getPacConf();
        $mode = $this->warpMode($p);
        if ($mode === 'masque' && $this->warpMasqueH2($p)) return null;
        $port = $p[self::warpPortKey($mode)] ?? null;
        return in_array($port, self::WARP_PORTS[$mode] ?? [], true) ? $port : null;
    }

    private function warpPortLine(array $p): string
    {
        $mode = $this->warpMode($p);
        $selected = $this->warpSelectedPort($p);
        $h2 = $mode === 'masque' && $this->warpMasqueH2($p);
        if ($mode === 'masque') {
            return $this->t('Порт: ', 'Port: ') . '<code>' . ($h2 ? 'TCP 443' : 'UDP ' . ($selected ?? 443)) . '</code>'
                . ($selected === null && !$h2 ? $this->t(' (по умолчанию)', ' (default)') : '');
        }
        preg_match('~^Endpoint\s*=\s*.+:(\d+)\s*$~m', (string) @file_get_contents('/etc/warp/wgcf-profile.conf'), $m);
        return $this->t('Порт: ', 'Port: ') . ($selected === null
            ? $this->t('авто (2408 → 500 → 1701 → 4500)', 'auto (2408 → 500 → 1701 → 4500)') : '<code>UDP ' . $selected . '</code>')
            . (isset($m[1]) ? $this->t(' · сейчас ', ' · now ') . '<code>' . (int) $m[1] . '</code>' : '');
    }

    public function warpPorts(): void
    {
        $p = $this->getPacConf();
        $mode = $this->warpMode($p);
        $selected = $this->warpSelectedPort($p);
        $text = ['Menu -> ' . $this->i18n('warp') . ' -> ' . $this->t('Порт', 'Port'),
            $this->t('Официальные порты Cloudflare WARP. Если хостер режет порт, выберите другой; при отказе бот вернёт прежний.',
                'Official Cloudflare WARP ports. If the host blocks a port, choose another; the bot restores the previous one if it fails.')];
        if ($mode === 'masque' && $this->warpMasqueH2($p)) {
            $text[] = $this->t('MASQUE по HTTP/2 работает только через TCP 443. Порт выбирается для HTTP/3.', 'MASQUE over HTTP/2 uses TCP 443 only. Ports apply to HTTP/3.');
            $buttons = [];
        } else {
            $buttons = [['text' => ($selected === null ? '✓ ' : '') . ($mode === 'masque' ? $this->t('По умолчанию (443)', 'Default (443)') : $this->t('Авто', 'Auto')),
                'callback_data' => '/warpPort auto']];
            foreach (self::WARP_PORTS[$mode] as $port) $buttons[] = ['text' => ($selected === $port ? '✓ ' : '') . $port, 'callback_data' => "/warpPort $port"];
        }
        $data = array_chunk($buttons, 3);
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => '/warp']];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $text), $data);
    }

    /** Save the port, bring the link up on it; on failure restore the previous port. */
    public function warpPort(string $choice): void
    {
        $this->withLock('warp-control', function () use ($choice) {
            $chat = $this->input['chat'];
            $p = $this->getPacConf();
            $mode = $this->warpMode($p);
            $h2 = $this->warpMasqueH2($p);
            if ($mode === 'masque' && $h2) return;
            $port = $choice === 'auto' ? null : (int) $choice;
            if ($port !== null && !in_array($port, self::WARP_PORTS[$mode], true)) return;
            $key = self::warpPortKey($mode);
            $before = $p[$key] ?? null;
            $save = function (?int $value) use ($key) {
                $this->pacConfUpdate(function (&$p) use ($key, $value) {
                    if ($value === null) unset($p[$key]);
                    else $p[$key] = $value;
                });
            };
            $off = !empty($p['warpoff']);
            $log = '';
            $label = $port === null ? ($mode === 'masque' ? '443' : 'auto') : (string) $port;
            if ($mode === 'masque') {
                if (!$off && !$this->warpStep($log, "checking MASQUE on port $label",
                    fn() => $this->warpCommand('sh /warp_masque.sh check h3 ' . ($port ?? 443)))) {
                    $this->send($chat, $log . '❌ ' . $this->t('Узел WARP не ответил на этом порту; порт не изменён.', 'The WARP endpoint did not answer on this port; the port is unchanged.'));
                    return;
                }
                $save($port);
                // The watchdog rebuilds the proxy for the new port; wait for its fresh mark.
                $this->warpCommand('rm -f /run/warp-mode');
                $this->warpKick();
                if (!$off && !$this->warpStep($log, 'switching to port ' . $label, fn() => $this->warpAwait('masque', false))) {
                    $save(is_int($before) ? $before : null);
                    $this->warpCommand('rm -f /run/warp-mode');
                    $this->warpKick();
                    $this->send($chat, $log . '❌ ' . $this->i18n('warp mode reverted'));
                    return;
                }
            } else {
                $save($port);
                if (!$off && !$this->warpStep($log, 'bringing WARP up on port ' . $label, fn() => $this->warpCommand(self::WARP_STOP . '; ' . self::WARP_UP))) {
                    $save(is_int($before) ? $before : null);
                    $this->warpCommand(self::WARP_UP);
                    $this->warpKick();
                    $this->send($chat, $log . '❌ ' . $this->t('Рукопожатия на этом порту нет; возвращён прежний порт.', 'No handshake on this port; the previous port is restored.'));
                    return;
                }
                $this->warpKick();
            }
            $this->send($chat, $log . '✅ ' . $this->t('Порт WARP: ', 'WARP port: ') . $label);
        });
        $this->warp();
    }

    /** A new WARP account through the key path: backup, rollback and MASQUE device included. */
    public function warpReregister(bool $confirmed): void
    {
        $p = $this->getPacConf();
        $key = (string) ($p['warp'] ?? '');
        if (!$confirmed) {
            $this->update($this->input['chat'], $this->input['message_id'], implode("\n", ['Menu -> ' . $this->i18n('warp'),
                $key !== '' ? $this->t('Зарегистрировать новый аккаунт WARP с сохранённым ключом WARP+? Ключ привяжется к новому устройству. При отказе вернётся прежний аккаунт.',
                    'Register a new WARP account with the saved WARP+ key? The key is bound to a new device. On failure the previous account is restored.')
                    : $this->t('Зарегистрировать новый бесплатный аккаунт WARP? При отказе вернётся прежний аккаунт.',
                    'Register a new free WARP account? On failure the previous account is restored.')]),
                [[['text' => $this->t('🔄 Зарегистрировать', '🔄 Register'), 'callback_data' => '/warpRegYes'], ['text' => $this->i18n('back'), 'callback_data' => '/warp']]]);
            return;
        }
        $this->addWarpPlus($key);
    }

    // Сведения об устройстве MASQUE для меню; секретов скрипт не отдаёт.
    public function warpMasqueStatus(): array
    {
        $status = json_decode((string) $this->ssh('[ -f /warp_masque.sh ] && sh /warp_masque.sh status 2>/dev/null', 'wp'), true);
        return is_array($status) ? $status : [];
    }
}
