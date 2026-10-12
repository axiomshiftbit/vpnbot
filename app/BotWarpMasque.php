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
        $this->withLock('pac', function () use ($mode, $h2) {
            $p = $this->getPacConf();
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
            if (!$this->setPacConf($p)) {
                throw new RuntimeException('Не удалось сохранить настройки WARP');
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
                    fn() => $this->warpCommand('sh /warp_masque.sh check ' . ($h2 ? 'h2' : 'h3')))) {
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
                fn() => $this->warpCommand('sh /warp_masque.sh check ' . ($h2 ? 'h2' : 'h3')))) {
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

    // Сведения об устройстве MASQUE для меню; секретов скрипт не отдаёт.
    public function warpMasqueStatus(): array
    {
        $status = json_decode((string) $this->ssh('[ -f /warp_masque.sh ] && sh /warp_masque.sh status 2>/dev/null', 'wp'), true);
        return is_array($status) ? $status : [];
    }
}
