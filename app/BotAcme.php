<?php

/**
 * Продление Let's Encrypt через службу хоста acme-window (scripts/acme_window.py).
 *
 * Если firewall держит порт 80 закрытым, certbot из бота проверку Let's Encrypt
 * не пройдёт. Тогда бот certbot не запускает, а кладёт запрос в /acme/request;
 * служба хоста открывает порт на несколько минут, вызывает acme_renew.php
 * (issue, затем install) и пишет состояние в /acme/state — у бота этот каталог
 * только для чтения. Без службы «renew SSL» работает как раньше.
 */
trait BotAcme
{
    public string $acmeRoot = '/acme';

    // Служба обновляет agent.json раз в час (таймер со случайной задержкой до
    // 20 мин). Старше трёх часов — считаем, что службы нет.
    public int $acmeAgentTtl = 10800;

    // Запрос, на который служба не ответила за это время, показываем зависшим.
    public int $acmeBusyTtl = 3600;

    // Сколько ждать идущее восстановление из бэкапа перед установкой.
    public int $acmeInstallLockWait = 120;

    public function acmeReadJson(string $file): ?array
    {
        if (!is_file($file) || is_link($file) || filesize($file) > 65536) {
            return null;
        }
        $data = json_decode((string) @file_get_contents($file), true);
        return is_array($data) ? $data : null;
    }

    // null — службы нет или она давно молчит.
    public function acmeAgent(): ?array
    {
        $agent = $this->acmeReadJson("{$this->acmeRoot}/state/agent.json");
        if (!$agent || !is_int($agent['updated'] ?? null) || time() - $agent['updated'] > $this->acmeAgentTtl) {
            return null;
        }
        return $agent;
    }

    public function acmeAgentStale(): bool
    {
        return !$this->acmeAgent() && is_file("{$this->acmeRoot}/state/agent.json");
    }

    // Цели службы: свой сертификат бота (kind vpnbot) первым, затем остальные.
    public function acmeStates(): array
    {
        $states = [];
        foreach (glob("{$this->acmeRoot}/state/*.json") ?: [] as $file) {
            $name = basename($file, '.json');
            if ($name === 'agent' || !preg_match('~^[a-z0-9]{1,32}$~', $name)) {
                continue;
            }
            $s = $this->acmeReadJson($file);
            if (!$s || ($s['name'] ?? '') !== $name) {
                continue;
            }
            foreach (['updated', 'not_after', 'due_at', 'next_attempt', 'last_attempt', 'last_success', 'failures', 'last_rejected'] as $key) {
                $s[$key] = (int) ($s[$key] ?? 0);
            }
            $s['auto']        = (bool) ($s['auto'] ?? false);
            $s['busy']        = !empty($s['busy']) && time() - $s['updated'] < $this->acmeBusyTtl;
            $s['kind']        = (string) ($s['kind'] ?? '');
            $s['last_result'] = (string) ($s['last_result'] ?? '');
            $s['last_detail'] = mb_substr((string) ($s['last_detail'] ?? ''), 0, 300);
            $states[$name] = $s;
        }
        uasort($states, fn ($a, $b) => [$a['kind'] !== 'vpnbot', $a['name']] <=> [$b['kind'] !== 'vpnbot', $b['name']]);
        return $states;
    }

    public function acmeSelfTarget(): ?string
    {
        foreach ($this->acmeStates() as $name => $s) {
            if ($s['kind'] === 'vpnbot') {
                return $name;
            }
        }
        return null;
    }

    // Файл-запрос для службы. Содержимое служба не читает, только имя.
    public function acmeRequest(string $action, string $target = ''): bool
    {
        if (!in_array($action, ['renew', 'auto-on', 'auto-off', 'refresh'], true)) {
            return false;
        }
        if ($action !== 'refresh' && !isset($this->acmeStates()[$target])) {
            return false;
        }
        $file = "{$this->acmeRoot}/request/req-$action" . ($target !== '' ? "-$target" : '');
        if (file_exists($file)) {
            return true;
        }
        return @file_put_contents($file, time() . "\n") !== false;
    }

    // Ждём, пока служба заберёт запрос (обычно секунда-две).
    public function acmeWaitTaken(string $file, float $seconds = 4.0): bool
    {
        $deadline = microtime(true) + $seconds;
        while (file_exists($file)) {
            if (microtime(true) >= $deadline) {
                return false;
            }
            usleep(200000);
        }
        return true;
    }

    public function acmeLabel(array $s): string
    {
        $label = $s['label'] ?? [];
        $text  = is_array($label) ? ($label[$this->language] ?? $label['en'] ?? $s['name']) : (string) $label;
        return htmlspecialchars((string) $text, ENT_QUOTES);
    }

    public function acmeResultText(string $code): string
    {
        return match ($code) {
            ''                => '—',
            'ok'              => '✅ ' . $this->t('сертификат обновлён', 'certificate renewed'),
            'ok_served_old'   => '⚠️ ' . $this->t('сертификат выпущен, но сервер отдаёт прежний', 'certificate issued, but the server still serves the old one'),
            'dry_run_ok'      => '✅ ' . $this->t('пробный выпуск прошёл', 'test issuance passed'),
            'dry_run_fail'    => '❌ ' . $this->t('пробный выпуск не прошёл', 'test issuance failed'),
            'fail_issue'      => '❌ ' . $this->t("Let's Encrypt не выдал сертификат", "Let's Encrypt did not issue the certificate"),
            'fail_install'    => '❌ ' . $this->t('сертификат выпущен, но не установлен', 'certificate issued but not installed'),
            'fail_verify'     => '❌ ' . $this->t('файл сертификата не изменился', 'the certificate file did not change'),
            'fail_dns'        => '❌ ' . $this->t('имя в DNS указывает не на этот сервер', 'a DNS name does not point to this server'),
            'fail_preflight'  => '❌ ' . $this->t('проверка перед выпуском не прошла', 'the pre-issuance check failed'),
            'fail_window'     => '❌ ' . $this->t('порт 80 не открылся или не закрылся вовремя', 'port 80 did not open or close in time'),
            'not_letsencrypt' => $this->t("сертификат не от Let's Encrypt", "not a Let's Encrypt certificate"),
            'rate_limited'    => '⏳ ' . $this->t("отклонено: лимит попыток (Let's Encrypt)", "refused: attempt limit (Let's Encrypt)"),
            default           => htmlspecialchars($code, ENT_QUOTES),
        };
    }

    public function acmeDate(int $time): string
    {
        return $time > 0 ? date('Y-m-d H:i', $time) : '—';
    }

    public function acmeStatusText(array $s): string
    {
        $lines   = ["<b>{$this->acmeLabel($s)}</b>"];
        $left    = $s['not_after'] > 0 ? (int) floor(($s['not_after'] - time()) / 86400) : null;
        $lines[] = $this->t('действует до: ', 'valid until: ') . $this->acmeDate($s['not_after'])
            . (null === $left ? '' : $this->t(" (дней: $left)", " ($left days)"));
        $lines[] = $this->t('автообновление: ', 'auto-renewal: ') . ($s['auto']
            ? $this->t('вкл, следующая попытка ', 'on, next attempt ') . ($s['next_attempt'] > time() ? $this->acmeDate($s['next_attempt']) : $this->t('при ближайшей проверке', 'at the next check'))
            : $this->t('выкл', 'off'));
        if ($s['busy']) {
            $lines[] = '⏳ ' . $this->t('идёт выпуск сертификата', 'issuing a certificate now');
        }
        if ($s['last_attempt'] > 0 || $s['last_result'] !== '') {
            $lines[] = $this->t('последняя попытка: ', 'last attempt: ') . $this->acmeDate($s['last_attempt']) . ' ' . $this->acmeResultText($s['last_result']);
        }
        if ($s['failures'] > 1) {
            $lines[] = $this->t("неудач подряд: {$s['failures']}", "failures in a row: {$s['failures']}");
        }
        if ($s['last_rejected'] > $s['last_attempt']) {
            $lines[] = $this->acmeResultText('rate_limited') . ' ' . $this->acmeDate($s['last_rejected']);
        }
        return implode("\n", $lines);
    }

    public function acmeMenu(string $notice = '')
    {
        $text = ['Menu -> ' . $this->i18n('config') . ' -> SSL'];
        if ($notice !== '') {
            $text[] = $notice;
        }
        $text[] = $this->t(
            'Порт 80 закрыт firewall и открывается службой хоста только на время проверки Let\'s Encrypt (не дольше 10 минут). Автообновление продлевает сертификат, когда остаётся треть срока; неудачные попытки повторяются через 1, 2, 4 и затем каждые 6 часов.',
            'Port 80 is closed by the firewall; the host service opens it only for the Let\'s Encrypt check (10 minutes at most). Auto-renewal renews a certificate when a third of its lifetime is left; failed attempts are retried after 1, 2, 4 and then every 6 hours.'
        );
        $data = [];
        foreach ($this->acmeStates() as $name => $s) {
            $text[] = '';
            $text[] = $this->acmeStatusText($s);
            $data[] = [
                [
                    'text'          => ($s['auto'] ? '✅ ' : '⬜ ') . $this->t('авто: ', 'auto: ') . $this->acmeLabel($s),
                    'callback_data' => "/acmeAuto $name " . ($s['auto'] ? 'off' : 'on'),
                ],
                [
                    'text'          => '♻️ ' . $this->t('обновить: ', 'renew: ') . $this->acmeLabel($s),
                    'callback_data' => "/acmeRenew $name",
                ],
            ];
        }
        if (!$this->acmeAgent()) {
            $text[] = '';
            $text[] = '⚠️ ' . $this->t('служба хоста acme-window не отвечает больше трёх часов', 'the acme-window host service has not answered for over three hours');
        }
        $data[] = $this->menuHelpButton('acme');
        $data[] = [
            ['text' => '🔄', 'callback_data' => '/acmeMenu refresh'],
            ['text' => $this->i18n('back'), 'callback_data' => '/menu config'],
        ];
        return $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $text), $data);
    }

    public function acmeRefresh()
    {
        $file = "{$this->acmeRoot}/request/req-refresh";
        if ($this->acmeRequest('refresh')) {
            $this->acmeWaitTaken($file);
            usleep(500000);
        }
        return $this->acmeMenu();
    }

    public function acmeAuto(string $name, bool $on)
    {
        if (!isset($this->acmeStates()[$name])) {
            return $this->acmeMenu();
        }
        $action = $on ? 'auto-on' : 'auto-off';
        if (!$this->acmeRequest($action, $name)) {
            return $this->acmeMenu('❌ ' . $this->t('запрос не записан', 'the request was not written'));
        }
        // Служба меняет состояние за секунду-две: ждём, чтобы меню показало итог.
        $taken = $this->acmeWaitTaken("{$this->acmeRoot}/request/req-$action-$name");
        usleep(500000);
        return $this->acmeMenu($taken ? '' : '⏳ ' . $this->t('служба хоста занята — изменение применится, когда она освободится', 'the host service is busy; the change applies when it is free'));
    }

    public function acmeRenew(string $name, bool $confirm)
    {
        $states = $this->acmeStates();
        if (!isset($states[$name])) {
            return $this->acmeMenu();
        }
        if (!$confirm) {
            $text = 'Menu -> ' . $this->i18n('config') . ' -> SSL -> ' . $this->acmeLabel($states[$name]) . "\n" . '⚠ ' . $this->t(
                "Сертификат будет выпущен заново сейчас, даже если срок не подошёл. Порт 80 откроется не дольше чем на 10 минут. Let's Encrypt выдаёт не больше 5 одинаковых сертификатов за неделю, служба — не больше 3.",
                "The certificate will be issued again now, even if it is not due. Port 80 opens for 10 minutes at most. Let's Encrypt issues at most 5 identical certificates a week, the service at most 3."
            );
            return $this->update($this->input['chat'], $this->input['message_id'], $text, [
                [['text' => '♻️ ' . $this->t('выпустить сейчас', 'issue now'), 'callback_data' => "/acmeRenew $name confirm"]],
                [['text' => $this->i18n('cancel'), 'callback_data' => '/acmeMenu']],
            ]);
        }
        if (!$this->acmeRequest('renew', $name)) {
            return $this->acmeMenu('❌ ' . $this->t('запрос не записан', 'the request was not written'));
        }
        $this->acmeWaitTaken("{$this->acmeRoot}/request/req-renew-$name", 3.0);
        return $this->acmeMenu('⏳ ' . $this->t('запрос принят: результат придёт отдельным сообщением через несколько минут', 'request accepted: the result arrives as a separate message in a few minutes'));
    }

    public function acmeNotifyText(array $s, string $result): string
    {
        $text = ['🔐 SSL ' . $this->acmeLabel($s) . ': ' . $this->acmeResultText($result)];
        $text[] = $this->t('действует до: ', 'valid until: ') . $this->acmeDate($s['not_after']);
        if (!str_starts_with($result, 'ok') && $result !== 'rate_limited' && $s['last_detail'] !== '') {
            $text[] = '<code>' . htmlspecialchars($s['last_detail'], ENT_QUOTES) . '</code>';
        }
        if (!str_starts_with($result, 'ok') && $s['auto'] && $s['next_attempt'] > 0) {
            $text[] = $this->t('следующая попытка: ', 'next attempt: ') . $this->acmeDate($s['next_attempt']);
        }
        return implode("\n", $text);
    }

    // ── выпуск без Telegram: общий для кнопки и acme_renew.php ──

    // Имена сертификата. Домен и поддомен AdGuard уходят в shell, поэтому
    // проверяются как имена хостов (алиасы проверены в addDomainAlias).
    public function letsencryptNames(array $conf): array
    {
        if (!preg_match('~^[a-zA-Z0-9.-]+$~', (string) ($conf['domain'] ?? ''))) {
            throw new InvalidArgumentException($this->t('ОШИБКА: неверный домен', 'ERROR: invalid domain'));
        }
        if (!empty($conf['adguardkey']) && !preg_match('~^[a-zA-Z0-9-]+$~', (string) $conf['adguardkey'])) {
            throw new InvalidArgumentException($this->t('ОШИБКА: неверный поддомен AdGuard', 'ERROR: invalid adguard subdomain'));
        }
        $domain = $conf['domain'];
        $names  = [$domain];
        foreach (['oc', 'np'] as $sub) {
            if ($h = $this->getHashSubdomain($sub)) {
                $names[] = "$h.$domain";
            }
        }
        // WEB-режим telemt живёт на своём поддомене, и Telegram Desktop не
        // откроет соединение без валидного сертификата именно на это имя. SAN
        // просим только при включённом WEB: каждое лишнее имя — лишняя
        // зависимость выпуска от DNS-записи.
        if (!empty($conf['telemt_web']) && ($tw = $this->getHashSubdomain('tw'))) {
            $names[] = "$tw.$domain";
        }
        if (!empty($conf['adguardkey'])) {
            $names[] = "{$conf['adguardkey']}.$domain";
        }
        // Алиасы — дополнительные SAN того же серта. DoT AdGuardHome отвечает
        // по имени adguardkey.<домен>, и меню печатает эту точку входа для
        // каждого домена: без своего SAN на алиасе имя не совпало бы.
        foreach ($conf['domain_aliases'] ?? [] as $a) {
            $names[] = $a;
            if (!empty($conf['adguardkey'])) {
                $names[] = $conf['adguardkey'] . '.' . $a;
            }
        }
        foreach ($this->managedCertificateNames() as $name) {
            $names[] = $name;
        }
        return array_values(array_unique($names));
    }

    // --cert-name держит одну цепочку на домен: при новом алиасе certbot
    // расширяет её, а не создаёт domain-0001, которую установка бы не нашла.
    public function letsencryptCommand(array $conf, bool $dryRun = false): string
    {
        $names = $this->letsencryptNames($conf);
        $args  = implode(' ', array_map(fn ($n) => '-d ' . escapeshellarg($n), $names));
        return 'timeout -k 10 300 certbot certonly --force-renew --preferred-chain ' . escapeshellarg('ISRG Root X1')
            . ' -n --agree-tos --email ' . escapeshellarg("mail@{$conf['domain']}")
            . ' --cert-name ' . escapeshellarg($conf['domain']) . " $args --webroot -w /certs/"
            . ' --logs-dir /logs --max-log-backups 0' . ($dryRun ? ' --dry-run' : '') . ' 2>&1';
    }

    // Один certbot за раз: кнопка без службы и служба хоста не пересекаются.
    public function issueLetsencrypt(array $conf, bool $dryRun = false): array
    {
        $cmd  = $this->letsencryptCommand($conf, $dryRun);
        $lock = fopen(sys_get_temp_dir() . '/vpnbot-certbot.lock', 'c');
        if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) {
            return [75, [$this->t('certbot уже запущен', 'certbot is already running')]];
        }
        try {
            exec($cmd, $out, $code);
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
        return [$code, $out];
    }

    // Под блокировкой бэкапа: экспорт не снимет половину пары, а восстановление
    // не пройдёт между выпуском и установкой. Настройки читаются уже под
    // блокировкой: если восстановление сменило домен или вернуло свой
    // сертификат, выпущенный для прежних настроек не ставится.
    public function installLetsencrypt(string $domain, array $expectedNames = []): bool
    {
        return $this->withBackupLock(function () use ($domain, $expectedNames) {
            $conf = $this->getPacConf();
            if (($conf['domain'] ?? '') !== $domain || !$this->acmeWantsLetsencrypt($conf)) {
                return false;
            }
            // Восстановление могло сменить только алиасы/поддомены, сохранив
            // основной домен. Порядок SAN значения не имеет.
            if ($expectedNames) {
                $currentNames = $this->letsencryptNames($conf);
                sort($currentNames, SORT_STRING);
                sort($expectedNames, SORT_STRING);
                if ($currentNames !== $expectedNames) return false;
            }
            $live   = "/etc/letsencrypt/live/$domain";
            $bundle = @file_get_contents("$live/privkey.pem") . @file_get_contents("$live/fullchain.pem");
            $conf['letsencrypt'] = 'letsencrypt';
            unset($conf['acme_requested']);
            return $this->applyCertificateBundle($bundle, $conf);
        }, $this->acmeInstallLockWait);
    }

    // Кнопка Let's Encrypt при работающей службе только ставит acme_requested:
    // первый выпуск тоже идёт через окно, а свой сертификат служба не трогает.
    public function acmeWantsLetsencrypt(array $conf): bool
    {
        return !empty($conf['domain'])
            && (($conf['letsencrypt'] ?? '') === 'letsencrypt' || !empty($conf['acme_requested']));
    }

    // Проверяем каждый PEM-блок: OpenSSL при сверке ключа читает только первый.
    public static function certificatePairValid(string $public, string $private): bool
    {
        $count = preg_match_all('~-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----~s', $public, $certificates);
        if (!$count || $count !== substr_count($public, '-----BEGIN CERTIFICATE-----')
            || $count !== substr_count($public, '-----END CERTIFICATE-----')) return false;
        foreach ($certificates[0] as $certificate) {
            if (!@openssl_x509_read($certificate)) return false;
        }
        return @openssl_x509_check_private_key($certificates[0][0], $private);
    }

    // Бандл ключа и цепочки → /certs и службы, которые читают сертификат.
    public function applyCertificateBundle(string $bundle, array $conf): bool
    {
        if (!preg_match('~[^\s]+BEGIN PRIVATE KEY.+?END PRIVATE KEY[^\s]+~s', $bundle, $m)) {
            return false;
        }
        $public = preg_replace('~[^\s]+BEGIN PRIVATE KEY.+?END PRIVATE KEY[^\s]+~s', '', $bundle);
        if (!self::certificatePairValid($public, $m[0])) return false;
        return $this->withBackupLock(function () use ($conf, $m, $public) {
            $previous = $this->getPacConf();
            if ($this->setPacConf($conf) === false) return false;
            try {
                // Сначала готовим оба файла; ошибка записи/переименования
                // откатывает пару тем же механизмом, что восстановление бэкапа.
                $this->restoreBackupTree(['cert_private' => $m[0], 'cert_public' => $public],
                    $this->protocolCertRoot, ['cert_private' => 0600, 'cert_public' => 0644]);
            } catch (Throwable $error) {
                if ($this->setPacConf($previous) === false) {
                    throw new RuntimeException($this->t('Не удалось вернуть настройки SSL', 'Could not restore SSL settings'), 0, $error);
                }
                if ($error->getCode() === self::BACKUP_PARTIAL) throw $error;
                error_log('applyCertificateBundle: certificate files not written');
                return false;
            }
            $this->adguardSync();
            $this->cloakNginx();
            $this->restartTt();
            $this->telemtWebSync();
            return true;
        }, $this->acmeInstallLockWait);
    }
}
