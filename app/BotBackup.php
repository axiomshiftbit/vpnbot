<?php

trait BotBackup
{
    private bool $backupLocked = false;
    private array $backupModuleFailures = [];
    public const BACKUP_MAX_BYTES = 20 * 1024 * 1024;
    protected const BACKUP_APPLY_TIMEOUT = 60;
    // Код исключения: снимок лёг частично, прежние файлы вернуть не удалось.
    public const BACKUP_PARTIAL = 2;
    // Разделы, по которым файл узнаётся как резервная копия бота.
    public const BACKUP_SECTIONS = ['pac', 'wg', 'wg1', 'ad', 'hwid', 'ssl', 'dnstt', 'xray', 'hy', 'hy_users',
        'oc', 'ocu', 'tt', 'ss', 'sl', 'cloak', 'ckusers', 'ovpn', 'ipsec', 'xraystats', 'managed_protocols', 'extra_files'];

    // php и service видят один каталог конфигурации. Две операции restore
    // либо export/restore не должны перемешивать разделы разных снимков.
    // $wait — сколько секунд ждать чужую операцию (установка сертификата
    // службой acme-window ждёт восстановление, а не отказывает сразу).
    private function withBackupLock(callable $action, int $wait = 0)
    {
        if ($this->backupLocked) return $action();
        $mask = umask(0077);
        $lock = @fopen(dirname($this->pac) . '/.backup.lock', 'c');
        umask($mask);
        if (!$lock) throw new RuntimeException($this->t('Не удалось открыть блокировку бэкапа', 'Could not open the backup lock'));
        try {
            $deadline = microtime(true) + $wait;
            while (!flock($lock, LOCK_EX | LOCK_NB)) {
                if (microtime(true) >= $deadline) throw new RuntimeException($this->t('Другая операция бэкапа ещё выполняется', 'Another backup operation is still running'));
                usleep(500000);
            }
            $this->backupLocked = true;
            return $action();
        } finally {
            $this->backupLocked = false;
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    // app/restore.php: файл с диска сервера (make restore FILE=…). Тот же
    // путь, что у копии из Telegram: проверки, блокировка, откат.
    public function importCliFile(string $path): bool
    {
        try { return $this->withBackupLock(fn() => $this->restoreBackup($path)); }
        catch (Throwable $error) { return $this->backupImportError('apply', true, $error); }
        finally { unset($this->wg); }
    }

    private function preflightBackupWireguard(array $json): void
    {
        foreach (['wg' => 'amnezia', 'wg1' => 'wg1_amnezia'] as $service => $modeKey) {
            $checked = $this->withWireguardLock(function () use ($json, $service, $modeKey) {
                if ($this->hasWireguardPending()) throw new RuntimeException($this->t('WireGuard ожидает подтверждения; восстановление не начато', 'WireGuard confirmation is pending; restore has not started'));
                if (isset($json['pac']) && empty($json[$service]['server'])
                    && !empty($json['pac'][$modeKey]) !== !empty($this->getPacConf()[$modeKey])) {
                    throw new RuntimeException($this->t('Смена режима WireGuard требует его конфигурации в бэкапе', 'Changing WireGuard mode requires its configuration in the backup'));
                }
                return true;
            }, $service, 120, false);
            if (!$checked) throw new RuntimeException('WireGuard restore lock unavailable');
        }
    }

    // Полная копия до переключателей модулей (без managed_protocols) снята с
    // сервера, где работал набор по умолчанию. Новая установка запускает только
    // TeleMT — восстановление такой копии возвращает прежние протоколы.
    // Частичная копия (без pac) переключатели не трогает.
    public function restoreLegacyModules(array $json): void
    {
        if (array_key_exists('managed_protocols', $json) || !array_key_exists('pac', $json)) return;
        $modules = new ProtocolModules($this->protocolModulesFile);
        if ($modules->read() !== ProtocolModules::DEFAULTS) $modules->setMany(ProtocolModules::DEFAULTS);
    }

    public function protocolModulesSnapshot(): ?array
    {
        try { return (new ProtocolModules($this->protocolModulesFile))->read(); }
        catch (Throwable $e) { return null; }
    }

    // Переключатели модулей применяет обработчик хоста (update/update.sh).
    // Если копия включила модули, сервисы восстанавливаются только после того,
    // как он запустит их контейнеры: иначе перезапуск Shadowsocks, Hysteria и
    // др. уходил в ещё не созданный контейнер и восстановление на новой
    // установке (только TeleMT) заканчивалось отказом. Без файла состояния
    // обработчик не работал — ждать нечего.
    public function waitProtocolModulesApplied(?array $before, int $timeout = 150): bool
    {
        $this->backupModuleFailures = [];
        $after = $this->protocolModulesSnapshot();
        if ($before === null || $after === null) {
            $this->backupModuleFailures = ['Protocol modules'];
            return false;
        }
        if ($after === $before) return true;
        $changed = array_keys(array_filter($after, static fn($key) => ($before[$key] ?? null) !== $after[$key], ARRAY_FILTER_USE_KEY));
        $status = dirname($this->protocolModulesFile) . '/protocol-services.status.json';
        if (!is_file($status)) { $this->backupModuleFailures = $changed; return false; }
        $deadline = time() + $timeout;
        do {
            $applied = json_decode((string) @file_get_contents($status), true);
            $settled = is_array($applied) && is_array($applied['settings'] ?? null);
            $pending = [];
            foreach ($settled ? $after : [] as $key => $value) {
                $error = $applied['errors'][$key] ?? '';
                if ($error !== '' && $error !== 'operation_pending') {
                    $this->backupModuleFailures[] = $key;
                }
                if (($applied['settings'][$key] ?? null) !== $value || $error !== '') $pending[] = $key;
            }
            if ($this->backupModuleFailures) return false;
            if ($settled && !$pending && ($applied['ok'] ?? false) === true) {
                foreach (['oc', 'ovpn', 'tt', 'hy', 'ss', 'dnstt', 'ipsec', 'telemt'] as $service) {
                    if (empty($before[$service]) && ($applied['settings'][$service] ?? false) === true && $this->protocolModuleEnabled($service)
                        && !$this->waitForSshService($service, max(1, min(30, $deadline - time())))) {
                        $this->backupModuleFailures[] = $service;
                        return false;
                    }
                }
                return true;
            }
            if (time() >= $deadline) break;
            sleep(1);
        } while (time() < $deadline);
        $this->backupModuleFailures = $pending ?: $changed;
        error_log('importFile: protocol modules were not applied in time');
        return false;
    }

    private function backupReadFile(string $path): string
    {
        if (!is_file($path) || is_link($path)) throw new RuntimeException($this->t('Файл бэкапа недоступен', 'The backup file is unavailable'));
        $body = @file_get_contents($path, false, null, 0, self::BACKUP_MAX_BYTES + 1);
        if (!is_string($body) || strlen($body) > self::BACKUP_MAX_BYTES) throw new RuntimeException($this->t('Не удалось прочитать файл бэкапа', 'Could not read the backup file'));
        return $body;
    }

    private function backupTreePath(string $root, string $relative): string
    {
        if (!preg_match('~\A[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*\z~D', $relative)
            || preg_match('~(?:^|/)\.{1,2}(?:/|$)~', $relative)
            || str_contains($relative, '..') || str_starts_with($relative, '.restore-')) {
            throw new InvalidArgumentException($this->t('Недопустимое имя файла в снимке', 'Invalid file name in the snapshot'));
        }
        $path = rtrim($root, '/') . '/' . $relative;
        // Проверяем и сам файл, и все существующие родительские каталоги.
        // realpath только конечного файла не замечает ещё не созданный файл
        // внутри каталога-ссылки.
        for ($p = $path; $p !== dirname($p); $p = dirname($p)) {
            if (is_link($p)) throw new InvalidArgumentException($this->t('Симлинк в пути восстановления', 'A symlink in the restore path'));
        }
        if (file_exists($path) && !is_file($path)) throw new InvalidArgumentException($this->t('Путь восстановления занят каталогом', 'The restore path is taken by a directory'));
        return $path;
    }

    public function decodeBackupTree(array $files, string $root, array $required = []): array
    {
        if (count($files) > 8192) throw new InvalidArgumentException($this->t('Слишком много файлов в снимке', 'Too many files in the snapshot'));
        $decoded = []; $total = 0;
        foreach ($files as $relative => $encoded) {
            if (!is_string($relative) || !is_string($encoded)) throw new InvalidArgumentException($this->t('Неверный файл снимка', 'Invalid snapshot file'));
            $this->backupTreePath($root, $relative);
            if (strlen($encoded) > self::BACKUP_MAX_BYTES || ($body = base64_decode($encoded, true)) === false) {
                throw new InvalidArgumentException($this->t('Повреждён base64 в снимке', 'Damaged base64 in the snapshot'));
            }
            $total += strlen($body);
            if ($total > self::BACKUP_MAX_BYTES) throw new InvalidArgumentException($this->t('Снимок слишком большой', 'The snapshot is too large'));
            $decoded[$relative] = $body;
        }
        $missing = array_diff($required, array_keys($decoded));
        if ($missing) throw new InvalidArgumentException($this->t('В снимке нет обязательных файлов: ', 'Required files are missing from the snapshot: ') . implode(', ', $missing));
        foreach (array_keys($decoded) as $relative) {
            for ($p = dirname($relative); $p !== '.'; $p = dirname($p)) {
                if (array_key_exists($p, $decoded)) throw new InvalidArgumentException($this->t('Файл и каталог имеют одинаковый путь', 'A file and a directory have the same path'));
            }
        }
        return $decoded;
    }

    protected function backupRename(string $from, string $to): bool
    {
        return @rename($from, $to);
    }

    public function validateBackupPki(array $files, string $protocol): void
    {
        $ca = $files['pki/ca.crt'] ?? null;
        $server = $protocol === 'ovpn' ? 'pki/issued/server.crt' : 'pki/server.crt';
        $key = $protocol === 'ovpn' ? 'pki/private/server.key' : 'pki/server.key';
        if (!is_string($ca) || !@openssl_x509_read($ca)
            || !@openssl_x509_check_private_key($files[$server] ?? '', $files[$key] ?? '')) {
            throw new InvalidArgumentException($this->t('Повреждена пара сертификата и ключа PKI', 'Damaged PKI certificate and key pair'));
        }
        $authority = openssl_pkey_get_public($ca);
        if (!$authority || @openssl_x509_verify($files[$server], $authority) !== 1) throw new InvalidArgumentException($this->t('Сертификат сервера не подписан CA из бэкапа', 'The server certificate is not signed by the CA from the backup'));
        $caKey = $protocol === 'ovpn' ? 'pki/private/ca.key' : 'pki/ca.key';
        if (isset($files[$caKey]) && !@openssl_x509_check_private_key($ca, $files[$caKey])) throw new InvalidArgumentException($this->t('CA не соответствует приватному ключу', 'The CA does not match the private key'));
        if ($protocol === 'ovpn') foreach ($files as $name => $body) {
            if (!preg_match('~\Apki/issued/([^/]+)\.crt\z~D', $name, $m)) continue;
            if (@openssl_x509_verify($body, $authority) !== 1) throw new InvalidArgumentException($this->t('Повреждён сертификат пользователя OpenVPN', 'Damaged OpenVPN user certificate'));
            $private = 'pki/private/' . $m[1] . '.key';
            if (isset($files[$private]) && !@openssl_x509_check_private_key($body, $files[$private])) throw new InvalidArgumentException($this->t('Сертификат пользователя не соответствует ключу', 'The user certificate does not match the key'));
        }
    }

    // Два этапа: сначала все новые файлы записаны и синхронизированы, затем
    // заменяем рабочие. Ошибка переноса/удаления откатывает весь набор.
    public function restoreBackupTree(array $decoded, string $root, array $modes = [], array $remove = []): void
    {
        $before = [];
        foreach (array_unique(array_merge(array_keys($decoded), $remove)) as $relative) {
            $path = $this->backupTreePath($root, $relative);
            $before[$relative] = is_file($path) ? [$this->backupReadFile($path), fileperms($path) & 0777] : null;
        }
        if (!is_dir($root) && !@mkdir($root, 0700, true)) throw new RuntimeException($this->t('Не удалось создать каталог восстановления', 'Could not create the restore directory'));
        $stage = "$root/.restore-" . bin2hex(random_bytes(8));
        if (!mkdir($stage, 0700)) throw new RuntimeException($this->t('Не удалось создать каталог подготовки', 'Could not create the staging directory'));
        $written = [];
        try {
            foreach ($decoded as $relative => $body) {
                $path = "$stage/$relative";
                if (!is_dir(dirname($path)) && !mkdir(dirname($path), 0700, true)) throw new RuntimeException($this->t('Не удалось подготовить каталог', 'Could not prepare the directory'));
                if (!$this->writePrivateKey($path, $body) || !chmod($path, $modes[$relative] ?? 0600)) throw new RuntimeException($this->t('Не удалось подготовить файл', 'Could not prepare the file'));
            }
            foreach ($decoded as $relative => $_) {
                $path = $this->backupTreePath($root, $relative);
                if (!is_dir(dirname($path)) && !mkdir(dirname($path), 0755, true)) throw new RuntimeException($this->t('Не удалось создать каталог назначения', 'Could not create the target directory'));
                $written[] = $relative;
                if (!$this->backupRename("$stage/$relative", $path)) throw new RuntimeException($this->t('Не удалось перенести подготовленный файл', 'Could not move the prepared file'));
            }
            foreach ($remove as $relative) {
                $path = $this->backupTreePath($root, $relative);
                $written[] = $relative;
                if (file_exists($path) && !unlink($path)) throw new RuntimeException($this->t('Не удалось удалить прежний файл', 'Could not delete the previous file'));
            }
            foreach (array_unique(array_map(fn($relative) => dirname("$root/$relative"), $written)) as $dir) {
                $handle = @fopen($dir, 'r');
                if (!$handle) throw new RuntimeException($this->t('Не удалось открыть каталог', 'Could not open the directory'));
                try { if (!fsync($handle)) throw new RuntimeException($this->t('Не удалось синхронизировать каталог', 'Could not sync the directory')); }
                finally { fclose($handle); }
            }
        } catch (Throwable $error) {
            $rollback = true;
            foreach (array_reverse($written) as $relative) {
                $path = "$root/$relative"; $old = $before[$relative];
                $ok = $old === null ? (!file_exists($path) || @unlink($path))
                    : ($this->writePrivateKey($path, $old[0]) && chmod($path, $old[1]));
                $rollback = $ok && $rollback;
            }
            if (!$rollback) throw new RuntimeException($this->t('Восстановлено ЧАСТИЧНО: откат файлов не завершён', 'Restored PARTIALLY: the file rollback did not finish'), self::BACKUP_PARTIAL, $error);
            throw $error;
        } finally { $this->rmrf($stage); }
    }

    // Отдельно примонтированные файлы WG/SS/Xray нельзя заменять rename:
    // контейнер останется на старом inode. Не обрезаем файл до успешной записи.
    protected function backupWriteInPlace(string $path, string $body): bool
    {
        if (is_link($path)) return false;
        $mask = umask(0077); $handle = @fopen($path, 'c+b'); umask($mask);
        if (!$handle) return false;
        try {
            if (!flock($handle, LOCK_EX) || !chmod($path, 0600)) return false;
            $old = stream_get_contents($handle);
            if (!is_string($old) || !rewind($handle)) return false;
            if (@fwrite($handle, $body) === strlen($body) && ftruncate($handle, strlen($body)) && fflush($handle) && fsync($handle)) return true;
            rewind($handle);
            if (@fwrite($handle, $old) !== strlen($old) || !ftruncate($handle, strlen($old)) || !fflush($handle) || !fsync($handle)) {
                error_log('importFile: in-place rollback failed');
            }
            return false;
        } finally { flock($handle, LOCK_UN); fclose($handle); }
    }

    private function restoreBackupShadowsocks(array $sections): bool
    {
        return (bool) $this->withShadowsocksLock(function () use ($sections) {
            if (isset($sections['ss']) && empty($sections['ss']['acl'])) $sections['ss']['acl'] = '/config/ss.acl';
            return $this->applyShadowsocksConfigsLocked($sections, true);
        });
    }

    private function restoreBackupSimpleTls(string $body): bool
    {
        $config = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($config)) throw new RuntimeException('Invalid simple-tls backup');
        return (bool) $this->withShadowsocksLock(function () use ($body, $config) {
            $path = $this->backupExtraPath('stlsserver.json');
            if (file_exists($path) && !is_file($path)) return false;
            $before = is_file($path) ? file_get_contents($path) : null;
            if ($before === false) return false;
            $mode = $before === null ? null : fileperms($path) & 0777;
            $enabled = $this->protocolModuleEnabled('ss');
            if ($enabled && !$this->controlContainerService('ss', 'simple-tls', 'stop')) return false;
            $starting = false;
            try {
                if (!$this->writePrivateKey($path, $body)) throw new RuntimeException('Could not save simple-tls');
                if (!$enabled || empty($config['Enabled'])) return true;
                $starting = true;
                if ($this->controlContainerService('ss', 'simple-tls', 'start')) return true;
            } catch (Throwable $error) {
                // A failed write may already have published the new file.
            }
            // A failed start may still have spawned a process: confirm stop
            // before restoring the old generation. No PAC/node locks on SSH.
            if ($starting && !$this->controlContainerService('ss', 'simple-tls', 'stop')) {
                throw new RuntimeException('Could not stop simple-tls during rollback', self::BACKUP_PARTIAL);
            }
            $restored = $before === null ? (!file_exists($path) || @unlink($path))
                : ($this->writePrivateKey($path, $before) && @chmod($path, $mode));
            if ($restored && $enabled && !empty(json_decode($before ?? '{}', true)['Enabled'])) {
                $restored = $this->controlContainerService('ss', 'simple-tls', 'start');
            }
            if (!$restored) throw new RuntimeException('Could not roll back simple-tls', self::BACKUP_PARTIAL);
            return false;
        });
    }

    // Подтверждаем процессы и применение нужной ревизии supervisor, а не
    // только доставку команды SSH. Выключенные модули сохраняют данные без
    // требования запуска контейнера.
    public function verifyBackupServices(array $json): array
    {
        $failed = []; $checks = []; $pac = $this->getPacConf();
        $supervised = [];
        foreach (['ss'=>['ss','ssserver'], 'sl'=>['proxy','sslocal'], 'ad'=>['ad','adguard']] as $section => [$service, $daemon]) {
            if (!empty($json[$section])) $supervised[$section === 'ad' ? 'AdGuard' : $section] = [$service, $daemon, true];
        }
        if (!empty($json['ovpn'])) $checks['ovpn'] = ['ovpn', 'pgrep -x openvpn >/dev/null'];
        if (isset($json['pac']) || !empty($json['dnstt'])) {
            $supervised['DNSTT'] = ['dnstt', 'dnstt', !empty($pac['dnsttDomain']) && !empty($pac['dnsttPassword'])];
        }
        if (!empty($json['ipsec'])) $checks['IPsec'] = ['ipsec', 'pgrep -x charon >/dev/null'
            . ($this->protocolModuleEnabled('l2tp') ? ' && pgrep -x xl2tpd >/dev/null' : '')];
        if (isset($json['tt'])) $supervised['TrustTunnel'] = ['tt', 'trusttunnel', (bool) $this->getClientsTt()];
        if (!empty($json['cloak'])) $supervised['Cloak'] = ['ss', 'ck-server', !empty($json['cloak']['Enabled'])];
        if (isset($json['extra_files']['stlsserver.json'])) $supervised['simple-tls'] = ['ss', 'simple-tls', !empty($this->getStlsConfig()['Enabled'])];
        if (isset($json['pac'])) $supervised['NaiveProxy'] = ['np', 'naive', self::naiveReady($pac)];
        foreach ($supervised as $name => [$service, $daemon, $running]) {
            $check = '/bin/sh /service_supervisor.sh status ' . $daemon;
            if (!$running) $check = '{ ' . $check . '; [ "$?" -eq 3 ]; }';
            $checks[$name] = [$service, $check];
        }
        if (isset($json['pac']) && $this->backupHasTelemt($json['pac']) && !empty($pac['telemt_users'])) {
            $checks['TeleMT'] = ['telemt', 'pgrep -x telemt >/dev/null'];
            foreach (['telemt_web','telemt_web_negotiation'] as $key) {
                if (isset($json['pac'][$key]) && ($pac[$key] ?? null) != $json['pac'][$key]) $failed[] = 'TeleMT WEB';
            }
        }
        if (!empty($json['oc']) && (!empty($pac['ocserv']) || !empty($pac[self::OC_USERS]))) $checks['OpenConnect'] = ['oc', 'pgrep -x ocserv >/dev/null'];
        foreach ($checks as $name => [$service, $check]) {
            if (!$this->protocolModuleEnabled($service)) continue;
            $cmd = 'for n in 1 2 3 4 5 6 7 8 9 10; do if ' . $check
                . '; then sleep 0.2; ' . $check . ' && printf VPNBOT_SERVICE_READY; exit; fi; sleep 0.2; done; exit 1';
            $output = $this->ssh($cmd, $service);
            if ($this->sshFailed || trim($output) !== 'VPNBOT_SERVICE_READY') $failed[] = $name;
        }
        $pending = [];
        foreach ($json['managed_protocols']['protocols'] ?? [] as $name => $_) {
            // Копия другой версии может содержать протокол, которого здесь нет.
            if (!isset(ManagedProtocol::NAMES[$name])) continue;
            if (!$this->protocolModuleEnabled($name)) continue;
            $store = $this->protocolStore($name); $state = $store->read();
            $pending[$name] = [$store->directory() . '/runtime', $state['revision'], $state['restore_usage']['id'] ?? null];
        }
        if ((isset($json['hy_users']) || !empty($json['hy'])) && $this->protocolModuleEnabled('hy')) {
            $state = $this->hysteriaUsersStore()->read();
            if (is_file($this->hysteriaUsersRoot . '/users.json')) {
                // Без пользователей и общего пароля Hysteria обслуживать некого:
                // ядро не настроено и законно не запускается — это не отказ копии.
                if ($state['users'] || !empty($pac['hysteria_pass'])) {
                    $pending['Hysteria'] = [$this->hysteriaUsersRoot . '/runtime', $state['revision'], $state['restore_usage']['id'] ?? null];
                }
            } elseif (!empty($pac['hysteria_pass'])) {
                $output = $this->ssh('pgrep -x hysteria >/dev/null && printf VPNBOT_SERVICE_READY', 'hy');
                if ($this->sshFailed || trim($output) !== 'VPNBOT_SERVICE_READY') $failed[] = 'Hysteria';
            }
        }
        // Host-worker создаёт контейнеры последовательно. При восстановлении
        // на чистой установке последние ядра ещё могут ожидать своей очереди.
        $deadline = microtime(true) + static::BACKUP_APPLY_TIMEOUT;
        while ($pending) {
            foreach ($pending as $name => [$root, $revision, $restoreId]) {
                $status = json_decode((string) @file_get_contents("$root/status.json"), true);
                $usage = json_decode((string) @file_get_contents("$root/usage.json"), true);
                if (is_array($status) && ($status['time'] ?? 0) >= time() - 15 && empty($status['error'])
                    && is_int($status['revision'] ?? null) && $status['revision'] >= $revision
                    && ($restoreId === null || ($usage['restored'] ?? null) === $restoreId)
                    && (!empty($status['running']) || in_array($status['phase'] ?? '', ['idle', 'disabled'], true))) {
                    unset($pending[$name]);
                }
            }
            if (!$pending || microtime(true) >= $deadline) break;
            usleep(200000);
        }
        return array_values(array_unique(array_merge($failed, array_keys($pending))));
    }

    // Структурная проверка ВСЕХ разделов до первой записи/перезапуска.
    // Проверка конфигов самими ядрами остаётся обязательной при применении.
    public function validateBackup(array $json): void
    {
        // Export and every import use the same limit, including base64 and JSON
        // formatting overhead. A structurally valid but unrestorable copy fails
        // before it can replace the last backup or mutate live settings.
        $encoded = json_encode($json, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        if (strlen($encoded) > self::BACKUP_MAX_BYTES) {
            throw new InvalidArgumentException($this->t('Размер бэкапа превышает предел восстановления (20 МиБ)', 'Backup exceeds the restore limit (20 MiB)'));
        }
        unset($encoded);
        foreach (['pac', 'wg', 'wg1', 'ad', 'hwid', 'xray', 'hy', 'hy_users', 'ss', 'sl',
            'xraystats', 'managed_protocols', 'extra_files', 'telemt_quota'] as $key) {
            if (array_key_exists($key, $json) && !is_array($json[$key])) throw new InvalidArgumentException($this->t('Неверный раздел: ', 'Invalid section: ') . $key);
        }
        if (array_key_exists('xraystats', $json)) self::normalizeXrayStats($json['xraystats']);
        foreach (['ssl', 'dnstt', 'cloak', 'ckusers', 'ovpn', 'ipsec'] as $key) {
            if (isset($json[$key]) && $json[$key] !== false && !is_array($json[$key])) throw new InvalidArgumentException($this->t('Неверный раздел: ', 'Invalid section: ') . $key);
        }
        foreach (['oc', 'ocu', 'tt'] as $key) {
            if (array_key_exists($key, $json) && !is_string($json[$key])) throw new InvalidArgumentException($this->t('Неверный раздел: ', 'Invalid section: ') . $key);
        }
        $pac = $json['pac'] ?? [];
        foreach (['domain', 'language', 'transport', 'dnsttDomain', 'dnsttPassword', 'hysteria_pass'] as $key) {
            if (isset($pac[$key]) && !is_string($pac[$key])) throw new InvalidArgumentException($this->t('Неверные настройки бота', 'Invalid bot settings'));
        }
        if (!empty($pac['domain']) && !ManagedProtocol::hostname($pac['domain'])) throw new InvalidArgumentException($this->t('Неверный домен', 'Invalid domain'));
        foreach (['domain_aliases', 'naive', 'reality', 'datlist', 'telemt_users', 'ocserv_users'] as $key) {
            if (isset($pac[$key]) && !is_array($pac[$key])) throw new InvalidArgumentException($this->t('Неверные настройки бота', 'Invalid bot settings'));
        }
        foreach ($pac['domain_aliases'] ?? [] as $domain) if (!ManagedProtocol::hostname($domain)) throw new InvalidArgumentException($this->t('Неверный домен', 'Invalid domain'));
        foreach (['wg', 'wg1'] as $key) if (isset($json[$key])) {
            $wg = $json[$key];
            if (!is_array($wg['server'] ?? null) || !is_array($wg['clients'] ?? null)) throw new InvalidArgumentException($this->t('Неполный снимок WireGuard', 'Incomplete WireGuard snapshot'));
            foreach (array_merge([$wg['server']], array_values($wg['clients'])) as $config) {
                if (!is_array($config) || (isset($config['interface']) && !is_array($config['interface']))
                    || (isset($config['peers']) && !is_array($config['peers']))) throw new InvalidArgumentException($this->t('Неверный снимок WireGuard', 'Invalid WireGuard snapshot'));
                foreach (array_merge([$config['interface'] ?? []], $config['peers'] ?? []) as $section) {
                    if (!is_array($section)) throw new InvalidArgumentException($this->t('Неверная секция WireGuard', 'Invalid WireGuard section'));
                    foreach ($section as $value) if (!is_scalar($value)) throw new InvalidArgumentException($this->t('Неверное поле WireGuard', 'Invalid WireGuard field'));
                }
            }
            if ($wg['clients'] && empty($wg['server']['interface'])) throw new InvalidArgumentException($this->t('Нет сервера WireGuard', 'No WireGuard server'));
        }
        if (!empty($json['ssl']) && (!is_string($json['ssl']['private'] ?? null) || !is_string($json['ssl']['public'] ?? null)
            || !self::certificatePairValid($json['ssl']['public'], $json['ssl']['private']))) throw new InvalidArgumentException($this->t('Неверная TLS-пара', 'Invalid TLS pair'));
        if (!empty($json['dnstt'])) {
            foreach (['private', 'public'] as $key) if (!is_string($json['dnstt'][$key] ?? null)
                || !preg_match('/\A[0-9a-fA-F]{64}\s*\z/D', $json['dnstt'][$key])) throw new InvalidArgumentException($this->t('Неверная пара DNSTT', 'Invalid DNSTT pair'));
            foreach (['ssh_private', 'ssh_public'] as $key) if (isset($json['dnstt'][$key]) && !is_string($json['dnstt'][$key])) throw new InvalidArgumentException($this->t('Неверный ключ SSH DNSTT', 'Invalid DNSTT SSH key'));
            if (empty($json['dnstt']['ssh_private']) !== empty($json['dnstt']['ssh_public'])) throw new InvalidArgumentException($this->t('Неполная пара SSH DNSTT', 'Incomplete DNSTT SSH pair'));
        }
        if (array_key_exists('ovpn_limits', $json)) self::validateOvpnLimits($json['ovpn_limits']);
        if (!empty($json['ovpn'])) $this->validateBackupPki($this->decodeBackupTree($json['ovpn'], dirname($this->ovpnPaths()['pki']), self::OVPN_SNAPSHOT_CORE), 'ovpn');
        if (!empty($json['ipsec'])) {
            $pki = $this->decodeBackupTree($json['ipsec'], $this->ipsecPaths()['conf']);
            if (array_filter(array_keys($pki), static fn($name) => str_starts_with($name, 'pki/'))) $this->validateBackupPki($pki, 'ipsec');
        }
        if (isset($json['managed_protocols'])) {
            $material = $this->validateManagedBackup($json['managed_protocols']);
            foreach (['private','public'] as $part) {
                if (!empty($json['ssl']) && isset($material['/certs/cert_' . $part])
                    && $json['ssl'][$part] !== $material['/certs/cert_' . $part]) throw new InvalidArgumentException($this->t('Разделы бэкапа содержат разные TLS-пары', 'Backup sections contain different TLS pairs'));
            }
        }
        if (isset($json['hy_users'])) HysteriaUsers::validateSnapshot($json['hy_users']);
        $extra = $this->validateBackupExtraFiles($json['extra_files'] ?? []);
        if (isset($pac['managed_nodes']) && !is_array($pac['managed_nodes'])) {
            throw new InvalidArgumentException($this->t('Неверный список нод', 'Invalid node list'));
        }
        foreach ($pac['managed_nodes'] ?? [] as $id => $node) {
            if (!preg_match('~\A[a-f0-9]{8}\z~D', (string) $id) || !is_array($node)) {
                throw new InvalidArgumentException($this->t('Неверная нода в бэкапе', 'Invalid node in backup'));
            }
            $required = !empty($node['connected']) ? ['key', 'key.pub', 'endpoint.json', 'snapshot.json'] : ['key', 'key.pub'];
            foreach ($required as $name) {
                if (!isset($extra["nodes/$id/$name"]) || $extra["nodes/$id/$name"] === '') {
                    throw new InvalidArgumentException($this->t('Неполная копия ноды: отсутствуют обязательные файлы управления', 'Incomplete node backup: required management files are missing'));
                }
            }
        }
        $limits = $this->telemtLimitsOf($pac);
        if (isset($json['telemt_quota'])) $this->telemtValidateQuotaState($json['telemt_quota'], $pac);
        elseif (array_filter($limits, static fn($row) => !empty($row['quota']))) throw new InvalidArgumentException($this->t('Нет расхода TeleMT', 'No TeleMT usage'));
    }
}
