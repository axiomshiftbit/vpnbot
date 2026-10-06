<?php

require_once __DIR__ . '/ManagedProtocol.php';
require_once __DIR__ . '/ProtocolModules.php';
require_once __DIR__ . '/BotProtocolOptions.php';
require_once __DIR__ . '/BotProtocolSubscriptions.php';
require_once __DIR__ . '/BotConnectionExports.php';

trait BotProtocols
{
    use BotProtocolOptions;
    use BotProtocolSubscriptions;
    use BotConnectionExports;
    public string $protocolRoot = '/config/protocols';
    public string $protocolModulesFile = '/config/protocol-services.json';
    public string $upstreamFile = '/config/upstream.conf';
    public string $protocolNginxFile = '/config/nginx.conf';
    public string $protocolCertRoot = '/certs';
    public bool $protocolReturnMain = false;
    public bool $protocolFingerprintShortcut = false;
    public array $protocolRelayOrigin = [];
    public bool $protocolOutput = false;

    public function protocolNavigationStart(): void
    {
        $this->protocolFingerprintShortcut = false;
        $this->protocolRelayOrigin = [];
        $this->protocolOutput = false;
        if (!$this->admin) return;
        $key = $this->input['chat'] . ':' . $this->input['message_id'];
        $outputs = $_SESSION['protocol_output'][$key] ?? [];
        if ($outputs) {
            $this->sessionApply(function () use ($key) { unset($_SESSION['protocol_output'][$key]); });
            foreach ($outputs as $id) $this->delete($this->input['chat'], $id);
        }
        if (!empty($_SESSION['protocol_relay'][$key])) {
            if (preg_match('~^/(relay(?:Menu|Add|Edit|Del)|switchRelayAggregate|setRelay\w+|prset)(?: |$)~', (string) $this->input['callback'])) {
                $this->protocolRelayOrigin = $_SESSION['protocol_relay'][$key];
            } else {
                $this->sessionApply(function () use ($key) { unset($_SESSION['protocol_relay'][$key]); });
            }
        }
    }

    // Only explicitly requested protocol files/QRs are temporary. Never sweep chat history.
    public function rememberProtocolOutput($result)
    {
        if ($this->protocolOutput && !empty($result['result']['message_id'])) {
            $key = $this->input['chat'] . ':' . $this->input['message_id'];
            $this->sessionApply(function () use ($key, $result) {
                $_SESSION['protocol_output'][$key][] = (int) $result['result']['message_id'];
                $_SESSION['protocol_output'] = array_slice($_SESSION['protocol_output'], -50, null, true);
            });
        }
        return $result;
    }

    public function protocolError(string $message, string $back, string $retry = ''): void
    {
        $buttons = [];
        if ($retry !== '') $buttons[] = [['text' => 'Повторить ввод', 'callback_data' => $retry]];
        $buttons[] = [['text' => $this->i18n('back'), 'callback_data' => $back]];
        $this->update($this->input['chat'], $this->input['message_id'], '❌ ' . self::esc($message), $buttons);
    }

    public function protocolManageRelays(string $protocol, string $id = ''): void
    {
        if (!$this->admin) return;
        $key = $this->input['chat'] . ':' . $this->input['message_id'];
        $this->protocolRelayOrigin = ['back' => ($this->protocolReturnMain ? '/!' : '/') . ($id === '' ? "protocol $protocol" : "pr $protocol $id page"),
            'label' => ManagedProtocol::NAMES[$protocol]];
        $this->sessionApply(function () use ($key) {
            $_SESSION['protocol_relay'][$key] = $this->protocolRelayOrigin;
            $_SESSION['protocol_relay'] = array_slice($_SESSION['protocol_relay'], -50, null, true);
        });
        $this->relayMenu();
    }

    public function protocolNavigationButtons($buttons)
    {
        if (!is_array($buttons)) return $buttons;
        foreach ($buttons as &$row) foreach ($row as &$button) {
            $callback = $button['callback_data'] ?? '';
            if ($this->protocolRelayOrigin && $callback === '/xray') $callback = $this->protocolRelayOrigin['back'];
            if ($this->protocolFingerprintShortcut) {
                if (preg_match('~^/po (anytls|shadowtls) (show|reset|pick) client\.fingerprint(.*)$~D', $callback, $m)) $callback = "/pf {$m[1]} {$m[2]}{$m[3]}";
                elseif (preg_match('~^/po (anytls|shadowtls) show client$~D', $callback, $m)) $callback = "/protocol {$m[1]}";
            }
            if ($this->protocolReturnMain) {
                if ($callback === '/protocolModules') $callback = '/menu';
                elseif (preg_match('~^/(protocol|pr|prset|prmanage|po|ps|pf|menuhelp) ~', $callback)) $callback = '/!' . substr($callback, 1);
            }
            if (isset($button['callback_data'])) $button['callback_data'] = $callback;
        }
        return $buttons;
    }

    public function protocolStore(string $protocol): ManagedProtocol
    {
        return new ManagedProtocol($protocol, $this->protocolRoot);
    }

    public function protocolPortPrompt(string $protocol): void
    {
        if (!$this->admin) return;
        $settings = $this->protocolStore($protocol)->read()['settings'];
        $text = ManagedProtocol::NAMES[$protocol] . ' · внешний порт: ' . $settings['port'] . ".\n";
        if ($protocol === 'anytls') {
            $text .= 'AnyTLS принимает подключения на общем 443/TCP через отдельное имя SNI. Внутренний порт — 8443. Отдельная смена порта здесь недоступна: общий вход используется и другими сервисами.';
        } else {
            $transport = $protocol === 'tuic' ? 'UDP' : (in_array($protocol, ['mieru', 'masque'], true) ? 'TCP/UDP' : 'TCP');
            $text .= "Меняется внешний порт $transport в Docker и в выдаваемых профилях. Адрес, SNI и внутренний порт сохраняются. Применение может кратко прервать соединения этого протокола.\n"
                . 'Откройте новый порт в своём внешнем firewall/NAT, затем обновите клиентскую подписку. Переадресация на отдельном relay меняется вручную. 0 не отключает сервис; выключатель находится в настройках протокола.';
        }
        $this->update($this->input['chat'], $this->input['message_id'], self::esc($text), [[['text' => $this->i18n('back'), 'callback_data' => '/ports']]]);
        if ($protocol === 'anytls') return;
        $r = $this->send($this->input['chat'], 'Новый внешний порт: целое число 1024–65535. Для отмены нажмите «Назад».',
            $this->input['message_id'], reply: '1024–65535');
        $this->stashReply($r, ['start_message' => $this->input['message_id'], 'callback' => 'protocolPortReply', 'args' => [$protocol]]);
    }

    public function protocolPortReply($input, string $protocol): void
    {
        if (!$this->admin) return;
        try {
            $input = trim((string) $input);
            if (!in_array($protocol, ['mieru', 'tuic', 'shadowtls', 'masque'], true)
                || !preg_match('/\A[0-9]{4,5}\z/D', $input) || (int) $input < 1024 || (int) $input > 65535) {
                throw new InvalidArgumentException('Внешний порт должен быть целым числом 1024–65535.');
            }
            $this->protocolStore($protocol)->configure(['port' => (int) $input]);
            $this->ports();
        } catch (InvalidArgumentException | RuntimeException $e) {
            $this->protocolError($e->getMessage(), '/ports', "/protocolPort $protocol");
        }
    }

    public function protocolModuleEnabled(string $module): bool
    {
        return (new ProtocolModules($this->protocolModulesFile))->enabled($module);
    }

    public function managedProtocolVersionCells(): array
    {
        $cells = [];
        foreach (['anytls' => 'AnyTLS/sb', 'mieru' => 'Mieru', 'tuic' => 'TUIC5/sb', 'shadowtls' => 'ShadowTLS3/sb', 'masque' => 'MASQUE/Xray'] as $protocol => $label) {
            if (!$this->protocolModuleEnabled($protocol)) { $cells[] = "$label выкл."; continue; }
            $status = $this->protocolStore($protocol)->status();
            $version = $status['core_version'] ?? '';
            $known = !$status['stale'] && is_string($version) && preg_match('/\A[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?\z/D', $version);
            $cells[] = $label . ' ' . ($known ? self::esc($version) : 'нет данных');
        }
        return $cells;
    }

    public function configureProtocolSelfHost(string $protocol): void
    {
        if (!in_array($protocol, ['anytls', 'shadowtls', 'tuic', 'masque'], true)) throw new InvalidArgumentException('Для этого протокола задайте адрес и порт');
        $domain = strtolower((string) ($this->getPacConf()['domain'] ?? ''));
        if (!ManagedProtocol::hostname($domain) || filter_var($domain, FILTER_VALIDATE_IP)) throw new RuntimeException('Сначала задайте основной домен сервера');
        $store = $this->protocolStore($protocol);
        $settings = ['host' => $domain, 'sni' => $domain,
            'blocked_ips' => filter_var($this->ip, FILTER_VALIDATE_IP) ? [$this->ip] : []];
        if (!in_array($protocol, ['shadowtls', 'masque'], true)) {
            $label = $this->getHashSubdomain($protocol === 'tuic' ? 'tc' : 'at');
            if ($label === '') throw new RuntimeException('Неверный поддомен протокола');
            $settings['host'] = $settings['sni'] = $label . '.' . $domain;
        }
        if (!in_array($protocol, ['tuic', 'masque'], true)) $settings['self_hosted'] = true;
        if ($protocol === 'anytls') $settings += ['cover_host' => $domain, 'port' => 443];
        $current = $store->read()['settings'];
        foreach ($settings as $key => $value) if (($current[$key] ?? null) !== $value) {
            $store->configure($settings);
            break;
        }
    }

    public function syncManagedSelfHosts(): void
    {
        foreach (['anytls', 'shadowtls'] as $protocol) {
            $store = $this->protocolStore($protocol);
            if (is_file($store->directory() . '/desired.json') && !empty($store->read()['settings']['self_hosted'])) {
                $this->configureProtocolSelfHost($protocol);
            }
        }
    }

    public function prepareProtocolSelfHost(): void
    {
        $ok = $this->editProtocolProxyConfig($this->protocolNginxFile, 'ng', static function (string $text): string {
            return preg_replace_callback('~^([ \t]*)listen 10\\.10\\.0\\.2:443 ssl proxy_protocol([^;\r\n]*);([ \t]*\r?\n)(?![ \t]*listen 10\\.10\\.0\\.2:10443 ssl)~m',
                static fn($m) => $m[0] . $m[1] . 'listen 10.10.0.2:10443 ssl' . (str_contains($m[2], 'default_server') ? ' default_server' : '') . ";\n", $text);
        });
        if (!$ok || !str_contains((string) @file_get_contents($this->protocolNginxFile), 'listen 10.10.0.2:10443 ssl')) {
            throw new RuntimeException('Не удалось подготовить внутренний TLS-маршрут к своему сайту');
        }
    }

    private function protocolPortApplied(string $protocol, array $state): bool
    {
        if ($protocol === 'anytls') {
            return is_file($this->upstreamFile) && $state['settings']['sni'] !== ''
                && preg_match('~^\s*' . preg_quote($state['settings']['sni'], '~') . '\s+anytls_bridge\s*;\s*$~mi',
                    file_get_contents($this->upstreamFile)) === 1;
        }
        $path = dirname($this->protocolModulesFile) . '/protocol-services.status.json';
        if (!is_file($path)) return false;
        $status = ManagedProtocol::readJson($path);
        return ($status['bindings'][$protocol] ?? null) === $state['settings']['port'];
    }

    public function managedCertificateNames(): array
    {
        $names = [];
        foreach (ManagedProtocol::NAMES as $protocol => $_) {
            if (in_array($protocol, ['mieru', 'shadowtls'], true)) continue;
            $state = $this->protocolStore($protocol)->read();
            $sni = $state['settings']['sni'];
            if ($sni !== '' && ManagedProtocol::hostname($sni) && !filter_var($sni, FILTER_VALIDATE_IP)) $names[] = $sni;
        }
        return array_values(array_unique($names));
    }

    public function managedProtocolDomainLines(): array
    {
        $lines = [];
        foreach (['anytls' => 'AnyTLS', 'tuic' => 'TUIC v5', 'shadowtls' => 'ShadowTLS', 'masque' => 'MASQUE'] as $protocol => $label) {
            try {
                $settings = $this->protocolStore($protocol)->read()['settings'];
            } catch (RuntimeException | InvalidArgumentException $e) {
                $lines[] = "$label: ошибка состояния";
                continue;
            }
            if ($settings['host'] === '') {
                $lines[] = "$label: не настроен";
                continue;
            }
            $ownSite = !empty($settings['self_hosted']);
            $certificate = $protocol === 'shadowtls' ? ($ownSite ? '/certs/cert_public' : '') : $settings['certificate'];
            $identity = $settings['sni'] !== '' ? $settings['sni'] : $settings['host'];
            $expiry = $certificate !== '' ? $this->managedCertificateDomainSuffix($certificate, $identity) : '';
            $sameName = strcasecmp($identity, $settings['host']) === 0;
            $lines[] = "$label: <code>" . self::esc($settings['host']) . '</code>' . ($sameName ? $expiry : '');
            if ($protocol !== 'shadowtls' && !$sameName) {
                $lines[] = "$label SNI: <code>" . self::esc($settings['sni']) . '</code>' . $expiry;
            }
            $cover = $protocol === 'anytls' ? $settings['cover_host'] : ($protocol === 'shadowtls' ? $settings['sni'] : '');
            if ($cover !== '') {
                $lines[] = "$label сайт прикрытия" . ($protocol === 'shadowtls' ? ' (SNI)' : '') . ': <code>' . self::esc($cover) . '</code>'
                    . ($ownSite ? $this->managedCertificateDomainSuffix('/certs/cert_public', $cover) : '');
            }
        }
        return $lines;
    }

    private function managedCertificateDomainSuffix(string $certificate, string $hostname): string
    {
        $missing = ' (ssl: нет сертификата для домена)';
        try {
            $file = $this->managedCertificatePath($certificate);
        } catch (RuntimeException | InvalidArgumentException $e) {
            return $missing;
        }
        if (!is_file($file)) return $missing;
        $pem = @file_get_contents($file, false, null, 0, 1024 * 1024 + 1);
        if ($pem === false || strlen($pem) > 1024 * 1024
            || !preg_match('~-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----~', $pem, $match)) return $missing;
        // Pass PEM bytes only: OpenSSL also accepts file:// references. Read afresh
        // on each render so a long-lived Telegram poller sees renewed certificates.
        $info = @openssl_x509_parse($match[0]);
        if (empty($info['validTo_time_t'])) return $missing;
        $hostname = strtolower($hostname);
        $ip = @inet_pton($hostname);
        foreach (explode(',', $info['extensions']['subjectAltName'] ?? '') as $entry) {
            $entry = trim($entry);
            $covered = false;
            if ($ip !== false && str_starts_with($entry, 'IP Address:')) {
                $covered = @inet_pton(substr($entry, 11)) === $ip;
            } elseif ($ip === false && str_starts_with($entry, 'DNS:')) {
                $name = strtolower(substr($entry, 4));
                $covered = $name === $hostname || (str_starts_with($name, '*.')
                    && preg_match('~\A[^.]+\.' . preg_quote(substr($name, 2), '~') . '\z~D', $hostname) === 1);
            }
            if ($covered) return ' (ssl: ' . date('Y-m-d H:i:s', (int) $info['validTo_time_t']) . ')';
        }
        return $missing;
    }

    public function exportManagedProtocols(): array
    {
        $out = ['modules' => (new ProtocolModules($this->protocolModulesFile))->read(), 'protocols' => [], 'certificates' => []];
        foreach (ManagedProtocol::NAMES as $protocol => $_) {
            $store = $this->protocolStore($protocol);
            if (!is_file($store->directory() . '/desired.json')) continue;
            $out['protocols'][$protocol] = $snapshot = $store->snapshot();
            if (in_array($protocol, ['anytls', 'tuic', 'masque'], true)) {
                $settings = $snapshot['state']['settings'];
                if (is_file($this->managedCertificatePath($settings['certificate'])) !== is_file($this->managedCertificatePath($settings['private_key']))) {
                    throw new RuntimeException('Не удалось сохранить неполную TLS-пару');
                }
                foreach (['certificate', 'private_key'] as $key) {
                    $path = $settings[$key];
                    $file = $this->managedCertificatePath($path);
                    if (is_file($file)) {
                        $body = file_get_contents($file);
                        if ($body === false || strlen($body) > 1024 * 1024) throw new RuntimeException('Не удалось сохранить TLS-файл');
                        $out['certificates'][$path] = base64_encode($body);
                    }
                }
            }
        }
        return $out;
    }

    private function managedCertificatePath(string $path, bool $create = false): string
    {
        if (!preg_match('~\A/certs/[a-zA-Z0-9_./-]+\z~D', $path) || str_contains($path, '..')) throw new InvalidArgumentException('Неверный путь TLS-файла');
        $root = realpath($this->protocolCertRoot);
        if ($root === false) throw new RuntimeException('Каталог сертификатов недоступен');
        $target = $root . '/' . substr($path, 7);
        $parent = dirname($target);
        // Check existing ancestors before creating directories through a symlink.
        while (!file_exists($parent)) $parent = dirname($parent);
        $resolved = realpath($parent);
        if ($resolved !== $root && !str_starts_with((string) $resolved, $root . '/')) throw new InvalidArgumentException('TLS-файл вне каталога сертификатов');
        if (file_exists($target) && !str_starts_with((string) realpath($target), $root . '/')) throw new InvalidArgumentException('TLS-файл вне каталога сертификатов');
        if ($create && !is_dir(dirname($target)) && !mkdir(dirname($target), 0700, true) && !is_dir(dirname($target))) throw new RuntimeException('Не удалось создать каталог сертификатов');
        return $target;
    }

    public function xraySubscriptionMetadata(array $client, int $index): void
    {
        header('Profile-Update-Interval: 12');
        $info = []; $managed = $this->xrayProtocolUsage($client);
        if (is_file('/config/xray.stats')) {
            $stats = $this->getXrayStats()['users'][$index] ?? null;
            if (is_array($stats) && isset($stats['session']['upload'], $stats['session']['download'])) {
                foreach (['upload', 'download'] as $direction) {
                    $managed[$direction] += max(0, (int) $stats['session'][$direction] + (int) ($stats['global'][$direction] ?? 0));
                }
            }
        }
        if (array_sum($managed)) foreach ($managed as $direction => $bytes) $info[] = "$direction=$bytes";
        if ((int) ($client['traffic'] ?? 0) > 0) $info[] = 'total=' . (int) $client['traffic'];
        if ((int) ($client['time'] ?? 0) > 0) $info[] = 'expire=' . (int) $client['time'];
        if ($info) header('Subscription-Userinfo: ' . implode('; ', $info));
    }

    public function validateManagedBackup(array $data): array
    {
        if (!is_array($data['modules'] ?? null) || !is_array($data['protocols'] ?? null)) throw new InvalidArgumentException('Неверная резервная копия модулей');
        unset($data['modules']['snolc'], $data['protocols']['snolc']);
        if (array_diff_key($data['modules'], ProtocolModules::DEFAULTS)
            || array_diff_key($data['protocols'], ManagedProtocol::NAMES)) throw new InvalidArgumentException('Неверная резервная копия модулей');
        foreach ($data['modules'] as $value) if (!is_bool($value)) throw new InvalidArgumentException('Неверное состояние модуля');
        foreach ($data['protocols'] as $protocol => $snapshot) $this->protocolStore($protocol)->validateSnapshot($snapshot);
        $certificates = $data['certificates'] ?? [];
        if (!is_array($certificates)) throw new InvalidArgumentException('Неверная копия сертификатов');
        $allowed = []; $material = [];
        foreach (['anytls', 'tuic', 'masque'] as $protocol) if (isset($data['protocols'][$protocol])) {
            $settings = $data['protocols'][$protocol]['state']['settings'];
            foreach (['certificate', 'private_key'] as $key) $allowed[$settings[$key]] = true;
            if (isset($certificates[$settings['certificate']]) || isset($certificates[$settings['private_key']])) {
                foreach (['certificate', 'private_key'] as $key) {
                    $path = $settings[$key]; $body = $certificates[$path] ?? null;
                    if (!is_string($body) || strlen($body) > 1400000 || ($material[$path] = base64_decode($body, true)) === false) throw new InvalidArgumentException('Неполная копия TLS-пары');
                    $this->managedCertificatePath($path);
                }
                if (!@openssl_x509_check_private_key($material[$settings['certificate']], $material[$settings['private_key']])) throw new InvalidArgumentException('TLS-сертификат не соответствует ключу');
            }
        }
        if (array_diff_key($certificates, $allowed)) throw new InvalidArgumentException('Посторонний TLS-файл в резервной копии');
        return $material;
    }

    public function importManagedProtocols(array $data, bool $syncUpstreams = true): void
    {
        $material = $this->validateManagedBackup($data);
        unset($data['modules']['snolc'], $data['protocols']['snolc']);
        foreach (['anytls', 'shadowtls'] as $protocol) {
            if (!empty($data['protocols'][$protocol]['state']['settings']['self_hosted'])) {
                $this->prepareProtocolSelfHost();
                break;
            }
        }
        $certificates = [];
        foreach ($material as $path => $body) $certificates[substr($path, 7)] = $body;
        if ($certificates) $this->restoreBackupTree($certificates, $this->protocolCertRoot);
        foreach ($data['protocols'] as $protocol => $snapshot) $this->protocolStore($protocol)->restore($snapshot);
        $modules = new ProtocolModules($this->protocolModulesFile);
        $modules->setMany($data['modules']);
        if ($syncUpstreams) $this->syncManagedUpstreams();
    }

    public function filterProtocolButtons($rows)
    {
        if (!is_array($rows)) return $rows;
        return array_values(array_filter(array_map(function ($row) {
            return array_values(array_filter($row, function ($button) {
                if (($button['callback_data'] ?? '') === '/dnstt') return $this->protocolModuleEnabled('dnstt');
                if (($button['callback_data'] ?? '') === '/telemt') return $this->protocolModuleEnabled('telemt');
                if (preg_match('~^/menu ([a-z0-9]+)$~', $button['callback_data'] ?? '', $m)) {
                    return $this->protocolModuleEnabled($m[1]);
                }
                return true;
            }));
        }, $rows)));
    }

    public function optionalProtocolColumns(array $columns): array
    {
        $keys = ['wg', 'wg1', 'xray', 'naive', 'oc', 'hy', 'tt', 'ovpn', 'l2tp', 'ikev2', 'ad', 'ss', 'dnstt', 'telemt', 'warp'];
        foreach ($keys as $index => $key) {
            if (!$this->protocolModuleEnabled($key)) foreach ($columns as &$column) unset($column[$index]);
            unset($column);
        }
        return array_map('array_values', $columns);
    }

    public function protocolModulesMenu(): void
    {
        $modules = new ProtocolModules($this->protocolModulesFile);
        $settings = $modules->read();
        $text = ["Настройки → Протоколы", 'Отключённые контейнеры не запускаются и не загружаются. Доступы и настройки сохраняются.',
            'Выключатель Shadowsocks отключает также Cloak и simple-tls в его контейнере.',
            'Выключатель TeleMT отключает обычный MTProto и WEB. При ручном Docker ядро останавливается, контейнер остановите вручную.',
            'IKEv2 и L2TP используют один контейнер IPsec. Он нужен, пока включён хотя бы один из них.'];
        $path = dirname($this->protocolModulesFile) . '/protocol-services.status.json';
        $status = is_file($path) ? ManagedProtocol::readJson($path) : [];
        if (($status['settings'] ?? null) !== $settings || empty($status['ok'])) {
            $text[] = 'Ожидается применение настроек службой управления.';
            if (!empty($status['failed_service'])) $text[] = 'Не удалось применить: ' . self::esc($status['failed_service']);
        }
        $buttons = [];
        foreach (ProtocolModules::LABELS as $key => $label) {
            if (isset(ManagedProtocol::NAMES[$key])) continue;
            $blocked = $settings[$key] && !$modules->enabled($key);
            $hint = $blocked ? ($key === 'ipsec' ? ' · IKEv2 и L2TP выключены' : ' · IPsec выключен') : '';
            $buttons[] = [['text' => ($blocked ? '🟡 ' : ($settings[$key] ? '🟢 ' : '🔴 ')) . $label . $hint, 'callback_data' => "/protocolModules $key"]];
        }
        foreach (ManagedProtocol::NAMES as $key => $label) {
            $buttons[] = [['text' => ($settings[$key] ? '🟢 ' : '🔴 ') . $label, 'callback_data' => "/protocol $key"]];
        }
        $buttons[] = [['text' => $this->i18n('back'), 'callback_data' => '/menu config']];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n\n", $text), $buttons);
    }

    public function protocolModulesToggle(string $module): void
    {
        if (!$this->admin) return;
        try {
            $modules = new ProtocolModules($this->protocolModulesFile);
            if (!isset(ProtocolModules::DEFAULTS[$module]) || (isset(ManagedProtocol::NAMES[$module]) && $module !== 'masque')) return;
            if ($module === 'masque') $this->toggleManagedProtocol($module);
            elseif ($module === 'telemt') $this->toggleTelemtService();
            else $modules->toggle($module);
            $this->protocolModulesMenu();
        } catch (Throwable $e) {
            error_log('protocolModulesToggle: ' . get_class($e) . ' at ' . basename($e->getFile()) . ':' . $e->getLine());
            $this->protocolError('Не удалось сохранить настройки протоколов.', '/protocolModules');
        }
    }

    private function toggleManagedProtocol(string $protocol): void
    {
        $this->withLock('protocol-toggle', function () use ($protocol) {
            $store = $this->protocolStore($protocol);
            $state = $store->read();
            $on = !$state['enabled'];
            if ($on && !empty($state['settings']['self_hosted'])) $this->prepareProtocolSelfHost();
            $store->configure([], $on);
            try {
                (new ProtocolModules($this->protocolModulesFile))->set($protocol, $on);
            } catch (Throwable $e) {
                $store->configure([], $state['enabled']);
                throw $e;
            }
            $this->syncManagedUpstreams();
            $this->syncXrayProtocolUsers();
        });
    }

    public function protocolRelayEndpoint(string $protocol, string $name): array
    {
        if (!isset(ManagedProtocol::NAMES[$protocol]) || !preg_match('~\A[\w.\-]{1,32}\z~D', $name)) {
            throw new InvalidArgumentException('Неверный relay');
        }
        $relay = $this->getPacConf()['relays'][$name] ?? null;
        if (!is_array($relay)) throw new InvalidArgumentException('Relay не найден');
        $port = $relay[$protocol . '_port'] ?? null;
        if (!is_string($port) && !is_int($port)) throw new InvalidArgumentException('Порт relay не задан');
        $endpoint = ['host' => $relay[$protocol . '_address'] ?? '', 'port' => (int) self::relayPortInput($port)];
        ManagedProtocol::validateClientEndpoint($endpoint);
        return $endpoint;
    }

    public function protocolRelayPrompt(string $protocol, string $name): void
    {
        if (!$this->admin || !isset(ManagedProtocol::NAMES[$protocol], $this->getPacConf()['relays'][$name])) return;
        $r = $this->send($this->input['chat'], self::esc(ManagedProtocol::NAMES[$protocol])
            . ': адрес relay и внешний порт через пробел, например relay.example.com 443. '
            . '0 — отключить этот протокол на relay. Переадресация на relay настраивается отдельно.',
            $this->input['message_id'], reply: 'Адрес relay и порт');
        $this->stashReply($r, ['start_message' => $this->input['message_id'],
            'callback' => 'protocolRelayReply', 'args' => [$protocol, $name]]);
    }

    public function protocolRelayReply($input, string $protocol, string $name): void
    {
        if (!$this->admin) return;
        try {
            $conf = $this->getPacConf();
            if (!isset(ManagedProtocol::NAMES[$protocol], $conf['relays'][$name])) throw new InvalidArgumentException('Relay не найден');
            $input = trim((string) $input);
            if ($input === '0') {
                unset($conf['relays'][$name][$protocol . '_address'], $conf['relays'][$name][$protocol . '_port']);
            } else {
                $parts = preg_split('/\s+/', $input);
                $endpoint = ['host' => $parts[0], 'port' => count($parts) === 2 ? (int) self::relayPortInput($parts[1]) : 0];
                ManagedProtocol::validateClientEndpoint($endpoint);
                $conf['relays'][$name][$protocol . '_address'] = $endpoint['host'];
                $conf['relays'][$name][$protocol . '_port'] = $endpoint['port'];
            }
            if ($this->setPacConf($conf) === false) throw new RuntimeException('Не удалось сохранить relay');
            $this->relayEdit($name);
        } catch (InvalidArgumentException | RuntimeException $e) {
            $this->protocolError($e->getMessage(), "/relayEdit $name", "/prset $protocol $name");
        }
    }

    public function protocolRelay(string $protocol, string $id, string $key = 'page', string $format = ''): void
    {
        if (!$this->admin) return;
        try {
            $store = $this->protocolStore($protocol);
            if (!$this->protocolModuleEnabled($protocol)) throw new RuntimeException('Протокол отключён');
            $store->profile($id, $protocol === 'masque' ? 'native' : 'mihomo'); // Includes current expiry/quota/revocation checks.
            $relays = [];
            foreach ($this->getPacConf()['relays'] ?? [] as $name => $_) {
                try { $endpoint = $this->protocolRelayEndpoint($protocol, (string) $name); }
                catch (InvalidArgumentException $e) { continue; }
                $relays[(string) $name] = $endpoint;
            }
            $text = [self::esc(ManagedProtocol::NAMES[$protocol]) . ' · relay'];
            $buttons = [];
            $prefix = "/pr $protocol $id";
            if ($key === 'page') {
                if ($format !== '' && !preg_match('/\A[0-9]{1,6}\z/D', $format)) throw new InvalidArgumentException('Неверная страница');
                $page = min((int) $format, max(0, (int) ceil(count($relays) / 20) - 1));
                $text[] = 'Выберите relay. Адрес и порт каждого протокола задаются в его карточке.';
                foreach (array_slice($relays, $page * 20, 20, true) as $name => $endpoint) {
                    $buttons[] = [['text' => $name . ' · ' . $endpoint['host'] . ':' . $endpoint['port'],
                        'callback_data' => $prefix . ' ' . substr(hash('sha256', (string) $name), 0, 16)]];
                }
                $nav = [];
                if ($page > 0) $nav[] = ['text' => '←', 'callback_data' => "$prefix page " . ($page - 1)];
                if (count($relays) > ($page + 1) * 20) $nav[] = ['text' => '→', 'callback_data' => "$prefix page " . ($page + 1)];
                if ($nav) $buttons[] = $nav;
                $buttons[] = [['text' => 'Настроить relay', 'callback_data' => "/prmanage $protocol $id"]];
                $buttons[] = [['text' => $this->i18n('back'), 'callback_data' => "/protocol $protocol user $id"]];
            } else {
                // Stable short keys keep Telegram callbacks below 64 bytes, even
                // for 32-character relay names. Never resolve a stale list index.
                $names = array_keys(array_filter($relays, static fn($name) => substr(hash('sha256', (string) $name), 0, 16) === $key, ARRAY_FILTER_USE_KEY));
                if (count($names) !== 1) throw new InvalidArgumentException('Relay удалён или отключён для этого протокола');
                $name = (string) $names[0]; $endpoint = $relays[$name];
                if ($format !== '') {
                    if (!isset($store->formats()[$format]) && !in_array($format, ['yaml', 'qr'], true)) throw new InvalidArgumentException('Неверный формат');
                    $this->protocolCommand($protocol, in_array($format, ['yaml', 'qr'], true) ? $format : 'export', $id, $format, $name);
                    return;
                }
                $state = $store->read(); $settings = $state['settings'];
                $transport = $protocol === 'tuic' ? 'UDP' : ($protocol === 'masque' ? 'TCP/UDP' : ($protocol === 'mieru' ? $settings['transport'] : 'TCP'));
                $text[] = self::esc($name) . ': <code>' . self::esc($endpoint['host']) . '</code> · ' . $endpoint['port'] . ' ' . $transport;
                $text[] = 'Переадресация на <code>' . self::esc($settings['host']) . '</code> · ' . $settings['port'] . ' ' . $transport . '.';
                if ($protocol !== 'mieru') $text[] = 'SNI: <code>' . self::esc($settings['sni']) . '</code>. Проверка сертификата включена.';
                $text[] = ($protocol === 'mieru' ? 'Relay передаёт зашифрованный поток Mieru.' : 'Relay передаёт зашифрованный поток без завершения TLS.')
                    . ' После изменения адреса или порта обновите подписку либо импортируйте профиль заново.';
                if (isset($store->formats()['uri'])) {
                    $text[] = '<code>' . self::esc($store->profile($id, 'uri', $state, $endpoint)) . '</code>';
                    $buttons[] = [['text' => 'QR · relay', 'callback_data' => "$prefix $key qr"]];
                }
                foreach ($store->formats() as $f => $label) $buttons[] = [['text' => $label . ' · relay', 'callback_data' => "$prefix $key $f"]];
                $buttons[] = [['text' => '🔗 Подписки · relay', 'callback_data' => "/ps $protocol $id $key"]];
                if ($protocol !== 'masque') $buttons[] = [['text' => 'Запись прокси · скопировать', 'callback_data' => "$prefix $key yaml"]];
                if ($domain = $this->getDomain()) {
                    $base = 'https://' . $domain . '/pac' . $this->getHashBot() . '/protocol/' . $protocol . '/' . $state['users'][$id]['token'];
                    foreach ($store->formats() as $f => $label) if (!str_contains($f, 'uri')) {
                        $text[] = '<a href="' . self::esc($base . '/' . $f . '?relay=' . rawurlencode($name)) . '">Подписка ' . self::esc($label) . ' · relay</a>';
                    }
                }
                $buttons[] = [['text' => $this->i18n('back'), 'callback_data' => "$prefix page"]];
            }
            $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $text), $buttons);
        } catch (InvalidArgumentException | RuntimeException $e) {
            $this->protocolError($e->getMessage(), "/protocol $protocol user $id");
        }
    }

    public function protocolCommand(string $protocol, string $action = '', string $id = '', string $format = '', string $relayName = ''): void
    {
        if (!$this->admin) return;
        try {
            $store = $this->protocolStore($protocol);
            if (in_array($protocol, ['anytls', 'shadowtls'], true) && !is_file($store->directory() . '/desired.json')
                && ($this->getPacConf()['domain'] ?? '') !== '') $this->configureProtocolSelfHost($protocol);
            $state = $store->read();
            if ($action === 'add') { $this->xray(); return; }
            if ($id !== '' && isset($state['users'][$id]['xray_source'])) {
                $this->xrayProtocolsMenu($state['users'][$id]['xray_source']); return;
            }
            $endpoint = $relayName === '' ? null : $this->protocolRelayEndpoint($protocol, $relayName);
            $relayKey = $relayName === '' ? '' : substr(hash('sha256', $relayName), 0, 16);
            if ($action === 'relays') { $this->protocolRelay($protocol, $id); return; }
            if ($action === 'page') { $this->protocolMenu($protocol, '', (int) $id); return; }
            if (in_array($action, ['name', 'expires', 'quota', 'rolling', 'settings'], true)) {
                $prompt = match ($action) {
                    'name' => 'Название доступа (до 100 символов):',
                    'expires' => 'Срок: дата и время UTC в формате 2026-10-01 12:00, либо 0 без срока:',
                    'quota' => 'Лимит в ГиБ (например 10 или 0.5), либо 0 без лимита:',
                    'rolling' => 'Квота Mieru: число дней и МиБ через пробел, например 30 10240. Либо 0 без периодической квоты:',
                    'settings' => $protocol === 'mieru' ? 'Адрес сервера, порт и транспорт TCP или UDP через пробел (например vpn.example.com 24445 TCP):'
                        : ($protocol === 'shadowtls' ? 'Адрес VPN, домен сайта прикрытия с TLS 1.3 и отдельный порт через пробел (например vpn.example.com www.microsoft.com 24447):'
                        : 'Адрес сервера, SNI и порт через пробел (например vpn.example.com vpn.example.com 443):'),
                };
                $r = $this->send($this->input['chat'], $prompt, $this->input['message_id'], reply: 'Введите значение');
                $this->stashReply($r, ['start_message' => $this->input['message_id'],
                    'callback' => 'protocolReply', 'args' => [$protocol, $action, $id]]);
                return;
            }
            if ($action === 'toggle') {
                $this->toggleManagedProtocol($protocol);
            } elseif ($action === 'auto') {
                if (in_array($protocol, ['anytls', 'shadowtls'], true)) $this->prepareProtocolSelfHost();
                $this->configureProtocolSelfHost($protocol);
                $this->syncManagedUpstreams();
            } elseif ($action === 'user-toggle') {
                if (!isset($state['users'][$id])) throw new RuntimeException('Доступ не найден');
                $store->user($id, ['enabled' => !$state['users'][$id]['enabled']]);
            } elseif (in_array($action, ['delete', 'rotate', 'rotate-outer', 'rotate-inner', 'reset'], true)) {
                $store->user($id, [], $action);
                if ($action === 'delete') $id = '';
            } elseif ($action === 'export') {
                $document = $store->profileDocument($id, $format, endpoint: $endpoint);
                $this->protocolOutput = true;
                try {
                    $this->sendFile($this->input['chat'], new CURLStringFile($document['body'],
                        "$protocol-$format" . ($relayKey === '' ? '' : '-relay-' . $relayKey) . '.' . $document['extension'], $document['mime']));
                } finally { $this->protocolOutput = false; }
                return;
            } elseif ($action === 'yaml') {
                $proxies = $store->profile($id, 'mihomo', endpoint: $endpoint)['proxies'];
                $proxies[0]['name'] = $protocol . '-' . $id . ($relayKey === '' ? '' : '-relay-' . $relayKey);
                $yaml = yaml_emit($proxies, YAML_UTF8_ENCODING);
                if ($yaml === false) throw new RuntimeException('Не удалось сформировать YAML');
                $yaml = preg_replace('~\A---\r?\n|\r?\n\.\.\.(?:\r?\n)?\z~', '', $yaml);
                $yaml = preg_replace('~^~m', '  ', rtrim($yaml)) . "\n";
                $text = 'Вставьте этот элемент в существующий раздел <code>proxies:</code> конфигурации Mihomo в XKeen UI. '
                    . 'Добавьте имя <code>' . self::esc($proxies[0]['name']) . '</code> в нужную группу <code>proxy-groups</code>. '
                    . 'Порты, DNS и правила маршрутизации роутера сохраняются.'
                    . "\n\n<pre><code class=\"language-yaml\">" . self::esc($yaml) . '</code></pre>';
                if ($this->messageTextLength($text) > 4096) {
                    $this->protocolOutput = true;
                    try { $this->sendFile($this->input['chat'], new CURLStringFile($yaml, "$protocol-proxy.yaml", 'application/yaml')); }
                    finally { $this->protocolOutput = false; }
                    $text = 'Запись прокси слишком длинная для сообщения и отправлена файлом. Вставьте её в раздел <code>proxies:</code> и добавьте имя прокси в нужную группу. Сохраните файл до следующего нажатия.';
                }
                $this->update($this->input['chat'], $this->input['message_id'], $text, [[
                    ['text' => $this->i18n('back'), 'callback_data' => $relayKey === '' ? "/protocol $protocol user $id" : "/pr $protocol $id $relayKey"],
                ]]);
                return;
            } elseif ($action === 'qr') {
                $this->protocolOutput = true;
                try { $this->sendQr($protocol . '-' . $id . ($relayKey === '' ? '' : '-relay-' . $relayKey), $store->profile($id, 'uri', endpoint: $endpoint)); }
                finally { $this->protocolOutput = false; }
                return;
            } elseif ($action === 'egress') {
                $on = $state['settings']['egress'] === 'direct';
                $source = match ($protocol) { 'mieru' => '10.10.0.23', 'tuic' => '10.10.0.24', 'shadowtls' => '10.10.0.25', 'masque' => '10.10.0.27', default => '10.10.0.22' };
                if ($on && !str_contains($this->ssh(self::warpSocksAllowCmd($source, true), 'wp'), self::SS_ACL_PRESENT)) {
                    throw new RuntimeException('Не удалось разрешить выход через WARP');
                }
                $store->configure(['egress' => $on ? 'warp' : 'direct']);
                if (!$on) $this->ssh(self::warpSocksAllowCmd($source, false), 'wp');
            } elseif ($action === 'udp-mode' && $protocol === 'tuic') {
                $options = $state['settings']['options'];
                if (!empty($options['client']['udp_over_stream'])) {
                    $options['client']['udp_over_stream'] = false;
                    $mode = 'native';
                } else $mode = $state['settings']['udp_mode'] === 'native' ? 'quic' : 'native';
                $store->configure(['udp_mode' => $mode, 'options' => $options]);
            } elseif ($action === 'udp-mode' && $protocol === 'shadowtls') {
                $store->configure(['udp_over_tcp' => !$state['settings']['udp_over_tcp']]);
            } elseif ($action === 'congestion' && $protocol === 'tuic') {
                $modes = ['cubic', 'new_reno', 'bbr'];
                $store->configure(['congestion' => $modes[(array_search($state['settings']['congestion'], $modes, true) + 1) % 3]]);
            } elseif (!in_array($action, ['', 'user'], true)) {
                throw new RuntimeException('Неизвестное действие');
            }
            $this->protocolMenu($protocol, $id);
        } catch (Throwable $e) {
            // Messages from storage validators are bounded and never contain credentials.
            $this->protocolError($e instanceof InvalidArgumentException || $e instanceof RuntimeException
                ? $e->getMessage() : 'Не удалось выполнить действие протокола', "/protocol $protocol");
        }
    }

    public function protocolReply($input, string $protocol, string $action, string $id = ''): void
    {
        if (!$this->admin) return;
        try {
            $store = $this->protocolStore($protocol);
            $input = trim((string) $input);
            if ($action === 'add') { $this->xray(); return; }
            if (isset($store->read()['users'][$id]['xray_source'])) {
                $this->xrayProtocolsMenu($store->read()['users'][$id]['xray_source']); return;
            }
            if ($action === 'name') $store->user($id, ['name' => $input]);
            elseif ($action === 'quota') {
                if (!preg_match('/\A\d+(?:\.\d{1,3})?\z/D', $input) || (float) $input > 1000000) throw new InvalidArgumentException('Неверный лимит');
                $store->user($id, ['quota' => (float) $input == 0 ? null : (int) round((float) $input * 1073741824)]);
            } elseif ($action === 'rolling') {
                if ($protocol !== 'mieru' || ($input !== '0' && !preg_match('/\A([0-9]{1,3}) ([0-9]{1,10})\z/D', $input, $m))) throw new InvalidArgumentException('Нужны дни и МиБ');
                $store->user($id, ['rolling_quota' => $input === '0' ? null : ['days' => (int) $m[1], 'megabytes' => (int) $m[2]]]);
            } elseif ($action === 'expires') {
                $time = DateTimeImmutable::createFromFormat('!Y-m-d H:i', $input, new DateTimeZone('UTC'));
                if ($input !== '0' && (!$time || $time->format('Y-m-d H:i') !== $input)) throw new InvalidArgumentException('Неверная дата UTC');
                $store->user($id, ['expires' => $input === '0' ? null : $time->getTimestamp()]);
            } elseif ($action === 'settings') {
                $parts = preg_split('/\s+/', $input);
                if ($protocol === 'mieru') {
                    if (count($parts) !== 3 || !preg_match('/\A[0-9]+\z/D', $parts[1]) || (int) $parts[1] < 1024) throw new InvalidArgumentException('Нужны адрес, порт 1024–65535 и TCP/UDP');
                    $settings = ['host' => $parts[0], 'sni' => '', 'port' => (int) $parts[1], 'transport' => strtoupper($parts[2])];
                } else {
                    if (count($parts) !== 3 || !preg_match('/\A[0-9]+\z/D', $parts[2])) throw new InvalidArgumentException('Нужны адрес, SNI и порт');
                    $settings = ['host' => $parts[0], 'sni' => $parts[1], 'port' => (int) $parts[2]];
                }
                if (in_array($protocol, ['anytls', 'shadowtls'], true)) $settings['self_hosted'] = false;
                if ($protocol === 'anytls') $settings['cover_host'] = '';
                $store->configure($settings + ['blocked_ips' => filter_var($this->ip, FILTER_VALIDATE_IP) ? [$this->ip] : []]);
                $this->syncManagedUpstreams();
            } else throw new InvalidArgumentException('Неизвестное поле');
            $this->protocolMenu($protocol, $id);
        } catch (Throwable $e) {
            $this->protocolError('Не удалось сохранить: ' . ($e instanceof InvalidArgumentException ? $e->getMessage() : 'проверьте состояние и права записи'),
                $id === '' ? "/protocol $protocol" : "/protocol $protocol user $id", rtrim("/protocol $protocol $action $id"));
        }
    }

    public function protocolMenu(string $protocol, string $id = '', int $page = 0): void
    {
        $store = $this->protocolStore($protocol);
        $s = $store->read(); $status = $store->status(); $usage = $store->usage();
        $title = ManagedProtocol::NAMES[$protocol];
        $phase = !$status['stale'] && !empty($status['running']) ? 'работает' : 'остановлен';
        if ($s['enabled'] && !$status['stale'] && ($status['phase'] ?? '') === 'idle') $phase = 'ожидает активного доступа';
        if ($s['enabled'] && !$status['stale'] && ($status['phase'] ?? '') === 'cover_only') $phase = 'сайт прикрытия работает; нет активных доступов';
        if ($status['stale'] && $s['enabled']) $phase = 'нет свежего статуса';
        if (($status['revision'] ?? null) !== $s['revision']) $phase .= '; ожидается применение';
        if ($s['enabled'] && !$this->protocolPortApplied($protocol, $s)) $phase .= '; внешний маршрут ещё не применён';
        if (!empty($status['error'])) $phase .= '; ' . self::serviceErrorText((string) $status['error']);
        $text = [self::esc($title) . ' — ' . $phase];
        $buttons = [];
        if ($id !== '') {
            $u = $s['users'][$id] ?? null;
            if (!$u) throw new RuntimeException('Доступ не найден');
            $bytes = $usage['users'][$id] ?? null;
            $text[] = 'Доступ: ' . AccessPolicy::reason($u, AccessPolicy::bytes($u, $bytes), time());
            if ($u['quota'] !== null && AccessPolicy::bytes($u, $bytes) !== null) $text[] = 'Осталось: ' . $this->getBytes(max(0, $u['quota'] - AccessPolicy::bytes($u, $bytes)));
            array_push($text, ...$this->accessPolicySummary($u));
            $buttons[] = [['text' => 'Календарь и уведомления', 'callback_data' => "/ap $protocol $id"]];
            $text[] = self::esc($u['name']) . ($store->allowed($u, $id, $usage) ? ' 🟢' : ' 🔴');
            $text[] = $bytes ? 'Отправлено: ' . $this->protocolBytes($bytes['upload']) . '; получено: ' . $this->protocolBytes($bytes['download'])
                : 'Статистика ещё не получена';
            if ($bytes && time() - ($status['stats_time'] ?? 0) > 15) $text[] = 'Счётчики устарели';
            $text[] = 'Лимит: ' . ($u['quota'] === null ? 'без лимита' : $this->protocolBytes($u['quota']));
            $text[] = 'Срок UTC: ' . ($u['expires'] === null ? 'без срока' : gmdate('Y-m-d H:i', $u['expires']));
            if ($protocol === 'mieru') {
                $q = $u['rolling_quota'] ?? null;
                $text[] = $q ? 'Квота ядра за последние ' . $q['days'] . ' дн.: ' . $q['megabytes'] . ' МиБ; расход: ' . $this->protocolBytes($bytes['rolling'] ?? 0)
                    : 'Периодическая квота ядра: без ограничения';
                $text[] = 'Сброс общего расхода не сбрасывает историю периодической квоты.';
                $buttons[] = [['text' => 'Квота за период', 'callback_data' => "/protocol $protocol rolling $id"]];
            }
            $text[] = 'Отзыв доступа завершает соединения этого протокола. После изменения параметров обновите профиль.';
            $text[] = 'Файлы и QR временные: сохраните их до следующего нажатия в этом меню.';
            if ($s['enabled'] && $store->allowed($u, $id, $usage)) {
                if (isset($store->formats()['uri'])) {
                    $uri = $store->profile($id, 'uri');
                    if (strlen($uri) < 1500) $text[] = '<code>' . self::esc($uri) . '</code>';
                    $buttons[] = [['text' => 'QR', 'callback_data' => "/protocol $protocol qr $id"]];
                }
                foreach ($store->formats() as $format => $label) {
                    $buttons[] = [['text' => $label, 'callback_data' => "/protocol $protocol export $id $format"]];
                }
                if ($protocol !== 'masque') $buttons[] = [['text' => 'Запись прокси · скопировать', 'callback_data' => "/protocol $protocol yaml $id"]];
                $buttons[] = [['text' => '🔗 Relay', 'callback_data' => "/protocol $protocol relays $id"]];
                $buttons[] = [['text' => '🔗 Подписки', 'callback_data' => "/ps $protocol $id"]];
                $domain = $this->getDomain();
                if ($domain) {
                    $base = 'https://' . $domain . '/pac' . $this->getHashBot() . '/protocol/' . $protocol . '/' . $u['token'];
                    foreach ($store->formats() as $format => $label) if (!str_contains($format, 'uri')) {
                        $text[] = '<a href="' . self::esc($base . '/' . $format) . '">' . ($format === 'native' ? 'Загрузить ' : 'Подписка ') . self::esc($label) . '</a>';
                    }
                }
            }
            foreach (['name' => 'Переименовать', 'user-toggle' => $u['enabled'] ? 'Отключить доступ' : 'Включить доступ',
                'rotate' => 'Сменить секрет', 'expires' => 'Срок', 'quota' => 'Лимит', 'reset' => 'Сбросить расход', 'delete' => 'Удалить'] as $action => $label) {
                $buttons[] = [['text' => $label, 'callback_data' => "/protocol $protocol $action $id"]];
            }
            if ($protocol === 'shadowtls') foreach (['rotate-outer' => 'Сменить пароль ShadowTLS', 'rotate-inner' => 'Сменить личный ключ SS'] as $action => $label) {
                $buttons[] = [['text' => $label, 'callback_data' => "/protocol $protocol $action $id"]];
            }
            $buttons[] = $this->menuHelpButton('p_' . $protocol, $id);
            $buttons[] = [['text' => $this->i18n('back'), 'callback_data' => "/protocol $protocol"]];
        } else {
            $buttons[] = [['text' => 'Диагностика', 'callback_data' => "/diag $protocol"]];
            $text[] = self::esc($s['settings']['host'] . ':' . $s['settings']['port'] . ($protocol === 'mieru' ? ' · ' . $s['settings']['transport'] : ' · SNI ' . $s['settings']['sni']));
            if (!empty($s['settings']['self_hosted'])) $text[] = 'Прикрытие собственным сайтом: https://' . self::esc($protocol === 'anytls' ? $s['settings']['cover_host'] : $s['settings']['sni']) . '. Домен берётся из настроек этого сервера.';
            if ($protocol === 'anytls' && !empty($s['settings']['self_hosted'])) $text[] = 'Имя поддомена формируется автоматически. Запись DNS (A/AAAA/CNAME или wildcard) должна указывать на этот сервер, а сертификат TLS — включать это имя.';
            $text[] = $protocol === 'mieru' ? 'Без TLS; транспорт TCP/UDP. Клиент: Mihomo или нативный Mieru.'
                : ($protocol === 'shadowtls' ? 'Прикрытие: сайт с TLS 1.3 на указанном SNI.'
                : 'Для TLS требуется действительный сертификат на указанное имя. После добавления имени обновите SSL в настройках.');
            if ($protocol === 'masque') $text[] = 'HTTP/3 (UDP) и HTTP/2 (TCP). Клиент: Xray 26.9.30+.';
            if ($protocol === 'tuic') {
                $text[] = 'TUIC v5 требует доступного UDP-порта. Блокировка UDP прерывает и TCP, и UDP приложений. Проверка TLS включена. 0-RTT: '
                    . (!empty($s['settings']['options']['client']['zero_rtt_handshake']) ? 'включён.' : 'выключен.');
                $buttons[] = [['text' => 'UDP: ' . (!empty($s['settings']['options']['client']['udp_over_stream']) ? 'over-stream' : $s['settings']['udp_mode']), 'callback_data' => "/protocol $protocol udp-mode"]];
                $buttons[] = [['text' => 'Congestion: ' . $s['settings']['congestion'], 'callback_data' => "/protocol $protocol congestion"]];
            }
            if ($protocol === 'shadowtls') {
                $text[] = $s['settings']['udp_over_tcp'] ? 'UDP передаётся только внутри TCP-туннеля (UoT v2).' : 'Только TCP. UDP явно отклоняется.';
                $buttons[] = [['text' => 'UDP через TCP: ' . ($s['settings']['udp_over_tcp'] ? 'включён' : 'выключен'), 'callback_data' => "/protocol $protocol udp-mode"]];
            }
            $buttons[] = [['text' => $s['enabled'] ? 'Отключить сервис' : 'Включить сервис', 'callback_data' => "/protocol $protocol toggle"]];
            $buttons[] = [['text' => ($protocol === 'mieru' ? 'Адрес / порт / транспорт' : 'Адрес / SNI / порт'), 'callback_data' => "/protocol $protocol settings"]];
            if (in_array($protocol, ['anytls', 'shadowtls', 'tuic', 'masque'], true)) $buttons[] = [['text' => in_array($protocol, ['tuic', 'masque'], true) ? 'Использовать домен сервера' : 'Прикрытие своим сайтом · авто', 'callback_data' => "/protocol $protocol auto"]];
            $buttons[] = [['text' => 'Выход: ' . $s['settings']['egress'], 'callback_data' => "/protocol $protocol egress"]];
            if ($s['settings']['egress'] === 'warp') {
                $text[] = 'Выход через WARP передаёт TCP и поддерживаемый этим протоколом UDP. Переключатели UDP сохраняют своё действие. При отказе WARP прямой обход не включается.';
            }
            $buttons[] = [['text' => 'Дополнительные настройки', 'callback_data' => "/po $protocol"]];
            if (in_array($protocol, ['anytls', 'shadowtls'], true)) {
                $buttons[] = [['text' => 'TLS fingerprint: ' . ($s['settings']['options']['client']['fingerprint'] ?? 'default'),
                    'callback_data' => "/pf $protocol"]];
            }
            $text[] = 'Доступы и лимиты связаны с VLESS. Профили: карточка пользователя → Отдельные подключения.';
            $text[] = 'Изменение настроек сервера перезапускает его соединения.';
            $buttons[] = [['text' => 'Пользователи и готовые подписки', 'callback_data' => '/xray']];
            $buttons[] = [['text' => 'Relay для подписок', 'callback_data' => "/prmanage $protocol"]];
            $legacy = array_filter($s['users'], static fn($u) => !isset($u['xray_source']));
            if ($legacy) $text[] = 'Ниже — ранее созданные отдельные доступы. Их настройки и старые ссылки сохранены для действующих клиентов.';
            if ($legacy) $buttons[] = [['text' => 'Групповые действия · отдельные доступы', 'callback_data' => "/abstart $protocol"]];
            $last = max(0, (int) ceil(count($legacy) / 20) - 1); $page = min(max(0, $page), $last);
            foreach (array_slice($legacy, $page * 20, 20, true) as $uid => $user) $buttons[] = [['text' => mb_substr($user['name'], 0, 45), 'callback_data' => "/protocol $protocol user $uid"]];
            $navigation = [];
            if ($page > 0) $navigation[] = ['text' => '←', 'callback_data' => "/protocol $protocol page " . ($page - 1)];
            if ($page < $last) $navigation[] = ['text' => '→', 'callback_data' => "/protocol $protocol page " . ($page + 1)];
            if ($navigation) $buttons[] = $navigation;
            $buttons[] = $this->menuHelpButton('p_' . $protocol, $page > 0 ? 'page_' . $page : '');
            $buttons[] = [['text' => $this->i18n('back'), 'callback_data' => '/protocolModules']];
        }
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n\n", $text), $buttons);
    }

    private function protocolBytes(int $bytes): string { return number_format($bytes / 1073741824, 3, '.', '') . ' ГиБ'; }

    public function reconcileManagedUpstreams(): void
    {
        if (is_file($this->protocolStore('anytls')->directory() . '/desired.json')) $this->syncManagedUpstreams();
    }

    public function syncManagedUpstreams(): void
    {
        $path = $this->upstreamFile;
        if (!is_file($path)) return;
        $s = $this->protocolStore('anytls')->read();
        $sni = $s['settings']['sni'];
        if ($sni !== '' && (!ManagedProtocol::hostname($sni) || filter_var($sni, FILTER_VALIDATE_IP))) return;
        $pac = $this->getPacConf();
        $reserved = array_merge([(string) ($pac['domain'] ?? '')], $pac['domain_aliases'] ?? []);
        $conf = file_get_contents($path);
        preg_match_all('~^\s*([^#\s;]+)\s+(?:reality|naive|ocserv)\s*;~m', $conf, $matches);
        $reserved = array_merge($reserved, $matches[1]);
        if ($s['enabled'] && in_array(strtolower($sni), array_map('strtolower', $reserved), true)) {
            throw new RuntimeException('Это SNI уже используется другим сервисом');
        }
        $body = $s['enabled'] && $sni !== '' ? "$sni anytls_bridge;" : '# disabled';
        if (preg_match_all('/^\s*#anytls\s*$/m', $conf) !== 2
            || !$this->editUpstream(fn($conf) => self::upstreamReplace($conf, '#anytls', $body))) {
            throw new RuntimeException('Маршрут AnyTLS не применён. Проверьте миграцию и доступность NGINX');
        }
    }

    /** Validate outside the stable lock; compare before replacing a concurrent edit. */
    public function editUpstream(callable $edit): bool
    {
        return $this->editProtocolProxyConfig($this->upstreamFile, 'up', $edit);
    }

    private function editProtocolProxyConfig(string $path, string $service, callable $edit): bool
    {
        if (!is_file($path)) return false;
        $lock = @fopen(dirname($path) . '/' . pathinfo($path, PATHINFO_FILENAME) . '.lock', 'c');
        if (!$lock) return false;
        $write = fn(string $body): bool => $this->backupWriteInPlace($path, $body);
        try {
            for ($attempt = 0; $attempt < 4; $attempt++) {
                if (!flock($lock, LOCK_EX)) return false;
                $before = file_get_contents($path);
                flock($lock, LOCK_UN);
                $after = $edit($before);
                if ($before === $after) return true;
                $temporary = ($service === 'ng' ? '/etc/nginx/protocol-validation-' : '/tmp/upstream-') . bin2hex(random_bytes(8)) . '.conf';
                try {
                    // exec-запрос SSH ограничен размером пакета. Конфиг после
                    // base64 уже превышает этот предел; передаём частями,
                    // кратными четырём, и проверяем каждую запись до nginx -t.
                    foreach (str_split(base64_encode($after), 12000) as $part => $chunk) {
                        $cmd = 'umask 077; ' . ($part === 0 ? 'set -C; ' : '')
                            . 'printf %s ' . escapeshellarg($chunk) . ' | base64 -d '
                            . ($part === 0 ? '> ' : '>> ') . $temporary . ' && printf VPNBOT_STAGED';
                        if (trim($this->ssh($cmd, $service)) !== 'VPNBOT_STAGED') return false;
                    }
                    if (!str_contains($this->ssh('nginx -t -c ' . $temporary
                        . ' >/dev/null 2>&1 && printf VPNBOT_VALID', $service), 'VPNBOT_VALID')) return false;
                } finally {
                    $this->ssh('rm -f -- ' . $temporary, $service);
                }
                if (!flock($lock, LOCK_EX)) return false;
                if (file_get_contents($path) !== $before) { flock($lock, LOCK_UN); continue; }
                $ok = $write($after);
                if (!$ok) $write($before);
                flock($lock, LOCK_UN);
                if (!$ok) return false;
                if (str_contains($this->ssh('nginx -t >/dev/null 2>&1 && nginx -s reload >/dev/null 2>&1 && printf VPNBOT_APPLIED', $service), 'VPNBOT_APPLIED')) return true;
                if (!flock($lock, LOCK_EX)) return false;
                if (file_get_contents($path) === $after) $write($before);
                flock($lock, LOCK_UN);
                $this->ssh('nginx -t >/dev/null 2>&1 && nginx -s reload >/dev/null 2>&1', $service);
                return false;
            }
            return false;
        } finally { flock($lock, LOCK_UN); fclose($lock); }
    }

    public function protocolSubscriptions(string $protocol, string $id, string $relayKey = 'direct', string $action = ''): void
    {
        if (!$this->admin) return;
        try {
            $store = $this->protocolStore($protocol); $state = $store->read();
            if (!$this->protocolModuleEnabled($protocol)) throw new RuntimeException('Сервис выключен');
            $store->profile($id, $protocol === 'masque' ? 'native' : 'mihomo', $state); // Same access checks as every export.
            if ($protocol === 'masque' && $action === 'provider') throw new InvalidArgumentException('Этот протокол не поддерживается Mihomo provider');
            $domain = $this->getDomain();
            if (!$domain) throw new RuntimeException('Сначала настройте домен и SSL');
            $relay = '';
            if ($relayKey !== 'direct') {
                $matches = [];
                foreach (array_keys($this->getPacConf()['relays'] ?? []) as $name) {
                    if (substr(hash('sha256', (string) $name), 0, 16) === $relayKey) $matches[] = (string) $name;
                }
                if (count($matches) !== 1) throw new InvalidArgumentException('Relay не найден');
                $relay = $matches[0]; $this->protocolRelayEndpoint($protocol, $relay);
            }
            $base = 'https://' . $domain . '/pac' . $this->getHashBot() . '/protocol/' . $protocol . '/' . $state['users'][$id]['token'];
            $query = $relay === '' ? '' : '?relay=' . rawurlencode($relay);
            $name = $protocol . '-' . $id . ($relay === '' ? '' : '-' . $relayKey);
            $text = [self::esc(ManagedProtocol::NAMES[$protocol] . ' · подписки' . ($relay === '' ? '' : ' · relay ' . $relay))];
            if ($action === 'provider') {
                $provider = [
                    'proxy-providers' => [$name => ['type' => 'http', 'url' => $base . '/mihomo' . $query,
                        'path' => './proxy_providers/' . $name . '.yaml', 'interval' => 3600, 'proxy' => 'DIRECT', 'size-limit' => 1048576]],
                    'proxy-groups' => [['name' => $name . '-group', 'type' => 'select', 'use' => [$name]]],
                ];
                $yaml = preg_replace('/\A---\s*\n|\n\.\.\.\s*\z/', '', yaml_emit($provider, YAML_UTF8_ENCODING));
                $text[] = 'Добавьте эти записи в разделы YAML Mihomo / XKeen UI. Если раздел уже существует, объедините записи. В правилах выберите созданную группу. Provider загружает только список прокси в YAML раз в час; порты, DNS и правила вашего клиента сохраняются.';
                $text[] = '<pre><code class="language-yaml">' . self::esc($yaml) . '</code></pre>';
            } else {
                foreach ($store->formats($state) as $format => $label) if (!str_contains($format, 'uri')) {
                    $text[] = self::esc($label) . ":\n<code>" . self::esc($base . '/' . $format . $query) . '</code>';
                }
                $text[] = 'Личные ссылки: не публикуйте их. После изменения параметров обновите подписку или скачайте профиль заново. Инструкция — в справке.';
            }
            $back = $relay === '' ? "/protocol $protocol user $id" : "/pr $protocol $id $relayKey";
            $buttons = $action === '' && $protocol !== 'masque' ? [[['text' => 'Подключить provider YAML', 'callback_data' => "/ps $protocol $id $relayKey provider"]]] : [];
            if ($action === '') $buttons[] = $this->menuHelpButton('ps_' . $protocol, $id . '.' . $relayKey);
            $buttons[] = [['text' => $this->i18n('back'), 'callback_data' => $action === '' ? $back : "/ps $protocol $id $relayKey"]];
            $this->update($this->input['chat'], $this->input['message_id'], implode("\n\n", $text), $buttons);
        } catch (InvalidArgumentException | RuntimeException $e) {
            $this->protocolError($e->getMessage(), "/protocol $protocol user $id");
        }
    }

    public function protocolMachine(string $protocol, string $token, string $format): void
    {
        $this->subSecurityHeaders();
        try {
            $store = $this->protocolStore($protocol); $s = $store->read(); $id = null;
            if (!isset($store->formats($s)[$format])) { $this->subRateLimit('', 'miss'); http_response_code(404); return; }
            foreach ($s['users'] as $uid => $u) if (hash_equals($u['token'], $token)) { $id = $uid; break; }
            if ($id === null || ($protocol !== 'masque' && isset($s['users'][$id]['xray_source'])) || !$this->protocolModuleEnabled($protocol) || !$s['enabled']) {
                $this->subRateLimit('', 'miss'); http_response_code(404); return;
            }
            $this->subRateLimit($protocol . ':' . $id);
            if ($protocol === 'masque' && isset($s['users'][$id]['xray_source'])) {
                $this->syncXrayProtocolUsers();
                $s = $store->read();
            }
            if (!isset($s['users'][$id]) || !hash_equals($s['users'][$id]['token'], $token)
                || !$s['enabled'] || !$store->allowed($s['users'][$id], $id)) {
                http_response_code(404); return;
            }
            $endpoint = null;
            if (array_key_exists('relay', $_GET)) {
                try {
                    if (!is_string($_GET['relay'])) throw new InvalidArgumentException('Неверный relay');
                    $endpoint = $this->protocolRelayEndpoint($protocol, $_GET['relay']);
                } catch (InvalidArgumentException $e) {
                    http_response_code(404); return;
                }
            }
            if (!$this->processHwidRequest(['id' => $protocol . ':' . $id, 'hwid_limit' => 0])) return;
            $status = $store->status();
            if ($status['stale'] || empty($status['running']) || ($status['revision'] ?? null) !== $s['revision']
                || !$this->protocolPortApplied($protocol, $s)) {
                throw new RuntimeException('Состояние ещё не применено');
            }
            $document = $store->profileDocument($id, $format, $s, $endpoint);
            $u = $s['users'][$id]; $usage = $store->usage();
            header('Profile-Title: base64:' . base64_encode($u['name']));
            header('Profile-Update-Interval: 12');
            $info = [];
            if (isset($usage['users'][$id]) && time() - ($status['stats_time'] ?? 0) <= 15) {
                $info[] = 'upload=' . (int) $usage['users'][$id]['upload'];
                $info[] = 'download=' . (int) $usage['users'][$id]['download'];
            }
            if ($u['quota'] !== null) $info[] = 'total=' . $u['quota'];
            if ($u['expires'] !== null) $info[] = 'expire=' . $u['expires'];
            if ($info) header('Subscription-Userinfo: ' . implode('; ', $info));
            header('Content-Type: ' . $document['mime'] . '; charset=utf-8');
            echo $document['body'];
        } catch (Throwable $e) {
            http_response_code(503);
            header('Retry-After: 15');
            echo 'Данные протокола временно недоступны';
        }
    }
}
