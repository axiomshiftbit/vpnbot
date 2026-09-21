<?php

/** Independent state for one protocol. No IDs or credentials are shared with Xray. */
final class ManagedProtocol
{
    public const NAMES = ['anytls' => 'AnyTLS', 'mieru' => 'Mieru', 'tuic' => 'TUIC v5', 'shadowtls' => 'ShadowTLS v3 + SS'];

    public function formats(): array
    {
        if (in_array($this->protocol, ['tuic', 'shadowtls'], true)) return ['singbox' => 'sing-box', 'mihomo' => 'mihomo'];
        return $this->protocol === 'mieru'
            ? ['native' => 'mieru JSON', 'native-uri' => 'mieru:// TXT', 'uri' => 'mierus:// TXT', 'mihomo' => 'mihomo']
            : ['singbox' => 'sing-box', 'mihomo' => 'mihomo', 'uri' => 'Ссылка TXT'];
    }

    public function __construct(public readonly string $protocol, public readonly string $root = '/config/protocols')
    {
        if (!isset(self::NAMES[$protocol])) throw new InvalidArgumentException('Неизвестный протокол');
    }

    public function directory(): string { return $this->root . '/' . $this->protocol; }

    public function defaults(): array
    {
        $state = ['schema' => 1, 'protocol' => $this->protocol, 'revision' => 0, 'enabled' => false,
            'settings' => ['host' => '', 'sni' => '', 'port' => 443, 'listen_port' => 8443,
                'dns' => '1.1.1.1', 'egress' => 'direct', 'blocked_ips' => [],
                'certificate' => '/certs/cert_public', 'private_key' => '/certs/cert_private'],
            'users' => []];
        if (in_array($this->protocol, ['anytls', 'shadowtls'], true)) $state['settings']['self_hosted'] = false;
        if ($this->protocol === 'anytls') $state['settings']['cover_host'] = '';
        if ($this->protocol === 'mieru') {
            $state['settings']['port'] = $state['settings']['listen_port'] = 24445;
            $state['settings']['transport'] = 'TCP';
        }
        if ($this->protocol === 'tuic') {
            $state['settings']['port'] = $state['settings']['listen_port'] = 9443;
            $state['settings']['udp_mode'] = 'native';
            $state['settings']['congestion'] = 'cubic';
        }
        if ($this->protocol === 'shadowtls') {
            $state['settings']['port'] = $state['settings']['listen_port'] = 24447;
            $state['settings']['handshake_port'] = 443;
            $state['settings']['ss_server_key'] = '';
            $state['settings']['udp_over_tcp'] = false;
        }
        return $state;
    }

    public static function readJson(string $path): array
    {
        $raw = @file_get_contents($path);
        if ($raw === false) throw new RuntimeException('Не удалось прочитать состояние протокола');
        try { $value = json_decode($raw, true, 512, JSON_THROW_ON_ERROR); }
        catch (JsonException $e) { throw new RuntimeException('Повреждён JSON состояния протокола'); }
        if (!is_array($value)) throw new RuntimeException('Неверный формат состояния протокола');
        return $value;
    }

    public function read(): array
    {
        $path = $this->directory() . '/desired.json';
        if (!file_exists($path)) return $this->defaults();
        $state = self::readJson($path);
        $this->validate($state);
        // Old saved states remain manual until the administrator selects auto setup.
        foreach (['self_hosted', 'cover_host'] as $key) {
            if (array_key_exists($key, $this->defaults()['settings']) && !array_key_exists($key, $state['settings'])) {
                $state['settings'][$key] = $this->defaults()['settings'][$key];
            }
        }
        return $state;
    }

    public static function writeJson(string $path, array $value): void
    {
        if (isset($value['protocol'], $value['users'])) $value['users'] = (object) $value['users'];
        $json = json_encode($value, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR) . "\n";
        $tmp = $path . '.' . bin2hex(random_bytes(8)) . '.tmp';
        $old = umask(0077);
        $file = @fopen($tmp, 'x');
        umask($old);
        if (!$file) throw new RuntimeException('Не удалось создать файл состояния');
        try {
            if (fwrite($file, $json) !== strlen($json) || !fflush($file) || !fsync($file)) {
                throw new RuntimeException('Не удалось записать состояние');
            }
            if (!@rename($tmp, $path)) throw new RuntimeException('Не удалось заменить состояние');
            $directory = @fopen(dirname($path), 'r');
            if (!$directory) throw new RuntimeException('Не удалось открыть каталог состояния');
            try { if (!fsync($directory)) throw new RuntimeException('Не удалось синхронизировать каталог состояния'); }
            finally { fclose($directory); }
        } finally {
            fclose($file);
            if (is_file($tmp)) unlink($tmp);
        }
    }

    /** The stable lock covers the entire read/modify/rename, never an SSH call. */
    public function change(callable $edit): array
    {
        $dir = $this->directory();
        if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new RuntimeException('Не удалось создать каталог протокола');
        }
        if (!is_dir($dir . '/runtime') && !@mkdir($dir . '/runtime', 0700) && !is_dir($dir . '/runtime')) {
            throw new RuntimeException('Не удалось создать каталог статистики');
        }
        $old = umask(0077);
        $lock = @fopen($dir . '/state.lock', 'c');
        umask($old);
        if (!$lock) throw new RuntimeException('Не удалось открыть блокировку');
        try {
            if (!flock($lock, LOCK_EX)) throw new RuntimeException('Не удалось заблокировать состояние');
            $state = $this->read();
            if ($this->protocol === 'shadowtls' && $state['settings']['ss_server_key'] === '') {
                $state['settings']['ss_server_key'] = base64_encode(random_bytes(16));
            }
            $edit($state);
            $state['revision']++;
            $this->validate($state);
            $state['config'] = $this->serverConfig($state);
            self::writeJson($dir . '/desired.json', $state);
            return $state;
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    public static function hostname($host): bool
    {
        return is_string($host) && strlen($host) <= 253
            && (bool) preg_match('/\A(?=.{1,253}\z)[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?\z/D', $host)
            && filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false;
    }

    public function validate(array $s): void
    {
        if (($s['schema'] ?? null) !== 1 || ($s['protocol'] ?? '') !== $this->protocol
            || !is_int($s['revision'] ?? null) || $s['revision'] < 0 || !is_bool($s['enabled'] ?? null)
            || !is_array($s['users'] ?? null) || !is_array($s['settings'] ?? null)) {
            throw new InvalidArgumentException('Неверная структура состояния');
        }
        $c = $s['settings'];
        if (array_key_exists('self_hosted', $c) && !is_bool($c['self_hosted'])) throw new InvalidArgumentException('Неверный режим собственного сайта');
        if (array_key_exists('cover_host', $c) && !is_string($c['cover_host'])) throw new InvalidArgumentException('Неверный адрес сайта прикрытия');
        if ($this->protocol === 'anytls' && ($c['cover_host'] ?? '') !== '') {
            if (!self::hostname($c['cover_host']) || filter_var($c['cover_host'], FILTER_VALIDATE_IP)
                || strcasecmp($c['cover_host'], $c['sni'] ?? '') === 0) {
                throw new InvalidArgumentException('Сайт прикрытия AnyTLS должен иметь отдельное доменное имя');
            }
        }
        foreach (['port', 'listen_port'] as $key) {
            if (!is_int($c[$key] ?? null) || $c[$key] < 1 || $c[$key] > 65535) throw new InvalidArgumentException('Порт: 1–65535');
        }
        foreach (['host', 'sni'] as $key) {
            if (!is_string($c[$key] ?? null) || ($c[$key] !== '' && !self::hostname($c[$key])
                && !filter_var($c[$key], FILTER_VALIDATE_IP))) throw new InvalidArgumentException('Неверное имя сервера');
            if ($s['enabled'] && $c[$key] === '' && ($key === 'host' || $this->protocol !== 'mieru')) throw new InvalidArgumentException('Сначала задайте адрес и SNI для TLS');
        }
        if (!filter_var($c['dns'] ?? '', FILTER_VALIDATE_IP) || !in_array($c['egress'] ?? '', ['direct', 'warp'], true)) {
            throw new InvalidArgumentException('Неверный DNS или маршрут');
        }
        if (!is_array($c['blocked_ips'] ?? null)) throw new InvalidArgumentException('Неверный список служебных адресов');
        foreach ($c['blocked_ips'] as $ip) if (!filter_var($ip, FILTER_VALIDATE_IP)) throw new InvalidArgumentException('Неверный служебный адрес');
        foreach (['certificate', 'private_key'] as $key) {
            if (!is_string($c[$key] ?? null) || !preg_match('~\A/certs/[a-zA-Z0-9_./-]+\z~D', $c[$key])
                || str_contains($c[$key], '..')) throw new InvalidArgumentException('Сертификат должен находиться в /certs');
        }
        if ($this->protocol === 'anytls' && ($c['port'] !== 443 || $c['listen_port'] !== 8443
            || ($c['sni'] !== '' && !self::hostname($c['sni'])) || filter_var($c['sni'], FILTER_VALIDATE_IP))) {
            throw new InvalidArgumentException('AnyTLS: общий TCP-порт 443, внутренний 8443 и отдельное доменное имя SNI');
        }
        if ($this->protocol === 'mieru' && (!in_array($c['transport'] ?? '', ['TCP', 'UDP'], true)
            || $c['port'] < 1024 || $c['listen_port'] !== 24445)) throw new InvalidArgumentException('Mieru: внешний порт 1024–65535, внутренний 24445, транспорт TCP или UDP');
        if ($this->protocol === 'tuic' && ($c['port'] < 1024 || $c['listen_port'] !== 9443
            || !in_array($c['udp_mode'] ?? '', ['native', 'quic'], true)
            || !in_array($c['congestion'] ?? '', ['cubic', 'new_reno', 'bbr'], true))) throw new InvalidArgumentException('Неверный порт или режим TUIC');
        if ($this->protocol === 'shadowtls' && ($c['port'] < 1024 || $c['listen_port'] !== 24447
            || !is_bool($c['udp_over_tcp'] ?? null) || !is_int($c['handshake_port'] ?? null)
            || $c['handshake_port'] < 1 || $c['handshake_port'] > 65535
            || ($c['sni'] !== '' && (!self::hostname($c['sni']) || filter_var($c['sni'], FILTER_VALIDATE_IP)))
            || (($s['enabled'] || ($c['ss_server_key'] ?? '') !== '') && !self::ssKey($c['ss_server_key'] ?? null)))) {
            throw new InvalidArgumentException('Неверные параметры ShadowTLS: отдельный порт, домен TLS 1.3 и ключ SS2022');
        }
        foreach ($s['users'] as $id => $u) {
            if (!is_string($id) || !preg_match('/\A[a-f0-9]{16}\z/D', $id) || !is_array($u)
                || !is_string($u['name'] ?? null) || trim($u['name']) === '' || mb_strlen($u['name']) > 100
                || preg_match('/[\x00-\x1f\x7f]/', $u['name']) || !is_bool($u['enabled'] ?? null)
                || !preg_match('/\A[a-f0-9]{64}\z/D', $u['token'] ?? '')
                || !preg_match('/\A[A-Za-z0-9_-]{43}\z/D', $u['password'] ?? '')
                || !preg_match('/\A[a-f0-9]{16}\z/D', $u['reset'] ?? '')) throw new InvalidArgumentException('Неверные данные доступа');
            foreach (['expires', 'quota'] as $key) {
                if (!array_key_exists($key, $u) || ($u[$key] !== null && (!is_int($u[$key]) || $u[$key] <= 0))) {
                    throw new InvalidArgumentException('Срок и лимит должны быть положительными или отсутствовать');
                }
            }
            if (isset($u['rolling_quota'])) {
                if ($this->protocol !== 'mieru' || !is_array($u['rolling_quota'])) throw new InvalidArgumentException('Неверная периодическая квота');
                foreach (['days' => 365, 'megabytes' => 2147483647] as $key => $max) {
                    if (!is_int($u['rolling_quota'][$key] ?? null) || $u['rolling_quota'][$key] < 1 || $u['rolling_quota'][$key] > $max) throw new InvalidArgumentException('Неверная периодическая квота');
                }
            }
            if ($this->protocol === 'tuic' && !preg_match('/\A[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}\z/D', $u['uuid'] ?? '')) throw new InvalidArgumentException('Неверный UUID TUIC');
            if ($this->protocol === 'shadowtls' && !self::ssKey($u['ss_key'] ?? null)) throw new InvalidArgumentException('Неверный личный ключ SS2022');
        }
    }

    public function configure(array $settings, ?bool $enabled = null): array
    {
        return $this->change(function (&$s) use ($settings, $enabled) {
            if (array_diff_key($settings, $s['settings'])) throw new InvalidArgumentException('Неизвестная настройка');
            $s['settings'] = array_replace($s['settings'], $settings);
            if ($enabled !== null) $s['enabled'] = $enabled;
        });
    }

    public function add(string $name): string
    {
        // Purely decimal array keys are silently converted to integers by PHP.
        do { $id = bin2hex(random_bytes(8)); } while (preg_match('/\A[0-9]+\z/D', $id));
        $this->change(function (&$s) use ($name, $id) {
            $s['users'][$id] = ['name' => trim($name), 'password' => self::secret(),
                'token' => bin2hex(random_bytes(32)), 'enabled' => true, 'expires' => null,
                'quota' => null, 'reset' => bin2hex(random_bytes(8))];
            if ($this->protocol === 'tuic') $s['users'][$id]['uuid'] = self::uuid();
            if ($this->protocol === 'shadowtls') $s['users'][$id]['ss_key'] = base64_encode(random_bytes(16));
        });
        return $id;
    }

    public static function secret(): string { return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '='); }

    private static function ssKey($key): bool
    {
        return is_string($key) && preg_match('~\A[A-Za-z0-9+/]{22}==\z~D', $key)
            && strlen(base64_decode($key, true)) === 16 && base64_encode(base64_decode($key, true)) === $key;
    }

    private static function uuid(): string
    {
        $bytes = random_bytes(16);
        $bytes[6] = chr((ord($bytes[6]) & 15) | 64); $bytes[8] = chr((ord($bytes[8]) & 63) | 128);
        $hex = bin2hex($bytes);
        return substr($hex, 0, 8) . '-' . substr($hex, 8, 4) . '-' . substr($hex, 12, 4) . '-' . substr($hex, 16, 4) . '-' . substr($hex, 20);
    }

    public function user(string $id, array $fields = [], string $action = ''): array
    {
        return $this->change(function (&$s) use ($id, $fields, $action) {
            if (!isset($s['users'][$id])) throw new InvalidArgumentException('Доступ не найден');
            if (array_diff_key($fields, array_flip(['name', 'enabled', 'expires', 'quota', 'rolling_quota']))) throw new InvalidArgumentException('Неизвестное поле');
            $s['users'][$id] = array_replace($s['users'][$id], $fields);
            if ($action === 'delete') unset($s['users'][$id]);
            elseif (in_array($action, ['rotate', 'rotate-outer', 'rotate-inner'], true)) {
                if ($action !== 'rotate' && $this->protocol !== 'shadowtls') throw new InvalidArgumentException('Действие только для ShadowTLS');
                if ($action !== 'rotate-inner') $s['users'][$id]['password'] = self::secret();
                $s['users'][$id]['token'] = bin2hex(random_bytes(32));
                if ($this->protocol === 'tuic') $s['users'][$id]['uuid'] = self::uuid();
                if ($this->protocol === 'shadowtls' && $action !== 'rotate-outer') $s['users'][$id]['ss_key'] = base64_encode(random_bytes(16));
            } elseif ($action === 'reset') $s['users'][$id]['reset'] = bin2hex(random_bytes(8));
            elseif ($action !== '') throw new InvalidArgumentException('Неизвестное действие');
        });
    }

    public function usage(): array
    {
        $file = $this->directory() . '/runtime/usage.json';
        return is_file($file) ? self::readJson($file) : [];
    }

    public function snapshot(): array
    {
        $state = $this->read();
        unset($state['config'], $state['restore_usage']);
        $usage = $this->usage();
        unset($usage['restored']);
        foreach (array_keys($usage['users'] ?? []) as $id) unset($usage['users'][$id]['last']);
        return ['state' => $state, 'usage' => $usage];
    }

    public function validateSnapshot(array $snapshot): void
    {
        if (!is_array($snapshot['state'] ?? null) || !is_array($snapshot['usage'] ?? null)) throw new InvalidArgumentException('Неверная резервная копия протокола');
        $this->validate($snapshot['state']);
        if (isset($snapshot['usage']['native_metrics']) && ($this->protocol !== 'mieru'
            || !is_string($snapshot['usage']['native_metrics']) || strlen($snapshot['usage']['native_metrics']) > 32 * 1024 * 1024
            || base64_decode($snapshot['usage']['native_metrics'], true) === false)) throw new InvalidArgumentException('Неверная история квоты Mieru');
        foreach ($snapshot['usage']['users'] ?? [] as $id => $record) {
            if (!preg_match('/\A[a-f0-9]{16}\z/D', (string) $id) || !is_array($record)) throw new InvalidArgumentException('Неверные счётчики');
            foreach (['upload', 'download'] as $key) if (!is_int($record[$key] ?? null) || $record[$key] < 0) throw new InvalidArgumentException('Неверные счётчики');
            if (!preg_match('/\A[a-f0-9]{16}\z/D', $record['reset'] ?? '')) throw new InvalidArgumentException('Неверный счётчик сброса');
        }
    }

    public function restore(array $snapshot): void
    {
        $this->validateSnapshot($snapshot);
        $this->change(function (&$state) use ($snapshot) {
            $revision = $state['revision'];
            $state = $snapshot['state'];
            unset($state['config'], $state['restore_usage']);
            $state['revision'] = $revision;
            // Only the supervisor writes usage; restore closes active sessions first.
            $state['restore_usage'] = ['id' => bin2hex(random_bytes(16)), 'users' => (object) ($snapshot['usage']['users'] ?? [])];
            if ($this->protocol === 'mieru') $state['restore_usage']['native_metrics'] = $snapshot['usage']['native_metrics'] ?? '';
        });
    }

    public function status(): array
    {
        $file = $this->directory() . '/runtime/status.json';
        $s = is_file($file) ? self::readJson($file) : [];
        $s['stale'] = time() - ($s['time'] ?? 0) > 15;
        return $s;
    }

    public function allowed(array $u, string $id, ?array $usage = null): bool
    {
        $usage ??= $this->usage();
        $bytes = $usage['users'][$id] ?? [];
        return $u['enabled'] && ($u['expires'] === null || $u['expires'] > time())
            && ($u['quota'] === null || ($bytes['upload'] ?? 0) + ($bytes['download'] ?? 0) < $u['quota']);
    }

    public function serverConfig(array $s): array
    {
        $c = $s['settings'];
        if ($this->protocol === 'mieru') {
            $users = [];
            foreach ($s['users'] as $id => $u) if ($u['enabled']) {
                $users[] = ['name' => $id, 'password' => $u['password'], 'allowPrivateIP' => false, 'allowLoopbackIP' => false,
                    'quotas' => isset($u['rolling_quota']) ? [$u['rolling_quota']] : []];
            }
            $rules = [];
            if ($c['blocked_ips']) $rules[] = ['ipRanges' => array_map(fn($ip) => $ip . (str_contains($ip, ':') ? '/128' : '/32'), $c['blocked_ips']), 'action' => 'REJECT'];
            if ($c['egress'] === 'warp') $rules[] = ['ipRanges' => ['*'], 'domainNames' => ['*'], 'action' => 'PROXY', 'proxyNames' => ['warp']];
            return ['listenIPAddress' => '0.0.0.0', 'portBindings' => [['port' => $c['listen_port'], 'protocol' => $c['transport']]],
                'users' => $users, 'loggingLevel' => 'WARN', 'advancedSettings' => ['metricsLoggingInterval' => '5s'],
                'dns' => ['dualStack' => 'PREFER_IPv4'], 'egress' => ['rules' => $rules,
                    'proxies' => [['name' => 'warp', 'protocol' => 'SOCKS5_PROXY_PROTOCOL', 'host' => '10.10.0.13', 'port' => 1080]]]];
        }
        $users = [];
        foreach ($s['users'] as $id => $u) if ($u['enabled']) $users[] = ['name' => $id, 'password' => $u['password']]
            + ($this->protocol === 'tuic' ? ['uuid' => $u['uuid']] : []);
        $rules = [['action' => 'resolve', 'server' => 'dns'], ['ip_is_private' => true, 'action' => 'reject'],
            ['ip_cidr' => ['0.0.0.0/8', '100.64.0.0/10', '198.18.0.0/15', '240.0.0.0/4',
                '64:ff9b::/96', '64:ff9b:1::/48', '2002::/16', '2001::/32'], 'action' => 'reject']];
        if ($c['blocked_ips']) $rules[] = ['ip_cidr' => array_map(fn($ip) => $ip . (str_contains($ip, ':') ? '/128' : '/32'), $c['blocked_ips']), 'action' => 'reject'];
        $config = ['log' => ['level' => 'warn', 'timestamp' => true],
            'dns' => ['servers' => [['type' => 'udp', 'tag' => 'dns', 'server' => $c['dns']]]],
            'inbounds' => [['type' => $this->protocol, 'tag' => $this->protocol, 'listen' => '0.0.0.0',
                'listen_port' => $c['listen_port'], 'users' => $users,
                'tls' => ['enabled' => true, 'certificate_path' => $c['certificate'], 'key_path' => $c['private_key']]]],
            'outbounds' => [['type' => 'direct', 'tag' => 'direct'],
                ['type' => 'socks', 'tag' => 'warp', 'server' => '10.10.0.13', 'server_port' => 1080]],
            'route' => ['rules' => $rules, 'final' => $c['egress'], 'default_domain_resolver' => 'dns'],
            'experimental' => ['v2ray_api' => ['listen' => '127.0.0.1:10085',
                'stats' => ['enabled' => true, 'users' => array_keys($s['users'])]]]];
        if ($this->protocol === 'anytls' && ($c['cover_host'] ?? '') !== '') {
            $config['inbounds'][0]['fallback_server_name'] = $c['cover_host'];
            if (!empty($c['self_hosted'])) $config['inbounds'][0]['fallback_address'] = '10.10.0.2:10443';
            $config['inbounds'][0]['tls']['alpn'] = ['http/1.1'];
        }
        if ($this->protocol === 'tuic') {
            $config['inbounds'][0] += ['congestion_control' => $c['congestion'], 'zero_rtt_handshake' => false, 'auth_timeout' => '3s', 'heartbeat' => '10s'];
            $config['inbounds'][0]['tls'] += ['alpn' => ['h3'], 'min_version' => '1.3'];
        }
        if ($this->protocol === 'shadowtls') {
            $config['inbounds'] = [
                ['type' => 'shadowtls', 'tag' => 'shadowtls', 'listen' => '0.0.0.0', 'listen_port' => 24447,
                    'version' => 3, 'strict_mode' => true, 'wildcard_sni' => 'off', 'users' => $users,
                    'handshake' => ['server' => !empty($c['self_hosted']) ? '10.10.0.2' : $c['sni'],
                        'server_port' => !empty($c['self_hosted']) ? 10443 : $c['handshake_port'], 'domain_resolver' => 'dns'], 'detour' => 'inner-ss'],
                ['type' => 'shadowsocks', 'tag' => 'inner-ss', 'listen' => '127.0.0.1', 'listen_port' => 10086, 'network' => 'tcp',
                    'method' => '2022-blake3-aes-128-gcm', 'password' => $c['ss_server_key'],
                    'users' => array_map(fn($u) => ['name' => $u['name'], 'password' => $s['users'][$u['name']]['ss_key']], $users)]];
            if (!$c['udp_over_tcp']) array_unshift($config['route']['rules'], ['network' => 'udp', 'action' => 'reject']);
        }
        return $config;
    }

    public function profile(string $id, string $format, ?array $state = null): array|string
    {
        $s = $state ?? $this->read();
        if (!isset($s['users'][$id]) || !$s['enabled'] || !$this->allowed($s['users'][$id], $id)) {
            throw new RuntimeException('Доступ отключён, истёк или исчерпан');
        }
        $u = $s['users'][$id]; $c = $s['settings'];
        if ($this->protocol === 'mieru') return $this->mieruProfile($id, $u, $c, $format);
        if ($this->protocol === 'tuic') return $this->tuicProfile($u, $c, $format);
        if ($this->protocol === 'shadowtls') return $this->shadowtlsProfile($u, $c, $format);
        if ($format === 'uri') {
            $host = str_contains($c['host'], ':') ? '[' . $c['host'] . ']' : $c['host'];
            return 'anytls://' . rawurlencode($u['password']) . '@' . $host . ':' . $c['port']
                . '/?sni=' . rawurlencode($c['sni']) . '&insecure=0#' . rawurlencode($u['name']);
        }
        if ($format === 'singbox') return [
            'log' => ['level' => 'warn'],
            'dns' => ['servers' => [['type' => 'local', 'tag' => 'bootstrap']]],
            'inbounds' => [['type' => 'mixed', 'tag' => 'local', 'listen' => '127.0.0.1', 'listen_port' => 1080]],
            'outbounds' => [['type' => 'anytls', 'tag' => 'VPN', 'server' => $c['host'], 'server_port' => $c['port'],
                'password' => $u['password'], 'tls' => ['enabled' => true, 'server_name' => $c['sni']],
                'domain_resolver' => 'bootstrap']], 'route' => ['final' => 'VPN']];
        if ($format === 'mihomo') return ['mixed-port' => 1080, 'allow-lan' => false, 'log-level' => 'warning',
            'mode' => 'rule', 'proxies' => [['name' => 'VPN', 'type' => 'anytls', 'server' => $c['host'],
                'port' => $c['port'], 'password' => $u['password'], 'sni' => $c['sni'],
                'udp' => true, 'skip-cert-verify' => false]], 'rules' => ['MATCH,VPN', 'MATCH,REJECT']];
        throw new InvalidArgumentException('Клиент не поддерживается для этого протокола');
    }

    private function shadowtlsProfile(array $u, array $c, string $format): array
    {
        $password = $c['ss_server_key'] . ':' . $u['ss_key'];
        if ($format === 'singbox') return ['log' => ['level' => 'warn'],
            'dns' => ['servers' => [['type' => 'local', 'tag' => 'bootstrap']]],
            'inbounds' => [['type' => 'mixed', 'tag' => 'local', 'listen' => '127.0.0.1', 'listen_port' => 1080]],
            'outbounds' => [
                ['type' => 'shadowsocks', 'tag' => 'VPN', 'server' => $c['host'], 'server_port' => $c['port'],
                    'method' => '2022-blake3-aes-128-gcm', 'password' => $password, 'detour' => 'shadowtls',
                    'udp_over_tcp' => ['enabled' => $c['udp_over_tcp'], 'version' => 2]],
                ['type' => 'shadowtls', 'tag' => 'shadowtls', 'server' => $c['host'], 'server_port' => $c['port'],
                    'version' => 3, 'password' => $u['password'], 'tls' => ['enabled' => true, 'server_name' => $c['sni'],
                        'min_version' => '1.3'], 'domain_resolver' => 'bootstrap']],
            'route' => ['final' => 'VPN', 'rules' => $c['udp_over_tcp'] ? [] : [['network' => 'udp', 'action' => 'reject']]]];
        if ($format === 'mihomo') return ['mixed-port' => 1080, 'allow-lan' => false, 'log-level' => 'warning', 'mode' => 'rule',
            'proxies' => [['name' => 'VPN', 'type' => 'ss', 'server' => $c['host'], 'port' => $c['port'],
                'cipher' => '2022-blake3-aes-128-gcm', 'password' => $password, 'udp' => $c['udp_over_tcp'],
                'udp-over-tcp' => $c['udp_over_tcp'], 'udp-over-tcp-version' => 2,
                'plugin' => 'shadow-tls', 'plugin-opts' => ['host' => $c['sni'], 'password' => $u['password'],
                    'version' => 3, 'skip-cert-verify' => false]]], 'rules' => ['MATCH,VPN', 'MATCH,REJECT']];
        throw new InvalidArgumentException('Для связки ShadowTLS + SS используйте полный профиль');
    }

    private function tuicProfile(array $u, array $c, string $format): array
    {
        if ($format === 'singbox') return ['log' => ['level' => 'warn'],
            'dns' => ['servers' => [['type' => 'local', 'tag' => 'bootstrap']]],
            'inbounds' => [['type' => 'mixed', 'tag' => 'local', 'listen' => '127.0.0.1', 'listen_port' => 1080]],
            'outbounds' => [['type' => 'tuic', 'tag' => 'VPN', 'server' => $c['host'], 'server_port' => $c['port'],
                'uuid' => $u['uuid'], 'password' => $u['password'], 'congestion_control' => $c['congestion'],
                'udp_relay_mode' => $c['udp_mode'], 'zero_rtt_handshake' => false, 'heartbeat' => '10s',
                'tls' => ['enabled' => true, 'server_name' => $c['sni'], 'alpn' => ['h3']], 'domain_resolver' => 'bootstrap']],
            'route' => ['final' => 'VPN']];
        if ($format === 'mihomo') return ['mixed-port' => 1080, 'allow-lan' => false, 'log-level' => 'warning', 'mode' => 'rule',
            'proxies' => [['name' => 'VPN', 'type' => 'tuic', 'server' => $c['host'], 'port' => $c['port'],
                'uuid' => $u['uuid'], 'password' => $u['password'], 'congestion-controller' => $c['congestion'], 'udp-relay-mode' => $c['udp_mode'],
                'sni' => $c['sni'], 'alpn' => ['h3'], 'skip-cert-verify' => false, 'disable-sni' => false,
                'reduce-rtt' => false, 'heartbeat-interval' => 10000, 'udp' => true]], 'rules' => ['MATCH,VPN', 'MATCH,REJECT']];
        throw new InvalidArgumentException('Для TUIC используйте полный профиль sing-box или mihomo');
    }

    private function mieruProfile(string $id, array $u, array $c, string $format): array|string
    {
        $endpoint = [(filter_var($c['host'], FILTER_VALIDATE_IP) ? 'ipAddress' : 'domainName') => $c['host'],
            'portBindings' => [['port' => $c['port'], 'protocol' => $c['transport']]]];
        $profile = ['profileName' => $u['name'], 'user' => ['name' => $id, 'password' => $u['password']],
            'servers' => [$endpoint], 'mtu' => 1400, 'multiplexing' => ['level' => 'MULTIPLEXING_LOW'], 'handshakeMode' => 'HANDSHAKE_STANDARD'];
        if ($format === 'native') return ['profiles' => [$profile], 'activeProfile' => $u['name'], 'socks5Port' => 1080,
            'rpcPort' => 1081, 'loggingLevel' => 'WARN', 'socks5ListenLAN' => false, 'advancedSettings' => ['noCheckUpdate' => true]];
        if ($format === 'uri') {
            $host = str_contains($c['host'], ':') ? '[' . $c['host'] . ']' : $c['host'];
            return 'mierus://' . rawurlencode($id) . ':' . rawurlencode($u['password']) . '@' . $host . '?' . http_build_query([
                'profile' => $u['name'], 'port' => $c['port'], 'protocol' => $c['transport'], 'mtu' => 1400,
                'multiplexing' => 'MULTIPLEXING_LOW', 'handshake-mode' => 'HANDSHAKE_STANDARD'], '', '&', PHP_QUERY_RFC3986);
        }
        if ($format === 'native-uri') {
            // Pinned Mieru v3 clientcfg.proto/base.proto; round-trip tested with its official decoder.
            $binding = self::protoField(1, $c['port']) . self::protoField(2, $c['transport'] === 'TCP' ? 2 : 1);
            $server = self::protoField(isset($endpoint['ipAddress']) ? 1 : 2, $c['host']) . self::protoField(3, $binding);
            $user = self::protoField(1, $id) . self::protoField(2, $u['password']);
            $p = self::protoField(1, $u['name']) . self::protoField(2, $user) . self::protoField(3, $server)
                . self::protoField(4, 1400) . self::protoField(5, self::protoField(1, 2)) . self::protoField(6, 1);
            return 'mieru://' . base64_encode(self::protoField(1, $p) . self::protoField(2, $u['name'])
                . self::protoField(3, 1081) . self::protoField(4, 1080) . self::protoField(5, self::protoField(1, 1)) . self::protoField(6, 3));
        }
        if ($format === 'mihomo') return ['mixed-port' => 1080, 'allow-lan' => false, 'log-level' => 'warning', 'mode' => 'rule',
            'proxies' => [['name' => 'VPN', 'type' => 'mieru', 'server' => $c['host'], 'port' => $c['port'],
                'transport' => $c['transport'], 'udp' => true, 'username' => $id, 'password' => $u['password'], 'multiplexing' => 'MULTIPLEXING_LOW',
                'handshake-mode' => 'HANDSHAKE_STANDARD']], 'rules' => ['MATCH,VPN', 'MATCH,REJECT']];
        throw new InvalidArgumentException('Клиент не поддерживается для Mieru');
    }

    private static function protoField(int $number, string|int $value): string
    {
        $varint = static function (int $value): string {
            $out = '';
            do { $byte = $value & 127; $value >>= 7; $out .= chr($byte | ($value ? 128 : 0)); } while ($value);
            return $out;
        };
        return $varint(($number << 3) | (is_string($value) ? 2 : 0))
            . (is_string($value) ? $varint(strlen($value)) . $value : $varint($value));
    }
}
