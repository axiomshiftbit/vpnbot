<?php

require_once __DIR__ . "/ProtocolOptionHelp.php";

/** Optional tuning for the pinned sing-box / Mieru servers and supported clients. */
final class ProtocolOptions
{
    public const FINGERPRINTS = ['default', 'chrome', 'firefox', 'edge', 'safari', 'ios', 'random'];
    public const MULTIPLEXING = ['MULTIPLEXING_OFF', 'MULTIPLEXING_LOW', 'MULTIPLEXING_MIDDLE', 'MULTIPLEXING_HIGH'];
    public const HANDSHAKES = ['HANDSHAKE_STANDARD', 'HANDSHAKE_NO_WAIT'];
    public const NONCES = ['NONCE_TYPE_RANDOM', 'NONCE_TYPE_PRINTABLE', 'NONCE_TYPE_PRINTABLE_SUBSET', 'NONCE_TYPE_FIXED'];
    public const ENTROPY = ['LOW_ENTROPY_MODE_OFF', 'LOW_ENTROPY_MODE_32', 'LOW_ENTROPY_MODE_40', 'LOW_ENTROPY_MODE_48', 'LOW_ENTROPY_MODE_56'];
    private const CIPHERS = [
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
    ];

    public static function groups(string $protocol): array
    {
        if ($protocol === 'snolc') return [];
        return $protocol === 'mieru'
            ? ['server' => 'Сервер Mieru', 'client' => 'Клиенты Mieru', 'native' => 'Только Mieru JSON / URI', 'mihomo' => 'Только Mihomo']
            : ['server' => 'Сервер', 'client' => 'Общие настройки клиентов', 'singbox' => 'Только sing-box', 'mihomo' => 'Только Mihomo']
                + ($protocol === 'shadowtls' ? ['multiplex' => 'Мультиплексирование SS'] : []);
    }

    public static function schema(string $protocol): array
    {
        if ($protocol === 'snolc') return [];
        $bool = ['bool']; $int = static fn($min, $max) => ['int', $min, $max];
        $enum = static fn($values) => ['enum', $values];
        $list = static fn($rule, $max = 32) => ['list', $rule, $max];
        $duration = ['duration', 0, 86400000];
        $alpn = $list(['text', 1, 32], 8);
        $tcp = ['tcp_fast_open' => $bool, 'tcp_multi_path' => $bool, 'disable_tcp_keep_alive' => $bool,
            'tcp_keep_alive' => $duration, 'tcp_keep_alive_interval' => $duration];
        $quic = ['idle_timeout' => $duration, 'keep_alive_period' => $duration,
            'stream_receive_window' => $int(16384, 67108864), 'connection_receive_window' => $int(16384, 67108864),
            'max_concurrent_streams' => $int(1, 4096), 'initial_packet_size' => $int(1200, 1452),
            'disable_path_mtu_discovery' => $bool];
        $tls = ['alpn' => $alpn, 'min_version' => $enum(['1.2', '1.3']), 'max_version' => $enum(['1.2', '1.3']),
            'cipher_suites' => $list($enum(self::CIPHERS), 6),
            'curve_preferences' => $list($enum(['P256', 'P384', 'P521', 'X25519', 'X25519MLKEM768']), 5),
            'handshake_timeout' => ['duration', 1, 300000]];
        if (in_array($protocol, ['tuic', 'shadowtls'], true)) {
            $tls['min_version'] = $tls['max_version'] = $enum(['1.3']);
            unset($tls['cipher_suites']); // TLS 1.3 cipher suites are selected by the TLS engine.
        }
        $clientTLS = $tls + ['certificate_public_key_sha256' => $list(['pin'], 8)];
        if ($protocol !== 'tuic') $clientTLS += ['fragment' => $bool, 'fragment_fallback_delay' => ['duration', 1, 5000],
            'record_fragment' => $bool, 'spoof' => ['hostname'], 'spoof_method' => $enum(['wrong-sequence', 'wrong-checksum', 'wrong-ack', 'wrong-md5', 'wrong-timestamp'])];
        $commonMihomo = ['ip-version' => $enum(['dual', 'ipv4', 'ipv6', 'ipv4-prefer', 'ipv6-prefer'])];
        if ($protocol !== 'tuic') $commonMihomo += ['tfo' => $bool, 'mptcp' => $bool];
        $schema = [
            'server' => ['log_level' => $enum(['trace', 'debug', 'info', 'warn', 'error', 'fatal', 'panic']), 'dns_server' => ['ip']]
                + ($protocol === 'tuic' ? ['udp_fragment' => $bool, 'udp_timeout' => $duration] : $tcp),
            'client' => [],
            'singbox' => ['connect_timeout' => ['duration', 1, 300000], 'tls' => ['object', $clientTLS]]
                + ($protocol === 'tuic' ? $quic + ['udp_fragment' => $bool] : $tcp),
            'mihomo' => $commonMihomo,
        ];
        if ($protocol === 'anytls') {
            unset($schema['singbox']['tcp_fast_open']); // Rejected by sing-box's AnyTLS dialer.
            $schema['server'] += ['padding_scheme' => ['padding'], 'tls' => ['object', $tls]];
            $schema['client'] = ['fingerprint' => $enum(self::FINGERPRINTS), 'alpn' => $alpn,
                'idle_session_check_interval' => ['duration', 1000, 86400000],
                'idle_session_timeout' => ['duration', 1000, 86400000], 'min_idle_session' => $int(0, 128),
                'client_metadata' => ['text', 0, 256], 'udp' => $bool];
            $schema['mihomo'] += ['disable-reuse' => $bool];
        } elseif ($protocol === 'tuic') {
            $schema['server'] += $quic + ['auth_timeout' => ['duration', 1, 60000], 'tls' => ['object', $tls]];
            $schema['client'] = ['alpn' => $alpn, 'heartbeat' => ['duration', 1000, 300000],
                'zero_rtt_handshake' => $bool, 'udp_over_stream' => $bool];
            $schema['mihomo'] += ['request-timeout' => $int(100, 300000), 'max-udp-relay-packet-size' => $int(1200, 65535),
                'fast-open' => $bool, 'max-open-streams' => $int(1, 4096), 'cwnd' => $int(1, 16384),
                'bbr-profile' => $enum(['standard', 'conservative', 'aggressive']),
                'recv-window-conn' => $int(16384, 67108864), 'recv-window' => $int(16384, 67108864),
                'disable-mtu-discovery' => $bool, 'max-datagram-frame-size' => $int(1200, 65535)];
        } elseif ($protocol === 'shadowtls') {
            $schema['server']['handshake'] = ['object', ['server_port' => $int(1, 65535), 'connect_timeout' => ['duration', 1, 60000]] + $tcp];
            $schema['client'] = ['fingerprint' => $enum(self::FINGERPRINTS), 'alpn' => $alpn];
            $schema['multiplex'] = ['enabled' => $bool, 'padding' => $bool, 'protocol' => $enum(['h2mux', 'smux', 'yamux']),
                'max_connections' => $int(1, 128), 'min_streams' => $int(0, 1024), 'max_streams' => $int(0, 1024)];
        } elseif ($protocol === 'mieru') {
            $pattern = ['object', [
                'seed' => $int(-2147483648, 2147483647), 'unlockAll' => $bool,
                'tcpFragment' => ['object', ['enable' => $bool, 'maxSleepMs' => $int(0, 100)]],
                'nonce' => ['object', ['type' => $enum(self::NONCES), 'applyToAllUDPPacket' => $bool,
                    'minLen' => $int(0, 12), 'maxLen' => $int(0, 12), 'customHexStrings' => $list(['hex'], 32)]],
                'padding' => ['object', ['maxMiddlePaddingLen' => $int(0, 255), 'maxEndPaddingLen' => $int(0, 255)]],
                'lowEntropy' => ['object', ['mode' => $enum(self::ENTROPY), 'maskRotation' => ['rotation']]],
            ]];
            $logging = $enum(['FATAL', 'ERROR', 'WARN', 'INFO', 'DEBUG', 'TRACE']);
            $schema = [
                'server' => ['mtu' => $int(1280, 1500), 'loggingLevel' => $logging,
                    'advancedSettings' => ['object', ['metricsLoggingInterval' => ['duration', 1000, 86400000], 'userHintIsMandatory' => $bool]],
                    'dns' => ['object', ['dualStack' => $enum(['USE_FIRST_IP', 'PREFER_IPv4', 'PREFER_IPv6', 'ONLY_IPv4', 'ONLY_IPv6']), 'hosts' => ['hosts']]],
                    'trafficPattern' => $pattern],
                'client' => ['multiplexing' => $enum(self::MULTIPLEXING), 'handshakeMode' => $enum(self::HANDSHAKES), 'trafficPattern' => $pattern],
                'native' => ['mtu' => $int(1280, 1500), 'loggingLevel' => $logging,
                    'metricsLoggingInterval' => ['duration', 1000, 86400000],
                    'socks5Port' => $int(1024, 65535), 'rpcPort' => $int(1024, 65535), 'httpProxyPort' => $int(1024, 65535)],
                'mihomo' => $commonMihomo,
            ];
        } else throw new InvalidArgumentException('Неизвестный протокол');
        return $schema;
    }

    public static function definition(string $protocol, string $path = ''): array
    {
        $rule = ['object', array_map(static fn($fields) => ['object', $fields], self::schema($protocol))];
        if ($path === '') return $rule;
        if (strlen($path) > 96 || !preg_match('/\A[a-zA-Z][a-zA-Z0-9_-]*(?:\.[a-zA-Z][a-zA-Z0-9_-]*)*\z/D', $path)) throw new InvalidArgumentException('Неизвестный параметр');
        foreach (explode('.', $path) as $key) {
            if ($rule[0] !== 'object' || !isset($rule[1][$key])) throw new InvalidArgumentException('Неизвестный параметр');
            $rule = $rule[1][$key];
        }
        return $rule;
    }

    public static function callback(string $protocol, string $action, string $path = '', ?int $choice = null): string
    {
        $suffix = $choice === null ? '' : " $choice";
        $callback = rtrim("/po $protocol $action $path") . $suffix;
        if (strlen($callback) > 63) $callback = "/po $protocol $action @" . substr(hash('sha256', $path), 0, 12) . $suffix;
        return $callback;
    }

    public static function resolvePath(string $protocol, string $path): string
    {
        if (!str_starts_with($path, '@')) return $path;
        $matches = [];
        $visit = static function(array $rule, string $prefix = '') use (&$visit, &$matches, $path): void {
            if ('@' . substr(hash('sha256', $prefix), 0, 12) === $path) $matches[] = $prefix;
            if ($rule[0] === 'object') foreach ($rule[1] as $key => $child) $visit($child, $prefix === '' ? $key : "$prefix.$key");
        };
        $visit(self::definition($protocol));
        if (count($matches) !== 1) throw new InvalidArgumentException('Неизвестный параметр');
        return $matches[0];
    }

    public static function at(array $options, string $path): mixed
    {
        $value = $options;
        if ($path === '') return $value;
        foreach (explode('.', $path) as $key) {
            if (!is_array($value) || !array_key_exists($key, $value)) return null;
            $value = $value[$key];
        }
        return $value;
    }

    public static function describe(array $rule): string
    {
        return match ($rule[0]) {
            'object' => 'Группа настроек.',
            'bool' => 'Включено или выключено.',
            'int' => "Целое число: {$rule[1]}–{$rule[2]}.",
            'enum' => 'Значения: ' . implode(', ', $rule[1]) . '.',
            'duration' => "Длительность с ms, s, m или h; диапазон {$rule[1]}–{$rule[2]} мс. Например 10s.",
            'list' => 'JSON-массив, не более ' . $rule[2] . ' элементов. ' . self::describe($rule[1]),
            'text' => "Текст: {$rule[1]}–{$rule[2]} символов, без управляющих знаков.",
            'hostname' => 'Доменное имя без https://, пути и порта.',
            'ip' => 'Адрес IPv4 или IPv6.',
            'pin' => 'SHA-256 публичного ключа сертификата, 32 байта в base64.',
            'hex' => 'HEX без 0x, от 1 до 12 байт.',
            'rotation' => 'LOW_ENTROPY_MASK_NO_ROTATION либо LOW_ENTROPY_MASK_ROTATE_RIGHT_1…15 / LEFT_1…15.',
            'hosts' => 'JSON-объект домен → IP, до 64 записей.',
            'padding' => 'JSON-массив строк: stop=1…32, затем номер=диапазон[,c,диапазон]. До 33 строк, размеры 1–4096 байт. Например ["stop=2","0=30-30","1=100-400"].',
        };
    }

    public static function hint(string $protocol, string $path): string
    {
        return ProtocolOptionHelp::text($protocol, $path);
    }

    public static function validate(string $protocol, array $options, array $settings): void
    {
        $schema = self::schema($protocol);
        self::value($options, ['object', array_map(static fn($fields) => ['object', $fields], $schema)], 'options');
        $server = $options['server'] ?? []; $client = $options['client'] ?? []; $singbox = $options['singbox'] ?? [];
        if ($protocol === 'tuic') foreach ([$server['tls'] ?? [], $client, $singbox['tls'] ?? []] as $tls) {
            if (isset($tls['alpn']) && $tls['alpn'] === []) throw new InvalidArgumentException('TUIC требует непустой ALPN');
        }
        if ($protocol === 'shadowtls' && !empty($settings['self_hosted']) && isset($server['handshake']['server_port'])
            && $server['handshake']['server_port'] !== 10443) throw new InvalidArgumentException('Собственный сайт ShadowTLS использует внутренний порт 10443');
        foreach ([$server['tls'] ?? [], $singbox['tls'] ?? []] as $tls) {
            if (($tls['min_version'] ?? '1.2') > ($tls['max_version'] ?? '1.3')) throw new InvalidArgumentException('Минимальная версия TLS выше максимальной');
            if (in_array($protocol, ['tuic', 'shadowtls'], true)
                && (($tls['min_version'] ?? '1.3') !== '1.3' || ($tls['max_version'] ?? '1.3') !== '1.3')) {
                throw new InvalidArgumentException('TUIC и ShadowTLS v3 требуют TLS 1.3');
            }
            if (isset($tls['spoof_method']) && empty($tls['spoof'])) throw new InvalidArgumentException('Для spoof_method сначала задайте spoof');
        }
        if ($protocol === 'anytls') {
            $serverTLS = $server['tls'] ?? []; $clientTLS = $singbox['tls'] ?? [];
            if (max($serverTLS['min_version'] ?? '1.2', $clientTLS['min_version'] ?? '1.2')
                > min($serverTLS['max_version'] ?? '1.3', $clientTLS['max_version'] ?? '1.3')) {
                throw new InvalidArgumentException('Версии TLS клиента и сервера не пересекаются');
            }
            foreach (['idle_session_check_interval', 'idle_session_timeout'] as $field) {
                if (isset($client[$field]) && self::milliseconds($client[$field]) % 1000 !== 0) throw new InvalidArgumentException('Интервалы AnyTLS задаются целыми секундами для совместимости с Mihomo');
            }
            if (!empty($settings['cover_host']) && isset($server['tls']['alpn']) && $server['tls']['alpn'] !== ['http/1.1']) {
                throw new InvalidArgumentException('Сайт прикрытия AnyTLS использует ALPN http/1.1');
            }
        }
        if ($protocol === 'mieru') {
            foreach ([$server['trafficPattern'] ?? [], $client['trafficPattern'] ?? []] as $pattern) {
                $nonce = $pattern['nonce'] ?? [];
                if (isset($nonce['minLen'], $nonce['maxLen']) && $nonce['minLen'] > $nonce['maxLen']) throw new InvalidArgumentException('Mieru: minLen выше maxLen');
                if (isset($nonce['maxLen']) && $nonce['maxLen'] < 12 && !isset($nonce['minLen'])) throw new InvalidArgumentException('Mieru: перед уменьшением maxLen задайте minLen; автоматически выбранный минимум может быть выше');
                if (($nonce['type'] ?? '') === 'NONCE_TYPE_FIXED' && empty($nonce['customHexStrings'])) throw new InvalidArgumentException('Mieru: для FIXED нужны customHexStrings');
            }
            $native = $options['native'] ?? [];
            $ports = [$native['socks5Port'] ?? 1080, $native['rpcPort'] ?? 1081];
            if (isset($native['httpProxyPort'])) $ports[] = $native['httpProxyPort'];
            if (count(array_unique($ports)) !== count($ports)) throw new InvalidArgumentException('Локальные порты Mieru должны отличаться');
        }
        foreach ([$server, $singbox] as $quic) if (isset($quic['stream_receive_window'], $quic['connection_receive_window'])
            && $quic['connection_receive_window'] < $quic['stream_receive_window']) {
            throw new InvalidArgumentException('Окно соединения QUIC меньше окна потока');
        }
        $mux = $options['multiplex'] ?? [];
        if (!empty($mux['max_streams']) && !empty($mux['min_streams'])) throw new InvalidArgumentException('Укажите min_streams либо max_streams');
        // ALPN is a negotiated property, not a label. Disjoint lists cannot work.
        $serverAlpn = $server['tls']['alpn'] ?? ($protocol === 'tuic' ? ['h3'] : (!empty($settings['cover_host']) ? ['http/1.1'] : []));
        foreach ([$client['alpn'] ?? [], $singbox['tls']['alpn'] ?? []] as $alpn) {
            if ($serverAlpn && $alpn && !array_intersect($serverAlpn, $alpn)) throw new InvalidArgumentException('ALPN клиента и сервера не пересекаются');
        }
    }

    public static function milliseconds(string $duration): int
    {
        if (!preg_match('/\A([0-9]{1,8})(ms|s|m|h)\z/D', $duration, $m)) throw new InvalidArgumentException('Длительность: целое число с ms, s, m или h');
        return (int) $m[1] * ['ms' => 1, 's' => 1000, 'm' => 60000, 'h' => 3600000][$m[2]];
    }

    private static function value($value, array $rule, string $path): void
    {
        $ok = false;
        switch ($rule[0]) {
            case 'bool': $ok = is_bool($value); break;
            case 'int': $ok = is_int($value) && $value >= $rule[1] && $value <= $rule[2]; break;
            case 'enum': $ok = is_string($value) && in_array($value, $rule[1], true); break;
            case 'text': $ok = is_string($value) && mb_strlen($value) >= $rule[1] && mb_strlen($value) <= $rule[2] && !preg_match('/[\x00-\x1f\x7f]/', $value); break;
            case 'hostname': $ok = ManagedProtocol::hostname($value) && !filter_var($value, FILTER_VALIDATE_IP); break;
            case 'ip': $ok = is_string($value) && filter_var($value, FILTER_VALIDATE_IP); break;
            case 'hex': $ok = is_string($value) && preg_match('/\A(?:[a-fA-F0-9]{2}){1,12}\z/D', $value); break;
            case 'pin': $ok = is_string($value) && strlen($value) === 44 && strlen((string) base64_decode($value, true)) === 32; break;
            case 'rotation': $ok = is_string($value) && preg_match('/\ALOW_ENTROPY_MASK_(?:NO_ROTATION|ROTATE_(?:RIGHT|LEFT)_(?:[1-9]|1[0-5]))\z/D', $value); break;
            case 'duration':
                $ok = is_string($value) && preg_match('/\A[0-9]{1,8}(?:ms|s|m|h)\z/D', $value);
                if ($ok) { $ms = self::milliseconds($value); $ok = $ms >= $rule[1] && $ms <= $rule[2]; }
                break;
            case 'object':
                $ok = is_array($value) && ($value === [] || !array_is_list($value)) && !array_diff_key($value, $rule[1]);
                if ($ok) foreach ($value as $key => $entry) self::value($entry, $rule[1][$key], "$path.$key");
                break;
            case 'list':
                $ok = is_array($value) && array_is_list($value) && count($value) <= $rule[2];
                if ($ok) foreach ($value as $entry) self::value($entry, $rule[1], $path);
                break;
            case 'hosts':
                $ok = is_array($value) && count($value) <= 64;
                if ($ok) foreach ($value as $host => $ip) if (!ManagedProtocol::hostname($host) || !is_string($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) { $ok = false; break; }
                break;
            case 'padding':
                $ok = is_array($value) && array_is_list($value) && count($value) >= 2 && count($value) <= 33
                    && is_string($value[0]) && preg_match('/\Astop=([1-9]|[12][0-9]|3[0-2])\z/D', $value[0], $stop);
                $seen = [];
                if ($ok) foreach (array_slice($value, 1) as $line) {
                    if (!is_string($line) || strlen($line) > 256 || !preg_match('/\A([0-9]{1,2})=([0-9c,=-]+)\z/D', $line, $m)
                        || (int) $m[1] >= (int) $stop[1] || isset($seen[(int) $m[1]])) { $ok = false; break; }
                    $seen[(int) $m[1]] = true; $parts = explode(',', $m[2]);
                    if (count($parts) > 15) { $ok = false; break; }
                    foreach ($parts as $part) {
                        if ($part === 'c') continue;
                        if (!preg_match('/\A([0-9]{1,4})-([0-9]{1,4})\z/D', $part, $range)
                            || (int) $range[1] < 1 || (int) $range[1] > (int) $range[2] || (int) $range[2] > 4096) { $ok = false; break 2; }
                    }
                }
                break;
        }
        if (!$ok) throw new InvalidArgumentException('Неверное или неподдерживаемое значение: ' . $path);
    }

    /** Merge objects, replace lists: array_replace_recursive leaves stale list entries. */
    public static function merge(array $base, array $extra): array
    {
        foreach ($extra as $key => $value) {
            if ($value === [] && (!isset($base[$key]) || !is_array($base[$key]) || !array_is_list($base[$key]))) continue;
            if (is_array($value) && $value !== [] && !array_is_list($value) && is_array($base[$key] ?? null)) $base[$key] = self::merge($base[$key], $value);
            else $base[$key] = $value;
        }
        return $base;
    }

    public static function server(string $protocol, array $config, array $settings): array
    {
        $options = $settings['options'] ?? []; $server = $options['server'] ?? [];
        if ($protocol === 'mieru') return self::merge($config, $server);
        if (isset($server['log_level'])) { $config['log']['level'] = $server['log_level']; unset($server['log_level']); }
        if (isset($server['dns_server'])) { $config['dns']['servers'][0]['server'] = $server['dns_server']; unset($server['dns_server']); }
        $config['inbounds'][0] = self::merge($config['inbounds'][0], $server);
        if ($protocol === 'tuic') foreach (['heartbeat', 'zero_rtt_handshake'] as $field) {
            if (isset($options['client'][$field])) $config['inbounds'][0][$field] = $options['client'][$field];
        }
        if ($protocol === 'shadowtls' && !empty($options['multiplex']['enabled'])) {
            $config['inbounds'][1]['multiplex'] = ['enabled' => true, 'padding' => $options['multiplex']['padding'] ?? false];
        }
        return $config;
    }

    public static function profile(string $protocol, string $format, array $profile, array $settings): array
    {
        $options = $settings['options'] ?? []; $client = $options['client'] ?? [];
        if ($format === 'mihomo') {
            $proxy = &$profile['proxies'][0];
            foreach ($client as $field => $value) {
                switch ($field) {
                    case 'fingerprint': if ($value !== 'default') $proxy['client-fingerprint'] = $value; break;
                    case 'alpn':
                        if ($protocol === 'shadowtls') $proxy['plugin-opts']['alpn'] = $value;
                        else $proxy['alpn'] = $value;
                        break;
                    case 'heartbeat': $proxy['heartbeat-interval'] = self::milliseconds($value); break;
                    case 'zero_rtt_handshake': $proxy['reduce-rtt'] = $value; break;
                    case 'udp_over_stream':
                        if ($value) { unset($proxy['udp-relay-mode']); $proxy['udp-over-stream'] = true; $proxy['udp-over-stream-version'] = 2; }
                        break;
                    case 'idle_session_check_interval': case 'idle_session_timeout':
                        $proxy[str_replace('_', '-', $field)] = intdiv(self::milliseconds($value), 1000); break;
                    case 'trafficPattern': $proxy['traffic-pattern'] = base64_encode(self::trafficPatternBytes($value)); break;
                    case 'handshakeMode': $proxy['handshake-mode'] = $value; break;
                    default: $proxy[str_replace('_', '-', $field)] = $value;
                }
            }
            if ($protocol === 'shadowtls' && !empty($options['multiplex']['enabled'])) {
                $proxy['smux'] = [];
                foreach ($options['multiplex'] + ['protocol' => 'smux'] as $field => $value) $proxy['smux'][str_replace('_', '-', $field)] = $value;
            }
            $proxy = self::merge($proxy, $options['mihomo'] ?? []);
        } elseif ($format === 'singbox') {
            $index = $protocol === 'shadowtls' ? 1 : 0;
            $proxy = &$profile['outbounds'][$index];
            foreach ($client as $field => $value) {
                switch ($field) {
                    case 'fingerprint': if ($value !== 'default') $proxy['tls']['utls'] = ['enabled' => true, 'fingerprint' => $value]; break;
                    case 'alpn': $proxy['tls']['alpn'] = $value; break;
                    case 'udp': if (!$value) $profile['route']['rules'][] = ['network' => 'udp', 'action' => 'reject']; break;
                    case 'udp_over_stream': if ($value) { unset($proxy['udp_relay_mode']); $proxy['udp_over_stream'] = true; } break;
                    default: $proxy[$field] = $value;
                }
            }
            $proxy = self::merge($proxy, $options['singbox'] ?? []);
            if ($protocol === 'shadowtls' && !empty($options['multiplex']['enabled'])) $profile['outbounds'][0]['multiplex'] = $options['multiplex'] + ['protocol' => 'smux'];
        }
        return $profile;
    }

    public static function trafficPatternBytes(array $pattern): string
    {
        $out = '';
        foreach (['seed' => 1, 'unlockAll' => 2, 'tcpFragment' => 3, 'nonce' => 4, 'padding' => 5, 'lowEntropy' => 6] as $key => $number) {
            if (!array_key_exists($key, $pattern)) continue;
            $value = $pattern[$key];
            if ($key === 'seed' || $key === 'unlockAll') { $out .= self::protoField($number, (int) $value); continue; }
            $fields = match ($key) {
                'tcpFragment' => ['enable' => 1, 'maxSleepMs' => 2],
                'nonce' => ['type' => 1, 'applyToAllUDPPacket' => 2, 'minLen' => 3, 'maxLen' => 4, 'customHexStrings' => 5],
                'padding' => ['maxMiddlePaddingLen' => 1, 'maxEndPaddingLen' => 2],
                'lowEntropy' => ['mode' => 1, 'maskRotation' => 2],
            };
            $message = '';
            foreach ($fields as $field => $index) if (array_key_exists($field, $value)) {
                $entry = $value[$field];
                if ($field === 'customHexStrings') { foreach ($entry as $hex) $message .= self::protoField($index, $hex); continue; }
                if ($field === 'type') $entry = array_search($entry, self::NONCES, true);
                if ($field === 'mode') $entry = array_search($entry, self::ENTROPY, true);
                if ($field === 'maskRotation') {
                    $entry = preg_match('/_(RIGHT|LEFT)_([0-9]+)$/', $entry, $m) ? (int) $m[2] * ($m[1] === 'LEFT' ? 16 : 1) : 0;
                }
                $message .= self::protoField($index, (int) $entry);
            }
            $out .= self::protoField($number, $message);
        }
        return $out;
    }

    public static function protoField(int $number, string|int $value): string
    {
        $varint = static function (int $value): string {
            $out = '';
            for ($n = 0; $n < 9; $n++) {
                $byte = $value & 127; $value >>= 7; $out .= chr($byte | ($value ? 128 : 0));
                if (!$value) return $out;
            }
            return $out . "\x01"; // Sign-extended int32 uses a 10-byte protobuf varint.
        };
        return $varint(($number << 3) | (is_string($value) ? 2 : 0))
            . (is_string($value) ? $varint(strlen($value)) . $value : $varint($value));
    }
}
