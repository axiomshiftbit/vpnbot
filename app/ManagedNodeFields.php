<?php

/** UI metadata only. The node's typed schema and real core validate an apply. */
final class ManagedNodeFields
{
    public const GROUPS = [
        'basic' => ['ru' => 'Транспорт и ядро', 'en' => 'Transport and core'],
        'network' => ['ru' => 'IPv4 / IPv6', 'en' => 'IPv4 / IPv6'], 'domains' => ['ru' => 'Домены и сертификат', 'en' => 'Domains and certificate'],
        'crypto' => ['ru' => 'Шифрование', 'en' => 'Encryption'], 'reality' => ['ru' => 'REALITY', 'en' => 'REALITY'],
        'smux' => ['ru' => 'SMUX', 'en' => 'SMUX'], 'xhttp' => ['ru' => 'XHTTP', 'en' => 'XHTTP'],
        'dpi' => ['ru' => 'DPI клиента', 'en' => 'Client DPI'], 'finalmask' => ['ru' => 'Маски сервера', 'en' => 'Server masks'],
        'sniffing' => ['ru' => 'Sniffing', 'en' => 'Sniffing'], 'torrent' => ['ru' => 'Торренты', 'en' => 'Torrents'],
        'reserve' => ['ru' => 'Резервный канал', 'en' => 'Backup channel'],
        'wireguard' => ['ru' => 'WireGuard', 'en' => 'WireGuard'], 'amnezia' => ['ru' => 'AmneziaWG', 'en' => 'AmneziaWG'],
    ];

    public static function all(): array
    {
        $fields = [
            'transport' => ['basic', 'ru' => 'Транспорт', 'en' => 'Transport', 'choice', ['reality', 'ws', 'grpc', 'xhttp', 'trojan-grpc']],
            'core' => ['basic', 'ru' => 'Ядро', 'en' => 'Core', 'choice', ['origin', 'origin2', 'origin3', 'fork']],
            'family' => ['network', 'ru' => 'Выход в интернет', 'en' => 'Internet egress', 'choice', [4, 6]],
            'connect_family' => ['network', 'ru' => 'Связь бот → нода', 'en' => 'Bot → node link', 'choice', [4, 6]],
            'vpn_sources' => ['network', 'ru' => 'Серверы только для VPN 443', 'en' => 'VPN-only servers (443)', 'list'],
            'domain' => ['domains', 'ru' => 'Свой домен', 'en' => 'Own domain', 'string'],
            'domain_aliases' => ['domains', 'ru' => 'Дополнительные домены', 'en' => 'Additional domains', 'list'],
            'cover' => ['domains', 'ru' => 'Заглушка с паролем', 'en' => 'Password cover', 'bool'],
            'mask' => ['reality', 'ru' => 'Домен REALITY', 'en' => 'REALITY domain', 'string'],
            'wireguard.enabled' => ['wireguard', 'ru' => 'Разрешить WireGuard', 'en' => 'Enable WireGuard', 'bool'],
            'wireguard.active' => ['wireguard', 'ru' => 'Связь бота через WireGuard', 'en' => 'Bot link over WireGuard', 'bool'],
            'wireguard.mtu' => ['wireguard', 'WireGuard MTU', 'WireGuard MTU', 'int'],
            'amnezia.version' => ['amnezia', 'ru'=>'Версия протокола', 'en'=>'Protocol version', 'choice', ['1.5','2.0','3.0','3.1']],
            'amnezia.enabled' => ['amnezia', 'ru' => 'Разрешить AmneziaWG', 'en' => 'Enable AmneziaWG', 'bool'],
            'amnezia.active' => ['amnezia', 'ru' => 'Связь бота через AmneziaWG', 'en' => 'Bot link over AmneziaWG', 'bool'],
            'amnezia.mtu' => ['amnezia', 'AmneziaWG MTU', 'AmneziaWG MTU', 'int'],
            'xray.fingerprint' => ['basic', 'ru' => 'Отпечаток клиента', 'en' => 'Client fingerprint', 'choice', ['chrome', 'firefox', 'safari', 'ios', 'edge', 'qq', 'random', 'android', '360']],
            'xray.encryption.auth' => ['crypto', 'VLESS Encryption', 'VLESS Encryption', 'choice', ['off', 'x25519', 'mlkem768']],
            'xray.encryption.mode' => ['crypto', 'ru' => 'Режим шифрования', 'en' => 'Encryption mode', 'choice', ['native', 'xorpub', 'random']],
            'xray.reality.mldsa' => ['crypto', 'ru' => 'Постквантовая подпись ML-DSA', 'en' => 'Post-quantum ML-DSA signature', 'bool'],
            'xray.reality.requireMlkem' => ['crypto', 'ru' => 'Требовать ML-KEM (fork)', 'en' => 'Require ML-KEM (fork)', 'bool'],
            'xray.reality.maxTimeDiff' => ['reality', 'ru' => 'Допуск времени, мс', 'en' => 'Time tolerance, ms', 'int'],
            'xray.reality.minClientVer' => ['reality', 'ru' => 'Минимальная версия клиента', 'en' => 'Minimum client version', 'string'],
            'xray.reality.maxClientVer' => ['reality', 'ru' => 'Максимальная версия клиента', 'en' => 'Maximum client version', 'string'],
            'xray.reality.xver' => ['reality', 'ru' => 'PROXY protocol к сайту', 'en' => 'PROXY protocol to site', 'choice', [0, 1, 2]],
            'xray.reality.spiderX' => ['reality', 'ru' => 'Путь spiderX', 'en' => 'spiderX path', 'string'],
            'xray.smux.enabled' => ['smux', 'ru' => 'Включить SMUX (fork)', 'en' => 'Enable SMUX (fork)', 'bool'],
            'xray.smux.protocol' => ['smux', 'ru' => 'Протокол', 'en' => 'Protocol', 'choice', ['smux', 'h2mux']],
            'xray.smux.max_connections' => ['smux', 'ru' => 'Максимум соединений', 'en' => 'Maximum connections', 'int'],
            'xray.smux.min_streams' => ['smux', 'ru' => 'Минимум потоков', 'en' => 'Minimum streams', 'int'],
            'xray.smux.max_streams' => ['smux', 'ru' => 'Максимум потоков', 'en' => 'Maximum streams', 'int'],
            'xray.smux.padding' => ['smux', 'Padding', 'Padding', 'bool'],
            'xray.smux.only_tcp' => ['smux', 'ru' => 'Только TCP', 'en' => 'TCP only', 'bool'],
            'xray.smux.half_close' => ['smux', 'ru' => 'Половинное закрытие', 'en' => 'Half-close', 'choice', ['off', 'auto', 'require']],
            'xray.smux.h2mux_frame' => ['smux', 'ru' => 'Размер кадра h2mux', 'en' => 'h2mux frame size', 'int'],
            'xray.smux.brutal.enabled' => ['smux', 'Brutal', 'Brutal', 'bool'],
            'xray.smux.brutal.up' => ['smux', 'ru' => 'Brutal: отправка', 'en' => 'Brutal: upload', 'string'],
            'xray.smux.brutal.down' => ['smux', 'ru' => 'Brutal: приём', 'en' => 'Brutal: download', 'string'],
            'xray.xhttp.mode' => ['xhttp', 'ru' => 'Режим XHTTP', 'en' => 'XHTTP mode', 'choice', ['auto', 'packet-up', 'stream-up', 'stream-one']],
            'xray.xhttp.mux' => ['xhttp', 'Mux.Cool (fork)', 'Mux.Cool (fork)', 'bool'],
            'xray.sniffing.enabled' => ['sniffing', 'Sniffing', 'Sniffing', 'bool'],
            'xray.sniffing.metadataOnly' => ['sniffing', 'ru' => 'Только метаданные', 'en' => 'Metadata only', 'bool'],
            'xray.sniffing.routeOnly' => ['sniffing', 'ru' => 'Только маршрутизация', 'en' => 'Routing only', 'bool'],
            'xray.sniffing.destOverride' => ['sniffing', 'ru' => 'Протоколы: HTTP/TLS/QUIC', 'en' => 'Protocols: HTTP/TLS/QUIC', 'list'],
            'xray.sniffing.ipsExcluded' => ['sniffing', 'ru' => 'Исключения IP/CIDR', 'en' => 'IP/CIDR exclusions', 'list'],
            'xray.sniffing.domainsExcluded' => ['sniffing', 'ru' => 'Исключения доменов', 'en' => 'Domain exclusions', 'list'],
            'xray.block_torrent' => ['torrent', 'ru' => 'Блокировать BitTorrent', 'en' => 'Block BitTorrent', 'bool'],
        ];
        $fields['wireguard.keepalive'] = ['wireguard', 'ru' => 'Keepalive, с', 'en' => 'Keepalive, s', 'int'];
        $fields['amnezia.rotation_days'] = ['amnezia', 'ru'=>'Автогенерация: дней (0 — выкл.)', 'en'=>'Auto generation: days (0 = off)', 'choice', [0,1,3,7,14,30]];
        $fields['amnezia.keepalive'] = ['amnezia', 'ru' => 'Keepalive, с (диапазон)', 'en' => 'Keepalive, s (range)', 'string'];
        foreach (['Jc','Jmin','Jmax','S1','S2','S3','S4','H1','H2','H3','H4','I1','I2','I3','I4','I5',
            'ContentPaddingAddition','RekeyAfterTime','RekeyTimeout','RejectAfterTime','KeepaliveTimeout','MaxHandshakeAttempts'] as $name) {
            $fields['amnezia.parameters.'.$name] = ['amnezia', $name, $name, in_array($name,['Jc','Jmin','Jmax','S1','S2','S3','S4'],true) ? 'int' : 'string'];
        }
        foreach (['noGRPCHeader'=>'bool','xPaddingBytes'=>'string','scMaxEachPostBytes'=>'int',
            'scMinPostsIntervalMs'=>'int','scStreamUpServerSecs'=>'string'] as $name=>$type) $fields['xray.xhttp.extra.'.$name] = ['xhttp', $name, $name, $type];
        foreach (['cMaxReuseTimes'=>'int','maxConcurrency'=>'string','maxConnections'=>'int','hKeepAlivePeriod'=>'int',
            'hMaxRequestTimes'=>'string','hMaxReusableSecs'=>'string'] as $name=>$type) $fields['xray.xhttp.extra.xmux.'.$name] = ['xhttp', 'XMUX '.$name, 'XMUX '.$name, $type];
        foreach (['dpi', 'finalmask'] as $group) {
            foreach (['enabled' => ['Fragment', 'Fragment', 'bool'], 'packets' => ['packets', 'packets', 'string'],
                'length' => ['length', 'length', 'string'], 'delay' => ['interval (ms)', 'interval (ms)', 'string'],
                'maxSplit' => ['maxSplit', 'maxSplit', 'string']] as $name => $field) $fields["xray.$group.fragment.$name"] = [$group, ...$field];
            foreach (['enabled' => ['UDP noise', 'UDP noise', 'bool'], 'reset' => ['reset', 'reset', 'string'],
                'list' => ['noise (JSON)', 'noise (JSON)', 'json']] as $name => $field) $fields["xray.$group.noise.$name"] = [$group, ...$field];
        }
        return array_map('array_values', $fields);
    }

    /** Same scope as the main bot: settings of another transport stay out of the menu. */
    public static function groupActive(array $options, string $group): bool
    {
        $transport = $options['transport'] ?? 'reality';
        return match ($group) {
            'reality' => $transport === 'reality',
            'xhttp' => $transport === 'xhttp',
            'crypto' => $transport !== 'trojan-grpc',
            default => true,
        };
    }

    public static function fieldActive(array $options, string $path): bool
    {
        $field = self::all()[$path] ?? null;
        if (!$field || !self::groupActive($options, $field[0])) return false;
        return !str_starts_with($path, 'xray.reality.') || ($options['transport'] ?? 'reality') === 'reality';
    }

    public static function get(array $options, string $path)
    {
        $value = $options;
        foreach (explode('.', $path) as $name) $value = is_array($value) ? ($value[$name] ?? null) : null;
        return $value;
    }

    /** The node's reserved ranges (scripts/node_config.py PRIVATE4/PRIVATE6): bot and node agree. */
    public const RESERVED = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12',
        '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24',
        '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4', '::/96', '::ffff:0:0/96', '64:ff9b::/96', '64:ff9b:1::/48',
        '100::/64', '2001::/23', '2001:db8::/32', '2002::/16', '3fff::/20', 'fc00::/7', 'fe80::/10', 'ff00::/8'];

    private static function reserved(string $packed): bool
    {
        foreach (self::RESERVED as $network) {
            [$base, $bits] = explode('/', $network);
            $base = inet_pton($base);
            if (strlen($base) !== strlen($packed)) continue;
            $bytes = intdiv((int) $bits, 8); $rest = (int) $bits % 8;
            if (strncmp($base, $packed, $bytes) !== 0) continue;
            if ($rest === 0 || ((ord($base[$bytes]) ^ ord($packed[$bytes])) & (0xff << (8 - $rest)) & 0xff) === 0) return true;
        }
        return false;
    }

    /** Public unicast IPv4/IPv6 only, as the node enforces; at most 32, deduplicated. */
    public static function vpnSources(array $value): array
    {
        $result = [];
        foreach ($value as $ip) {
            $packed = is_string($ip) && filter_var($ip, FILTER_VALIDATE_IP) ? inet_pton($ip) : false;
            // IPv6 outside 2000::/3 is not global unicast for the node either.
            if ($packed === false || self::reserved($packed) || strlen($packed) === 16 && (ord($packed[0]) & 0xe0) !== 0x20) {
                throw new InvalidArgumentException('VPN-only servers need public IP addresses');
            }
            $result[inet_ntop($packed)] = true;
        }
        if (count($result) > 32) throw new InvalidArgumentException('At most 32 VPN-only servers are supported');
        return array_keys($result);
    }

    public static function change(array $options, string $path, $value): array
    {
        $field = self::all()[$path] ?? null;
        if (!$field) throw new InvalidArgumentException('Unknown node setting');
        $type = $field[3];
        if ($type === 'choice' && !in_array($value, $field[4], true) || $type === 'bool' && !is_bool($value)
            || $type === 'int' && (!is_int($value) || $value < 0 || $value > 86400000)
            || $type === 'string' && (!is_string($value) || strlen($value) > 4096 || preg_match('~[\x00-\x1f\x7f]~', $value))
            || in_array($type, ['json', 'list'], true) && (!is_array($value) || !array_is_list($value) || count($value) > 128)) {
            throw new InvalidArgumentException('Invalid node setting');
        }
        if ($path === 'vpn_sources') $value = self::vpnSources($value);
        $target =& $options;
        foreach (explode('.', $path) as $name) { if (!isset($target[$name])) $target[$name] = []; $target =& $target[$name]; }
        $target = $value;
        unset($target);
        if ($value === true && $path === 'wireguard.active') $options['amnezia']['active'] = false;
        if ($value === true && $path === 'amnezia.active') $options['wireguard']['active'] = false;
        if ($path === 'mask' && ($options['transport'] ?? '') === 'reality') $options['cover'] = false;
        if ($path === 'transport') {
            // These options would invalidate the new transport, and their screen
            // is hidden there: never strand a draft the user cannot correct.
            if ($value !== 'xhttp' && !empty($options['xray']['xhttp']['mux'])) $options['xray']['xhttp']['mux'] = false;
            if ($value !== 'reality' && !empty($options['xray']['reality']['requireMlkem'])) $options['xray']['reality']['requireMlkem'] = false;
            if ($value === 'trojan-grpc' && isset($options['xray']['encryption']['auth'])) $options['xray']['encryption']['auth'] = 'off';
        }
        if ($value === false && in_array($path, ['wireguard.enabled', 'amnezia.enabled'], true)) $options[explode('.', $path)[0]]['active'] = false;
        if ($value === true && in_array($path, ['wireguard.active', 'amnezia.active'], true)) $options[explode('.', $path)[0]]['enabled'] = true;
        return $options;
    }
}
