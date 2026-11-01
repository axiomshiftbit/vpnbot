<?php

require_once __DIR__ . '/ExitNodeLink.php';
require_once __DIR__ . '/XrayNoise.php';

/** A node may describe its client, never supply arbitrary local Xray config. */
final class ManagedNodeProfile
{
    private static function fields(array $value, array $allowed, array $required = []): void
    {
        if (array_diff(array_keys($value), $allowed) || array_diff($required, array_keys($value))) {
            throw new InvalidArgumentException('Invalid managed node profile fields');
        }
    }

    private static function integer($value, int $min, int $max): int
    {
        if (!is_int($value) || $value < $min || $value > $max) throw new InvalidArgumentException('Invalid managed node limit');
        return $value;
    }

    private static function range($value, int $min, int $max): string
    {
        if (!is_string($value)) throw new InvalidArgumentException('Invalid managed node range');
        XrayNoise::range($value, $min, $max);
        return $value;
    }

    private static function smux(array $value): array
    {
        $fields = ['enabled', 'protocol', 'maxConnections', 'minStreams', 'maxStreams', 'padding', 'onlyTcp'];
        self::fields($value, [...$fields, 'logicalHalfClose', 'brutal-opts'], $fields);
        if ($value['enabled'] !== true || !is_bool($value['padding']) || !is_bool($value['onlyTcp'])
            || !in_array($value['protocol'], ['smux', 'h2mux'], true)) throw new InvalidArgumentException('Invalid SMUX profile');
        foreach (['maxConnections', 'minStreams', 'maxStreams'] as $field) self::integer($value[$field], 0, 4096);
        if ($value['maxStreams'] > 0 && ($value['maxConnections'] || $value['minStreams'])) throw new InvalidArgumentException('Conflicting SMUX limits');
        if (isset($value['logicalHalfClose']) && ($value['protocol'] !== 'smux' || !in_array($value['logicalHalfClose'], ['auto', 'require'], true))) {
            throw new InvalidArgumentException('Invalid SMUX half-close mode');
        }
        if (isset($value['brutal-opts'])) {
            $rates = $value['brutal-opts'];
            if (!is_array($rates)) throw new InvalidArgumentException('Invalid Brutal profile');
            self::fields($rates, ['enabled', 'up', 'down'], ['enabled', 'up', 'down']);
            if ($rates['enabled'] !== true) throw new InvalidArgumentException('Invalid Brutal flag');
            foreach (['up', 'down'] as $field) {
                if (!is_string($rates[$field]) || !preg_match('~^[1-9][0-9]{0,5}\s*(?:[KMG]bps|[KMG]Bps|bps|Bps)$~D', $rates[$field])) {
                    throw new InvalidArgumentException('Invalid Brutal rate');
                }
            }
        }
        return $value;
    }

    private static function masks(array $value): array
    {
        self::fields($value, ['tcp', 'udp']);
        foreach ($value as $protocol => &$list) {
            if (!is_array($list) || !array_is_list($list) || count($list) !== 1 || !is_array($list[0])) throw new InvalidArgumentException('Invalid finalmask list');
            self::fields($list[0], ['type', 'settings'], ['type', 'settings']);
            $type = $protocol === 'tcp' ? 'fragment' : 'noise';
            if ($list[0]['type'] !== $type || !is_array($list[0]['settings'])) throw new InvalidArgumentException('Invalid finalmask type');
            $settings = $list[0]['settings'];
            if ($type === 'fragment') {
                self::fields($settings, ['packets', 'length', 'delay', 'maxSplit'], ['packets', 'length', 'delay']);
                if ($settings['packets'] !== 'tlshello') self::range($settings['packets'], 1, 65535);
                self::range($settings['length'], 1, 16384);
                self::range($settings['delay'], 0, 1000);
                if (isset($settings['maxSplit'])) self::range($settings['maxSplit'], 1, 4096);
            } else {
                self::fields($settings, ['reset', 'noise'], ['reset', 'noise']);
                if (!is_array($settings['noise']) || !array_is_list($settings['noise']) || count($settings['noise']) > 8) throw new InvalidArgumentException('Invalid noise list');
                $items = [];
                foreach ($settings['noise'] as $item) {
                    if (!is_array($item)) throw new InvalidArgumentException('Invalid noise packet');
                    if (array_key_exists('rand', $item)) {
                        self::fields($item, ['rand', 'randRange', 'delay'], ['rand', 'randRange', 'delay']);
                        if ($item['randRange'] !== '0-255') throw new InvalidArgumentException('Invalid random byte range');
                        $item = ['type' => 'rand', 'packet' => $item['rand'], 'delay' => $item['delay']];
                    } else self::fields($item, ['type', 'packet', 'delay'], ['type', 'packet', 'delay']);
                    $items[] = $item;
                }
                $settings = XrayNoise::settings(['reset' => self::range($settings['reset'], 1, 86400)], $items);
            }
            $list[0]['settings'] = $settings;
        }
        unset($list);
        return $value;
    }

    public static function parse(array $profile, string $core): array
    {
        if (!isset($profile['link']) || !is_string($profile['link']) || !is_array($profile['outbound'] ?? null)
            || strlen(json_encode($profile, JSON_THROW_ON_ERROR)) > 65536) throw new InvalidArgumentException('Invalid managed node profile');
        // Reuse the normal bot's link validator for identity, TLS, Reality,
        // encryption and paths. Ignore the peer's raw dialer/settings/address.
        $parsed = ExitNodeLink::parse($profile['link']);
        if ($parsed['protocol'] !== 'vless') throw new InvalidArgumentException('A managed node requires VLESS');
        $outbound = $parsed['outbound'];
        $extra = $profile['outbound'];
        if (($profile['channel'] ?? 'vless') === 'wireguard') {
            return $parsed + ['managed_outbound' => self::wireguard($extra, $parsed['address'])];
        }
        $channel = $profile['channel'] ?? 'vless';
        if (!in_array($channel, ['vless', 'amnezia'], true)) throw new InvalidArgumentException('Unknown node channel');
        $amnezia = $channel === 'amnezia' ? self::amnezia($profile['amnezia'] ?? null, $parsed['address']) : null;
        self::fields($extra, ['tag', 'protocol', 'settings', 'streamSettings', 'smux', 'mux']);
        if (isset($extra['smux'])) {
            if ($core !== 'fork' || !is_array($extra['smux'])) throw new InvalidArgumentException('SMUX requires the fork on the main bot');
            $outbound['smux'] = self::smux($extra['smux']);
        }
        if (isset($extra['mux'])) {
            $expected = ['enabled' => true, 'concurrency' => 8, 'xudpConcurrency' => 16, 'xudpProxyUDP443' => 'allow'];
            if ($core !== 'fork' || $outbound['streamSettings']['network'] !== 'xhttp' || $extra['mux'] !== $expected || isset($outbound['smux'])) {
                throw new InvalidArgumentException('Invalid XHTTP Mux.Cool profile');
            }
            $outbound['mux'] = $expected;
        }
        $stream = $extra['streamSettings'] ?? [];
        if (!is_array($stream)) throw new InvalidArgumentException('Invalid node stream');
        self::fields($stream, ['network', 'security', 'tlsSettings', 'realitySettings', 'wsSettings', 'grpcSettings', 'xhttpSettings', 'finalmask']);
        if (isset($stream['finalmask'])) {
            if (!is_array($stream['finalmask'])) throw new InvalidArgumentException('Invalid finalmask profile');
            $outbound['streamSettings']['finalmask'] = self::masks($stream['finalmask']);
        }
        // MPTCP is never inherited from an external profile.
        $outbound['streamSettings']['sockopt'] = ['tcpMptcp' => false];
        return $parsed + ['managed_outbound' => $outbound] + ($amnezia === null ? [] : ['managed_amnezia' => $amnezia]);
    }

    private static function amnezia($value, string $address): array
    {
        if (!is_array($value)) throw new InvalidArgumentException('Invalid Amnezia profile');
        $fields = ['endpoint', 'port', 'private', 'public', 'psk', 'mtu', 'parameters'];
        self::fields($value, $fields, $fields);
        if ($value['endpoint'] !== $address || $value['port'] !== 51821) throw new InvalidArgumentException('Invalid Amnezia endpoint');
        self::integer($value['mtu'], 1280, 1420);
        foreach (['private', 'public', 'psk'] as $field) self::key($value[$field]);
        $params = $value['parameters'];
        if (!is_array($params)) throw new InvalidArgumentException('Invalid Amnezia parameters');
        $ints = ['Jc' => [0,10], 'Jmin' => [64,1024], 'Jmax' => [64,1024],
            'S1' => [12,64], 'S2' => [12,64], 'S3' => [12,64], 'S4' => [12,32]];
        $ranges = ['ContentPaddingAddition' => [10,40], 'RekeyAfterTime' => [110,130], 'RekeyTimeout' => [5,10],
            'RejectAfterTime' => [170,190], 'KeepaliveTimeout' => [10,15], 'MaxHandshakeAttempts' => [15,25],
            'H1' => [1,2147483647], 'H2' => [1,2147483647], 'H3' => [1,2147483647], 'H4' => [1,2147483647]];
        $fields = [...array_keys($ints), ...array_keys($ranges), 'HeaderProtectionKey'];
        self::fields($params, $fields, $fields);
        foreach ($ints as $name => $bounds) self::integer($params[$name], ...$bounds);
        $sizes = [$params['S1']+148, $params['S2']+92, $params['S3']+64, $params['S4']+32];
        if ($params['Jmin'] > $params['Jmax'] || $params['S1'] === $params['S2'] || count(array_unique($sizes)) !== 4) {
            throw new InvalidArgumentException('Incompatible Amnezia padding');
        }
        $headers = [];
        foreach ($ranges as $name => [$low, $high]) {
            if (!is_string($params[$name]) || !preg_match('~^([0-9]{1,10})-([0-9]{1,10})$~D', $params[$name], $match)) {
                throw new InvalidArgumentException('Invalid Amnezia range');
            }
            [$left, $right] = [(int) $match[1], (int) $match[2]];
            if ($left < $low || $left > $right || $right > $high) throw new InvalidArgumentException('Invalid Amnezia range');
            if (str_starts_with($name, 'H')) {
                foreach ($headers as [$a, $b]) if ($left <= $b && $a <= $right) throw new InvalidArgumentException('Overlapping Amnezia headers');
                $headers[] = [$left, $right];
            }
        }
        self::key($params['HeaderProtectionKey']);
        return $value;
    }

    private static function key($value): void
    {
        $raw = is_string($value) && strlen($value) === 44 ? base64_decode($value, true) : false;
        if (!is_string($raw) || strlen($raw) !== 32 || base64_encode($raw) !== $value || $raw === str_repeat("\0", 32)) {
            throw new InvalidArgumentException('Invalid backup channel key');
        }
    }

    private static function wireguard(array $value, string $address): array
    {
        self::fields($value, ['tag', 'protocol', 'settings'], ['protocol', 'settings']);
        if ($value['protocol'] !== 'wireguard' || !is_array($value['settings'])) throw new InvalidArgumentException('Invalid WireGuard profile');
        $settings = $value['settings'];
        $fields = ['secretKey', 'address', 'mtu', 'noKernelTun', 'peers', 'remoteDNS'];
        self::fields($settings, $fields, $fields);
        self::integer($settings['mtu'], 1280, 1420);
        $family = match ($settings['address']) {
            ['10.77.77.2/32'] => 4, ['fd42:7662:77::2/128'] => 6,
            default => throw new InvalidArgumentException('Invalid WireGuard tunnel address'),
        };
        $dns = $family === 4 ? ['1.1.1.1', '9.9.9.9'] : ['2606:4700:4700::1111', '2620:fe::fe'];
        if ($settings['noKernelTun'] !== true || $settings['remoteDNS'] !== $dns
            || !is_array($settings['peers']) || !array_is_list($settings['peers']) || count($settings['peers']) !== 1
            || !is_array($settings['peers'][0])) throw new InvalidArgumentException('Invalid WireGuard peer list');
        $peer = $settings['peers'][0];
        $fields = ['publicKey', 'preSharedKey', 'endpoint', 'allowedIPs', 'keepAlive'];
        self::fields($peer, $fields, $fields);
        $endpoint = (str_contains($address, ':') ? "[$address]" : $address) . ':51820';
        if ($peer['endpoint'] !== $endpoint || $peer['allowedIPs'] !== ['0.0.0.0/0', '::/0'] || $peer['keepAlive'] !== 25) {
            throw new InvalidArgumentException('Invalid WireGuard endpoint');
        }
        foreach ([$settings['secretKey'], $peer['publicKey'], $peer['preSharedKey']] as $key) {
            $bytes = is_string($key) && strlen($key) === 44 ? base64_decode($key, true) : false;
            if (!is_string($bytes) || strlen($bytes) !== 32 || base64_encode($bytes) !== $key || $bytes === str_repeat("\0", 32)) {
                throw new InvalidArgumentException('Invalid WireGuard key');
            }
        }
        // All fields were validated, including the literal endpoint inherited
        // from the regular link. No arbitrary route, DNS or kernel TUN config.
        return ['protocol' => 'wireguard', 'settings' => $settings];
    }
}
