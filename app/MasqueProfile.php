<?php

require_once __DIR__ . '/XrayNoise.php';

/** Native Xray CONNECT-IP profiles. Other bundled clients cannot import these. */
final class MasqueProfile
{
    public static function noise(array $settings): ?array
    {
        $noise = $settings['options']['noise'] ?? [];
        if (empty($noise['enabled'])) return null;
        return XrayNoise::settings($noise + ['reset' => '60-120'], $noise['packets'] ?? XrayNoise::dynamicPackets());
    }

    /** XMUX клиента (Xray 26.10.17+, форк 26.10.13+): число туннелей CONNECT-IP и срок их повторного использования. */
    public static function xmux(array $client): ?array
    {
        if (!isset($client['connections']) && !isset($client['reuse'])) return null;
        // Без hMaxReusableSecs ядро не переоткрывает туннель: умолчание 1800-3000
        // действует, только когда xmux не задан вовсе.
        $reuse = (string) ($client['reuse'] ?? '1800-3000');
        if (!preg_match('/\A([0-9]{2,5})(?:-([0-9]{2,5}))?\z/D', $reuse, $m)
            || (int) $m[1] < 60 || (int) ($m[2] ?? $m[1]) < (int) $m[1] || (int) ($m[2] ?? $m[1]) > 86400) {
            throw new InvalidArgumentException('XMUX: срок туннеля — 60–86400 секунд, число или диапазон, начало не выше конца');
        }
        return ['maxConnections' => $client['connections'] ?? 1, 'hMaxReusableSecs' => isset($m[2]) ? $reuse : (int) $reuse];
    }

    public static function server(array $state): array
    {
        $s = $state['settings']; $users = [];
        foreach ($state['users'] as $id => $u) if ($u['enabled']) $users[] = ['email' => $id, 'pass' => $u['password'], 'level' => 0];
        $stream = ['network' => 'masque', 'security' => 'tls', 'tlsSettings' => ['alpn' => ['h3', 'h2'],
            'minVersion' => '1.3', 'certificates' => [['certificateFile' => $s['certificate'], 'keyFile' => $s['private_key']]]]];
        if ($noise = self::noise($s)) $stream['finalmask']['udp'] = [['type' => 'noise', 'settings' => $noise]];
        $blocked = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
            '172.16.0.0/12', '192.168.0.0/16', '198.18.0.0/15', '224.0.0.0/4', '240.0.0.0/4',
            '::/128', '::1/128', '64:ff9b::/96', '64:ff9b:1::/48', 'fc00::/7', 'fe80::/10', 'ff00::/8', '2002::/16', '2001::/32'];
        foreach ($s['blocked_ips'] as $ip) $blocked[] = $ip . (str_contains($ip, ':') ? '/128' : '/32');
        return ['log' => ['loglevel' => 'warning'], 'stats' => new stdClass(),
            'api' => ['tag' => 'api', 'services' => ['StatsService']],
            'policy' => ['levels' => (object) ['0' => ['statsUserUplink' => true, 'statsUserDownlink' => true]]],
            'inbounds' => [
                ['tag' => 'masque', 'listen' => '0.0.0.0', 'port' => 24449, 'protocol' => 'masque',
                    // Каждый туннель (с XMUX их у клиента до 4) берёт по адресу из каждого пула.
                    // Пул IPv4 больше: при исчерпании первым кончается IPv6, и туннель
                    // без адреса IPv4 не возникает.
                    'settings' => ['users' => $users, 'address' => ['10.14.0.1/21', 'fd14::1/118'], 'mtu' => 1280],
                    'streamSettings' => $stream],
                ['tag' => 'api', 'listen' => '127.0.0.1', 'port' => 10085, 'protocol' => 'dokodemo-door', 'settings' => ['address' => '127.0.0.1']]],
            'outbounds' => [['tag' => 'direct', 'protocol' => 'freedom'], ['tag' => 'block', 'protocol' => 'blackhole'],
                ['tag' => 'warp', 'protocol' => 'socks', 'settings' => ['servers' => [['address' => '10.10.0.13', 'port' => 1080]]]]],
            'routing' => ['rules' => [
                ['type' => 'field', 'inboundTag' => ['api'], 'outboundTag' => 'api'],
                ['type' => 'field', 'ip' => $blocked, 'outboundTag' => 'block'],
                ['type' => 'field', 'inboundTag' => ['masque'], 'outboundTag' => $s['egress']]]]];
    }

    public static function client(string $id, array $user, array $settings): array
    {
        $http = $settings['options']['client']['http'] ?? 'h3';
        $stream = ['network' => 'masque', 'security' => 'tls',
            'tlsSettings' => ['serverName' => $settings['sni'], 'alpn' => [$http], 'minVersion' => '1.3'],
            'masqueSettings' => ['user' => $id, 'pass' => $user['password']]];
        if ($xmux = self::xmux($settings['options']['client'] ?? [])) $stream['masqueSettings']['xmux'] = $xmux;
        if ($http === 'h3' && ($noise = self::noise($settings))) $stream['finalmask']['udp'] = [['type' => 'noise', 'settings' => $noise]];
        return ['log' => ['loglevel' => 'warning'],
            'inbounds' => [['tag' => 'local', 'listen' => '127.0.0.1', 'port' => 1080, 'protocol' => 'socks', 'settings' => ['udp' => true]]],
            'outbounds' => [['tag' => 'VPN', 'protocol' => 'masque',
                'settings' => ['address' => $settings['host'], 'port' => $settings['port'], 'remoteDNS' => [$settings['dns']]],
                'streamSettings' => $stream]]];
    }
}
