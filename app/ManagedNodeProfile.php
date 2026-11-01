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
        if (isset($outbound['streamSettings']['xhttpSettings']['extra'])) {
            self::xhttpExtra($outbound['streamSettings']['xhttpSettings']['extra']);
        }
        // MPTCP is never inherited from an external profile.
        $outbound['streamSettings']['sockopt'] = ['tcpMptcp' => false];
        return $parsed + ['managed_outbound' => $outbound] + ($amnezia === null ? [] : ['managed_amnezia' => $amnezia]);
    }

    private static function xhttpExtra(array $extra): void
    {
        self::fields($extra, ['xmux', 'noGRPCHeader', 'xPaddingBytes', 'scMaxEachPostBytes', 'scMinPostsIntervalMs', 'scStreamUpServerSecs']);
        if (isset($extra['noGRPCHeader']) && !is_bool($extra['noGRPCHeader'])) throw new InvalidArgumentException('Invalid XHTTP header flag');
        foreach (['xPaddingBytes'=>65535, 'scStreamUpServerSecs'=>86400] as $name=>$max) if (isset($extra[$name])) self::range($extra[$name], 0, $max);
        if (isset($extra['scMaxEachPostBytes'])) self::integer($extra['scMaxEachPostBytes'], 1, 16000000);
        if (isset($extra['scMinPostsIntervalMs'])) self::integer($extra['scMinPostsIntervalMs'], 0, 60000);
        if (isset($extra['xmux'])) {
            $mux = $extra['xmux'];
            if (!is_array($mux)) throw new InvalidArgumentException('Invalid XHTTP mux');
            self::fields($mux, ['cMaxReuseTimes','maxConcurrency','maxConnections','hKeepAlivePeriod','hMaxRequestTimes','hMaxReusableSecs']);
            foreach (['maxConcurrency','hMaxRequestTimes','hMaxReusableSecs'] as $name) if (isset($mux[$name])) self::range($mux[$name], 0, 99999);
            foreach (['cMaxReuseTimes','maxConnections','hKeepAlivePeriod'] as $name) if (isset($mux[$name])) self::integer($mux[$name], 0, 1000000);
            if (!empty($mux['maxConnections']) && array_sum(array_map('intval', explode('-', $mux['maxConcurrency'] ?? '16-32')))) throw new InvalidArgumentException('Conflicting XHTTP mux limits');
        }
    }

    /** Export only validated fields in the stable 3x-ui outbound format. */
    public static function panel(array $profile, string $core, string $name): array
    {
        if (!preg_match('~^[A-Za-z0-9_.-]{1,40}$~D',$name)) throw new InvalidArgumentException('Invalid panel tag');
        $parsed=self::parse($profile,$core);
        $outbound=$parsed['managed_outbound']; $outbound['tag']=$name;
        if (($profile['channel']??'vless')!=='amnezia') return $outbound;
        $awg=$parsed['managed_amnezia']; $params=$awg['parameters'];
        $settings=['secretKey'=>$awg['private'],'address'=>['10.77.78.'.(($awg['slot']??0)+2).'/32'],
            'mtu'=>$awg['mtu'],'s3'=>0,'s4'=>0,'randomTrailers'=>($awg['version']??'3.1')==='3.1','disableCookies'=>false,
            'peers'=>[['publicKey'=>$awg['public'],'presharedKey'=>$awg['psk'],'allowedIPs'=>['10.77.78.1/32'],
                'endpoint'=>(str_contains($awg['endpoint'],':')?'['.$awg['endpoint'].']':$awg['endpoint']).':51821',
                'keepAlive'=>(int)($awg['keepalive']??25)]]];
        foreach ($params as $key=>$value) $settings[lcfirst($key)]=$value;
        foreach (['H1','H2','H3'] as $key) if (count(array_unique(explode('-', $params[$key]))) > 1) $settings['randomTrailers']=false;
        $tag=$name.'-awg';
        $outbound['settings']['vnext'][0]['address']='10.77.78.1';
        $outbound['settings']['vnext'][0]['port']=443;
        $outbound['streamSettings']['sockopt']['dialerProxy']=$tag;
        // The carrier exposes only the VLESS listener, never arbitrary LAN
        // forwarding. Route to the VLESS tag, which retains TLS/REALITY.
        return ['outbounds'=>[$outbound,['tag'=>$tag,'protocol'=>'amneziawg','settings'=>$settings]]];
    }

    private static function amnezia($value, string $address): array
    {
        if (!is_array($value)) throw new InvalidArgumentException('Invalid Amnezia profile');
        $fields = ['endpoint', 'port', 'private', 'public', 'psk', 'mtu', 'parameters'];
        self::fields($value, [...$fields, 'keepalive', 'version', 'slot'], $fields);
        if (isset($value['slot'])) self::integer($value['slot'],0,32);
        $version=$value['version'] ?? '3.1';
        if (!in_array($version,['1.5','2.0','3.0','3.1'],true)) throw new InvalidArgumentException('Invalid Amnezia version');
        if (isset($value['keepalive'])) {
            self::range($value['keepalive'], 0, 65535);
            if (!str_starts_with($version,'3.') && !preg_match('~^[0-9]+$~D',$value['keepalive'])) throw new InvalidArgumentException('Legacy keepalive must be fixed');
        }
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
        if (!str_starts_with($version,'3.')) {
            foreach ($ints as $name=>&$bounds) if (str_starts_with($name,'S')) $bounds[0]=0;
            unset($bounds);
            $ranges=array_intersect_key($ranges,array_flip(['H1','H2','H3','H4']));
        }
        if ($version==='1.5') {
            unset($ints['S3'],$ints['S4']);
            foreach ($ranges as &$bounds) $bounds[1]=4294967295;
            unset($bounds);
        }
        $fields = [...array_keys($ints), ...array_keys($ranges), ...(str_starts_with($version,'3.')?['HeaderProtectionKey']:[])];
        self::fields($params, [...$fields,'I1','I2','I3','I4','I5'], $fields);
        foreach (['I1','I2','I3','I4','I5'] as $name) if (isset($params[$name]) && $params[$name] !== '') {
            $valueCps = $params[$name];
            if (!is_string($valueCps) || strlen($valueCps) > 4096 || substr_count($valueCps, '<t>') > 1
                || !preg_match('~^(?:<b 0x[0-9a-fA-F]+>|<(?:r|rc|rd) [0-9]{1,4}>|<t>)+$~D', $valueCps)) throw new InvalidArgumentException('Invalid Amnezia signature');
            preg_match_all('~<(?:r|rc|rd) ([0-9]+)>~', $valueCps, $matches);
            foreach ($matches[1] as $length) if ((int)$length > 1000) throw new InvalidArgumentException('Amnezia signature field too long');
            XrayNoise::expression($valueCps);
        }
        foreach ($ints as $name => $bounds) self::integer($params[$name], ...$bounds);
        $sizes = [$params['S1']+148, $params['S2']+92, ($params['S3']??0)+64, ($params['S4']??0)+32];
        if ($params['Jmin'] > $params['Jmax'] || $params['S1'] === $params['S2'] || count(array_unique($sizes)) !== 4) {
            throw new InvalidArgumentException('Incompatible Amnezia padding');
        }
        $headers = [];
        foreach ($ranges as $name => [$low, $high]) {
            if (!is_string($params[$name]) || !preg_match($version==='1.5'?'~^([0-9]{1,10})$~D':'~^([0-9]{1,10})-([0-9]{1,10})$~D', $params[$name], $match)) {
                throw new InvalidArgumentException('Invalid Amnezia range');
            }
            [$left, $right] = [(int) $match[1], (int) ($match[2] ?? $match[1])];
            if ($left < $low || $left > $right || $right > $high) throw new InvalidArgumentException('Invalid Amnezia range');
            if (str_starts_with($name, 'H')) {
                foreach ($headers as [$a, $b]) if ($left <= $b && $a <= $right) throw new InvalidArgumentException('Overlapping Amnezia headers');
                $headers[] = [$left, $right];
            }
        }
        if (str_starts_with($version,'3.')) self::key($params['HeaderProtectionKey']);
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
        $family = null;
        for ($slot=0;$slot<=32;$slot++) {
            if ($settings['address']===['10.77.77.'.($slot+2).'/32']) $family=4;
            if ($settings['address']===['fd42:7662:77::'.dechex($slot+2).'/128']) $family=6;
        }
        if ($family===null) throw new InvalidArgumentException('Invalid WireGuard tunnel address');
        $dns = $family === 4 ? ['1.1.1.1', '9.9.9.9'] : ['2606:4700:4700::1111', '2620:fe::fe'];
        if ($settings['noKernelTun'] !== true || $settings['remoteDNS'] !== $dns
            || !is_array($settings['peers']) || !array_is_list($settings['peers']) || count($settings['peers']) !== 1
            || !is_array($settings['peers'][0])) throw new InvalidArgumentException('Invalid WireGuard peer list');
        $peer = $settings['peers'][0];
        $fields = ['publicKey', 'preSharedKey', 'endpoint', 'allowedIPs', 'keepAlive'];
        self::fields($peer, $fields, $fields);
        $endpoint = (str_contains($address, ':') ? "[$address]" : $address) . ':51820';
        if ($peer['endpoint'] !== $endpoint || $peer['allowedIPs'] !== ['0.0.0.0/0', '::/0']) {
            throw new InvalidArgumentException('Invalid WireGuard endpoint');
        }
        self::integer($peer['keepAlive'], 0, 65535);
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
