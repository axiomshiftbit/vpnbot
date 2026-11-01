<?php

/** UI metadata only. The node's typed schema and real core validate an apply. */
final class ManagedNodeFields
{
    public const GROUPS = ['basic' => ['ru' => 'Подключение и сайт', 'en' => 'Connection and site'], 'crypto' => ['ru' => 'Шифрование', 'en' => 'Encryption'],
        'reality' => ['REALITY', 'REALITY'], 'smux' => ['SMUX', 'SMUX'], 'xhttp' => ['XHTTP', 'XHTTP'],
        'dpi' => ['ru' => 'DPI клиента', 'en' => 'Client DPI'], 'finalmask' => ['ru' => 'Маски сервера', 'en' => 'Server masks'], 'sniffing' => ['ru' => 'Sniffing и торренты', 'en' => 'Sniffing and torrents'],
        'reserve' => ['ru' => 'Резервный канал', 'en' => 'Backup channel']];

    public static function all(): array
    {
        $fields = [
            'transport' => ['basic', 'ru' => 'Транспорт', 'en' => 'Transport', 'choice', ['reality', 'ws', 'grpc', 'xhttp']],
            'core' => ['basic', 'ru' => 'Ядро', 'en' => 'Core', 'choice', ['origin', 'origin2', 'origin3', 'fork']],
            'family' => ['basic', 'ru' => 'Выход в интернет', 'en' => 'Internet egress', 'choice', [4, 6]],
            'connect_family' => ['basic', 'ru' => 'Связь бот → нода', 'en' => 'Bot → node link', 'choice', [4, 6]],
            'domain' => ['basic', 'ru' => 'Свой домен', 'en' => 'Own domain', 'string'],
            'cover' => ['basic', 'ru' => 'Заглушка с паролем', 'en' => 'Password cover', 'bool'],
            'mask' => ['basic', 'ru' => 'Домен REALITY', 'en' => 'REALITY domain', 'string'],
            'wireguard.enabled' => ['reserve', 'ru' => 'Разрешить WireGuard', 'en' => 'Enable WireGuard', 'bool'],
            'wireguard.active' => ['reserve', 'ru' => 'Связь бота через WireGuard', 'en' => 'Bot link over WireGuard', 'bool'],
            'wireguard.mtu' => ['reserve', 'WireGuard MTU', 'WireGuard MTU', 'int'],
            'amnezia.enabled' => ['reserve', 'ru' => 'Разрешить AmneziaWG', 'en' => 'Enable AmneziaWG', 'bool'],
            'amnezia.active' => ['reserve', 'ru' => 'Связь бота через AmneziaWG', 'en' => 'Bot link over AmneziaWG', 'bool'],
            'amnezia.mtu' => ['reserve', 'AmneziaWG MTU', 'AmneziaWG MTU', 'int'],
            'xray.fingerprint' => ['crypto', 'ru' => 'Отпечаток клиента', 'en' => 'Client fingerprint', 'choice', ['chrome', 'firefox', 'safari', 'ios', 'edge', 'qq', 'random', 'randomized', 'android', '360']],
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
            'xray.block_torrent' => ['sniffing', 'ru' => 'Блокировать BitTorrent', 'en' => 'Block BitTorrent', 'bool'],
        ];
        foreach (['dpi', 'finalmask'] as $group) {
            foreach (['enabled' => ['ru' => 'Фрагментация', 'en' => 'Fragmentation', 'bool'], 'packets' => ['ru' => 'Пакеты', 'en' => 'Packets', 'string'],
                'length' => ['ru' => 'Размер фрагмента', 'en' => 'Fragment size', 'string'], 'delay' => ['ru' => 'Задержка, мс', 'en' => 'Delay, ms', 'string'],
                'maxSplit' => ['ru' => 'Предел разбиения', 'en' => 'Split limit', 'string']] as $name => $field) $fields["xray.$group.fragment.$name"] = [$group, ...$field];
            foreach (['enabled' => ['UDP noise', 'UDP noise', 'bool'], 'reset' => ['ru' => 'Период шума', 'en' => 'Noise reset', 'string'],
                'list' => ['ru' => 'Пакеты шума (JSON)', 'en' => 'Noise packets (JSON)', 'json']] as $name => $field) $fields["xray.$group.noise.$name"] = [$group, ...$field];
        }
        return array_map('array_values', $fields);
    }

    public static function get(array $options, string $path)
    {
        $value = $options;
        foreach (explode('.', $path) as $name) $value = is_array($value) ? ($value[$name] ?? null) : null;
        return $value;
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
        $target =& $options;
        foreach (explode('.', $path) as $name) { if (!isset($target[$name])) $target[$name] = []; $target =& $target[$name]; }
        $target = $value;
        unset($target);
        if ($value === true && $path === 'wireguard.active') $options['amnezia']['active'] = false;
        if ($value === true && $path === 'amnezia.active') $options['wireguard']['active'] = false;
        return $options;
    }
}
