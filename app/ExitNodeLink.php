<?php

require_once __DIR__ . '/Lang.php';

/**
 * Ссылка узла выхода → выход Xray.
 *
 * Узел — другой сервер с vpnbot; его «Профиль для узла» выдаёт обычную ссылку
 * пользователя (Bot::linkXray). Принимаются ровно её форматы: VLESS с REALITY,
 * TLS + TCP, WebSocket, XHTTP или gRPC (с VLESS Encryption или без) и Trojan с TLS +
 * gRPC. Соединение без проверки сервера (security=none, allowInsecure) не
 * принимается: узел получает весь трафик выбранных доменов пользователей.
 *
 * JSON выхода собирается здесь по белому списку полей; из ссылки в него не
 * копируется ничего «как есть», кроме проверенных значений.
 */
final class ExitNodeLink
{
    public const MAX_LENGTH = 6000;
    private const FINGERPRINTS = ['chrome', 'firefox', 'safari', 'ios', 'android', 'edge', '360', 'qq', 'random', 'randomized'];
    private const XHTTP_MODES = ['auto', 'packet-up', 'stream-up', 'stream-one'];

    /**
     * @return array{protocol:string,address:string,port:int,remark:string,outbound:array}
     * @throws InvalidArgumentException с понятной причиной
     */
    public static function parse(string $link): array
    {
        $link = trim($link);
        if ($link === '' || strlen($link) > self::MAX_LENGTH || preg_match('~[\x00-\x20\x7f]~', $link)) {
            throw new InvalidArgumentException(Lang::t('ссылка пустая, слишком длинная или с пробелами', 'the link is empty, too long or contains spaces'));
        }
        if (!preg_match('~^(vless|trojan)://([^@/?#]+)@(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+):([0-9]{1,5})/?\?([^#]*)(?:#(.*))?$~D', $link, $m)) {
            throw new InvalidArgumentException(Lang::t('нужна ссылка vless:// или trojan:// из «Профиля для узла»', 'a vless:// or trojan:// link from Node profile is needed'));
        }
        [, $scheme, $credential, $host, $port, $query] = $m;
        $remark = isset($m[6]) ? rawurldecode($m[6]) : '';
        $credential = rawurldecode($credential);
        $host = trim($host, '[]');
        $port = (int) $port;
        if ($port < 1 || $port > 65535) throw new InvalidArgumentException(Lang::t('неверный порт', 'invalid port'));
        if (!filter_var($host, FILTER_VALIDATE_IP) && !self::hostname($host)) throw new InvalidArgumentException(Lang::t('неверный адрес узла', 'invalid node address'));
        $q = self::query($query);
        $security = $q['security'] ?? '';
        $type = $q['type'] ?? 'tcp';
        if ($type === 'raw') $type = 'tcp';
        if ($type === 'tcp' && ($q['headerType'] ?? 'none') !== 'none') {
            throw new InvalidArgumentException(Lang::t('неподдерживаемый заголовок TCP', 'unsupported TCP header'));
        }
        foreach (['allowInsecure', 'insecure', 'allow_insecure'] as $unsafe) {
            if (isset($q[$unsafe]) && $q[$unsafe] !== '0' && $q[$unsafe] !== 'false') throw new InvalidArgumentException(Lang::t('ссылка без проверки сертификата не принимается', 'a link without certificate verification is not accepted'));
        }
        if (!in_array($security, ['reality', 'tls'], true)) throw new InvalidArgumentException(Lang::t('нужна защита REALITY или TLS', 'REALITY or TLS protection is required'));
        $fp = $q['fp'] ?? 'chrome';
        if (!in_array($fp, self::FINGERPRINTS, true)) throw new InvalidArgumentException(Lang::t('неизвестный отпечаток fp', 'unknown fp fingerprint'));
        $sni = $q['sni'] ?? '';
        if (!self::hostname($sni)) throw new InvalidArgumentException(Lang::t('неверный sni', 'invalid sni'));

        $stream = ['network' => $type, 'security' => $security];
        if ($security === 'reality') {
            if ($type !== 'tcp') throw new InvalidArgumentException(Lang::t('REALITY поддерживается только с type=tcp', 'REALITY is supported only with type=tcp'));
            $pbk = $q['pbk'] ?? '';
            $sid = $q['sid'] ?? '';
            if (!preg_match('~^[A-Za-z0-9_-]{43}$~D', $pbk)) throw new InvalidArgumentException(Lang::t('неверный ключ REALITY pbk', 'invalid REALITY key pbk'));
            if (!preg_match('~^[0-9a-f]{0,16}$~D', $sid) || strlen($sid) % 2) throw new InvalidArgumentException(Lang::t('неверный shortId sid', 'invalid shortId sid'));
            $reality = ['serverName' => $sni, 'fingerprint' => $fp, 'publicKey' => $pbk, 'shortId' => $sid];
            if (isset($q['spx'])) {
                if (!preg_match('~^/[\x21-\x7e]{0,200}$~D', $q['spx'])) throw new InvalidArgumentException(Lang::t('неверный spiderX spx', 'invalid spiderX spx'));
                $reality['spiderX'] = $q['spx'];
            }
            if (isset($q['pqv'])) {
                if (!preg_match('~^[A-Za-z0-9_-]{100,3000}$~D', $q['pqv'])) throw new InvalidArgumentException(Lang::t('неверный ключ ML-DSA pqv', 'invalid ML-DSA key pqv'));
                $reality['mldsa65Verify'] = $q['pqv'];
            }
            $stream['realitySettings'] = $reality;
        } else {
            $tls = ['serverName' => $sni, 'fingerprint' => $fp];
            if (isset($q['alpn']) && $q['alpn'] !== '') {
                $alpn = explode(',', $q['alpn']);
                if (count($alpn) > 3 || array_diff($alpn, ['h2', 'http/1.1', 'h3'])) throw new InvalidArgumentException(Lang::t('неверный alpn', 'invalid alpn'));
                $tls['alpn'] = $alpn;
            }
            $stream['tlsSettings'] = $tls;
            switch ($type) {
                case 'tcp':
                    break;
                case 'ws':
                    $stream['wsSettings'] = ['path' => self::path($q['path'] ?? '/')] + self::hostField($q);
                    break;
                case 'xhttp':
                    $xhttp = ['path' => self::path($q['path'] ?? '/'), 'mode' => $q['mode'] ?? 'auto'] + self::hostField($q);
                    if (!in_array($xhttp['mode'], self::XHTTP_MODES, true)) throw new InvalidArgumentException(Lang::t('неверный режим XHTTP', 'invalid XHTTP mode'));
                    if (isset($q['extra']) && $q['extra'] !== '') {
                        $extra = json_decode($q['extra'], true);
                        if (!is_array($extra) || array_is_list($extra) || strlen($q['extra']) > 4000) throw new InvalidArgumentException(Lang::t('неверный extra XHTTP', 'invalid XHTTP extra'));
                        // downloadSettings — отдельное соединение со своими streamSettings
                        // (в том числе security none или allowInsecure): обход запрета на
                        // связь без проверки сервера. Go сравнивает имена полей без
                        // учёта регистра Unicode: например, ſ тоже совпадает с s.
                        foreach (array_keys($extra) as $key) {
                            if (preg_match('~^(?:downloadsettings|extra)$~iuD', (string) $key)) {
                                throw new InvalidArgumentException(Lang::t('extra XHTTP с отдельным соединением не принимается', 'XHTTP extra with a separate connection is not accepted'));
                            }
                        }
                        $xhttp['extra'] = $extra;
                    }
                    $stream['xhttpSettings'] = $xhttp;
                    break;
                case 'grpc':
                    $service = $q['serviceName'] ?? '';
                    if (!preg_match('~^[A-Za-z0-9._/-]{1,200}$~D', $service)) throw new InvalidArgumentException(Lang::t('неверный serviceName', 'invalid serviceName'));
                    $stream['grpcSettings'] = ['serviceName' => $service, 'multiMode' => ($q['mode'] ?? 'gun') === 'multi'];
                    break;
                default:
                    throw new InvalidArgumentException(Lang::t('транспорт ', 'transport ') . $type . Lang::t(' не поддерживается', ' is not supported'));
            }
        }

        if ($scheme === 'vless') {
            if (!preg_match('~^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$~D', strtolower($credential))) {
                throw new InvalidArgumentException(Lang::t('неверный UUID пользователя', 'invalid user UUID'));
            }
            $encryption = $q['encryption'] ?? 'none';
            if ($encryption !== 'none' && !preg_match('~^mlkem768x25519plus\.(native|xorpub|random)\.(0rtt|1rtt)\.[A-Za-z0-9_-]{40,3000}(?:\.[A-Za-z0-9_-]{40,3000})*$~D', $encryption)) {
                throw new InvalidArgumentException(Lang::t('неверный VLESS Encryption', 'invalid VLESS Encryption'));
            }
            $flow = $q['flow'] ?? '';
            if (!in_array($flow, ['', 'xtls-rprx-vision'], true)) throw new InvalidArgumentException(Lang::t('неизвестный flow', 'unknown flow'));
            if ($flow !== '' && $type !== 'tcp' && $encryption === 'none') throw new InvalidArgumentException(Lang::t('для Vision требуется TCP или VLESS Encryption', 'Vision requires TCP or VLESS Encryption'));
            $user = ['id' => strtolower($credential), 'encryption' => $encryption];
            if ($flow !== '') $user['flow'] = $flow;
            $outbound = ['protocol' => 'vless', 'settings' => ['vnext' => [['address' => $host, 'port' => $port, 'users' => [$user]]]]];
        } else {
            if ($security !== 'tls' || $type !== 'grpc') throw new InvalidArgumentException(Lang::t('Trojan поддерживается только с TLS и gRPC', 'Trojan is supported only with TLS and gRPC'));
            if (!preg_match('~^[\x21-\x7e]{8,128}$~D', $credential)) throw new InvalidArgumentException(Lang::t('неверный пароль Trojan', 'invalid Trojan password'));
            $outbound = ['protocol' => 'trojan', 'settings' => ['servers' => [['address' => $host, 'port' => $port, 'password' => $credential]]]];
        }
        $outbound['streamSettings'] = $stream;
        return ['protocol' => $scheme, 'address' => $host, 'port' => $port,
            'remark' => mb_substr(preg_replace('~[\x00-\x1f\x7f]~u', '', $remark) ?? '', 0, 64), 'outbound' => $outbound];
    }

    // Разбор query без parse_str: тот превращает «a.b» в «a_b» и молча
    // принимает массивы вида x[]=…; повтор параметра — отказ, а не «последний».
    private static function query(string $query): array
    {
        $result = [];
        foreach ($query === '' ? [] : explode('&', $query) as $pair) {
            if ($pair === '') continue;
            [$key, $value] = array_pad(explode('=', $pair, 2), 2, '');
            $key = rawurldecode($key);
            if (!preg_match('~^[A-Za-z][A-Za-z0-9_]{0,31}$~D', $key)) throw new InvalidArgumentException(Lang::t('неверный параметр ссылки', 'invalid link parameter'));
            if (array_key_exists($key, $result)) throw new InvalidArgumentException(Lang::t('параметр ', 'parameter ') . $key . Lang::t(' повторяется', ' is repeated'));
            $value = rawurldecode(str_replace('+', '%20', $value));
            if (!mb_check_encoding($value, 'UTF-8') || preg_match('~[\x00-\x1f\x7f]~', $value)) throw new InvalidArgumentException(Lang::t('неверное значение ', 'invalid value ') . $key);
            $result[$key] = $value;
        }
        return $result;
    }

    private static function hostname(string $host): bool
    {
        return strlen($host) <= 253 && (bool) preg_match('~^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9-]{0,62}$~D', $host);
    }

    private static function path(string $path): string
    {
        if (!preg_match('#^/[A-Za-z0-9._~/-]{0,200}$#D', $path)) throw new InvalidArgumentException(Lang::t('неверный path', 'invalid path'));
        return $path;
    }

    private static function hostField(array $q): array
    {
        if (!isset($q['host']) || $q['host'] === '') return [];
        if (!self::hostname($q['host'])) throw new InvalidArgumentException(Lang::t('неверный host', 'invalid host'));
        return ['host' => $q['host']];
    }
}
