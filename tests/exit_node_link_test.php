<?php

// Ссылки узла выхода: форматы Bot::linkXray принимаются, всё небезопасное — нет.
require __DIR__ . '/../app/ExitNodeLink.php';

$checks = 0;
function exitLinkCheck(bool $ok, string $name): void
{
    global $checks;
    $checks++;
    if (!$ok) throw new RuntimeException('FAIL: ' . $name);
}
function exitLinkReject(string $link, string $name): void
{
    try {
        ExitNodeLink::parse($link);
    } catch (InvalidArgumentException $e) {
        exitLinkCheck($e->getMessage() !== '', $name);
        return;
    }
    throw new RuntimeException('FAIL: принята ' . $name);
}

$uuid = '0b6e8f8a-3c1d-4f6e-9a2b-1c2d3e4f5a6b';
$pbk = str_repeat('A', 42) . 'Q';
$enc = 'mlkem768x25519plus.native.0rtt.' . str_repeat('Ab_-', 20);

// REALITY, как в linkXray: Vision, spiderX, шифрование.
$r = ExitNodeLink::parse("vless://$uuid@203.0.113.7:443?security=reality&sni=www.example.com&fp=firefox&pbk=$pbk&sid=a1b2&type=tcp&flow=xtls-rprx-vision&spx=%2Fx&encryption=none#%F0%9F%87%AB%F0%9F%87%AE%20node-example");
$s = $r['outbound']['streamSettings'];
exitLinkCheck($r['outbound']['protocol'] === 'vless' && $r['address'] === '203.0.113.7' && $r['port'] === 443, 'REALITY: адрес');
exitLinkCheck($r['outbound']['settings']['vnext'][0]['users'][0] === ['id' => $uuid, 'encryption' => 'none', 'flow' => 'xtls-rprx-vision'], 'REALITY: пользователь');
exitLinkCheck($s === ['network' => 'tcp', 'security' => 'reality', 'realitySettings' => ['serverName' => 'www.example.com', 'fingerprint' => 'firefox', 'publicKey' => $pbk, 'shortId' => 'a1b2', 'spiderX' => '/x']], 'REALITY: поток');
exitLinkCheck($r['remark'] === '🇫🇮 node-example', 'имя из #fragment');

// WebSocket + TLS + VLESS Encryption.
$r = ExitNodeLink::parse("vless://$uuid@fi.example.org:443?flow=&path=%2Fwsabc123&security=tls&sni=fi.example.org&fp=chrome&type=ws&encryption=" . rawurlencode($enc) . '#n');
exitLinkCheck($r['outbound']['streamSettings'] === ['network' => 'ws', 'security' => 'tls', 'tlsSettings' => ['serverName' => 'fi.example.org', 'fingerprint' => 'chrome'], 'wsSettings' => ['path' => '/wsabc123']], 'WS: поток');
exitLinkCheck($r['outbound']['settings']['vnext'][0]['users'][0] === ['id' => $uuid, 'encryption' => $enc], 'WS: шифрование');

// XHTTP с extra и alpn.
$extra = rawurlencode(json_encode(['xmux' => ['maxConcurrency' => '16-32'], 'noGRPCHeader' => false]));
$r = ExitNodeLink::parse("vless://$uuid@fi.example.org:443?security=tls&type=xhttp&headerType=&path=%2Fwsabc&host=fi.example.org&flow=&mode=packet-up&extra=$extra&sni=fi.example.org&fp=chrome&alpn=h2%2Chttp%2F1.1&encryption=none#x");
$x = $r['outbound']['streamSettings'];
exitLinkCheck($x['xhttpSettings'] === ['path' => '/wsabc', 'mode' => 'packet-up', 'host' => 'fi.example.org', 'extra' => ['xmux' => ['maxConcurrency' => '16-32'], 'noGRPCHeader' => false]], 'XHTTP: настройки');
exitLinkCheck($x['tlsSettings']['alpn'] === ['h2', 'http/1.1'], 'XHTTP: alpn');

// Trojan + gRPC.
$r = ExitNodeLink::parse('trojan://' . rawurlencode('p@ss:word-123') . '@[2001:db8::7]:8443?type=grpc&serviceName=grpcabc&mode=gun&security=tls&sni=fi.example.org&fp=chrome&alpn=h2#t');
exitLinkCheck($r['outbound']['protocol'] === 'trojan' && $r['address'] === '2001:db8::7' && $r['port'] === 8443, 'Trojan: адрес IPv6');
exitLinkCheck($r['outbound']['settings']['servers'][0]['password'] === 'p@ss:word-123', 'Trojan: пароль');
exitLinkCheck($r['outbound']['streamSettings']['grpcSettings'] === ['serviceName' => 'grpcabc', 'multiMode' => false], 'Trojan: gRPC');

// Пробелы и перевод строки по краям — обычный след копирования.
exitLinkCheck(ExitNodeLink::parse("  vless://$uuid@fi.example.org:443?security=tls&type=ws&path=%2F&sni=fi.example.org\n")['port'] === 443, 'края обрезаются');

// Отказы: небезопасные и чужие форматы.
$ok = "vless://$uuid@fi.example.org:443?security=reality&sni=a.example.com&fp=chrome&pbk=$pbk&sid=ab&type=tcp&flow=xtls-rprx-vision";
foreach ([
    'без защиты' => "vless://$uuid@fi.example.org:443?security=none&type=tcp",
    'без security' => "vless://$uuid@fi.example.org:443?type=ws&path=%2F",
    'allowInsecure' => "vless://$uuid@fi.example.org:443?security=tls&sni=fi.example.org&type=ws&path=%2F&allowInsecure=1",
    'vmess' => 'vmess://eyJhZGQiOiIxIn0=',
    'ss' => 'ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388',
    'неверный UUID' => "vless://not-a-uuid@fi.example.org:443?security=tls&sni=fi.example.org&type=ws&path=%2F",
    'порт 0' => str_replace(':443?', ':0?', $ok),
    'порт 70000' => str_replace(':443?', ':70000?', $ok),
    'пробел внутри' => str_replace('&type', ' &type', $ok),
    'перевод строки в значении' => $ok . '&spx=%2F%0Aa',
    'повтор параметра' => $ok . '&sni=b.example.com',
    'REALITY без pbk' => str_replace("&pbk=$pbk", '', $ok),
    'REALITY с ws' => str_replace('type=tcp', 'type=ws', $ok),
    'нечётный sid' => str_replace('sid=ab', 'sid=abc', $ok),
    'чужой flow' => str_replace('xtls-rprx-vision', 'xtls-rprx-direct', $ok),
    'неизвестный fp' => str_replace('fp=chrome', 'fp=evil', $ok),
    'sni с путём' => str_replace('sni=a.example.com', 'sni=a.example.com%2Fx', $ok),
    'адрес с символами' => str_replace('@fi.example.org', '@nl_example$', $ok),
    'XHTTP extra список' => "vless://$uuid@fi.example.org:443?security=tls&type=xhttp&path=%2Fa&sni=fi.example.org&extra=%5B1%5D",
    'XHTTP чужой режим' => "vless://$uuid@fi.example.org:443?security=tls&type=xhttp&path=%2Fa&sni=fi.example.org&mode=evil",
    'path без слэша' => "vless://$uuid@fi.example.org:443?security=tls&type=ws&path=a&sni=fi.example.org",
    'path с кавычкой' => "vless://$uuid@fi.example.org:443?security=tls&type=ws&path=%2Fa%22b&sni=fi.example.org",
    'неизвестный транспорт' => "vless://$uuid@fi.example.org:443?security=tls&type=kcp&sni=fi.example.org",
    'VLESS с gRPC' => "vless://$uuid@fi.example.org:443?security=tls&type=grpc&serviceName=a&sni=fi.example.org",
    'Trojan с ws' => 'trojan://password123@fi.example.org:443?type=ws&path=%2F&security=tls&sni=fi.example.org',
    'Trojan короткий пароль' => 'trojan://short@fi.example.org:443?type=grpc&serviceName=a&security=tls&sni=fi.example.org',
    'неверное шифрование' => "vless://$uuid@fi.example.org:443?security=tls&type=ws&path=%2F&sni=fi.example.org&encryption=aes",
    'Vision без REALITY' => "vless://$uuid@fi.example.org:443?security=tls&type=ws&path=%2F&sni=fi.example.org&flow=xtls-rprx-vision",
    'массив в параметре' => $ok . '&x%5B%5D=1',
    'слишком длинная' => $ok . '&spx=%2F' . str_repeat('a', 7000),
] as $name => $link) exitLinkReject($link, $name);

// Собранные выходы загружает настоящее ядро (как остальные тесты с VLESS_TEST_XRAY).
$xray = getenv('VLESS_TEST_XRAY');
if (is_string($xray) && $xray !== '' && is_executable($xray)) {
    foreach ([
        "vless://$uuid@203.0.113.7:443?security=reality&sni=www.example.com&fp=chrome&pbk=" . rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=') . "&sid=a1b2&type=tcp&flow=xtls-rprx-vision&encryption=none",
        "vless://$uuid@fi.example.org:443?path=%2Fwsabc&security=tls&sni=fi.example.org&fp=chrome&type=ws&encryption=none",
        "vless://$uuid@fi.example.org:443?security=tls&type=xhttp&path=%2Fwsabc&host=fi.example.org&mode=packet-up&extra=$extra&sni=fi.example.org&fp=chrome&alpn=h2%2Chttp%2F1.1&encryption=none",
        'trojan://password123@fi.example.org:443?type=grpc&serviceName=grpcabc&mode=gun&security=tls&sni=fi.example.org&fp=chrome&alpn=h2',
    ] as $n => $link) {
        $config = ['log' => ['loglevel' => 'warning'], 'inbounds' => [['listen' => '127.0.0.1', 'port' => 10899, 'protocol' => 'socks']],
            'outbounds' => [ExitNodeLink::parse($link)['outbound'] + ['tag' => 'exit']]];
        $file = sys_get_temp_dir() . '/exit-node-link-' . getmypid() . "-$n.json";
        file_put_contents($file, json_encode($config, JSON_UNESCAPED_SLASHES));
        exec(escapeshellarg($xray) . ' run -test -config ' . escapeshellarg($file) . ' 2>&1', $out, $code);
        unlink($file);
        exitLinkCheck($code === 0, 'ядро принимает выход ' . $n . ': ' . implode(' ', array_slice($out, -2)));
        $out = [];
    }
}

echo "exit_node_link_test: $checks OK\n";
