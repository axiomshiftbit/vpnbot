<?php

// Trojan-gRPC (транспорт grpc у Xray, «gun»-режим).
//
// Инварианты, которые ломаются молча — конфиг собирается, ссылка выглядит
// правильной, а туннель не поднимается:
//
//  1. serviceName обязан совпадать у сервера, у всех трёх клиентских диалектов
//     и у ссылки: gRPC-запрос идёт на путь /<serviceName>/Tun, и сервер сверяет
//     его точно. Плюс он же должен попадать в локацию nginx (/grpc$hash).
//  2. Локация /grpc обязана быть на grpc_pass. proxy_pass ломает h2-фрейминг
//     gRPC, а xray за nginx слушает h2c без TLS.
//  3. mode=gun (multiMode=false) на обеих сторонах: сервер не задаёт multiMode,
//     значит и ссылка обязана говорить gun, иначе клиент уйдёт на /…/TunMulti.
//  4. alpn=h2: gRPC не существует поверх http/1.1, а TLS терминирует nginx.
//  5. Учётка trojan'а — password, а не uuid; ссылка и json-конфиги должны брать
//     одно и то же поле, иначе пользователь получит рабочую подписку и нерабочую
//     ссылку (или наоборот).

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function tgAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

$src   = file_get_contents(__DIR__ . '/../app/bot.php');
$nginx = file_get_contents(__DIR__ . '/../config/nginx_default.conf');
$bot   = (new ReflectionClass(Bot::class))->newInstanceWithoutConstructor();

// --- 1: serviceName один и тот же везде --------------------------------------
// Сервер строит его от $h (getHashBot), клиенты — от $hash той же подписки.
preg_match_all('~[\'"]?(?:serviceName|service_name|grpc-service-name)[\'"]?\s*=>\s*"grpc\$(h|hash)"~', $src, $svc);
tgAssert(count($svc[0]) >= 4,
    'serviceName должен быть задан на сервере и во всех трёх клиентских диалектах, найдено: ' . count($svc[0]));
preg_match('~"\?type=grpc"\s*\.\s*"&serviceName=grpc\$hash"~', $src, $lnk);
tgAssert(!empty($lnk[0]), 'ссылка trojan:// должна нести type=grpc и тот же serviceName=grpc$hash');

// Локация nginx получает тот же $h (updateNginx подставляет хеш в /grpc).
tgAssert(strpos($src, "'~(/webapp|/pac|/adguard|/ws|/grpc|/v2ray|location /dns-query)~'") !== false,
    'хеш должен подставляться в локацию /grpc — иначе serviceName grpc$h мимо неё');

// --- 2: /grpc именно на grpc_pass -------------------------------------------
// Обе копии: активная и закомментированная (её раскомментирует updateNginx для
// домена с letsencrypt — разъехавшись, они дадут рабочий grpc на IP и битый на
// домене).
preg_match_all('~location /grpc \{(.+?)\n\s*(?:#\s*)?\}~s', $nginx, $loc);
tgAssert(count($loc[1]) === 2, 'в nginx должны быть обе локации /grpc — активная и доменная, найдено: ' . count($loc[1]));
foreach ($loc[1] as $body) {
    tgAssert(strpos($body, 'grpc_pass grpc://xr:443;') !== false, '/grpc обязан быть на grpc_pass к xray');
    tgAssert(strpos($body, 'proxy_pass') === false, '/grpc не должен использовать proxy_pass — сломается h2-фрейминг');
    // Тело gRPC-стрима не ограничено: это туннель, а не запрос.
    tgAssert(strpos($body, 'client_max_body_size 0;') !== false, '/grpc: тело стрима нельзя ограничивать');
}

// --- 3: gun-режим на обеих сторонах ------------------------------------------
tgAssert(strpos($src, '"&mode=gun"') !== false, 'ссылка должна закреплять mode=gun');
preg_match('~case \'trojan-grpc\':\s+\$x\[\'inbounds\'\].+?break;~s', $src, $srv);
tgAssert(!empty($srv[0]), 'серверная ветка trojan-grpc не найдена');
tgAssert(strpos($srv[0], 'multiMode') === false,
    'сервер не включает multiMode, поэтому и ссылка обязана оставаться gun');
// TLS терминирует nginx: у inbound'а не должно быть ни security, ни tlsSettings.
tgAssert(strpos($srv[0], 'tlsSettings') === false && strpos($srv[0], '"security"') === false,
    'inbound trojan-grpc слушает голый h2c — TLS терминирует nginx');
// Реальный IP клиента вместо адреса nginx (см. nginxFrontedSockopt).
tgAssert(strpos($srv[0], 'nginxFrontedSockopt()') !== false,
    'inbound trojan-grpc должен получать sockopt.trustedXForwardedFor');

// --- 4: alpn = h2 ------------------------------------------------------------
tgAssert(strpos($src, '"&alpn=h2"') !== false, 'ссылка trojan-grpc должна нести alpn=h2');
foreach ([
    "~case 'trojan-grpc':\s+\\\$c\['outbounds'\]\[\\\$index\] = \[.+?\];~s" => 'xray',
    "~case 'trojan-grpc':\s+\\\$c\['outbounds'\]\[\\\$index\]\['type'\].+?break;~s" => 'sing-box',
    "~case \\\$pac\['transport'\] == 'trojan-grpc':.+?break;~s" => 'mihomo',
] as $re => $client) {
    preg_match($re, $src, $blk);
    tgAssert(!empty($blk[0]), "блок $client trojan-grpc не найден");
    if (!empty($blk[0])) {
        // xray/sing-box пишут ключом массива ('alpn' => [...]), mihomo —
        // присваиванием ($c['proxies'][$i]['alpn'] = [...]).
        tgAssert((bool) preg_match("~'alpn'\]?\s*(?:=>|=)\s*\[\s*'h2'\s*\]~", $blk[0]),
            "$client: alpn обязан быть ровно ['h2'] — gRPC поверх http/1.1 не существует");
        tgAssert(strpos($blk[0], "'~uid~'") !== false || strpos($blk[0], "'password' => '~uid~'") !== false,
            "$client: учётка trojan'а подставляется через ~uid~");
    }
}

// --- 5: ~uid~ для trojan разворачивается в password, не в uuid ---------------
tgAssert((bool) preg_match(
    "#'~uid~'\s*=>\s*\(\\\$pac\['transport'\] == 'trojan-grpc' \? \(\\\$client\['password'\] \?\? \\\$uid\) : \\\$uid\)#",
    $src,
), 'подстановка ~uid~ в json-конфигах должна давать password клиента');
// Та же учётка в ссылке, с тем же запасным значением: клиент, заведённый мимо
// changeTransport/addxrus, password не имеет.
tgAssert(strpos($src, "['password']\n                            ?? \$c['inbounds'][0]['settings']['clients'][\$i]['id']") !== false,
    'ссылка trojan:// должна брать password с тем же фолбэком на id, что и json');

// --- mihomo: SNI trojan'а читается из `sni`, а не `servername` ---------------
preg_match("~case \\\$pac\['transport'\] == 'trojan-grpc':.+?break;~s", $src, $cl);
tgAssert(!empty($cl[0]) && strpos($cl[0], "unset(\$c['proxies'][\$index]['servername'])") !== false,
    'mihomo: servername у trojan игнорируется, его надо снять');
tgAssert(!empty($cl[0]) && strpos($cl[0], "['sni']") !== false, 'mihomo: SNI trojan\'а задаётся полем sni');

echo $failed ? "trojan_grpc_test FAILED ($failed)\n" : "trojan_grpc_test OK\n";
exit($failed ? 1 : 0);
