<?php

// Отбор образов для cleanDocker().
//
// Проверка была прибита к литералу «^mercurykd/vpnbot» и после перехода на
// ghcr.io/axiomshiftbit/vpnbot-* (aca3ea2) не совпадала ни с чем. Массив совпадений
// оставался неинициализированным, array_diff(null, …) выбрасывал TypeError, и
// service.php умирал на 26-й строке: dnsttStart, restartHysteria, restartTt,
// setUpstreamDomain/Naive/Ocserv, syncOcservCamouflage и xrayUpdateRules не
// выполнялись ни при одном старте контейнера — молча, фатал уходил только в
// php_error. Тест фиксирует, что отбор переживает смену реестра и владельца
// и при этом не цепляет чужие образы.

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function t(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        echo "FAIL: $msg\n";
        $failed++;
    }
}

// Наши образы — во всех вариантах именования, что были в истории проекта.
$ours = [
    'ghcr.io/axiomshiftbit/vpnbot-php:latest',   // текущий боевой (aca3ea2)
    'ghcr.io/axiomshiftbit/vpnbot-xr:dev',
    'ghcr.io/axiomshiftbit/vpnbot-wg:2.30',
    'mercurykd/vpnbot:latest',             // апстрим, до миграции
    'mercurykd/vpnbot-ng:latest',
    'vpnbot-php:latest',                   // локальная сборка без реестра
    'vpnbot',
    'registry.example.com:5000/team/vpnbot-ss:1.0',
];
foreach ($ours as $name) {
    t(Bot::isVpnbotImage($name), "должен опознаваться как наш: $name");
}

// Чужие образы трогать нельзя: cleanDocker удаляет всё, что опознал и что не
// занято контейнером. Особенно важен «myvpnbot» — без якоря (^|/) он бы попал.
$others = [
    'someone/myvpnbot:latest',
    'myvpnbot',
    'notvpnbot-php',
    'alpine:3.23',
    'nginx/unit:1.29.0-php8.1',
    'ghcr.io/axiomshiftbit/other:latest',
    'ghcr.io/vpnbotcompany-tools/thing',   // vpnbot… но не наш: не после «/» целиком
];
foreach ($others as $name) {
    t(!Bot::isVpnbotImage($name), "НЕ должен опознаваться как наш: $name");
}

// Мусорный вход не должен ронять отбор: Docker API умеет отдавать записи без
// RepoTags и контейнеры без Image, а раньше сюда прилетал и голый null.
foreach ([null, '', false, 0, [], new stdClass()] as $bad) {
    t(!Bot::isVpnbotImage($bad), 'мусорный вход отвергается: ' . var_export($bad, true));
}

echo $failed ? "\n$failed FAILED\n" : "OK\n";
exit($failed ? 1 : 0);
