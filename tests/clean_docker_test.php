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

// ── Брокер Docker API ───────────────────────────────────────────────────────
// docker.sock больше не монтируется в php и service: ":ro" не ограничивал ни
// одной операции API (этот же dockerApi() делал через него DELETE и POST),
// значит проходил бы и POST /containers/create с Binds:["/:/host"] — root на
// хосте из любого дефекта в php-контейнере. Сокет держит отдельный сервис
// dockerproxy, а сюда открыт allowlist ровно под cleanDocker().
$compose = (string) file_get_contents(__DIR__ . '/../docker-compose.yml');
$conf    = (string) file_get_contents(__DIR__ . '/../config/dockerproxy.conf');
$src     = (string) file_get_contents(__DIR__ . '/../app/bot.php');

t(substr_count($compose, '/var/run/docker.sock:/var/run/docker.sock') === 1,
    'сокет смонтирован ровно в один контейнер (брокер), не в php и не в service');
t((bool) preg_match('~^    dockerproxy:$~m', $compose), 'сервис dockerproxy объявлен');
t(strpos($compose, 'ipv4_address: 10.10.0.8') !== false,
    'у брокера фиксированный адрес: на него завязан allow-список в его конфиге');
t(strpos($src, "public const DOCKER_PROXY = 'http://dockerproxy:2375'") !== false,
    'dockerApi() ходит в брокер по HTTP');

// Allowlist: ровно те пять эндпоинтов, что зовёт cleanDocker(), и ровно теми
// методами. Регрессия «добавили location без limit_except» открывает демон.
$allow = [
    'location = /images/json'                 => 'GET',
    'location = /containers/json'             => 'GET',
    'location = /images/prune'                => 'POST',
    'location = /build/prune'                 => 'POST',
    'location ~ "^/images/[A-Za-z0-9:_.@-]+$"' => 'DELETE',
];
foreach ($allow as $loc => $method) {
    $re = '~' . preg_quote($loc, '~') . '\s*\{\s*limit_except ' . $method . ' \{ deny all; \}~';
    t((bool) preg_match($re, $conf), "брокер: $loc разрешён только методом $method");
}
t(substr_count($conf, 'location ') === count($allow) + 1,
    'в конфиге брокера нет локаций сверх allowlist (плюс catch-all)');
t((bool) preg_match('~location / \{\s*deny all;~', $conf),
    'всё остальное Docker API закрыто catch-all');
t(strpos($conf, 'allow 10.10.0.7;') !== false && strpos($conf, 'allow 10.10.0.15;') !== false,
    'до брокера допущены только php и service');
// Конфиг nginx локально не проверить (бинаря нет), но незакрытая скобка —
// самая вероятная опечатка, а ценой ей будет неподнявшийся контейнер.
t(substr_count($conf, '{') === substr_count($conf, '}'), 'скобки в конфиге брокера сбалансированы');

// cleanDocker() не должен звать ничего сверх allowlist: новый вызов мимо
// списка молча вернул бы 403 и «очистка» перестала бы чистить.
preg_match_all('~dockerApi\(\s*"([^"$]*)~', $src, $m1);
preg_match_all("~dockerApi\(\s*'([^']*)~", $src, $m2);
$called = array_unique(array_merge($m1[1], $m2[1]));
foreach ($called as $path) {
    $ok = in_array($path, ['/images/json', '/containers/json?all=1', '/images/prune', '/build/prune'], true)
        || str_starts_with($path, '/images/');
    t($ok, "вызов dockerApi('$path') должен быть в allowlist брокера");
}

echo $failed ? "\n$failed FAILED\n" : "OK\n";
exit($failed ? 1 : 0);
