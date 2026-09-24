<?php

// СРЕДНИЕ отчёта AUDIT-2026-08-18-03-docker-ci.md.
//
// 1. Ни одного лимита памяти/процессов и restart-политика только у одного
//    сервиса из 19: разросшийся контейнер клал весь хост (на 1-2 ГБ VPS это
//    штатный сценарий), а упавший php означал молчание бота до ручного make r.
// 2. cap_add: NET_ADMIN у np, которому он не нужен — привилегия добавляется
//    ПОВЕРХ дефолтного набора.
// 3. Версии dnslookup/sing-box/mihomo были зашиты в dockerfile, поэтому
//    renovate (он читает аннотации в .env) их не видел и обновлять их было
//    некому.
// 4. apk без --no-cache и сборочные утилиты в рантайм-образе.
//
// Парсера YAML в тестовом окружении нет (php-yaml не установлен), поэтому
// проверки текстовые — зато они же ловят и опечатки в отступах.

$compose = (string) file_get_contents(__DIR__ . '/../docker-compose.yml');
$failed  = 0;

function chAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

// Сервисы верхнего уровня: строки вида «    name:» внутри services.
preg_match_all('~^    ([a-z0-9_-]+):$~m', substr($compose, strpos($compose, "\nservices:")), $m);
$services = $m[1];
chAssert(count($services) >= 19, 'сервисы разобраны: ' . count($services));

// ── 1. Лимиты и restart ─────────────────────────────────────────────────────
chAssert(substr_count($compose, 'mem_limit:') === count($services),
    'потолок памяти есть у каждого сервиса: ' . substr_count($compose, 'mem_limit:') . ' из ' . count($services));
chAssert(preg_match_all('~pids_limit: (?:128|512)~', $compose) === count($services),
    'потолок процессов есть у каждого сервиса (защита от зафоркавшегося демона)');
chAssert(substr_count($compose, 'init: true') === count($services),
    'init собирает осиротевшие процессы после рестартов демонов через SSH');
// Значения именно щедрые: слишком низкий потолок убивал бы xray под нагрузкой.
chAssert(!preg_match('~mem_limit: (\d+)m~', $compose, $mm) || (int) $mm[1] >= 256,
    'потолки не занижены');
foreach (['php', 'service', 'ng', 'up'] as $svc) {
    preg_match('~^    ' . preg_quote($svc, '~') . ':\n(.*?)(?=^    [a-z0-9_-]+:|\z)~ms', $compose, $match);
    $block = $match[1] ?? '';
    chAssert(str_contains($block, 'restart: unless-stopped'),
        "$svc поднимается сам после падения");
}
chAssert(!str_contains($compose, '# restart: unless-stopped'),
    'закомментированных restart-политик не осталось');

// ── 2. Привилегии ───────────────────────────────────────────────────────────
$np = substr($compose, strpos($compose, "\n    np:\n"), 2500);
chAssert(!preg_match('~^\s+cap_add:~m', $np), 'у np нет cap_add: NET_ADMIN ему не нужен');
// Обоснованные привилегии не тронуты — иначе туннели просто не поднимутся.
foreach (['wg', 'wg1', 'oc', 'ovpn', 'ipsec', 'wp', 'ad'] as $svc) {
    preg_match('~^    ' . preg_quote($svc, '~') . ':\n(.*?)(?=^    [a-z0-9_-]+:|\z)~ms', $compose, $match);
    $block = $match[1] ?? '';
    chAssert(str_contains($block, 'cap_add:'), "$svc сохранил NET_ADMIN (он ему нужен)");
}

// mknod сам по себе не даёт pppd права открыть устройство: проверено на
// Docker/cgroup v2, где без правила L2TP завершается с EPERM.
preg_match('~^    ipsec:\n(.*?)(?=^    [a-z0-9_-]+:|\z)~ms', $compose, $ipsec);
chAssert((bool) preg_match("~device_cgroup_rules:\\s*\\n\\s*- ['\"]c 108:0 rwm['\"]~", $ipsec[1] ?? ''),
    'ipsec разрешает открытие PPP (char 108:0), не всех устройств');

// ── 3. Пины версий php-образа ───────────────────────────────────────────────
$env = (string) file_get_contents(__DIR__ . '/../.env');
$df  = (string) file_get_contents(__DIR__ . '/../dockerfile/php.dockerfile');
foreach (['DNSLOOKUP_VERSION', 'SINGBOX_VERSION', 'MIHOMO_VERSION'] as $var) {
    chAssert((bool) preg_match("~^# renovate: .*\n$var=~m", $env),
        ".env: $var запиннен и снабжён аннотацией renovate");
    chAssert(str_contains($df, "ARG $var="), "php.dockerfile: $var объявлен как ARG");
    chAssert(str_contains($compose, "$var: \${{$var}"), "compose прокидывает $var в сборку");
}
// Литералов версий в dockerfile остаться не должно — иначе пин в .env фиктивен.
chAssert(!preg_match('~download/v1\.11\.1/~', $df), 'версия dnslookup не зашита в URL');
chAssert(!preg_match('~sing-box-1\.14\.0-linux~', $df), 'версия sing-box не зашита в URL');
chAssert(!preg_match('~mihomo-linux-amd64-v1\.19\.30~', $df), 'версия mihomo не зашита в URL');

// CI: новая переменная не должна пересобирать все 14 образов.
$ci = (string) file_get_contents(__DIR__ . '/../.github/workflows/images.yml');
chAssert(str_contains($ci, 'DNSLOOKUP_VERSION|SINGBOX_SHA256|MIHOMO_VERSION|MIHOMO_SHA256'),
    'images.yml знает пины утилит PHP');

// ── 4. Образы ───────────────────────────────────────────────────────────────
foreach (glob(__DIR__ . '/../dockerfile/*.dockerfile') as $file) {
    $name = basename($file);
    $body = (string) file_get_contents($file);
    foreach (explode("\n", $body) as $line) {
        if (preg_match('~apk add~', $line) && !str_contains($line, '--no-cache')) {
            chAssert(false, "$name: apk add без --no-cache — индекс остаётся в слое: " . trim($line));
        }
    }
}
$ss = (string) file_get_contents(__DIR__ . '/../dockerfile/shadowsocks.dockerfile');
chAssert(str_contains($ss, 'apk del git xz unzip'),
    'shadowsocks: сборочные утилиты удалены из рантайм-образа');
chAssert(strpos($ss, 'tar -xf shadowsocks-rust.tar.xz') < strpos($ss, 'apk del'),
    'удаление идёт ПОСЛЕ распаковки (tar.xz без xz не распакуется)');
chAssert(!preg_match('~apk del[^\n]*\bjq\b~', $ss),
    'jq остаётся: его зовёт start_ss.sh в рантайме');

// ── НИЗКИЕ того же отчёта ───────────────────────────────────────────────────
$ci = (string) file_get_contents(__DIR__ . '/../.github/workflows/images.yml');
// Без строк-комментариев: пояснение над permissions цитирует то, что мы убрали.
$head = implode("\n", array_filter(
    explode("\n", substr($ci, 0, strpos($ci, 'jobs:'))),
    static fn(string $l): bool => !preg_match('~^\s*#~', $l)
));
chAssert(!str_contains($head, 'packages: write'),
    'packages: write снят с уровня workflow — джобу plan он не нужен');
chAssert((bool) preg_match('~build:.*?permissions:\s*\n\s*contents: read\s*\n\s*packages: write~s', $ci),
    'права на запись пакетов объявлены в джобе build');
chAssert(str_contains($ci, 'неизвестный сервис'),
    'ручной ввод services сверяется со списком: значение уходит в имя публикуемого пакета');
chAssert(str_contains($ci, 'length) > 0'),
    'prune не трогает версии без тегов: иначе удалялись бы дочерние манифесты живого канального тега');

// stop_grace_period у сервисов с состоянием
foreach (['ad', 'ipsec', 'ovpn'] as $svc) {
    preg_match('~^    ' . preg_quote($svc, '~') . ':\n(.*?)(?=^    [a-z0-9_-]+:|\z)~ms', $compose, $match);
    $block = $match[1] ?? '';
    chAssert(str_contains($block, 'stop_grace_period: 10s'),
        "$svc получает 10s на завершение: через секунду после SIGTERM прилетает SIGKILL");
}
// stateless-сервисам секунда по-прежнему оправдана
chAssert(substr_count($compose, 'stop_grace_period: 1s') >= 15, 'остальным 1s не тронут');

// depends_on у service
preg_match('~^    service:\n(.*?)(?=^    [a-z0-9_-]+:|\z)~ms', $compose, $serviceMatch);
$svcBlock = $serviceMatch[1] ?? '';
foreach (['ipsec', 'telemt', 'wp'] as $dep) {
    chAssert((bool) preg_match("~depends_on:.*?\\n            $dep:\\n                condition: service_started~s", $svcBlock),
        "service ждёт $dep: стартовые задачи ходят в контейнеры по ssh");
}

// xray.json только на чтение
chAssert(str_contains($compose, './config/xray.json:/xray.json:ro'),
    'xr получает конфиг на чтение: пишет его только бот из php');
// ss и proxy переписывают свои конфиги сами — им :ro нельзя
chAssert(!preg_match('~\./config/ssserver\.json:/config\.json:ro~', $compose),
    'ssserver.json остаётся на запись: start_ss.sh правит в нём порт');

// ── 5. Пины не расходятся между .env, фолбэком compose и ARG-дефолтом ──────
// Одно значение живёт в трёх местах: .env (источник истины — его читают
// renovate, CI и bake), фолбэк ${VAR:-default} в compose и ARG-дефолт в
// dockerfile. Разъехавшись, они не ломаются немедленно: CI собирает с args из
// .env, поэтому подмена всплывает только там, где build-args не передаются
// вовсе. А такое место есть: сервисы proxy и ss собирают ОДИН образ
// vpnbot-ss, но proxy не передаёт ни одного из четырёх пинов — локальный
// `docker compose build` собрал бы его по ARG-дефолту и молча вернул старую
// версию shadowsocks.
//
// К 2026-09-01 так разъехались ADGUARD_VERSION (78 в compose против 79 в
// .env), TELEMT_VERSION (3.5.2 против 3.5.5) и TT_REF (фолбэк master при пине
// на коммит — ровно то плавающее поведение, от которого уходили).
$envRaw = (string) file_get_contents(__DIR__ . '/../.env');
$env    = [];
foreach (preg_split('~\r\n|\n~', $envRaw) as $line) {
    if (preg_match('~^([A-Za-z_][A-Za-z0-9_]*)=(.*)$~', $line, $em)) {
        $env[$em[1]] = $em[2];
    }
}
chAssert(count($env) > 30, 'переменные .env разобраны: ' . count($env));

// Исключение ровно одно и оно осознанное: у xray ARG намеренно ПУСТОЙ —
// «пусто» для fetch_xray означает releases/latest, а не «повтори пин»
// (dockerfile/xray.dockerfile, три допустимых значения аргумента).
$pinSkip = ['XRAY_VERSION' => true, 'XRAY_FORK_VERSION' => true];

preg_match_all('~\$\{([A-Za-z_][A-Za-z0-9_]*):-([^}]*)\}~', $compose, $cm, PREG_SET_ORDER);
$checked = 0;
foreach ($cm as [, $var, $dflt]) {
    if (($env[$var] ?? '') === '' || isset($pinSkip[$var])) {
        continue;
    }
    $checked++;
    chAssert($dflt === $env[$var],
        "фолбэк compose для $var: «{$dflt}» против «{$env[$var]}» в .env");
}
chAssert($checked > 20, "фолбэки compose проверены: $checked");

$checkedArg = 0;
foreach (glob(__DIR__ . '/../dockerfile/*.dockerfile') as $df) {
    preg_match_all('~^ARG ([A-Za-z_][A-Za-z0-9_]*)="?([^"\n]*)"?$~m', (string) file_get_contents($df), $am, PREG_SET_ORDER);
    foreach ($am as [, $var, $dflt]) {
        if (($env[$var] ?? '') === '' || isset($pinSkip[$var])) {
            continue;
        }
        $checkedArg++;
        chAssert($dflt === $env[$var],
            basename($df) . ": ARG-дефолт $var — «{$dflt}» против «{$env[$var]}» в .env");
    }
}
// Тот же счётчик, что и у compose выше, и по той же причине: обе половины
// молча пропускают всё, чего нет в .env, — переименование ключей или перевод
// ARG на форму без «=» обнулили бы проверку, не уронив ни одного assert.
// Пропущено осознанно: TUN2SOCKS_VERSION и RUST_VERSION в .env не заводятся
// (единственный источник — сам dockerfile, compose их не передаёт), APK_REFRESH
// это дата-инвалидатор кеша apk, а `ARG image` пишется строчными.
chAssert($checkedArg > 20, "ARG-дефолты dockerfile'ов проверены: $checkedArg");

if ($failed) {
    echo "audit_compose_hardening_test FAILED ($failed)\n";
    exit(1);
}
echo "audit_compose_hardening_test OK\n";
