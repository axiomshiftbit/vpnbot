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
chAssert(substr_count($compose, 'pids_limit: 512') === count($services),
    'потолок процессов есть у каждого сервиса (защита от зафоркавшегося демона)');
// Значения именно щедрые: слишком низкий потолок убивал бы xray под нагрузкой.
chAssert(!preg_match('~mem_limit: (\d+)m~', $compose, $mm) || (int) $mm[1] >= 256,
    'потолки не занижены');
foreach (['php', 'service', 'ng', 'up'] as $svc) {
    $block = substr($compose, strpos($compose, "\n    $svc:\n"), 3000);
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
    $block = substr($compose, strpos($compose, "\n    $svc:\n"), 3000);
    chAssert(str_contains($block, 'cap_add:'), "$svc сохранил NET_ADMIN (он ему нужен)");
}

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
chAssert(!preg_match('~sing-box-1\.12\.15-linux~', $df), 'версия sing-box не зашита в URL');
chAssert(!preg_match('~mihomo-linux-amd64-v1\.19\.12~', $df), 'версия mihomo не зашита в URL');

// CI: новая переменная не должна пересобирать все 14 образов.
$ci = (string) file_get_contents(__DIR__ . '/../.github/workflows/images.yml');
chAssert(str_contains($ci, 'DNSLOOKUP_VERSION|SINGBOX_VERSION|MIHOMO_VERSION'),
    'images.yml знает новые пины и собирает по ним только php');

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
    $block = substr($compose, strpos($compose, "\n    $svc:\n"), 3000);
    chAssert(str_contains($block, 'stop_grace_period: 10s'),
        "$svc получает 10s на завершение: через секунду после SIGTERM прилетает SIGKILL");
}
// stateless-сервисам секунда по-прежнему оправдана
chAssert(substr_count($compose, 'stop_grace_period: 1s') >= 15, 'остальным 1s не тронут');

// depends_on у service
$svcBlock = substr($compose, strpos($compose, "\n    service:\n"), 4000);
foreach (['ipsec', 'telemt', 'wp'] as $dep) {
    chAssert((bool) preg_match("~depends_on:.*?- $dep~s", $svcBlock),
        "service ждёт $dep: стартовые задачи ходят в контейнеры по ssh");
}

// xray.json только на чтение
chAssert(str_contains($compose, './config/xray.json:/xray.json:ro'),
    'xr получает конфиг на чтение: пишет его только бот из php');
// ss и proxy переписывают свои конфиги сами — им :ro нельзя
chAssert(!preg_match('~\./config/ssserver\.json:/config\.json:ro~', $compose),
    'ssserver.json остаётся на запись: start_ss.sh правит в нём порт');

if ($failed) {
    echo "audit_compose_hardening_test FAILED ($failed)\n";
    exit(1);
}
echo "audit_compose_hardening_test OK\n";
