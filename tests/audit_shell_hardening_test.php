<?php

// СРЕДНИЕ отчёта AUDIT-2026-08-18-04-shell-scripts.md.
// Скрипты запускаются в контейнерах от root и управляют сетью, поэтому
// сторожа текстовые: выполнить их в тестовом окружении нельзя, а регрессия
// возвращается одной правкой.

$failed = 0;

function shAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

$read = static fn(string $p): string => (string) file_get_contents(__DIR__ . '/../' . $p);

// Код без строк-комментариев: сами комментарии цитируют то, что мы убрали,
// и наивный поиск подстроки нашёл бы её именно там.
$code = static function (string $body): string {
    $out = [];
    foreach (explode("\n", $body) as $line) {
        if (!preg_match('~^\s*#~', $line)) {
            $out[] = $line;
        }
    }
    return implode("\n", $out);
};

// ── update.sh: честный отчёт и ключ бота вне argv ───────────────────────────
$up = $read('update/update.sh');
shAssert(str_contains($up, 'start_rc=$?'), 'update.sh проверяет код возврата make start');
shAssert(str_contains($up, 'make start FAILED'),
    'при неудаче в чат уходит причина, а не «bot started»');
shAssert(str_contains($up, 'curl -s -K -'),
    'URL с ключом бота уходит curl через stdin-конфиг, а не аргументом (виден в ps)');
shAssert(!preg_match('~-X POST "https://\$TELEGRAM_API/bot\$_key~', $up),
    'ключа бота в командной строке curl не осталось');

// ── Определение внешнего интерфейса ────────────────────────────────────────
foreach (['scripts/start_wg.sh', 'scripts/start_oc.sh', 'scripts/start_ovpn.sh', 'scripts/start_ipsec.sh'] as $p) {
    $body = $read($p);
    shAssert(str_contains($body, 'ip route show default'),
        basename($p) . ': есть фолбэк определения интерфейса (route может отсутствовать)');
    shAssert(str_contains($body, 'default interface not detected'),
        basename($p) . ': пустой интерфейс попадает в лог, а не гасится через || true');
}

// ── start_wg.sh: пустой ADDRESS ────────────────────────────────────────────
$wg = $read('scripts/start_wg.sh');
shAssert(str_contains($wg, 'FATAL: ADDRESS is empty'),
    'start_wg.sh падает при пустом ADDRESS вместо тихой утечки мимо tun0');
shAssert(strpos($wg, 'FATAL: ADDRESS is empty') < strpos($wg, 'iptables -t nat -A POSTROUTING -o'),
    'проверка стоит до правил NAT');

// ── start_php.sh: стабильный ssh-ключ ──────────────────────────────────────
$php = $read('scripts/start_php.sh');
shAssert(!preg_match('~^rm /ssh/key\*~m', $php), 'ключ больше не сносится безусловно');
shAssert(str_contains($php, 'if [ ! -s /ssh/key ]'),
    'ключ генерируется только при отсутствии: иначе рестарт php рассинхронизировал бы authorized_keys во всех контейнерах');

// ── reset_wg.sh: валидация и идемпотентность ───────────────────────────────
$rs = $read('scripts/reset_wg.sh');
shAssert(str_contains($rs, 'usage: reset_wg.sh'), 'reset_wg.sh валидирует аргументы');
shAssert(str_contains($rs, 'port must be a number'), 'порт проверяется как число');
shAssert(substr_count($rs, 'iptables -t nat -C POSTROUTING') === 3,
    'все три правила PostUp идемпотентны (-C перед -A/-I), иначе цепочка растёт с каждым down/up');

// ── start_xray.sh: не молчать ──────────────────────────────────────────────
$xr = $read('scripts/start_xray.sh');
shAssert(!str_contains($xr, 'xray run -config /xray.json > /dev/null 2>&1'),
    'stderr ядра больше не уходит в /dev/null');
shAssert(str_contains($xr, 'no client uuid in /xray.json'),
    'пропуск запуска ядра попадает в лог: раньше контейнер выглядел здоровым');

// ── block_torrent.sh ───────────────────────────────────────────────────────
$bt = $read('scripts/block_torrent.sh');
$btCode = $code($bt);
shAssert(!preg_match('~--string "torrent"~', $btCode),
    'слишком широкое правило --string "torrent" убрано (ломало обычный HTTP)');
shAssert(!preg_match('~--string "announce"~', $btCode),
    'слишком широкое правило --string "announce" убрано');
shAssert(str_contains($bt, 'BitTorrent protocol'), 'точные сигнатуры протокола остались');
shAssert(str_contains($bt, 'ipp2p rules not applied'),
    'провал ipp2p (нет модуля на хосте) виден в логе, а не только в меню «заблокировано»');
shAssert(str_contains($bt, 'iptables -C "$chain"'), 'повторный запуск не плодит правила');

// ── sync_image_tag.sh ──────────────────────────────────────────────────────
$sy = $read('scripts/sync_image_tag.sh');
shAssert(str_contains($sy, 'set -eu'), 'sync_image_tag.sh падает на ошибке шага');
shAssert(str_contains($sy, 'if [ ! -s "$tmp" ]'),
    'пустой временный файл не затирает override.env с настройками машины');
shAssert(str_contains($sy, 'flock'), 'перезапись override.env под локом');

// ── start_wp.sh: ключ WARP+ ────────────────────────────────────────────────
$wp = $read('scripts/start_wp.sh');
shAssert(!preg_match('~sed -i "s/\^license_key~', $wp),
    'ключ WARP+ больше не интерполируется в тело sed-выражения');
shAssert(str_contains($wp, 'ENVIRON["LK"]'),
    'значение передаётся через окружение: спецсимволы /, & и \\ больше не ломают подстановку');

// ── init.sh: docker из подписанного репозитория ────────────────────────────
$in = $read('scripts/init.sh');
shAssert(!str_contains($code($in), 'get.docker.com'),
    'curl|sh от третьей стороны от root убран');
shAssert(str_contains($in, 'DOCKER_GPG_FPR='), 'отпечаток ключа docker сверяется явно');
shAssert(str_contains($in, 'signed-by=/etc/apt/keyrings/docker.gpg'),
    'репозиторий docker подключён с привязкой к ключу');

if ($failed) {
    echo "audit_shell_hardening_test FAILED ($failed)\n";
    exit(1);
}
echo "audit_shell_hardening_test OK\n";
