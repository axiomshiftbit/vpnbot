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
// На VPS проверены реальные клиенты: DNS работает, а TCP Docker API,
// панели, AdGuard UI и SSH самого VPN-контейнера отвергаются.
foreach (['scripts/start_ovpn.sh' => '-i tun+', 'scripts/start_ipsec.sh' => '-s "$CLIENT_SUBNET"', 'scripts/start_oc.sh' => '-i "${VPN_DEVICE}+"'] as $path => $selector) {
    $body = $read($path);
    $guard = str_replace(['scripts/start_', '.sh'], '', $path) . '_guard';
    // Защита обязана встать: REJECT, при его недоступности DROP, иначе FATAL и выход.
    $function = preg_match('~^' . preg_quote($guard, '~') . '\(\) \{\n(.*?)^\}~ms', $body, $m) ? $m[1] : '';
    shAssert(str_contains($body, "$guard -A INPUT $selector -j REJECT")
        && str_contains($function, 'iptables "$@" && return 0') && str_contains($function, 'set -- "$@" DROP')
        && preg_match('~FATAL: [^\n]*client firewall was not installed[^\n]*; exit 1\n\}?~', $function . "\n") === 1,
        "$path: службы самого контейнера закрыты от VPN с проверкой применения");
    $deny = strpos($body, "$selector -d 10.10.0.0/16 -j REJECT");
    shAssert($deny !== false, "$path: служебная сеть закрыта от VPN");
    foreach (['udp', 'tcp'] as $proto) {
        $dns = strpos($body, "-p $proto --dport 53 -j ACCEPT");
        shAssert($dns !== false && $dns < $deny, "$path: $proto DNS разрешён до запрета служебной сети");
    }
}

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

// ── НИЗКИЕ того же отчёта ───────────────────────────────────────────────────

// Шебанги: скрипты запускаются с явным интерпретатором, но без шебанга их
// нельзя запустить руками и нельзя понять, под какой оболочкой они писались.
foreach (glob(__DIR__ . '/../scripts/*.sh') as $p) {
    $first = strtok((string) file_get_contents($p), "\n");
    shAssert(str_starts_with((string) $first, '#!'), basename($p) . ': есть шебанг');
}

// [[ ]] под /bin/sh: работает лишь потому, что busybox собран с ASH_BASH_COMPAT.
foreach (['scripts/check_file.sh', 'scripts/start_php.sh'] as $p) {
    shAssert(!str_contains($code($read($p)), '[['),
        basename($p) . ': POSIX-условия вместо [[ ]] (healthcheck запускается через /bin/sh)');
}

// Права на ключи.
shAssert(str_contains($read('scripts/start_ipsec.sh'), 'umask 077'),
    'start_ipsec.sh: PKI и PSK создаются сразу с узкими правами, а не chmod-ом потом');
foreach (['scripts/start_wg.sh', 'scripts/reset_wg.sh'] as $p) {
    shAssert(str_contains($read($p), 'umask 077;'),
        basename($p) . ': приватный ключ WireGuard не создаётся 0644');
    shAssert(str_contains($read($p), 'HOSTNAME="${HOSTNAME:-$(hostname)}"'),
        basename($p) . ': выбор инстанса не держится на переменной, которую заводит docker');
}

// exec перед фоновым запуском и мёртвый tail.
foreach (glob(__DIR__ . '/../scripts/*.sh') as $p) {
    shAssert(!str_contains((string) file_get_contents($p), 'exec /usr/sbin/sshd -D -e "$@" &'),
        basename($p) . ': нет `exec cmd &` (это обычный фоновый запуск, а читается наоборот)');
}
// Контейнер обязан переживать intentional stopAd/startAd. Supervisor также
// восстанавливает процесс после аварии; runtime регрессии проверяют оба пути.
shAssert(str_contains($read('scripts/start_ad.sh'), 'exec /bin/sh /service_supervisor.sh supervise ad'),
    'start_ad.sh: supervisor сохраняет SSH между stopAd/startAd');

// install_as_service.sh и diagnose_bot.sh
$ias = $read('scripts/install_as_service.sh');
shAssert(str_contains($ias, 'set -eu'), 'install_as_service.sh падает на ошибке шага');
shAssert(!str_contains($code($ias), 'sed "s|__VPNBOT_PATH__'),
    'путь установки не идёт в тело sed-выражения (символ | в пути ломал его)');
shAssert(str_contains($ias, 'if [ ! -s "$tmp" ]'), 'пустой юнит-файл не попадёт в systemd');
shAssert(str_contains($read('scripts/diagnose_bot.sh'), 'cd "$ROOT" || exit 1'),
    'diagnose_bot.sh не диагностирует чужой каталог');

// Полуфабрикаты с секретами в корне контейнера.
$wgAll = $read('scripts/start_wg.sh');
shAssert(!str_contains($code($wgAll), '> change_port') && !str_contains($code($wgAll), '> change_address'),
    'start_wg.sh не оставляет в корне контейнера копии wg0.conf с ключами');

if ($failed) {
    echo "audit_shell_hardening_test FAILED ($failed)\n";
    exit(1);
}
echo "audit_shell_hardening_test OK\n";
