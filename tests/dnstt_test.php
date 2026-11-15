<?php

require_once __DIR__ . '/../app/bot.php';
$failed = 0;
function dtAssert(bool $ok, string $message): void
{
    global $failed;
    if (!$ok) { $failed++; echo "FAIL: $message\n"; }
}

foreach (['t.example.com', 'dns-tunnel.example.org', 'T.EXAMPLE.COM'] as $domain) {
    dtAssert(Bot::dnsttDomainOk($domain), 'допустимый домен ' . $domain);
}
foreach (['', 'localhost', '-t.example.com', 't-.example.com', 't..example.com',
          "t.example.com\n", 't.example.com;id', str_repeat('a', 64) . '.com'] as $domain) {
    dtAssert(!Bot::dnsttDomainOk($domain), 'некорректный DNS suffix отклонён');
}

// До исправления SSH поверх dnstt отвечал только publickey: пароль из меню
// никогда не работал. Исключение теперь локальное, не для остальных служб.
$start = file_get_contents(__DIR__ . '/../scripts/start_dnstt.sh');
$shared = file_get_contents(__DIR__ . '/../config/sshd_config');
$daemon = file_get_contents(__DIR__ . '/../scripts/service_daemon.sh');
$supervisor = file_get_contents(__DIR__ . '/../scripts/service_supervisor.sh');
dtAssert(str_contains($start, 'Match User vpnbot Address 127.0.0.1'), 'исключение ограничено пользователем и tunnel endpoint');
foreach (['PasswordAuthentication yes', 'AllowTcpForwarding local', 'MaxSessions 0',
          'AllowStreamLocalForwarding no', 'PermitUserRC no'] as $directive) {
    dtAssert(str_contains($start, $directive), 'изолированная SSH-политика: ' . $directive);
}
dtAssert(!str_contains($shared, 'Match User vpnbot'), 'общая SSH-политика контейнеров не ослаблена');
dtAssert(str_contains($start, '--uid-owner vpnbot') && str_contains($start, '10.0.0.0/8'), 'forward изолирован от служебных сетей');
dtAssert(str_contains($start, 'HostKey /dnstt/ssh_host_ed25519_key'), 'SSH identity переживает recreate');
// Применение теперь проходит launcher → controller → adapter. Проверяем всю
// цепочку: одна строка в неисполняемом helper не доказывает отзыв сеансов.
$stopStart = strpos($supervisor, 'stop_daemon()');
$stopEnd = strpos($supervisor, 'start_daemon()', $stopStart ?: 0);
$stopBody = $stopStart !== false && $stopEnd !== false
    ? substr($supervisor, $stopStart, $stopEnd - $stopStart) : '';
$stoppedStart = strpos($daemon, 'if [ "$action" = stopped ]');
$stoppedEnd = $stoppedStart !== false ? strpos($daemon, "\nfi", $stoppedStart) : false;
$stoppedBody = $stoppedStart !== false && $stoppedEnd !== false
    ? substr($daemon, $stoppedStart, $stoppedEnd - $stoppedStart) : '';
dtAssert(str_contains($start, '/service_supervisor.sh restart dnstt')
    && str_contains($start, '/service_supervisor.sh stop dnstt')
    && str_contains($stopBody, 'sh "$HELPER" stopped "$NAME"')
    && str_contains($stoppedBody, 'pkill -u vpnbot'),
    'смена пароля прекращает существующие сеансы через controller adapter');
dtAssert(str_contains($daemon, "jq -r '\"vpnbot:\" + .password_hash' /dnstt/settings.json | chpasswd -e"),
    'сервис получает хэш вместо пароля');
$initialBranch = strpos($start, 'if [ "${1:-}" != "--reload" ]; then');
$initialStop = strpos($start, '/bin/sh /service_daemon.sh stopped dnstt');
$sshdLaunch = strpos($start, '/usr/sbin/sshd -D');
dtAssert($initialBranch !== false && $initialStop !== false && $sshdLaunch !== false
    && $initialBranch < $initialStop && $initialStop < $sshdLaunch
    && str_contains($stoppedBody, "printf 'vpnbot:!\\n' | chpasswd -e"),
    'блокировка на первом запуске идемпотентна, включая существующую учётку и disabled settings');

echo $failed ? "dnstt_test FAILED ($failed)\n" : "dnstt_test OK\n";
exit($failed ? 1 : 0);
