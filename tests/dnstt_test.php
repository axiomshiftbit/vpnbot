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
dtAssert(str_contains($start, 'Match User vpnbot Address 127.0.0.1'), 'исключение ограничено пользователем и tunnel endpoint');
foreach (['PasswordAuthentication yes', 'AllowTcpForwarding local', 'MaxSessions 0',
          'AllowStreamLocalForwarding no', 'PermitUserRC no'] as $directive) {
    dtAssert(str_contains($start, $directive), 'изолированная SSH-политика: ' . $directive);
}
dtAssert(!str_contains($shared, 'Match User vpnbot'), 'общая SSH-политика контейнеров не ослаблена');
dtAssert(str_contains($start, '--uid-owner vpnbot') && str_contains($start, '10.0.0.0/8'), 'forward изолирован от служебных сетей');
dtAssert(str_contains($start, 'HostKey /dnstt/ssh_host_ed25519_key'), 'SSH identity переживает recreate');
dtAssert(str_contains($start, 'pkill -u vpnbot'), 'смена пароля прекращает существующие сеансы');
dtAssert(str_contains($start, 'chpasswd -e'), 'сервис получает хэш вместо пароля');
dtAssert(str_contains($start, "printf 'vpnbot:!\\n' | chpasswd -e"),
    'блокировка на первом запуске идемпотентна');

echo $failed ? "dnstt_test FAILED ($failed)\n" : "dnstt_test OK\n";
exit($failed ? 1 : 0);
