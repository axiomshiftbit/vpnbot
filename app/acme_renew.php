<?php

/**
 * Выпуск сертификата Let's Encrypt без Telegram — для службы хоста acme-window
 * (scripts/acme_window.py). Служба вызывает через docker exec:
 *
 *   php acme_renew.php check                 имена сертификата (JSON); код 3 — не Let's Encrypt
 *   php acme_renew.php issue [--dry-run]     certbot; порт 80 в это время открыт службой
 *   php acme_renew.php install               бандл в /certs и перезапуск зависимых служб
 *   php acme_renew.php notify ЦЕЛЬ РЕЗУЛЬТАТ сообщение администраторам по /acme/state/ЦЕЛЬ.json
 *
 * issue и install разделены: служба закрывает порт сразу после certbot и не
 * держит его открытым, пока перезапускаются nginx, AdGuard и TrustTunnel.
 */

require __DIR__ . '/timezone.php';
require __DIR__ . '/bot.php';
require __DIR__ . '/config.php';
require __DIR__ . '/i18n.php';

set_exception_handler(function (Throwable $e) {
    fwrite(STDERR, 'acme_renew: ' . $e->getMessage() . "\n");
    exit(1);
});

$bot  = new Bot($c['key'], $i);
$cmd  = $argv[1] ?? '';
$conf = $bot->getPacConf();

$letsencrypt = $bot->acmeWantsLetsencrypt($conf);

switch ($cmd) {
    case 'check':
        if (!$letsencrypt) {
            exit(3);
        }
        echo json_encode(['domains' => $bot->letsencryptNames($conf)]), "\n";
        break;

    case 'issue':
        if (!$letsencrypt) {
            exit(3);
        }
        [$code, $out] = $bot->issueLetsencrypt($conf, ($argv[2] ?? '') === '--dry-run');
        echo implode("\n", $out), "\n";
        exit($code === 0 ? 0 : 1);

    case 'install':
        if (!$letsencrypt) {
            exit(3);
        }
        if (!$bot->installLetsencrypt($conf['domain'])) {
            fwrite(STDERR, "acme_renew: not installed: settings changed or no key and chain in /etc/letsencrypt/live/{$conf['domain']}\n");
            exit(1);
        }
        echo "installed\n";
        break;

    case 'notify':
        $name   = (string) ($argv[2] ?? '');
        $result = (string) ($argv[3] ?? '');
        $state  = $bot->acmeStates()[$name] ?? null;
        if (!$state || !preg_match('~^[a-z_]{1,32}$~', $result)) {
            fwrite(STDERR, "acme_renew: unknown target or result\n");
            exit(2);
        }
        $text = $bot->acmeNotifyText($state, $result);
        $sent = 0;
        foreach ((array) ($c['admin'] ?? []) as $admin) {
            $r = $bot->send($admin, $text);
            $sent += !empty($r['ok']) ? 1 : 0;
        }
        exit($sent > 0 ? 0 : 1);

    default:
        fwrite(STDERR, "usage: php acme_renew.php check|issue [--dry-run]|install|notify TARGET RESULT\n");
        exit(2);
}
