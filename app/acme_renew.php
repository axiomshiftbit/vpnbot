<?php

/**
 * Выпуск сертификата Let's Encrypt без Telegram — для службы хоста acme-window
 * (scripts/acme_window.py). Служба вызывает через docker exec:
 *
 *   php acme_renew.php check                 имена сертификата (JSON); код 3 — не Let's Encrypt
 *   php acme_renew.php issue [--dry-run]     certbot; порт 80 в это время открыт службой
 *   php acme_renew.php install ДОМЕН [JSON]  бандл в /certs, если имена выпуска ещё актуальны
 *   php acme_renew.php reapply SHA256       повторно применить текущую пару указанного поколения
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
        if ($code === 0 && ($argv[2] ?? '') !== '--dry-run') {
            echo json_encode(['issued_certificate' => @hash_file('sha256', "/etc/letsencrypt/live/{$conf['domain']}/fullchain.pem") ?: '']), "\n";
        }
        exit($code === 0 ? 0 : 1);

    case 'install':
        if (!$letsencrypt) {
            exit(3);
        }
        // Без аргумента оставлен прежний вызов для ещё не обновлённой службы.
        // Новая служба передаёт домен и полный набор имён начатого выпуска.
        $domain = (string) ($argv[2] ?? $conf['domain']);
        $names = isset($argv[3]) ? json_decode($argv[3], true, 32, JSON_THROW_ON_ERROR) : [];
        // Receipt и проверка поколения под той же блокировкой, что restore.
        // При отказе reload файл уже может быть новым: scheduler должен знать
        // именно его fingerprint, не принимать чужой restore за свою запись.
        $expected = $argv[4] ?? null;
        $issued = $argv[5] ?? null;
        foreach ([$expected, $issued] as $hash) {
            if ($hash !== null && $hash !== '' && !preg_match('~^[a-f0-9]{64}$~D', $hash)) exit(2);
        }
        $receipt = $bot->installLetsencryptReceipt($domain, $names, $expected, $issued);
        echo json_encode($receipt), "\n";
        if (empty($receipt['installed'])) exit(!empty($receipt['stale']) ? 4 : 1);
        break;

    case 'reapply':
        $expected = $argv[2] ?? '';
        if (!preg_match('~^[a-f0-9]{64}$~D', $expected)) exit(2);
        $receipt = $bot->reapplyCertificateReceipt($expected);
        echo json_encode($receipt), "\n";
        exit(!empty($receipt['installed']) ? 0 : (!empty($receipt['stale']) ? 4 : 1));

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
        fwrite(STDERR, "usage: php acme_renew.php check|issue [--dry-run]|install [DOMAIN [NAMES_JSON [CURRENT_SHA256 [ISSUED_SHA256]]]]|reapply SHA256|notify TARGET RESULT\n");
        exit(2);
}
