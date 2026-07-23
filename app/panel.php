<?php

/**
 * CLI веб-панели: пароль, владелец, адрес, очистка ленты.
 *
 *   docker compose exec php php panel.php url
 *   docker compose exec php php panel.php passwd [новый-пароль]
 *   docker compose exec php php panel.php admin <telegram-id>
 *   docker compose exec php php panel.php reset
 *
 * Пароль задаётся отсюда, а не из меню бота: панель нужна ровно тогда, когда
 * Telegram недоступен, и просить «нажмите кнопку в боте» было бы бессмысленно.
 */

require __DIR__ . '/timezone.php';
require __DIR__ . '/bot.php';
require __DIR__ . '/config.php';
require __DIR__ . '/i18n.php';
require __DIR__ . '/panel/Panel.php';

$bot   = new Bot($c['key'], $i);
$panel = new Panel($bot, $c);
$cmd   = $argv[1] ?? 'url';
$port  = Panel::port();

switch ($cmd) {
    case 'url':
        $plain = $panel->ensurePassword();
        echo "Панель: http://127.0.0.1:$port{$panel->prefix()}/\n";
        echo "Порт наружу не открыт — пробросьте его по ssh:\n";
        echo "  ssh -L $port:127.0.0.1:$port <сервер>\n";
        if ($plain) {
            echo "\nСгенерирован пароль: $plain\n";
            echo "Он же лежит в " . Panel::dataDir() . "/initial_password.txt — удалите после входа.\n";
        }
        if (empty($c['admin'])) {
            echo "\nВНИМАНИЕ: в config.php пуст \$c['admin'] — бот никому не принадлежит.\n";
            echo "Задайте владельца: php panel.php admin <telegram-id>\n";
        }
        break;

    case 'passwd':
        $new = $argv[2] ?? null;
        if (null === $new) {
            echo 'Новый пароль: ';
            // Эхо в терминале гасим: пароль не должен остаться на экране и в
            // истории команд (аргументом его тоже видно в ps, но это выбор).
            @shell_exec('stty -echo 2>/dev/null');
            $new = trim((string) fgets(STDIN));
            @shell_exec('stty echo 2>/dev/null');
            echo "\n";
        }
        if (strlen($new) < 8) {
            fwrite(STDERR, "Пароль короче 8 символов — отказ.\n");
            exit(1);
        }
        $panel->setPassword($new);
        echo "Пароль обновлён, все открытые сессии панели сброшены.\n";
        break;

    case 'admin':
        $id = $argv[2] ?? '';
        if (!preg_match('~^-?\d+$~', (string) $id)) {
            fwrite(STDERR, "Нужен числовой telegram-id: php panel.php admin <id>\n");
            exit(1);
        }
        $file = __DIR__ . '/config.php';
        require $file;
        $c['admin'] = array_values(array_unique(array_merge((array) ($c['admin'] ?? []), [(int) $id])));
        file_put_contents($file, "<?php\n\n\$c = " . var_export($c, true) . ";\n");
        echo "Владельцы бота: " . implode(', ', $c['admin']) . "\n";
        break;

    case 'reset':
        $panel->store()->reset();
        echo "Лента панели очищена.\n";
        break;

    default:
        fwrite(STDERR, "Команды: url | passwd [пароль] | admin <id> | reset\n");
        exit(1);
}
