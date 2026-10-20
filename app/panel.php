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

// Пароль пишется в pac.json, и Panel::pacConf() бросает исключение, когда файл
// недоступен или повреждён (записать поверх него конфиг из одного panelpswd
// значило бы потерять клиентов и ключи reality). В CLI это выглядело фаталом со
// стектрейсом — говорим по-человечески.
set_exception_handler(function (Throwable $e) {
    fwrite(STDERR, 'panel: ' . $e->getMessage() . "\n");
    exit(1);
});

switch ($cmd) {
    case 'url':
        $plain = $panel->ensurePassword();
        echo Lang::t("Панель: http://127.0.0.1:$port{$panel->prefix()}/\n", "Panel: http://127.0.0.1:$port{$panel->prefix()}/\n");
        echo Lang::t("Порт наружу не открыт — пробросьте его по ssh:\n", "The port is not open to the outside; forward it over ssh:\n");
        echo Lang::t("  ssh -L $port:127.0.0.1:$port <сервер>\n", "  ssh -L $port:127.0.0.1:$port <server>\n");
        if ($plain) {
            echo Lang::t("\nСгенерирован пароль: $plain\n", "\nGenerated password: $plain\n");
            echo Lang::t("Он же лежит в ", "It is also stored in ") . Panel::dataDir() . Lang::t("/initial_password.txt — файл удалится после первого входа.\n", "/initial_password.txt; the file is deleted after the first sign-in.\n");
        }
        if (empty($c['admin'])) {
            echo Lang::t("\nВНИМАНИЕ: в config.php пуст \$c['admin'] — бот никому не принадлежит.\n", "\nWARNING: \$c['admin'] is empty in config.php; the bot belongs to nobody.\n");
            echo Lang::t("Задайте владельца: php panel.php admin <telegram-id>\n", "Set the owner: php panel.php admin <telegram-id>\n");
        }
        break;

    case 'passwd':
        $new = $argv[2] ?? null;
        if (null === $new) {
            echo Lang::t('Новый пароль: ', 'New password: ');
            // Эхо в терминале гасим: пароль не должен остаться на экране и в
            // истории команд (аргументом его тоже видно в ps, но это выбор).
            @shell_exec('stty -echo 2>/dev/null');
            $new = trim((string) fgets(STDIN));
            @shell_exec('stty echo 2>/dev/null');
            echo "\n";
        }
        if (strlen($new) < 8) {
            fwrite(STDERR, Lang::t("Пароль короче 8 символов — отказ.\n", "The password is shorter than 8 characters; refused.\n"));
            exit(1);
        }
        $panel->setPassword($new);
        echo Lang::t("Пароль обновлён, все открытые сессии панели сброшены.\n", "Password updated, all open panel sessions are reset.\n");
        break;

    case 'admin':
        $id = $argv[2] ?? '';
        if (!preg_match('~^-?\d+$~', (string) $id)) {
            fwrite(STDERR, Lang::t("Нужен числовой telegram-id: php panel.php admin <id>\n", "A numeric telegram-id is needed: php panel.php admin <id>\n"));
            exit(1);
        }
        $file = __DIR__ . '/config.php';
        require $file;
        $c['admin'] = array_values(array_unique(array_merge((array) ($c['admin'] ?? []), [(int) $id])));
        file_put_contents($file, "<?php\n\n\$c = " . var_export($c, true) . ";\n");
        echo Lang::t("Администраторы бота (первый — владелец): ", "Bot administrators (the first is the owner): ") . implode(', ', $c['admin']) . "\n";
        break;

    case 'reset':
        $panel->store()->reset();
        echo Lang::t("Лента панели очищена.\n", "The panel feed is cleared.\n");
        break;

    default:
        fwrite(STDERR, Lang::t("Команды: url | passwd [пароль] | admin <id> | reset\n", "Commands: url | passwd [password] | admin <id> | reset\n"));
        exit(1);
}
