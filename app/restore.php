<?php

// Восстановление резервной копии из командной строки: make restore
// FILE=backup.json, проверка без изменений — make restore-check FILE=…
// Без make: docker compose exec -T php php /app/restore.php [--check] < backup.json
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require __DIR__ . '/timezone.php';
require __DIR__ . '/bot.php';
require __DIR__ . '/BackupCli.php';
require __DIR__ . '/config.php';
require __DIR__ . '/i18n.php';

exit((new BackupCli($c['key'], $i))->cli(array_slice($argv, 1), STDIN));
