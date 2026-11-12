<?php

// Адрес Bot API этого бота и ретранслятор Telegram API из командной строки:
// make tgapi cmd="status" (или docker compose exec -T php php /app/tgapi.php
// help). Нужна, когда бот уже не может ответить в Telegram и меню недоступно.
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require __DIR__ . '/timezone.php';
require __DIR__ . '/bot.php';
require __DIR__ . '/config.php';
require __DIR__ . '/i18n.php';

exit((new Bot($c['key'], $i))->telegramApiCli(array_slice($argv, 1)));
