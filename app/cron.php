<?php

require __DIR__ . '/timezone.php';

// require __DIR__ . '/debug.php';
require __DIR__ . '/bot.php';
require __DIR__ . '/config.php';
require __DIR__ . '/i18n.php';

// Без аргумента — основной процесс контейнера service: шаги access и надзор за
// дочерним `cron.php maintenance` (сетевые и медленные шаги), см. Bot::cron().
$group = $argv[1] ?? 'access';
if (!in_array($group, ['access', 'maintenance'], true)) {
    fwrite(STDERR, "cron: unknown group\n");
    exit(2);
}
(new Bot($c['key'], $i))->cron($group, $group === 'access' ? __FILE__ : null);
