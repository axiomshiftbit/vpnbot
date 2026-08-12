<?php

// __DIR__, как во всех остальных точках входа: относительный путь резолвится
// от рабочего каталога вызывающего, и из cron/другого каталога скрипт падал.
require __DIR__ . '/config.php';

$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL            => "https://api.telegram.org/bot{$c['key']}/getWebhookInfo",
    CURLOPT_RETURNTRANSFER => true,
]);
$res = curl_exec($ch);
die(var_dump($res));
