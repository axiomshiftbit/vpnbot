<?php

// __DIR__, как во всех остальных точках входа: относительный путь резолвится
// от рабочего каталога вызывающего, и из cron/другого каталога скрипт падал.
require __DIR__ . '/config.php';

require __DIR__ . '/TelegramApi.php';

// Тот же адрес API, что и у бота (Bot::__construct): при работе через зеркало
// или ретранслятор хардкод api.telegram.org показывал состояние не того эндпоинта.
$api = TelegramApi::current()['url'];

$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL            => "$api/bot{$c['key']}/getWebhookInfo",
    CURLOPT_RETURNTRANSFER => true,
]);
if ($proxy = getenv('TELEGRAM_PROXY')) {
    curl_setopt($ch, CURLOPT_PROXY, $proxy);
}
$res = curl_exec($ch);
die(var_dump($res));
