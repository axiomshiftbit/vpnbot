<?php

require './config.php';

// Тот же адрес API, что и у бота (Bot::__construct): при работе через зеркало
// хардкод api.telegram.org показывал состояние не того эндпоинта.
$api = getenv('TELEGRAM_API') ?: 'api.telegram.org';

$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL            => "https://$api/bot{$c['key']}/getWebhookInfo",
    CURLOPT_RETURNTRANSFER => true,
]);
if ($proxy = getenv('TELEGRAM_PROXY')) {
    curl_setopt($ch, CURLOPT_PROXY, $proxy);
}
$res = curl_exec($ch);
die(var_dump($res));
