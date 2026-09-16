<?php

error_reporting(E_ALL | E_NOTICE);

$debug = [
    // Тела запросов, файлы и ответы содержат пароли, ключи и подписки.
    // Даже debug сохраняет только размеры и код результата, без URI/query.
    'request_bytes' => strlen((string) file_get_contents('php://input')),
    'post_fields' => count($_POST),
    'file_fields' => count($_FILES),
];
register_shutdown_function('exit_log', $debug);

function exit_log($debug)
{
    $debug['response_bytes'] = strlen((string) ob_get_contents());
    $debug['http_code'] = http_response_code();
    file_put_contents('/logs/requests', json_encode($debug) . "\n", FILE_APPEND | LOCK_EX);
    @chmod('/logs/requests', 0600);
}
