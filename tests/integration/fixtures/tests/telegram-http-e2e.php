<?php
require '/app/config.php';
if (getenv('TELEGRAM_API') !== 'tg-audit:8443') throw new RuntimeException('Test API required');
$admin = (int) ((array) $c['admin'])[0];
$command = $argv[1];
$from = ($argv[2] ?? '') === 'unauthorized' ? $admin + 1000000000 : $admin;
$payload = ['update_id' => time(), 'callback_query' => [
    'id' => 'published-http-e2e', 'from' => ['id' => $from, 'is_bot' => false, 'first_name' => 'Fixture'],
    'message' => ['message_id' => 5001, 'chat' => ['id' => $from, 'type' => 'private'], 'text' => 'Fixture'],
    'data' => $command,
]];
$curl = curl_init('http://127.0.0.1/tlgrm?k=' . rawurlencode($c['key']));
curl_setopt_array($curl, [CURLOPT_POST => true, CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
    CURLOPT_POSTFIELDS => json_encode($payload), CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 90]);
$response = curl_exec($curl);
echo json_encode(['http' => curl_getinfo($curl, CURLINFO_RESPONSE_CODE), 'curl' => curl_errno($curl),
    'body_bytes' => strlen((string) $response), 'php_error_in_response' =>
    (bool) preg_match('/Warning:|Fatal error:|Deprecated:/', (string) $response)]), "\n";
