<?php

// Настоящий cURL читает ответы фиктивного API через file://. В копии класса
// меняется только путь журнала, чтобы тест не трогал /logs установки.
if (!extension_loaded('curl')) {
    echo "request_logging_test SKIP: нужен curl\n";
    exit(0);
}
$dir = sys_get_temp_dir() . '/vpnbot-log-' . bin2hex(random_bytes(6));
mkdir($dir, 0700);
$log = "$dir/requests_error";
foreach (['ClashTemplateValidator.php', 'VlessEncryption.php', 'BotProtocols.php', 'BotProtocolOptions.php', 'BotProtocolSubscriptions.php', 'BotConnectionExports.php', 'BotHysteria.php', 'HysteriaUsers.php', 'ProtocolModules.php', 'ManagedProtocol.php', 'ProtocolOptions.php', 'ProtocolOptionHelp.php', 'PanelPasswordVault.php'] as $file) {
    copy(__DIR__ . '/../app/' . $file, "$dir/$file");
}
file_put_contents("$dir/bot.php", str_replace("'/logs/requests_error'", var_export($log, true),
    file_get_contents(__DIR__ . '/../app/bot.php')));
require "$dir/bot.php";
$marker = 'AUDIT_SECRET_MUST_NOT_ENTER_LOG';
try {
    $bot = (new ReflectionClass(Bot::class))->newInstanceWithoutConstructor();
    $bot->api = "file://$dir/";
    file_put_contents("$dir/sendDocument", json_encode(['ok' => false, 'error_code' => 400, 'description' => $marker]));
    file_put_contents("$dir/sendMessage", '<html>' . $marker . '</html>');
    file_put_contents("$dir/editMessageText", json_encode(['ok' => false, 'description' => 'message is not modified']));
    file_put_contents($log, '');
    chmod($log, 0644);
    $bot->request('sendDocument', ['caption' => $marker, 'document' => new CURLStringFile($marker, 'backup.json')]);
    $bot->request('sendMessage', json_encode(['text' => $marker]), 1);
    $bot->request('editMessageText', ['text' => $marker]);
    $bot->request('missingMethod', ['text' => $marker]);
    $raw = file_get_contents($log);
    $lines = array_map(fn($line) => json_decode($line, true), explode("\n", trim($raw)));
    if (str_contains($raw, $marker) || count($lines) !== 3
        || $lines[0]['method'] !== 'sendDocument' || $lines[0]['api_error_code'] !== 400
        || $lines[2]['curl_code'] === 0 || (fileperms($log) & 0777) !== 0600) {
        throw new RuntimeException('Журнал раскрыл содержимое или потерял код ошибки');
    }

    // Shutdown debug-писателя проверяем в отдельном процессе с телом ответа.
    file_put_contents("$dir/debug.php", str_replace("'/logs/requests'", var_export("$dir/debug-log", true),
        file_get_contents(__DIR__ . '/../app/debug.php')));
    $worker = '<?php $_POST=["password"=>' . var_export($marker, true) . ']; $_FILES=[]; ob_start(); '
        . 'require ' . var_export("$dir/debug.php", true) . '; echo ' . var_export($marker, true) . ';';
    file_put_contents("$dir/worker.php", $worker);
    $proc = proc_open([PHP_BINARY, "$dir/worker.php"], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    stream_get_contents($pipes[1]);
    $err = stream_get_contents($pipes[2]);
    fclose($pipes[1]); fclose($pipes[2]);
    if (proc_close($proc) !== 0 || $err !== '') throw new RuntimeException('Debug-писатель завершился с ошибкой');
    $raw = file_get_contents("$dir/debug-log");
    $debug = json_decode($raw, true);
    if (str_contains($raw, $marker) || $debug['post_fields'] !== 1
        || $debug['response_bytes'] !== strlen($marker) || (fileperms("$dir/debug-log") & 0777) !== 0600) {
        throw new RuntimeException('Debug-журнал раскрыл содержимое запроса или ответа');
    }
} finally {
    foreach (glob("$dir/*") as $file) unlink($file);
    rmdir($dir);
}
echo "request_logging_test OK\n";
