<?php
// Нативные DNS и cURL. Нет overrides и чтения app/config.php/runtime state.
if (!is_file('/run/vpnbot-synthetic-audit') || is_link('/run/vpnbot-synthetic-audit')
    || trim(file_get_contents('/run/vpnbot-synthetic-audit')) !== 'SYNTHETIC-ONLY') {
    fwrite(STDERR, "Нужен маркер синтетического контейнера\n"); exit(2);
}
if (!extension_loaded('curl')) { fwrite(STDERR, "Нужен нативный PHP cURL\n"); exit(2); }
$mode = $argv[1] ?? '';
if (!in_array($mode, ['rebind', 'large', 'baseline'], true)) exit(2);
require '/src/app/bot.php';
$bot = (new ReflectionClass(Bot::class))->newInstanceWithoutConstructor();
$settings = $bot->xdriveSettings(['xdrive' => ['service' => 'webdav',
    'url' => $mode === 'rebind' ? 'http://storage.audit.test:8098' : 'http://11.77.78.2:8098',
    'folder' => 'fixture', 'secrets' => ['fixture-user', 'synthetic-only']]]);
$start = microtime(true);
$error = $bot->xdriveProbe($settings);
echo json_encode(['mode' => $mode, 'returned' => true, 'error' => $error,
    'peak_memory_bytes' => memory_get_peak_usage(true), 'seconds' => round(microtime(true) - $start, 3)]), "\n";
exit($error === '' ? 0 : 1);
