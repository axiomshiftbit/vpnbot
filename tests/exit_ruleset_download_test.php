<?php
// Скачивание наборов .srs/.mrs узлов выхода: внутренние адреса, NAT64 и не-HTTPS
// отвергаются до соединения; проверенные адреса закрепляются за curl.
require_once __DIR__ . '/../app/bot.php';

class ExitDownloadBot extends Bot
{
    public function __construct() {}
    public function download(string $url): ?string { return $this->exitRulesetDownload($url); }
}

$checks = 0;
$check = static function (bool $ok, string $name) use (&$checks): void {
    $checks++;
    if (!$ok) throw new RuntimeException('FAIL: ' . $name);
};
$bot = new ExitDownloadBot();
foreach (['https://127.0.0.1/x.srs', 'https://[::1]/x.srs', 'https://[::ffff:127.0.0.1]/x.srs',
    'https://[64:ff9b::7f00:1]/x.srs', 'https://10.10.0.2/x.srs', 'https://100.64.0.1/x.srs', 'https://169.254.169.254/x.srs',
    'http://example.com/x.srs', 'https://user:pass@example.com/x.srs'] as $url) {
    $check($bot->download($url) === null, 'отказ: ' . $url);
}
// Сам транспорт проверяет exit_ruleset_download_test.py: настоящий HTTPS,
// разные адреса при проверке и подключении, переадресация, IPv6 и проверка TLS.
echo "exit_ruleset_download_test OK ($checks checks)\n";
