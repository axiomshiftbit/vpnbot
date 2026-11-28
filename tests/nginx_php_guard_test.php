<?php

// Адреса nginx, ведущие в PHP бота (/pac, /tlgrm, @php после /webapp),
// не принимают multipart/form-data (PHP2Shell, CVE-2026-109618/109619):
//  - строка защиты ставится первой в каждый такой location, в том числе в
//    закомментированные копии #-domain, и после uncomment() остаётся рабочей;
//  - повторный проход ничего не меняет, чужие location не трогаются;
//  - шаблоны репозитория уже защищены;
//  - cron дописывает защиту в шаблон и рабочий nginx.conf старой установки.

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function guardAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

class NginxGuardTestBot extends Bot
{
    public array $commands = [];

    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
    {
        $this->commands[] = [$service, (string) $cmd];
        // Как у живого контейнера nginx: печатаем отметку, которую ждёт команда.
        return preg_match_all('~printf (VPNBOT_[A-Z]+)~', (string) $cmd, $m) ? end($m[1]) : '';
    }
}

$line = 'if ($http_content_type ~* "multipart/form-data") { return 415; } # ' . Bot::NGINX_PHP_GUARD;

// ── 1. вставка в действующие и закомментированные блоки ─────────────────────
$sample = <<<'NGX'
        location /tlgrm {
            proxy_pass http://php;
        }
        location @php {
            proxy_pass http://php;
        }
        location /pac {
            proxy_pass http://php;
        }
        location /pac1a2b3c4d {
            proxy_pass http://php;
        }
        location /pac-x {
            proxy_pass http://other;
        }
        location /adguard/ {
        }
    #-domain
    # server {
    #     location /pac {
    #         proxy_pass http://php;
    #     }
    # }
    #-domain
NGX;
$guarded = Bot::nginxPhpMultipartGuard($sample);
guardAssert(substr_count($guarded, Bot::NGINX_PHP_GUARD) === 5, 'защита в четырёх действующих и одном закомментированном location');
guardAssert(str_contains($guarded, "        location /pac1a2b3c4d {\n            $line\n"), '/pac с хэшем бота (после cloakNginx) защищён');
guardAssert(str_contains($guarded, "        location /tlgrm {\n            $line\n            proxy_pass"), '/tlgrm: строка первой, с отступом блока');
guardAssert(str_contains($guarded, "        location @php {\n            $line\n"), '@php защищён');
guardAssert(str_contains($guarded, "    #     location /pac {\n    #         $line\n"), 'закомментированная копия получает строку с тем же префиксом');
foreach (['/pac-x', '/adguard/'] as $other) {
    preg_match('~location ' . preg_quote($other, '~') . ' \{(.*?)\}~s', $guarded, $m);
    guardAssert(!str_contains($m[1], 'multipart'), "$other не трогается");
}
guardAssert(Bot::nginxPhpMultipartGuard($guarded) === $guarded, 'повторный проход без изменений');

// uncomment() блока #-domain даёт рабочую директиву
$bot = (new ReflectionClass(NginxGuardTestBot::class))->newInstanceWithoutConstructor();
preg_match('~#-domain.+?#-domain~s', $guarded, $m);
$open = $bot->uncomment($m[0], 'domain');
guardAssert(str_contains($open, "         location /pac {\n             $line\n"), 'после uncomment() строка защиты действующая');

// ── 2. шаблоны репозитория ───────────────────────────────────────────────────
foreach (['nginx.conf', 'nginx_default.conf'] as $name) {
    $text = file_get_contents(__DIR__ . "/../config/$name");
    guardAssert(Bot::nginxPhpMultipartGuard($text) === $text, "$name: уже защищён");
    preg_match_all('~^[ \t]*(?:#[ \t]*)?location[ \t]+(?:/pac|/tlgrm|@php)[ \t]*\{\n(.*)$~m', $text, $m);
    guardAssert(count($m[1]) >= 3, "$name: найдены location PHP");
    foreach ($m[1] as $next) guardAssert(str_contains($next, $line), "$name: первая строка location PHP — защита");
}

// Хэш бота меняется при переустановке: замена из cloakNginx() с любым хэшем
// сохраняет все строки защиты, а миграция их не удваивает.
$template = file_get_contents(__DIR__ . '/../config/nginx_default.conf');
foreach ([bin2hex(random_bytes(4)), bin2hex(random_bytes(4))] as $h) {
    $installed = preg_replace('~(/webapp|/pac|/adguard|/ws|/grpc|/v2ray|location /dns-query)~', '${1}' . $h, $template);
    guardAssert(str_contains($installed, "location /pac$h {\n            $line\n"), "хэш $h: /pac$h защищён после cloakNginx()");
    guardAssert(substr_count($installed, Bot::NGINX_PHP_GUARD) === 5, "хэш $h: все строки защиты на месте");
    guardAssert(Bot::nginxPhpMultipartGuard($installed) === $installed, "хэш $h: миграция ничего не добавляет");
    guardAssert(Bot::nginxPhpMultipartGuard(str_replace("            $line\n", '', $installed)) === $installed, "хэш $h: снятая защита возвращается миграцией");
}

// ── 3. cron дописывает защиту в старую установку ─────────────────────────────
$dir = sys_get_temp_dir() . '/nginx-guard-' . bin2hex(random_bytes(4));
mkdir($dir, 0700);
$oldLogs = <<<'NGX'
log_format custom '$status "$http_user_agent"';
log_format noargs '$status $body_bytes_sent "$http_user_agent"';
log_format nopath '$remote_addr [$time_local] "$request_method" '
                  '$status $body_bytes_sent "$http_user_agent"';
NGX;
$sample = $oldLogs . "\n" . $sample;
$guarded = str_replace('$body_bytes_sent "$http_user_agent"', '$body_bytes_sent', $oldLogs) . "\n" . $guarded;
file_put_contents("$dir/nginx_default.conf", $sample);
file_put_contents("$dir/nginx.conf", $sample);
$bot->xrayConf = "$dir/xray.json";
guardAssert($bot->ensureNginxPhpMultipartGuard(), 'миграция прошла');
guardAssert(file_get_contents("$dir/nginx_default.conf") === $guarded, 'шаблон защищён');
guardAssert(file_get_contents("$dir/nginx.conf") === $guarded, 'рабочий nginx.conf защищён');
$cmds = implode("\n", array_column($bot->commands, 1));
guardAssert(str_contains($cmds, 'nginx -t -c') && str_contains($cmds, 'nginx -s reload'), 'nginx.conf проверен nginx -t и перечитан');
guardAssert(array_unique(array_column($bot->commands, 0)) === ['ng'], 'команды только в контейнер ng');
$bot->commands = [];
guardAssert($bot->ensureNginxPhpMultipartGuard() && $bot->commands === [], 'защищённая установка: без команд nginx');
array_map('unlink', glob("$dir/*"));
@unlink("$dir/nginx.lock");
rmdir($dir);

if ($failed) {
    echo "nginx_php_guard_test FAILED: $failed\n";
    exit(1);
}
echo "nginx_php_guard_test OK\n";
