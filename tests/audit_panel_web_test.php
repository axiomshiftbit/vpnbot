<?php

// СРЕДНИЕ отчёта AUDIT-2026-08-18-02-panel-web.md.
//
// 1. /webapp<hash>/ и location / смотрят в ОДИН каталог (app/webapp), но
//    basic-auth стоит только на втором: GET /webapp<hash>/.htpasswd отдавал
//    файл паролей фейк-страницы целиком, а <hash> есть в каждой ссылке
//    подписки.
// 2. /pac<hash>?t=changelog запускает `git fetch` без лимита и без блокировки:
//    сотня параллельных запросов = форк-бомба из git-процессов и исчерпание
//    воркеров unit, то есть остановка выдачи подписок и вебхука.
// 3. subDomain() принимала ЛЮБОЙ синтаксически валидный домен из ?cdn= или
//    Host — чужой домен уезжал в rule-providers, DoH и ссылку самообновления
//    подписки жертвы (проверяется в audit_sub_ratelimit_test).
// 4. Cookie «c» для /adguard<hash>/ выдавалась без флагов, а сама админка
//    какое-то время работала вообще без пароля (в шаблоне он пуст).

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function pwAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

// ── 1. Точечные файлы ───────────────────────────────────────────────────────
foreach (['nginx.conf', 'nginx_default.conf'] as $name) {
    $conf = (string) file_get_contents(__DIR__ . '/../config/' . $name);
    pwAssert(substr_count($conf, 'location ~ /\.') === 3,
        "$name: dotfiles закрыты на IP, основном домене и TeleMT");
    pwAssert(str_contains($conf, "location ~ /\\. {\n            deny all;"),
        "$name: dotfiles закрыты deny all");
    // Только ACME-подкаталог публичен на :80; произвольное вхождение
    // .well-known в имени файла не должно открывать остальной /certs.
    pwAssert(str_contains($conf, 'location ^~ /.well-known/acme-challenge/'),
        "$name: ACME-челлендж остаётся доступным certbot");
    pwAssert(!str_contains($conf, 'location ~\.well-known'),
        "$name: широкого совпадения .well-known больше нет");
    // Файл паролей по-прежнему лежит там, где его ждёт nginx.
    pwAssert(str_contains($conf, 'auth_basic_user_file /app/.htpasswd;'),
        "$name: путь к .htpasswd не тронут");
}

// ── 2. changelog ────────────────────────────────────────────────────────────
$idx = (string) file_get_contents(__DIR__ . '/../app/index.php');
// Окно в БАЙТАХ, комментарии кириллицей — по два байта на символ.
$chg = substr($idx, strpos($idx, "case 'changelog':"), 5000);
pwAssert(str_contains($chg, "subRateLimit('', 'changelog')"),
    'changelog считается лимитером (своё ведро: sid у него нет)');
pwAssert(str_contains($chg, 'LOCK_EX | LOCK_NB'),
    'параллельные запросы не плодят git fetch — неблокирующий лок');
pwAssert(strpos($chg, 'LOCK_EX | LOCK_NB') < strpos($chg, 'git -C / fetch'),
    'лок берётся до сетевой операции');
pwAssert((bool) preg_match('~!flock\(\$h, LOCK_EX \| LOCK_NB\)\) \{\s*\n\s*echo~', $chg),
    'не получивший лок отдаёт кэш, а не встаёт в очередь');

// ── 3. Пропуск в панель AdGuard ─────────────────────────────────────────────
// Раньше пропуском была cookie c = публичный hash из ссылок подписки: её мог
// выставить любой подписчик. Теперь — подписанный ключом бота токен со сроком,
// который проверяет бот через auth_request nginx (подробно — adguard_gate_test).
$src0 = (string) file_get_contents(__DIR__ . '/../app/bot.php');
$cookie = substr($src0, strpos($src0, 'public function adguardSetGateCookie('), 900);
pwAssert(str_contains($cookie, "'httponly' => true"), 'cookie пропуска недоступна скриптам страницы');
pwAssert(str_contains($cookie, "'samesite' => 'Lax'"), 'cookie не уходит с межсайтовыми запросами');
pwAssert(str_contains($cookie, "'secure' => \$secure") && str_contains($cookie, "!empty(\$_SERVER['HTTPS'])"), 'secure выставляется по факту HTTPS, а не всегда');
$check = substr($idx, strpos($idx, '/webapp$hash/check'), 900);
pwAssert(str_contains($check, 'adguardSetGateCookie($hash, Bot::ADGUARD_GATE_TTL)') && !str_contains($check, "setcookie('c', \$hash"), 'мини-приложение выдаёт подписанный пропуск, а не публичный hash');

// ── 4. Пустой пароль AdGuard ────────────────────────────────────────────────
$src = (string) file_get_contents(__DIR__ . '/../app/bot.php');
pwAssert(method_exists('Bot', 'ensureAdguardPassword'), 'шаг проверки пароля AdGuard существует');
pwAssert(str_contains($src, "'ensureAdguardPassword',"), 'шаг включён в цикл cron');
$ens = substr($src, strpos($src, 'public function ensureAdguardPassword('), 1600);
pwAssert(str_contains($ens, "!empty(\$c['users'][0]['password'])"),
    'adguardSync() дёргается только при пустом пароле, а не на каждом тике');
// В шаблоне пароль пуст — именно поэтому шаг и нужен.
$tpl = (string) file_get_contents(__DIR__ . '/../config/AdGuardHome.yaml');
pwAssert((bool) preg_match('~password:\s*$~m', $tpl),
    'контроль: в шаблоне AdGuardHome.yaml пароль действительно пуст');

if ($failed) {
    echo "audit_panel_web_test FAILED ($failed)\n";
    exit(1);
}
echo "audit_panel_web_test OK\n";
