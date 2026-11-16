<?php
// WEB-01 (аудит A): неприсвоенный бот не должен отдавать права владельца
// первому написавшему. Владелец задаётся при установке (VPNBOT_ADMIN_ID).
// Тело настоящего auth() компилируется рядом с синтетическим config.php:
// настоящий app/config.php не читается и не меняется.
require_once __DIR__ . '/../app/bot.php';

$root = sys_get_temp_dir() . '/vpnbot-auth-owner-' . bin2hex(random_bytes(6));
mkdir($root, 0700);
$failed = 0; $count = 0;
$check = static function (bool $ok, string $what) use (&$failed, &$count) { $count++; if (!$ok) { $failed++; echo "FAIL: $what\n"; } };
$ref = new ReflectionMethod(Bot::class, 'auth');
$lines = file($ref->getFileName());
$body = implode('', array_slice($lines, $ref->getStartLine() - 1, $ref->getEndLine() - $ref->getStartLine() + 1));
file_put_contents("$root/AuthFixture.php", "<?php class AuthFixture { public \$input = []; public \$admin = false;\n$body\n}\n");
require "$root/AuthFixture.php";
$log = "$root/errors.log";
ini_set('log_errors', '1'); ini_set('display_errors', '0'); ini_set('error_log', $log);
$config = static fn(array $c) => file_put_contents("$root/config.php", "<?php\n\n\$c = " . var_export($c, true) . ";\n");
$who = static function (int $from): AuthFixture { $a = new AuthFixture(); $a->input = ['from' => $from]; $a->auth(); return $a; };
try {
    // Установка без владельца: посторонний не получает прав и не записывается.
    $config(['key' => 'SYNTHETIC']);
    $check($who(111111)->admin === false, 'первый написавший не становится владельцем');
    require "$root/config.php";
    $check(empty($c['admin']), 'config.php не получает чужой ID');
    $check($who(222222)->admin === false, 'следующий пользователь тоже без прав');
    $check(str_contains((string) @file_get_contents($log), '111111'), 'журнал подсказывает ID для привязки владельца');

    // Владелец задан при установке.
    $config(['key' => 'SYNTHETIC', 'admin' => [333333]]);
    $check($who(333333)->admin === true, 'владелец из config.php проходит');
    $check($who(111111)->admin === false, 'посторонний не проходит');
    $config(['key' => 'SYNTHETIC', 'admin' => '333333']);
    $check($who(333333)->admin === true, 'строковый ID старых установок принимается');
} finally {
    exec('rm -rf ' . escapeshellarg($root));
}
echo "auth_owner_binding_test: " . ($count - $failed) . "/$count\n";
exit($failed ? 1 : 0);
