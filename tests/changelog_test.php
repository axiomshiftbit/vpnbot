<?php
// Changelog: история своего репозитория вместо устаревшего файла version; доступ по ключу администратора.
require_once __DIR__ . '/../app/bot.php';
set_error_handler(static function ($level, $message, $file, $line) { if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line); return true; });

$checks = 0;
function check(bool $condition, string $label): void { global $checks; $checks++; if (!$condition) { fwrite(STDERR, "FAIL: $label\n"); exit(1); } }
function sh(string $command): string { exec($command . ' 2>&1', $out, $code); if ($code !== 0) throw new RuntimeException($command . "\n" . implode("\n", $out)); return implode("\n", $out); }

class ChangelogBot extends Bot
{
    public function __construct(string $language = 'ru')
    {
        $this->key = '123456:TEST-KEY';
        $this->ip = '203.0.113.9';
        $this->language = $language;
        require __DIR__ . '/../app/i18n.php';
        $this->i18n = $i;
    }
    public function getPacConf() { return ['domain' => 'vpn.example.org', 'hashbot' => 'abcd1234']; }
}

$root = sys_get_temp_dir() . '/vpnbot-changelog-' . bin2hex(random_bytes(6));
register_shutdown_function(static fn() => exec('rm -rf ' . escapeshellarg($root)));
mkdir($root);
// gc.auto=0 и maintenance.auto=false обязательны: тест делает десятки коммитов
// подряд, а git после части из них запускает фоновую упаковку объектов. Она
// шла одновременно со следующим коммитом, и тот изредка падал с «bad tree
// object HEAD» (прогон 38469252248, alpine 85) — без всякой связи с кодом.
$git = static fn(string $dir, string $args) => sh('git -C ' . escapeshellarg($dir) . ' -c user.name=t -c user.email=t@example.org -c commit.gpgsign=false -c gc.auto=0 -c maintenance.auto=false ' . $args);
$commit = static function (string $dir, string $subject, string $date) use ($git): void {
    file_put_contents("$dir/file.txt", $subject . "\n", FILE_APPEND);
    $git($dir, 'add -A');
    sh('GIT_AUTHOR_DATE=' . escapeshellarg("$date 12:00:00 +0000") . ' GIT_COMMITTER_DATE=' . escapeshellarg("$date 12:00:00 +0000")
        . ' git -C ' . escapeshellarg($dir) . ' -c user.name=t -c user.email=t@example.org -c commit.gpgsign=false -c gc.auto=0 -c maintenance.auto=false commit -q -m ' . escapeshellarg($subject));
};
sh('git init -q -b dev ' . escapeshellarg("$root/origin"));
file_put_contents("$root/origin/version", "27.03.2026 v2.30\n- старая запись исходного проекта\n");
$commit("$root/origin", 'feat: первое изменение', '2026-10-01');
$commit("$root/origin", 'fix: второе <b>изменение</b> & co', '2026-10-02');
sh('git clone -q ' . escapeshellarg("$root/origin") . ' ' . escapeshellarg("$root/server"));

$bot = new ChangelogBot();

// --- установлено то же, что в ветке
$text = $bot->changelogBuild("$root/server");
$head = trim($git("$root/server", 'rev-parse --short HEAD'));
check(str_starts_with($text, "vpnbot · ветка dev\nУстановлено: $head · 2026-10-02\nУстановленная версия совпадает с веткой.\n"), 'header names the branch and the installed commit');
check(!str_contains($text, 'ЕЩЁ НЕ УСТАНОВЛЕНО'), 'nothing is pending when the branch is installed');
check(strpos($text, '2026-10-02  fix: второе <b>изменение</b> & co') < strpos($text, '2026-10-01  feat: первое изменение'), 'installed changes are listed newest first, subjects as written');
check(str_ends_with($text, "ВЕРСИИ ИСХОДНОГО ПРОЕКТА\n27.03.2026 v2.30\n- старая запись исходного проекта\n"), 'the original version list is kept at the end');

// --- в ветке появились изменения, которых нет на сервере
$commit("$root/origin", 'feat(ovpn): новое в ветке', '2026-10-05');
$commit("$root/origin", 'fix(xdrive): ещё новее', '2026-10-06');
$text = $bot->changelogBuild("$root/server");
$remote = trim($git("$root/origin", 'rev-parse --short HEAD'));
check(str_contains($text, "Установлено: $head · 2026-10-02\nВ ветке: $remote · 2026-10-06\n"), 'the page fetches the branch itself and shows both commits');
check(str_contains($text, "ЕЩЁ НЕ УСТАНОВЛЕНО (2)\n") && str_contains($text, 'придут со следующим обновлением'), 'pending changes are counted and explained');
$pending = substr($text, strpos($text, 'ЕЩЁ НЕ УСТАНОВЛЕНО'), strpos($text, 'УСТАНОВЛЕННЫЕ ИЗМЕНЕНИЯ') - strpos($text, 'ЕЩЁ НЕ УСТАНОВЛЕНО'));
$installed = substr($text, strpos($text, 'УСТАНОВЛЕННЫЕ ИЗМЕНЕНИЯ'));
check(str_contains($pending, '2026-10-06  fix(xdrive): ещё новее') && str_contains($pending, '2026-10-05  feat(ovpn): новое в ветке') && !str_contains($pending, 'первое изменение'), 'pending section holds only what is not installed');
check(!str_contains($installed, 'новое в ветке') && str_contains($installed, 'первое изменение'), 'installed section holds only what is installed');

// --- сервер обновился
$git("$root/server", 'merge -q --ff-only origin/dev');
$text = $bot->changelogBuild("$root/server");
check(str_contains($text, "Установлено: $remote · 2026-10-06\nУстановленная версия совпадает с веткой.") && !str_contains($text, 'ЕЩЁ НЕ УСТАНОВЛЕНО'), 'after the update nothing is pending');

// --- длинная история обрезается
for ($n = 0; $n < 70; $n++) $commit("$root/server", "chore: шаг $n", '2026-10-07');
$text = $bot->changelogBuild("$root/server");
check(substr_count($text, '  chore: шаг ') === 60 && str_contains($text, 'chore: шаг 69') && !str_contains($text, 'chore: шаг 9' . "\n"), 'only the latest 60 installed changes are shown');

// --- английский
check(str_starts_with((new ChangelogBot('en'))->changelogBuild("$root/server"), "vpnbot · branch dev\nInstalled: "), 'English version');

// --- без git: прежний список версий, без ошибок
mkdir("$root/plain");
file_put_contents("$root/plain/version", "v1\n- запись\n");
check($bot->changelogBuild("$root/plain") === "v1\n- запись", 'no repository: the plain version list');
check($bot->changelogBuild("$root/missing") === '', 'no directory: empty, not an error');
sh('git init -q -b ' . escapeshellarg('we$ird;name') . ' ' . escapeshellarg("$root/odd"));
file_put_contents("$root/odd/version", "v2\n");
check($bot->changelogBuild("$root/odd") === 'v2', 'a branch name with shell characters is never put on a command line');

// --- ключ и ссылка
$key = $bot->changelogKey();
check(preg_match('~^[0-9a-f]{32}$~D', $key) === 1 && $key === (new ChangelogBot())->changelogKey(), 'the key is stable for the same bot');
$other = new ChangelogBot(); $other->key = '654321:OTHER';
check($other->changelogKey() !== $key && !str_contains($key, 'TEST') && $key !== substr(hash('sha256', $bot->key), 0, 32), 'the key differs per bot and is not the bot token or the public hash');
check($bot->changelogUrl() === "https://vpn.example.org/pacabcd1234?t=changelog&k=$key", 'admin buttons carry the key');
$source = file_get_contents(__DIR__ . '/../app/bot.php');
check(substr_count($source, "'web_app' => ['url' => \$this->changelogUrl()]") === 3 && !str_contains($source, '?t=changelog"'), 'all three changelog buttons use the keyed link');

// --- страница: история только с ключом
$index = file_get_contents(__DIR__ . '/../app/index.php');
$case = substr($index, strpos($index, "case 'changelog':"), 4500);
check(str_contains($case, "\$admin = is_string(\$_GET['k'] ?? null) && hash_equals(\$bot->changelogKey(), \$_GET['k']);"), 'the key is compared in constant time and must be a string');
check(preg_match('~if \(\$admin\) \{\s+\$log = \$bot->changelogBuild\(\);\s+\} else \{~', $case) === 1, 'commit history is built only for the admin key');
check(str_contains($case, "(\$admin ? '|admin' : '')"), 'admin and public answers never share a cache file');
check(strpos($case, "\$bot->subRateLimit('', 'changelog');") < strpos($case, 'changelogBuild()'), 'the rate limit still applies before any git work');
check(str_contains($case, "header('X-Content-Type-Options: nosniff');") && str_contains($case, "text/plain"), 'commit subjects are served as plain text');

echo "changelog: $checks checks passed\n";
