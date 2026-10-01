<?php

require_once __DIR__ . '/../app/bot.php';

$root = sys_get_temp_dir() . '/telemt-decoy-' . bin2hex(random_bytes(6));
mkdir($root, 0755);
$bot = (new ReflectionClass(Bot::class))->newInstanceWithoutConstructor();
$html = file_get_contents(__DIR__ . '/../app/telemt-decoy/index.html');
$css = file_get_contents(__DIR__ . '/../app/telemt-decoy/loading.css');
$checks = 0;
$check = static function (bool $ok, string $message) use (&$checks): void {
    $checks++;
    if (!$ok) throw new RuntimeException($message);
};
$legacy = "<!doctype html>\n<html lang=\"en\">\n<head>\n"
    . "<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
    . "<title>It works!</title>\n</head>\n<body>\n<h1>It works!</h1>\n"
    . "<p>This is the default page for this server.</p>\n</body>\n</html>\n";
try {
    $bot->telemtDecoyDir = "$root/new/site";
    $bot->telemtWebDecoy();
    $check(file_get_contents("$root/new/site/index.html") === $html, 'новая установка получает страницу');
    $check(file_get_contents("$root/new/site/loading.css") === $css, 'CSS доступен без inline-style');
    $check((fileperms("$root/new/site/loading.css") & 0777) === 0644, 'ядро может читать CSS');
    touch("$root/new/site/index.html", 1000000000);
    $bot->telemtWebDecoy();
    clearstatcache();
    $check(filemtime("$root/new/site/index.html") === 1000000000, 'повторный запуск не переписывает HTML');
    unlink("$root/new/site/loading.css");
    $bot->telemtWebDecoy();
    $check(file_get_contents("$root/new/site/loading.css") === $css, 'потерянный CSS восстанавливается');
    file_put_contents("$root/new/site/loading.css", '/* custom style */');
    $bot->telemtWebDecoy();
    $check(file_get_contents("$root/new/site/loading.css") === '/* custom style */', 'свои стили сохраняются');

    $bot->telemtDecoyDir = "$root/legacy";
    mkdir($bot->telemtDecoyDir);
    file_put_contents("$root/legacy/index.html", $legacy);
    $bot->telemtWebDecoy();
    $check(file_get_contents("$root/legacy/index.html") === $html, 'штатная старая заглушка обновляется');
    $check(file_get_contents("$root/legacy/loading.css") === $css, 'обновление добавляет CSS');

    $bot->telemtDecoyDir = "$root/custom";
    mkdir($bot->telemtDecoyDir);
    file_put_contents("$root/custom/index.html", '<h1>Свой сайт</h1>');
    $bot->telemtWebDecoy();
    $check(file_get_contents("$root/custom/index.html") === '<h1>Свой сайт</h1>', 'свой HTML сохраняется');
    $check(!file_exists("$root/custom/loading.css"), 'свой сайт не получает лишние файлы');

    // Ошибка при публикации CSS не должна заменять рабочий HTML или оставлять
    // временные файлы в публичном snapshot-каталоге.
    $bot->telemtDecoyDir = "$root/write-failure";
    mkdir($bot->telemtDecoyDir);
    mkdir("$root/write-failure/loading.css");
    file_put_contents("$root/write-failure/index.html", $legacy);
    set_error_handler(static fn() => true);
    try {
        $failed = false;
        try { $bot->telemtWebDecoy(); } catch (RuntimeException $e) { $failed = true; }
    } finally { restore_error_handler(); }
    $check($failed, 'ошибка записи не скрывается');
    $check(file_get_contents("$root/write-failure/index.html") === $legacy, 'HTML не меняется при ошибке CSS');
    $check(glob("$root/write-failure/.decoy-*") === [], 'временные файлы убраны после ошибки');

    $bot->telemtDecoyDir = "$root/link";
    symlink("$root/custom", "$root/link");
    $failed = false;
    try { $bot->telemtWebDecoy(); } catch (RuntimeException $e) { $failed = true; }
    $check($failed, 'каталог-симлинк отвергается до записи');
    unlink("$root/link");
    mkdir("$root/link");
    symlink("$root/custom/index.html", "$root/link/index.html");
    $failed = false;
    try { $bot->telemtWebDecoy(); } catch (RuntimeException $e) { $failed = true; }
    $check($failed, 'HTML-симлинк отвергается до записи');
    $check(file_get_contents("$root/custom/index.html") === '<h1>Свой сайт</h1>', 'цель симлинка не изменена');
    echo "telemt_decoy_test OK ($checks)\n";
} finally {
    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,
        FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($files as $f) {
        if ($f->isLink() || !$f->isDir()) unlink($f->getPathname());
        else rmdir($f->getPathname());
    }
    rmdir($root);
}
