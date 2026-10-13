<?php

// Код бота не должен звать функции расширений, которых нет в рабочем образе
// PHP. Локально и в хостовом CI они обычно есть, поэтому такой вызов проходит
// все тесты и падает фатальной ошибкой только на сервере (так ctype_digit
// едва не уехал в меню AdGuard — образ собран без ctype).
//
// Список — расширения, отсутствующие в образе: см. `php -m` в образе php.

$missing = '~(?<![\w>:$\\\\])(ctype_[a-z]+|posix_[a-z_]+|pcntl_[a-z_]+|socket_[a-z_]+|gmp_[a-z_]+|sodium_[a-z0-9_]+'
    . '|bc(?:add|sub|mul|div|mod|pow|comp|sqrt|scale)|token_get_all|token_name|simplexml_[a-z_]+|apcu_[a-z_]+|gettext|shmop_[a-z_]+)\s*\(~i';
$failed = 0;
$files  = glob(__DIR__ . '/../app/*.php') ?: [];
foreach ($files as $file) {
    // `php -w` убирает комментарии штатным разборщиком, без расширения tokenizer.
    $code = (string) shell_exec(escapeshellarg(PHP_BINARY) . ' -w ' . escapeshellarg($file) . ' 2>/dev/null');
    if ($code === '') {
        echo 'FAIL: не удалось разобрать ' . basename($file) . "\n";
        $failed++;
        continue;
    }
    // Строки в кавычках вызовами не считаются.
    $code = preg_replace('~\'(?:\\\\.|[^\'\\\\])*\'|"(?:\\\\.|[^"\\\\])*"~s', "''", $code) ?? $code;
    if (preg_match_all($missing, $code, $m)) {
        foreach (array_unique($m[1]) as $function) {
            echo 'FAIL: ' . basename($file) . " вызывает $function() — этого расширения нет в образе php\n";
            $failed++;
        }
    }
}
if (count($files) < 10) {
    echo "FAIL: файлы приложения не найдены\n";
    $failed++;
}
echo $failed ? "php_extensions_test FAILED ($failed)\n" : 'php_extensions_test OK (' . count($files) . " файлов)\n";
exit($failed ? 1 : 0);
