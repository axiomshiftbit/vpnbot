<?php

// Файл паролей фейк-страницы (auth_basic на корне домена).
//
// Проверяем то, что не видно глазом и стоит дорого:
//
//  1. Без файла nginx отвечает на присланные креденшелы 403, а не 401, и пишет
//     `open() … failed` в лог. Настоящий сайт отвечает 401 повторно — значит
//     отсутствие файла само выдаёт сервер активному пробингу, ради защиты от
//     которого страница и стоит. Файл обязан появляться сам.
//  2. Чужой файл (админ положил свой пароль, чтобы открывать веб-панель)
//     трогать нельзя ни при каких обстоятельствах.
//  3. Хеш обязан быть тем, который nginx на alpine принимает, а права — теми,
//     при которых воркер nginx (uid nginx, не root) файл прочитает. Ошибка в
//     любом из двух возвращает ровно тот 403, от которого уходим.

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function hpAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

$dir = sys_get_temp_dir() . '/htpasswd_test_' . getmypid();
@mkdir($dir, 0755, true);

function hpBot(string $path): Bot
{
    $b = (new ReflectionClass(Bot::class))->newInstanceWithoutConstructor();
    $b->htpasswd = $path;

    return $b;
}

// --- 1: файла нет — создаётся ------------------------------------------------
$f = "$dir/new";
$b = hpBot($f);
hpAssert($b->ensureHtpasswd() === true, 'файла нет — метод сообщает, что создал');
hpAssert(is_file($f), 'файл появился');

$line = trim((string) file_get_contents($f));
hpAssert(substr_count($line, ':') === 1, 'ровно одна пара логин:хеш');
[$user, $hash] = explode(':', $line, 2);
hpAssert($user !== '', 'логин не пустой');

// nginx на alpine принимает bcrypt ($2y$) — проверено на живом сервере. Другие
// схемы (apr1 PHP не умеет, {SHA} слаб) сюда попасть не должны.
// Фигурные скобки обязательны: в двойных кавычках PHP считает частью имени
// переменной и байты выше ASCII, поэтому «$hash»» разобралось бы как одно имя.
hpAssert(str_starts_with($hash, '$2y$'), "хеш bcrypt, а не «{$hash}»");
hpAssert(strlen($hash) === 60, 'длина bcrypt-хеша 60 символов');

// Права: файл создаёт root, читает воркер nginx.
hpAssert((fileperms($f) & 0044) === 0044, 'файл читаем не только владельцем');

// --- 2: пароль случайный и не предсказуемый ----------------------------------
// Два подряд созданных файла обязаны различаться: одинаковый пароль на всех
// установках — это общий пароль, то есть его отсутствие.
$g = "$dir/second";
hpBot($g)->ensureHtpasswd();
hpAssert(file_get_contents($f) !== file_get_contents($g), 'два вызова дают разные хеши');

// Пароль не должен утечь рядом с файлом — в каталоге ровно то, что создано.
hpAssert(count(array_diff(scandir($dir), ['.', '..'])) === 2,
    'метод не оставляет побочных файлов с паролем');

// --- 3: существующий файл неприкосновенен ------------------------------------
$own = "$dir/own";
file_put_contents($own, "admin:\$2y\$10\$ownownownownownownownownownownownownownownownownownownow\n");
$before = file_get_contents($own);
$b = hpBot($own);
hpAssert($b->ensureHtpasswd() === false, 'файл на месте — метод ничего не делает');
hpAssert(file_get_contents($own) === $before, 'чужой пароль не перезаписан');

// --- 4: пустой файл считается отсутствующим ----------------------------------
// Пустым он может стать только от оборванной записи; nginx на нём отвечает 401,
// но пускать внутрь всё равно нечем — пересоздаём.
$empty = "$dir/empty";
touch($empty);
hpAssert(hpBot($empty)->ensureHtpasswd() === true, 'пустой файл пересоздаётся');
// clearstatcache обязателен: filesize() кеширует stat, а ноль туда положила
// сама ensureHtpasswd() своей проверкой перед записью. На PHP 8.4 кеш этого
// пути сбрасывается записью, на 8.3 (раннер CI) — нет, и тест видел прежний
// ноль. Проверяем размер на диске, а не в кеше.
clearstatcache(true, $empty);
hpAssert(filesize($empty) > 0, 'после пересоздания файл не пуст');

// --- 5: недоступный путь не роняет cron --------------------------------------
// Каталога нет — запись провалится. Шаг обязан вернуть false и жить дальше:
// он крутится в общем цикле cron рядом с продлением сертификатов и бэкапом.
$b = hpBot("$dir/nope/deeper/.htpasswd");
hpAssert($b->ensureHtpasswd() === false, 'недоступный путь — false, без исключения');

// --- 6: шаг зарегистрирован в cron -------------------------------------------
// Метод, который никто не зовёт, — это отсутствующий метод.
$src = file_get_contents(__DIR__ . '/../app/bot.php');
hpAssert(str_contains($src, "'ensureHtpasswd',"), 'ensureHtpasswd в списке шагов cron');

// Уборка.
foreach (glob("$dir/*") as $tmp) {
    @unlink($tmp);
}
@rmdir($dir);

if ($failed) {
    echo "htpasswd_test FAILED: $failed\n";
    exit(1);
}
echo "htpasswd_test OK\n";
