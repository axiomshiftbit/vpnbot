<?php

/**
 * Сторож к регрессии a8a5550: writeXrayJson() писал «tmp + rename», а
 * config/xray.json прокинут в контейнер xray ОТДЕЛЬНЫМ файловым bind-mount'ом
 * (config/xray.json → /xray.json). Файловый mount держит inode, поэтому после
 * первого же rename() контейнер навсегда оставался на конфиге, замороженном в
 * момент своего старта: restartXray() исправно писал новый файл на хосте, а
 * `xray run -config /xray.json` поднимался на старом — без клиентов и не с тем
 * транспортом. Снаружи это выглядело как «заглушка не открывается и никто не
 * подключается», а лечилось только пересозданием контейнеров.
 *
 * Отсюда два инварианта:
 *   1) writeXrayJson() не меняет inode файла;
 *   2) читатель никогда не видит файл наполовину — запись под LOCK_EX,
 *      чтение (getXray/readXrayJson) под LOCK_SH.
 */

require_once __DIR__ . '/../app/calc.php';
require_once __DIR__ . '/../app/bot.php';

function xrayConfAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$bot = (new ReflectionClass(Bot::class))->newInstanceWithoutConstructor();

$dir = sys_get_temp_dir() . '/xray_conf_test_' . getmypid();
@mkdir($dir, 0700, true);
$f              = $dir . '/xray.json';
$bot->xrayConf  = $f;

// ── 1. inode переживает запись ───────────────────────────────────────────────
$first = json_encode(['inbounds' => [['tag' => 'vless_tls', 'settings' => ['clients' => []]]]]);
xrayConfAssert($bot->writeXrayJson($first), 'первая запись должна пройти');
$ino = fileinode($f);
xrayConfAssert($ino !== false, 'файл должен существовать после записи');

$clients = [];
for ($i = 0; $i < 200; $i++) {
    $clients[] = ['id' => sprintf('%036d', $i), 'email' => "client-$i"];
}
$second = json_encode(['inbounds' => [['tag' => 'vless_tls', 'settings' => ['clients' => $clients]]]]);
xrayConfAssert($bot->writeXrayJson($second), 'повторная запись должна пройти');

clearstatcache(true, $f);
xrayConfAssert(
    fileinode($f) === $ino,
    'writeXrayJson() сменил inode — файловый bind-mount в контейнере xray отвалится'
);

// ── 2. содержимое доезжает целиком, в том числе через getXray() ──────────────
xrayConfAssert(file_get_contents($f) === $second, 'на диске должен лежать последний конфиг');
xrayConfAssert($bot->readXrayJson() === $second, 'readXrayJson() должен вернуть его же');
$parsed = $bot->getXray();
xrayConfAssert(is_array($parsed), 'getXray() должен разобрать конфиг в массив');
xrayConfAssert(
    count($parsed['inbounds'][0]['settings']['clients']) === 200,
    'getXray() потерял клиентов'
);

// Запись КОРОЧЕ предыдущей: без ftruncate() в файле остался бы хвост старого
// JSON, и json_decode() отдал бы null на всём конфиге.
xrayConfAssert($bot->writeXrayJson($first), 'укорачивающая запись должна пройти');
xrayConfAssert(file_get_contents($f) === $first, 'хвост предыдущей записи не обрезан');
clearstatcache(true, $f);
xrayConfAssert(fileinode($f) === $ino, 'укорачивающая запись сменила inode');

// ── 3. читатель ждёт писателя, а не ловит обрезанный файл ────────────────────
// Держим LOCK_EX и обрезаем файл в отдельном процессе: пока лок жив,
// readXrayJson() обязан блокироваться, а не прочитать пустоту.
$holder = __DIR__ . '/../.xray_conf_lock_holder.php';
file_put_contents($holder, <<<'PHP'
<?php
$h = fopen($argv[1], 'c');
flock($h, LOCK_EX);
ftruncate($h, 0);
file_put_contents($argv[1] . '.ready', '1');
usleep(400000);
rewind($h);
fwrite($h, $argv[2]);
fflush($h);
flock($h, LOCK_UN);
fclose($h);
PHP);

$proc = proc_open(
    [PHP_BINARY, $holder, $f, $second],
    [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
    $pipes
);
xrayConfAssert(is_resource($proc), 'не удалось запустить процесс-писатель');

// Ждём, пока писатель реально возьмёт лок и обрежет файл.
$deadline = microtime(true) + 5;
while (!is_file($f . '.ready') && microtime(true) < $deadline) {
    usleep(5000);
}
xrayConfAssert(is_file($f . '.ready'), 'процесс-писатель не стартовал');

$got = $bot->readXrayJson();
proc_close($proc);

xrayConfAssert(
    $got === $second,
    'readXrayJson() прочитал файл во время чужой записи — LOCK_SH не работает'
);

@unlink($f . '.ready');
@unlink($holder);
@unlink($f);
@rmdir($dir);

echo "xray_conf_inode_test: OK\n";
