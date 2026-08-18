<?php

// ВЫСОКИЕ отчёта AUDIT-2026-08-18-06-code-quality.md.
//
// 1. checkVersion() считал «что нового» как разницу ЧИСЛА СТРОК файла version.
//    Удалённая ветка короче локальной → отрицательная длина в array_slice (а
//    это «убрать N с конца») → откат объявлялся обновлением, и при autoupdate
//    бот откатывал сам себя. Равное число строк → разница пуста, и реальное
//    обновление терялось навсегда ($this->last уже перезаписан).
// 2. getPacConf() не давал дефолтов, а шаблон config/pac.json — это «{}»:
//    26 чтений без ?? писали в лог Undefined array key, а addSubnets()
//    падал с TypeError на implode(',', null).
// 3. Имя пользователя TeleMT не ограничивалось по длине и целиком уезжало в
//    callback_data: >64 байт → BUTTON_DATA_INVALID → меню не открывается
//    вообще, и удалить запись из бота нечем.

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function cqAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

$src = (string) file_get_contents(__DIR__ . '/../app/bot.php');

// ── 1. Поведение прежней формулы против новой ───────────────────────────────
// Фиксируем сам дефект: на укоротившемся удалённом changelog старая формула
// отдавала непустой diff (то есть «есть обновление»), новая — пустой.
$remote  = "L1\nL2\n";            // удалённая ветка короче
$local   = "L1\nL2\nL3\nL4\n";    // локальная длиннее
$oldWay  = array_slice(explode("\n", $remote), 0, count(explode("\n", $remote)) - count(explode("\n", $local)));
$newWay  = array_values(array_diff(
    array_filter(array_map('trim', explode("\n", $remote)), 'strlen'),
    explode("\n", $local)
));
cqAssert(!empty($oldWay), 'контроль: старая формула действительно видела «обновление» при откате');
cqAssert($newWay === [], 'откат больше не выглядит обновлением');

// Обратный случай: новых строк столько же, сколько было, но они другие.
$remote2 = "NEW1\nNEW2\n";
$local2  = "OLD1\nOLD2\n";
$oldWay2 = array_slice(explode("\n", $remote2), 0, count(explode("\n", $remote2)) - count(explode("\n", $local2)));
$newWay2 = array_values(array_diff(
    array_filter(array_map('trim', explode("\n", $remote2)), 'strlen'),
    explode("\n", $local2)
));
cqAssert($oldWay2 === [], 'контроль: старая формула теряла обновление при равном числе строк');
cqAssert($newWay2 === ['NEW1', 'NEW2'], 'новые строки замечены независимо от длины файла');

$check = substr($src, strpos($src, 'public function checkVersion('), 4800);
cqAssert(str_contains($check, 'array_diff('), 'checkVersion() сравнивает содержимое, а не длины');
cqAssert(!preg_match('~count\(explode\("\\\\n", \$last\)\) - count\(explode~', $check),
    'старая формула по числу строк удалена');
cqAssert(str_contains($check, 'rev-list --count HEAD..'),
    'autoupdate срабатывает, только когда удалённая ветка реально впереди');
cqAssert(strpos($check, 'rev-list --count HEAD..') < strpos($check, 'applyupdatebot()'),
    'проверка «впереди ли» стоит до самообновления');
cqAssert(str_contains($check, 'catch (\Throwable $e)'),
    'ловится Throwable: TypeError в PHP 8 — не Exception, и шаг cron падал молча');
cqAssert(substr_count($check, "exec('git -C / fetch") === 1, 'fetch не выполняется дважды');

// ── 2. Дефолты pac.json ─────────────────────────────────────────────────────
$bot = (new ReflectionClass(Bot::class))->newInstanceWithoutConstructor();
$tmp = tempnam(sys_get_temp_dir(), 'pac');
$bot->pac = $tmp;

file_put_contents($tmp, '{}');                       // ровно то, что в шаблоне
$conf = $bot->getPacConf();
cqAssert(is_array($conf), 'свежая установка: pac.json = {} даёт массив');
foreach (array_keys(Bot::PAC_DEFAULTS) as $k) {
    cqAssert(array_key_exists($k, $conf), "ключ '$k' присутствует и не даёт Undefined array key");
}
// Тот самый фатал: implode(',', null) → TypeError.
cqAssert(is_array($conf['subnets']) && implode(',', $conf['subnets']) === '',
    'addSubnets() на пустом конфиге больше не роняет воркер');
// Дефолты не должны менять поведение существующих проверок.
cqAssert(!$conf['language'] && !$conf['limitpage'] && !$conf['domain'] && !$conf['autoupdate'],
    'дефолты остаются falsy: конструкции ?: и if() работают как раньше');

file_put_contents($tmp, '{"language":"ru","limitpage":9,"subnets":["10.0.0.0/8"]}');
$conf = $bot->getPacConf();
cqAssert($conf['language'] === 'ru' && $conf['limitpage'] === 9 && $conf['subnets'] === ['10.0.0.0/8'],
    'заданные значения дефолтами не перетираются');

file_put_contents($tmp, 'не json');
cqAssert(is_array($bot->getPacConf()), 'битый pac.json не превращается в null у вызывающего');
unlink($tmp);
cqAssert(is_array($bot->getPacConf()), 'отсутствующий pac.json тоже даёт массив');

// ── 3. Длина имени TeleMT ───────────────────────────────────────────────────
$add = substr($src, strpos($src, 'public function telemtUserAdd('), 1400);
cqAssert((bool) preg_match('~strlen\(\$name\) > 2[0-9]~', $add),
    'telemtUserAdd() ограничивает длину имени, а не только набор символов');

// Худший случай по длине среди четырёх кнопок строки пользователя: у /telemtQr
// к имени приписывается ещё и имя relay (у него свой лимит 32).
$maxName = 20;
$worst   = strlen('/telemtQr ') + $maxName + 1 + 32;
cqAssert($worst <= 64, "самая длинная кнопка укладывается в лимит Telegram: $worst байт");

// Якорь — сам рендер строки пользователя (ссылка с эмодзи), а не объявление
// роута: строка «/telemtToggleUser» встречается в файле и там, и там.
$render = substr($src, strpos($src, '"🔗 $name"'), 1400);
cqAssert(str_contains($render, 'strlen($cb) <= 64'),
    'рендер отбрасывает кнопку с слишком длинным callback_data (записи, заведённые до лимита)');

if ($failed) {
    echo "audit_code_quality_test FAILED ($failed)\n";
    exit(1);
}
echo "audit_code_quality_test OK\n";
