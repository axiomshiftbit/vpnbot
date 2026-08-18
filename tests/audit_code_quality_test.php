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

// ── 4. СРЕДНИЕ того же отчёта ───────────────────────────────────────────────

// Тесты должны запускаться сами: 50 файлов держались на памяти разработчика —
// ни CI, ни makefile, ни readme их не знали.
$mk = (string) file_get_contents(__DIR__ . '/../makefile');
cqAssert((bool) preg_match('~^test:~m', $mk), 'в makefile есть цель test');
cqAssert(str_contains($mk, 'tests/*_test.php'), 'цель test гоняет весь каталог');
cqAssert(is_file(__DIR__ . '/../.github/workflows/tests.yml'), 'есть workflow с тестами');
$ci = (string) file_get_contents(__DIR__ . '/../.github/workflows/tests.yml');
cqAssert(str_contains($ci, 'php -l'), 'CI прогоняет линтер');
cqAssert(str_contains($ci, 'tests/*_test.php'), 'CI прогоняет тесты');
// images.yml триггерится только на dockerfile/.env/compose — на правки PHP он
// не запускается, поэтому workflow отдельный.
cqAssert(!preg_match("~paths:~", substr($ci, 0, strpos($ci, 'jobs:'))),
    'workflow тестов не ограничен путями: он должен срабатывать на любой push');

// Герметичность прогона.
cqAssert((bool) preg_match('~public \$denyConf~', $src),
    'путь /config/deny вынесен в свойство: прогон внутри контейнера перезаписывал боевой список');
cqAssert(!str_contains($src, "file_put_contents('/config/deny'"),
    'захардкоженного пути в syncDeny не осталось');
cqAssert((bool) preg_match('~public \$xrayLog~', $src),
    'путь access-лога xray тоже свойство');
$cron = (string) file_get_contents(__DIR__ . '/audit_cron_test.php');
cqAssert(str_contains($cron, '$bot->denyConf = sys_get_temp_dir()'),
    'тест cron подменяет путь, а не пишет в /config');
$on = (string) file_get_contents(__DIR__ . '/online_ips_test.php');
cqAssert(!str_contains($on, "!is_file('/logs/xray')"),
    'online_ips_test больше не требует отсутствия боевого лога');

// Мёртвые тумблеры *Outbound: ключи никто не читал, кнопок не было.
foreach (['appOutbound', 'domainsOutbound', 'finalOutbound', 'processOutbound'] as $fn) {
    cqAssert(!str_contains($src, "public function $fn("), "мёртвый тумблер $fn удалён");
    cqAssert(!str_contains($src, "/$fn\$~"), "роут /$fn удалён");
}
cqAssert(str_contains($src, 'public function mainOutbound('),
    'рабочий mainOutbound (у него есть кнопка) остался');

// blinkmenu: режим существовал в коде, включить его было нечем.
cqAssert(str_contains($src, '"/blinkmenuswitch"'), 'кнопка переключения blinkmenu вернулась в меню');
cqAssert(substr_count($src, "getPacConf()['blinkmenu']")
    === substr_count($src, "getPacConf()['blinkmenu'] ?? false"),
    'все читатели флага идут через ?? false, а не голым чтением ключа');

// listPac и createConfig: чтение отсутствующих ключей.
cqAssert(!preg_match("~\\\$domains = \\\$this->getPacConf\(\)\[\\\$type\];~", $src),
    'listPac читает список через ?? []');
cqAssert(!preg_match("~\\\$peer\['# PublicKey'\] \?~", $src),
    "createConfig проверяет '# PublicKey' через empty(): у включённого пира ключа нет");

// Дедупликация.
cqAssert(method_exists('Bot', 'rotateRealityKeys'),
    'ротация Reality-ключей вынесена в общий метод');
cqAssert(substr_count($src, 'rotateRealityKeys(') === 3,
    'им пользуются обе ротации (regenRealityXr и regenAllXr)');
cqAssert(method_exists('Bot', 'sendChunkedLogs'), 'рассылка логов кусками вынесена в общий метод');
cqAssert(substr_count($src, 'array_chunk($v, 10)') === 0, 'копий хвоста рассылки не осталось');

// updatepac.php
$up = (string) file_get_contents(__DIR__ . '/../app/updatepac.php');
cqAssert(str_contains($up, '$tail = \'\';'),
    '$tail инициализируется: при пустом includelist и непустом reverselist читалась неопределённая переменная');
cqAssert(!preg_match("~^\s+unlink\(__DIR__~m", $up),
    'unlink() везде под проверкой существования');

// ── НИЗКИЕ того же отчёта ───────────────────────────────────────────────────

// Мёртвые методы: проверено, что нет ни определения, ни вызова.
foreach (['change_server_ip', 'isSafeExtUrl', 'getAwgVless', 'normalizeAwgForVless', 'setAsVlessTransport'] as $dead) {
    cqAssert(!str_contains($src, "public function $dead("), "мёртвый метод $dead удалён");
    cqAssert(!preg_match("~\\\$this->$dead\\(~", $src), "вызовов $dead не осталось");
}
cqAssert(!str_contains($src, "public function comment("), 'мёртвый comment() удалён');
cqAssert(str_contains($src, 'public function uncomment('),
    'парный uncomment() жив: его зовёт cloakNginx()');
// Без строк-комментариев: пояснение об удалении само упоминает имя роута.
$srcCode = implode("\n", array_filter(
    explode("\n", $src),
    static fn(string $l): bool => !preg_match('~^\s*//~', $l)
));
cqAssert(!str_contains($srcCode, '/setAsVlessTransport'), 'роут удалённого метода снят');

// Мёртвый LZW с багом KwKwK в декодере.
$up2 = (string) file_get_contents(__DIR__ . '/../app/updatepac.php');
cqAssert(!str_contains($up2, 'function elzw(') && !str_contains($up2, 'function dlzw('),
    'нерабочая реализация LZW удалена');

// Часовой пояс.
$tz = (string) file_get_contents(__DIR__ . '/../app/timezone.php');
cqAssert(str_contains($tz, "getenv('TZ') ?: 'UTC'"),
    'timezone.php не остаётся без пояса при запуске вне docker');

// Разбор расписания бэкапа и ротация без клиентов.
cqAssert(str_contains($src, "array_pad(array_values(array_filter(explode('/', \$conf['backup'] ?? ''))), 2, '')"),
    'разбор расписания переиндексирует и дополняет массив');
cqAssert((bool) preg_match("~foreach \\(\\\$x\\['inbounds'\\]\\[0\\]\\['settings'\\]\\['clients'\\] \\?\\? \\[\\] as~", $src),
    'regenAllXr переживает инбаунд без клиентов');

// Готовые ключи перевода подставлены.
cqAssert(str_contains($src, "i18n(\$update ? 'have updates' : 'no updates')"),
    'индикатор обновлений идёт через i18n, а не английской строкой в коде');
cqAssert(str_contains($src, "\$out[] = \$this->i18n('reset nginx');"),
    "'reset nginx' переводится");

if ($failed) {
    echo "audit_code_quality_test FAILED ($failed)\n";
    exit(1);
}
echo "audit_code_quality_test OK\n";
