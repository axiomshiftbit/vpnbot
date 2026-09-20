<?php

// Парность «ветка кода <-> канал образов».
//
// Схема, которую проверяем: бот кнопкой пишет ветку в update/branch ->
// update/update.sh делает checkout -> scripts/sync_image_tag.sh приводит
// VPNBOT_TAG в override.env к этой ветке -> make start тянет образы из нужного
// канала. Раньше вторая половина делалась руками, и «переключил на dev и
// обновил» давало код dev с образами master.
//
// Проверяем то, что не видно глазом:
//
//  1. Соответствие master->latest / dev->dev совпадает с тем, что публикует CI
//     (.github/workflows/images.yml), И совпадает у скрипта с Bot::branchTag —
//     бот показывает пользователю ровно то, что скрипт потом поставит.
//  2. Скрипт не трогает остальные строки override.env: там лежат другие
//     настройки машины, и «синхронизация тега» не должна их стирать.
//  3. Молчит, когда менять нечего (иначе каждый рестарт слал бы отчёт), и
//     ничего не меняет на detached HEAD, где ветки нет вовсе.

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function itAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

$script = __DIR__ . '/../scripts/sync_image_tag.sh';
$dir    = sys_get_temp_dir() . '/image_tag_test_' . getmypid();

// Тестовый репозиторий: имя стартовой ветки у разных версий git разное
// (master/main), поэтому ветки заводим явно.
exec('rm -rf ' . escapeshellarg($dir));
mkdir($dir, 0755, true);
exec('git -C ' . escapeshellarg($dir) . ' init -q'
    . ' && git -C ' . escapeshellarg($dir) . ' -c user.email=t@t -c user.name=t commit -q --allow-empty -m init'
    . ' && git -C ' . escapeshellarg($dir) . ' branch -M master 2>/dev/null', $o, $rc);
itAssert($rc === 0, 'тестовый репозиторий создан');

function itRun(string $script, string $dir): array
{
    exec('bash ' . escapeshellarg($script) . ' ' . escapeshellarg($dir) . ' 2>&1', $out, $rc);

    return ['out' => trim(implode("\n", $out)), 'rc' => $rc];
}

function itTag(string $dir): ?string
{
    $f = "$dir/override.env";
    if (!is_file($f)) {
        return null;
    }

    return preg_match('~^VPNBOT_TAG=(.*)$~m', (string) file_get_contents($f), $m) ? trim($m[1]) : null;
}

// --- 1: master без override.env — файл заводится с latest ---------------------
$r = itRun($script, $dir);
itAssert($r['rc'] === 0, 'скрипт на master завершился без ошибки');
itAssert(itTag($dir) === 'latest', 'ветка master -> VPNBOT_TAG=latest');
itAssert(str_contains($r['out'], 'latest') && str_contains($r['out'], 'master'),
    'о смене канала сообщено одной строкой: ' . $r['out']);

// --- 2: повторный прогон молчит ----------------------------------------------
$r = itRun($script, $dir);
itAssert($r['out'] === '', 'менять нечего — скрипт молчит (иначе отчёт на каждом рестарте)');
itAssert(itTag($dir) === 'latest', 'повторный прогон не испортил значение');

// --- 3: переезд на dev --------------------------------------------------------
// Соседние строки кладём ДО переключения: они обязаны пережить правку тега.
file_put_contents("$dir/override.env", "TZ=Europe/Moscow\n" . file_get_contents("$dir/override.env") . "CKPORT=443\n");
exec('git -C ' . escapeshellarg($dir) . ' checkout -q -b dev');
$r = itRun($script, $dir);
itAssert(itTag($dir) === 'dev', 'ветка dev -> VPNBOT_TAG=dev');
$env = (string) file_get_contents("$dir/override.env");
itAssert(str_contains($env, 'TZ=Europe/Moscow') && str_contains($env, 'CKPORT=443'),
    'соседние настройки машины сохранены');
itAssert(substr_count($env, 'VPNBOT_TAG=') === 1, 'строка тега ровно одна, а не дописана второй');
itAssert(str_contains($r['out'], 'latest') && str_contains($r['out'], 'dev'),
    'в отчёте видны старое и новое значения: ' . $r['out']);

// --- 4: произвольная ветка — тоже канал dev (так публикует CI) ----------------
exec('git -C ' . escapeshellarg($dir) . ' checkout -q -b feature/x');
itRun($script, $dir);
itAssert(itTag($dir) === 'dev', 'ветка не master -> канал dev');

// --- 4b: пин на сборку не трогаем --------------------------------------------
// sha-<commit> в override.env — документированный откат на конкретную сборку
// (см. .env). Правило парности его не отменяет: канальные теги разъезжаются
// сами, а пин ставят руками и ровно затем, чтобы он держался.
file_put_contents("$dir/override.env", "VPNBOT_TAG=sha-deadbeef\n");
$r = itRun($script, $dir);
itAssert(itTag($dir) === 'sha-deadbeef', 'пин на сборку пережил синхронизацию');
itAssert($r['out'] === '', 'о нетронутом пине не сообщается');
// Пин снимается руками — возвращаем канальный тег для следующих проверок.
file_put_contents("$dir/override.env", "VPNBOT_TAG=dev\n");

// --- 5: detached HEAD — ветки нет, трогать нечего -----------------------------
exec('git -C ' . escapeshellarg($dir) . ' checkout -q master');
itRun($script, $dir);
itAssert(itTag($dir) === 'latest', 'вернулись на master — тег latest');
$sha = trim((string) shell_exec('git -C ' . escapeshellarg($dir) . ' rev-parse HEAD'));
exec('git -C ' . escapeshellarg($dir) . ' checkout -q ' . escapeshellarg($sha) . ' 2>/dev/null');
$r = itRun($script, $dir);
itAssert($r['out'] === '' && itTag($dir) === 'latest',
    'detached HEAD: канал не угадывается, значение не тронуто');

// --- 6: не репозиторий — молча ничего --------------------------------------
$plain = "$dir-plain";
@mkdir($plain, 0755, true);
$r = itRun($script, $plain);
itAssert($r['rc'] === 0 && $r['out'] === '' && !is_file("$plain/override.env"),
    'вне git-репозитория скрипт ничего не создаёт');

// --- 7: бот показывает то же соответствие, что ставит скрипт ------------------
itAssert(Bot::branchTag('master') === 'latest', 'Bot::branchTag(master) = latest');
itAssert(Bot::branchTag('dev') === 'dev', 'Bot::branchTag(dev) = dev');
itAssert(Bot::branchTag('feature/x') === 'dev', 'Bot::branchTag(любая другая) = dev');
itAssert(Bot::branchTag(" master \n") === 'latest', 'пробелы/перевод строки из /update/branch не ломают выбор');

// --- 8: соответствие сверено с CI, а не выдумано ------------------------------
$ci = (string) file_get_contents(__DIR__ . '/../.github/workflows/images.yml');
itAssert(str_contains($ci, "github.ref_name == 'master' && 'latest' || 'dev'"),
    'правило каналов в images.yml не изменилось (иначе править branchTag и sync_image_tag.sh)');

// --- 9: update.sh действительно зовёт скрипт ----------------------------------
// Комментарии выкидываем: в них обе строки упоминаются в обратном порядке, и
// наивный strpos по всему файлу сравнивал бы прозу, а не команды.
$up = implode("\n", array_filter(
    file(__DIR__ . '/../update/update.sh', FILE_IGNORE_NEW_LINES),
    fn($l) => !str_starts_with(ltrim($l), '#')
));
itAssert(str_contains($up, 'scripts/sync_image_tag.sh'), 'update.sh зовёт синхронизацию канала');
// Аварийный запуск прежнего дерева при отказе backup не меняет ветку/канал.
itAssert(strpos($up, 'update/sync_image_tag.sh"') < strpos($up, 'start_out=$(make start'),
    'синхронизация идёт ДО make start, иначе pull образов уйдёт со старым тегом');

// --- 10: копия помощника переживает checkout чужой ветки ----------------------
// Тонкость, из-за которой переезд dev -> master молча не работал бы: файл
// scripts/sync_image_tag.sh читается уже ПОСЛЕ checkout, а в ветке, куда
// переехали, его может не быть вовсе. Поэтому он копируется в update/ (каталог
// вне git) ДО git-операций, а исполняется именно копия.
itAssert(strpos($up, 'cp -f') > strpos($up, 'git checkout'),
    'копия обновляется из свежего дерева, уже после checkout');
itAssert(strpos($up, 'cp -f') < strpos($up, 'bash "$pwd/update/sync_image_tag.sh"'),
    'сначала обновляем копию, потом её же исполняем');
itAssert(strpos($up, 'bash "$pwd/update/sync_image_tag.sh"') > strpos($up, 'git checkout'),
    'исполняется копия из update/, уже после checkout');
$ignore = (string) file_get_contents(__DIR__ . '/../.gitignore');
itAssert(preg_match('~^update/\*$~m', $ignore) === 1,
    'каталог update/ вне git — иначе копию снесло бы `git clean -fd`');

exec('rm -rf ' . escapeshellarg($dir) . ' ' . escapeshellarg($plain));

echo $failed ? "image_tag_test FAILED ($failed)\n" : "image_tag_test OK\n";
exit($failed ? 1 : 0);
