<?php

// Периодика: таймеры, расписания сброса, списки IP и хранилище HWID.
// Регрессии из аудита 2026-08-12 (раздел «cron / HWID / логи»):
//  - timerClient(): нераспознанный ввод давал 1970-01-01, и клиент выключался
//    в ближайшие 10 секунд;
//  - allowIp()/delAdmin(): unset($arr[array_search(...)]) при промахе удалял
//    элемент [0] — в delAdmin это ГЛАВНЫЙ администратор;
//  - checkResetXrayStats(): «1 month» от эпохи = 31 день, расписание съезжало;
//    а без инициализации метки первый же тик стирал всю статистику;
//  - suspicious(): O(n²) по логам, ipInRange() на каждую строку.

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function cronAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

class CronTestBot extends Bot
{
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
    {
        return 'syntax is ok';
    }

    public array $pacFake = [];
    public array $sent    = [];
    public array $hwidLog = [];

    public function getPacConf()
    {
        return $this->pacFake;
    }

    public function setPacConf(array $conf)
    {
        $this->pacFake = $conf;
        return true;
    }

    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false)
    {
        $this->sent[] = $text;
        return ['result' => ['message_id' => 1]];
    }

    public function menu($type = false, $arg = false, $return = false)
    {
        return null;
    }

    public function denyList($page = 0, $white = 0)
    {
        return null;
    }

    // Отрисовка меню к делу не относится и требует живого окружения.
    public function xray($page = 0)
    {
        return null;
    }

    public function resetXrStats($nomenu = false)
    {
        $this->resetCalls++;
    }

    public int $resetCalls = 0;
}

$bot = (new ReflectionClass(CronTestBot::class))->newInstanceWithoutConstructor();
$bot->input = ['chat' => 1, 'message_id' => 2];

// ── 1. lastScheduled: календарные периоды не съезжают ───────────────────────
$jan1 = strtotime('2026-01-01 00:00:00');
$feb2 = strtotime('2026-02-02 12:00:00');
$mar2 = strtotime('2026-03-02 12:00:00');
$may2 = strtotime('2026-05-02 12:00:00');
cronAssert(date('Y-m-d', Bot::lastScheduled($jan1, '1 month', $feb2)) === '2026-02-01',
    'февраль: ' . date('Y-m-d', Bot::lastScheduled($jan1, '1 month', $feb2)));
cronAssert(date('Y-m-d', Bot::lastScheduled($jan1, '1 month', $mar2)) === '2026-03-01',
    'март не съехал на 04.03: ' . date('Y-m-d', Bot::lastScheduled($jan1, '1 month', $mar2)));
cronAssert(date('Y-m-d', Bot::lastScheduled($jan1, '1 month', $may2)) === '2026-05-01',
    'май не съехал на 02.05: ' . date('Y-m-d', Bot::lastScheduled($jan1, '1 month', $may2)));
// Периоды фиксированной длины считаются как раньше.
cronAssert(Bot::lastScheduled($jan1, '1 day', $jan1 + 86400 * 3 + 60) === $jan1 + 86400 * 3,
    'суточное расписание');
cronAssert(Bot::lastScheduled($jan1, '1 day', $jan1 - 10) === 0, 'до старта расписание не наступило');
cronAssert(Bot::lastScheduled(0, '1 day', $jan1) === 0, 'без старта — 0');
cronAssert(Bot::lastScheduled($jan1, 'ерунда', $may2) === 0, 'неразбираемый период — 0');

// ── 2. Включение месячного сброса не стирает статистику ─────────────────────
$bot->pacFake = [];
$bot->switchMonthlyStats();
cronAssert(!empty($bot->pacFake['reset_monthly']), 'тумблер включён');
cronAssert(!empty($bot->pacFake['last_reset_xray_time']), 'метка проставлена сразу');
$bot->checkResetXrayStats();
cronAssert($bot->resetCalls === 0, 'сразу после включения статистика НЕ стирается');
// Пустая метка (конфиг от прежней версии) тоже не должна означать «пора».
$bot->pacFake = ['reset_monthly' => 1];
$bot->checkResetXrayStats();
cronAssert($bot->resetCalls === 0, 'отсутствующая метка не считается просроченной');
cronAssert(!empty($bot->pacFake['last_reset_xray_time']), 'метка проставлена на месте');
// Метка из прошлого месяца — сброс происходит ровно один раз.
$bot->pacFake['last_reset_xray_time'] = strtotime('first day of last month midnight');
$bot->checkResetXrayStats();
cronAssert($bot->resetCalls === 1, 'по календарной границе сброс выполнен: ' . $bot->resetCalls);
$bot->checkResetXrayStats();
cronAssert($bot->resetCalls === 1, 'повторный тик в том же месяце не сбрасывает снова');

// ── 3. allowIp/delAdmin при промахе ничего не удаляют ───────────────────────
// Путь к /config/deny — свойство именно ради этого: allowIp() в конце
// безусловно пишет файл и дёргает `nginx -s reload`, и на dev-машине это был
// warning, а ВНУТРИ контейнера тот же прогон перезаписал бы боевой список
// блокировок и перезагрузил фронтовой nginx.
$bot->denyConf = sys_get_temp_dir() . '/deny_' . getmypid();
$bot->pacFake = ['deny' => ['1.1.1.1', '2.2.2.2']];
$bot->allowIp('9.9.9.9', 0);
cronAssert($bot->pacFake['deny'] === ['1.1.1.1', '2.2.2.2'],
    'промах не удалил первую запись: ' . json_encode($bot->pacFake['deny']));
$bot->allowIp('1.1.1.1', 0);
cronAssert(array_values($bot->pacFake['deny']) === ['2.2.2.2'],
    'найденный адрес удалён: ' . json_encode($bot->pacFake['deny']));

// ── 4. suspicious: списки исключений и фильтр «свой» ────────────────────────
$log = sys_get_temp_dir() . '/susp_' . getmypid() . '.log';
file_put_contents($log, implode("\n", [
    '10.0.0.1 - - "GET / HTTP/1.1" 200 5 0',
    '203.0.113.9 - - "GET /.env HTTP/1.1" 404 5 0',
    '198.51.100.7 - - "GET / HTTP/1.1" 200 5 0',
]) . "\n");
// Массив = список исключений: подозрителен тот, кого в нём нет.
$r = $bot->suspicious('~\.env~', $log, ['10.0.0.0/23', '198.51.100.7/32'], 'scanner');
cronAssert(array_keys($r) === ['203.0.113.9'], 'вне исключений: ' . json_encode(array_keys($r)));
// /32 из списка исключений отрабатывает так же, как подсеть.
$r = $bot->suspicious('~GET / ~', $log, ['198.51.100.7/32'], 'scanner');
cronAssert(!isset($r['198.51.100.7']), 'адрес из исключений не подозрителен');
cronAssert(isset($r['10.0.0.1']), 'адрес вне исключений подозрителен');
// Скаляр = фильтр «свой»: подозрителен тот, кто СОВПАЛ.
$r = $bot->suspicious('~200\s\d+\s0$~', $log, '198.51.100.7/32', 'reality');
cronAssert(array_keys($r) === ['198.51.100.7'], 'скалярный фильтр: ' . json_encode(array_keys($r)));
@unlink($log);

// ── 5. HWID: лимит и запись одной операцией под локом ───────────────────────
$bot->hwid = sys_get_temp_dir() . '/hwid_' . getmypid() . '.json';
@unlink($bot->hwid);
$bot->setHwidDevice('uid1', 'dev1', ['time' => 1]);
$bot->setHwidDevice('uid1', 'dev2', ['time' => 2]);
cronAssert(count($bot->getHwidDevicesByUser('uid1')) === 2, 'два устройства записаны');
// hwidUpdate отдаёт наружу результат мутатора и сохраняет изменения.
$ok = $bot->hwidUpdate(function (array &$s) {
    $s['uid1']['dev3'] = ['time' => 3];
    return 'saved';
});
cronAssert($ok === 'saved', 'результат мутатора возвращается');
cronAssert(count($bot->getHwidDevicesByUser('uid1')) === 3, 'изменение сохранено');
$bot->deleteHwidDevice('uid1', 'dev3');
cronAssert(count($bot->getHwidDevicesByUser('uid1')) === 2, 'устройство удалено');
$bot->deleteHwidUser('uid1');
cronAssert($bot->getHwidDevicesByUser('uid1') === [], 'пользователь удалён');
// Битый файл больше не значит «привязок нет»: json пишется атомарно, поэтому
// читатель видит либо старое, либо новое целиком.
$bot->setHwidDevice('uid2', 'dev1', ['time' => 1]);
// С pdo_sqlite (образ php) устройства лежат в базе: проверяем то хранилище,
// которым бот действительно пользуется.
cronAssert($bot->store() ? $bot->getHwidDevicesByUser('uid2') === ['dev1' => ['time' => 1]]
    : json_decode((string) file_get_contents($bot->hwid), true) !== null, 'на диске валидные данные');
@unlink($bot->hwid);
@unlink($bot->hwid . '.lock');

// ── 6. Список логов: только файлы, операции по имени ────────────────────────
// Раньше меню строилось прямо по scandir: в нём были «.», «..», каталог
// geodata и кэши menu_*.json, а кнопки несли ПОЗИЦИЮ — появление нового файла
// сдвигало нумерацию, и «очистить» попадало в соседний лог.
class LogsTestBot extends CronTestBot
{
    public string $dir = '';

    protected function logDirectory(): string { return $this->dir; }

}

$lb = (new ReflectionClass(LogsTestBot::class))->newInstanceWithoutConstructor();
$lb->dir = sys_get_temp_dir() . '/logs_' . getmypid();
$lb->protocolRoot = $lb->dir . '/protocols';
@mkdir($lb->dir . '/geodata', 0777, true);
file_put_contents($lb->dir . '/nginx_access', "x\n");
file_put_contents($lb->dir . '/xray', "y\n");
file_put_contents($lb->dir . '/menu_status.json', '{}');
file_put_contents($lb->dir . '/.hidden', 'z');
file_put_contents($lb->dir . '/geodata/geosite.dat', 'd');

$files = $lb->logFiles();
cronAssert($files === ['nginx_access', 'xray'], 'в списке только логи: ' . json_encode($files));
cronAssert(!in_array('geodata', $files, true), 'каталог geodata не показывается как лог');
cronAssert(!in_array('menu_status.json', $files, true), 'кэш меню не показывается как лог');
cronAssert(!in_array('.', $files, true) && !in_array('..', $files, true), 'точечные записи отсеяны');

// Имя как идентификатор устойчиво к появлению нового файла — в отличие от
// позиции в scandir.
$before = array_search('xray', $lb->logFiles(), true);
file_put_contents($lb->dir . '/aaa_new', 'n');
$after  = array_search('xray', $lb->logFiles(), true);
cronAssert($before !== $after, 'позиция в списке действительно съезжает от нового файла');
cronAssert(in_array('xray', $lb->logFiles(), true), 'а имя остаётся тем же идентификатором');

array_map('unlink', glob($lb->dir . '/*.*') ?: []);
array_map('unlink', array_filter(glob($lb->dir . '/*') ?: [], 'is_file'));
@unlink($lb->dir . '/.hidden');
array_map('unlink', glob($lb->dir . '/geodata/*') ?: []);
@rmdir($lb->dir . '/geodata');
@rmdir($lb->dir);

@unlink($bot->denyConf);

if ($failed) {
    echo "audit_cron_test FAILED: $failed\n";
    exit(1);
}
echo "audit_cron_test OK\n";
