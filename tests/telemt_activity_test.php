<?php
// TeleMT: «онлайн», накопление трафика и журнал адресов (BotTelemtActivity).
// API ядра подменён снимками; настоящее ядро проверяет набор
// tests/integration/fixtures/telemt-native/probe_activity.py.
require_once __DIR__ . '/../app/bot.php';
require __DIR__ . '/../app/i18n.php';
set_error_handler(static function ($level, $message, $file, $line) {
    if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line);
    return true;
});

class TelemtActivityBot extends Bot
{
    public array $conf = [], $screen = [], $feed = [], $answers = [], $geoCalls = [];
    public string $root;
    public bool $module = true, $running = true;
    public int $fetches = 0;
    public function __construct(string $root, array $strings) {
        $this->root = $root; $this->i18n = $strings; $this->language = 'ru'; $this->admin = true;
        $this->ip = '203.0.113.10'; $this->key = 'fixture';
        $this->conf = ['telemt_users' => ['alice' => str_repeat('ab', 16), 'bob' => str_repeat('cd', 16), '<b>x</b>' => str_repeat('ef', 16), 'carol' => str_repeat('12', 16)], 'telemt_web' => 0];
        $this->input = ['chat' => 1, 'message_id' => 2, 'callback_id' => 3, 'callback' => '', 'message' => ''];
    }
    public function getPacConf() { return $this->conf; }
    public function getWgMsg() { return null; }
    public function getPorts() { return ['telemt' => ['port' => 8443, 'enable' => true]]; }
    public function protocolModuleEnabled(string $module): bool { return $this->module; }
    public function telemtServiceRunning(): bool { return $this->running; }
    public function telemtActivityPath(): string { return "$this->root/activity.json"; }
    public function telemtApiFetch(array $paths): array { $this->fetches++; return $this->feed; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
    public function getGeoCache(): array { return []; }
    public function setGeoCache(array $cache) {}
    public function geoLookup(string $ip, array &$cache, bool $cacheOnly = false): array { $this->geoCalls[] = $ip; return []; }
    public function telemtVersion(): string { return '3.5.14'; }
    public function update($chat, $message, $text, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false) { $this->screen = ['text' => $text, 'buttons' => $button]; }
    public function answer($callback_id, $textNotify = false, $notify = false) { $this->answers[] = $textNotify; }
    public function click(string $callback): void { $this->input['callback'] = $callback; $this->action(); }
}

$root = sys_get_temp_dir() . '/vpnbot-telemt-activity-' . bin2hex(random_bytes(6));
mkdir($root, 0700);
$failed = 0; $count = 0;
$check = static function (bool $ok, string $what) use (&$failed, &$count) {
    $count++;
    if (!$ok) { $failed++; echo "FAIL: $what\n"; }
};
$row = static fn(string $name, int $conns, array $active, array $recent, int $octets) => [
    'username' => $name, 'current_connections' => $conns, 'active_unique_ips_list' => $active,
    'recent_unique_ips_list' => $recent, 'total_octets' => $octets, 'links' => ['classic' => ['tg://secret-must-not-be-stored']],
];
$feed = static function (TelemtActivityBot $b, array $rows, int $boot = 1000) {
    $b->feed = ['/v1/users' => $rows, '/v1/system/info' => ['process_started_at_epoch_secs' => $boot]];
    return $b->trackTelemtOnline(true);
};
// Сдвиг часов: тест переписывает метки времени в сохранённом состоянии.
$age = static function (TelemtActivityBot $b, int $seconds) {
    $state = $b->getTelemtActivity();
    $state['at'] -= $seconds;
    foreach ($state['users'] as &$user) {
        if ($user['last']) $user['last'] -= $seconds;
        foreach ($user['ips'] as &$rec) { $rec['first'] -= $seconds; $rec['last'] -= $seconds; }
    }
    file_put_contents($b->telemtActivityPath(), json_encode($state));
};
$labels = static fn(array $screen) => array_map(static fn($r) => $r[0]['text'], $screen['buttons']);

try {
    $b = new TelemtActivityBot($root, $i);

    // ── нет данных ──────────────────────────────────────────────────────────
    $check($b->getTelemtActivity() === ['at' => 0, 'boot' => 0, 'users' => []], 'без файла состояние пустое');
    $b->feed = ['/v1/users' => null, '/v1/system/info' => null];
    $check($b->trackTelemtOnline(true) === false && !is_file($b->telemtActivityPath()), 'недоступный API ничего не пишет');
    $check($b->telemtActivityOf('alice') === null, 'пользователя без данных нет в учёте');
    $b->telemtUserCard('alice');
    $check(str_contains($b->screen['text'], $i['telemt activity none']['ru']), 'карточка объясняет отсутствие данных');
    file_put_contents($b->telemtActivityPath(), '{broken');
    $check($b->getTelemtActivity()['users'] === [], 'повреждённый файл читается как пустой');
    file_put_contents($b->telemtActivityPath(), json_encode(['users' => 'x']));
    $check($b->getTelemtActivity()['users'] === [], 'чужая структура читается как пустая');
    unlink($b->telemtActivityPath());

    // ── первый снимок: онлайн, адреса, трафик ───────────────────────────────
    $check($feed($b, [
        $row('alice', 2, ['198.51.100.1', '2001:db8::1'], ['198.51.100.1', '2001:db8::1', '198.51.100.9'], 10200),
        $row('bob', 0, [], [], 0),
        $row('ghost', 5, ['203.0.113.77'], [], 999),
    ]) === true, 'снимок принят');
    $alice = $b->telemtActivityOf('alice');
    $check($alice['conns'] === 2 && $alice['online'] === ['198.51.100.1', '2001:db8::1'] && $alice['fresh'], 'онлайн: число соединений и адреса');
    $check($alice['bytes'] === 10200 && $alice['last'] > 0, 'трафик и время последнего появления');
    $check(array_keys($alice['ips']) === ['198.51.100.1', '2001:db8::1', '198.51.100.9'], 'в журнал идут активные и недавние адреса');
    $check($alice['ips']['198.51.100.9']['count'] === 1, 'короткое подключение из окна «недавних» засчитано');
    $bob = $b->telemtActivityOf('bob');
    $check($bob['conns'] === 0 && $bob['online'] === [] && $bob['last'] === 0 && $bob['ips'] === [], 'не подключавшийся пользователь чист');
    $check($b->telemtActivityOf('ghost') === null, 'пользователь вне конфига не учитывается');
    $raw = file_get_contents($b->telemtActivityPath());
    $check(!str_contains($raw, 'secret') && !str_contains($raw, 'links') && !str_contains($raw, str_repeat('ab', 16)), 'ссылки и секреты в файл не попадают');
    $check((fileperms($b->telemtActivityPath()) & 0777) === 0600, 'файл с адресами закрыт для остальных');

    // ── накопление трафика ──────────────────────────────────────────────────
    $feed($b, [$row('alice', 2, ['198.51.100.1'], [], 15000)]);
    $check($b->telemtActivityOf('alice')['bytes'] === 15000, 'прирост счётчика прибавляется');
    $feed($b, [$row('alice', 2, ['198.51.100.1'], [], 15000)]);
    $check($b->telemtActivityOf('alice')['bytes'] === 15000, 'повторный снимок трафик не удваивает');
    $feed($b, [$row('alice', 1, ['198.51.100.1'], [], 700)], 2000);
    $check($b->telemtActivityOf('alice')['bytes'] === 15700, 'после перезапуска ядра счётчик продолжается, а не обнуляется');
    $feed($b, [$row('alice', 1, ['198.51.100.1'], [], 90000)], 3000);
    $check($b->telemtActivityOf('alice')['bytes'] === 105700, 'перезапуск с быстрым ростом: старое значение не вычитается');
    $feed($b, [$row('alice', 1, ['198.51.100.1'], [], 500)], 0);
    $check($b->telemtActivityOf('alice')['bytes'] === 106200, 'без времени запуска перезапуск виден по уменьшению счётчика');
    $feed($b, [$row('alice', 0, [], [], -5)], 0);
    $check($b->telemtActivityOf('alice')['bytes'] === 106200, 'отрицательный счётчик не уменьшает накопленное');
    // Счётчик ядра упал до нуля, значит следующие 500 байт — новый трафик.
    $feed($b, [$row('alice', 1, ['198.51.100.1'], [], 500)], 0);
    $check($b->telemtActivityOf('alice')['bytes'] === 106700, 'после сброса счётчика ядра учёт продолжается');

    // Время запуска ядра стало известно впервые — это не перезапуск.
    $state = $b->getTelemtActivity(); $state['boot'] = 0; file_put_contents($b->telemtActivityPath(), json_encode($state));
    $feed($b, [$row('alice', 1, ['198.51.100.1'], [], 500)], 7000);
    $check($b->telemtActivityOf('alice')['bytes'] === 106700 && $b->getTelemtActivity()['boot'] === 7000, 'первое известное время запуска трафик не удваивает');
    $feed($b, [$row('alice', 1, ['198.51.100.1'], [], 500)], 0);
    $check($b->getTelemtActivity()['boot'] === 7000, 'пропавшее время запуска не стирает известное');

    // ── журнал: подключения считаются по паузе, а не по опросам ──────────────
    $before = $b->telemtActivityOf('alice')['ips']['198.51.100.1']['count'];
    $feed($b, [$row('alice', 1, ['198.51.100.1'], [], 500)], 0);
    $check($b->telemtActivityOf('alice')['ips']['198.51.100.1']['count'] === $before, 'непрерывное подключение — одно');
    $age($b, 400);
    $first = $b->telemtActivityOf('alice')['ips']['198.51.100.1']['first'];
    $feed($b, [$row('alice', 1, ['198.51.100.1'], [], 500)], 0);
    $rec = $b->telemtActivityOf('alice')['ips']['198.51.100.1'];
    $check($rec['count'] === $before + 1 && $rec['first'] === $first && $rec['last'] > $first, 'появление после паузы — новое подключение, первая дата сохраняется');

    // ── отключение и свежесть ───────────────────────────────────────────────
    $feed($b, [$row('alice', 0, [], [], 500)], 0);
    $alice = $b->telemtActivityOf('alice');
    $check($alice['conns'] === 0 && $alice['online'] === [] && $alice['last'] > 0 && $alice['fresh'], 'отключившийся не в сети, время сохранено');
    $feed($b, [$row('alice', 3, ['198.51.100.1'], [], 500)], 0);
    $age($b, 120);
    $stale = $b->telemtActivityOf('alice');
    $check(!$stale['fresh'] && $stale['conns'] === 0 && $stale['online'] === [], 'устаревший снимок не выдаётся за «онлайн»');
    $check($stale['bytes'] === 106700 && $stale['ips'] !== [], 'накопленное при этом не теряется');

    // ── мусор от API ────────────────────────────────────────────────────────
    $feed($b, [
        ['username' => ['alice'], 'current_connections' => 9],
        'строка вместо записи',
        $row('bob', 1, ['not-an-ip', '198.51.100.2', '<script>', ['x'], '198.51.100.2 ', 7], ['10.0.0.1'], 100),
        ['username' => 'alice'],
    ]);
    $bob = $b->telemtActivityOf('bob');
    $check(array_keys($bob['ips']) === ['198.51.100.2', '10.0.0.1'] && $bob['online'] === ['198.51.100.2'], 'в журнал идут только корректные адреса');
    $check($b->telemtActivityOf('alice')['conns'] === 0, 'запись без полей читается как нули');

    // ── пределы хранения ────────────────────────────────────────────────────
    $many = [];
    for ($n = 1; $n <= 70; $n++) $many[] = '198.18.' . intdiv($n, 250) . '.' . ($n % 250);
    $feed($b, [$row('bob', 70, $many, [], 100)]);
    $check(count($b->telemtActivityOf('bob')['ips']) === 50, 'не больше 50 адресов на пользователя');
    $age($b, 2592000 + 60);
    $feed($b, [$row('bob', 1, ['198.51.100.200'], [], 100)]);
    $check(array_keys($b->telemtActivityOf('bob')['ips']) === ['198.51.100.200'], 'записи старше 30 дней удаляются');

    // ── пользователи: переименование, удаление, выключенный модуль ──────────
    $feed($b, [$row('bob', 1, ['198.51.100.200'], [], 100)]);
    $check($b->telemtActivityOf('alice') !== null && $b->telemtActivityOf('alice')['conns'] === 0, 'пользователь, которого ядро ещё не отдало, сохраняет накопленное');
    $b->telemtActivityForget('alice', true);
    $alice = $b->telemtActivityOf('alice');
    $check($alice['ips'] === [] && $alice['bytes'] === 106700, 'очистка журнала не трогает трафик');
    $b->telemtActivityForget('alice');
    $check($b->telemtActivityOf('alice') === null, 'удалённый пользователь забыт целиком');
    $b->telemtActivityForget('nobody');
    unset($b->conf['telemt_users']['bob']);
    $feed($b, [$row('bob', 1, ['198.51.100.200'], [], 100)]);
    $check($b->telemtActivityOf('bob') === null, 'исчезнувший из конфига пользователь исключается из учёта');
    $b->conf['telemt_users']['bob'] = str_repeat('cd', 16);
    $b->module = false; $fetches = $b->fetches;
    $check($feed($b, [$row('bob', 1, [], [], 1)]) === false && $b->fetches === $fetches, 'выключенный модуль не опрашивается');
    $b->module = true;
    $b->running = false; $fetches = $b->fetches;
    $check($feed($b, [$row('bob', 1, [], [], 1)]) === false && $b->fetches === $fetches, 'остановленный сервис не опрашивается');
    $b->running = true;
    $saved = $b->conf['telemt_users']; $b->conf['telemt_users'] = []; $fetches = $b->fetches;
    $check($feed($b, []) === false && $b->fetches === $fetches, 'без пользователей опроса нет');
    $b->conf['telemt_users'] = $saved;

    // ── частота опроса из cron ──────────────────────────────────────────────
    $b->feed = ['/v1/users' => [$row('bob', 1, ['198.51.100.200'], [], 100)], '/v1/system/info' => []];
    $b->time_telemttrack = 0; $fetches = $b->fetches;
    $b->trackTelemtOnline(); $b->trackTelemtOnline(); $b->trackTelemtOnline();
    $check($b->fetches === $fetches + 1, 'cron опрашивает ядро не чаще раза в 20 с');
    $b->time_telemttrack = time() - 21;
    $b->trackTelemtOnline();
    $check($b->fetches === $fetches + 2, 'по истечении периода опрос повторяется');

    // ── экраны ──────────────────────────────────────────────────────────────
    $feed($b, [
        $row('alice', 2, ['198.51.100.1', '2001:db8::1'], [], 5 * 1024 * 1024),
        $row('bob', 0, [], [], 0),
        $row('<b>x</b>', 1, ['198.51.100.3'], [], 2048),
        $row('carol', 0, [], [], 0),
    ], 4000);
    $fetches = $b->fetches;
    $b->telemtUsers(); $b->telemtUserCard('alice'); $b->telemtUserLog('alice');
    $check($b->fetches === $fetches, 'меню не опрашивают ядро, пока снимку меньше 5 с');
    $state = $b->getTelemtActivity(); $state['at'] -= 6; file_put_contents($b->telemtActivityPath(), json_encode($state));
    $b->telemtUsers();
    $check($b->fetches === $fetches + 1, 'устаревший снимок меню обновляет само');
    $list = $labels($b->screen);
    $check(str_contains($b->screen['text'], 'users: 4 · ' . $i['online']['ru'] . ': 2'), 'список показывает число подключённых');
    $check(str_contains($list[0], 'alice') && str_contains($list[0], '👤2') && str_contains($list[0], $b->fmtBytes(5 * 1024 * 1024)), 'кнопка: соединения и трафик');
    $check(in_array('🟢 carol', $list, true), 'не подключавшийся — без пометок');
    $check(in_array('🟢 bob · ' . $b->fmtBytes(100), $list, true), 'отключившийся — трафик без отметки подключения');
    $check(mb_strlen($list[0]) <= 64, 'подпись кнопки не длиннее прежнего предела');

    $b->telemtUserCard('alice');
    $card = $b->screen['text'];
    $check(str_contains($card, '🟢 ' . $i['online']['ru']) && str_contains($card, '<code>198.51.100.1</code>, <code>2001:db8::1</code>'), 'карточка: онлайн и адреса');
    $check(str_contains($card, $i['telemt activity traffic']['ru'] . ': ' . $b->fmtBytes(5 * 1024 * 1024)), 'карточка: трафик');
    $log = array_values(array_filter(array_merge(...$b->screen['buttons']), static fn($btn) => str_contains($btn['text'], $i['connection log']['ru'])));
    $check(count($log) === 1 && strlen($log[0]['callback_data']) <= 64, 'кнопка журнала есть и укладывается в лимит Telegram');

    $b->telemtUserCard('carol');
    $check(str_contains($b->screen['text'], '⚪ ' . $i['offline']['ru']) && !str_contains($b->screen['text'], $i['last seen']['ru']), 'карточка: не в сети, раньше не появлялся');
    $b->telemtUserCard('bob');
    $check(str_contains($b->screen['text'], '⚪ ' . $i['offline']['ru'] . ' · ' . $i['last seen']['ru'] . ': ' . date('d.m.Y')), 'карточка: не в сети, показано последнее появление');

    $b->click($log[0]['callback_data']);
    $view = $b->screen['text'];
    $check(str_contains($view, '198.51.100.1') && str_contains($view, '2001:db8::1') && str_contains($view, $i['telemt activity log note']['ru']), 'журнал открывается кнопкой и показывает адреса');
    $check(in_array('198.51.100.1', $b->geoCalls, true), 'журнал отрисован общей функцией с геоданными');
    $clear = array_values(array_filter(array_merge(...$b->screen['buttons']), static fn($btn) => str_contains($btn['text'], $i['clear log']['ru'])));
    $check(count($clear) === 1, 'у непустого журнала есть очистка');
    // Очистка не должна тут же заполнить журнал заново текущим снимком.
    $b->click($clear[0]['callback_data']);
    $check(str_contains($b->screen['text'], $i['no log']['ru']) && $b->telemtActivityOf('alice')['ips'] === [], 'журнал очищен');
    $check($b->telemtActivityOf('alice')['bytes'] === 5 * 1024 * 1024 && in_array('🗑 ' . $i['log cleared']['ru'], $b->answers, true), 'трафик сохранён, действие подтверждено');
    $check(!array_filter(array_merge(...$b->screen['buttons']), static fn($btn) => str_contains($btn['text'], $i['clear log']['ru'])), 'у пустого журнала кнопки очистки нет');

    // Имя с разметкой нигде не становится HTML.
    $b->telemtUserCard('<b>x</b>');
    $check(!str_contains($b->screen['text'], '<b>x</b></b>') && str_contains($b->screen['text'], '&lt;b&gt;x&lt;/b&gt;'), 'имя экранируется в карточке');
    $b->telemtUserLog('<b>x</b>');
    $check(!str_contains($b->screen['text'], '<b>x</b>') && str_contains($b->screen['text'], '&lt;b&gt;x&lt;/b&gt;'), 'имя экранируется в журнале');

    // Чужой и устаревший ключ кнопки не открывает и не чистит чужой журнал.
    $b->click('/tuc 000000000000 0 direct logclear');
    $check($b->telemtActivityOf('<b>x</b>')['ips'] !== [], 'неизвестный ключ ничего не очищает');
    $b->telemtUserLog('nobody');
    $check(str_contains($b->screen['text'], $i['telemt users']['ru'] ?? 'users'), 'журнал несуществующего пользователя возвращает в список');

    // Удаление пользователя стирает его учёт.
    $src = file_get_contents(__DIR__ . '/../app/bot.php');
    $del = substr($src, strpos($src, 'public function telemtDelUser('), 900);
    $check(str_contains($del, '$this->telemtActivityForget((string) $name);'), 'удаление пользователя стирает журнал и трафик');
    $check((bool) preg_match("~'trackWgOnline',\s*'trackTelemtOnline',~", $src), 'опрос включён в шаги cron');
} finally {
    foreach (glob("$root/*") as $file) unlink($file);
    rmdir($root);
}
if ($failed) exit(1);
echo "telemt_activity_test: $count OK\n";
