<?php
require_once __DIR__ . '/../app/bot.php';
require __DIR__ . '/../app/i18n.php';
set_error_handler(static function ($level, $message, $file, $line) {
    if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line);
    return true;
});
$checks = 0;
$check = static function ($ok, $message) use (&$checks) {
    $checks++;
    if (!$ok) throw new RuntimeException($message);
};
$row = ['username' => 'alice', 'sessions' => 2, 'inbound' => 1024, 'outbound' => 4096, 'ip' => '2001:db8::1'];
$stats = Bot::parseTtClientStats(json_encode([$row]));
$check($stats['alice'] === ['sessions' => 2, 'upload' => 1024, 'download' => 4096, 'ip' => '2001:db8::1'], 'Направление счётчиков: inbound — загрузка на сервер, outbound — клиенту');
foreach (['', '{}', 'null', '{', '[null]', '["oops"]', json_encode([$row, $row])] as $bad) {
    $check(Bot::parseTtClientStats($bad) === null, 'Неполный ответ не превращается в нулевой расход');
}
foreach (['sessions', 'inbound', 'outbound'] as $field) foreach ([-1, '10', 1.2, null, []] as $bad) {
    $changed = $row; $changed[$field] = $bad;
    $check(Bot::parseTtClientStats(json_encode([$changed])) === null, 'Некорректный счётчик отвергается');
}
$changed = $row; $changed['ip'] = '<b>forged</b>';
$check(Bot::parseTtClientStats(json_encode([$changed])) === null, 'IP валидируется');
$changed['ip'] = null; $changed['sessions'] = 0;
$check(Bot::parseTtClientStats(json_encode([$changed]))['alice']['ip'] === null, 'Неактивный пользователь без IP поддерживается');
$check(Bot::parseTtClientStats('[]') === [], 'Пустой список API допустим');
$old = "listen_address = \"0.0.0.0:8443\"\n[listen_protocols.http2]\nmax_concurrent_streams = 1000\n";
$new = Bot::migrateTtMetrics($old);
$check(str_starts_with($new, $old) && str_contains($new, 'address = "127.0.0.1:1987"'), 'Миграция дополняет старый конфиг локальными метриками');
$check(Bot::migrateTtMetrics($new) === $new, 'Повторная миграция идемпотентна');
foreach (["[metrics]\naddress = \"127.0.0.1:8000\"\nper_client_metrics = false\n", 'metrics = {address="127.0.0.1:8000"}', '["metrics"]'] as $manual) {
    $check(Bot::migrateTtMetrics($old . $manual) === $old . $manual, 'Ручная политика метрик сохранена');
}
class TtStatsMenuBot extends Bot
{
    public array $users = ['alice' => 'secret<&>'];
    public string $response = '';
    public array $screen = [];
    public array $commands = [];
    public bool $enabled = true;
    public function __construct(array $strings) {
        $this->i18n = $strings; $this->language = 'ru';
        $this->input = ['chat' => 1, 'message_id' => 2];
    }
    public function getClientsTt() { return $this->users; }
    public function ttDomain() { return 'vpn.example'; }
    public function getTtPort() { return 2443; }
    public function ttBlockers() { return []; }
    public function ttRunning() { return $this->enabled; }
    public function protocolModuleEnabled(string $key): bool { return $this->enabled; }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') {
        $this->commands[] = [$cmd, $service];
        if (!str_contains($cmd, 'http://127.0.0.1:1987/clients') || $service !== 'tt') throw new RuntimeException('Неожиданная команда при просмотре');
        return $this->response;
    }
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML') { $this->screen = [$text, $button]; }
}
$bot = new TtStatsMenuBot($i); $bot->response = json_encode([$row]);
$bot->ttClientMenu('alice');
$check(str_contains($bot->screen[0], 'Активные сессии: 2') && str_contains($bot->screen[0], 'Отправлено клиентом: 1.0 KB') && str_contains($bot->screen[0], 'Получено клиентом: 4.0 KB'), 'Карточка показывает настоящие поля API');
$check(str_contains($bot->screen[0], 'secret&lt;&amp;&gt;') && str_contains($bot->screen[0], 'обнуляются'), 'HTML экранируется и указан срок жизни счётчиков');
$buttons = array_column(array_merge(...$bot->screen[1]), 'callback_data');
$check(in_array('/ttClientMenu alice', $buttons, true) && in_array('/menuhelp tt 0 alice', $buttons, true), 'Доступны обновление и контекстная справка');
$menu = $bot->ttMenu();
$check(!str_contains($menu['text'], 'secret'), 'Список не раскрывает пароли');
$labels = array_column(array_merge(...$menu['data']), 'text');
$check(in_array('🟢 alice', $labels, true), 'Активная сессия отмечена');
$bot->response = 'not-json'; $bot->ttClientMenu('alice');
$check(str_contains($bot->screen[0], 'Статистика недоступна') && !str_contains($bot->screen[0], 'Получено клиентом: 0'), 'Ошибка API не маскируется под нулевой трафик');
$bot->enabled = false; $count = count($bot->commands); $bot->ttClientMenu('alice');
$check(count($bot->commands) === $count, 'Выключенный модуль не вызывает SSH');
$bot->enabled = true;
for ($n = 1; $n <= 40; $n++) $bot->users['user' . $n] = 'private';
foreach ([0 => 20, 1 => 20, 2 => 1, 999 => 1, -1 => 20] as $page => $expected) {
    $menu = $bot->ttMenu($page);
    $callbacks = array_column(array_merge(...$menu['data']), 'callback_data');
    $check(count(array_filter($callbacks, static fn($cb) => str_starts_with($cb, '/ttClientMenu '))) === $expected, 'Пагинация показывает нужную страницу');
    foreach ($callbacks as $cb) $check(strlen($cb) <= 64, 'Кнопки укладываются в Telegram callback');
}
foreach (['ru', 'en'] as $lang) {
    $bot->language = $lang;
    $check($bot->menuHelpContent('tt', 'alice')[1] === '/ttClientMenu alice', 'Справка возвращает в карточку');
    $check($bot->menuHelpContent('tt')[1] === '/menu tt', 'Общая справка возвращает в список');
}
echo "trusttunnel_stats_test OK ($checks checks)\n";
