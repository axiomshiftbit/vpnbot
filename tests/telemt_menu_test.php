<?php
require_once __DIR__ . '/../app/bot.php';
set_error_handler(static function ($level, $message, $file, $line) {
    if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line);
    return true;
});
class TelemtMenuBot extends Bot {
    public array $conf = [];
    public array $screen = [];
    public function __construct() { $this->key = 'fixture'; $this->ip = '203.0.113.10'; $this->input = ['chat'=>1,'message_id'=>1]; }
    public function getPacConf() { return $this->conf; }
    public function setPacConf(array $conf) { $this->conf = $conf; return true; }
    public function getWgMsg() { return null; }
    public function restartTelemt() {}
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
    public function getDomain($cdn = false) { return str_repeat('a', 60) . '.' . str_repeat('b', 60) . '.example.test'; }
    public function getPorts() { return ['telemt'=>['port'=>8443,'enable'=>true]]; }
    public function i18n(string $menu): string { return $menu; }
    public function update($chat, $message, $text, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false) { $this->screen = ['text'=>$text,'buttons'=>$button]; }
}
$bot = new TelemtMenuBot();
$bot->conf = ['telemt_domain'=>str_repeat('a',60) . '.' . str_repeat('b',60) . '.' . str_repeat('c',60) . '.example.test'];
for ($i = 0; $i < 40; $i++) $bot->conf['telemt_users']['user'.$i] = str_pad(dechex($i+1),32,'0',STR_PAD_LEFT);
$seen = []; $page = 0;
do {
    $bot->telemtUsers('', $page);
    if ($bot->messageTextLength($bot->screen['text']) > 4096) throw new RuntimeException('Меню пользователей Telemt превышает лимит Telegram');
    $next = false;
    foreach ($bot->screen['buttons'] as $row) foreach ($row as $button) {
        $callback = $button['callback_data'] ?? '';
        if (strlen($callback)>64) throw new RuntimeException('Слишком длинная кнопка Telemt');
        if (preg_match('~^/telemtToggleUser (\w+)~', $callback, $match)) $seen[] = $match[1];
        if (preg_match('~^/telemtUsersPage (\d+)$~', $callback, $match) && (int)$match[1] === $page+1) $next=true;
    }
    $page++;
} while ($next && $page<50);
if (count($seen)!==40 || count(array_unique($seen))!==40) throw new RuntimeException('Не все пользователи доступны в меню Telemt');
$bot->input += ['callback'=>'/telemtUsersPage 1','message'=>''];
$bot->action();
if (!str_contains($bot->screen['text'], '2 / ')) throw new RuntimeException('Кнопка следующей страницы не открывает страницу');
$button = null;
foreach ($bot->screen['buttons'] as $row) foreach ($row as $candidate) {
    if (str_starts_with($candidate['callback_data'] ?? '', '/telemtToggleUser ')) { $button = $candidate['callback_data']; break 2; }
}
$bot->input['callback'] = $button;
$bot->action();
if (!str_contains($bot->screen['text'], '2 / ')) throw new RuntimeException('Переключение пользователя теряет страницу');
preg_match('~^/telemtToggleUser (\w+)~', $button, $match);
if (($bot->conf['telemt_user_enabled'][$match[1]] ?? true) !== 0) throw new RuntimeException('Новая кнопка не отключает пользователя');
$bot->input['callback'] = '/telemtToggleUser ' . $match[1];
$bot->action();
if (empty($bot->conf['telemt_user_enabled'][$match[1]])) throw new RuntimeException('Старая кнопка перестала работать');
$relay = str_repeat('r', 32);
$bot->conf['telemt_relays'][$relay] = ['address'=>'relay.example.test','port'=>443];
$bot->input['callback'] = "/telemtUsersPage 1 $relay";
$bot->action();
$callback = '';
foreach ($bot->screen['buttons'] as $row) foreach ($row as $candidate) {
    if (strlen($candidate['callback_data'] ?? '') > 64) throw new RuntimeException('Кнопка с relay превышает лимит');
    if (str_starts_with($candidate['callback_data'] ?? '', '/tu t ')) $callback = $candidate['callback_data'];
}
if ($callback === '') throw new RuntimeException('Нет кнопки переключения через relay');
$bot->input['callback'] = $callback;
$bot->action();
if (!str_contains($bot->screen['text'], $relay) || !str_contains($bot->screen['text'], '2 / ')) throw new RuntimeException('Переключение теряет relay или страницу');
echo "telemt_menu_test: OK\n";
