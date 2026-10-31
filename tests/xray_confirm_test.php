<?php

// Подтверждение ротаций Xray: «ротация всего», «pbk+sid», «новый clientID»,
// «сменить ссылку подписки» и «сменить ссылки подписок» (у всех).
// Первое нажатие показывает, что произойдёт, и только «Подтвердить»
// выполняет действие. Для одного пользователя в кнопку вшит его отпечаток:
// если номер стал указывать на другого, действие не выполняется.

require_once __DIR__ . '/../app/bot.php';
require __DIR__ . '/../app/i18n.php';

set_error_handler(static function ($level, $message, $file, $line) {
    if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line);
    return false;
});

$checks = 0;
function cfCheck(bool $ok, string $label): void
{
    global $checks;
    if (!$ok) throw new RuntimeException($label);
    $checks++;
}

class ConfirmBot extends Bot
{
    public array $done = [], $screen = [], $answers = [];
    public array $xr = ['inbounds' => [['settings' => ['clients' => [
        ['email' => 'alice', 'id' => '11111111-1111-4111-8111-111111111111'],
        ['email' => 'Боб <b>', 'id' => '22222222-2222-4222-8222-222222222222'],
    ]]]]];
    public function __construct(array $strings)
    {
        $this->i18n = $strings; $this->language = 'ru'; $this->admin = true;
        $this->input = ['chat' => 1, 'message_id' => 2, 'callback_id' => 'cb', 'callback' => '', 'message' => '', 'from' => 1];
    }
    public function getXray() { return $this->xr; }
    public function regenAllXr() { $this->done[] = 'regenAllXr'; }
    public function regenRealityXr() { $this->done[] = 'regenRealityXr'; }
    public function rotateAllSubTokens() { $this->done[] = 'rotateAllSubTokens'; }
    public function regenIdXr($i) { $this->done[] = "regenIdXr:$i"; }
    public function rotateSubToken($i) { $this->done[] = "rotateSub:$i"; }
    public function xray($page = 0) { $this->screen = ['text' => 'xray', 'buttons' => []]; }
    public function userXr($i, $back = null) { $this->screen = ['text' => "user $i", 'buttons' => []]; }
    public function answer($callback_id, $textNotify = false, $notify = false) { $this->answers[] = $textNotify; }
    public function update($chat, $message, $text, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false) { $this->screen = ['text' => $text, 'buttons' => $button]; }
    public function click(string $callback): void { $this->input['callback'] = $callback; $this->action(); }
}

$b = new ConfirmBot($i);

// ── 1. Действия над всеми: первое нажатие — только экран ───────────────────
foreach (['regenAllXr', 'regenRealityXr', 'rotateAllSubTokens'] as $action) {
    $b->done = [];
    $b->click("/$action");
    cfCheck($b->done === [], "$action: первое нажатие ничего не меняет");
    cfCheck(str_contains($b->screen['text'], $i["confirm $action"]['ru']) && str_contains($b->screen['text'], $i['confirm irreversible']['ru']), "$action: экран объясняет последствия");
    cfCheck($b->screen['buttons'][0][0]['callback_data'] === "/$action ok" && $b->screen['buttons'][1][0]['callback_data'] === '/xray', "$action: «Подтвердить» и «Отмена»");
    $b->click("/$action ok");
    cfCheck($b->done === [$action], "$action: подтверждение выполняет действие один раз");
}

// ── 2. Действия над одним пользователем ─────────────────────────────────────
foreach (['regenIdXr' => 'regenIdXr', 'rotateSub' => 'rotateSub'] as $route => $done) {
    $b->done = [];
    $b->click("/$route 1");
    cfCheck($b->done === [], "$route: первое нажатие ничего не меняет");
    $confirm = $b->screen['buttons'][0][0]['callback_data'];
    $key = $b->xrClientKey($b->xr['inbounds'][0]['settings']['clients'][1]);
    cfCheck($confirm === "/$route 1 $key" && $b->screen['buttons'][1][0]['callback_data'] === '/userXr 1', "$route: подтверждение с отпечатком, отмена — в карточку");
    cfCheck(str_contains($b->screen['text'], 'Боб &lt;b&gt;') && !str_contains($b->screen['text'], 'Боб <b>'), "$route: имя экранировано");
    $b->click($confirm);
    cfCheck($b->done === ["$done:1"], "$route: подтверждение выполняет действие для того же пользователя");

    // Номер теперь указывает на другого человека (первый удалён).
    $b->done = []; $b->answers = [];
    $saved = $b->xr;
    array_splice($b->xr['inbounds'][0]['settings']['clients'], 0, 1);
    $b->xr['inbounds'][0]['settings']['clients'][] = ['email' => 'carol', 'id' => '33333333-3333-4333-8333-333333333333'];
    $b->click($confirm);
    cfCheck($b->done === [] && $b->answers === [$i['confirm stale']['ru']], "$route: устаревшее подтверждение отклонено");
    $b->xr = $saved;
    $b->click("/$route 1 00000000");
    cfCheck($b->done === [], "$route: чужой отпечаток отклонён");
    $b->click("/$route 9");
    cfCheck($b->done === [] && $b->screen['text'] === 'xray', "$route: несуществующий пользователь — в меню");
    $b->click("/$route 9 $key");
    cfCheck($b->done === [], "$route: подтверждение для несуществующего — ничего");
}

// После смены clientID отпечаток другой: старая кнопка подтверждения недействительна.
$old = $b->xrClientKey($b->xr['inbounds'][0]['settings']['clients'][0]);
$b->xr['inbounds'][0]['settings']['clients'][0]['id'] = '44444444-4444-4444-8444-444444444444';
cfCheck($old !== $b->xrClientKey($b->xr['inbounds'][0]['settings']['clients'][0]), 'отпечаток зависит от clientID');

// ── 3. Пределы Telegram и тексты ────────────────────────────────────────────
$b->click('/regenIdXr 999999');
foreach (['/regenIdXr 999999 abcdef12', '/rotateSub 999999 abcdef12', '/rotateAllSubTokens ok', '/regenRealityXr ok'] as $cb) cfCheck(strlen($cb) <= 64, "callback ≤ 64: $cb");
foreach (['confirm yes', 'cancel', 'confirm stale', 'confirm irreversible', 'confirm regenAllXr', 'confirm regenRealityXr', 'confirm regenIdXr', 'confirm rotateSub', 'confirm rotateAllSubTokens'] as $key) {
    cfCheck(preg_match('~[А-Яа-я]~u', $i[$key]['ru']) && !preg_match('~[А-Яа-я]~u', $i[$key]['en']), "перевод: $key");
}
$src = (string) file_get_contents(__DIR__ . '/../app/bot.php');
foreach (['/regenAllXr', '/regenRealityXr', '/rotateAllSubTokens'] as $cb) {
    cfCheck(!preg_match('~\'callback_data\'\s*=>\s*"' . preg_quote($cb, '~') . ' ok"~', $src), "в меню нет прямой кнопки $cb ok");
}

echo "xray_confirm_test OK ($checks проверок)\n";
