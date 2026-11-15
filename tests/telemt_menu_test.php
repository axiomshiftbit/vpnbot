<?php
require_once __DIR__ . '/../app/bot.php';
require __DIR__ . '/../app/i18n.php';
set_error_handler(static function ($level, $message, $file, $line) {
    if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line);
    return true;
});
class TelemtMenuBot extends Bot {
    public array $conf = [];
    public array $screen = [];
    public array $qr = [];
    public int $restarts = 0;
    public int $reloads = 0;
    public function __construct(array $strings) {
        $this->key = 'fixture'; $this->ip = '203.0.113.10'; $this->i18n = $strings; $this->language = 'ru';
        $this->input = ['chat'=>1,'message_id'=>1,'callback_id'=>1,'callback'=>'','message'=>''];
    }
    public function getPacConf() { return $this->conf; }
    public function setPacConf(array $conf) { $this->conf = $conf; return true; }
    public function getWgMsg() { return null; }
    public function restartTelemt() { $this->restarts++; }
    public function cloakNginx() { $this->reloads++; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
    public function getDomain($cdn = false) { return str_repeat('a', 60) . '.' . str_repeat('b', 60) . '.example.test'; }
    public function getPorts() { return ['telemt'=>['port'=>8443,'enable'=>true]]; }
    public function telemtVersion(): string { return '3.5.9'; }
    public function telemtActivityRefresh(): void {}
    public function getTelemtActivity(): array { return ['at'=>time(), 'boot'=>0, 'users'=>[]]; }
    public function telemtQr($name, $relay = '', bool $keepMenu = false) { $this->qr[] = ['mt', $name, $relay, $keepMenu]; }
    public function telemtWebLink($name, bool $keepMenu = false) { $this->qr[] = ['web', $name, $keepMenu]; }
    public function update($chat, $message, $text, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false) { $this->screen = ['text'=>$text,'buttons'=>$button]; }
    public function click(string $callback): void { $this->input['callback'] = $callback; $this->action(); }
}
$checks = 0;
$check = static function (bool $ok, string $name) use (&$checks): void {
    $checks++; if (!$ok) throw new RuntimeException($name);
};
$callbacks = static fn(TelemtMenuBot $b): array => array_column(array_merge(...$b->screen['buttons']), 'callback_data');
$verifyScreen = static function (TelemtMenuBot $b) use ($check): void {
    $check($b->messageTextLength($b->screen['text']) <= 4096, 'Сообщение в лимите Telegram');
    foreach ($b->screen['buttons'] as $row) {
        $check(count($row) <= 2, 'Не более двух кнопок в ряд');
        foreach ($row as $button) $check(strlen($button['callback_data'] ?? '') <= 64, 'Callback в лимите 64 байт');
    }
};
$bot = new TelemtMenuBot($i);
$bot->conf = ['telemt_domain'=>str_repeat('a',60) . '.' . str_repeat('b',60) . '.' . str_repeat('c',60) . '.example.test',
    'domain' => 'vpn.example', 'tw_domain' => 'webfixture', 'letsencrypt' => 'letsencrypt', 'telemt_web' => 1];
for ($n = 0; $n < 40; $n++) $bot->conf['telemt_users']['user'.$n] = str_pad(dechex($n+1),32,'0',STR_PAD_LEFT);
$seen = [];
for ($page = 0; $page < 5; $page++) {
    $bot->click('/telemtUsersPage ' . $page); $verifyScreen($bot);
    $check(str_contains($bot->screen['text'], ($page+1) . ' / 5'), 'Пагинация списка');
    foreach ($bot->screen['buttons'] as $row) {
        $callback = $row[0]['callback_data'] ?? '';
        if (str_starts_with($callback, '/tuc ')) {
            $check(count($row) === 1, 'Имя пользователя занимает всю строку');
            $seen[] = $callback;
        }
    }
}
$check(count($seen) === 40 && count(array_unique($seen)) === 40, 'Все пользователи доступны ровно один раз');
$before = $bot->conf; $bot->click($seen[9]); $verifyScreen($bot);
$check($bot->conf === $before && $bot->restarts === 0, 'Открытие карточки не меняет доступ');
$check(str_contains($bot->screen['text'], '<b>user9</b>'), 'Карточка выбранного пользователя');
$check(str_contains($bot->screen['text'], 'tg://proxy?') && str_contains($bot->screen['text'], 'tg://webproxy?'), 'Обе ссылки видны текстом');
$urls = array_column(array_merge(...$bot->screen['buttons']), 'url');
$check(in_array($bot->linkTelemt('user9'), $urls, true) && in_array($bot->linkTelemtWeb('user9'), $urls, true), 'Обе кнопки подключения соответствуют ссылкам');
$check(end($bot->screen['buttons'])[0]['callback_data'] === '/telemtUsersPage 1', 'Возврат на исходную страницу');
$bot->click($seen[32]);
$check(!str_contains($bot->screen['text'], 'tg://webproxy?') && str_contains($bot->screen['text'], $bot->i18n('telemt web profiles capped')), '33-й пользователь получает объяснение лимита WEB');
$bot->conf['telemt_web'] = 0; $bot->click($seen[9]);
$check(!str_contains($bot->screen['text'], 'tg://webproxy?'), 'При выключенном WEB не выдаём неработающую ссылку');
$bot->conf['telemt_web'] = 1;
$relay = str_repeat('r',32);
$bot->conf['telemt_relays'][$relay] = ['address'=>'relay.example.test','portmap'=>[8443=>9443]];
for ($n=0; $n<5; $n++) $bot->conf['telemt_relays']['relay'.$n] = ['address'=>'r'.$n.'.example.test'];
$bot->click('/telemtUsersPage 1 ' . $relay); $verifyScreen($bot);
$card = $bot->telemtUserCallback('user9', 1, $relay);
$bot->click($card); $verifyScreen($bot);
$check(str_contains($bot->screen['text'], 'relay.example.test') && str_contains($bot->screen['text'], $bot->i18n('telemt web direct only')), 'MTProxy использует relay; WEB явно напрямую');
$check(str_contains($bot->screen['text'], 'tg://webproxy?'), 'WEB остаётся в карточке relay');
$oldNative = $bot->linkTelemt('user9'); $oldWeb = $bot->linkTelemtWeb('user9');
$bot->click($card . ' toggle');
$check(($bot->conf['telemt_user_enabled']['user9'] ?? true) === 0, 'Кнопка отключает правильного пользователя');
$check(str_contains($bot->screen['text'], '<b>user9</b>') && str_contains($bot->screen['text'], $bot->i18n('telemt user disabled')), 'После отключения остаёмся в карточке с предупреждением');
$check(end($bot->screen['buttons'])[0]['callback_data'] === '/telemtUsersPage 1 ' . $relay, 'Не теряем relay и страницу');
$bot->click($card . ' toggle');
$check(!empty($bot->conf['telemt_user_enabled']['user9']), 'Повторное нажатие включает доступ');
$bot->click($card . ' qr'); $bot->click($card . ' web');
$check($bot->qr === [['mt','user9',$relay,true],['web','user9',true]], 'QR получает нужного пользователя и сохраняет карточку');
$before = $bot->conf; $restarts = $bot->restarts;
$bot->click($card . ' regen');
$check($bot->conf === $before && $bot->restarts === $restarts, 'Перед ротацией есть подтверждение без изменения секрета');
$check(in_array($card . ' regen-confirm', $callbacks($bot), true), 'Подтверждение ротации доступно');
$bot->click($card . ' regen-confirm');
$check($bot->linkTelemt('user9') !== $oldNative && $bot->linkTelemtWeb('user9') !== $oldWeb, 'Ротация обновляет обе ссылки');
$check(str_contains($bot->screen['text'], '<b>user9</b>'), 'После ротации отображается та же карточка');
$card = $bot->telemtUserCallback('user9', 1, $relay);
$before = $bot->conf; $restarts = $bot->restarts;
$bot->click($card . ' delete');
$check($bot->conf === $before && $bot->restarts === $restarts, 'Удаление сначала требует подтверждения');
$bot->click($card . ' delete-confirm');
$check(!isset($bot->conf['telemt_users']['user9']) && isset($bot->conf['telemt_users']['user10']), 'Удалён только нужный пользователь');
$restarts = $bot->restarts; $before = $bot->conf;
$bot->click($card . ' toggle');
$check($bot->conf === $before && $bot->restarts === $restarts, 'Старая кнопка удалённого пользователя не меняет соседа');
$bot->conf['telemt_users']['123'] = str_repeat('b',32);
$bot->click($bot->telemtUserCallback('123'));
$check(str_contains($bot->screen['text'], '<b>123</b>'), 'Числовое имя открывает правильную карточку');
$legacy = str_repeat('legacy_',12);
$bot->conf['telemt_users'][$legacy] = str_repeat('c',32);
$bot->click($bot->telemtUserCallback($legacy, 4, $relay)); $verifyScreen($bot);
$check(str_contains($bot->screen['text'], $legacy), 'Длинное старое имя доступно без переполнения callback');
$bot->click('/telemtToggleUser user10 1');
$check(!isset($bot->conf['telemt_user_enabled']['user10']), 'Старая кнопка без identity только обновляет меню');
$bot->click('/tu t user10 1 ' . $relay);
$check(!isset($bot->conf['telemt_user_enabled']['user10']), 'Старая короткая relay-кнопка не меняет доступ');
$bot->click('/telemtUsersPage 99999'); $verifyScreen($bot);
$check(str_contains($bot->screen['text'], '6 / 6'), 'Слишком большая страница ограничена последней');
echo "telemt_menu_test: $checks проверок OK\n";
