<?php
// Справка Hysteria: полная по меню и отдельная по тонким настройкам.
require_once __DIR__ . '/../app/bot.php';
require __DIR__ . '/../app/i18n.php';
set_error_handler(static function ($level, $message, $file, $line) { if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line); return true; });

class HyHelpBot extends Bot
{
    public array $conf = ['domain' => 'vpn.example', 'hysteria_pass' => 'shared', 'hysteria_obfs' => 'x'];
    public array $screen = [], $sent = [];
    public int $writes = 0, $restarts = 0, $ssh = 0;
    public function __construct(array $strings, string $language, string $root) {
        $this->i18n = $strings; $this->language = $language; $this->admin = true; $this->ip = '203.0.113.10';
        $this->hysteriaConf = "$root/hysteria.yaml"; $this->hysteriaUsersRoot = "$root/hysteria";
        $this->input = ['chat' => 1, 'message_id' => 2, 'callback_id' => 3, 'callback' => '', 'message' => '', 'username' => 'admin'];
    }
    public function getPacConf() { return $this->conf; }
    public function setPacConf(array $conf) { $this->writes++; $this->conf = $conf; return true; }
    public function getPorts() { return ['hy' => ['enable' => true, 'port' => 443]]; }
    public function getDomain($cdn = false) { return 'vpn.example'; }
    public function getWgMsg() { return null; }
    public function protocolModuleEnabled(string $key): bool { return true; }
    public function flagName(string $name, string|array $hosts, bool $cacheOnly = true): string { return $name; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
    public function restartHysteria() { $this->restarts++; return true; }
    public function hysteriaVersion(): string { return 'v2.13.0'; }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') { $this->ssh++; return ''; }
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML') { $this->screen = ['text' => $text, 'buttons' => is_array($button) ? $button : []]; }
    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false) { $this->sent[] = $text; return ['result' => ['message_id' => 9]]; }
    public function menu($type = false, $arg = false, $return = false) { $this->screen = ['text' => 'menu:' . $type, 'buttons' => []]; }
    public function stashReply($r, array $state) {}
    public function answer($callback_id, $textNotify = false, $notify = false) {}
    public function click(string $callback): void { $this->input['callback'] = $callback; $this->action(); }
    public function callbacks(): array { return array_column(array_merge(...$this->screen['buttons']), 'callback_data'); }
}

$root = sys_get_temp_dir() . '/vpnbot-hy-help-' . bin2hex(random_bytes(6));
mkdir($root, 0700);
$failed = 0; $count = 0;
$check = static function (bool $ok, string $what) use (&$failed, &$count) { $count++; if (!$ok) { $failed++; echo "FAIL: $what\n"; } };
// Telegram отвергает сообщение с незакрытыми или неизвестными тегами.
$balanced = static function (string $html): bool {
    preg_match_all('~<(/?)([a-z]+)[^>]*>~', $html, $m, PREG_SET_ORDER);
    $stack = [];
    foreach ($m as [$_, $close, $tag]) {
        if (!in_array($tag, ['b', 'i', 'code', 'pre'], true)) return false;
        if ($close === '') $stack[] = $tag;
        elseif (array_pop($stack) !== $tag) return false;
    }
    return !$stack && !preg_match('~<(?!/?(?:b|i|code|pre)>)~', $html);
};
try {
    $expected = ['hy' => [7, '/menu hy'], 'hy_tune' => [6, '/hyTune']];
    foreach (['ru', 'en'] as $language) {
        $b = new HyHelpBot($i, $language, $root);
        foreach ($expected as $topic => [$pages, $back]) {
            [$title, $route, $content] = $b->menuHelpContent($topic);
            $check($route === $back && count($content) === $pages && str_starts_with($title, 'Hysteria'), "$language/$topic: $pages страниц, возврат в $back");
            $b->click("/menuhelp $topic 0");
            $check(count($b->screen['buttons']) === $pages + 1 && end($b->screen['buttons'])[0]['callback_data'] === $back, "$language/$topic: оглавление и возврат");
            foreach (range(1, $pages) as $page) {
                $b->click("/menuhelp $topic $page");
                $text = $b->screen['text'];
                $check(mb_strlen($text) <= 4096, "$language/$topic/$page: укладывается в сообщение Telegram (" . mb_strlen($text) . ')');
                $check(mb_strlen($text) >= 500, "$language/$topic/$page: страница содержательна");
                $check($balanced($text), "$language/$topic/$page: разметка корректна");
                $check(in_array($back, $b->callbacks(), true) && in_array("/menuhelp $topic 0", $b->callbacks(), true), "$language/$topic/$page: есть возврат и оглавление");
                foreach ($b->callbacks() as $callback) $check(strlen($callback) <= 64, "$language/$topic/$page: callback в пределах лимита");
            }
            // Справка на языке интерфейса: те же страницы, свой текст.
            $ruContent = (new HyHelpBot($i, 'ru', $root))->menuHelpContent($topic)[2];
            $check(count($content) === count($ruContent) && ($content === $ruContent) === ($language === 'ru'), "$language/$topic: справка на языке интерфейса");
            foreach ($content as $name => $page) {
                $plain = preg_replace('~<code>.*?</code>|<[^>]+>~su', '', $page);
                $cyrillic = preg_match_all('~[А-Яа-яЁё]~u', $name . $plain);
                $check($language === 'ru' ? $cyrillic > 4 * preg_match_all('~[A-Za-z]~', $plain) : $cyrillic === 0, "$language/$topic/«{$name}»: страница на языке интерфейса");
            }
        }
        $check($b->writes === 0 && $b->restarts === 0 && $b->ssh === 0, "$language: просмотр справки ничего не меняет и не обращается к ядру");
        $check($b->menuHelpContent('hy_tune', 'main')[1] === '/hyTune' && $b->menuHelpContent('hy', 'x')[1] === '/menu hy', "$language: контекст не подменяет маршрут возврата");
    }

    // ── справка называет каждую кнопку меню и каждую настройку ───────────────
    $b = new HyHelpBot($i, 'ru', $root);
    $all = implode("\n", $b->menuHelpContent('hy')[2]);
    foreach (['Сменить пароль', 'Сгенерировать пароль', 'Персональные доступы', 'Срок', 'Квота', 'Сменить реквизиты', 'Сбросить расход', 'Календарь и уведомления',
        'Групповые действия', 'Отключить общий пароль', 'маскировка', 'custom', 'obfs', 'insecure', 'cc', 'Brutal', 'port hopping', 'nft rule', 'relay', 'Диагностика', 'config',
        'UDP', 'hysteria2://', 'Тонких настройках'] as $term) {
        $check(str_contains($all, $term), "полная справка описывает «{$term}»");
    }
    // Английская справка называет кнопки так же, как английское меню.
    $en = new HyHelpBot($i, 'en', $root);
    $allEn = implode("\n", $en->menuHelpContent('hy')[2] + $en->menuHelpContent('hy_tune')[2]);
    foreach ([$i['change password']['en'], $i['generate password']['en'], $i['masquerade']['en'], $i['hy tune']['en'], 'Personal access', 'Bulk actions',
        'Disable shared password', 'Change credentials', 'Reset usage', 'Calendar and notifications', 'Diagnostics', 'nft rule', 'Ignore client bandwidth', 'Brutal loss compensation'] as $term) {
        $check(stripos($allEn, $term) !== false, "английская справка называет «{$term}»");
    }
    $tune = implode("\n", $b->menuHelpContent('hy_tune')[2]);
    foreach (['salamander', 'gecko', '2.9.2', 'bbr-conservative', 'bbr-aggressive', 'reno', 'Компенсация потерь', 'Игнорировать полосу клиента', 'sniff', 'AdGuard', 'новые ссылки'] as $term) {
        $check(str_contains($tune, $term), "справка тонких настроек описывает «{$term}»");
    }
    // Тексты кнопок, на которые ссылается справка, действительно есть в меню.
    file_put_contents($b->hysteriaConf, "masquerade:\n  type: proxy\n  proxy:\n    url: https://vpn.example\n");
    $main = $b->hysteriaMenu();
    $labels = implode("\n", array_column(array_merge(...$main['data']), 'text'));
    foreach (['Персональные доступы', 'Диагностика', $i['change password']['ru'], $i['generate password']['ru'], $i['masquerade']['ru'], 'obfs: ', 'cc: ', 'insecure: ', 'port hopping: ', $i['hy tune']['ru'], 'config', $i['menu help']['ru']] as $label) {
        $check(str_contains($labels, $label), "в главном меню есть кнопка «{$label}»");
    }
    $check(in_array('/menuhelp hy 0', array_column(array_merge(...$main['data']), 'callback_data'), true), 'главное меню ведёт в полную справку');
    $b->click('/hyTune');
    $check(in_array('/menuhelp hy_tune 0', $b->callbacks(), true), 'тонкие настройки ведут в свою справку');

    // ── выключение нулём: пустое сообщение в Telegram отправить нельзя ───────
    $b->conf['hysteria_hop'] = '20000-20100';
    $b->chHyHop('0');
    $check(!isset($b->conf['hysteria_hop']), 'смена портов выключается ответом 0');
    $b->chHyHop(' 20000-20100 ');
    $check($b->conf['hysteria_hop'] === '20000-20100', 'диапазон по-прежнему принимается');
    foreach (['00', '0-0', '-', 'off', '70000', '5-1'] as $bad) {
        $b->chHyHop($bad);
        $check($b->conf['hysteria_hop'] === '20000-20100', "«{$bad}» не выключает и не портит смену портов");
    }
    $b->conf['hysteria_sni'] = 'decoy.example';
    $b->chHySNI('0');
    $check(!isset($b->conf['hysteria_sni']), 'свой сайт маскировки сбрасывается ответом 0');
    $b->chHySNI('decoy.example');
    $check($b->conf['hysteria_sni'] === 'decoy.example', 'свой сайт маскировки по-прежнему задаётся');
    $b->conf['hysteria_bw_up'] = '10 mbps'; $b->conf['hysteria_bw_down'] = '10 mbps';
    $b->chHyBw('0');
    $check(!isset($b->conf['hysteria_bw_up'], $b->conf['hysteria_bw_down']), 'полоса сбрасывается ответом 0');
    // Подсказки ввода говорят то же, что справка.
    $b->sent = []; $b->setHyHop(); $b->changeHySNI(); $b->changeHyBw();
    $check(count($b->sent) === 3 && !array_filter($b->sent, static fn($text) => str_contains($text, 'empty')) && count(array_filter($b->sent, static fn($text) => str_contains($text, '<code>0</code>'))) === 3,
        'подсказки ввода называют 0, а не пустой ответ');
} finally {
    foreach (glob("$root/*") as $file) is_dir($file) ? @rmdir($file) : unlink($file);
    @rmdir($root);
}
if ($failed) exit(1);
echo "hysteria_help_test: $count OK\n";
