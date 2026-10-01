<?php
require_once __DIR__ . '/../app/bot.php';
require __DIR__ . '/../app/i18n.php';
set_error_handler(static function ($level, $message, $file, $line) {
    if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line);
    return true;
});

class MenuHelpTestBot extends Bot
{
    public array $conf = [];
    public array $screen = [];
    public array $answers = [];
    public int $writes = 0;
    public int $restarts = 0;
    public int $reloads = 0;
    public string $version = '3.5.9';
    public function __construct(array $strings) {
        $this->i18n = $strings; $this->language = 'ru'; $this->admin = true;
        $this->key = 'fixture'; $this->ip = '203.0.113.10';
        $this->input = ['chat' => 1, 'message_id' => 2, 'callback_id' => 3, 'callback' => '', 'message' => ''];
        $this->conf = ['domain' => 'vpn.example', 'tw_domain' => 'webfixture', 'letsencrypt' => 'letsencrypt',
            'telemt_web' => 1, 'telemt_users' => ['alice' => '00112233445566778899aabbccddeeff']];
    }
    public function getPacConf() { return $this->conf; }
    public function setPacConf(array $conf) { $this->writes++; $this->conf = $conf; return true; }
    public function getWgMsg() { return null; }
    public function getPorts() { return ['telemt' => ['port' => 8443, 'enable' => true]]; }
    public function telemtVersion(): string { return $this->version; }
    public function restartTelemt() { $this->restarts++; }
    public function cloakNginx() { $this->reloads++; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML') {
        $this->screen = [$text, $this->protocolNavigationButtons($button)];
    }
    public function answer($callback_id, $textNotify = false, $notify = false) { $this->answers[] = $textNotify; }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') { throw new RuntimeException('Неожиданный SSH при просмотре меню'); }
    public function click(string $callback): void { $this->input['callback'] = $callback; $this->action(); }
}

$checks = 0;
$check = static function (bool $ok, string $name) use (&$checks): void {
    $checks++;
    if (!$ok) throw new RuntimeException($name);
};
$callbacks = static fn(array $screen): array => array_column(array_merge(...$screen[1]), 'callback_data');
$configFor = static fn(string $mode): array => str_starts_with($mode, 'auto-')
    ? ['telemt_web_negotiation' => substr($mode, 5), 'telemt_web_carrier' => 'https-lanes']
    : ['telemt_web_negotiation' => 'off', 'telemt_web_carrier' => $mode];
$modes = ['auto-https', 'auto-full', 'https', 'https-lanes'];
foreach ($modes as $start) foreach ($modes as $target) {
    $bot = new MenuHelpTestBot($i);
    $bot->conf += $configFor($start);
    $bot->conf += ['telemt_web_path' => 'articles/news', 'telemt_web_secret_mode' => 'dd', 'telemt_web_diag' => 1,
        'unrelated_setting' => ['keep' => true]];
    $before = $bot->conf; $link = $bot->linkTelemtWeb('alice');
    $bot->click('/telemtWebMode ' . $target);
    $check($bot->telemtWebModeOf($bot->conf) === $target, "$start → $target: выбран точный режим");
    $check($bot->restarts === ($start === $target ? 0 : 1), "$start → $target: ровно один рестарт только при изменении");
    $check($bot->writes === ($start === $target ? 0 : 1), "$start → $target: повторное нажатие не пишет конфиг");
    $check($bot->reloads === 0, 'Смена carrier не перезагружает nginx');
    $check($bot->linkTelemtWeb('alice') === $link, 'Ссылка после смены carrier прежняя');
    foreach (['telemt_web_path', 'telemt_web_secret_mode', 'telemt_web_diag', 'unrelated_setting'] as $key) {
        $check($bot->conf[$key] === $before[$key], "Не меняется $key");
    }
    $rows = array_merge(...$bot->screen[1]);
    $selected = array_values(array_filter($rows, fn($b) => str_starts_with($b['text'], '✅ ')));
    $check(count($selected) === 1 && $selected[0]['callback_data'] === '/telemtWebMode ' . $target, 'Отмечен ровно текущий выбор');
    $check(array_slice($callbacks($bot->screen), 0, 4) === array_map(fn($m) => '/telemtWebMode ' . $m, $modes), 'Все четыре режима доступны из любого состояния');
    $toml = $bot->telemtToml();
    $expected = match ($target) {
        'auto-https' => ['https', '["https-lanes"]'],
        'auto-full' => ['https', '["websocket-lanes", "websocket", "https-lanes"]'],
        default => [$target, null],
    };
    $check(str_contains($toml, 'carrier = "' . $expected[0] . '"'), 'Фиксированный carrier/fallback в TOML соответствует выбору');
    $check($expected[1] === null ? !str_contains($toml, 'carriers =') : str_contains($toml, 'carriers = ' . $expected[1]), 'Список кандидатов в TOML соответствует выбору');
    $bot->click('/telemtWeb');
    $check($bot->messageTextLength($bot->screen[0]) < 1800, 'Основное меню WEB компактно');
    $check(in_array('/telemtWebMode', $callbacks($bot->screen), true), 'Выбор транспорта доступен из WEB');
    $check(!in_array('/telemtWebCarrier', $callbacks($bot->screen), true), 'Нет скрытого независимого переключателя carrier');
    $check(str_contains($bot->screen[0], $bot->i18n('telemt web lanes ios')) === ($target === 'https-lanes'), 'Предупреждение iOS соответствует фиксированному Lanes');
}

$bot = new MenuHelpTestBot($i);
$before = $bot->conf;
foreach (['/telemtWebCarrier', '/telemtWebNegotiation', '/telemtWebMode'] as $old) {
    $bot->click($old);
    $check($bot->conf === $before && $bot->restarts === 0 && $bot->writes === 0, 'Старая кнопка открывает выбор, не меняя настройки');
    $check(in_array('/telemtWebMode auto-full', $callbacks($bot->screen), true), 'Старая кнопка ведёт к рабочему новому меню');
}
$bot->conf['telemt_web'] = 0;
$bot->click('/telemtWebMode auto-full');
$check($bot->telemtWebModeOf($bot->conf) === 'auto-full' && $bot->restarts === 0, 'При WEB off сохраняем настройку без обрыва обычного MTProxy');
$bot->version = '3.5.3';
$bot->click('/telemtWebMode https');
$check($bot->telemtWebModeOf($bot->conf) === 'https', 'Старое ядро позволяет выйти из подбора');
$before = $bot->conf;
$bot->click('/telemtWebMode auto-https');
$check($bot->conf === $before && count($bot->answers) === 1, 'Старое ядро не включает неподдерживаемый подбор');
$bot->telemtWebMode('invalid');
$check($bot->conf === $before, 'Неизвестный выбор не меняет настройки');

$bot = new MenuHelpTestBot($i);
$bot->click('/telemtWeb');
foreach (['/telemtWebToggle', '/telemtWebSecret', '/telemtWebPath', '/telemtWebDiag', '/menuhelp telemt 0', '/telemt'] as $callback) {
    $check(in_array($callback, $callbacks($bot->screen), true), "Доступна функция $callback");
}
$link = $bot->linkTelemtWeb('alice');
$bot->click('/telemtWebSecret');
$check($bot->telemtWebSecretModeOf($bot->conf) === 'plain' && $bot->linkTelemtWeb('alice') !== $link, 'Кнопка secret меняет формат и WEB-ссылку');
$bot->click('/telemtWebSecret');
$check($bot->linkTelemtWeb('alice') === $link, 'Повторное переключение secret возвращает dd');
$before = $bot->conf; $restarts = $bot->restarts;
$bot->click('/telemtWebPath');
$check($bot->conf === $before && $bot->restarts === $restarts, 'Открытие пути только показывает настройки');
$native = $bot->linkTelemt('alice');
$bot->click('/telemtWebPath generate');
$path = $bot->telemtWebPathOf($bot->conf);
$check(strlen($path) === 16 && $bot->linkTelemtWeb('alice') !== $link, 'Кнопка path создаёт рабочий префикс');
$bot->click('/telemtWebPath generate');
$check($bot->telemtWebPathOf($bot->conf) !== $path, 'Повторная генерация заменяет путь без промежуточного отключения');
$check($bot->linkTelemt('alice') === $native, 'Генерация пути WEB не меняет обычную MTProxy-ссылку');
$bot->click('/telemtWebPath reset');
$check($bot->telemtWebPathOf($bot->conf) === '' && $bot->linkTelemtWeb('alice') === $link, 'Path возвращается к корню');
$restarts = $bot->restarts; $writes = $bot->writes;
$bot->click('/telemtWebPath reset');
$check($bot->restarts === $restarts && $bot->writes === $writes, 'Повторный выбор корня не пишет конфиг и не перезапускает TeleMT');
$bot->click('/telemtWebDiag');
$check(!empty($bot->conf['telemt_web_diag']), 'Диагностика включается');
$bot->click('/telemtWebDiag');
$check(empty($bot->conf['telemt_web_diag']), 'Диагностика выключается');
$bot->click('/telemtWebToggle');
$check(!$bot->telemtWebEnabled($bot->conf) && $bot->reloads === 1, 'WEB выключается вместе с маршрутом nginx');
$bot->click('/telemtWebToggle');
$check($bot->telemtWebEnabled($bot->conf) && $bot->reloads === 2, 'WEB включается вместе с маршрутом nginx');

$topics = ['telemt' => '', 'telemt_carrier' => '', 'telemt_path' => '', 'telemt_mask' => '', 'dpi' => '', 'smux' => '', 'finalmask' => '',
    'dpi_frag' => '', 'dpi_noise' => '', 'finalmask_frag' => '', 'finalmask_noise' => '', 'encryption' => '',
    'awg' => '1_4', 'naive_relay' => 'relay.example-test'];
foreach (ManagedProtocol::NAMES as $protocol => $name) {
    $topics['p_' . $protocol] = 'a123456789abcdef';
    $topics['ps_' . $protocol] = 'a123456789abcdef.0123456789abcdef';
}
foreach (['ru', 'en'] as $lang) foreach ($topics as $topic => $context) {
    $bot = new MenuHelpTestBot($i); $bot->language = $lang;
    [$title, $back, $pages] = $bot->menuHelpContent($topic, $context);
    $before = $bot->conf;
    foreach (range(0, count($pages) + 1) as $page) {
        $bot->click('/menuhelp ' . $topic . ' ' . $page . ($context === '' ? '' : ' ' . $context));
        [$text, $buttons] = $bot->screen;
        $check($bot->messageTextLength($text) < 4096, "$lang/$topic/$page: длина сообщения");
        $check(mb_strlen(strip_tags($text)) > 40, "$lang/$topic/$page: содержимое не пустое");
        preg_match_all('~<(/?)([a-z]+)(?:\s[^<>]*)?>~i', $text, $tags, PREG_SET_ORDER);
        $stack = [];
        foreach ($tags as $tag) {
            if ($tag[1] === '/') $check(array_pop($stack) === $tag[2], "$lang/$topic/$page: HTML закрывает правильный тег");
            else { $check(in_array($tag[2], ['b', 'i', 'code', 'pre', 'a'], true), 'Поддерживаемый Telegram HTML'); $stack[] = $tag[2]; }
        }
        $check($stack === [], "$lang/$topic/$page: все HTML-теги закрыты");
        $cbs = $callbacks($bot->screen);
        foreach ($cbs as $cb) $check(strlen($cb) <= 64, "$lang/$topic/$page: callback до 64 байт");
        $check(end($cbs) === $back, "$lang/$topic/$page: точный возврат в исходное меню");
        $check($bot->conf === $before && $bot->writes === 0 && $bot->restarts === 0, 'Справка не меняет состояние');
        $check(!str_contains($text, '0011223344556677'), 'Справка не раскрывает секрет пользователя');
        if ($page === 0 && count($pages) > 1) $check(count($cbs) === count($pages) + 1, 'Оглавление открывает все темы');
    }
}
$bot = new MenuHelpTestBot($i);
$bot->click('/!menuhelp p_masque 1 a123456789abcdef');
$check(end($bot->screen[1])[0]['callback_data'] === '/!protocol masque user a123456789abcdef', 'Справка сохраняет вход из главного меню');
$bot->click('/!menuhelp p_masque 0');
$check(str_starts_with($bot->screen[1][0][0]['callback_data'], '/!menuhelp p_masque'), 'Оглавление сохраняет вход из главного меню');
$bot->click('/menuhelp p_mieru 1 page_2');
$check(end($bot->screen[1])[0]['callback_data'] === '/protocol mieru page 2', 'Справка сохраняет страницу отдельных доступов');
foreach ([['missing', ''], ['awg', '2_3'], ['awg', '1_3 /menu'], ['p_bad', ''], ['p_masque', '../bad'], ['naive_relay', '<bad>']] as [$topic, $context]) {
    $check($bot->menuHelpContent($topic, $context) === [], 'Неизвестная тема/некорректный контекст отвергнуты');
}
echo "menu_help_test: $checks проверок OK\n";
