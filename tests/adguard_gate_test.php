<?php

// Пропуск в веб-панель AdGuard (/adguard<hash>/).
//
// Раньше nginx сравнивал cookie c с hash из ссылок подписки: значение знал
// любой подписчик, выставлял его сам и получал страницу входа и API AdGuard.
// Пять неверных паролей блокировали вход на 15 минут ВСЕМ: AdGuard считает
// попытки по адресу соединения, а это nginx (X-Forwarded-For он не учитывает —
// проверено на AdGuardHome v0.107.79).
//
// Теперь пропуск — токен «срок.случайное.подпись» (HMAC от ключа бота):
//  1. проверка: верный проходит; чужой ключ, другой вид, правка любой части,
//     истёкший срок, мусор и старая cookie c=<hash> — нет;
//  2. одноразовая ссылка для стороннего браузера: только при включённом
//     «сторонний браузер», один раз, срок 15 минут;
//  3. nginx: auth_request на каждый запрос к панели, подзапрос внутренний,
//     отказ — в мини-приложение; прежней проверки cookie c нет;
//  4. меню: кнопка ссылки только в режиме «сторонний браузер», ссылка уходит
//     сообщением администратору.

require_once __DIR__ . '/../app/bot.php';

set_error_handler(static function ($level, $message, $file, $line) {
    if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line);
    return false;
});

$checks = 0;
function agCheck(bool $ok, string $label): void
{
    global $checks;
    if (!$ok) throw new RuntimeException($label);
    $checks++;
}

class GateBot extends Bot
{
    public array $conf = ['domain' => 'vpn.example.org', 'hashbot' => 'abcd1234'];
    public array $sent = [];
    public array $locks = [];
    public string $linksFile;
    public function __construct(string $key)
    {
        $this->key = $key; $this->language = 'ru'; Lang::$en = false;
        $this->input = ['chat' => 1, 'message_id' => 2, 'callback_id' => 'cb', 'callback' => ''];
        $this->linksFile = sys_get_temp_dir() . '/adg-links-' . bin2hex(random_bytes(4)) . '.json';
    }
    public function getPacConf() { return $this->conf; }
    public function setPacConf(array $conf) { $this->conf = $conf; return true; }
    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false) { $this->sent[] = $text; return ['result' => ['message_id' => 3]]; }
    public function menu($type = false, $arg = false, $return = false) {}
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { $this->locks[] = $name; return $fn(); }
}

// adguardLinkConsume пишет в /logs; в тесте подменяем путь через подкласс.
class GateBotTmp extends GateBot
{
    protected function adguardLinksFile(): string { return $this->linksFile; }
}

$bot = new GateBot('123456:secret-key-A');
$other = new GateBot('123456:secret-key-B');

// ── 1. Проверка токена ───────────────────────────────────────────────────────
$t = $bot->adguardGateToken('cookie', 3600);
agCheck((bool) preg_match('~^\d{10}\.[a-f0-9]{16}\.[a-f0-9]{40}$~', $t), 'формат токена');
agCheck($bot->adguardGateCheck($t, 'cookie'), 'верный пропуск проходит');
agCheck(!$other->adguardGateCheck($t, 'cookie'), 'токен другого ключа бота не проходит');
agCheck(!$bot->adguardGateCheck($t, 'link'), 'пропуск не годится как ссылка (вид входит в подпись)');
[$exp, $nonce, $sig] = explode('.', $t);
foreach ([($exp + 100000) . ".$nonce.$sig", "$exp." . str_repeat('0', 16) . ".$sig", "$exp.$nonce." . str_repeat('a', 40),
    "$exp.$nonce.$sig.", " $t", 'abcd1234', '', "$exp.$nonce"] as $bad) {
    agCheck(!$bot->adguardGateCheck($bad, 'cookie'), 'подделка не проходит: ' . substr($bad, 0, 30));
}
$expired = (time() - 10) . ".$nonce." . $bot->adguardGateSign('cookie', time() - 10, $nonce);
agCheck(!$bot->adguardGateCheck($expired, 'cookie'), 'истёкший пропуск не проходит');
agCheck(!$bot->adguardGateCheck($bot->conf['hashbot'], 'cookie'), 'прежняя cookie c=<hash> больше ничего не открывает');

// ── 2. Одноразовая ссылка ────────────────────────────────────────────────────
$tmp = new GateBotTmp('123456:secret-key-A');
$link = $tmp->adguardGateToken('link', Bot::ADGUARD_LINK_TTL);
agCheck($tmp->adguardLinkConsume($link), 'ссылка срабатывает');
agCheck(!$tmp->adguardLinkConsume($link), 'повторно ссылка не срабатывает');
agCheck(!$tmp->adguardLinkConsume($tmp->adguardGateToken('cookie', 600)), 'пропуск браузера не принимается как ссылка');
@unlink($tmp->linksFile);
@unlink($tmp->linksFile . '.lock');
$empty = new GateBot('');
agCheck(!$empty->adguardGateCheck($empty->adguardGateToken('cookie', 600), 'cookie'), 'Пустой ключ не авторизует');
file_put_contents($tmp->linksFile, '{broken');
agCheck(!$tmp->adguardLinkConsume($tmp->adguardGateToken('link', 600)), 'Повреждённый реестр закрывает доступ');
@unlink($tmp->linksFile); @unlink($tmp->linksFile . '.lock');
if (function_exists('pcntl_fork')) {
    $link = $tmp->adguardGateToken('link', 600);
    $children = [];
    for ($index = 0; $index < 6; ++$index) {
        $pid = pcntl_fork();
        if ($pid === -1) throw new RuntimeException('fork fixture failed');
        if ($pid === 0) exit($tmp->adguardLinkConsume($link) ? 0 : 10);
        $children[] = $pid;
    }
    $accepted = 0;
    foreach ($children as $pid) {
        pcntl_waitpid($pid, $status);
        agCheck(pcntl_wifexited($status) && in_array(pcntl_wexitstatus($status), [0, 10], true), 'Параллельный обработчик завершился штатно');
        if (pcntl_wexitstatus($status) === 0) ++$accepted;
    }
    agCheck($accepted === 1, 'Из шести одновременных переходов срабатывает ровно один');
    agCheck((fileperms($tmp->linksFile) & 0777) === 0600, 'История одноразовых ссылок закрыта');
    @unlink($tmp->linksFile); @unlink($tmp->linksFile . '.lock');
}
$src = (string) file_get_contents(__DIR__ . '/../app/bot.php');

// ── 3. nginx ─────────────────────────────────────────────────────────────────
$gen = substr($src, strpos($src, '$r = <<<CONF'), 2500);
agCheck(str_contains($gen, 'auth_request /adguard-gate;') && str_contains($gen, 'error_page 401 = @adguardlogin;'), 'каждый запрос к панели проходит auth_request');
agCheck((bool) preg_match('~location = /adguard-gate \{\s*internal;~', $gen), 'подзапрос проверки только внутренний');
agCheck(str_contains($gen, 'proxy_pass_request_body off;') && str_contains($gen, 'return 302 /webapp;'), 'тело в проверку не уходит, отказ — в мини-приложение');
agCheck(!str_contains($gen, 'cookie_c'), 'прежней проверки cookie c в шаблоне нет');
// Подстановка hash в шаблоне превращает пути в /adguard<hash>-gate и /webapp<hash>.
$hashed = preg_replace('~(/webapp|/pac|/adguard|/ws|/grpc|/v2ray|location /dns-query)~', '${1}abcd1234', $gen);
agCheck(str_contains($hashed, 'auth_request /adguardabcd1234-gate;') && str_contains($hashed, 'location = /adguardabcd1234-gate {')
    && str_contains($hashed, 'return 302 /webappabcd1234;') && !str_contains($hashed, '@adguardabcd1234'), 'пути после подстановки hash');
$idx = (string) file_get_contents(__DIR__ . '/../app/index.php');
agCheck(str_contains($idx, '=== "/adguard$hash-gate"') && str_contains($idx, "adguardGateCheck(is_string(\$_COOKIE['adg'] ?? null)"), 'index.php отвечает на подзапрос по cookie adg');
agCheck(strpos($idx, '"/adguard$hash-gate"') < strpos($idx, '// tlgrm') && strpos($idx, '"/webapp$hash/adg"') < strpos($idx, 'preg_quote("/webapp$hash/")'),
    'маршруты пропуска стоят раньше общего отказа /webapp<hash>/');
agCheck(str_contains($idx, "empty(\$bot->getPacConf()['adgbrowser']) || !\$bot->adguardLinkConsume(\$token)"), 'ссылка работает только в режиме «сторонний браузер»');

// ── 4. Меню и ссылка ─────────────────────────────────────────────────────────
require __DIR__ . '/../app/i18n.php';
$bot->i18n = $i;
$bot->adguardBrowserLink();
agCheck($bot->sent === [], 'без режима «сторонний браузер» ссылка не выдаётся');
$bot->conf['adgbrowser'] = 1;
$bot->adguardBrowserLink();
agCheck(count($bot->sent) === 1 && preg_match('~https://vpn\.example\.org/webappabcd1234/adg\?t=(\d{10}\.[a-f0-9]{16}\.[a-f0-9]{40})~', $bot->sent[0], $m)
    && $bot->adguardGateCheck($m[1], 'link') && (int) explode('.', $m[1])[0] - time() <= Bot::ADGUARD_LINK_TTL, 'ссылка на 15 минут уходит администратору');
agCheck(str_contains($bot->sent[0], 'один раз'), 'в сообщении сказано про одноразовость');
foreach (['browser_notify_on', 'browser_notify_off'] as $key) {
    agCheck(preg_match('~[А-Яа-я]~u', $i[$key]['ru']) && !preg_match('~[А-Яа-я]~u', $i[$key]['en']), "перевод $key");
}

echo "adguard_gate_test OK ($checks проверок)\n";
