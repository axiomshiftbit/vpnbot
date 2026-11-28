<?php

// Внешние ссылки пользователя (Vless → пользователь → внешние ссылки) и
// User-Agent загрузки внешних подписок:
//  1. экран: имя пользователя экранировано, кнопки строк несут отпечаток
//     строки, справка и User-Agent на месте, callback_data ≤ 64 байт;
//  2. добавление: несколько ссылок по строкам, мусор и http отклоняются с
//     объяснением, дубли пропускаются, подписка сразу загружается;
//  3. кнопки старого сообщения (номер строки сдвинулся) ничего не трогают;
//  4. переименование: управляющие символы и длина, 0 — исходное имя;
//  5. User-Agent: неверный — ошибка на экране без записи; верный — запись и
//     немедленная перезагрузка включённых подписок этого пользователя;
//  6. base64-подписка: внешние ссылки после своей, выключенные — нет.

require_once __DIR__ . '/../app/bot.php';

set_error_handler(static function ($level, $message, $file, $line) {
    if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line);
    return false;
});

$checks = 0;
function elCheck(bool $ok, string $label): void
{
    global $checks;
    if (!$ok) throw new RuntimeException($label);
    $checks++;
}

class ExtLinksTransport
{
    public array $calls = [];
    public function call($method, $data, $json = 0)
    {
        $this->calls[] = [$method, $data];
        return ['ok' => true, 'result' => ['message_id' => count($this->calls) + 10, 'chat' => ['id' => 1]]];
    }
}

class ExtLinksBot extends Bot
{
    public array $conf = [];
    public array $xr = [];
    public array $cache = [];
    public array $fetched = [];
    public array $prompts = [];
    public int $saves = 0;
    public array $screen = ['', []];
    public function __construct(array $strings, string $lang = 'ru')
    {
        $this->admin = true; $this->i18n = $strings; $this->language = $lang; Lang::$en = $lang === 'en';
        $this->ip = '192.0.2.1'; $this->key = 'fixture';
        $this->input = ['chat' => 1, 'from' => 1, 'message_id' => 5, 'callback_id' => 'cb', 'username' => 'admin', 'message' => '', 'callback' => ''];
        $this->transport = new ExtLinksTransport();
        $this->xr = ['inbounds' => [['settings' => ['clients' => [
            ['id' => '11111111-2222-4333-8444-555555555555', 'email' => 'Ann & <b>', 'subtoken' => 'tok0'],
            ['id' => '21111111-2222-4333-8444-555555555555', 'email' => 'Bob', 'subtoken' => 'tok1',
                'ext' => [['kind' => 'sub', 'value' => 'https://other.example.test/bob', 'remark' => '', 'off' => 0]]],
        ]]]]];
    }
    public function getPacConf() { return $this->conf + self::PAC_DEFAULTS; }
    public function setPacConf(array $conf) { $this->conf = $conf; return true; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
    public function getXray() { return $this->xr; }
    public function saveXray(array $c): void { $this->saves++; $this->xr = $c; }
    public function readExtSubCache(): array { return $this->cache; }
    public function refreshExtSubOne(string $url): void { $this->fetched[] = $url; }
    public function stashReply($r, array $state) { $this->prompts[] = $state; }
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML')
    {
        $this->screen = [$text, is_array($button) ? $button : []];
    }
    public function fresh(string $callback): string { return $this->xrayIdentityButtons([[['callback_data' => $callback]]], $this->xr)[0][0]['callback_data']; }
    public function click(string $callback): void { $this->input['callback'] = str_contains($callback, ' !') ? $callback : $this->fresh($callback); $this->action(); $this->input['callback'] = ''; }
    public function callbacks(): array { return array_column(array_merge(...($this->screen[1] ?: [[]])), 'callback_data'); }
    public function ext(int $i = 0): array { return $this->xr['inbounds'][0]['settings']['clients'][$i]['ext'] ?? []; }
    public function subRateLimit($sid, $scope = '') {}
    public function subSecurityHeaders() {}
    public function processHwidRequest(array $client, bool $htmlPreview = false) { return true; }
    public function xraySubscriptionMetadata(array $client, int $index): void {}
    public function getXrayStats() { return []; }
    public function xrayProtocolUsage(array $client): array { return []; }
    public function linkXray($i, $s = false) { return 'vless://cred@origin.example.test:443?security=reality#own'; }
}

function elScreen(ExtLinksBot $bot, string $label): array
{
    [$text, $buttons] = $bot->screen;
    elCheck($bot->messageTextLength($text) < 4096, "$label: длина");
    preg_match_all('~<(/?)([a-z]+)(?:\s[^<>]*)?>~i', $text, $tags, PREG_SET_ORDER);
    $stack = [];
    foreach ($tags as $tag) {
        if ($tag[1] === '/') elCheck(array_pop($stack) === $tag[2], "$label: теги");
        else { elCheck(in_array($tag[2], ['b', 'i', 'code', 'pre', 'a'], true), "$label: тег $tag[2]"); $stack[] = $tag[2]; }
    }
    elCheck($stack === [], "$label: теги закрыты");
    foreach ($buttons as $row) foreach ($row as $b) elCheck(strlen($b['callback_data'] ?? '') <= 64, "$label: callback ≤ 64");
    return [$text, $bot->callbacks()];
}

$vless = 'vless://a@one.example.test:443?security=tls#One';
$vmess = 'vmess://' . base64_encode(json_encode(['v' => '2', 'ps' => 'Old', 'add' => 'two.example.test', 'port' => '443', 'id' => 'x']));

foreach (['ru', 'en'] as $lang) {
    require __DIR__ . '/../app/i18n.php';
    $bot = new ExtLinksBot($i, $lang);

    $privacyBot = new ExtLinksBot($i, $lang);
    $privacyBot->extAddSave("trojan://fixture-private@vpn.example.test:443#Node", 0, 'link');
    $privacyBot->extAddSave("https://sub.tld/fixture-private", 0, 'sub');
    $privacyBot->click('/extUser 0');
    $rendered = json_encode($privacyBot->screen, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    elCheck(!str_contains($rendered, 'fixture-private') && !str_contains($rendered, 'fixture-pri'),
        "$lang: список и кнопки не показывают пароль подключения или путь персональной подписки");

    // ── 1. Пустой экран ─────────────────────────────────────────────────────
    $bot->click('/extUser 0');
    [$text, $cbs] = elScreen($bot, "$lang пустой экран");
    elCheck(str_contains($text, 'Ann &amp; &lt;b&gt;'), "$lang: имя пользователя экранировано");
    elCheck(str_contains($text, 'base64') && in_array($bot->fresh('/extAdd 0 link'), $cbs, true) && in_array($bot->fresh('/extAdd 0 sub'), $cbs, true)
        && in_array('/extUA 0', $cbs, true) && in_array('/menuhelp ext 0 0', $cbs, true) && end($cbs) === $bot->fresh('/userXr 0'), "$lang: кнопки и пояснение");
    if ($lang === 'en') elCheck(!preg_match('~\p{Cyrillic}~u', strip_tags($text . implode(' ', array_column(array_merge(...$bot->screen[1]), 'text')))), 'en: без русского');

    // ── 2. Добавление ссылок ────────────────────────────────────────────────
    $bot->extAddSave("$vless\n  $vmess  \r\nhttp://junk.example.test\njavascript:alert(1)\n$vless", 0, 'link');
    [$text] = elScreen($bot, "$lang после добавления");
    elCheck(array_column($bot->ext(), 'value') === [$vless, $vmess], "$lang: две ссылки отдельными строками, мусор и дубль отброшены");
    elCheck(str_contains($text, '✅') && str_contains($text, '⚠️') && str_contains($text, '(2)'), "$lang: сообщение о добавленных и отклонённых");
    $saves = $bot->saves;
    $bot->extAddSave($vless, 0, 'link');
    elCheck(count($bot->ext()) === 2 && $bot->saves === $saves && str_contains($bot->screen[0], 'ℹ️'), "$lang: повтор не пишет конфиг и объясняется");
    $bot->extAddSave('just text', 0, 'link');
    elCheck(count($bot->ext()) === 2 && str_contains($bot->screen[0], '⚠️'), "$lang: не-ссылка отклонена с пояснением");

    // ── 3. Добавление подписок ──────────────────────────────────────────────
    $bot->fetched = [];
    $bot->extAddSave("http://plain.example.test/sub\nhttps://\nhttps://sub.example.test/a b\nhttps://sub.example.test/x?token=1", 0, 'sub');
    elCheck(array_column(array_filter($bot->ext(), fn($e) => $e['kind'] === 'sub'), 'value') === ['https://sub.example.test/x?token=1'], "$lang: только корректный https");
    elCheck($bot->fetched === ['https://sub.example.test/x?token=1'] && str_contains($bot->screen[0], '(3)'), "$lang: подписка загружена сразу, три строки отклонены");

    // ── 4. Строки списка и статусы ──────────────────────────────────────────
    $bot->cache = ['https://sub.example.test/x?token=1' => ['ts' => time() - 120, 'at' => time(), 'links' => [$vless, $vless . '2'], 'err' => 'http 403 <x>']];
    $bot->click('/extUser 0');
    [$text, $cbs] = elScreen($bot, "$lang список");
    elCheck(str_contains($text, 'http 403 &lt;x&gt;') && (str_contains($text, '· узлов: 2') || str_contains($text, '· nodes: 2')), "$lang: ошибка экранирована, видны узлы прошлой загрузки");
    $keys = array_map(fn($e) => Bot::extRowKey($e), $bot->ext());
    foreach ($keys as $k => $h) {
        foreach (['extToggle', 'extRename', 'extDel'] as $action) elCheck(in_array($bot->fresh("/$action 0_{$k}_$h"), $cbs, true), "$lang: кнопка $action несёт отпечаток");
    }

    // ── 5. Старые кнопки и отпечатки ────────────────────────────────────────
    $saves = $bot->saves;
    foreach (['/extDel 0_0', '/extDel 0_0_00000000', "/extDel 0_1_$keys[0]", '/extToggle 0_7_' . $keys[0]] as $stale) {
        $bot->click($stale);
        elCheck(count($bot->ext()) === 3 && $bot->saves === $saves && str_contains($bot->screen[0], '⚠️'), "$lang: «{$stale}» ничего не меняет");
    }
    $bot->click("/extDel 0_0_$keys[0]");
    elCheck(array_column($bot->ext(), 'value')[0] === $vmess, "$lang: удалена нужная строка");
    $bot->click("/extDel 0_0_$keys[0]");
    elCheck(count($bot->ext()) === 2 && str_contains($bot->screen[0], '⚠️'), "$lang: повторное нажатие 🗑 не удаляет соседнюю строку");
    $h = Bot::extRowKey($bot->ext()[0]);
    $bot->click("/extToggle 0_0_$h");
    elCheck(!empty($bot->ext()[0]['off']), "$lang: выключение строки");

    // ── 6. Переименование ───────────────────────────────────────────────────
    $bot->click("/extRename 0_0_$h");
    $state = end($bot->prompts);
    elCheck($state['callback'] === 'extRenameSave' && $state['args'] === ['0', '0', $h], "$lang: ответ привязан к строке и отпечатку");
    $bot->extRenameSave("Nice\nname\t" . str_repeat('я', 100), 0, 0, $h);
    $remark = $bot->ext()[0]['remark'];
    elCheck(!preg_match('~[\x00-\x1f]~', $remark) && mb_strlen($remark) === 64 && str_starts_with($remark, 'Nice name'), "$lang: имя очищено и обрезано");
    elCheck((json_decode(base64_decode(substr($bot->applyExtRemark($vmess, 'Новое'), 8)), true)['ps'] ?? '') === 'Новое', "$lang: имя vmess пишется в ps");
    $bot->extRenameSave('0', 0, 0, $h);
    elCheck($bot->ext()[0]['remark'] === '', "$lang: 0 возвращает исходное имя");
    $bot->extRenameSave('X', 0, 0, 'ffffffff');
    elCheck($bot->ext()[0]['remark'] === '' && str_contains($bot->screen[0], '⚠️'), "$lang: переименование устаревшей строки отклонено");

    // ── 7. User-Agent ───────────────────────────────────────────────────────
    $bot->click('/extUA 0');
    elCheck(end($bot->prompts)['callback'] === 'extUASave', "$lang: запрос User-Agent");
    // Готовые значения: каждое в <code> (копируется нажатием), проходит проверку
    // бота и принимается ответом; запрос не длиннее лимита Telegram.
    [$method, $sent] = end($bot->transport->calls);
    $prompt = (string) ($sent['text'] ?? '');
    elCheck($method === 'sendMessage' && $bot->messageTextLength($prompt) < 4096, "$lang: запрос User-Agent отправлен целиком");
    if ($lang === 'en') elCheck(!preg_match('~\p{Cyrillic}~u', strip_tags($prompt)), 'en: запрос User-Agent без русского');
    elCheck(count(Bot::EXT_SUB_USER_AGENT_PRESETS) >= 5 && array_key_first(Bot::EXT_SUB_USER_AGENT_PRESETS) === Bot::EXT_SUB_USER_AGENT, "$lang: список начинается со значения по умолчанию");
    [, , $pages] = $bot->menuHelpContent('ext', '0');
    $help = implode("\n", $pages);
    foreach (Bot::EXT_SUB_USER_AGENT_PRESETS as $ua => $note) {
        elCheck(Bot::extSubUserAgentValid($ua), "$lang: готовое значение «{$ua}» проходит проверку");
        elCheck(str_contains($prompt, '<code>' . htmlspecialchars($ua) . '</code>') && str_contains($help, '<code>' . htmlspecialchars($ua) . '</code>'), "$lang: «{$ua}» копируется из сообщения и есть в справке");
        elCheck($note['ru'] !== '' && $note['en'] !== '' && !preg_match('~\p{Cyrillic}~u', $note['en']) && preg_match('~\p{Cyrillic}~u', $note['ru']), "$lang: пояснение к «{$ua}» на двух языках");
        $bot->extUASave($ua, 0);
        elCheck($bot->extSubUserAgent() === $ua && str_contains($bot->screen[0], '✅ User-Agent: <code>' . htmlspecialchars($ua) . '</code>'), "$lang: «{$ua}» принимается");
    }
    foreach (['clash-verge', 'mihomo', 'SFA', 'Karing', 'HiddifyNext'] as $unfit) {
        elCheck(!isset(Bot::EXT_SUB_USER_AGENT_PRESETS[$unfit]) && str_contains($help, "<code>$unfit</code>"), "$lang: «{$unfit}» назван неподходящим");
    }
    $bot->extUASave('-', 0);
    $before = $bot->conf;
    $bot->extUASave("Evil\r\nX-Injected: 1", 0);
    elCheck($bot->conf === $before && str_contains($bot->screen[0], '⚠️'), "$lang: User-Agent с переводом строки отклонён на экране");
    $bot->fetched = [];
    $bot->extUASave('Happ/3.0.0', 0);
    elCheck($bot->extSubUserAgent() === 'Happ/3.0.0' && $bot->fetched === ['https://sub.example.test/x?token=1'], "$lang: User-Agent сохранён, подписки этого пользователя перезагружены");
    elCheck(str_contains($bot->screen[0], 'Happ/3.0.0'), "$lang: экран подтверждает новое значение");
    $bot->extUASave('-', 0);
    elCheck($bot->extSubUserAgent() === Bot::EXT_SUB_USER_AGENT && !isset($bot->conf['extsub_user_agent']), "$lang: «-» возвращает значение по умолчанию");

    // ── 8. Base64-подписка ──────────────────────────────────────────────────
    $_GET = ['s' => 'tok0'];
    ob_start(); $bot->subVless(); $lines = explode("\n", base64_decode(ob_get_clean()));
    elCheck($lines === ['vless://cred@origin.example.test:443?security=reality#own', $vless, $vless . '2'],
        "$lang: своя ссылка, затем узлы внешней подписки; выключенная строка не попала");
    $_GET = [];
}

echo "ext_links_test OK ($checks проверок)\n";
