<?php

// Формат клиентских масок DPI (dpi.format): fragment/noises у freedom (по
// умолчанию, понимает любой клиент Xray) либо streamSettings.finalmask
// прокси-выхода (Xray 26.3.27+; 26.10.29 считает freedom-форму устаревшей).
//
//  1. Без выбора формата профиль прежний: выход dpi-fragment и dialerProxy.
//  2. finalmask: тех же значений маски на прокси-выходе, без freedom и dialerProxy;
//     interval меню становится delay маски, умолчания меню сохраняются.
//  3. Уже заданный finalmask выхода дополняется, а не затирается.
//  4. Значения, которых finalmask не принимает, — прежний формат, не сломанный профиль.
//  5. С VLESS_TEST_XRAY ядро принимает обе формы профиля.
//  6. Переключатель в меню: только при включённых масках, тексты на ru и en.

require_once __DIR__ . '/../app/bot.php';

$failed = 0;
function dfAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) { $failed++; echo "FAIL: $msg\n"; }
}

class DpiFormatBot extends Bot
{
    public array $conf = [];
    public array $buttons = []; public array $texts = [];
    public function __construct()
    {
        $this->language = 'ru';
        require __DIR__ . '/../app/i18n.php';
        $this->i18n = $i;
        $this->input = ['chat' => 1, 'message_id' => 2, 'callback_id' => 'cb'];
    }
    public function getPacConf() { return $this->conf; }
    public function setPacConf(array $conf) { $this->conf = $conf; return true; }
    public function getXray() { return ['inbounds' => [['sniffing' => ['enabled' => false]]]]; }
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML') { $this->texts[] = $text; $this->buttons = is_array($button) ? $button : []; }
    public function callbacks(): array { $all = []; foreach ($this->buttons as $row) foreach ($row as $b) $all[$b['callback_data']] = $b['text']; return $all; }
}

$bot = new DpiFormatBot();
$profile = static fn() => ['outbounds' => [['tag' => 'proxy', 'protocol' => 'vless', 'streamSettings' => ['network' => 'tcp', 'security' => 'reality']],
    ['tag' => 'direct', 'protocol' => 'freedom']]];
$dpi = ['fragment' => ['enabled' => 1, 'packets' => '', 'length' => '50-90', 'interval' => '', 'maxSplit' => '4-6'],
    'noise' => ['enabled' => 1, 'list' => [['type' => 'rand', 'packet' => '20-30', 'delay' => ''], ['type' => 'str', 'packet' => 'hello', 'delay' => '5-9']]]];

// 1. Прежний формат по умолчанию.
$c = $profile();
$bot->applyDpiFragment($c, 0, ['dpi' => $dpi]);
dfAssert(($c['outbounds'][2]['tag'] ?? '') === 'dpi-fragment' && ($c['outbounds'][0]['streamSettings']['sockopt']['dialerProxy'] ?? '') === 'dpi-fragment',
    'без выбора формата — freedom dpi-fragment и dialerProxy, как раньше');
dfAssert(($c['outbounds'][2]['settings']['fragment'] ?? null) === ['packets' => '1-3', 'length' => '50-90', 'interval' => '10-20', 'maxSplit' => '4-6']
    && count($c['outbounds'][2]['settings']['noises'] ?? []) === 2 && !isset($c['outbounds'][0]['streamSettings']['finalmask']),
    'прежняя форма freedom не изменилась');

// 2. finalmask.
$c = $profile();
$bot->applyDpiFragment($c, 0, ['dpi' => $dpi + ['format' => 'finalmask']]);
$fm = $c['outbounds'][0]['streamSettings']['finalmask'] ?? [];
dfAssert(count($c['outbounds']) === 2 && !isset($c['outbounds'][0]['streamSettings']['sockopt']), 'finalmask: без выхода freedom и без dialerProxy');
dfAssert($fm['tcp'] === [['type' => 'fragment', 'settings' => ['packets' => '1-3', 'length' => '50-90', 'delay' => '10-20', 'maxSplit' => '4-6']]],
    'finalmask: fragment с теми же значениями, interval → delay');
dfAssert(($fm['udp'][0]['type'] ?? '') === 'noise' && ($fm['udp'][0]['settings']['noise'] ?? null)
    === [['rand' => '20-30', 'randRange' => '0-255', 'delay' => '10-16'], ['type' => 'str', 'packet' => 'hello', 'delay' => '5-9']],
    'finalmask: шум — те же пакеты в форме NoiseMask');
$c = $profile();
$bot->applyDpiFragment($c, 0, ['dpi' => ['fragment' => ['enabled' => 1, 'packets' => 'tlshello']] + ['format' => 'finalmask']]);
dfAssert(($c['outbounds'][0]['streamSettings']['finalmask'] ?? null) === ['tcp' => [['type' => 'fragment', 'settings' => ['packets' => 'tlshello', 'length' => '100-200', 'delay' => '10-20']]]],
    'finalmask: только fragment, умолчания меню, без udp');

// 3. Существующий finalmask дополняется.
$c = $profile();
$c['outbounds'][0]['streamSettings']['finalmask'] = ['udp' => [['type' => 'header-dns', 'settings' => []]]];
$bot->applyDpiFragment($c, 0, ['dpi' => $dpi + ['format' => 'finalmask']]);
$fm = $c['outbounds'][0]['streamSettings']['finalmask'];
dfAssert(($fm['udp'][0]['type'] ?? '') === 'header-dns' && ($fm['udp'][1]['type'] ?? '') === 'noise' && count($fm['tcp']) === 1, 'finalmask: прежние маски выхода сохраняются');

// 4. Недопустимое для finalmask — прежний формат.
$c = $profile();
$bad = $dpi; $bad['noise']['list'] = [['type' => 'hex', 'packet' => 'zz', 'delay' => '']];
$bot->applyDpiFragment($c, 0, ['dpi' => $bad + ['format' => 'finalmask']]);
dfAssert(($c['outbounds'][2]['tag'] ?? '') === 'dpi-fragment' && !isset($c['outbounds'][0]['streamSettings']['finalmask']),
    'значение, которого finalmask не примет, — профиль в прежнем формате');
$c = ['outbounds' => [['tag' => 'direct', 'protocol' => 'freedom']]];
$bot->applyDpiFragment($c, 5, ['dpi' => $dpi + ['format' => 'finalmask']]);
dfAssert(count($c['outbounds']) === 2 && $c['outbounds'][1]['tag'] === 'dpi-fragment', 'нет прокси-выхода — прежнее поведение');

// 5. Настоящее ядро принимает обе формы.
$binary = getenv('VLESS_TEST_XRAY');
if ($binary && is_executable($binary)) {
    foreach (['freedom', 'finalmask'] as $format) {
        $c = ['inbounds' => [['listen' => '127.0.0.1', 'port' => 24480, 'protocol' => 'socks']], 'outbounds' => [
            ['tag' => 'proxy', 'protocol' => 'vless', 'settings' => ['vnext' => [['address' => '127.0.0.1', 'port' => 24443,
                'users' => [['id' => '11111111-2222-4333-8444-555555555555', 'encryption' => 'none']]]]], 'streamSettings' => ['network' => 'tcp']],
            ['tag' => 'direct', 'protocol' => 'freedom']]];
        $bot->applyDpiFragment($c, 0, ['dpi' => $dpi + ['format' => $format]]);
        $file = sys_get_temp_dir() . '/vpnbot-dpi-format-' . bin2hex(random_bytes(4)) . '.json';
        file_put_contents($file, json_encode($c, JSON_UNESCAPED_SLASHES));
        exec(escapeshellarg($binary) . ' run -test -config ' . escapeshellarg($file) . ' 2>&1', $out, $code);
        unlink($file);
        dfAssert($code === 0, "ядро принимает профиль в формате $format");
        dfAssert($format === 'freedom' || !preg_grep('~deprecated~i', $out), 'формат finalmask без предупреждения об устаревании');
        $out = [];
    }
}

// 6. Меню.
$bot->conf = ['dpi' => []];
$bot->dpiMenu();
dfAssert(!isset($bot->callbacks()['/dpiToggle format']), 'без включённых масок переключателя формата нет');
$bot->conf = ['dpi' => ['fragment' => ['enabled' => 1]]];
$bot->dpiMenu();
dfAssert(str_ends_with($bot->callbacks()['/dpiToggle format'] ?? '', ': freedom') && str_contains(end($bot->texts), '26.3.27'), 'переключатель показан, по умолчанию freedom, с пояснением');
$bot->dpiToggle('format');
dfAssert(($bot->conf['dpi']['format'] ?? '') === 'finalmask', 'переключение на finalmask');
$bot->dpiMenu();
dfAssert(str_contains($bot->callbacks()['/dpiToggle format'] ?? '', 'finalmask (Xray 26.3.27+)'), 'кнопка показывает finalmask и нужную версию');
$bot->dpiToggle('format');
dfAssert(($bot->conf['dpi']['format'] ?? '') === 'freedom', 'и обратно на freedom');
require __DIR__ . '/../app/i18n.php';
foreach (['dpi format', 'dpi format freedom hint', 'dpi format finalmask hint', 'dpi format help'] as $key) {
    dfAssert(!empty($i[$key]['ru']) && !empty($i[$key]['en']) && preg_match('~[А-Яа-я]~u', $i[$key]['ru']) && !preg_match('~[А-Яа-я]~u', $i[$key]['en']), "перевод ru/en: $key");
}

if ($failed) exit(1);
echo "dpi_format_test OK\n";
