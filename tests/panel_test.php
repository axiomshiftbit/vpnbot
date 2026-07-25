<?php

/**
 * Проверки веб-панели (app/panel): хранилище ленты, транспорт Bot API,
 * подпись сессионной куки и санитайзер телеграмного HTML.
 *
 * Сети здесь нет и быть не должно: смысл транспорта именно в том, что
 * Bot::request() перестаёт ходить в api.telegram.org.
 */

require_once __DIR__ . '/../app/bot.php';
require_once __DIR__ . '/../app/panel/Panel.php';

function panelAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$dir = sys_get_temp_dir() . '/panel_test_' . bin2hex(random_bytes(4));
mkdir($dir, 0700, true);
register_shutdown_function(function () use ($dir) {
    foreach (glob("$dir/files/*") ?: [] as $f) {
        @unlink($f);
    }
    @rmdir("$dir/files");
    foreach (glob("$dir/*") ?: [] as $f) {
        @unlink($f);
    }
    @rmdir($dir);
});

/** Бот без конструктора: /config недоступен, а он тут и не нужен. */
class PanelTestBot extends Bot
{
    public $conf = [];

    public function __construct()
    {
    }

    public function getHashBot($notset = false)
    {
        return 'deadbeef';
    }

    public function getPacConf()
    {
        return $this->conf;
    }

    public function setPacConf(array $conf)
    {
        $this->conf = $conf;
    }
}

$store     = new PanelStore($dir);
$transport = new PanelTransport($store);

// ── Bot::request() уходит в транспорт, а не в сеть ───────────────────────────
$bot            = new PanelTestBot();
$bot->transport = $transport;
$bot->file      = $store->filesDir();

$r = $bot->send(777, "меню\n<b>жирный</b>", 0, [
    [['text' => 'A', 'callback_data' => '/menu']],
    [['text' => 'док', 'url' => 'https://example.com'], ['text' => 'редактор', 'web_app' => ['url' => 'https://d/pac1?t=te&ty=xray']]],
]);
$mid = $r['result']['message_id'] ?? 0;
panelAssert($mid >= PanelStore::ID_BASE, 'send() должен вернуть message_id панельного диапазона');

$msg = $store->read()['messages'][$mid];
panelAssert(str_contains($msg['text'], '<b>жирный</b>'), 'текст сохранён как есть');
panelAssert(count($msg['buttons']) === 2, 'две строки клавиатуры');
panelAssert($msg['buttons'][0][0]['cb'] === '/menu', 'callback_data разобран');
panelAssert(($msg['buttons'][1][1]['webapp'] ?? false) === true, 'web_app-кнопка помечена');

// ── правка и удаление ────────────────────────────────────────────────────────
$bot->update(777, $mid, 'обновлено', [[['text' => 'B', 'callback_data' => '/x']]]);
$msg = $store->read()['messages'][$mid];
panelAssert('обновлено' === $msg['text'], 'editMessageText правит текст');
panelAssert($msg['buttons'][0][0]['cb'] === '/x', 'editMessageText правит клавиатуру');

$miss = $transport->call('editMessageText', ['message_id' => 424242, 'text' => 'nope']);
panelAssert(empty($miss['ok']), 'правка несуществующего сообщения — ошибка, как в Telegram');

// ── force_reply ──────────────────────────────────────────────────────────────
$rp  = $bot->send(777, 'введите имя', 0, false, 'имя клиента');
$rid = $rp['result']['message_id'];
panelAssert($store->read()['messages'][$rid]['reply'] === 'имя клиента', 'force_reply превращается в подсказку ввода');

// ── тост ─────────────────────────────────────────────────────────────────────
$bot->answer('cbid', 'готово', true);
$st = $store->since(0);
panelAssert(($st['toast']['text'] ?? '') === 'готово' && $st['toast']['alert'], 'answerCallbackQuery → тост');
$bot->answer('cbid', false);
panelAssert(($store->read()['toast']['text'] ?? '') === 'готово', 'пустой answer тост не затирает');

// ── вложения и getFile ───────────────────────────────────────────────────────
$bot->sendFile(777, new CURLStringFile("cfg\n", 'peer.conf', 'text/plain'));
$last = array_key_last($store->read()['messages']);
$att  = $store->read()['messages'][$last]['attach'];
panelAssert('document' === $att['kind'] && 'peer.conf' === $att['name'], 'документ сохранён с исходным именем');
panelAssert(file_exists($store->filePath($att['file'])), 'файл лежит в хранилище');

$png = "$dir/qr.png";
file_put_contents($png, 'PNGDATA');
$bot->sendPhoto(777, curl_file_create($png), 'подпись');
$last = array_key_last($store->read()['messages']);
$att  = $store->read()['messages'][$last]['attach'];
panelAssert('photo' === $att['kind'], 'png определяется как фото');
unlink($png); // sendQr() удаляет файл сразу после отправки
panelAssert('PNGDATA' === file_get_contents($store->filePath($att['file'])), 'содержимое скопировано в момент отправки');

// file_id ↔ file_path: так импорт конфигов читает загруженное
$fid = $store->storeFile('{"a":1}', 'backup.json');
$g   = $transport->call('getFile', ['file_id' => $fid]);
panelAssert('{"a":1}' === file_get_contents($bot->file . $g['result']['file_path']), 'getFile + Bot::$file дают содержимое');
panelAssert(false === $store->filePath('../../etc/passwd'), 'выход за пределы папки файлов запрещён');

// ── инкрементальный опрос ────────────────────────────────────────────────────
$rev = $store->read()['rev'];
$bot->send(777, 'новое');
$diff = $store->since($rev);
panelAssert(count($diff['messages']) === 1 && 'новое' === $diff['messages'][0]['text'], 'since отдаёт только изменения');
$store->delete($mid);
$diff = $store->since($rev);
$del  = array_values(array_filter($diff['messages'], fn ($m) => $m['id'] === $mid));
panelAssert(!empty($del[0]['deleted']), 'удаление доезжает до UI');

// ── кука сессии ──────────────────────────────────────────────────────────────
$panel = new Panel($bot, ['key' => 'test-token:AAH', 'admin' => [111]], $store);
$panel->setPassword('correct horse');

$sign = (new ReflectionMethod(Panel::class, 'sign'));
$sign->setAccessible(true);
$exp = time() + 3600;

$_COOKIE['panel'] = $exp . '.' . $sign->invoke($panel, $exp);
panelAssert($panel->authed(), 'валидная кука пускает');

$_COOKIE['panel'] = $exp . '.' . str_repeat('0', 64);
panelAssert(!$panel->authed(), 'подделанная подпись не пускает');

$old              = time() - 10;
$_COOKIE['panel'] = $old . '.' . $sign->invoke($panel, $old);
panelAssert(!$panel->authed(), 'просроченная кука не пускает');

$_COOKIE['panel'] = $exp . '.' . $sign->invoke($panel, $exp);
$panel->setPassword('another one');
panelAssert(!$panel->authed(), 'смена пароля сбрасывает выданные сессии');

// Пока пароля нет, подпись куки считается по "panel|<exp>|" и ключу бота — на
// свежей установке он пуст, то есть кука подделывается кем угодно.
$noPass                  = new PanelTestBot();
$noPass->transport       = $transport;
$blank                   = new Panel($noPass, ['key' => 'test-token:AAH', 'admin' => [111]], $store);
$blankSign               = $sign->invoke($blank, $exp);
$_COOKIE['panel']        = $exp . '.' . $blankSign;
panelAssert(!$blank->authed(), 'без заданного пароля кука не пускает');
$noKey            = new Panel($bot, ['key' => '', 'admin' => [111]], $store);
$_COOKIE['panel'] = $exp . '.' . $sign->invoke($noKey, $exp);
panelAssert(!$noKey->authed(), 'без ключа бота кука не пускает');
unset($_COOKIE['panel']);

// pac.json недоступен/битый → getPacConf() отдаёт null. Записать поверх него
// конфиг из одного panelpswd означало бы потерять все настройки бота.
class PanelBrokenPacBot extends PanelTestBot
{
    public function getPacConf()
    {
        return null;
    }
}
$broken = new Panel(new PanelBrokenPacBot(), ['key' => 'k', 'admin' => [111]], $store);
$threw  = false;
try {
    $broken->setPassword('whatever!');
} catch (RuntimeException $e) {
    $threw = true;
}
panelAssert($threw, 'битый pac.json не затирается паролем панели');

// ── лимит попыток входа ──────────────────────────────────────────────────────
// Попытка записывается ДО проверки пароля и одной операцией под локом, иначе
// параллельные воркеры unit видели один и тот же счётчик.
$hit   = new ReflectionMethod(Panel::class, 'rateHit');
$clear = new ReflectionMethod(Panel::class, 'rateClear');
$rl    = new Panel($bot, ['key' => 'k', 'admin' => [111]], $store);
$clear->invoke($rl);
for ($i = 1; $i <= 5; $i++) {
    panelAssert($hit->invoke($rl), "попытка $i в пределах лимита");
}
panelAssert(!$hit->invoke($rl), 'шестая попытка за окно отклоняется');
$clear->invoke($rl);
panelAssert($hit->invoke($rl), 'удачный вход обнуляет счётчик');
$clear->invoke($rl);

// ── Host: защита от DNS rebinding ────────────────────────────────────────────
panelAssert(Panel::hostAllowed('127.0.0.1:8090'), 'loopback-адрес разрешён');
panelAssert(Panel::hostAllowed('localhost:8090'), 'localhost разрешён');
panelAssert(Panel::hostAllowed('[::1]:8090'), 'IPv6-loopback разрешён');
panelAssert(Panel::hostAllowed('10.0.0.5'), 'literal-IP разрешён: rebinding идёт по имени');
panelAssert(!Panel::hostAllowed('rebind.attacker.test:8090'), 'чужое имя в Host отклоняется');
panelAssert(!Panel::hostAllowed(''), 'пустой Host отклоняется');

// ── санитайзер телеграмного HTML ─────────────────────────────────────────────
$h = Panel::renderText('<b>ok</b> <script>alert(1)</script> <code>x</code>');
panelAssert(str_contains($h, '<b>ok</b>') && str_contains($h, '<code>x</code>'), 'белый список тегов сохраняется');
panelAssert(!str_contains($h, '<script>'), 'скрипт из текста экранирован');

$h = Panel::renderText('<a href="javascript:alert(1)">клик</a>');
panelAssert(!str_contains($h, 'javascript:'), 'javascript-ссылка выброшена');

$h = Panel::renderText('<a href="https://ok.test/x">клик</a>');
panelAssert(str_contains($h, '<a href="https://ok.test/x" target="_blank"'), 'http-ссылка остаётся ссылкой');

$h = Panel::renderText('<span class="tg-spoiler">секрет</span>');
panelAssert(str_contains($h, '<span class="tg-spoiler">секрет</span>'), 'спойлер сохраняется');

// В <pre> перенос уже отображается сам (white-space: pre-wrap) — <br> внутри
// давал бы двойные пустые строки во всех диагностиках и логах.
$h = Panel::renderText("шапка\n<pre>строка1\nстрока2</pre>\nхвост");
preg_match('~<pre>(.*?)</pre>~s', $h, $m);
panelAssert(!str_contains($m[1] ?? '<br>', '<br>'), 'внутри <pre> переносы не дублируются');
panelAssert(str_contains(explode('<pre>', $h)[0], '<br>'), 'вне <pre> переносы становятся <br>');

// ── опасные схемы в кнопках и вложениях ──────────────────────────────────────
$bot->send(777, 'ссылки', 0, [[
    ['text' => 'плохая', 'url' => 'javascript:alert(1)'],
    ['text' => 'хорошая', 'url' => 'https://ok.test'],
    ['text' => 'клиент', 'url' => 'vless://uuid@host'],
]]);
$btns = $store->read()['messages'][array_key_last($store->read()['messages'])]['buttons'][0];
panelAssert(count($btns) === 2, 'javascript-кнопка выброшена');
panelAssert($btns[1]['url'] === 'vless://uuid@host', 'deep-link клиента сохраняется');
panelAssert(null === (new ReflectionMethod(PanelTransport::class, 'ingest'))
    ->invoke($transport, 'data:text/html,<script>'), 'data:-вложение не создаётся');

// Браузер выбрасывает управляющие символы внутри схемы: "java\tscript:" — это
// javascript:. Проверка должна смотреть на ту же строку, что и он.
panelAssert(!PanelTransport::safeUrl("java\tscript:alert(1)"), 'схема с табом внутри не проходит');
panelAssert(!PanelTransport::safeUrl("java\nscript:alert(1)"), 'схема с переносом внутри не проходит');
panelAssert(!PanelTransport::safeUrl("\x01javascript:alert(1)"), 'управляющий символ перед схемой не спасает');
panelAssert(!PanelTransport::safeUrl(' DATA:text/html,x'), 'регистр и пробел схему не прячут');
panelAssert(PanelTransport::safeUrl('https://ok.test/a?b=c'), 'обычная ссылка проходит');
panelAssert(PanelTransport::safeUrl('sing-box://import?u=1'), 'deep-link клиента проходит');

// ── уборка загруженных файлов ────────────────────────────────────────────────
$orphan = $store->storeFile('x', 'old.json');
touch($store->filePath($orphan), time() - 90000);
$store->pruneUploads();
panelAssert(!$store->fileExists($orphan), 'старый загруженный файл удаляется');
$fresh = $store->storeFile('x', 'new.json');
$store->pruneUploads();
panelAssert($store->fileExists($fresh), 'свежий загруженный файл остаётся');
$att = $store->read()['messages'][$last]['attach'];
panelAssert($store->fileExists($att['file']), 'вложение сообщения уборкой не трогается');

// ── очистка ленты ────────────────────────────────────────────────────────────
// $fresh только что создан и ни к какому сообщению ещё не привязан — ровно тот
// случай, когда длинный обработчик уже записал вложение через storeFile(), но
// не успел отправить сообщение. Прежний reset() сносил такой файл, и в ленте
// оставался бабл с битой картинкой.
$store->reset();
panelAssert([] === $store->read()['messages'], 'reset() чистит ленту');
panelAssert(!$store->fileExists($att['file']), 'reset() удаляет вложения ленты');
panelAssert($store->fileExists($fresh), 'reset() не трогает файл, ещё не привязанный к сообщению');
touch($store->filePath($fresh), time() - 120);
$store->reset();
panelAssert(!$store->fileExists($fresh), 'осиротевший файл убирается следующей очисткой');

// ── откуда пускаем: слушатель виден всей docker-сети ─────────────────────────
$gw = (new ReflectionMethod(Panel::class, 'defaultGateway'))->invoke(null);
panelAssert(Panel::clientAllowed('127.0.0.1'), 'loopback пускаем');
panelAssert(Panel::clientAllowed('::1'), 'IPv6-loopback пускаем');
// xray-контейнер (10.10.0.9) ходит через freedom-outbound, которому разрешена
// вся 10.10.0.0/16 — так VPN-клиент дотягивался до панели на 10.10.0.7:8090.
panelAssert(!Panel::clientAllowed('10.10.0.9'), 'соседний контейнер не пускаем');
if ('10.10.0.1' !== $gw) {
    panelAssert(!Panel::clientAllowed('10.10.0.1'), 'чужой шлюз сам по себе не пускаем');
}
panelAssert(!Panel::clientAllowed(''), 'пустой адрес не пускаем');
panelAssert(!Panel::clientAllowed('не-адрес'), 'мусор вместо адреса не пускаем');
if ('' !== $gw) {
    panelAssert(Panel::clientAllowed($gw), 'шлюз своей сети (проброшенный порт и хост) пускаем');
}
putenv('PANEL_TRUSTED=10.10.0.0/24 203.0.113.7');
panelAssert(Panel::clientAllowed('10.10.0.9'), 'PANEL_TRUSTED открывает сеть по CIDR');
panelAssert(Panel::clientAllowed('203.0.113.7'), 'PANEL_TRUSTED открывает одиночный адрес');
panelAssert(!Panel::clientAllowed('10.10.1.9'), 'соседний CIDR не попадает под PANEL_TRUSTED');
putenv('PANEL_TRUSTED=*');
panelAssert(Panel::clientAllowed('198.51.100.4'), 'PANEL_TRUSTED=* снимает проверку');
putenv('PANEL_TRUSTED');
panelAssert(!Panel::clientAllowed('198.51.100.4'), 'без PANEL_TRUSTED внешний адрес закрыт');

echo "panel_test: OK\n";
