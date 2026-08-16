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

// Dual-stack слушатель отдаёт loopback как «::ffff:127.0.0.1»: побайтовое
// сравнение v6 (16 байт) с правилом v4 (4 байта) не совпало бы никогда, и
// панель ответила бы 403 самому админу.
panelAssert(Panel::clientAllowed('::ffff:127.0.0.1'), 'IPv4-mapped loopback пускаем');
panelAssert(!Panel::clientAllowed('::ffff:10.10.0.9'), 'IPv4-mapped адрес контейнера по-прежнему закрыт');
putenv('PANEL_TRUSTED=10.10.0.0/24');
panelAssert(Panel::clientAllowed('::ffff:10.10.0.9'), 'IPv4-mapped адрес попадает под CIDR из PANEL_TRUSTED');
putenv('PANEL_TRUSTED');

// ── массивы в query/POST не должны быть фаталом ──────────────────────────────
// preg_match с массивом во втором аргументе — TypeError, то есть 500 вместо
// ответа. Для /pac<hash>?t=te этот путь вообще не аутентифицирован.
$tload = new ReflectionMethod(Panel::class, 'tload');
$tload->setAccessible(true);
$_POST = ['ty' => ['x'], 'te' => ['y']];
ob_start();
$tload->invoke($panel);
$outJson = json_decode((string) ob_get_clean(), true);
panelAssert(is_array($outJson) && false === ($outJson['status'] ?? null), 'tload с ty[] отвечает, а не падает');

$editor = new ReflectionMethod(Panel::class, 'editor');
$editor->setAccessible(true);
$_GET = ['ty' => ['x']];
ob_start();
$editor->invoke($panel);
panelAssert('' === trim((string) ob_get_clean()), 'editor с ty[] отвечает пустым 404, а не падает');
$_GET = $_POST = [];

// ── шаблоны: тип/имя/тело из POST приходят как есть ──────────────────────────
$tpl = new PanelTestBot();
panelAssert(false === $tpl->saveTemplate('origin', '../app/x', '{}')['status'], 'type с траверсалом отвергается');
panelAssert(false === $tpl->saveTemplate(['a'], 'xray', '{}')['status'], 'name массивом отвергается');
panelAssert(false === $tpl->saveTemplate('t', ['xray'], '{}')['status'], 'type массивом отвергается');
panelAssert(false === $tpl->saveTemplate('t', 'xray', ['{}'])['status'], 'json массивом отвергается');
panelAssert(false === $tpl->saveTemplate('', 'xray', '{}')['status'], 'пустое имя отвергается');

// ── битые байты в ленте не должны стирать её целиком ─────────────────────────
// json_encode() возвращает FALSE на невалидном UTF-8, а file_put_contents($f,
// false) пишет пустой файл и рапортует об успехе: прежний save() подменял бы
// state.json нулями, теряя всю переписку.
$store->reset();
$keep = $store->put(['text' => 'важное']);
$store->put(['text' => "вывод \xB1\x31 команды"]);
$after = $store->read();
panelAssert(isset($after['messages'][$keep]), 'сообщение с битыми байтами не уносит ленту с собой');
panelAssert(count($after['messages']) === 2, 'битый текст сохраняется с подстановкой, а не теряется');

// ── мультиадминство: подпись/аутентификация несёт выбранного админа ─────────
$multi = new Panel($bot, ['key' => 'test-token:AAH', 'admin' => [111, 222]], $store);
$sign2 = new ReflectionMethod(Panel::class, 'sign');
$sign2->setAccessible(true);

$exp2 = time() + 3600;
$_COOKIE['panel'] = $exp2 . '.222.' . $sign2->invoke($multi, $exp2, 222);
panelAssert($multi->authed(), 'валидная кука с явным admin=222 пускает');

$chatId2 = new ReflectionMethod(Panel::class, 'chatId');
$chatId2->setAccessible(true);
panelAssert(222 === $chatId2->invoke($multi), 'chatId() отражает выбранного при логине админа');

$_COOKIE['panel'] = $exp2 . '.999.' . $sign2->invoke($multi, $exp2, 999);
panelAssert(!$multi->authed(), 'id вне $c[admin] не пускает, даже с верной по форме подписью');

// Подмена id в куке без пересчёта HMAC не должна давать доступ от чужого имени.
$validCookie      = $exp2 . '.111.' . $sign2->invoke($multi, $exp2, 111);
[$e2, , $sig2]     = explode('.', $validCookie, 3);
$_COOKIE['panel'] = "$e2.222.$sig2";
panelAssert(!$multi->authed(), 'подмена admin в куке без пересчёта подписи отклоняется');

// Старый двухчастный формат (единственный админ) на мультиадминной панели
// по-прежнему аутентифицирует, но всегда как admins[0] — иначе апгрейд с
// одного админа на двух молча выкинул бы всех, у кого кука ещё старого вида.
$_COOKIE['panel'] = $exp2 . '.' . $sign2->invoke($multi, $exp2);
panelAssert($multi->authed(), 'легаси-кука (2 части) валидна и на мультиадминной панели');
panelAssert(111 === $chatId2->invoke($multi), 'легаси-кука всегда резолвится в admins[0]');
unset($_COOKIE['panel']);

// ── диагностика панели ───────────────────────────────────────────────────────
$_COOKIE['panel'] = $exp2 . '.222.' . $sign2->invoke($multi, $exp2, 222);
panelAssert($multi->authed(), 'кука для diag()-проверки валидна');
$diag = new ReflectionMethod(Panel::class, 'diag');
$diag->setAccessible(true);
ob_start();
$diag->invoke($multi);
$diagOut = json_decode((string) ob_get_clean(), true);
panelAssert(true === ($diagOut['ok'] ?? null), 'diag() отвечает ok');
panelAssert(222 === ($diagOut['admin'] ?? null), 'diag() отражает выбранного админа');
panelAssert(2 === ($diagOut['admin_count'] ?? null), 'diag() считает всех настроенных админов');
panelAssert(($diagOut['ttl'] ?? 0) > 0 && $diagOut['ttl'] <= 3600, 'diag() отдаёт остаток TTL сессии');
unset($_COOKIE['panel']);

// ── удаление одного сообщения из ленты (dismiss) ─────────────────────────────
$dismissId = $store->put(['text' => 'уберите меня']);
panelAssert(!($store->read()['messages'][$dismissId]['deleted'] ?? false), 'сообщение перед dismiss() ещё живое');
$_POST      = ['message_id' => $dismissId];
$dismiss    = new ReflectionMethod(Panel::class, 'dismiss');
$dismiss->setAccessible(true);
ob_start();
$dismiss->invoke($panel);
$dismissOut = json_decode((string) ob_get_clean(), true);
$_POST      = [];
panelAssert(true === ($dismissOut['ok'] ?? null), 'dismiss() отвечает ok');
panelAssert(!empty($store->read()['messages'][$dismissId]['deleted']), 'dismiss() помечает сообщение удалённым, как и Store::delete()');

// ── login() на мультиадминной панели требует известный admin в POST ─────────
$clear->invoke($multi); // счётчик попыток общий с $panel — сбрасываем перед проверкой
$login = new ReflectionMethod(Panel::class, 'login');
$login->setAccessible(true);

$_POST = ['password' => 'another one', 'admin' => 222];
ob_start();
$login->invoke($multi);
$loginOut = json_decode((string) ob_get_clean(), true);
panelAssert(true === ($loginOut['ok'] ?? null) && 222 === ($loginOut['admin'] ?? null), 'login() с известным admin пускает и возвращает его id');

$clear->invoke($multi);
$_POST = ['password' => 'another one', 'admin' => 555];
ob_start();
$login->invoke($multi);
$loginOut2 = json_decode((string) ob_get_clean(), true);
panelAssert(false === ($loginOut2['ok'] ?? null) && 'unknown admin' === ($loginOut2['error'] ?? null), 'login() с чужим admin отклоняется, не выдавая куку');
$_POST = [];
$clear->invoke($multi);

echo "panel_test: OK\n";
