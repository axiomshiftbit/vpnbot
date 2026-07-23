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
unset($_COOKIE['panel']);

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

// ── очистка ленты ────────────────────────────────────────────────────────────
$store->reset();
panelAssert([] === $store->read()['messages'], 'reset() чистит ленту');
panelAssert([] === (glob("$dir/files/*") ?: []), 'reset() чистит файлы');

echo "panel_test: OK\n";
