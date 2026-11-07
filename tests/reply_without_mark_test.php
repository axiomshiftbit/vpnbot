<?php

// Ответ на запрос бота без пометки reply (вставка в Telegram Desktop, закрытая
// панель ответа) раньше молча отменял запрос: ссылка оставалась в чате и не
// применялась, приходилось нажимать кнопку и вставлять второй раз.

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function replyMarkAssert(bool $condition, string $message): void
{
    global $failed;
    if (!$condition) {
        $failed++;
        echo "FAIL: $message\n";
    }
}

class ReplyMarkTestBot extends Bot
{
    public array $calls = [];
    public array $deleted = [];

    public function delete($chat, $message_id)
    {
        $this->deleted[] = (int) $message_id;
    }

    public function testLinkCallback($message, $tag)
    {
        $this->calls[] = [$message, $tag];
    }
}

ini_set('session.use_cookies', '0');
session_save_path(sys_get_temp_dir());

function replyMarkBot(array $input): ReplyMarkTestBot
{
    $bot = (new ReflectionClass(ReplyMarkTestBot::class))->newInstanceWithoutConstructor();
    // Личный чат: id чата совпадает с id отправителя.
    $bot->input = $input + ['chat' => $input['from'], 'reply' => false, 'callback' => false, 'group' => false, 'file_id' => false, 'message' => ''];
    return $bot;
}

function replyMarkStash(ReplyMarkTestBot $bot, int $prompt, string $tag): void
{
    $saved = $bot->input;
    $bot->input['message_id'] = 100;
    $bot->stashReply(['result' => ['message_id' => $prompt]], ['start_message' => 100, 'callback' => 'testLinkCallback', 'args' => [$tag]]);
    $bot->input = $saved;
}

// 1. Вставка без reply применяется к последнему запросу; старый запрос отменяется.
$sid = 'replymark' . bin2hex(random_bytes(6));
$bot = replyMarkBot(['from' => $sid, 'message_id' => 205, 'message' => 'vless://example@node.invalid:443?type=tcp#n']);
replyMarkStash($bot, 201, 'old');
replyMarkStash($bot, 203, 'new');
$bot->session();
session_write_close();
replyMarkAssert($bot->input['reply'] === 203, 'обычное сообщение не привязано к последнему запросу');
replyMarkAssert($bot->deleted === [201], 'старый запрос не отменён или отменён не тот');
$bot->reply();
replyMarkAssert(count($bot->calls) === 1 && $bot->calls[0][1] === 'new', 'ответ не применён к последнему запросу');
replyMarkAssert($bot->calls[0][0] === 'vless://example@node.invalid:443?type=tcp#n', 'callback получил не текст сообщения');
replyMarkAssert(in_array(205, $bot->deleted, true) && in_array(203, $bot->deleted, true), 'сообщение со ссылкой или запрос не удалены');

// 2. Команда отменяет запрос, а не становится ответом.
$sid = 'replymark' . bin2hex(random_bytes(6));
$bot = replyMarkBot(['from' => $sid, 'message_id' => 305, 'message' => '/menu']);
replyMarkStash($bot, 301, 'x');
$bot->session();
session_write_close();
replyMarkAssert($bot->input['reply'] === false, 'команда принята как ответ на запрос');
replyMarkAssert($bot->deleted === [301], 'команда не отменила запрос');

// 3. Нажатие кнопки по-прежнему отменяет запрос.
$sid = 'replymark' . bin2hex(random_bytes(6));
$bot = replyMarkBot(['from' => $sid, 'message_id' => 405, 'message' => 'текст меню', 'callback' => '/menu']);
replyMarkStash($bot, 401, 'x');
$bot->session();
session_write_close();
replyMarkAssert($bot->input['reply'] === false && $bot->deleted === [401], 'кнопка не отменила запрос');

// 4. В группе обычные сообщения не перехватываются.
$sid = 'replymark' . bin2hex(random_bytes(6));
$bot = replyMarkBot(['from' => $sid, 'message_id' => 505, 'message' => 'привет', 'group' => true]);
replyMarkStash($bot, 501, 'x');
$bot->session();
session_write_close();
replyMarkAssert($bot->input['reply'] === false, 'сообщение в группе перехвачено как ответ');

// 5. Ответ с пометкой reply работает как раньше.
$sid = 'replymark' . bin2hex(random_bytes(6));
$bot = replyMarkBot(['from' => $sid, 'message_id' => 605, 'message' => 'vless://a@b.invalid:443', 'reply' => 601]);
replyMarkStash($bot, 601, 'marked');
$bot->session();
session_write_close();
$bot->reply();
replyMarkAssert(count($bot->calls) === 1 && $bot->calls[0][1] === 'marked', 'ответ с пометкой reply не обработан');

// 6. Давно брошенный запрос не принимает случайное сообщение: он отменяется.
$sid = 'replymark' . bin2hex(random_bytes(6));
$bot = replyMarkBot(['from' => $sid, 'message_id' => 705, 'message' => 'привет']);
replyMarkStash($bot, 701, 'stale');
$bot->input['from'] = $sid; session_id($sid); session_start(); $_SESSION['reply']["$sid:701"]['time'] = time() - 3600; session_write_close();
$bot->session();
session_write_close();
replyMarkAssert($bot->input['reply'] === false && $bot->deleted === [701], 'устаревший запрос перехватил сообщение');

// 7. Супергруппа (type=supergroup, отрицательный id чата): обычное сообщение не ответ.
$sid = 'replymark' . bin2hex(random_bytes(6));
$bot = replyMarkBot(['from' => $sid, 'chat' => -1001234567890, 'message_id' => 805, 'message' => 'сообщение в супергруппе']);
replyMarkStash($bot, 801, 'x');
$bot->session();
session_write_close();
replyMarkAssert($bot->input['reply'] === false, 'сообщение в супергруппе перехвачено как ответ');

if ($failed) {
    echo "FAILED: $failed\n";
    exit(1);
}
echo "OK reply_without_mark_test\n";
