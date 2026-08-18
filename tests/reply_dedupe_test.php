<?php

// Reply-state должен потребляться ДО долгого callback. Иначе повтор одного и
// того же webhook Telegram успевает выполнить callback второй раз (особенно
// заметно на добавлении OpenConnect/OpenVPN/L2TP/IPsec/IKEv2/TrustTunnel) и в
// чате появляются две карточки/два меню.

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function replyDedupeAssert(bool $condition, string $message): void
{
    global $failed;
    if (!$condition) {
        $failed++;
        echo "FAIL: $message\n";
    }
}

class ReplyDedupeTestBot extends Bot
{
    public int $calls = 0;
    public array $deleted = [];
    public bool $wouldEditMenu = false;

    public function delete($chat, $message_id)
    {
        $this->deleted[] = [$chat, $message_id];
    }

    public function testReplyCallback($message, $suffix)
    {
        $this->calls++;
        $this->wouldEditMenu = $this->replyMenuEdit;
        replyDedupeAssert($message === 'alice', 'callback получил не текст ответа');
        replyDedupeAssert($suffix === 'ok', 'callback потерял сохранённые args');
    }

    public function replyMenuEditActive(): bool
    {
        return $this->replyMenuEdit;
    }
}

ini_set('session.use_cookies', '0');
session_save_path(sys_get_temp_dir());
$sid = 'replydedupe' . bin2hex(random_bytes(6));

$bot = (new ReflectionClass(ReplyDedupeTestBot::class))->newInstanceWithoutConstructor();
$bot->input = [
    'from'       => $sid,
    'chat'       => 777,
    'reply'      => 901,
    'message_id' => 902,
    'message'    => 'alice',
];
$bot->stashReply(['result' => ['message_id' => 901]], [
    'start_message' => 900,
    'callback'      => 'testReplyCallback',
    'args'          => ['ok'],
]);

$bot->reply();
replyDedupeAssert($bot->calls === 1, 'первый webhook не выполнил callback');
replyDedupeAssert($bot->input['message_id'] === 900, 'меню не привязано к исходному сообщению');
replyDedupeAssert(count($bot->deleted) === 2, 'prompt и ответ должны удалиться ровно один раз');
replyDedupeAssert($bot->wouldEditMenu, 'menu() во время reply отправил бы новое окно вместо редактирования исходного');
replyDedupeAssert(!$bot->replyMenuEditActive(), 'флаг редактирования меню не сбросился после reply callback');

// Эмулируем повтор того же webhook. В памяти могла остаться старая копия
// $_SESSION, но takeReply() обязан перечитать файл под lock и увидеть, что
// state уже забран первым обработчиком.
$bot->input['message_id'] = 902;
$bot->reply();
replyDedupeAssert($bot->calls === 1, 'повтор webhook выполнил callback второй раз');
replyDedupeAssert(count($bot->deleted) === 2, 'повтор webhook снова удалял сообщения');

// Все названные пользовательские сценарии действительно регистрируют ввод
// имени через тот же stashReply → reply путь, который проверен выше.
$source = (string) file_get_contents(__DIR__ . '/../app/bot.php');
replyDedupeAssert(
    str_contains($source, "if (!empty(\$this->input['callback_id']) || \$this->replyMenuEdit)"),
    'menu() не учитывает reply-контекст и снова создаст второе окно'
);
foreach ([
    'addOcUser'    => 'addocus',
    'addOvpnUser'  => 'addovus',
    'addL2tpUser'  => 'addl2us',
    'addIkev2User' => 'addik2us',
    'addTtUser'    => 'addttus',
] as $prompt => $callback) {
    replyDedupeAssert(
        (bool) preg_match(
            '~public function ' . preg_quote($prompt, '~')
                . '\(\).*?stashReply\(\$r, \[.*?[\'\"]callback[\'\"]\s*=>\s*[\'\"]'
                . preg_quote($callback, '~') . '[\'\"]~s',
            $source
        ),
        "$prompt не проходит через общий защищённый reply-механизм"
    );
}

@unlink(sys_get_temp_dir() . '/sess_' . $sid);

if ($failed) {
    echo "reply_dedupe_test FAILED ($failed)\n";
    exit(1);
}
echo "reply_dedupe_test OK\n";
