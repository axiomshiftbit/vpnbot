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

// ── Падение обработчика не должно быть немым ───────────────────────────────
// state забирается ДО вызова callback (иначе повтор webhook выполнит действие
// дважды), prompt и ответ уже удалены — повторить нечего. Значит исключение
// обязано превратиться в видимое сообщение, а не в «бот съел сообщение».
class ReplyFailureTestBot extends Bot
{
    public array $sent = [];
    public int $menus  = 0;

    public function delete($chat, $message_id) {}
    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false)
    {
        $this->sent[] = (string) $text;
    }
    public function menu($type = false, $arg = false, $return = false)
    {
        $this->menus++;
    }
    public function i18n(string $menu): string
    {
        return $menu;
    }
    public function boom($message)
    {
        throw new RuntimeException('easyrsa упал');
    }
    public function isReplyMenuEdit(): bool
    {
        return $this->replyMenuEdit;
    }
}

$sid2 = 'replyfail' . bin2hex(random_bytes(6));
$failBot = (new ReflectionClass(ReplyFailureTestBot::class))->newInstanceWithoutConstructor();
$failBot->input = [
    'from'       => $sid2,
    'chat'       => 777,
    'reply'      => 901,
    'message_id' => 902,
    'message'    => 'alice',
];
$failBot->stashReply(['result' => ['message_id' => 901]], [
    'start_message' => 900,
    'callback'      => 'boom',
    'args'          => [],
]);
$errLog = sys_get_temp_dir() . '/replyfail_' . bin2hex(random_bytes(4)) . '.log';
$prevErrLog = ini_get('error_log');
ini_set('error_log', $errLog);          // ожидаемая запись не должна шуметь в выводе теста
$failBot->reply();
ini_set('error_log', (string) $prevErrLog);
replyDedupeAssert(str_contains((string) @file_get_contents($errLog), 'reply(boom)'),
    'падение обработчика пишется в журнал');
@unlink($errLog);
replyDedupeAssert(
    (bool) array_filter($failBot->sent, fn($t) => str_contains($t, 'easyrsa упал')),
    'падение обработчика показывается пользователю, а не теряется молча'
);
replyDedupeAssert($failBot->menus === 1, 'после ошибки меню перерисовывается, чтобы можно было повторить');
replyDedupeAssert(!$failBot->isReplyMenuEdit(), 'флаг редактирования меню сброшен после исключения');

// Перерисовка меню тем же текстом («message is not modified») обязана оставить
// подтверждение: сообщение пользователя уже удалено, иначе он не видит НИЧЕГО.
$botSource2 = (string) file_get_contents(__DIR__ . '/../app/bot.php');
replyDedupeAssert(str_contains($botSource2, "stripos((string) (\$r['description'] ?? ''), 'not modified')"),
    'ответ Telegram «not modified» распознаётся');
replyDedupeAssert(
    (bool) preg_match('~replyMenuEdit && is_array\(\$r\) && empty\(\$r\[.ok.\]\)~', $botSource2),
    'подтверждение шлётся только для пути ответа на промпт'
);

@unlink(sys_get_temp_dir() . '/sess_' . $sid2);
@unlink(sys_get_temp_dir() . '/sess_' . $sid);

if ($failed) {
    echo "reply_dedupe_test FAILED ($failed)\n";
    exit(1);
}
echo "reply_dedupe_test OK\n";
