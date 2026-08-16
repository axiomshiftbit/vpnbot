<?php

// Ядро: диспетчер, ответы на промпты, разбиение сообщений.
// Регрессии из аудита 2026-08-12 (K5 и раздел «Ядро / диспетчер / транспорт»):
//  - input(): пер-запросный $this->wg не сбрасывался между апдейтами, и в
//    polling (один объект Bot на все апдейты) инстанс WG «залипал»;
//  - splitText(): одна длинная строка без \n не резалась вовсе, кусок уходил
//    в Telegram целиком и отвергался с «message is too long»;
//  - answer(): не выставлял $this->callback, и callbackCheck() слал второй
//    answerCallbackQuery на тот же id;
//  - auth(): при первом апдейте без 'from' в config.php уезжало
//    array(0 => NULL), после чего бот навсегда оставался без админа.

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function coreAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

class CoreTestBot extends Bot
{
    public array $requests = [];
    public array $pacFake  = [];

    public function getPacConf()
    {
        return $this->pacFake;
    }

    public function request($method, $data = [], $post = true)
    {
        $this->requests[] = [$method, $data];
        return ['ok' => true, 'result' => ['message_id' => 1]];
    }

    // input() зовёт auth()/session()/action(); здесь проверяется только
    // подготовка $this->input, поэтому диспетчер отключаем.
    public function auth()
    {
        $this->admin = false;
    }
}

$bot = (new ReflectionClass(CoreTestBot::class))->newInstanceWithoutConstructor();

// ── 1. $this->wg не переживает апдейт ───────────────────────────────────────
$bot->wg = 1;
$bot->input(['message' => ['message_id' => 5, 'chat' => ['id' => 7], 'from' => ['id' => 7], 'text' => '/delete 3']]);
coreAssert($bot->wg === null,
    'инстанс WG сброшен новым апдейтом (иначе операция уйдёт в чужой инстанс)');
$bot->pacFake = [];
coreAssert($bot->getInstanceWG() === 'wg', 'после сброса резолвится нулевой инстанс');

// Неучтённый тип апдейта не должен сыпать warning'ами и обязан дать null.
$bot->input(['poll_answer' => ['poll_id' => '1', 'option_ids' => [0]]]);
coreAssert($bot->input['from'] === null, 'from = null для poll_answer');
coreAssert($bot->input['chat'] === null, 'chat = null для poll_answer');
coreAssert($bot->input['message_id'] === null, 'message_id = null для poll_answer');

// ── 2. splitText ────────────────────────────────────────────────────────────
// Одна длинная строка без переводов.
$one = str_repeat('a', 10000);
$parts = $bot->splitText($one, 4096);
coreAssert(count($parts) >= 3, 'длинная строка разбита: ' . count($parts));
foreach ($parts as $i => $p) {
    coreAssert(mb_strlen($p, 'utf-8') <= 4096 + 1, "кусок $i не длиннее лимита: " . mb_strlen($p, 'utf-8'));
}
coreAssert(str_replace("\n", '', implode('', $parts)) === $one, 'содержимое не потеряно');

// Много коротких строк: перевод строки учитывается в длине куска.
$many  = implode("\n", array_fill(0, 3000, 'line'));
$parts = $bot->splitText($many, 4096);
foreach ($parts as $i => $p) {
    coreAssert(mb_strlen($p, 'utf-8') <= 4096 + 1, "кусок $i с учётом \\n: " . mb_strlen($p, 'utf-8'));
}
coreAssert(substr_count(implode('', $parts), 'line') === 3000, 'все строки на месте');

// Короткий текст остаётся одним куском.
$parts = $bot->splitText("a\nb", 4096);
coreAssert(count($parts) === 1, 'короткий текст не дробится');
coreAssert(trim($parts[0]) === "a\nb", 'короткий текст не искажён');
coreAssert($bot->splitText('', 4096) === [''], 'пустой текст переживает разбиение');

// ── 3. update() режет длинный текст ─────────────────────────────────────────
$bot->requests = [];
$bot->update(7, 5, str_repeat('b', 8000));
$methods = array_column($bot->requests, 0);
coreAssert(in_array('editMessageText', $methods, true), 'редактирование выполнено');
coreAssert(in_array('sendMessage', $methods, true), 'хвост дослан отдельными сообщениями');
foreach ($bot->requests as [$m, $d]) {
    coreAssert(mb_strlen((string) $d['text'], 'utf-8') <= 4096, "$m: текст в пределах лимита");
}

// ── 4. answer() отмечает, что на callback уже ответили ──────────────────────
$bot->callback = false;
$bot->input    = ['callback_id' => 'q1', 'callback' => '/menu'];
$bot->requests = [];
$bot->answer('q1', 'обновлено');
coreAssert($bot->callback === true, 'флаг выставлен');
$GLOBALS['debug'] = false;
$bot->callbackCheck();
coreAssert(count(array_filter($bot->requests, fn($r) => $r[0] === 'answerCallbackQuery')) === 1,
    'второй answerCallbackQuery не отправлен');
// Без ответа обработчика callbackCheck отвечает сам.
$bot->callback = false;
$bot->requests = [];
$bot->callbackCheck();
coreAssert(count($bot->requests) === 1, 'на неотвеченный callback ответ уходит');

if ($failed) {
    echo "audit_core_test FAILED: $failed\n";
    exit(1);
}
echo "audit_core_test OK\n";
