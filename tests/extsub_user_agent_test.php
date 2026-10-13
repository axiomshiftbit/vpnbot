<?php

// User-Agent, с которым бот забирает внешние подписки: значение по умолчанию,
// сохранение, сброс и отказ от значений, способных дописать заголовки.

require_once __DIR__ . '/../app/bot.php';

function uaAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

class ExtUaTestBot extends Bot
{
    public array $sent = [];
    public int $menus = 0;

    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false)
    {
        $this->sent[] = $text;
    }

    public function extUser($i)
    {
        $this->menus++;
    }
}

$pac = sys_get_temp_dir() . '/vpnbot-extua-' . getmypid() . '.json';
try {
    $bot = (new ReflectionClass(ExtUaTestBot::class))->newInstanceWithoutConstructor();
    $bot->pac = $pac;
    $bot->input = ['chat' => 1, 'from' => 1, 'message_id' => 2];
    file_put_contents($pac, json_encode(['domain' => 'example.test']));

    uaAssert($bot->extSubUserAgent() === Bot::EXT_SUB_USER_AGENT, 'default User-Agent mismatch');

    $bot->extUASave(' Happ/2.1.0 (iOS) ', 0);
    uaAssert($bot->extSubUserAgent() === 'Happ/2.1.0 (iOS)', 'User-Agent was not saved');
    uaAssert((json_decode(file_get_contents($pac), true)['domain'] ?? '') === 'example.test', 'other settings were lost');

    foreach (["a\r\nX-Evil: 1", "a\nb", 'клиент', str_repeat('a', 201), "tab\there"] as $bad) {
        uaAssert(!Bot::extSubUserAgentValid($bad), 'bad User-Agent accepted: ' . json_encode($bad));
    }
    $bot->sent = [];
    $bot->extUASave('клиент/1.0', 0);
    uaAssert($bot->extSubUserAgent() === 'Happ/2.1.0 (iOS)' && count($bot->sent) === 1, 'invalid value changed the setting');

    // Значение, испорченное в pac.json в обход бота, в запрос не уходит.
    file_put_contents($pac, json_encode(['extsub_user_agent' => "x\r\nHost: evil"]));
    uaAssert($bot->extSubUserAgent() === Bot::EXT_SUB_USER_AGENT, 'tampered User-Agent reached the request');

    $bot->extUASave('Happ/2.1.0', 0);
    $bot->extUASave('-', 0);
    uaAssert(!array_key_exists('extsub_user_agent', json_decode(file_get_contents($pac), true)), 'reset kept the setting');
    uaAssert($bot->menus === 4, 'menu was not redrawn after each reply');

    echo "extsub_user_agent_test OK\n";
} finally {
    @unlink($pac);
}
