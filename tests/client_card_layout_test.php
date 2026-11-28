<?php

require_once __DIR__ . '/../app/bot.php';
require_once __DIR__ . '/../app/panel/PanelTransport.php';
require __DIR__ . '/../app/i18n.php';

function cardAssert(bool $ok, string $message): void
{
    if (!$ok) throw new RuntimeException($message);
}

class CardCaptureTransport
{
    public array $calls = [];
    public function call($method, $data, $json = 0)
    {
        $this->calls[] = [$method, $data];
        return ['ok' => true, 'result' => ['message_id' => 1]];
    }
}

class CardLayoutBot extends Bot
{
    public array $testPac;
    public array $testXr;
    public function __construct(array $translations, string $auth, bool $mldsa)
    {
        $this->language = 'ru';
        $this->i18n = $translations;
        $this->ip = '192.0.2.1';
        $this->input = ['chat' => 1, 'from' => 1, 'message_id' => 1, 'callback_id' => 'test'];
        $key = fn(int $bytes) => rtrim(strtr(base64_encode(str_repeat('a', $bytes)), '+/', '-_'), '=');
        $this->testPac = array_replace(self::PAC_DEFAULTS, [
            'transport' => 'Reality', 'fingerprint' => 'chrome', 'xray' => $key(32),
            'hwid_device_count' => 1, 'defaultsingtemplate' => '', 'defaultv2raytemplate' => '', 'defaultclashtemplate' => '',
            'reality' => ['domain' => 'example.test', 'shortId' => '1234', 'mldsa' => $mldsa,
                'mldsa65Seed' => $key(32), 'mldsa65Verify' => $key(1952)],
            'relays' => ['Реле & # 🇷🇺' => ['address' => 'relay.test', 'awg_address' => '']],
        ]);
        $this->testXr = ['inbounds' => [[
            'protocol' => 'vless', 'settings' => ['clients' => [[
                'id' => '11111111-2222-4333-8444-555555555555', 'subtoken' => str_repeat('c', 32),
                'email' => "Тест 🇷🇺 & # + ' <узел>", 'time' => 0, 'off' => 0, 'hwid_limit' => 0,
                'singtemplate' => '', 'v2raytemplate' => '', 'clashtemplate' => '',
            ]]],
            'streamSettings' => ['realitySettings' => ['serverNames' => ['example.test'], 'shortIds' => ['1234']]],
        ]]];
        if ($auth !== 'off') {
            [$server, $client] = VlessEncryption::KEY_BYTES[$auth];
            $this->testPac['vless_encryption'] = ['enabled' => true, 'auth' => $auth, 'mode' => 'native',
                'decryption' => 'mlkem768x25519plus.native.600s.' . $key($server),
                'encryption' => 'mlkem768x25519plus.native.0rtt.' . $key($client)];
        }
        VlessEncryption::applyServer($this->testXr, $this->testPac);
    }
    public function getPacConf() { return $this->testPac; }
    public function getXray() { return $this->testXr; }
    public function getDomain($cdn = false) { return 'vpn.example.test'; }
    public function getHashBot($notset = false) { return '12345678'; }
    public function nginxGetTypeCert() { return 'letsencrypt'; }
    public function getHwidDevicesByUser($uid) { return []; }
    public function getXrayStats() { return []; }
    public function readRelayHealth(): array { return []; }
    public function flagName(string $name, string|array $hosts, bool $cacheOnly = true): string { return $name; }
    public function xrayCoreProbe(bool $fresh = false): array
    {
        return ['ok' => true, 'active' => 'origin', 'running' => 'origin', 'version' => 'Xray 26.9.9'];
    }
}

$tmp = sys_get_temp_dir() . '/vpnbot-card-' . bin2hex(random_bytes(4));
mkdir($tmp, 0700);
register_shutdown_function(function () use ($tmp) {
    foreach (glob($tmp . '/*') ?: [] as $dir) {
        foreach (glob($dir . '/*') ?: [] as $file) if (is_file($file)) unlink($file);
        if (is_dir($dir . '/files')) rmdir($dir . '/files');
        rmdir($dir);
    }
    rmdir($tmp);
});

foreach ([['off', false], ['x25519', false], ['mlkem768', false], ['off', true], ['mlkem768', true]] as $n => [$auth, $mldsa]) {
    $bot = new CardLayoutBot($i, $auth, $mldsa);
    $capture = new CardCaptureTransport();
    $bot->transport = $capture;
    $bot->userXr(0);
    cardAssert(count($capture->calls) === 1 && $capture->calls[0][0] === 'editMessageText',
        "$auth/mldsa=$mldsa: карточка не рассыпается на сообщения вокруг кнопок");
    $card = $capture->calls[0][1];
    $visible = html_entity_decode(strip_tags($card['text']), ENT_QUOTES | ENT_HTML5, 'UTF-8');
    cardAssert(mb_strlen($visible, 'UTF-8') <= 4096, 'карточка укладывается в лимит Telegram');
    foreach (['xray config:', 'sing-box config:', 'mihomo config:', 'Happ / v2rayNG (base64):'] as $label) {
        cardAssert(str_contains($card['text'], $label), "$label остаётся над клавиатурой в том же сообщении");
    }
    cardAssert(substr_count($card['text'], 'import://') === 10 && str_contains($card['text'], 'import://Happ'), 'все ссылки импорта сохранены, включая INCY');
    $buttons = json_decode($card['reply_markup'], true)['inline_keyboard'];
    cardAssert(end($buttons)[0]['callback_data'] === '/xray', 'кнопка возврата сохранена');
    $plainLink = $bot->linkXray(0);
    $fileButton = array_filter(array_merge(...$buttons), fn($b) => ($b['callback_data'] ?? '') === '/dw 0 uri');
    if ($fileButton) {
        $capture->calls = [];
        $bot->dw(0, 'uri');
        $file = $capture->calls[0][1]['document'] ?? null;
        cardAssert(count($capture->calls) === 1 && $capture->calls[0][0] === 'sendDocument', 'длинная ссылка скачивается файлом');
        cardAssert($file instanceof CURLStringFile && $file->data === $plainLink, 'URI не обрезан и не разбит переносами');
        cardAssert(str_ends_with($file->postname, '_uri.txt') && !str_contains($file->postname, '/'), 'имя файла безопасно');
    } else {
        cardAssert(str_contains(html_entity_decode($card['text'], ENT_QUOTES | ENT_HTML5, 'UTF-8'), $plainLink), 'короткая ссылка остаётся копируемой');
    }
    if ($auth === 'mlkem768' && $mldsa) cardAssert((bool) $fileButton, 'совмещённые постквантовые ключи выдаются целиком в файле');

    $store = new PanelStore($tmp . '/' . $n);
    $bot->transport = new PanelTransport($store);
    $bot->input['message_id'] = $bot->send(1, 'menu')['result']['message_id'];
    for ($repeat = 0; $repeat < 2; $repeat++) {
        $bot->userXr(0);
        $messages = array_values($store->read()['messages']);
        cardAssert(count($messages) === 1, 'повторное открытие в панели не создаёт хвосты подписок');
        cardAssert($messages[0]['text'] === $card['text'] && !empty($messages[0]['buttons']), 'панель хранит всю карточку и кнопки вместе');
    }
    $capture->calls = [];
    $bot->transport = $capture;
    $bot->relaySub(0, 'Реле & # 🇷🇺');
    cardAssert(count($capture->calls) === 1, 'relay-карточка не делится из-за длинных href');
}

$bot = new CardLayoutBot($i, 'mlkem768', true);
$bot->testPac['vless_encryption']['encryption'] = 'invalid';
$capture = new CardCaptureTransport();
$bot->transport = $capture;
$bot->dw(0, 'uri');
cardAssert(count($capture->calls) === 1 && $capture->calls[0][0] === 'answerCallbackQuery',
    'повреждённые параметры не выдаются пустым файлом или plaintext-ссылкой');
cardAssert($capture->calls[0][1]['show_alert'] === true, 'недоступность ссылки объясняется пользователю');

echo "client_card_layout_test OK\n";
