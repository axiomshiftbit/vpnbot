<?php

// Живой баг с рабочего сервера: кнопка "v2ray ⬇️"/"singbox ⬇️"/"mihomo ⬇️" (Bot::dw(),
// callback_data "/dw <i> s|si|cl") не отдавала конфиг при включённом
// pac.subtoken_strict — dw() подставляла в ?s= сырой id (credential) клиента
// вместо subtoken. findClientBySid() в строгом режиме резолвит ТОЛЬКО по
// subtoken (см. findClientBySid()), поэтому подбор по id проваливался,
// subscription(1) отдавала '', и в Telegram уходил пустой файл. Другие пути
// (userXr(), сама subscription()) уже брали sidOf($c) — только dw() был
// расхождением.

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function dwAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

class DwTestBot extends Bot
{
    public array $pacFake = ['subtoken_strict' => 1, 'transport' => 'Reality'];
    public ?string $capturedS = null;
    public ?string $capturedFilename = null;
    public string $capturedContent = '';

    public function getPacConf()
    {
        return $this->pacFake;
    }

    public function getXray()
    {
        return [
            'inbounds' => [[
                'settings' => [
                    'clients' => [
                        0 => ['id' => 'CREDENTIAL-UUID', 'email' => 'a@x', 'subtoken' => 'SUBTOKEN-HEX'],
                    ],
                ],
            ]],
        ];
    }

    public function getDomain($cdn = false)
    {
        return 'example.test';
    }

    // subscription() сама по себе (findClientBySid + сеть/лимитер) в юнит-тесте
    // не поднимается — здесь важно только то, ЧТО dw() успела положить в $_GET
    // ДО вызова, и что непустой ответ реально доезжает до sendFile().
    public function subscription($return = false)
    {
        $this->capturedS = $_GET['s'] ?? null;

        // Тот же исход, что и на рабочем сервере: подбор по 'id' в strict-режиме не находит
        // клиента вовсе — subscription() отдаёт '' (см. Bot::subscription()).
        return $this->capturedS === 'SUBTOKEN-HEX' ? '{"ok":true}' : '';
    }

    public function sendFile($chat, $id_url_cFile, $caption = false, $to = false)
    {
        $this->capturedFilename = $id_url_cFile->postname ?? null;
        $this->capturedContent  = $id_url_cFile->data ?? '';
    }
}

$bot = (new ReflectionClass(DwTestBot::class))->newInstanceWithoutConstructor();
$bot->input = ['from' => 111, 'chat' => 111, 'message_id' => 1];
$bot->dw(0, 's');

dwAssert('SUBTOKEN-HEX' === $bot->capturedS, 'dw() подставляет в ?s= subtoken (sidOf), а не сырой id');
dwAssert('CREDENTIAL-UUID' !== $bot->capturedS, 'сырой credential в ?s= больше не попадает');
dwAssert('{"ok":true}' === $bot->capturedContent, 'непустой конфиг реально доезжает до sendFile() при strict-режиме');
dwAssert('a@x_v2ray.json' === $bot->capturedFilename, 'имя файла как раньше — email + суффикс формата');
$bot->dw(0, 'clj');
dwAssert('a@x_mihomo.json' === $bot->capturedFilename, 'Общий Mihomo JSON выгружается с расширением JSON');
dwAssert(!$bot->protocolOutput, 'После выгрузки снимается флаг временного файла');

// ── стэйл-колбэк: индекс клиента мог устареть (удаление/переиндексация) ─────
class DwStaleTestBot extends DwTestBot
{
    public bool $fellBackToList = false;

    public function getXray()
    {
        return ['inbounds' => [['settings' => ['clients' => []]]]]; // клиент #0 больше не существует
    }

    public function xray($page = 0)
    {
        $this->fellBackToList = true;
    }
}

$stale = (new ReflectionClass(DwStaleTestBot::class))->newInstanceWithoutConstructor();
$stale->input = ['from' => 111];
$stale->dw(0, 's');
dwAssert($stale->fellBackToList, 'устаревший индекс клиента откатывается в список, а не падает на null[\'id\']');
dwAssert(null === $stale->capturedS, 'subscription() не вызывается для несуществующего клиента');

if ($failed) {
    echo "dw_subtoken_test FAILED: $failed\n";
    exit(1);
}
echo "dw_subtoken_test OK\n";
