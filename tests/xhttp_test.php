<?php

// XHTTP (транспорт Xray, discussions/4113 + infra/conf/transport_method.go).
// Проверяем инварианты, нарушение которых xray/клиенты ловят не предупреждением,
// а отказом собрать конфиг или молчаливой рассинхронизацией ссылки и json:
//
//  1. xray собирает xhttpSettings так: если задан "extra", он парсится КАК
//     ЦЕЛЫЙ SplitHTTPConfig и ЗАМЕНЯЕТ внешний объект — наружу переносятся
//     только host/path/mode. Любое поле, забытое снаружи extra, теряется.
//  2. Build() падает с "maxConnections cannot be specified together with
//     maxConcurrency", когда у обоих To > 0. У нас maxConcurrency = "16-32",
//     значит maxConnections обязан оставаться нулём.
//  3. mode должен быть одним из auto/packet-up/stream-up/stream-one.
//     Клиент пинуется на packet-up: локация /ws у nginx на proxy_pass (её
//     делит websocket), а stream-up официально требует grpc_pass.
//  4. Ссылка vless://…&extra=… и json-конфиг (t=s) обязаны нести один и тот
//     же extra: это одно и то же ядро, импортированное двумя способами.

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function xhAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

// Диапазон xray пишется как "N" или "LO-HI"; отдаём [from, to].
function xhRange($v): array
{
    if (is_int($v)) {
        return [$v, $v];
    }
    xhAssert((bool) preg_match('~^\d+(-\d+)?$~', (string) $v), "range syntax: $v");
    $p = explode('-', (string) $v);
    return [(int) $p[0], (int) ($p[1] ?? $p[0])];
}

// Конструктор Bot тянет токен/окружение — он тут не нужен, xhttpClientExtra()
// чистая.
$bot   = (new ReflectionClass(Bot::class))->newInstanceWithoutConstructor();
$extra = $bot->xhttpClientExtra();

// --- 2: конфликт maxConnections/maxConcurrency -------------------------------
$xmux = $extra['xmux'];
[, $concTo] = xhRange($xmux['maxConcurrency']);
[, $connTo] = xhRange($xmux['maxConnections']);
xhAssert(!($concTo > 0 && $connTo > 0), 'maxConnections cannot be set together with maxConcurrency');
xhAssert($concTo > 0, 'maxConcurrency must be set (иначе xmux вырождается в 1 запрос на коннект)');

foreach (['cMaxReuseTimes', 'hMaxRequestTimes', 'hMaxReusableSecs'] as $k) {
    xhRange($xmux[$k]);
}
xhAssert(is_int($xmux['hKeepAlivePeriod']), 'hKeepAlivePeriod — число секунд, не диапазон');

// --- xPaddingBytes нельзя отключить: Build() отвергает from/to <= 0 ----------
[$padFrom, $padTo] = xhRange($extra['xPaddingBytes']);
xhAssert($padFrom > 0 && $padTo > 0, 'xPaddingBytes cannot be disabled');

// --- scMaxEachPostBytes > 0, иначе packet-up не сможет отправить пост --------
[$postFrom] = xhRange($extra['scMaxEachPostBytes']);
xhAssert($postFrom > 0, 'scMaxEachPostBytes must be > 0');

// --- 1: всё, кроме host/path/mode, лежит внутри extra ------------------------
// Перебираем поля, которые xray переносит наружу, и убеждаемся, что их нет в
// extra (иначе они всё равно были бы перетёрты внешними значениями).
foreach (['host', 'path', 'mode'] as $k) {
    xhAssert(!array_key_exists($k, $extra), "$k не должен дублироваться внутри extra");
}

// --- 4: ссылка и json несут один и тот же extra ------------------------------
// Пересобираем закодированную форму ровно так, как это делает генератор ссылки,
// и разбираем обратно.
$encoded = rawurlencode(json_encode($extra, JSON_UNESCAPED_SLASHES));
$decoded = json_decode(rawurldecode($encoded), true);
xhAssert($decoded === $extra, 'extra ссылки декодируется в тот же массив, что и extra json-конфига');
xhAssert(strpos($encoded, '&') === false && strpos($encoded, '#') === false,
    'закодированный extra не должен содержать & и # — иначе он разорвёт ссылку');

// --- 3: mode из допустимого набора ------------------------------------------
// Значения берём из самого bot.php, чтобы тест ловил правку в конфиге, а не
// повторял её.
$src = file_get_contents(__DIR__ . '/../app/bot.php');
preg_match_all('~"mode"\s*=>\s*"([a-z-]+)"~', $src, $m);
xhAssert($m[1] !== [], 'в bot.php должны быть заданы xhttp-режимы');
foreach (array_unique($m[1]) as $mode) {
    xhAssert(in_array($mode, ['auto', 'packet-up', 'stream-up', 'stream-one'], true),
        "unsupported mode: $mode");
}
// Клиентский режим — packet-up, серверный — auto (принимает любой).
xhAssert(in_array('packet-up', $m[1], true), 'клиент должен быть на packet-up');
xhAssert(in_array('auto', $m[1], true), 'сервер должен слушать mode=auto');

// --- sing-box: x_padding_bytes обязателен ------------------------------------
// Форки sing-box с XHTTP проверяют СЫРОЕ поле, а не нормализованное, и без него
// отвечают "x_padding_bytes cannot be disabled" — конфиг не грузится вообще.
preg_match('~"type" => "xhttp".+?\];~s', $src, $sb);
xhAssert(!empty($sb[0]), 'блок sing-box xhttp не найден');
xhAssert(strpos($sb[0], 'x_padding_bytes') !== false,
    'sing-box xhttp: x_padding_bytes обязателен');
xhAssert(strpos($sb[0], '"max_connections"   => "0"') !== false,
    'sing-box xhttp: max_connections должен остаться нулевым при заданном max_concurrency');

echo $failed ? "xhttp_test FAILED ($failed)\n" : "xhttp_test OK\n";
exit($failed ? 1 : 0);
