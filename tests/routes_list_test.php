<?php

// Menu -> Vless -> routes -> block/warp/proxy list: записи должны попадать в
// ТЕЛО сообщения списком, как это давно сделано у rulesset list. В кнопке
// длинная запись обрезается Telegram'ом, поэтому список в чате — единственный
// способ увидеть её целиком и скопировать.
//
// Проверяется:
//  - три списка (blocklist/warplist/includelist) отдают строки тела, а списки,
//    у которых своего рендера не было (packagelist и т.п.), — не отдают;
//  - экранирование HTML: на неэкранированном '&' Telegram отвергает СООБЩЕНИЕ
//    ЦЕЛИКОМ, и меню перестаёт открываться (ровно это уже ловили на rulesset);
//  - punycode разворачивается — в чате видно то же, что на кнопке;
//  - бюджет длины: тело не должно перерастать лимит Telegram в 4096 символов,
//    иначе меню снова становится неоткрываемым.

require_once __DIR__ . '/../app/bot.php';

// routeEntryLabel() зовёт idn_to_utf8() из расширения intl. В php-контейнере
// оно есть (им уже отрисовываются подписи кнопок в этих же меню), но в голом
// CLI может отсутствовать — подставляем no-op, чтобы тест проверял всё
// остальное. Саму punycode-проверку ниже гейтим наличием расширения.
if (!function_exists('idn_to_utf8')) {
    function idn_to_utf8($domain, $flags = 0, $variant = 0, &$idna_info = null)
    {
        return $domain;
    }
}

$failed = 0;

function rlAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

// pac.json и i18n подменяем: listPac() читает только getPacConf() и i18n().
class RoutesListTestBot extends Bot
{
    public array $pacFake = [];

    public function getPacConf()
    {
        return $this->pacFake;
    }

    public function i18n(string $menu): string
    {
        return $menu;
    }
}

$bot = (new ReflectionClass(RoutesListTestBot::class))->newInstanceWithoutConstructor();
$bot->limit = 5;

$entries = [
    'domain:example.com'        => true,
    '1.2.3.4/24'                => true,
    'geoip:ru'                  => false,
    'regexp:^ads?\..*&utm=1$'   => true,   // & и < обязаны экранироваться
    'keyword:tracker<x>'        => true,
];

// ── 1. Три списка отдают тело сообщения ─────────────────────────────────────
foreach (['blocklist', 'warplist', 'includelist'] as $type) {
    $bot->pacFake = [$type => $entries];
    [$data, $text] = $bot->listPac($type, 0, 'menu');
    rlAssert(is_array($text) && count($text) === count($entries),
        "$type: строк в теле столько же, сколько записей на странице");
    rlAssert(count($data) >= count($entries), "$type: кнопки на месте");
    foreach ($text as $line) {
        rlAssert(str_starts_with($line, '<blockquote><code>') && str_ends_with($line, '</code></blockquote>'),
            "$type: строка обёрнута как у rulesset list");
    }
}

// ── 2. Экранирование ────────────────────────────────────────────────────────
$bot->pacFake = ['blocklist' => $entries];
[, $text] = $bot->listPac('blocklist', 0, 'menu');
$body = implode("\n", $text);
rlAssert(str_contains($body, '&amp;'), 'амперсанд экранирован');
rlAssert(str_contains($body, '&lt;') && str_contains($body, '&gt;'), 'угловые скобки экранированы');
// Голых '&' вне сущностей быть не должно — именно на них Telegram отвергает
// сообщение целиком.
rlAssert(!preg_match('~&(?!amp;|lt;|gt;|quot;|#\d+;)~', $body), 'голых & в теле не осталось');
// Разметка не должна порваться: тегов blockquote/code одинаковое число.
rlAssert(substr_count($body, '<blockquote>') === substr_count($body, '</blockquote>'), 'blockquote сбалансированы');
rlAssert(substr_count($body, '<code>') === substr_count($body, '</code>'), 'code сбалансированы');

// ── 3. punycode разворачивается (как на кнопке) ─────────────────────────────
$bot->pacFake = ['blocklist' => ['domain:xn--80ak6aa92e.com' => true]];
[, $text] = $bot->listPac('blocklist', 0, 'menu');
if (extension_loaded('intl')) {
    rlAssert(!str_contains($text[0], 'xn--'), 'idn-домен показан в utf-8, а не punycode');
} else {
    echo "  (intl не загружен — проверка punycode пропущена)\n";
}
// Независимо от intl: запись обязана попасть в тело и остаться экранированной.
rlAssert(str_contains($text[0], '<blockquote><code>'), 'idn-запись всё равно попадает в тело');

// ── 4. Списки без своего рендера тело не наполняют ──────────────────────────
foreach (['packagelist', 'processlist', 'subnetlist'] as $type) {
    $bot->pacFake = [$type => ['com.example.app' => true]];
    [, $text] = $bot->listPac($type, 0, 'menu');
    rlAssert($text === [], "$type: тело не наполняется (поведение не менялось)");
}

// ── 5. Пустой список — без warning и с пустым телом ─────────────────────────
$bot->pacFake = ['blocklist' => []];
$warn = null;
set_error_handler(function ($n, $s) use (&$warn) { $warn = $s; return true; });
[, $text] = $bot->listPac('blocklist', 0, 'menu');
restore_error_handler();
rlAssert($warn === null, 'на пустом списке нет warning: ' . var_export($warn, true));
rlAssert($text === [], 'на пустом списке тело пустое');

// ── 6. Бюджет длины ─────────────────────────────────────────────────────────
// limitpage задаётся пользователем; с длинными записями тело легко переросло
// бы 4096 символов, и Telegram отверг бы сообщение целиком.
$bot->limit = 60;
$long = [];
for ($i = 0; $i < 60; $i++) {
    $long['regexp:' . str_repeat("x$i", 40)] = true;
}
$bot->pacFake = ['blocklist' => $long];
[$data, $text] = $bot->listPac('blocklist', 0, 'menu');
$body = implode("\n", $text);
rlAssert(mb_strlen($body) < 4096, 'тело укладывается в лимит Telegram (получилось ' . mb_strlen($body) . ')');
rlAssert(in_array('…', $text, true), 'обрыв помечен многоточием');
rlAssert(count($data) > count($text), 'кнопки НЕ обрезаны — режется только текст');

if ($failed) {
    echo "routes_list_test FAILED ($failed)\n";
    exit(1);
}
echo "routes_list_test OK\n";
