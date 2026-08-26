<?php

// Полнота словаря интерфейса.
//
// Аудит 2026-08-12 насчитал 62 надписи, для которых ключа в i18n.php не было
// вовсе: i18n() отдавала сам ключ (то есть английский текст в русском
// интерфейсе) и добавляла «Undefined array key» в лог на каждую такую кнопку.
// Тест держит словарь полным: любая новая надпись обязана приехать с
// переводом на оба языка.

require_once __DIR__ . '/../app/i18n.php';   // объявляет $i

$failed = 0;

function i18nAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

$dict = $i;
i18nAssert(is_array($dict) && count($dict) > 300, 'словарь загружен: ' . count($dict) . ' ключей');

// Все ключи полны и непусты в обоих языках.
foreach ($dict as $k => $v) {
    i18nAssert(isset($v['en']), "ключ «{$k}»: нет en");
    i18nAssert(isset($v['ru']), "ключ «{$k}»: нет ru");
    i18nAssert(trim((string) ($v['en'] ?? '')) !== '', "ключ «{$k}»: пустой en");
    i18nAssert(trim((string) ($v['ru'] ?? '')) !== '', "ключ «{$k}»: пустой ru");
}

// Плейсхолдеры (%s, {name}, :val) обязаны совпадать между языками — иначе
// подстановка молча теряется в одном из переводов.
foreach ($dict as $k => $v) {
    $en = [];
    $ru = [];
    preg_match_all('~%[a-z]|\{[a-z_]+\}~i', (string) ($v['en'] ?? ''), $en);
    preg_match_all('~%[a-z]|\{[a-z_]+\}~i', (string) ($v['ru'] ?? ''), $ru);
    sort($en[0]);
    sort($ru[0]);
    i18nAssert($en[0] === $ru[0], "ключ «{$k}»: плейсхолдеры расходятся — "
        . json_encode($en[0], JSON_UNESCAPED_UNICODE) . ' vs ' . json_encode($ru[0], JSON_UNESCAPED_UNICODE));
}

// Каждая литеральная надпись из bot.php обязана быть в словаре.
$src = file_get_contents(__DIR__ . '/../app/bot.php');
preg_match_all('~i18n\(\s*\'([^\']+)\'\s*\)~', $src, $m);
$used    = array_unique($m[1]);
$missing = array_values(array_diff($used, array_keys($dict)));
i18nAssert(
    $missing === [],
    'нет перевода для: ' . implode(', ', array_map(fn($k) => "«{$k}»", $missing)),
);
i18nAssert(count($used) > 250, 'надписи найдены: ' . count($used));

// Тексты, уходящие в answerCallbackQuery, обязаны влезать в лимит Telegram:
// 200 символов. Длиннее — API отвечает 400, и всплывающее предупреждение не
// показывается ВООБЩЕ, то есть пользователь молча не узнаёт о причине отказа.
preg_match_all('~answer\(([^;]{0,400}?)\)\s*;~s', $src, $calls);
$alerts = [];
foreach ($calls[1] as $call) {
    if (preg_match_all('~i18n\(\s*\'([^\']+)\'~', $call, $k)) {
        foreach ($k[1] as $key) {
            $alerts[$key] = true;
        }
    }
}
i18nAssert(count($alerts) > 5, 'ключи-алерты найдены: ' . count($alerts));
foreach (array_keys($alerts) as $k) {
    foreach (['en', 'ru'] as $lang) {
        $len = mb_strlen((string) ($dict[$k][$lang] ?? ''));
        i18nAssert($len <= 200, "алерт «{$k}» ({$lang}): $len символов — лимит answerCallbackQuery 200");
    }
}

// Ключи с интерполяцией допустимы только тогда, когда переменная принимает
// значения из известного набора и все варианты в словаре есть. Собранный из
// пользовательского ввода ключ («clean logs 1.2.3.4») не совпадёт никогда.
preg_match_all('~i18n\(\s*"([^"]*\$[^"]*)"\s*\)~', $src, $dyn);
foreach (array_unique($dyn[1]) as $tpl) {
    $prefix = trim(preg_replace('~\$\w+.*$~', '', $tpl));
    $known  = array_filter(array_keys($dict), fn($k) => str_starts_with($k, $prefix . ' '));
    i18nAssert($known !== [], "интерполированный ключ «{$tpl}»: в словаре нет ни одного варианта «$prefix …»");
}

if ($failed) {
    echo "audit_i18n_test FAILED: $failed\n";
    exit(1);
}
echo "audit_i18n_test OK\n";
