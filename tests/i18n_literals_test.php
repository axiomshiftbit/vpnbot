<?php

// Каждая русская надпись в коде бота обязана иметь английскую пару.
//
// Аудит 2026-10-20 нашёл около 1500 русских строк вне словаря: меню узлов
// выхода, протоколов, резервной копии, справка XDRIVE, AdGuard, OpenVPN и
// подсказки полей показывались по-русски и в английском интерфейсе. Тест
// разбирает app/*.php на токены и пропускает русский литерал только там, где
// рядом есть английский вариант:
//   - первый аргумент ->t(), Lang::t(), $t() (вторым идёт английский);
//   - ветка «да» тернарника по русскому языку ($ru ? 'рус' : 'en');
//   - значение 'ru' => в массиве переводов;
//   - шаблон регулярного выражения и строки журнала (их видит только админ
//     в логах, не интерфейс).

$root = dirname(__DIR__) . '/app';
$skip = ['i18n.php', 'routes_help.php', 'routes_help_en.php'];
$langCalls = ['->t', 'Lang::t', '$t', 'self::localize']; // localize: таблица замен Panel::UI_EN, проверка ниже
$quietCalls = ['error_log', 'preg_match', 'preg_match_all', 'preg_replace', 'preg_replace_callback', 'preg_split', 'preg_quote', 'logLine', 'debugLog'];

function i18nTokens(string $file): array
{
    $sig = [];
    foreach (token_get_all(file_get_contents($file)) as $t) {
        if (is_array($t) && in_array($t[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) continue;
        $sig[] = $t;
    }
    return $sig;
}

function i18nText($t): string
{
    return is_array($t) ? $t[1] : $t;
}

// Ближайший охватывающий вызов: имя и номер аргумента, в котором стоит токен.
function i18nEnclosingCall(array $sig, int $i): array
{
    $depth = 0;
    $arg = 0;
    for ($j = $i - 1; $j >= 0; $j--) {
        $s = i18nText($sig[$j]);
        if ($s === ')' || $s === ']' || $s === '}') $depth++;
        elseif ($s === '[' || $s === '{' || $s === '(') {
            if ($depth > 0) { $depth--; continue; }
            if ($s !== '(') { $arg = 0; continue; } // элемент массива: ищем выше
            $name = $j > 0 ? i18nText($sig[$j - 1]) : '';
            if ($j > 1 && in_array(i18nText($sig[$j - 2]), ['->', '?->', '::'], true)) {
                $name = (i18nText($sig[$j - 2]) === '::' ? i18nText($sig[$j - 3]) . '::' : '->') . $name;
            }
            return [$name, $arg, $j];
        } elseif ($depth === 0 && $s === ',') $arg++;
        elseif ($depth === 0 && $s === ';') break;
    }
    return ['', 0, -1];
}

// Стоит ли токен в русской ветке тернарника: «да» при условии $ru / === 'ru' /
// !== 'en' либо «нет» при условии === 'en'.
function i18nRuBranch(array $sig, int $i): bool
{
    $depth = 0;
    $else = false;
    for ($j = $i - 1; $j >= 0; $j--) {
        $s = i18nText($sig[$j]);
        if ($s === ')' || $s === ']') $depth++;
        elseif ($s === '(' || $s === '[') { if ($depth === 0) return false; $depth--; }
        elseif ($depth === 0 && $s === ':' && !$else) $else = true;
        elseif ($depth === 0 && in_array($s, [',', ';', '=>', '=', ':', '{', '}', 'return'], true)) return false;
        elseif ($depth === 0 && $s === '?') {
            $cond = '';
            for ($k = max(0, $j - 8); $k < $j; $k++) $cond .= i18nText($sig[$k]);
            return $else
                ? (bool) preg_match('~==?[\'"]en[\'"]\)?$~', $cond)
                : (bool) preg_match('~(\$ru|==?[\'"]ru[\'"]\)?|!==?[\'"]en[\'"]\)?)$~', $cond);
        }
    }
    return false;
}

$bad = [];
foreach (array_merge(glob("$root/*.php"), glob("$root/panel/*.php")) as $file) {
    if (in_array(basename($file), $skip, true)) continue;
    $sig = i18nTokens($file);
    foreach ($sig as $i => $t) {
        if (!is_array($t) || !in_array($t[0], [T_CONSTANT_ENCAPSED_STRING, T_ENCAPSED_AND_WHITESPACE], true)) continue;
        // Строки-комментарии скрипта или конфига (// и #) внутри heredoc в
        // интерфейс не попадают. Однобуквенные литералы — синонимы ввода
        // (единицы «м/ч/д»), их не переводят.
        $text = $t[0] === T_ENCAPSED_AND_WHITESPACE ? preg_replace('~^\s*(//|#).*$~m', '', $t[1]) : $t[1];
        if (mb_strlen(trim($text, "'\"")) === 1) continue;
        if (!preg_match('~\p{Cyrillic}~u', $text)) continue;
        [$call, $arg] = i18nEnclosingCall($sig, $i);
        if (in_array($call, $langCalls, true) && $arg === 0) continue;
        if (in_array(ltrim($call, '->'), $quietCalls, true)) continue;
        if (i18nRuBranch($sig, $i)) continue;
        if ($i > 1 && i18nText($sig[$i - 1]) === '=>' && i18nText($sig[$i - 2]) === "'ru'") continue;
        $bad[] = basename($file) . ':' . $t[2] . ' ' . mb_substr(preg_replace('~\s+~', ' ', $t[1]), 0, 70);
    }
}

// Страница веб-панели: на английском не остаётся видимого русского текста
// (комментарии CSS/JS/HTML не в счёт).
require_once $root . '/Lang.php';
require_once $root . '/panel/Panel.php';
Lang::$en = true;
preg_match('~self::localize\(<<<HTML\n(.*?)\n\s*HTML\);~s', file_get_contents("$root/panel/Panel.php"), $editor);
foreach (['ui.html' => file_get_contents("$root/panel/ui.html"), 'editor' => $editor[1] ?? 'нет страницы редактора'] as $name => $html) {
    $visible = preg_replace(['~/\*.*?\*/~s', '~^\s*//.*$~m', '~\s//\s.*$~m', '~<!--.*?-->~s'], '', Panel::localize($html));
    if (preg_match_all('~.{0,30}\p{Cyrillic}+.{0,30}~u', $visible, $left)) {
        foreach ($left[0] as $line) $bad[] = "panel/$name: " . trim($line);
    }
}
Lang::$en = false;

if ($bad) {
    echo implode("\n", getenv('I18N_ALL') ? $bad : array_slice($bad, 0, 40)), "\n";
    echo "i18n_literals_test FAILED: " . count($bad) . " русских строк без английской пары\n";
    exit(1);
}
echo "i18n_literals_test OK\n";
