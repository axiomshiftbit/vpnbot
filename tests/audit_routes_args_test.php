<?php

// Аргументы роутов диспетчера: необязательная группа регулярки обязана
// читаться через ?? (или empty()).
//
// PHP не «добивает» незахваченные ХВОСТОВЫЕ группы: для «/xray» у регулярки
// ~^/xray(?: (\d+))?$~ ключа $m[1] в массиве попросту нет, и обращение к нему
// давало «Undefined array key» на каждом штатном нажатии кнопки. Аудит
// 2026-08-12 насчитал таких роутов больше двух десятков; чтобы они не
// возвращались с новыми командами, проверяем ВЕСЬ action() разом.
//
// Тест статический: разбирает регулярки роутов, находит группы, которые могут
// не совпасть, и смотрит, как обработчик читает соответствующий $m[...].

$src   = file_get_contents(__DIR__ . '/../app/bot.php');
$lines = preg_split('~\r\n|\n~', $src);

$failed = 0;

function routeArgAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

/**
 * Группы регулярки, которые могут отсутствовать в $m.
 *
 * Необязательна группа, за которой стоит ?/*‌/{0,…}, а также любая группа
 * внутри такой. Возвращаем и номера, и имена (?P<name>…).
 *
 * @return array<int|string,true>
 */
function optionalGroups(string $body): array
{
    $optional = [];
    $names    = [];   // номер группы => имя, если она именованная
    $stack    = [];   // открытые группы: ['id' => ?int, 'from' => int]
    $index    = 0;    // номер последней открытой захватывающей группы
    $len      = strlen($body);
    for ($i = 0; $i < $len; $i++) {
        $c = $body[$i];
        if ($c === '\\') {
            $i++;
            continue;
        }
        if ($c === '[') { // класс символов — скобки внутри не считаются
            for ($i++; $i < $len && $body[$i] !== ']'; $i++) {
                if ($body[$i] === '\\') {
                    $i++;
                }
            }
            continue;
        }
        if ($c === '(') {
            $id = null;
            if (($body[$i + 1] ?? '') !== '?') {
                $id = ++$index;                              // обычная захватывающая
            } elseif (preg_match('~^\(\?P?[<\']([^>\']+)[>\']~', substr($body, $i), $nm)) {
                $id          = ++$index;                     // именованная
                $names[$id]  = $nm[1];
            }
            // from — номер, ДО которого группы уже были: всё, что откроется
            // внутри, получит номер больше.
            $stack[] = ['id' => $id, 'from' => $index];
            continue;
        }
        if ($c === ')') {
            $g    = array_pop($stack) ?: ['id' => null, 'from' => 0];
            $next = $body[$i + 1] ?? '';
            $opt  = $next === '?' || $next === '*'
                || (bool) preg_match('~^\{0[,}]~', substr($body, $i + 1, 4));
            if (!$opt) {
                continue;
            }
            // Необязательна и сама группа, и ВСЁ, что внутри неё: это как раз
            // диапазон номеров, выданных между открытием и закрытием.
            for ($k = $g['from'] + ($g['id'] === null ? 1 : 0); $k <= $index; $k++) {
                if ($k === 0) {
                    continue;
                }
                $optional[$k] = true;
                if (isset($names[$k])) {
                    $optional[$names[$k]] = true;
                }
            }
            continue;
        }
    }
    return $optional;
}

// Собираем роуты: строка case preg_match(...) и тело до break.
$routes = 0;
foreach ($lines as $n => $line) {
    if (!preg_match('~case preg_match\(\s*\'(.+?)\',\s*\$this->input\[\'callback\'\]~', $line, $m)) {
        continue;
    }
    $routes++;
    $re = $m[1];
    // Снимаем делимитеры и флаги: разбираем только тело регулярки.
    $d    = $re[0];
    $end  = strrpos($re, $d);
    $body = substr($re, 1, $end - 1);
    $opt  = optionalGroups($body);
    if (empty($opt)) {
        continue;
    }
    // Тело обработчика — до первого break на том же уровне.
    $handler = '';
    for ($i = $n + 1; $i < count($lines) && $i < $n + 12; $i++) {
        if (preg_match('~^\s*break;~', $lines[$i])) {
            break;
        }
        $handler .= $lines[$i] . "\n";
    }
    // Ссылки на группы в обработчике.
    if (!preg_match_all('~\$m\[\s*(?:\'([^\']+)\'|(\d+))\s*\]~', $handler, $refs, PREG_SET_ORDER)) {
        continue;
    }
    foreach ($refs as $r) {
        $id = $r[1] !== '' ? $r[1] : (int) $r[2];
        if (!isset($opt[$id])) {
            continue;
        }
        $ref = preg_quote($r[0], '~');
        // Допустимые формы чтения: ?? , empty()/!empty(), isset().
        $guarded = (bool) preg_match("~$ref\s*\?\?~", $handler)
            || (bool) preg_match("~(?:!?empty|isset)\(\s*$ref~", $handler);
        routeArgAssert(
            $guarded,
            sprintf(
                "строка %d: %s — необязательная группа %s читается без ??\n        %s",
                $n + 1,
                $re,
                is_int($id) ? "\$m[$id]" : "\$m['$id']",
                trim($handler),
            ),
        );
    }
}

routeArgAssert($routes > 300, "роуты найдены (разобрано: $routes)");

// Самопроверка разборщика: без неё зелёный тест ничего не доказывал бы.
routeArgAssert(optionalGroups('^/xray(?: (\d+))?$') === [1 => true], 'хвостовая необязательная группа');
routeArgAssert(optionalGroups('^/menu (\w+)$') === [], 'обязательная группа не помечается');
routeArgAssert(optionalGroups('^/a (\d+)(?:_(\d+))?$') === [2 => true], 'помечается только необязательная');
routeArgAssert(optionalGroups('^/a(?: (?P<page>\d+))?$') === [1 => true, 'page' => true], 'именованная группа');
routeArgAssert(optionalGroups('^/a[(](\d+)$') === [], 'скобка в классе символов не считается группой');
routeArgAssert(optionalGroups('^/a\((\d+)$') === [], 'экранированная скобка не считается группой');

if ($failed) {
    echo "audit_routes_args_test FAILED: $failed\n";
    exit(1);
}
echo "audit_routes_args_test OK\n";
