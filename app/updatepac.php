<?php

// elzw()/dlzw() удалены (аудит 2026-08-18): ~60 строк LZW, которые не звал
// никто во всём проекте, и к тому же неверные. В декодере классический для LZW
// баг KwKwK: $keys[$cc] читался до того, как определялся код $code, поэтому на
// последовательностях вида «abababab» (их кодировщик выше порождал штатно) он
// падал на Undefined array key. Плюс $keys[$cc][0] брал первый БАЙТ, а не
// первый символ, что для строк из mb_str_split() неверно.

function getSize($url)
{
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_HEADER         => 1,
        CURLOPT_NOBODY         => 1,
        CURLOPT_RETURNTRANSFER => 1,
        CURLOPT_TIMEOUT        => 10,
    ]);
    $r = curl_exec($ch);
    if (!preg_match('~content-length.+?(\d+)~ius', (string) $r, $m)) {
        return 0;
    }
    return (int) $m[1];
}

function update($text)
{
    global $bot;
    $bot->update($bot->input['chat'], $bot->input['message_id'], $text);
}

/**
 * Разбирает запись pac-списка с учётом префиксов маршрутизации.
 *
 * Записи includelist пишутся в тех же формах, что и для ядер:
 * «vk.com», «domain:vk.com», «full:vk.com», «keyword:reddit»,
 * «regexp:.*\.ru$», «1.2.3.4/24», «ext:dlc.dat:tag», «geosite:cn».
 * Генератор PAC брал ключ СЫРЫМ: в mpac уезжал preg_quote("domain:vk.com"),
 * а в pac — $t["com"][9][] = "domain:vk", то есть любая запись с префиксом
 * молча не работала ни в одном из двух форматов.
 *
 * @return array{host: ?string, pattern: ?string} host — для доменного дерева
 *         pac (только то, что представимо суффиксом), pattern — регулярка для
 *         списка shadowsocks-android (mpac). null означает «не представимо».
 */
function pacEntry($bot, string $e): array
{
    $c = $bot->classifyRouteEntry($e);
    if (!$bot->routeEntryUsable($c)) {
        return ['host' => null, 'pattern' => null];
    }
    $v = (string) $c['value'];
    switch ($c['kind']) {
        case 'suffix':
        case 'domain':
        case 'full':
            // full: формально означает точное совпадение, а дерево pac умеет
            // только суффикс — берём как суффикс (шире, но работает), в mpac
            // же уходит обычной подстрокой, как и раньше.
            return ['host' => $bot->hostCanon($v), 'pattern' => preg_quote($bot->hostCanon($v), '~')];
        case 'keyword':
            // Дерево pac строится по TLD и длине метки — подстроке там места
            // нет. В mpac запись естественна: файл и так список регулярок.
            return ['host' => null, 'pattern' => preg_quote($v, '~')];
        case 'regexp':
            return ['host' => null, 'pattern' => $v];
        case 'ip':
            // Литерал адреса в URL. Маску отбрасываем: подсеть в PAC этого
            // формата не выразить.
            return ['host' => null, 'pattern' => preg_quote(explode('/', $v)[0], '~')];
        default: // ext, extip, geosite, geoip — это ссылки на .dat ядра
            return ['host' => null, 'pattern' => null];
    }
}

function start()
{
    global $bot, $source, $res, $load, $text;

    // $tail присваивается только внутри цикла ПРЯМОГО PAC. Если includelist
    // пуст, а reverselist нет, выполнение уходит в ветку «Empty domains», и
    // ниже, в reverse-ветке, чтение $tail давало «Undefined variable».
    $tail = '';

    $conf = $bot->getPacConf();

    // Список subzone'ов для исключения из PAC (используется ниже как $exclude).
    // Раньше присваивался в неиспользуемую $subzones, а $exclude был не определён,
    // из-за чего исключение не работало вовсе.
    $exclude = [];
    if (!empty($conf['subzoneslist'])) {
        $exclude = array_keys(array_filter($conf['subzoneslist'], fn($x) => $x == true));
    }

    // check && exclude
    if (!empty($conf['includelist'])) {
        $domains = array_filter($conf['includelist'], fn($x) => $x == true);
    }
    if (empty($domains)) {
        $text = "Empty domains. Delete pac files";
        // is_file: на первом запуске файлов ещё нет, и голый unlink() писал по
        // два warning'а в лог.
        foreach (['mpac', 'pac'] as $name) {
            if (is_file($p = __DIR__ . "/zapretlists/$name")) {
                unlink($p);
            }
        }
    } else {
        $domains = array_keys($domains);

        $size = count($domains);
        $curr = $j = 0;
        $time = microtime(true);
        $f = fopen(__DIR__ . '/zapretlists/mpac', 'w');
        $t = [];
        foreach ($domains as $v) {
            $curr ++;
            $percent = (int) ceil($curr * 100 / $size);
            $rotate = $curr != $size ? $load[$j % count($load)] : '';
            $tail = <<<text
                    Create pac for shadowsocks-android $percent% $rotate
                    text;
            if (microtime(true) - $time > 0.1) {
                update($text . $tail);
                $time = microtime(true);
                $j++;
            }
            if ($exclude && preg_match(excludePattern($exclude), $v)) {
                continue;
            }
            // Префиксы маршрутизации (domain:/full:/keyword:/regexp:/IP)
            // разбираем, а не пишем сырыми — см. pacEntry().
            ['host' => $host, 'pattern' => $pattern] = pacEntry($bot, $v);
            if ($pattern !== null) {
                fwrite($f, $pattern . "\n");
            }
            if ($host === null) {
                continue;
            }

            // Без точки в имени совпадения нет: $m остаётся пустым, и в PAC
            // уезжал мусор вида {"":[[null]]}, а strlen(null) в PHP 9 станет
            // TypeError. Такую строку просто пропускаем.
            if (!preg_match('~(.+)\.([^.]+)$~', $host, $m)) {
                continue;
            }
            $t[$m[2]][strlen($m[1])][] = $m[1];
        }
        fclose($f);
        $text .= $tail ? "$tail\n" : '';

        // create pac
        $domains = json_encode($t);
        $pac     = <<<PAC
                    function FindProxyForURL(t, e) {
                        var n = JSON.parse('$domains'),
                        r = e.match(/(.+)\.([^.]+)$/);
                        if (r && n.hasOwnProperty(r[2])) {
                            var suffix = r[1], group = n[r[2]];
                            while (suffix) {
                                if (group.hasOwnProperty(suffix.length) && group[suffix.length].indexOf(suffix) !== -1) {
                                    return "SOCKS5 ~address~:~port~; DIRECT";
                                }
                                var dot = suffix.indexOf('.');
                                if (dot === -1) break;
                                suffix = suffix.slice(dot + 1);
                            }
                        }
                        return "DIRECT";
                    }
                    PAC;
        $pac = preg_replace("~\s{2,}~", '', $pac);
        $pac = preg_replace("~\n~", '', $pac);
        file_put_contents(__DIR__ . '/zapretlists/pac', $pac);
        $text .= "Create minified pac 100%\n";
    }
    // create reverse PAC
    //
    // rmpac больше не генерируется: цикл, который его писал, закомментирован
    // ниже. Снимаем его в ОБЕИХ ветках, а не только когда reverselist пуст —
    // иначе оставшийся от прежней версии файл продолжал раздаваться как есть.
    if (is_file($stale = __DIR__ . '/zapretlists/rmpac')) {
        unlink($stale);
    }
    unset($domains);
    if (!empty($conf['reverselist'])) {
        $domains = array_filter($conf['reverselist'], fn($x) => $x == true);
    }
    if (empty($domains)) {

        // $text .= "Empty reverse domains. Delete reverse pac files";
        foreach (['rpac'] as $name) {   // rmpac уже снят выше
            if (is_file($p = __DIR__ . "/zapretlists/$name")) {
                unlink($p);
            }
        }
    } else {
        $domains = array_keys($domains);

        // reverse-PAC строится из СВОИХ доменов: цикл ниже закомментирован,
        // поэтому $t перестраиваем здесь, иначе в json ушёл бы $t от прямого PAC.
        $t = [];
        foreach ($domains as $v) {
            // Тот же разбор префиксов и тот же guard, что на прямой ветке:
            // здесь проверки результата не было вовсе, и домен без точки давал
            // «Undefined array key», strlen(null) и мусор в rpac.
            ['host' => $host] = pacEntry($bot, $v);
            if ($host === null || !preg_match('~(.+)\.([^.]+)$~', $host, $m)) {
                continue;
            }
            $t[$m[2]][strlen($m[1])][] = $m[1];
        }

        // $size = count($domains);
        // $curr = $j = 0;
        // $time = microtime(true);
        // $f = fopen(__DIR__ . '/zapretlists/rmpac', 'w');
        // $t = [];
        // foreach ($domains as $v) {
        //     $curr ++;
        //     $percent = (int) ceil($curr * 100 / $size);
        //     $rotate = $curr != $size ? $load[$j % count($load)] : '';
        //     $tail = <<<text
        //             Create reverse pac for shadowsocks-android $percent% $rotate
        //             text;
        //     if (microtime(true) - $time > 0.1) {
        //         update($text . $tail);
        //         $time = microtime(true);
        //         $j++;
        //     }
        //     fwrite($f, '!(' . preg_quote($v) . ')' . "\n");

        //     preg_match('~(.+)\.([^.]+)$~', $v, $m);
        //     $t[$m[2]][strlen($m[1])][] = $m[1];
        // }
        // fclose($f);
        $text .= $tail ? "$tail\n" : '';

        $domains = json_encode($t);
        $pac     = <<<PAC
                    function FindProxyForURL(t, e) {
                        var n = JSON.parse('$domains'),
                        r = e.match(/(.+)\.([^.]+)$/);
                        if (r && n.hasOwnProperty(r[2])) {
                            var suffix = r[1], group = n[r[2]];
                            while (suffix) {
                                if (group.hasOwnProperty(suffix.length) && group[suffix.length].indexOf(suffix) !== -1) {
                                    return "DIRECT";
                                }
                                var dot = suffix.indexOf('.');
                                if (dot === -1) break;
                                suffix = suffix.slice(dot + 1);
                            }
                        }
                        return "SOCKS5 ~address~:~port~";
                    }
                    PAC;
        $pac = preg_replace("~\s{2,}+~", '', $pac);
        $pac = preg_replace("~\n~", '', $pac);
        file_put_contents(__DIR__ . '/zapretlists/rpac', $pac);
        $text .= 'Create minified reverse pac 100%';
    }

    endScript($text);
}

function endScript($text)
{
    global $bot;
    if (empty($_SERVER['argv'][5])) {
        update($text);
        sleep(2);
        $bot->menu('pac');
    }
    die();
}

function download($index)
{
    global $source;
    $data = @file_get_contents($source[$index]['source']);
    // Не затираем локальный список (nxdomain.txt/dump.csv) пустотой, если
    // источник недоступен.
    if ($data === false || $data === '') {
        return;
    }
    file_put_contents($source[$index]['dest'], $data);
}

ini_set('memory_limit', '256M');
require __DIR__ . '/timezone.php';
require_once __DIR__ . '/exclude_pattern.php';
// require __DIR__ . '/debug.php';
require __DIR__ . '/bot.php';
require __DIR__ . '/config.php';
require __DIR__ . '/i18n.php';
$source = [
    [
        'source' => 'https://raw.githubusercontent.com/zapret-info/z-i/master/nxdomain.txt',
        'dest'   => __DIR__ . '/zapretlists/nxdomain.txt',
    ],
    [
        'source' => 'https://raw.githubusercontent.com/zapret-info/z-i/master/dump.csv',
        'dest'   => __DIR__ . '/zapretlists/dump.csv',
    ],
];

$res = __DIR__ . '/zapretlists/result';

$text = '';
$load = [
    '/',
    '-',
    '\\',
];
switch ($_SERVER['argv'][1]) {
    case 'start':
        $bot                       = new Bot($c['key'], $i);
        $bot->input['chat']        = $_SERVER['argv'][2];
        $bot->input['message_id']  = $_SERVER['argv'][3];
        $bot->input['callback_id'] = $_SERVER['argv'][4];
        start();
        break;
    case 'download':
        download($_SERVER['argv'][2]);
        break;
}
