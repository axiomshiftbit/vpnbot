<?php

require __DIR__ . '/timezone.php';
require __DIR__ . '/config.php';
if ($c['debug']) {
    require __DIR__ . '/debug.php';
}
require __DIR__ . '/calc.php';
require __DIR__ . '/bot.php';
require __DIR__ . '/i18n.php';
if (file_exists(__DIR__ . '/override.php')) {
    include __DIR__ . '/override.php';
}
$bot  = new Bot($c['key'], $i);
$hash = $bot->getHashBot();
if (!empty($_GET['hash'])) {
    $t = $_GET;
    unset($t['hash']);
    ksort($t);
    // Инициализация обязательна: запрос вида ?hash=... без единого другого
    // GET-параметра оставлял $s необъявленной, и implode() падал с TypeError,
    // роняя обработчик до switch (анонимный DoS на любой URI).
    $s = [];
    foreach ($t as $k => $v) {
        $s[] = "$k=$v";
    }
    $s      = implode("\n", $s);
    $sk     = hash_hmac('sha256', $c['key'], "WebAppData", true);
    $webapp = hash_equals(hash_hmac('sha256', $s, $sk), (string) $_GET['hash']);
}

switch (true) {
    // tlgrm
    case 'POST' == $_SERVER['REQUEST_METHOD'] && preg_match('~^/tlgrm~', $_SERVER['REQUEST_URI']) && hash_equals($c['key'], (string) ($_GET['k'] ?? '')):
        $bot->input();
        break;

    // save template
    case preg_match('~^' . preg_quote("/webapp$hash/save") . '~', $_SERVER['REQUEST_URI']) && $webapp && !empty($_POST['json']):
        echo json_encode($bot->saveTemplate($_POST['name'], $_POST['type'], $_POST['json']));
        break;

    // load template — содержимое редактора отдаём ТОЛЬКО по подписанному
    // initData. Параметры кладём в POST-тело, а не в query: HMAC считается по
    // всем $_GET, и лишний параметр в строке запроса сломал бы проверку.
    case preg_match('~^' . preg_quote("/webapp$hash/load") . '~', $_SERVER['REQUEST_URI']) && $webapp:
        header('Content-Type: application/json');
        $ty = preg_match('~^\w+$~', $_POST['ty'] ?? '') ? $_POST['ty'] : '';
        if ($ty === '') {
            echo json_encode(['status' => false]);
            break;
        }
        $te = (string) ($_POST['te'] ?? '');
        $t  = $te !== ''
            ? ($bot->getPacConf()["{$ty}templates"][$te] ?? null)
            : json_decode((string) @file_get_contents("/config/$ty.json"), true);
        echo json_encode([
            'status' => (bool) $t,
            'json'   => $t ?: new stdClass(),
        ]);
        break;

    // adguard cookie
    case preg_match('~^' . preg_quote("/webapp$hash/check") . '~', $_SERVER['REQUEST_URI']) && $webapp:
        setcookie('c', $hash, 0, '/');
        echo "/adguard$hash/";
        break;

    case preg_match('~^' . preg_quote("/pac$hash/sub") . '~', $_SERVER['REQUEST_URI']) && file_exists(__DIR__ . '/subscription.php'):
        $bot->sub();
        exit;

    // subs & pac
    case preg_match('~^' . preg_quote("/pac$hash") . '~', $_SERVER['REQUEST_URI']):
        // allowed_classes=false: payload — массив GET-параметров, объекты не
        // нужны; запрет их инстанцирования закрывает PHP object injection.
        // is_array: подделанный токен может нести скаляр («s:3:"abc";»), а
        // array_merge со скаляром — фатальный TypeError в PHP 8 вместо 404.
        if (is_array($t = @unserialize((string) base64_decode(explode('/', $_SERVER['REQUEST_URI'])[2]), ['allowed_classes' => false])) && $t) { // fix sing-box import
            // Запоминаем состав токена до слияния: subscription() отличает по нему
            // выборку rule-set'а ядром (параметры из токена) от deep-link'а
            // импорта (те же имена параметров, но из query-string).
            $bot->subToken = $t;
            $_GET = array_merge($_GET, $t);
        }
        $type    = $_GET['t'] ?? 'pac';
        $address = ($_GET['a'] ?? '') ?: '127.0.0.1';
        $port    = ($_GET['p'] ?? '') ?: '1080';
        switch ($type) {
            case 's':
            case 'si':
            case 'cl':
                $bot->subscription();
                exit;

            case 'vl':
                $bot->subVless();
                exit;

            case 'te':
                // $_GET['ty'] попадает в путь /config/<ty>.json и ключ конфига —
                // ограничиваем словом (\w), иначе `ty=../..` читает произвольный .json.
                $ty = preg_match('~^\w+$~', $_GET['ty'] ?? '') ? $_GET['ty'] : '';
                if ($ty === '') {
                    break;
                }
                // Содержимое шаблона (xray.json — uuid/password/subtoken всех
                // клиентов, pac.json — reality privateKey и adpswd) в страницу
                // НЕ встраиваем: этот GET ничем не аутентифицирован, а $hash в
                // URI есть у любого владельца подписки. Telegram передаёт
                // initData во фрагменте, серверу он не виден, поэтому редактор
                // забирает JSON отдельным подписанным POST /webapp$hash/load —
                // тем же способом, что уже используется для save.
                header('Content-Type: text/html');
                $te   = (string) ($_GET['te'] ?? '');
                $name = $te ?: 'origin';
                // Имена уходят в JS-литералы: кавычка в ?te= давала XSS.
                $jsName = json_encode($name, JSON_UNESCAPED_UNICODE);
                $jsType = json_encode($ty, JSON_UNESCAPED_UNICODE);
                $jsTe   = json_encode($te, JSON_UNESCAPED_UNICODE);
                echo <<<HTML
                        <!DOCTYPE HTML>
                        <html lang="en" style="height:100%">
                        <head>
                            <!-- when using the mode "code", it's important to specify charset utf-8 -->
                            <meta charset="utf-8">
                            <meta name="viewport" content="width=device-width, initial-scale=1.0">

                            <link href="/webapp$hash/jsoneditor.min.css" rel="stylesheet" type="text/css">
                            <script src="/webapp$hash/jsoneditor.min.js"></script>
                            <script src="/webapp$hash/jquery-3.7.1.min.js"></script>
                            <script src="https://telegram.org/js/telegram-web-app.js"></script>
                        </head>
                        <body style="height:100%">
                            <div id="jsoneditor" style="height:100%"></div>

                            <script>
                                jQuery(function($) {
                                    var tg = window.Telegram.WebApp;
                                    // create the editor
                                    const container = document.getElementById("jsoneditor")
                                    const options = {}
                                    const editor = new JSONEditor(container, options)
                                    editor.set({})
                                    // Данные приходят отдельным запросом, подписанным initData.
                                    $.ajax({
                                        url: '/webapp$hash/load?' + tg.initData,
                                        method: 'POST',
                                        data: {
                                            ty: {$jsType},
                                            te: {$jsTe}
                                        },
                                        dataType: 'json'
                                    }).done(function (r) {
                                        if (r && r.status == true) {
                                            editor.set(r.json);
                                        } else {
                                            tg.MainButton.setText('{$bot->i18n('error')}')
                                        }
                                    }).fail(function (r) {
                                        tg.MainButton.setText('{$bot->i18n('error')}')
                                    });
                                    tg.MainButton.show().setText('{$bot->i18n('save')}').onClick(function (e) {
                                        var self = this;
                                        $.ajax({
                                            url: '/webapp$hash/save?' + tg.initData,
                                            method: 'POST',
                                            data: {
                                                name: {$jsName},
                                                type: {$jsType},
                                                json: editor.getText()
                                            },
                                            dataType: 'json'
                                        }).done(function (r) {
                                            if (r.status == true) {
                                                tg.MainButton.setText('{$bot->i18n('success')}')
                                                setTimeout(() => {
                                                    tg.close();
                                                }, 500);
                                            } else {
                                                tg.MainButton.setText(r.message);
                                            }
                                        }).fail(function (r) {
                                            tg.MainButton.setText('{$bot->i18n('error')}')
                                        });
                                    });
                                });
                            </script>
                        </body>
                        </html>
                        HTML;
                exit;

            case 'changelog':
                // Changelog показываем из СВОЕГО репозитория, а не из upstream.
                // raw.githubusercontent для приватного репо отдаёт 404 (токена
                // в web_app-URL не передать), поэтому берём version-файл через
                // git: в remote приватного репо уже встроен x-access-token, так
                // что fetch/show работают. Показываем версию из удалённой ветки
                // (то, что приедет при обновлении); если git недоступен —
                // откатываемся на локально установленный /version.
                header('Content-Type: text/plain; charset=utf-8');
                // `git fetch` — сетевая операция, а эндпоинт доступен любому
                // владельцу ссылки подписки и ничем не ограничен: в цикле это
                // сколько угодно параллельных fetch'ей. Отдаём из кэша не чаще
                // раза в минуту (инъекции нет, escapeshellarg на месте).
                $cache = sys_get_temp_dir() . '/changelog.cache';
                if (is_file($cache) && time() - filemtime($cache) < 60) {
                    echo (string) file_get_contents($cache);
                    exit;
                }
                $b = exec('git -C / rev-parse --abbrev-ref HEAD');
                exec('git -C / fetch -q 2>/dev/null');
                $log = shell_exec('git -C / show ' . escapeshellarg("origin/$b:version") . ' 2>/dev/null');
                if (empty(trim((string) $log))) {
                    $log = @file_get_contents('/version');
                }
                @file_put_contents($cache, (string) $log);
                echo $log;
                exit;

            default:
                // $type приходит из query и подставляется в путь. Без проверки
                // ?t=../config.php отдавал app/config.php с токеном бота, а $hash
                // в URI известен любому владельцу подписки. Разрешаем только имя
                // файла: словарные символы, точка и дефис, и никаких «..».
                if (preg_match('~^[\w.-]+$~', (string) $type) && !str_contains((string) $type, '..')
                    && file_exists($file = __DIR__ . "/zapretlists/$type")) {
                    $pac = file_get_contents($file);
                    header('Content-Type: text/plain');
                    echo str_replace([
                        '~address~',
                        '~port~',
                    ], [
                        $address,
                        $port,
                    ], $pac);
                    exit;
                }
                break;
        }
        break;

    default:
        // Было header('500', true, 500): PHP ждёт «Header: value», получал «500»
        // и слал его как мусорный заголовок — Unit на каждый ответ писал
        // «colon not found in header '500'». Статус выставляем напрямую.
        http_response_code(500);
}
