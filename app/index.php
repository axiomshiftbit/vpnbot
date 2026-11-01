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
require __DIR__ . '/panel/Panel.php';

$bot  = new Bot($c['key'], $i);
$hash = $bot->getHashBot();

// Веб-панель существует ТОЛЬКО на своём слушателе unit (PANEL_PORT), который
// проброшен на 127.0.0.1 хоста и доступен через ssh -L. На публичном 443 её
// маршрутов нет вовсе — поэтому в nginx для неё ничего не заводится, а
// /panel<hash> снаружи отвечает так же, как любой несуществующий путь.
if (Panel::isPanelListener()) {
    // Проверка источника стоит на ВЕСЬ слушатель, а не только на /panel<hash>.
    // Слушатель висит на *:8090 внутри контейнера, то есть виден всей
    // 10.10.0.0/24, которую freedom-outbound xray разрешает явно, — и всё, что
    // не панель, обслуживал бы этот же index.php: подписки /pac<hash>,
    // t=changelog (а он дёргает `git fetch`), /webapp<hash>/*, вебхук /tlgrm.
    // На публичном 443 те же маршруты стоят за nginx, а тут — голый unit.
    // Панельные ссылки (panelizeUrl ведёт web_app-кнопки на этот же origin)
    // открывает админ с хоста, то есть с loopback/шлюза, и под запрет не
    // попадает.
    if (!Panel::clientAllowed()) {
        Panel::denyClient();
        exit;
    }
    if (!Panel::hostAllowed()) {
        Panel::denyHost();
        exit;
    }
    $panel = new Panel($bot, $c);
    if ($panel->matches($_SERVER['REQUEST_URI'])) {
        $panel->route($_SERVER['REQUEST_URI']);
        exit;
    }
}
// Проверка initData вынесена в Bot::webappAuth(): подпись + окно жизни
// auth_date + сверка user.id со списком админов. Подробности — там же.
$webapp = $bot->webappAuth($_GET, $c['key'], (array) ($c['admin'] ?? []));

switch (true) {
    // Пропуск в веб-панель AdGuard: подзапрос nginx (auth_request) перед
    // каждым запросом к /adguard<hash>/. 204 — пускать, 401 — в мини-приложение.
    case parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) === "/adguard$hash-gate":
        http_response_code($bot->adguardGateCheck(is_string($_COOKIE['adg'] ?? null) ? $_COOKIE['adg'] : '', 'cookie') ? 204 : 401);
        exit;

    // Одноразовая ссылка администратора для стороннего браузера (кнопка в
    // меню AdGuard при включённом «сторонний браузер»).
    case parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) === "/webapp$hash/adg":
        header('Cache-Control: no-store');
        header('Referrer-Policy: no-referrer');
        $token = is_string($_GET['t'] ?? null) ? $_GET['t'] : '';
        if (empty($bot->getPacConf()['adgbrowser']) || !$bot->adguardLinkConsume($token)) {
            http_response_code(403);
            header('Content-Type: text/plain; charset=utf-8');
            echo "The link is invalid, expired or already used. Request a new one in the bot.\n";
            exit;
        }
        $bot->adguardSetGateCookie($hash, Bot::ADGUARD_BROWSER_TTL);
        header("Location: /adguard$hash/", true, 302);
        exit;

    // tlgrm
    case 'POST' == $_SERVER['REQUEST_METHOD'] && preg_match('~^/tlgrm~', $_SERVER['REQUEST_URI']) && hash_equals($c['key'], (string) ($_GET['k'] ?? '')):
        $bot->input();
        break;

    // save template
    // $type уходит в путь /config/<type>.json (saveTemplate при name=origin) и
    // в ключ конфига — та же проверка, что на load ниже. Гейт $webapp тут уже
    // стоит, так что это защита от собственной опечатки, а не от чужака, но
    // цена ошибки — затёртый pac.json мимо setPacConf.
    case preg_match('~^' . preg_quote("/webapp$hash/save") . '~', $_SERVER['REQUEST_URI']) && $webapp && !empty($_POST['json']):
        header('Content-Type: application/json');
        if (!preg_match('~^\w+$~', (string) ($_POST['type'] ?? ''))) {
            echo json_encode(['status' => false, 'message' => 'bad type']);
            break;
        }
        echo json_encode($bot->saveTemplate($_POST['name'], $_POST['type'], $_POST['json']));
        break;

    // load template — содержимое редактора отдаём ТОЛЬКО по подписанному
    // initData. Параметры кладём в POST-тело, а не в query: HMAC считается по
    // всем $_GET, и лишний параметр в строке запроса сломал бы проверку.
    case preg_match('~^' . preg_quote("/webapp$hash/load") . '~', $_SERVER['REQUEST_URI']) && $webapp:
        header('Content-Type: application/json');
        // is_string ДО preg_match: «ty[]=x» приходит массивом, а preg_match с
        // массивом во втором аргументе — TypeError, то есть фатал вместо ответа
        // (та же находка, что уже закрыта в webappAuth для параметров подписи).
        $ty = (is_string($_POST['ty'] ?? null) && preg_match('~^\w+$~', $_POST['ty'])) ? $_POST['ty'] : '';
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

    // Любой /webapp$hash/*, не прошедший гейт, до этой ветки проваливался в
    // default и отвечал 500 — неотличимо от настоящей поломки, а в редакторе
    // виден одинаковый «error». Причина отказа уходит в лог из webappAuth().
    case preg_match('~^' . preg_quote("/webapp$hash/") . '~', $_SERVER['REQUEST_URI']) && !$webapp:
        http_response_code(403);
        header('Content-Type: application/json');
        echo json_encode(['status' => false]);
        break;

    // adguard cookie
    case preg_match('~^' . preg_quote("/webapp$hash/check") . '~', $_SERVER['REQUEST_URI']) && $webapp:
        // Сюда попадает только администратор: initData подписан Telegram и
        // сверен со списком админов ($webapp). httponly, samesite и secure
        // ставит adguardSetGateCookie (secure — только на HTTPS: без
        // сертификата cookie с ним не сохранится, и вход в панель сломается).
        // Пропуск — подписанный ключом бота токен со сроком, а не публичный
        // hash из ссылок подписки (его мог выставить себе любой подписчик).
        $bot->adguardSetGateCookie($hash, Bot::ADGUARD_GATE_TTL);
        echo "/adguard$hash/";
        break;

    case str_starts_with((string) parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), "/pac$hash/node/"):
        if (preg_match('~^' . preg_quote("/pac$hash/node/", '~') . '([a-f0-9]{8})/([a-f0-9]{64})/(sub|json)$~D',
            (string) parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), $m)) $bot->managedNodeSubscription($m[1], $m[2], $m[3]);
        else { $bot->subSecurityHeaders(); $bot->subRateLimit('', 'miss'); http_response_code(404); }
        break;
    case str_starts_with((string) parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), "/pac$hash/protocol/"):
        if (preg_match('~^' . preg_quote("/pac$hash/protocol/", '~') . '(anytls|mieru|tuic|shadowtls|snolc|masque)/([a-f0-9]{64})/(singbox|mihomo|uri|native|native-uri)$~D',
            (string) parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), $m)) {
            $bot->protocolMachine($m[1], $m[2], $m[3]);
        } else {
            $bot->subRateLimit('', 'miss');
            http_response_code(404);
        }
        exit;

    case preg_match('~^' . preg_quote("/pac$hash/sub") . '~', $_SERVER['REQUEST_URI']) && file_exists(__DIR__ . '/subscription.php'):
        $bot->sub();
        exit;

    // subs & pac
    case preg_match('~^' . preg_quote("/pac$hash") . '~', $_SERVER['REQUEST_URI']):
        // allowed_classes=false: payload — массив GET-параметров, объекты не
        // нужны; запрет их инстанцирования закрывает PHP object injection.
        // is_array: подделанный токен может нести скаляр («s:3:"abc";»), а
        // array_merge со скаляром — фатальный TypeError в PHP 8 вместо 404.
        // ?? '' — третьего сегмента пути может не быть вовсе: так открывают
        // редактор шаблонов (/pac<hash>?t=te), changelog и обычный pac, и на
        // каждом таком запросе шло «Undefined array key 2» плюс
        // base64_decode(null) (deprecated в PHP 8.1).
        $path = (string) parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
        $seg = str_starts_with($path, "/pac$hash/") ? substr($path, strlen("/pac$hash/")) : '';
        // Read both legacy base64 (including '/' inside relay names) and new
        // URL-safe tokens. Percent escapes belong to the path, not the payload.
        $seg = strtr(rawurldecode($seg), '-_', '+/');
        if (is_array($t = @unserialize((string) base64_decode($seg, true), ['allowed_classes' => false])) && $t) { // fix sing-box import
            // Запоминаем состав токена до слияния: subscription() отличает по нему
            // выборку rule-set'а ядром (параметры из токена) от deep-link'а
            // импорта (те же имена параметров, но из query-string).
            $bot->subToken = $t;
            $_GET = array_merge($_GET, $t);
        }
        $type    = $_GET['t'] ?? 'pac';
        // Значения подставляются в тело PAC-файла, а PAC — это JS, который
        // браузер исполняет в роли автоконфига прокси. Отражать туда
        // произвольную строку из query незачем: адрес — хостнейм или IP, порт —
        // число в допустимом диапазоне, иначе берём дефолт.
        $address = trim((string) ($_GET['a'] ?? ''));
        if ($address === '' || (!$bot->isHostname($address) && filter_var($address, FILTER_VALIDATE_IP) === false)) {
            $address = '127.0.0.1';
        }
        $port = (int) ($_GET['p'] ?? 0);
        $port = ($port >= 1 && $port <= 65535) ? (string) $port : '1080';
        switch ($type) {
            case 's':
            case 'si':
            case 'cl':
            case 'clj':
                $bot->subscription();
                exit;

            case 'vl':
                $bot->subVless();
                exit;

            case 'te':
                // $_GET['ty'] попадает в путь /config/<ty>.json и ключ конфига —
                // ограничиваем словом (\w), иначе `ty=../..` читает произвольный .json.
                // is_string обязателен: «?t=te&ty[]=x» доступен любому владельцу
                // ссылки подписки и без него давал TypeError → 500 вместо 404.
                $ty = (is_string($_GET['ty'] ?? null) && preg_match('~^\w+$~', $_GET['ty'])) ? $_GET['ty'] : '';
                if ($ty === '') {
                    http_response_code(404);
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
                // git: доступ к приватному репо даёт deploy-ключ из /.git, так
                // что fetch/show работают. Показываем версию из удалённой ветки
                // (то, что приедет при обновлении); если git недоступен —
                // откатываемся на локально установленный /version.
                header('Content-Type: text/plain; charset=utf-8');
                header('X-Content-Type-Options: nosniff');
                // С ключом из кнопки администратора — история изменений своего
                // репозитория; без ключа (ссылку знает любой владелец
                // подписки) — только прежний общий список версий.
                $admin = is_string($_GET['k'] ?? null) && hash_equals($bot->changelogKey(), $_GET['k']);
                // `git fetch` — сетевая операция, а эндпоинт доступен любому
                // владельцу ссылки подписки и ничем не ограничен: в цикле это
                // сколько угодно параллельных fetch'ей. Отдаём из кэша не чаще
                // раза в минуту (инъекции нет, escapeshellarg на месте).
                // Имя выводим из ключа бота, а не берём предсказуемое: файл
                // лежит в общем /tmp, и заранее созданный кем-то другим
                // changelog.cache заставил бы @file_put_contents молча
                // провалиться, а нас — отдавать чужое содержимое.
                $cache = sys_get_temp_dir() . '/changelog_' . hash('sha256', $c['key'] . ($admin ? '|admin' : '')) . '.cache';
                if (is_file($cache) && time() - filemtime($cache) < 60) {
                    echo (string) file_get_contents($cache);
                    exit;
                }
                // Кэш проверяется ДО работы и пишется ПОСЛЕ, без блокировки:
                // N параллельных запросов давали N параллельных `git fetch`
                // (сетевая операция) плюс `git show` — по три форка на запрос,
                // то есть исчерпание шести воркеров unit и остановку выдачи
                // подписок вместе с вебхуком бота. Эндпоинт при этом не требует
                // ни sid, ни subtoken: достаточно знать hash из любой ссылки.
                //
                // Ведро лимитера — своё: у changelog нет sid, а общий счётчик
                // подписок он бы вычерпывал.
                $bot->subRateLimit('', 'changelog');
                // Работает ОДИН процесс, остальные отдают что есть. LOCK_NB:
                // ждать под локом означало бы ровно ту же очередь из воркеров.
                $h = @fopen($cache . '.lock', 'c');
                if ($h === false || !flock($h, LOCK_EX | LOCK_NB)) {
                    echo is_file($cache) ? (string) file_get_contents($cache) : (string) @file_get_contents('/version');
                    exit;
                }
                if ($admin) {
                    $log = $bot->changelogBuild();
                } else {
                    $b = exec('git -C / rev-parse --abbrev-ref HEAD');
                    exec('git -C / fetch -q 2>/dev/null');
                    $log = shell_exec('git -C / show ' . escapeshellarg("origin/$b:version") . ' 2>/dev/null');
                }
                if (empty(trim((string) $log))) {
                    $log = @file_get_contents('/version');
                }
                @file_put_contents($cache, (string) $log);
                flock($h, LOCK_UN);
                fclose($h);
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
                    // Та же обвязка, что у остальных подписочных ответов:
                    // nosniff, no-store, noindex. Эта ветка её не проходила.
                    $bot->subSecurityHeaders();
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
                // Отбитый traversal и просто несуществующий список отдавали
                // пустой 200 — «файл есть, но пустой» вместо «нет такого».
                http_response_code(404);
                break;
        }
        break;

    // Панель обслуживается только своим слушателем (ветка выше). Отдельная
    // ветка нужна, чтобы с публичного 443 путь выглядел обычным «нет такой
    // страницы», а не 500 из default — по 500 факт существования панели
    // угадывался бы.
    case preg_match('~^/panel~', $_SERVER['REQUEST_URI']):
        http_response_code(404);
        break;

    default:
        // Было header('500', true, 500): PHP ждёт «Header: value», получал «500»
        // и слал его как мусорный заголовок — Unit на каждый ответ писал
        // «colon not found in header '500'». Статус выставляем напрямую.
        http_response_code(500);
}
