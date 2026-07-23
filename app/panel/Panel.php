<?php

require_once __DIR__ . '/PanelTransport.php';

/**
 * Веб-панель управления ботом — полноценная замена Telegram-интерфейса.
 *
 * Ничего не дублирует: клик по кнопке превращается в такой же update, какой
 * прислал бы Telegram, и уходит в Bot::input(); ответы бота перехватывает
 * PanelTransport и складывает в PanelStore, откуда их забирает UI.
 *
 * Доступ — только с отдельного слушателя unit (порт PANEL_PORT), который
 * проброшен на 127.0.0.1 хоста: снаружи панели нет вообще, ходить в неё
 * полагается через `ssh -L`. Пароль — второй барьер, а не единственный.
 */
class Panel
{
    private const COOKIE     = 'panel';
    private const TTL        = 43200; // 12 часов
    private const MAX_TRIES  = 5;
    private const TRY_WINDOW = 300;
    private const MAX_UPLOAD = 20971520; // 20 MiB

    private $bot;
    private $key;
    private $admins;
    private $store;
    private $transport;
    private $prefix;

    public function __construct(Bot $bot, array $c, $store = null)
    {
        $this->bot       = $bot;
        $this->key       = (string) ($c['key'] ?? '');
        $this->admins    = array_values((array) ($c['admin'] ?? []));
        $this->store     = $store ?: new PanelStore(self::dataDir());
        $this->transport = new PanelTransport($this->store);
        $this->prefix    = '/panel' . $bot->getHashBot();
    }

    public static function dataDir()
    {
        return getenv('PANEL_DIR') ?: '/config/panel';
    }

    /** Порт выделенного слушателя unit (см. config/unit.json). */
    public static function port()
    {
        return (int) (getenv('PANEL_PORT') ?: 8090);
    }

    /**
     * Панель обслуживается ТОЛЬКО своим слушателем. На публичном 443 её
     * маршруты не существуют — поэтому в nginx для неё ничего не заводится и
     * снаружи она не отвечает даже 401.
     */
    public static function isPanelPort()
    {
        return (int) ($_SERVER['SERVER_PORT'] ?? 0) === self::port();
    }

    public function prefix()
    {
        return $this->prefix;
    }

    public function matches($uri)
    {
        $path = parse_url((string) $uri, PHP_URL_PATH) ?: '';

        return $path === $this->prefix || str_starts_with($path, $this->prefix . '/');
    }

    // ── маршрутизация ───────────────────────────────────────────────────────

    public function route($uri)
    {
        $path   = parse_url((string) $uri, PHP_URL_PATH) ?: '';
        $action = trim(substr($path, strlen($this->prefix)), '/');
        $post   = 'POST' === ($_SERVER['REQUEST_METHOD'] ?? 'GET');

        // Кука выдаётся на путь /panel<hash>/ и на сам /panel<hash> браузером
        // уже не отправляется — без редиректа страница без слэша всегда
        // показывала бы форму входа, хотя вход выполнен.
        if ($path === $this->prefix && !$post) {
            http_response_code(302);
            header('Location: ' . $this->prefix . '/');

            return;
        }

        // Все изменяющие запросы обязаны нести собственный заголовок: браузер
        // не поставит его в кросс-сайтовой форме, поэтому CSRF отпадает даже
        // без токена в теле.
        if ($post && empty($_SERVER['HTTP_X_PANEL'])) {
            return $this->json(['ok' => false, 'error' => 'bad request'], 400);
        }

        if ('login' === $action && $post) {
            return $this->login();
        }

        if (!$this->authed()) {
            if ('' === $action) {
                return $this->page(false);
            }

            return $this->json(['ok' => false, 'error' => 'auth'], 401);
        }

        // Статика редактора шаблонов лежит в /app/webapp и наружу отдаётся
        // nginx'ом; на панельном слушателе nginx'а нет, отдаём сами.
        if (str_starts_with($action, 'a/')) {
            return $this->asset(substr($action, 2));
        }

        switch ($action) {
            case '':
                return $this->page(true);

            case 'logout':
                return $this->logout();

            case 'editor':
                return $this->editor();

            case 'tload':
                return $this->tload();

            case 'tsave':
                return $this->tsave();

            case 'state':
                return $this->state();

            case 'click':
                return $this->click();

            case 'text':
                return $this->text();

            case 'upload':
                return $this->upload();

            case 'file':
                return $this->file();

            case 'reset':
                $this->store->reset();

                return $this->json(['ok' => true]);
        }

        http_response_code(404);
    }

    // ── аутентификация ──────────────────────────────────────────────────────

    /**
     * Пароль хранится хешем в pac.json (как adpswd у AdGuard). Если его ещё
     * нет — генерируем и кладём открытый текст в файл рядом со стором: до
     * первого входа других каналов доставки нет, а SSH-доступ у владельца по
     * условию есть.
     */
    public function ensurePassword()
    {
        $conf = $this->bot->getPacConf() ?: [];
        if (!empty($conf['panelpswd'])) {
            return null;
        }
        $plain            = bin2hex(random_bytes(9));
        $conf['panelpswd'] = password_hash($plain, PASSWORD_DEFAULT);
        $this->bot->setPacConf($conf);
        $f = $this->store->dir() . '/initial_password.txt';
        @touch($f);
        @chmod($f, 0600);
        file_put_contents($f, "$plain\n");

        return $plain;
    }

    public function setPassword($plain)
    {
        $conf              = $this->bot->getPacConf() ?: [];
        $conf['panelpswd'] = password_hash((string) $plain, PASSWORD_DEFAULT);
        $this->bot->setPacConf($conf);
        @unlink($this->store->dir() . '/initial_password.txt');
    }

    private function passwordHash()
    {
        return (string) (($this->bot->getPacConf() ?: [])['panelpswd'] ?? '');
    }

    private function login()
    {
        if (!$this->rateOk()) {
            return $this->json(['ok' => false, 'error' => 'too many attempts'], 429);
        }
        $hash = $this->passwordHash();
        $pass = (string) ($_POST['password'] ?? '');
        if ('' === $hash || !password_verify($pass, $hash)) {
            $this->rateHit();
            // Пауза сглаживает перебор и разницу во времени между «пароль не
            // задан» и «пароль неверный».
            usleep(300000);

            return $this->json(['ok' => false, 'error' => 'wrong password'], 403);
        }
        $exp = time() + self::TTL;
        setcookie(self::COOKIE, $exp . '.' . $this->sign($exp), [
            'expires'  => $exp,
            'path'     => $this->prefix . '/',
            'httponly' => true,
            'samesite' => 'Strict',
        ]);

        return $this->json(['ok' => true]);
    }

    private function logout()
    {
        setcookie(self::COOKIE, '', [
            'expires'  => 1,
            'path'     => $this->prefix . '/',
            'httponly' => true,
            'samesite' => 'Strict',
        ]);

        return $this->json(['ok' => true]);
    }

    /**
     * Подпись куки завязана и на токен бота, и на текущий хеш пароля: смена
     * пароля разом обнуляет все выданные сессии.
     */
    private function sign($exp)
    {
        return hash_hmac('sha256', "panel|$exp|" . $this->passwordHash(), $this->key);
    }

    public function authed()
    {
        $v = (string) ($_COOKIE[self::COOKIE] ?? '');
        if (!preg_match('~^(\d+)\.([0-9a-f]{64})$~', $v, $m)) {
            return false;
        }
        if ((int) $m[1] < time()) {
            return false;
        }

        return hash_equals($this->sign((int) $m[1]), $m[2]);
    }

    private function rateFile()
    {
        return $this->store->dir() . '/login_attempts.json';
    }

    private function rateOk()
    {
        $t = json_decode((string) @file_get_contents($this->rateFile()), true) ?: [];
        $t = array_filter((array) $t, fn ($ts) => $ts > time() - self::TRY_WINDOW);

        return count($t) < self::MAX_TRIES;
    }

    private function rateHit()
    {
        $t   = json_decode((string) @file_get_contents($this->rateFile()), true) ?: [];
        $t   = array_values(array_filter((array) $t, fn ($ts) => $ts > time() - self::TRY_WINDOW));
        $t[] = time();
        @touch($this->rateFile());
        @chmod($this->rateFile(), 0600);
        file_put_contents($this->rateFile(), json_encode($t));
    }

    // ── страница ────────────────────────────────────────────────────────────

    private function page($authed)
    {
        header('Content-Type: text/html; charset=utf-8');
        header('X-Frame-Options: DENY');
        header('Referrer-Policy: no-referrer');
        self::csp();
        $html = (string) file_get_contents(__DIR__ . '/ui.html');
        echo strtr($html, [
            '{{PREFIX}}' => htmlspecialchars($this->prefix, ENT_QUOTES),
            '{{AUTH}}'   => $authed ? '1' : '0',
            '{{NOTE}}'   => htmlspecialchars($this->bootNote(), ENT_QUOTES),
        ]);
    }

    /**
     * Страница целиком своя (стили и скрипты инлайном, сторонних загрузок нет),
     * поэтому политика узкая: всё только со своего происхождения. Текст меню
     * приходит из логов и данных клиентов — если санитайзер когда-нибудь
     * пропустит тег, ему всё равно некуда будет обратиться.
     */
    private static function csp()
    {
        header("Content-Security-Policy: default-src 'self'; img-src 'self' data:; "
            . "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
            . "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'");
    }

    /** Подсказка на экране входа, если бот ещё не готов принимать команды. */
    private function bootNote()
    {
        if (empty($this->admins)) {
            return 'Бот ещё не присвоен: в config.php пуст $c[\'admin\']. Задайте свой Telegram-id: php panel.php admin <id>';
        }
        if ('' === $this->passwordHash()) {
            return 'Пароль не задан: php panel.php passwd';
        }

        return '';
    }

    // ── данные для UI ───────────────────────────────────────────────────────

    private function state()
    {
        $since = (int) ($_GET['since'] ?? 0);
        $s     = $this->store->since($since);
        foreach ($s['messages'] as &$m) {
            $m['html'] = self::renderText((string) ($m['text'] ?? ''));
            foreach ($m['buttons'] ?? [] as $ri => $row) {
                foreach ($row as $bi => $b) {
                    if (!empty($b['webapp']) && isset($b['url'])) {
                        $m['buttons'][$ri][$bi]['url'] = $this->panelizeUrl($b['url']);
                    }
                }
            }
        }
        unset($m);

        return $this->json(['ok' => true] + $s);
    }

    /**
     * Кнопки web_app ведут на публичный домен и рассчитаны на Telegram: там
     * страница получает initData, а здесь его взять неоткуда. Переписываем их
     * на панельное происхождение, а редактор шаблонов — на собственный
     * маршрут с шимом (см. editor()).
     */
    private function panelizeUrl($url)
    {
        $q    = parse_url($url, PHP_URL_QUERY) ?: '';
        $path = parse_url($url, PHP_URL_PATH) ?: '/';
        parse_str($q, $p);
        $origin = 'http://' . ($_SERVER['HTTP_HOST'] ?? ('127.0.0.1:' . self::port()));
        if (($p['t'] ?? '') === 'te') {
            return $origin . $this->prefix . '/editor?' . http_build_query([
                'ty' => $p['ty'] ?? '',
                'te' => $p['te'] ?? '',
            ]);
        }

        return $origin . $path . ($q ? '?' . $q : '');
    }

    private function asset($name)
    {
        $types = [
            'js'  => 'application/javascript',
            'css' => 'text/css',
            'svg' => 'image/svg+xml',
            'png' => 'image/png',
        ];
        $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
        // Имя приходит из URL: без белого списка расширений и запрета «..»
        // отсюда читался бы любой файл /app, включая config.php с токеном.
        if (!preg_match('~^[\w./-]+$~', $name) || str_contains($name, '..') || !isset($types[$ext])) {
            http_response_code(404);

            return;
        }
        $path = __DIR__ . '/../webapp/' . $name;
        if (!is_file($path)) {
            http_response_code(404);

            return;
        }
        header('Content-Type: ' . $types[$ext]);
        header('Cache-Control: max-age=86400');
        readfile($path);
    }

    /** Редактор шаблонов: та же JSONEditor-страница, но без Telegram. */
    private function editor()
    {
        $ty = preg_match('~^\w+$~', $_GET['ty'] ?? '') ? $_GET['ty'] : '';
        if ('' === $ty) {
            http_response_code(404);

            return;
        }
        $te   = (string) ($_GET['te'] ?? '');
        $name = $te ?: 'origin';
        // CSP здесь намеренно не ставим: JSONEditor поднимает Ace-воркер через
        // blob: и в режиме code полагается на eval — под политикой панели
        // редактор просто перестал бы открываться. Страница целиком своя и
        // грузит только собственную статику.
        header('Content-Type: text/html; charset=utf-8');
        $jPrefix = json_encode($this->prefix);
        $jTy     = json_encode($ty, JSON_UNESCAPED_UNICODE);
        $jTe     = json_encode($te, JSON_UNESCAPED_UNICODE);
        $jName   = json_encode($name, JSON_UNESCAPED_UNICODE);
        $eTy     = $this->esc($ty);
        $eName   = $this->esc($name);
        echo <<<HTML
        <!DOCTYPE html>
        <html lang="ru" style="height:100%">
        <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>$eTy: $eName</title>
        <link href="{$this->prefix}/a/jsoneditor.min.css" rel="stylesheet" type="text/css">
        <script src="{$this->prefix}/a/jsoneditor.min.js"></script>
        <style>
          html,body{margin:0;height:100%;font:14px sans-serif}
          #bar{height:44px;display:flex;align-items:center;gap:10px;padding:0 12px;background:#17212b;color:#e9edf1}
          #bar button{background:#3b82c4;color:#fff;border:0;border-radius:6px;padding:7px 14px;cursor:pointer}
          #jsoneditor{height:calc(100% - 44px)}
        </style>
        </head>
        <body>
        <div id="bar"><b>$eTy</b> / $eName<span style="flex:1"></span>
          <span id="st"></span><button id="save">Сохранить</button></div>
        <div id="jsoneditor"></div>
        <script>
        const P = $jPrefix, TY = $jTy, TE = $jTe, NAME = $jName;
        const editor = new JSONEditor(document.getElementById("jsoneditor"), {});
        const st = document.getElementById("st");
        const post = (u, o) => fetch(P + u, {method:"POST", headers:{"X-Panel":"1"}, body:o});
        const fd = o => { const f = new FormData(); for (const k in o) f.append(k, o[k]); return f; };
        editor.set({});
        post("/tload", fd({ty:TY, te:TE})).then(r => r.json()).then(r => {
          if (r && r.status) editor.set(r.json); else st.textContent = "ошибка загрузки";
        }).catch(() => st.textContent = "ошибка загрузки");
        document.getElementById("save").onclick = () => {
          st.textContent = "сохраняю…";
          post("/tsave", fd({name:NAME, type:TY, json:editor.getText()}))
            .then(r => r.json())
            .then(r => { st.textContent = r.status ? "сохранено" : (r.message || "ошибка"); })
            .catch(() => st.textContent = "ошибка");
        };
        </script>
        </body>
        </html>
        HTML;
    }

    private function esc($s)
    {
        return htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');
    }

    private function tload()
    {
        $ty = preg_match('~^\w+$~', $_POST['ty'] ?? '') ? $_POST['ty'] : '';
        if ('' === $ty) {
            return $this->json(['status' => false]);
        }
        $te = (string) ($_POST['te'] ?? '');
        $t  = '' !== $te
            ? ($this->bot->getPacConf()["{$ty}templates"][$te] ?? null)
            : json_decode((string) @file_get_contents("/config/$ty.json"), true);

        return $this->json([
            'status' => (bool) $t,
            'json'   => $t ?: new stdClass(),
        ]);
    }

    private function tsave()
    {
        if (empty($_POST['json'])) {
            return $this->json(['status' => false, 'message' => 'empty']);
        }

        return $this->json($this->bot->saveTemplate($_POST['name'] ?? '', $_POST['type'] ?? '', $_POST['json']));
    }

    /**
     * Телеграмный HTML → безопасный HTML для браузера.
     *
     * Текст меню собирается из данных клиентов, логов и вывода команд, поэтому
     * доверять ему нельзя. Экранируем всё, затем возвращаем к жизни только
     * теги из белого списка Telegram.
     */
    public static function renderText($text)
    {
        $e = htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $t = 'b|strong|i|em|u|ins|s|strike|del|code|pre|blockquote|tg-spoiler';
        $e = preg_replace('~&lt;(/?)(' . $t . ')&gt;~i', '<$1$2>', $e);
        $e = preg_replace('~&lt;span class=(&quot;|&#039;)tg-spoiler\1&gt;~i', '<span class="tg-spoiler">', $e);
        $e = str_replace('&lt;/span&gt;', '</span>', $e);
        $e = preg_replace('~&lt;code class=(&quot;|&#039;)language-([\w-]+)\1&gt;~i', '<code class="language-$2">', $e);
        $e = preg_replace_callback('~&lt;a href=(&quot;|&#039;)(.*?)\1&gt;~i', function ($m) {
            $u = html_entity_decode($m[2], ENT_QUOTES, 'UTF-8');
            // Только http(s): javascript:/data: в тексте меню взялись бы из
            // данных и выполнились бы кликом.
            if (!preg_match('~^https?://~i', $u)) {
                return '';
            }

            return '<a href="' . htmlspecialchars($u, ENT_QUOTES) . '" target="_blank" rel="noopener noreferrer">';
        }, $e);
        $e = str_replace('&lt;/a&gt;', '</a>', $e);

        // Переносы превращаем в <br> ВЕЗДЕ, КРОМЕ <pre>: там перенос уже
        // отображается сам (white-space: pre-wrap), и <br> внутри давал бы
        // двойные пустые строки во всех диагностиках и логах.
        $parts = preg_split('~(<pre>.*?</pre>)~s', $e, -1, PREG_SPLIT_DELIM_CAPTURE);
        foreach ($parts as $i => $p) {
            if (!str_starts_with($p, '<pre>')) {
                $parts[$i] = nl2br($p, false);
            }
        }

        return implode('', $parts);
    }

    private function file()
    {
        $id = (string) ($_GET['id'] ?? '');
        if (!$this->store->fileExists($id)) {
            http_response_code(404);

            return;
        }
        $path = $this->store->filePath($id);
        $name = preg_replace('~^[0-9a-f]{16}_~', '', $id);
        // nosniff ниже означает, что браузер поверит типу буквально: «image/jpg»
        // (такого типа нет) не отрисовался бы вовсе — сопоставляем явно.
        $imgTypes = [
            'png'  => 'image/png',
            'jpg'  => 'image/jpeg',
            'jpeg' => 'image/jpeg',
            'gif'  => 'image/gif',
            'webp' => 'image/webp',
        ];
        $type = $imgTypes[strtolower(pathinfo($name, PATHINFO_EXTENSION))] ?? null;
        $img  = null !== $type;
        header('Content-Type: ' . ($type ?: 'application/octet-stream'));
        header('Content-Length: ' . filesize($path));
        header('Content-Disposition: ' . ($img ? 'inline' : 'attachment') . '; filename="' . str_replace('"', '', $name) . '"');
        header('X-Content-Type-Options: nosniff');
        readfile($path);
    }

    // ── ввод: клики, текст, файлы ───────────────────────────────────────────

    private function click()
    {
        $mid = (int) ($_POST['message_id'] ?? 0);
        $cb  = (string) ($_POST['data'] ?? '');
        if (!$mid || '' === $cb) {
            return $this->json(['ok' => false, 'error' => 'bad request'], 400);
        }
        $msg = $this->store->read()['messages'][$mid] ?? null;

        return $this->dispatch([
            'callback_query' => [
                'id'      => (string) $mid . '.' . time(),
                'from'    => $this->fromUser(),
                'data'    => $cb,
                'message' => [
                    'message_id' => $mid,
                    'date'       => time(),
                    'text'       => (string) ($msg['text'] ?? ''),
                    'chat'       => ['id' => $this->chatId(), 'type' => 'private'],
                ],
            ],
        ]);
    }

    private function text()
    {
        $text = (string) ($_POST['text'] ?? '');
        $to   = (int) ($_POST['reply_to'] ?? 0);
        if ('' === trim($text)) {
            return $this->json(['ok' => false, 'error' => 'empty'], 400);
        }

        return $this->dispatch($this->userMessage(['text' => $text], $to));
    }

    private function upload()
    {
        $limit = $this->uploadLimit();
        $f     = $_FILES['file'] ?? null;
        // Превышение post_max_size PHP отбрасывает ДО нас: $_FILES и $_POST
        // пустые, ошибки в них нет. Без отдельной проверки пользователь видел
        // бы невнятное «upload failed» на любом большом файле.
        if (empty($_FILES) && (int) ($_SERVER['CONTENT_LENGTH'] ?? 0) > $limit) {
            return $this->json(['ok' => false, 'error' => 'файл больше ' . $this->human($limit) . ' (php.ini)'], 413);
        }
        if (empty($f) || !is_uploaded_file($f['tmp_name'] ?? '') || ($f['error'] ?? 1) !== UPLOAD_ERR_OK) {
            return $this->json(['ok' => false, 'error' => 'upload failed'], 400);
        }
        if (($f['size'] ?? 0) > $limit) {
            return $this->json(['ok' => false, 'error' => 'файл больше ' . $this->human($limit)], 413);
        }
        // Загруженные файлы к сообщениям не привязаны (reply() удаляет наш
        // бабл ДО того, как обработчик прочитает файл), поэтому их не
        // подчистит вытеснение ленты — убираем старьё сами.
        $this->store->pruneUploads();
        $body = (string) file_get_contents($f['tmp_name']);
        $name = (string) ($f['name'] ?? 'file');
        // Имя в хранилище работает как file_id: обработчики импорта берут
        // содержимое через getFile() + Bot::$file, который в панель-режиме
        // указывает в ту же папку.
        $id      = $this->store->storeFile($body, $name);
        $caption = (string) ($_POST['caption'] ?? '');

        return $this->dispatch($this->userMessage([
            'document' => ['file_id' => $id, 'file_name' => $name],
            'caption'  => $caption,
            'text'     => '',
        ], (int) ($_POST['reply_to'] ?? 0), '📎 ' . $name . ($caption ? " ($caption)" : '')));
    }

    /** Реальный потолок загрузки: меньшее из наших 20 МиБ и лимитов php.ini. */
    private function uploadLimit()
    {
        $bytes = function ($v) {
            $n = (int) $v;
            switch (strtolower(substr(trim((string) $v), -1))) {
                case 'g': return $n * 1024 * 1024 * 1024;
                case 'm': return $n * 1024 * 1024;
                case 'k': return $n * 1024;
            }

            return $n;
        };

        return min(array_filter([
            self::MAX_UPLOAD,
            $bytes(ini_get('upload_max_filesize')),
            $bytes(ini_get('post_max_size')),
        ]));
    }

    private function human($bytes)
    {
        return $bytes >= 1048576 ? round($bytes / 1048576, 1) . ' МиБ' : round($bytes / 1024) . ' КиБ';
    }

    /**
     * Сообщение «от пользователя»: сначала кладём его в ленту (UI должен
     * видеть свою реплику), затем отдаём его же как update — id совпадает,
     * поэтому reply_to из force_reply-диалогов ссылается на существующий бабл.
     */
    private function userMessage(array $fields, $replyTo = 0, $bubble = null)
    {
        $id  = $this->store->put([
            'text' => $bubble ?? (string) ($fields['text'] ?? ''),
            'own'  => true,
            'to'   => $replyTo ?: null,
        ]);
        $msg = [
            'message_id' => $id,
            'date'       => time(),
            'from'       => $this->fromUser(),
            'chat'       => ['id' => $this->chatId(), 'type' => 'private'],
        ] + $fields;
        if ($replyTo) {
            $prev = $this->store->read()['messages'][$replyTo] ?? null;
            $msg['reply_to_message'] = [
                'message_id' => $replyTo,
                'text'       => (string) ($prev['text'] ?? ''),
                'from'       => ['id' => 0],
            ];
        }

        return ['message' => $msg];
    }

    private function fromUser()
    {
        return ['id' => $this->chatId(), 'username' => 'panel', 'is_bot' => false];
    }

    private function chatId()
    {
        return $this->admins[0] ?? 0;
    }

    /**
     * Прогон update через штатный конвейер бота: auth() → session() →
     * action(). Транспорт подменён, поэтому все ответы осядут в сторе.
     */
    private function dispatch(array $update)
    {
        if (empty($this->admins)) {
            return $this->json(['ok' => false, 'error' => 'admin is not configured'], 409);
        }
        // Куки сессий выключаем, как в init.php: Bot::session() выставляет
        // session_id вручную, а PHPSESSID в браузере — это утечка id админа и
        // лишний конфликт при следующем запросе.
        ini_set('session.use_cookies', 0);
        // В Telegram обработчики крутятся в CLI-процессе polling'а, где лимита
        // нет. Здесь это обычный запрос под unit с max_execution_time = 30 из
        // php.ini — обновление, certbot и рестарты обрывались бы на середине.
        // ignore_user_abort: закрытая вкладка не должна ронять уже начатую
        // перенастройку.
        set_time_limit(0);
        ignore_user_abort(true);
        $this->attach();
        try {
            $this->bot->input($update);
        } catch (Throwable $e) {
            error_log('panel dispatch: ' . $e);
            $this->store->toast('error: ' . $e->getMessage(), true);
        } finally {
            if (PHP_SESSION_ACTIVE === session_status()) {
                session_write_close();
            }
        }

        return $this->json(['ok' => true]);
    }

    /** Подключает панельный транспорт к боту (и путь скачивания файлов). */
    public function attach()
    {
        $this->bot->transport = $this->transport;
        $this->bot->file      = $this->store->filesDir();
    }

    public function store()
    {
        return $this->store;
    }

    private function json($data, $code = 200)
    {
        http_response_code($code);
        header('Content-Type: application/json; charset=utf-8');
        // Опрос ленты идёт по одному и тому же URL, пока не поменяется rev —
        // кэш браузера тут только мешает.
        header('Cache-Control: no-store');
        echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }
}
