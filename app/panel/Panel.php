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

    /** Действия, меняющие состояние: только POST (см. route()). */
    private const MUTATING = ['login', 'logout', 'click', 'text', 'upload', 'reset', 'tload', 'tsave', 'dismiss'];

    private $bot;
    private $key;
    private $admins;
    private $store;
    private $transport;
    private $prefix;
    /** Чьей личностью действует текущая сессия — заполняет authed(), см. §1 плана мультиадминства. */
    private $actingAdmin;

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
     *
     * Проверять SERVER_PORT нельзя: unit 1.31 подставляет PHP 80 на любом
     * слушателе (проверено на 1.31.1 — панель отвечала 404 на своём же порту).
     * SERVER_NAME/Host тоже не годятся — их задаёт клиент. Признак даёт
     * config/unit.json: у *:8090 своё приложение со script panel/entry.php,
     * и только этот файл объявляет константу.
     */
    public static function isPanelListener()
    {
        return defined('PANEL_LISTENER');
    }

    /**
     * Кто вообще вправе обратиться к панели.
     *
     * Слушатель unit висит на *:8090 ВНУТРИ контейнера, то есть доступен всей
     * docker-сети 10.10.0.0/24 — а freedom-outbound xray её явно разрешает
     * (Bot::ensureFreedomCompat: allow 10.10.0.0/16, иначе ломается warp).
     * Значит любой vless/vmess/trojan-клиент мог открыть
     * http://10.10.0.7:8090/panel<hash>/ и получить форму входа: <hash> лежит в
     * каждой ссылке подписки, угадывать его не надо. «Снаружи панели нет»
     * держалось только на том, что порт опубликован на 127.0.0.1 хоста, но
     * контейнерную сеть публикация не закрывает.
     *
     * Легитимный источник ровно один — шлюз docker-сети (10.10.0.1): с него
     * приходит и проброшенный порт (docker-proxy/DNAT), и обращение с хоста
     * напрямую на 10.10.0.7. Соседний контейнер приходит со своего адреса
     * (xray — 10.10.0.9, wg — 10.10.0.4), и подменить его VPN-клиент не может:
     * наружу идёт новое TCP-соединение самого контейнера.
     *
     * PANEL_TRUSTED (.env) добавляет адреса/CIDR, '*' снимает проверку.
     */
    public static function clientAllowed($ip = null)
    {
        $ip  = self::normalizeIp((string) ($ip ?? ($_SERVER['REMOTE_ADDR'] ?? '')));
        $env = trim((string) getenv('PANEL_TRUSTED'));
        if ('*' === $env) {
            return true;
        }
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }
        $allow = ['127.0.0.0/8', '::1'];
        if ('' !== ($gw = self::defaultGateway())) {
            $allow[] = $gw;
        }
        if ('' !== $env) {
            $allow = array_merge($allow, preg_split('~[\s,]+~', $env, -1, PREG_SPLIT_NO_EMPTY) ?: []);
        }
        foreach ($allow as $rule) {
            if (self::ipMatch($ip, $rule)) {
                return true;
            }
        }

        return false;
    }

    /**
     * IPv4-mapped IPv6 → обычный IPv4.
     *
     * Слушатель может оказаться dual-stack (unit биндит по AF_INET6), и тогда
     * подключение с 127.0.0.1 приходит как «::ffff:127.0.0.1». Правила ниже
     * сравниваются побайтово через inet_pton, где v4 — 4 байта, а v6 — 16, то
     * есть mapped-адрес не совпал бы ни с loopback, ни со шлюзом: панель
     * ответила бы 403 самому админу. Приводим обе стороны к одному виду.
     */
    private static function normalizeIp($ip)
    {
        $ip = trim((string) $ip);
        if (preg_match('~^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$~i', $ip, $m)
            && filter_var($m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return $m[1];
        }

        return $ip;
    }

    /** Шлюз сети контейнера: маршрут по умолчанию из /proc/net/route. */
    private static function defaultGateway()
    {
        static $gw;
        if (null !== $gw) {
            return $gw;
        }
        $gw = '';
        foreach (preg_split('~\R~', (string) @file_get_contents('/proc/net/route')) as $line) {
            $f = preg_split('~\s+~', trim($line));
            // Iface Destination Gateway …: маршрут по умолчанию — Destination 0,
            // адрес записан hex'ом в сетевом порядке байтов задом наперёд.
            if (count($f) > 2 && '00000000' === $f[1]
                && preg_match('~^[0-9A-Fa-f]{8}$~', $f[2]) && '00000000' !== $f[2]) {
                $gw = implode('.', array_map('hexdec', array_reverse(str_split($f[2], 2))));
                break;
            }
        }

        return $gw;
    }

    /** Сверка адреса с правилом «IP» либо «сеть/длина префикса» (v4 и v6). */
    private static function ipMatch($ip, $rule)
    {
        $a = @inet_pton(self::normalizeIp($ip));
        if (false === $a) {
            return false;
        }
        if (!str_contains((string) $rule, '/')) {
            return ($b = @inet_pton(self::normalizeIp($rule))) !== false && $a === $b;
        }
        [$net, $bits] = explode('/', (string) $rule, 2);
        $b = @inet_pton(self::normalizeIp($net));
        if (false === $b || strlen($a) !== strlen($b)) {
            return false;
        }
        $bits = max(0, min((int) $bits, strlen($a) * 8));
        $full = intdiv($bits, 8);
        if (0 !== strncmp($a, $b, $full)) {
            return false;
        }
        $rest = $bits % 8;
        if (0 === $rest || $full >= strlen($a)) {
            return true;
        }
        $mask = chr((0xFF << (8 - $rest)) & 0xFF);

        return ($a[$full] & $mask) === ($b[$full] & $mask);
    }

    /**
     * Защита от DNS rebinding.
     *
     * Слушатель проброшен на 127.0.0.1 хоста, но «только loopback» браузер не
     * гарантирует: страница злоумышленника может перепривязать своё имя на
     * 127.0.0.1 и обращаться к панели уже как к своему origin'у — без CORS, а
     * значит и заголовок X-Panel ей поставить никто не мешает. Куки админа при
     * этом не уедут (домен другой), но форма входа окажется доступна для
     * перебора, а /panel<hash> угадывать не надо: хеш виден в любой ссылке
     * подписки.
     *
     * Rebinding возможен только по ИМЕНИ, поэтому literal-IP в Host пропускаем
     * как есть (ssh -L можно поднять на любой адрес), а имена — по списку.
     * PANEL_HOSTS расширяет его через .env, '*' отключает проверку.
     */
    public static function hostAllowed($host = null)
    {
        $host = strtolower(trim((string) ($host ?? ($_SERVER['HTTP_HOST'] ?? ''))));
        $env  = strtolower(trim((string) getenv('PANEL_HOSTS')));
        if ('*' === $env) {
            return true;
        }
        if ('' === $host) {
            return false;
        }
        // Host: [::1]:8090 | 127.0.0.1:8090 | localhost
        if (preg_match('~^\[([0-9a-f:.]+)\](?::(\d{1,5}))?$~', $host, $m)) {
            $name = $m[1];
        } elseif (preg_match('~^([^:]+)(?::(\d{1,5}))?$~', $host, $m)) {
            $name = $m[1];
        } else {
            return false;
        }
        if (filter_var($name, FILTER_VALIDATE_IP)) {
            return true;
        }
        $allow = ['localhost'];
        if ('' !== $env) {
            $allow = array_merge($allow, preg_split('~[\s,]+~', $env, -1, PREG_SPLIT_NO_EMPTY) ?: []);
        }

        return in_array($name, $allow, true);
    }

    /** 403 «не тот источник» — общий для route() и гейта слушателя в index.php. */
    public static function denyClient()
    {
        http_response_code(403);
        header('Content-Type: text/plain; charset=utf-8');
        header('X-Content-Type-Options: nosniff');
        $from = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
        $p    = self::port();
        echo 'panel: доступ с ' . (filter_var($from, FILTER_VALIDATE_IP) ? $from : 'неизвестного адреса')
            . " запрещён. Панель — только с хоста (ssh -L $p:127.0.0.1:$p), "
            . "иначе задайте PANEL_TRUSTED в .env\n";
    }

    /** 403 «чужое имя в Host» (DNS rebinding). */
    public static function denyHost()
    {
        http_response_code(403);
        header('Content-Type: text/plain; charset=utf-8');
        header('X-Content-Type-Options: nosniff');
        echo "panel: Host \"" . htmlspecialchars((string) ($_SERVER['HTTP_HOST'] ?? ''), ENT_QUOTES)
            . "\" не разрешён. Ходите по 127.0.0.1/localhost (ssh -L) либо задайте PANEL_HOSTS в .env\n";
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

        // Первым делом — откуда пришли: слушатель виден всей docker-сети, а её
        // freedom-outbound xray разрешает (см. clientAllowed()). Тот же барьер
        // стоит на весь слушатель в index.php; здесь он остаётся вторым рубежом
        // на случай, если route() позовут откуда-то ещё.
        if (!self::clientAllowed()) {
            self::denyClient();

            return;
        }

        // Чужое имя в Host — это либо DNS rebinding, либо запрос не туда, куда
        // думает клиент. Дальше Host уходит в origin панельных ссылок
        // (panelizeUrl), так что проверка нужна и для них.
        if (!self::hostAllowed()) {
            self::denyHost();

            return;
        }

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

        // Проверка X-Panel выше касается только POST'ов, поэтому изменяющее
        // действие, доступное по GET, обходило бы её целиком: `<img
        // src=".../reset">` со стороннего сайта чистил ленту (от куки спасала
        // одна лишь SameSite=Strict). Метод фиксируем явно.
        if (!$post && in_array($action, self::MUTATING, true)) {
            header('Allow: POST');

            return $this->json(['ok' => false, 'error' => 'method not allowed'], 405);
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

            case 'diag':
                return $this->diag();

            case 'dismiss':
                return $this->dismiss();

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
        $conf = $this->pacConf();
        if (!empty($conf['panelpswd'])) {
            return null;
        }
        $plain            = bin2hex(random_bytes(9));
        $conf['panelpswd'] = password_hash($plain, PASSWORD_DEFAULT);
        if (!PanelPasswordVault::remember($this->store->dir(), $plain, $conf['panelpswd'])) throw new RuntimeException('Не удалось сохранить защищённую копию пароля');
        if ($this->bot->setPacConf($conf) === false) throw new RuntimeException('Не удалось сохранить пароль панели');
        $f = $this->store->dir() . '/initial_password.txt';
        @touch($f);
        @chmod($f, 0600);
        file_put_contents($f, "$plain\n");

        return $plain;
    }

    public function setPassword($plain)
    {
        if (strlen((string) $plain) < 8 || strlen((string) $plain) > 72) throw new InvalidArgumentException('Пароль панели: от 8 до 72 байт');
        $conf              = $this->pacConf();
        $conf['panelpswd'] = password_hash((string) $plain, PASSWORD_DEFAULT);
        if (!PanelPasswordVault::remember($this->store->dir(), (string) $plain, $conf['panelpswd'])) throw new RuntimeException('Не удалось сохранить защищённую копию пароля');
        if ($this->bot->setPacConf($conf) === false) throw new RuntimeException('Не удалось сохранить пароль панели');
        @unlink($this->store->dir() . '/initial_password.txt');
    }

    /**
     * pac.json перед записью пароля. getPacConf() отдаёт null, если файл
     * недоступен или битый: с прежним `?: []` мы записали бы поверх него
     * конфиг из одного поля panelpswd, то есть потеряли бы все настройки бота
     * (клиентов, ключи reality, шаблоны). Пустой МАССИВ — законное состояние
     * («{}»), а null — нет.
     */
    private function pacConf()
    {
        $conf = $this->bot->getPacConf();
        if (!is_array($conf)) {
            throw new RuntimeException('pac.json недоступен или повреждён — пароль панели не записан');
        }

        return $conf;
    }

    private function passwordHash()
    {
        $conf = $this->bot->getPacConf();

        return (string) (is_array($conf) ? ($conf['panelpswd'] ?? '') : '');
    }

    private function login()
    {
        // Попытку считаем ДО проверки пароля и одной операцией под локом:
        // «прочитать счётчик → проверить → записать» разными вызовами — это
        // check-then-act, а панель обслуживают до 4 воркеров unit, так что
        // параллельные POST'ы видели один и тот же счётчик и лимит 5/300с
        // превращался в «5 на каждый одновременный запрос».
        if (!$this->rateHit()) {
            return $this->json(['ok' => false, 'error' => 'too many attempts'], 429);
        }
        $hash = $this->passwordHash();
        $pass = (string) ($_POST['password'] ?? '');
        if ('' === $hash || !password_verify($pass, $hash)) {
            // Пауза сглаживает перебор и разницу во времени между «пароль не
            // задан» и «пароль неверный».
            usleep(300000);

            return $this->json(['ok' => false, 'error' => 'wrong password'], 403);
        }
        // Пароль общий на всю панель, а вот действовать после входа можно от
        // имени любого из настроенных админов (мультиадминство): при одном
        // админе выбора нет и cookie остаётся в прежнем двухчастном виде —
        // ни формат, ни путь к ленте не меняются для однo-админских установок.
        $admin = $this->admins[0] ?? 0;
        if (count($this->admins) > 1) {
            $chosen = (int) ($_POST['admin'] ?? 0);
            if (!in_array($chosen, $this->admins, true)) {
                return $this->json(['ok' => false, 'error' => 'unknown admin'], 400);
            }
            $admin = $chosen;
        }
        $this->rateClear();
        PanelPasswordVault::remember($this->store->dir(), $pass, $hash);
        $exp   = time() + self::TTL;
        $value = count($this->admins) > 1
            ? $exp . '.' . $admin . '.' . $this->sign($exp, $admin)
            : $exp . '.' . $this->sign($exp);
        setcookie(self::COOKIE, $value, [
            'expires'  => $exp,
            'path'     => $this->prefix . '/',
            'httponly' => true,
            'samesite' => 'Strict',
            // По факту схемы, а не всегда: штатно панель открывают по http на
            // 127.0.0.1 через `ssh -L`, и безусловный secure просто не дал бы
            // войти. Но PANEL_HOSTS/PANEL_TRUSTED позволяют вынести её за
            // https-прокси — там кука обязана быть secure.
            'secure'   => self::httpsRequest(),
        ]);

        return $this->json(['ok' => true, 'admin' => $admin]);
    }

    private static function httpsRequest(): bool
    {
        return !empty($_SERVER['HTTPS'])
            || 'https' === ($_SERVER['REQUEST_SCHEME'] ?? '')
            || 'https' === ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '');
    }

    private function logout()
    {
        setcookie(self::COOKIE, '', [
            'expires'  => 1,
            'path'     => $this->prefix . '/',
            'httponly' => true,
            'samesite' => 'Strict',
            // Флаги при удалении обязаны совпадать с выдачей, иначе браузер
            // сочтёт это другой кукой и оставит прежнюю.
            'secure'   => self::httpsRequest(),
        ]);

        return $this->json(['ok' => true]);
    }

    /**
     * Подпись куки завязана и на токен бота, и на текущий хеш пароля: смена
     * пароля разом обнуляет все выданные сессии.
     *
     * $admin входит в подпись начиная с мультиадминства — иначе один
     * авторизованный админ мог бы переписать себе cookie на чужой id и
     * действовать от чужого имени без пароля. По умолчанию — admins[0], чтобы
     * старый однопараметрический вызов (в т.ч. в тестах) остался рабочим.
     */
    private function sign($exp, $admin = null)
    {
        $admin ??= $this->admins[0] ?? 0;

        return hash_hmac('sha256', "panel|$exp|$admin|" . $this->passwordHash(), $this->key);
    }

    public function authed()
    {
        // Секрет подписи — токен бота, соль — хеш пароля. Пока пароля нет,
        // login() всё равно никого не пускает, но кука проверялась бы по
        // "panel|<exp>|" с ключом $c['key'] — а на свежей установке (config.php
        // ещё без токена) он пуст, то есть подпись считается из одних лишь
        // общеизвестных данных и подделывается тривиально. Нет пароля или
        // ключа — нет и сессий.
        if ('' === $this->key || '' === $this->passwordHash()) {
            return false;
        }
        $v = (string) ($_COOKIE[self::COOKIE] ?? '');
        // Трёхчастная кука — мультиадминство (exp.adminId.hmac). Двухчастная —
        // прежний формат для установок с одним админом: он не менялся, чтобы
        // не рвать уже выданные сессии там, где выбирать всё равно не из чего.
        if (preg_match('~^(\d+)\.(-?\d+)\.([0-9a-f]{64})$~', $v, $m)) {
            $exp   = (int) $m[1];
            $admin = (int) $m[2];
            if ($exp < time() || !in_array($admin, $this->admins, true)) {
                return false;
            }
            if (!hash_equals($this->sign($exp, $admin), $m[3])) {
                return false;
            }
            $this->actingAdmin = $admin;

            return true;
        }
        if (preg_match('~^(\d+)\.([0-9a-f]{64})$~', $v, $m)) {
            $exp = (int) $m[1];
            if ($exp < time() || !hash_equals($this->sign($exp), $m[2])) {
                return false;
            }
            $this->actingAdmin = $this->admins[0] ?? 0;

            return true;
        }

        return false;
    }

    private function rateFile()
    {
        return $this->store->dir() . '/login_attempts.json';
    }

    /**
     * Записывает попытку входа и отвечает, была ли она в пределах лимита.
     * Чтение, подрезка окна и запись идут под одним LOCK_EX — иначе счётчик
     * гонялся между воркерами, а file_put_contents без лока мог оставить
     * порванный JSON, который json_decode вернул бы как null (счётчик с нуля).
     */
    private function rateHit()
    {
        $f = $this->rateFile();
        $h = @fopen($f, 'c+');
        if (!$h) {
            // Посчитать не вышло — пускаем к проверке пароля: иначе сломанный
            // файл запер бы админа снаружи навсегда, а барьер пароля остаётся.
            return true;
        }
        @chmod($f, 0600);
        flock($h, LOCK_EX);
        $t   = json_decode((string) stream_get_contents($h), true);
        $t   = array_values(array_filter((array) $t, fn ($ts) => is_numeric($ts) && $ts > time() - self::TRY_WINDOW));
        $ok  = count($t) < self::MAX_TRIES;
        $t[] = time();
        // Держим не больше двух окон попыток: файл не должен расти от долбёжки.
        $t = array_slice($t, -2 * self::MAX_TRIES);
        rewind($h);
        ftruncate($h, 0);
        fwrite($h, (string) json_encode($t));
        fflush($h);
        flock($h, LOCK_UN);
        fclose($h);

        return $ok;
    }

    /** Удачный вход обнуляет счётчик — иначе он копил бы и легальные заходы. */
    private function rateClear()
    {
        @unlink($this->rateFile());
    }

    // ── страница ────────────────────────────────────────────────────────────

    private function page($authed)
    {
        header('Content-Type: text/html; charset=utf-8');
        header('X-Frame-Options: DENY');
        header('Referrer-Policy: no-referrer');
        // Страница знает, выполнен ли вход ({{AUTH}}), и несёт подсказку о
        // состоянии установки — в кэш (в т.ч. общий) ей попадать незачем.
        header('Cache-Control: no-store');
        self::csp();
        $html = (string) file_get_contents(__DIR__ . '/ui.html');
        // Список id — не секрет: те же id уже видны любому админу в
        // configMenu() бота. Отдаём его только когда есть из чего выбирать —
        // однo-админские установки страницу логина не меняют вовсе.
        $admins = count($this->admins) > 1 ? $this->admins : [];
        echo strtr($html, [
            '{{PREFIX}}' => htmlspecialchars($this->prefix, ENT_QUOTES),
            '{{AUTH}}'   => $authed ? '1' : '0',
            '{{NOTE}}'   => htmlspecialchars($this->bootNote(), ENT_QUOTES),
            // HEX_TAG/HEX_AMP на случай, если id когда-нибудь перестанут быть
            // строго числовыми (сейчас гарантируют это CLI и auto-bootstrap в
            // Bot::auth()) — иначе "</script>" в значении вырвался бы из
            // JS-строки, а htmlspecialchars() сам по себе "/" не трогает.
            '{{ADMINS}}' => htmlspecialchars(json_encode($admins, JSON_HEX_TAG | JSON_HEX_AMP), ENT_QUOTES),
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
     * Диагностика самой панели (не бота и не VPN-сервисов — тому есть обычное
     * меню, тут дублировать нечего). ttl — единственное, что браузер не может
     * узнать сам: кука httponly и JS её не читает.
     */
    private function diag()
    {
        $exp = 0;
        if (preg_match('~^(\d+)\.~', (string) ($_COOKIE[self::COOKIE] ?? ''), $m)) {
            $exp = (int) $m[1];
        }
        $state = $this->store->read();

        return $this->json([
            'ok'           => true,
            'admin'        => $this->chatId(),
            'admin_count'  => count($this->admins),
            'ttl'          => max(0, $exp - time()),
            'messages'     => count($state['messages']),
            'rev'          => $state['rev'],
            'store_bytes'  => @filesize($this->store->dir() . '/state.json') ?: 0,
            'disk_free'    => @disk_free_space($this->store->dir()),
            'upload_limit' => $this->uploadLimit(),
        ]);
    }

    /**
     * Убрать один пузырь из ленты, не трогая остальные («очистить» сносит всё
     * разом, чего не всегда хочется). Тот же Store::delete(), которым бот сам
     * помечает свои сообщения удалёнными (см. PanelTransport::deleteMessage) —
     * значит вложение освобождается и правка видна во всех открытых вкладках.
     */
    private function dismiss()
    {
        $mid = (int) ($_POST['message_id'] ?? 0);
        if (!$mid) {
            return $this->json(['ok' => false, 'error' => 'bad request'], 400);
        }
        $this->store->delete($mid);

        return $this->json(['ok' => true]);
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
        header('X-Content-Type-Options: nosniff');
        header('Cache-Control: private, max-age=86400');
        readfile($path);
    }

    /** Редактор шаблонов: та же JSONEditor-страница, но без Telegram. */
    private function editor()
    {
        // is_string ДО preg_match: «?ty[]=x» — это TypeError, то есть фатал
        // вместо 404 (см. тот же разбор для /pac<hash>?t=te в index.php).
        $ty = (is_string($_GET['ty'] ?? null) && preg_match('~^\w+$~', $_GET['ty'])) ? $_GET['ty'] : '';
        if ('' === $ty) {
            http_response_code(404);

            return;
        }
        $te   = is_string($_GET['te'] ?? null) ? $_GET['te'] : '';
        $name = $te ?: 'origin';
        // CSP здесь намеренно не ставим: JSONEditor поднимает Ace-воркер через
        // blob: и в режиме code полагается на eval — под политикой панели
        // редактор просто перестал бы открываться. Страница целиком своя и
        // грузит только собственную статику.
        header('Content-Type: text/html; charset=utf-8');
        // Framing и Referrer к CSP отношения не имеют, а редактор — такая же
        // страница панели: без них его можно было положить в чужой iframe.
        header('X-Frame-Options: DENY');
        header('Referrer-Policy: no-referrer');
        header('X-Content-Type-Options: nosniff');
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
          html,body{margin:0;height:100%;font:14px -apple-system,Segoe UI,Roboto,Ubuntu,sans-serif}
          #bar{height:48px;display:flex;align-items:center;gap:8px;padding:0 14px;background:#17212b;color:#e9edf1;box-shadow:0 2px 10px rgba(0,0,0,.22)}
          #bar b{font-weight:600}
          #bar #st{color:#7f91a4;font-size:13px}
          #bar button{background:#3b82c4;color:#fff;border:0;border-radius:8px;padding:7px 14px;cursor:pointer;font:inherit;transition:filter .15s,transform .05s}
          #bar button:hover{filter:brightness(1.08)}
          #bar button:active{transform:scale(.96)}
          #bar button.sec{background:#2a3f52}
          #bar button.sec:hover{background:#33506b}
          #jsoneditor{height:calc(100% - 48px)}
        </style>
        </head>
        <body>
        <div id="bar"><b>$eTy</b> / $eName<span style="flex:1"></span>
          <span id="st"></span>
          <button id="import" class="sec">Загрузить с диска</button>
          <input id="importfile" type="file" accept="application/json" hidden>
          <button id="download" class="sec">Скачать</button>
          <button id="save">Сохранить</button></div>
        <div id="jsoneditor"></div>
        <script>
        const P = $jPrefix, TY = $jTy, TE = $jTe, NAME = $jName;
        let dirty = false;
        const editor = new JSONEditor(document.getElementById("jsoneditor"), {
          onChange: () => { dirty = true; }
        });
        const st = document.getElementById("st");
        const post = (u, o) => fetch(P + u, {method:"POST", headers:{"X-Panel":"1"}, body:o});
        const fd = o => { const f = new FormData(); for (const k in o) f.append(k, o[k]); return f; };
        editor.set({});
        post("/tload", fd({ty:TY, te:TE})).then(r => r.json()).then(r => {
          if (r && r.status) editor.set(r.json); else st.textContent = "ошибка загрузки";
          dirty = false;
        }).catch(() => st.textContent = "ошибка загрузки");
        document.getElementById("save").onclick = () => {
          st.textContent = "сохраняю…";
          post("/tsave", fd({name:NAME, type:TY, json:editor.getText()}))
            .then(r => r.json())
            .then(r => { st.textContent = r.status ? "сохранено" : (r.message || "ошибка"); if (r.status) dirty = false; })
            .catch(() => st.textContent = "ошибка");
        };
        document.getElementById("download").onclick = () => {
          const blob = new Blob([editor.getText()], {type: "application/json"});
          const a = document.createElement("a");
          a.href = URL.createObjectURL(blob);
          a.download = TY + "_" + NAME + ".json";
          a.click();
          URL.revokeObjectURL(a.href);
        };
        document.getElementById("import").onclick = () => document.getElementById("importfile").click();
        document.getElementById("importfile").onchange = function(){
          const f = this.files[0]; this.value = "";
          if (!f) return;
          f.text().then(t => {
            try { editor.set(JSON.parse(t)); dirty = true; st.textContent = "загружено из файла — не забудьте сохранить"; }
            catch (e) { st.textContent = "неверный JSON"; }
          });
        };
        window.onbeforeunload = () => dirty ? "" : undefined;
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
        $ty = (is_string($_POST['ty'] ?? null) && preg_match('~^\w+$~', $_POST['ty'])) ? $_POST['ty'] : '';
        if ('' === $ty) {
            return $this->json(['status' => false]);
        }
        $te = is_string($_POST['te'] ?? null) ? $_POST['te'] : '';
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

        // Переносы превращаем в <br> ВЕЗДЕ, КРОМЕ <pre> и <code>: там перенос
        // отображается сам (white-space: pre-wrap), и <br> внутри давал бы
        // двойные пустые строки во всех диагностиках и логах.
        //
        // <code> попал сюда вместе с pre-wrap в ui.html. Бот выравнивает
        // колонки пробелами (alignColumns) и заворачивает такие блоки — статусы
        // сервисов, версии — именно в <code>; при white-space:normal браузер
        // схлопывал кратные пробелы, и таблицы слипались в сплошной текст.
        // Одного CSS мало: nl2br() ОСТАВЛЯЕТ исходный \n и лишь дописывает <br>
        // перед ним, так что с pre-wrap каждая строка ломалась бы дважды.
        //
        // <pre> в альтернативе первым не случайно: у бота есть разметка
        // <pre><code class="language-shell">…</code></pre> (updatebot), и pre
        // должен съесть блок целиком, а не отдать внутренний code отдельно.
        $parts = preg_split('~(<pre>.*?</pre>|<code[^>]*>.*?</code>)~s', $e, -1, PREG_SPLIT_DELIM_CAPTURE);
        foreach ($parts as $i => $p) {
            if (str_starts_with($p, '<pre>')) {
                continue;
            }
            if (str_starts_with($p, '<code')) {
                // Браузер съедает первый перевод строки только внутри <pre>;
                // в <code> он остался бы пустой первой строкой — блок начинается
                // с «<code>\n», потому что бот собирает меню через implode("\n").
                $parts[$i] = preg_replace('~(<code[^>]*>)\n~', '$1', $p, 1);
                continue;
            }
            $parts[$i] = nl2br($p, false);
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
        // Поле, отправленное как file[], даёт массивы в каждом ключе $_FILES;
        // is_uploaded_file(array) — TypeError, то есть фатал вместо ответа.
        if (!is_array($f) || is_array($f['tmp_name'] ?? null)) {
            return $this->json(['ok' => false, 'error' => 'upload failed'], 400);
        }
        if (!is_uploaded_file($f['tmp_name'] ?? '') || ($f['error'] ?? 1) !== UPLOAD_ERR_OK) {
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
        return $this->actingAdmin ?? $this->admins[0] ?? 0;
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
        header('X-Content-Type-Options: nosniff');
        // Опрос ленты идёт по одному и тому же URL, пока не поменяется rev —
        // кэш браузера тут только мешает.
        header('Cache-Control: no-store');
        echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }
}
