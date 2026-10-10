<?php

// XDRIVE — транспорт Xray (с 26.9.30), в котором сервер и клиент не соединяются
// напрямую: обе стороны читают и пишут файлы в общей папке облачного
// хранилища. Сервер не открывает для него ни одного порта, а клиенту нужен
// доступ только к хранилищу, поэтому блокировка адреса сервера и белые списки
// IP такому подключению не мешают.
//
// Устройство в боте:
//  - отдельный вход VLESS с тегом xdrive в xray.json; пользователи те же, что
//    у основного входа, поэтому учёт трафика и лимиты общие;
//  - VLESS Encryption на этом входе обязателен и не выключается: всё, что
//    лежит в хранилище, видит его владелец, а заголовок VLESS без шифрования
//    содержит UUID пользователя. Ключи свои, от основного входа не зависят;
//  - клиент — только Xray: профиль выдаётся файлом JSON и содержит доступ к
//    хранилищу, поэтому годится лишь для своих.
trait BotXdrive
{
    public const XDRIVE_TAG = 'xdrive';
    // Первый выпуск ядра с транспортом; форк включает его с 26.10.5.
    public const XDRIVE_MIN_CORE = '26.9.30';
    public const XDRIVE_SERVICES = ['webdav' => 'WebDAV', 'gdrive' => 'Google Drive', 'template' => 'template'];
    // Имя файла — последняя часть ссылки в ответе PROPFIND; префикс пространства
    // имён у серверов разный (d:, D:, lp1:), сама папка заканчивается на «/».
    public const XDRIVE_WEBDAV_NAMES = '<(?:[A-Za-z0-9]+:)?href>[^<]*/([^/<]+)</(?:[A-Za-z0-9]+:)?href>';
    public const XDRIVE_POLL = [500, 10000];
    private ?array $xdriveInventory = null;

    public static function xdriveDefaults(): array
    {
        return ['enabled' => 0, 'service' => 'webdav', 'url' => '', 'folder' => '', 'secrets' => [],
            'template' => '', 'poll' => self::XDRIVE_POLL[0], 'enc' => []];
    }

    public function xdriveSettings(?array $p = null): array
    {
        $s = ($p ?? $this->getPacConf())['xdrive'] ?? [];
        $s = (is_array($s) ? $s : []) + self::xdriveDefaults();
        if (!isset(self::XDRIVE_SERVICES[$s['service']])) $s['service'] = 'webdav';
        $s['secrets'] = array_values(array_map('strval', is_array($s['secrets']) ? $s['secrets'] : []));
        $s['poll'] = max(self::XDRIVE_POLL[0], min(self::XDRIVE_POLL[1], (int) $s['poll']));
        foreach (['url', 'folder', 'template'] as $field) $s[$field] = is_string($s[$field]) ? $s[$field] : '';
        $s['enc'] = is_array($s['enc']) ? $s['enc'] : [];
        return $s;
    }

    // Адрес WebDAV: только http(s), без учётных данных, запроса и фрагмента.
    public static function xdriveWebdavUrl(string $url): ?string
    {
        $url = rtrim(trim($url), '/');
        $parts = parse_url($url);
        if (!is_array($parts) || !in_array(strtolower($parts['scheme'] ?? ''), ['http', 'https'], true) || empty($parts['host'])
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])
            || preg_match('~[\s{}"\\\\<>]~', $url) || strlen($url) > 300) {
            return null;
        }
        return $url;
    }

    // Имя папки подставляется в адрес как есть: только безопасные символы.
    public static function xdriveFolderOk(string $folder): bool
    {
        return (bool) preg_match('~^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$~D', $folder);
    }

    // Хранилище должно быть внешним: бот и ядро не ходят по этому адресу во
    // внутреннюю сеть Docker и на сам сервер.
    public function xdriveHostPublic(string $url): bool
    {
        $host = (string) parse_url($url, PHP_URL_HOST);
        $host = trim($host, '[]');
        $addresses = filter_var($host, FILTER_VALIDATE_IP) ? [$host] : $this->xdriveResolve($host);
        if (!$addresses) return false;
        foreach ($addresses as $address) {
            if (!filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) return false;
            // Общее адресное пространство провайдеров (100.64.0.0/10) фильтр PHP частным не считает.
            if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && (ip2long($address) & 0xFFC00000) === 0x64400000) return false;
        }
        return true;
    }

    protected function xdriveResolve(string $host): array
    {
        $found = [];
        foreach ((array) @dns_get_record($host, DNS_A | DNS_AAAA) as $record) {
            $found[] = $record['ip'] ?? $record['ipv6'] ?? '';
        }
        return array_values(array_filter($found));
    }

    public static function xdriveWebdavTemplate(string $url): array
    {
        $object = $url . '/{folder}/{name}';
        return [
            // Хранилище плоское: имена вида streams/<сессия>/… сводятся в одно.
            'flatten' => true,
            'auth' => ['type' => 'basic', 'username' => '{secret0}', 'password' => '{secret1}'],
            'put' => ['method' => 'PUT', 'url' => $object],
            'get' => ['method' => 'GET', 'url' => $object],
            'delete' => ['method' => 'DELETE', 'url' => $object],
            'list' => ['method' => 'PROPFIND', 'url' => $url . '/{folder}/', 'headers' => ['Depth' => '1'],
                'namesRegex' => self::XDRIVE_WEBDAV_NAMES],
        ];
    }

    // Чего не хватает для включения: ключи сообщений. Пусто — можно включать.
    public function xdriveProblems(array $s): array
    {
        $problems = [];
        $secrets = count(array_filter($s['secrets'], static fn($v) => $v !== ''));
        switch ($s['service']) {
            case 'webdav':
                $url = self::xdriveWebdavUrl($s['url']);
                if ($url === null) $problems[] = 'xdrive need url';
                elseif (!$this->xdriveHostPublic($url)) $problems[] = 'xdrive private url';
                if (!self::xdriveFolderOk($s['folder'])) $problems[] = 'xdrive need folder';
                if ($secrets !== 2 || count($s['secrets']) !== 2) $problems[] = 'xdrive need login';
                break;
            case 'gdrive':
                if (!preg_match('~^[A-Za-z0-9_-]{10,100}$~D', $s['folder'])) $problems[] = 'xdrive need folder id';
                if ($secrets !== 3 || count($s['secrets']) !== 3) $problems[] = 'xdrive need google keys';
                break;
            case 'template':
                $template = json_decode($s['template'], true);
                if (!is_array($template) || array_is_list($template)) {
                    $problems[] = 'xdrive need template';
                    break;
                }
                foreach (['put', 'get', 'delete', 'list'] as $operation) {
                    $target = $template[$operation]['url'] ?? '';
                    if (!is_string($target) || self::xdriveWebdavUrl(strtok(str_replace(['{', '}'], '', $target), '?')) === null) {
                        $problems[] = 'xdrive need template';
                        break 2;
                    }
                    if (!$this->xdriveHostPublic($target)) {
                        $problems[] = 'xdrive private url';
                        break 2;
                    }
                }
                if (!is_string($template['list']['namesRegex'] ?? null) || $template['list']['namesRegex'] === '') $problems[] = 'xdrive need template';
                if ($s['folder'] === '' || preg_match('~[\s{}"\\\\<>]~', $s['folder'])) $problems[] = 'xdrive need folder';
                break;
        }
        return array_values(array_unique($problems));
    }

    // streamSettings транспорта — одинаковые у сервера и клиента.
    public static function xdriveStream(array $s): array
    {
        $settings = match ($s['service']) {
            'gdrive' => ['remoteFolder' => $s['folder'], 'service' => 'Google Drive', 'secrets' => $s['secrets']],
            'template' => ['remoteFolder' => $s['folder'], 'service' => 'template', 'secrets' => $s['secrets'],
                'template' => json_decode($s['template'], true)],
            default => ['remoteFolder' => $s['folder'], 'service' => 'template', 'secrets' => $s['secrets'],
                'template' => self::xdriveWebdavTemplate((string) self::xdriveWebdavUrl($s['url']))],
        };
        // Реже опрашивать хранилище в простое: меньше запросов к его API ценой
        // задержки первого ответа. Во время обмена ядро опрашивает чаще само.
        if ((int) $s['poll'] > self::XDRIVE_POLL[0]) $settings['maxPollIntervalMs'] = (int) $s['poll'];
        return ['method' => 'xdrive', 'xdriveSettings' => $settings];
    }

    // Знает ли транспорт выбранное ядро. Версии читаются из образа xr, а не из
    // настроек: запомненный там ответ устарел бы после смены образа или
    // восстановления из копии, а ядро без транспорта с таким входом не
    // запустится вовсе. Ответ держится минуту — в режиме long polling один
    // объект бота живёт часами.
    public function xdriveCoreReady(?array $p = null): bool
    {
        if ($this->xdriveInventory === null || time() - $this->xdriveInventory[0] >= 60) {
            $this->xdriveInventory = [time(), $this->xrayCoreInventory()];
        }
        $version = (string) ($this->xdriveInventory[1][$this->xrayCoreSelection($p ?? $this->getPacConf())] ?? '');
        return $version !== '' && version_compare($version, self::XDRIVE_MIN_CORE, '>=');
    }

    // Работает ли вход сейчас: включён, настроен, ключи целы, ядро умеет.
    public function xdriveActive(?array $p = null, ?array $c = null): bool
    {
        $p = $p ?? $this->getPacConf();
        $s = $this->xdriveSettings($p);
        return !empty($s['enabled']) && VlessEncryption::pair($s['enc']) !== null
            && ($c === null || ($c['inbounds'][0]['protocol'] ?? '') === 'vless')
            && $this->xdriveCoreReady($p);
    }

    // Вход пересобирается при каждой записи конфига: список пользователей
    // всегда повторяет основной вход. Ядру без транспорта вход не отдаётся,
    // иначе оно не запустится вовсе.
    public function ensureXdriveInbound(array &$c, ?array $p = null): void
    {
        $c['inbounds'] = array_values(array_filter($c['inbounds'] ?? [],
            static fn($inbound) => ($inbound['tag'] ?? '') !== self::XDRIVE_TAG));
        $p = $p ?? $this->getPacConf();
        if (!$this->xdriveActive($p, $c)) return;
        $s = $this->xdriveSettings($p);
        $clients = [];
        foreach ($c['inbounds'][0]['settings']['clients'] ?? [] as $client) {
            if (!is_string($client['id'] ?? null) || $client['id'] === '') continue;
            // flow не переносится: Vision работает только поверх TLS и REALITY.
            $clients[] = array_intersect_key($client, ['id' => 1, 'email' => 1, 'level' => 1]);
        }
        if (!$clients) return;
        $c['inbounds'][] = [
            'tag' => self::XDRIVE_TAG,
            // Адрес и порт обязательны в конфиге, но транспорт их не открывает.
            'listen' => '127.0.0.1',
            'port' => 10444,
            'protocol' => 'vless',
            'settings' => ['clients' => $clients, 'decryption' => VlessEncryption::pair($s['enc'])['decryption']],
            'streamSettings' => self::xdriveStream($s),
            'sniffing' => $c['inbounds'][0]['sniffing'] ?? ['enabled' => true, 'destOverride' => ['http', 'tls', 'quic']],
        ];
    }

    // Готовый конфиг клиента Xray для одного пользователя. null — выдавать нечего.
    public function xdriveClientConfig(array $client, ?array $p = null): ?array
    {
        $p = $p ?? $this->getPacConf();
        $s = $this->xdriveSettings($p);
        $pair = VlessEncryption::pair($s['enc']);
        if (empty($s['enabled']) || $pair === null || $this->xdriveProblems($s) || !is_string($client['id'] ?? null) || $client['id'] === '') {
            return null;
        }
        return [
            'log' => ['loglevel' => 'warning'],
            'inbounds' => [
                ['tag' => 'socks', 'listen' => '127.0.0.1', 'port' => 10808, 'protocol' => 'socks', 'settings' => ['udp' => true],
                    'sniffing' => ['enabled' => true, 'destOverride' => ['http', 'tls', 'quic']]],
                ['tag' => 'http', 'listen' => '127.0.0.1', 'port' => 10809, 'protocol' => 'http'],
            ],
            'outbounds' => [[
                'tag' => 'proxy',
                'protocol' => 'vless',
                // Адрес сервера транспорту не нужен: соединение идёт через хранилище.
                'settings' => ['vnext' => [['address' => '127.0.0.1', 'port' => 10444,
                    'users' => [['id' => $client['id'], 'encryption' => $pair['encryption']]]]]],
                'streamSettings' => self::xdriveStream($s),
            ]],
        ];
    }

    // HTTP-запрос к хранилищу; в тестах подменяется. [код, тело] либо [0, ''].
    protected function xdriveHttp(string $method, string $url, array $headers = [], ?string $body = null): array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST => $method, CURLOPT_HTTPHEADER => $headers, CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 6, CURLOPT_TIMEOUT => 12, CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        ]);
        if ($body !== null) curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        $answer = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        return [$answer === false ? 0 : $code, $answer === false ? '' : (string) $answer];
    }

    // Проверка хранилища теми же действиями, что выполняет ядро: список,
    // запись, чтение, удаление. Возвращает ключ сообщения; пусто — всё работает.
    public function xdriveProbe(array $s): string
    {
        if ($this->xdriveProblems($s)) return 'xdrive probe incomplete';
        if ($s['service'] === 'gdrive') {
            [$code, $answer] = $this->xdriveHttp('POST', 'https://oauth2.googleapis.com/token', ['Content-Type: application/x-www-form-urlencoded'],
                http_build_query(['client_id' => $s['secrets'][0], 'client_secret' => $s['secrets'][1],
                    'refresh_token' => $s['secrets'][2], 'grant_type' => 'refresh_token']));
            $token = json_decode($answer, true)['access_token'] ?? '';
            if ($code === 0) return 'xdrive probe unreachable';
            if ($code !== 200 || !is_string($token) || $token === '') return 'xdrive probe auth';
            [$code] = $this->xdriveHttp('GET', 'https://www.googleapis.com/drive/v3/files?' . http_build_query([
                'q' => "'" . $s['folder'] . "' in parents and trashed = false", 'pageSize' => 1, 'fields' => 'files(id)']),
                ['Authorization: Bearer ' . $token]);
            return match (true) { $code === 200 => '', $code === 0 => 'xdrive probe unreachable',
                $code === 404 => 'xdrive probe folder', default => 'xdrive probe denied' };
        }
        if ($s['service'] !== 'webdav') return 'xdrive probe template';
        $base = self::xdriveWebdavUrl($s['url']) . '/' . $s['folder'] . '/';
        $auth = ['Authorization: Basic ' . base64_encode($s['secrets'][0] . ':' . $s['secrets'][1])];
        [$code] = $this->xdriveHttp('PROPFIND', $base, [...$auth, 'Depth: 1']);
        if ($code === 0) return 'xdrive probe unreachable';
        if ($code === 401 || $code === 403) return 'xdrive probe auth';
        if ($code === 404) return 'xdrive probe folder';
        if ($code < 200 || $code >= 300) return 'xdrive probe denied';
        // Имя не пересекается с файлами ядра (sessions~…, streams~…).
        $name = 'vpnbot-check~' . bin2hex(random_bytes(8));
        $data = random_bytes(64);
        [$code] = $this->xdriveHttp('PUT', $base . $name, [...$auth, 'Content-Type: application/octet-stream'], $data);
        if ($code < 200 || $code >= 300) return 'xdrive probe write';
        [$code, $read] = $this->xdriveHttp('GET', $base . $name, $auth);
        [, $listing] = $this->xdriveHttp('PROPFIND', $base, [...$auth, 'Depth: 1']);
        $listed = preg_match_all('~' . self::XDRIVE_WEBDAV_NAMES . '~', $listing, $m) && in_array($name, array_map('rawurldecode', $m[1]), true);
        [$deleted] = $this->xdriveHttp('DELETE', $base . $name, $auth);
        if ($code !== 200 || !hash_equals($data, $read)) return 'xdrive probe read';
        if (!$listed) return 'xdrive probe list';
        return $deleted >= 200 && $deleted < 300 ? '' : 'xdrive probe delete';
    }

    // Сохраняет настройки и перезапускает ядро. Возвращает ключ отказа либо ''.
    public function applyXdrive(array $s, bool $rotate = false): string
    {
        return $this->withLock('xray', function () use ($s, $rotate) {
            return $this->withLock('pac', function () use ($s, $rotate) {
                $p = $this->getPacConf();
                $x = $this->getXray();
                if (!is_array($p) || !is_array($x)) return 'xdrive save failed';
                $old = $p;
                $s = $this->xdriveSettings(['xdrive' => $s]);
                if (!empty($s['enabled'])) {
                    if (($x['inbounds'][0]['protocol'] ?? '') !== 'vless') return 'xdrive needs vless';
                    if ($problems = $this->xdriveProblems($s)) return $problems[0];
                    if (!$this->xdriveCoreReady($p)) return 'xdrive core old';
                    if ($rotate || VlessEncryption::pair($s['enc']) === null) {
                        // Вывод содержит закрытые ключи: не показывать и не писать в журнал.
                        $pairs = VlessEncryption::parseOutput((string) $this->ssh('xray vlessenc', 'xr'));
                        if ($this->sshFailed || !isset($pairs['mlkem768'])) return 'xdrive keys failed';
                        $s['enc'] = $pairs['mlkem768'];
                    }
                }
                $p['xdrive'] = $s;
                if (empty($s['enabled']) && empty($old['xdrive']['enabled'])) {
                    // Вход и был, и остаётся выключен: Xray не трогаем, чтобы
                    // заполнение полей не рвало соединения пользователей.
                    return $this->setPacConf($p) === false ? 'xdrive save failed' : '';
                }
                $this->ensureXdriveInbound($x, $p);
                if (!empty($s['enabled']) && !$this->validateXrayConfig($x)) return 'xdrive check failed';
                if ($this->setPacConf($p) === false) return 'xdrive save failed';
                if ($this->restartXray($x) === false) {
                    $this->setPacConf($old);
                    return 'xdrive save failed';
                }
                return '';
            }, 20, 'xdrive save failed');
        }, 20, 'xdrive save failed');
    }

    private static function xdriveMask(string $value): string
    {
        return $value === '' ? '—' : '••••';
    }

    public function xdriveMenu(string $notice = ''): void
    {
        $p = $this->getPacConf();
        $s = $this->xdriveSettings($p);
        $problems = $this->xdriveProblems($s);
        $text = ['Menu -> ' . $this->i18n('xray') . ' -> XDRIVE', $this->i18n('xdrive intro')];
        if ($notice !== '') $text[] = '<b>' . self::esc($this->i18n($notice)) . '</b>';
        if (!empty($s['enabled']) && !$this->xdriveActive($p, $this->getXray())) $text[] = '⚠️ ' . $this->i18n('xdrive inactive');
        $text[] = $this->i18n('xdrive service') . ': <b>' . self::XDRIVE_SERVICES[$s['service']] . '</b>';
        foreach ($problems as $problem) $text[] = '• ' . $this->i18n($problem);
        if ($s['service'] === 'webdav' && str_starts_with(strtolower($s['url']), 'http://')) $text[] = '⚠️ ' . $this->i18n('xdrive plain http');
        $field = static fn(string $label, string $name, string $value) => [['text' => "$label: $value", 'callback_data' => '/xdriveSet ' . $name]];
        $data = [
            [['text' => 'XDRIVE: ' . $this->i18n(!empty($s['enabled']) ? 'on' : 'off'), 'callback_data' => '/xdriveToggle']],
            array_map(fn($key) => ['text' => ($key === $s['service'] ? '✅ ' : '') . self::XDRIVE_SERVICES[$key], 'callback_data' => '/xdriveService ' . $key],
                array_keys(self::XDRIVE_SERVICES)),
        ];
        switch ($s['service']) {
            case 'webdav':
                $data[] = $field($this->i18n('xdrive url'), 'url', $s['url'] === '' ? '—' : $s['url']);
                $data[] = $field($this->i18n('xdrive folder'), 'folder', $s['folder'] === '' ? '—' : $s['folder']);
                $data[] = $field($this->i18n('xdrive login'), 'secret0', self::xdriveMask($s['secrets'][0] ?? ''));
                $data[] = $field($this->i18n('xdrive password'), 'secret1', self::xdriveMask($s['secrets'][1] ?? ''));
                break;
            case 'gdrive':
                $data[] = $field($this->i18n('xdrive folder id'), 'folder', $s['folder'] === '' ? '—' : $s['folder']);
                foreach (['Client ID', 'Client Secret', 'Refresh Token'] as $index => $label) {
                    $data[] = $field($label, 'secret' . $index, self::xdriveMask($s['secrets'][$index] ?? ''));
                }
                break;
            case 'template':
                $data[] = $field($this->i18n('xdrive template'), 'template', $s['template'] === '' ? '—' : strlen($s['template']) . ' B');
                $data[] = $field($this->i18n('xdrive folder'), 'folder', $s['folder'] === '' ? '—' : $s['folder']);
                $data[] = $field($this->i18n('xdrive secrets'), 'secrets', (string) count($s['secrets']));
                break;
        }
        $data[] = $field($this->i18n('xdrive poll'), 'poll', $s['poll'] . ' ms');
        $data[] = [['text' => $this->i18n('xdrive probe'), 'callback_data' => '/xdriveProbe'],
            ['text' => $this->i18n('xdrive rotate'), 'callback_data' => '/xdriveRotate']];
        if (!empty($s['enabled'])) $data[] = [['text' => $this->i18n('xdrive profiles'), 'callback_data' => '/xdriveUsers 0']];
        $data[] = $this->menuHelpButton('xdrive');
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => '/xray']];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $text), $data);
    }

    public function xdriveToggle(): void
    {
        $s = $this->xdriveSettings();
        $s['enabled'] = empty($s['enabled']) ? 1 : 0;
        $error = $this->applyXdrive($s);
        $this->xdriveMenu($error !== '' ? $error : ($s['enabled'] ? 'xdrive enabled' : 'xdrive disabled'));
    }

    public function xdriveService(string $service): void
    {
        $s = $this->xdriveSettings();
        if (!isset(self::XDRIVE_SERVICES[$service]) || $service === $s['service']) {
            $this->xdriveMenu();
            return;
        }
        // Доступы другого хранилища к новому не подходят; работающий вход
        // выключается, чтобы не остаться с наполовину заполненными настройками.
        $s = ['service' => $service, 'enabled' => 0, 'url' => '', 'folder' => '', 'secrets' => [], 'template' => ''] + $s;
        $error = $this->applyXdrive($s);
        $this->xdriveMenu($error);
    }

    public function xdriveRotate(): void
    {
        $s = $this->xdriveSettings();
        if (empty($s['enabled'])) {
            $this->xdriveMenu('xdrive rotate off');
            return;
        }
        $error = $this->applyXdrive($s, true);
        $this->xdriveMenu($error !== '' ? $error : 'xdrive rotated');
    }

    public function xdriveProbeMenu(): void
    {
        $error = $this->xdriveProbe($this->xdriveSettings());
        $this->xdriveMenu($error !== '' ? $error : 'xdrive probe ok');
    }

    public function xdriveSet(string $field): void
    {
        if (!preg_match('~^(url|folder|template|secrets|poll|secret[0-2])$~D', $field)) return;
        $r = $this->send($this->input['chat'], "@{$this->input['username']} " . $this->i18n('enter value') . "\n\n" . $this->i18n('xdrive hint ' . preg_replace('~\d$~', '', $field)),
            $this->input['message_id'], reply: $this->i18n('enter value'));
        $this->stashReply($r, ['start_message' => $this->input['message_id'], 'start_callback' => $this->input['callback_id'],
            'callback' => 'saveXdrive', 'args' => [$field]]);
    }

    // Ответ администратора с доступом к хранилищу удаляет reply(): в чате он не остаётся.
    public function saveXdrive($value, $field): void
    {
        $value = trim((string) $value);
        $s = $this->xdriveSettings();
        $before = $s;
        if (preg_match('~^secret([0-2])$~D', (string) $field, $m)) {
            $count = $s['service'] === 'gdrive' ? 3 : 2;
            $s['secrets'] = array_slice(array_pad($s['secrets'], $count, ''), 0, $count);
            if ((int) $m[1] < $count) $s['secrets'][(int) $m[1]] = $value;
        } elseif ($field === 'secrets') {
            $s['secrets'] = array_values(array_filter(array_map('trim', preg_split('~\R~', $value)), static fn($v) => $v !== ''));
        } elseif ($field === 'poll') {
            $s['poll'] = (int) $value;
        } elseif ($field === 'url') {
            $s['url'] = (string) (self::xdriveWebdavUrl($value) ?? '');
        } elseif (in_array($field, ['folder', 'template'], true)) {
            $s[$field] = $field === 'folder' ? trim($value, '/') : $value;
        } else {
            return;
        }
        // Неполные настройки сохраняются выключенными: заполнять их приходится по одному полю.
        $s = $this->xdriveSettings(['xdrive' => $s]);
        if (!empty($s['enabled']) && $this->xdriveProblems($s)) $s['enabled'] = 0;
        $error = $s === $before ? '' : $this->applyXdrive($s);
        $this->xdriveMenu($error !== '' ? $error : ($field === 'url' && $s['url'] === '' && $value !== '' ? 'xdrive need url' : ''));
    }

    public function xdriveUsers(int $page = 0): void
    {
        $p = $this->getPacConf();
        $clients = array_values(array_filter($this->getXray()['inbounds'][0]['settings']['clients'] ?? [],
            static fn($client) => is_string($client['id'] ?? null) && $client['id'] !== ''));
        $size = 10;
        $pages = max(1, (int) ceil(count($clients) / $size));
        $page = max(0, min($page, $pages - 1));
        $text = ['Menu -> ' . $this->i18n('xray') . ' -> XDRIVE -> ' . $this->i18n('xdrive profiles'), $this->i18n('xdrive profiles hint')];
        if (!$this->xdriveActive($p, $this->getXray())) $text[] = '⚠️ ' . $this->i18n('xdrive inactive');
        $data = [];
        foreach (array_slice($clients, $page * $size, $size) as $client) {
            $data[] = [['text' => (string) ($client['email'] ?? '—'), 'callback_data' => '/xdriveProfile ' . self::xdriveClientKey($client)]];
        }
        if ($pages > 1) {
            $nav = [];
            if ($page > 0) $nav[] = ['text' => '←', 'callback_data' => '/xdriveUsers ' . ($page - 1)];
            $nav[] = ['text' => ($page + 1) . "/$pages", 'callback_data' => '/xdriveUsers ' . $page];
            if ($page < $pages - 1) $nav[] = ['text' => '→', 'callback_data' => '/xdriveUsers ' . ($page + 1)];
            $data[] = $nav;
        }
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => '/xdrive']];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $text), $data);
    }

    // Пользователь в кнопке задан отпечатком идентификатора, а не номером в
    // списке: список мог измениться, пока меню открыто, и профиль ушёл бы не тому.
    public static function xdriveClientKey(array $client): string
    {
        return substr(hash('sha256', 'xdrive-profile:' . ($client['id'] ?? '')), 0, 16);
    }

    public function xdriveProfile(string $key): void
    {
        $found = null;
        foreach ($this->getXray()['inbounds'][0]['settings']['clients'] ?? [] as $client) {
            if (is_string($client['id'] ?? null) && $client['id'] !== '' && hash_equals(self::xdriveClientKey($client), $key)) $found = $client;
        }
        $config = $found === null ? null : $this->xdriveClientConfig($found);
        if ($config === null) {
            $this->answer($this->input['callback_id'], $this->i18n('xdrive profile unavailable'), true);
            return;
        }
        $name = preg_replace('~[^A-Za-z0-9._-]+~', '_', (string) ($found['email'] ?? '')) ?: 'user';
        $json = json_encode($config, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        try {
            $this->sendFile($this->input['chat'], new CURLStringFile($json . "\n", "xdrive-$name.json", 'application/json'),
                $this->i18n('xdrive profile caption'));
        } catch (Throwable $error) {
            $this->answer($this->input['callback_id'], $this->i18n('xdrive profile unavailable'), true);
            return;
        }
        $this->answer($this->input['callback_id']);
    }
}
