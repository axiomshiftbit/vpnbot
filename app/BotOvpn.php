<?php

// Дополнения раздела OpenVPN: перевыпуск сертификата клиента, настройки
// туннеля (весь трафик или выбранные сети, MSS, запасной TCP рядом с UDP),
// накопительный учёт трафика с лимитом. Базовые операции (PKI, перезапуск,
// выдача .ovpn) остаются в bot.php.
trait BotOvpn
{
    // Значения mssfix по кругу; 0 — директива не пишется (умолчание OpenVPN).
    public const OVPN_MSS = [0, 1360, 1280, 1200];
    public const OVPN_ROUTES_MAX = 40;
    // Адрес DNS сборки: при выборочной маршрутизации клиенту нужен путь к нему.
    public const OVPN_DNS = '10.10.0.5';
    // Как часто счётчики трафика пишутся на диск, пока сессии не менялись.
    public const OVPN_TRAFFIC_FLUSH = 60;

    public function ovpnTrafficPath(): string
    {
        return dirname($this->ovpnPaths()['srv']) . '/traffic.json';
    }

    // ---- server.conf: блоки между парными маркерами ------------------------

    private static function ovpnBlockRe(string $marker): string
    {
        return '~^[ \t]*#' . preg_quote($marker, '~') . '[ \t]*\R(.*?)^[ \t]*#' . preg_quote($marker, '~') . '[ \t]*$~sm';
    }

    // Содержимое блока; null — конфига или маркеров нет.
    public function ovpnBlock(string $marker): ?string
    {
        $srv = $this->ovpnPaths()['srv'];
        if (!file_exists($srv)) {
            return null;
        }
        return preg_match(self::ovpnBlockRe($marker), (string) file_get_contents($srv), $m) ? $m[1] : null;
    }

    // Заменяет содержимое блока. Маркеров нет (конфиг из старой копии) —
    // сначала доносим миграции тем же скриптом, что и при старте контейнера.
    public function ovpnSetBlock(string $marker, string $body): bool
    {
        $srv = $this->ovpnPaths()['srv'];
        if (!file_exists($srv)) {
            return false;
        }
        $re = self::ovpnBlockRe($marker);
        $cfg = (string) file_get_contents($srv);
        if (!preg_match($re, $cfg)) {
            $this->migrateOvpnServerConf();
            $cfg = (string) file_get_contents($srv);
            if (!preg_match($re, $cfg)) {
                return false;
            }
        }
        $body = $body === '' ? '' : rtrim($body, "\n") . "\n";
        $cfg = preg_replace_callback($re, static fn() => "#$marker\n$body#$marker", $cfg, 1);
        return file_put_contents($srv, $cfg) !== false;
    }

    // ---- udp, tcp или оба сразу ---------------------------------------------

    // OpenVPN 2.7 открывает несколько сокетов в одном процессе: общий пул
    // адресов, один файл состояния и один управляющий сокет.
    public function isOvpnDual(): bool
    {
        return (bool) preg_match('~^\s*local\s+\S+\s+\d+\s+tcp~m', (string) $this->ovpnBlock('ovpn-dual'));
    }

    // Что слушает сервер: ['udp'], ['tcp'] или ['udp', 'tcp'].
    public function ovpnListenProtos(): array
    {
        if ($this->isOvpnDual()) {
            return ['udp', 'tcp'];
        }
        return [str_starts_with($this->getOvpnProto(), 'tcp') ? 'tcp' : 'udp'];
    }

    // Блок #ovpn-port для upstream.conf: по серверу nginx на каждый протокол.
    public static function ovpnUpstreamBlock(int $port, array $protos): string
    {
        $block = "#ovpn-port\n";
        foreach ($protos as $proto) {
            $listen = $proto === 'tcp' ? "listen      $port reuseport;" : "listen      $port udp reuseport;";
            $block .= "    server {\n        $listen\n        proxy_pass  openvpn;\n    }\n";
        }
        return $block . "    #ovpn-port";
    }

    // ---- весь трафик или выбранные сети ------------------------------------

    // Без маркеров (конфиг до миграции) действует прежнее: весь трафик.
    public function isOvpnFullTunnel(): bool
    {
        $block = $this->ovpnBlock('ovpn-gateway');
        return $block === null || (bool) preg_match('~^\s*push\s+"redirect-gateway\b~m', $block);
    }

    public function toggleOvpnGateway()
    {
        $full = $this->isOvpnFullTunnel();
        // В выборочном режиме шлюз клиента не меняется, поэтому путь к DNS
        // сборки передаётся отдельным маршрутом: иначе имена не разрешаются.
        $body = $full
            ? 'push "route ' . self::OVPN_DNS . ' 255.255.255.255"'
            : 'push "redirect-gateway def1 bypass-dhcp"';
        if (!$this->ovpnSetBlock('ovpn-gateway', $body)) {
            $this->send($this->input['chat'], $this->i18n('ovpn conf markers'));
            return $this->menu('ovpn');
        }
        if ($full && !$this->getOvpnRoutes()) {
            $this->send($this->input['chat'], '⚠️ ' . $this->i18n('ovpn split empty'));
        }
        $this->restartOvpn();
        $this->menu('ovpn');
    }

    // Сети в записи CIDR, как их ввёл администратор (уже нормализованные).
    public function getOvpnRoutes(): array
    {
        $routes = [];
        preg_match_all('~^\s*push\s+"route\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)"~m', (string) $this->ovpnBlock('ovpn-routes'), $m, PREG_SET_ORDER);
        foreach ($m as $route) {
            $mask = ip2long($route[2]);
            if ($mask === false) {
                continue;
            }
            $routes[] = $route[1] . '/' . substr_count(decbin($mask & 0xFFFFFFFF), '1');
        }
        return $routes;
    }

    // Разбор ввода: сети через пробел, запятую или с новой строки.
    // Возвращает [сети, первая ошибочная запись либо ''].
    public static function ovpnParseRoutes(string $input): array
    {
        $routes = [];
        foreach (preg_split('~[\s,;]+~', trim($input), -1, PREG_SPLIT_NO_EMPTY) as $item) {
            if (!preg_match('~^(\d{1,3}(?:\.\d{1,3}){3})(?:/(\d{1,2}))?$~D', $item, $m)
                || filter_var($m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
                return [[], $item];
            }
            $prefix = isset($m[2]) ? (int) $m[2] : 32;
            // /0 — это «весь трафик», для него есть отдельный переключатель.
            if ($prefix < 1 || $prefix > 32) {
                return [[], $item];
            }
            $mask = (0xFFFFFFFF << (32 - $prefix)) & 0xFFFFFFFF;
            $routes[long2ip(ip2long($m[1]) & $mask) . '/' . $prefix] = true;
        }
        return [array_keys($routes), ''];
    }

    public function setOvpnRoutes()
    {
        $current = $this->getOvpnRoutes();
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} " . $this->i18n('enter value') . "\n\n" . $this->i18n('ovpn routes hint')
                . ($current ? "\n\n<code>" . implode("\n", $current) . '</code>' : ''),
            $this->input['message_id'],
            reply: $this->i18n('enter value'),
        );
        $this->stashReply($r, [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'saveOvpnRoutes',
            'args'           => [],
        ]);
    }

    public function saveOvpnRoutes($value)
    {
        $value = trim((string) $value);
        [$routes, $bad] = in_array($value, ['-', '0'], true) ? [[], ''] : self::ovpnParseRoutes($value);
        if ($bad !== '') {
            $this->send($this->input['chat'], $this->i18n('ovpn routes bad') . ': <code>' . htmlspecialchars($bad, ENT_QUOTES) . '</code>');
            return $this->menu('ovpn');
        }
        if (count($routes) > self::OVPN_ROUTES_MAX) {
            $this->send($this->input['chat'], $this->i18n('ovpn routes many') . ' ' . self::OVPN_ROUTES_MAX);
            return $this->menu('ovpn');
        }
        if ($routes === $this->getOvpnRoutes()) {
            return $this->menu('ovpn');
        }
        $lines = [];
        foreach ($routes as $route) {
            [$net, $prefix] = explode('/', $route);
            $lines[] = 'push "route ' . $net . ' ' . long2ip((0xFFFFFFFF << (32 - (int) $prefix)) & 0xFFFFFFFF) . '"';
        }
        if (!$this->ovpnSetBlock('ovpn-routes', implode("\n", $lines))) {
            $this->send($this->input['chat'], $this->i18n('ovpn conf markers'));
            return $this->menu('ovpn');
        }
        $this->restartOvpn();
        $this->menu('ovpn');
    }

    // ---- MSS ----------------------------------------------------------------

    public function getOvpnMss(): int
    {
        return preg_match('~^\s*mssfix\s+(\d+)~m', (string) $this->ovpnBlock('ovpn-mss'), $m) ? (int) $m[1] : 0;
    }

    public function toggleOvpnMss()
    {
        $index = array_search($this->getOvpnMss(), self::OVPN_MSS, true);
        $next = self::OVPN_MSS[($index === false ? 0 : $index + 1) % count(self::OVPN_MSS)];
        if (!$this->ovpnSetBlock('ovpn-mss', $next ? "mssfix $next" : '')) {
            $this->send($this->input['chat'], $this->i18n('ovpn conf markers'));
            return $this->menu('ovpn');
        }
        $this->restartOvpn();
        $this->menu('ovpn');
    }

    // ---- перевыпуск сертификата --------------------------------------------

    public function renewOvpnUser($user, $confirm = false)
    {
        $user = preg_replace('~[^a-zA-Z0-9_.\-]~', '', (string) $user);
        if (empty($user) || $user === 'server' || !in_array($user, $this->getOvpnUsers(), true)) {
            return $this->menu('ovpn');
        }
        if (!$confirm) {
            $text = 'Menu -> ' . $this->i18n('OpenVPN') . ' -> <code>' . htmlspecialchars($user, ENT_QUOTES) . "</code>\n"
                . '⚠ ' . $this->i18n('ovpn renew confirm');
            return $this->update($this->input['chat'], $this->input['message_id'], $text, [
                [['text' => '♻️ ' . $this->i18n('ovpn renew'), 'callback_data' => "/renewOvpnUser $user confirm"]],
                [['text' => $this->i18n('cancel'), 'callback_data' => "/ovpnClientMenu $user"]],
            ]);
        }
        // Отзыв и выпуск под одним локом: между ними никто не должен снять
        // снимок PKI или выпустить сертификат с тем же именем.
        $result = $this->withOvpnPkiLock(function () use ($user) {
            $p = $this->ovpnPaths();
            if (!file_exists($p['ca']) || !file_exists($p['pki'] . '/private/ca.key')) {
                return 'pki';
            }
            if ($this->ovpnRevokeLocked($user) === 'failed') {
                return 'revoke';
            }
            return $this->ovpnIssueLocked($user) === 'ok' ? 'ok' : 'issue';
        }, 25, 'busy');
        if ($result === 'busy') {
            $this->send($this->input['chat'], '⏳ ' . $this->i18n('OpenVPN') . ': ' . $this->i18n('ovpn pki busy'));
            return $this->ovpnClientMenu($user);
        }
        if ($result === 'pki') {
            $this->send($this->input['chat'], $this->i18n('ovpn pki not ready'));
            return $this->ovpnClientMenu($user);
        }
        if ($result === 'revoke') {
            // Старый сертификат остался действующим: клиент ничего не потерял.
            $this->send($this->input['chat'], '❌ ' . $this->i18n('ovpn renew failed'));
            return $this->ovpnClientMenu($user);
        }
        // Сессия по старому сертификату закрывается в обоих случаях.
        $this->ovpnMgmt(["kill $user", 'exit']);
        if ($result !== 'ok') {
            // Отозван, а новый не выпущен: клиента больше нет в списке.
            $this->send($this->input['chat'], '❌ ' . $this->i18n('ovpn renew lost') . ' <code>' . htmlspecialchars($user, ENT_QUOTES) . '</code>');
            return $this->menu('ovpn');
        }
        $this->sendOvpnConfigFile($user);
        $this->ovpnClientMenu($user);
    }

    // ---- учёт трафика --------------------------------------------------------

    public function ovpnTrafficLoad(): array
    {
        $data = json_decode((string) @file_get_contents($this->ovpnTrafficPath()), true);
        return is_array($data) && is_array($data['users'] ?? null) ? $data : ['users' => [], 'saved' => 0];
    }

    private function ovpnTrafficSave(array $data): void
    {
        $path = $this->ovpnTrafficPath();
        if (!is_dir(dirname($path))) {
            return;
        }
        $data['saved'] = time();
        $tmp = $path . '.tmp';
        if (file_put_contents($tmp, json_encode($data, JSON_UNESCAPED_SLASHES)) !== false) {
            @chmod($tmp, 0600);
            rename($tmp, $path);
        }
    }

    private static function ovpnTrafficUser(array $row): array
    {
        return ['rx' => max(0, (int) ($row['rx'] ?? 0)), 'tx' => max(0, (int) ($row['tx'] ?? 0)),
            'live' => is_array($row['live'] ?? null) ? $row['live'] : [], 'since' => (int) ($row['since'] ?? time()),
            'limit' => max(0, (int) ($row['limit'] ?? 0)), 'limited' => !empty($row['limited'])];
    }

    // Сводит счётчики демона с накопленными. OpenVPN отдаёт байты только по
    // текущей сессии, поэтому завершившиеся сессии складываются в итог, а
    // живые запоминаются по последнему значению. $mutate правит запись под
    // тем же локом (сброс, лимит). Возвращает клиентов с исчерпанным лимитом.
    public function ovpnTrafficSync(?callable $mutate = null): array
    {
        if ($mutate === null && !file_exists($this->ovpnPaths()['status'])) {
            return [];
        }
        return (array) $this->withLock('ovpn-traffic', function () use ($mutate) {
            $data = $this->ovpnTrafficLoad();
            $before = $data['users'];
            $users = array_flip($this->getOvpnUsers());
            $status = $this->getOvpnStatus();
            $ended = false;
            foreach ($data['users'] as $cn => $row) {
                // Клиента нет в списке — не трогаем: во время перевыпуска
                // сертификат на секунду исчезает. Запись убирает удаление.
                if (!isset($users[$cn])) {
                    continue;
                }
                $row = self::ovpnTrafficUser($row);
                $key = isset($status[$cn]) ? $status[$cn]['since'] . '|' . $status[$cn]['cid'] : null;
                foreach ($row['live'] as $session => $bytes) {
                    if ($session === $key) {
                        continue;
                    }
                    $row['rx'] += max(0, (int) ($bytes[0] ?? 0) - (int) ($bytes[2] ?? 0));
                    $row['tx'] += max(0, (int) ($bytes[1] ?? 0) - (int) ($bytes[3] ?? 0));
                    unset($row['live'][$session]);
                    $ended = true;
                }
                $data['users'][$cn] = $row;
            }
            foreach ($status as $cn => $session) {
                if (!isset($users[$cn])) {
                    continue;
                }
                $row = self::ovpnTrafficUser($data['users'][$cn] ?? []);
                $key = $session['since'] . '|' . $session['cid'];
                // Счётчик сессии только растёт; меньшее значение — устаревшее чтение.
                // Третье и четвёртое числа — сколько байт сессии уже было на
                // момент сброса счётчика: они в итог не идут.
                $row['live'][$key] = [max((int) $session['rx'], (int) ($row['live'][$key][0] ?? 0)),
                    max((int) $session['tx'], (int) ($row['live'][$key][1] ?? 0)),
                    (int) ($row['live'][$key][2] ?? 0), (int) ($row['live'][$key][3] ?? 0)];
                $data['users'][$cn] = $row;
            }
            if ($mutate !== null) {
                $data['users'] = $mutate($data['users']);
            }
            $limited = [];
            $crossed = false;
            foreach ($data['users'] as $cn => $row) {
                if (!isset($users[$cn])) {
                    continue;
                }
                $row = self::ovpnTrafficUser($row);
                $used = self::ovpnTrafficTotal($row);
                $over = $row['limit'] > 0 && $used['rx'] + $used['tx'] >= $row['limit'];
                $crossed = $crossed || $over !== $row['limited'];
                $row['limited'] = $over;
                if ($over) {
                    $limited[] = $cn;
                }
                $data['users'][$cn] = $row;
            }
            if ($mutate !== null || $ended || $crossed
                || ($data['users'] != $before && time() - (int) ($data['saved'] ?? 0) >= self::OVPN_TRAFFIC_FLUSH)) {
                $this->ovpnTrafficSave($data);
            }
            return $limited;
        }, 5, []);
    }

    private static function ovpnTrafficTotal(array $row): array
    {
        $rx = (int) ($row['rx'] ?? 0);
        $tx = (int) ($row['tx'] ?? 0);
        foreach ((array) ($row['live'] ?? []) as $bytes) {
            $rx += max(0, (int) ($bytes[0] ?? 0) - (int) ($bytes[2] ?? 0));
            $tx += max(0, (int) ($bytes[1] ?? 0) - (int) ($bytes[3] ?? 0));
        }
        return ['rx' => $rx, 'tx' => $tx];
    }

    // Итог по клиенту: ['rx','tx','since','limit','limited'].
    public function ovpnTraffic(string $user): array
    {
        $row = self::ovpnTrafficUser($this->ovpnTrafficLoad()['users'][$user] ?? []);
        return self::ovpnTrafficTotal($row) + ['since' => $row['since'], 'limit' => $row['limit'], 'limited' => $row['limited']];
    }

    // Шаг cron: обновляет счётчики и блокирует исчерпавших лимит. Решение
    // принимается по состоянию, а не по моменту превышения: лимит могли
    // уменьшить из меню, и это превышение увидел бы не cron.
    public function trackOvpnTraffic(): void
    {
        if (!$this->protocolModuleEnabled('ovpn')) {
            return;
        }
        foreach ($this->ovpnTrafficSync() as $user) {
            if ($this->isOvpnUserDisabled($user)) {
                continue;
            }
            $p = $this->ovpnPaths();
            @mkdir($p['ccd'], 0755, true);
            file_put_contents($p['ccd'] . '/' . $user, "disable\n");
            $this->ovpnMgmt(["kill $user", 'exit']);
            $admin = $this->ovpnAdminChat();
            if ($admin) {
                $this->send($admin, '🚫 ' . $this->i18n('OpenVPN') . ' <code>' . htmlspecialchars($user, ENT_QUOTES) . '</code>: '
                    . $this->i18n('ovpn limit reached'));
            }
        }
    }

    // Кому сообщать о сработавшем лимите: cron работает без входящего сообщения.
    protected function ovpnAdminChat()
    {
        if (!is_file(__DIR__ . '/config.php')) {
            return null;
        }
        require __DIR__ . '/config.php';
        return $c['admin'][0] ?? null;
    }

    public function resetOvpnTraffic($user)
    {
        $user = preg_replace('~[^a-zA-Z0-9_.\-]~', '', (string) $user);
        if (empty($user) || !in_array($user, $this->getOvpnUsers(), true)) {
            return $this->menu('ovpn');
        }
        $this->ovpnTrafficSync(function (array $users) use ($user) {
            $row = self::ovpnTrafficUser($users[$user] ?? []);
            // Живая сессия продолжает считаться с нуля: запоминаем, сколько
            // в ней уже набежало.
            foreach ($row['live'] as $session => $bytes) {
                $row['live'][$session] = [(int) ($bytes[0] ?? 0), (int) ($bytes[1] ?? 0), (int) ($bytes[0] ?? 0), (int) ($bytes[1] ?? 0)];
            }
            $users[$user] = ['rx' => 0, 'tx' => 0, 'since' => time()] + $row;
            return $users;
        });
        $this->ovpnClientMenu($user);
    }

    public function setOvpnLimit($user)
    {
        $user = preg_replace('~[^a-zA-Z0-9_.\-]~', '', (string) $user);
        if (empty($user) || !in_array($user, $this->getOvpnUsers(), true)) {
            return $this->menu('ovpn');
        }
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} " . $this->i18n('enter value') . "\n\n" . $this->i18n('ovpn limit hint'),
            $this->input['message_id'],
            reply: $this->i18n('enter value'),
        );
        $this->stashReply($r, [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'saveOvpnLimit',
            'args'           => [$user],
        ]);
    }

    public function saveOvpnLimit($value, $user)
    {
        $user = preg_replace('~[^a-zA-Z0-9_.\-]~', '', (string) $user);
        if (empty($user) || !in_array($user, $this->getOvpnUsers(), true)) {
            return $this->menu('ovpn');
        }
        $value = str_replace(',', '.', trim((string) $value));
        if (!preg_match('~^\d{1,6}(\.\d{1,3})?$~D', $value)) {
            $this->send($this->input['chat'], $this->i18n('ovpn limit bad'));
            return $this->ovpnClientMenu($user);
        }
        $limit = (int) round((float) $value * 1024 ** 3);
        $this->ovpnTrafficSync(function (array $users) use ($user, $limit) {
            $users[$user] = ['limit' => $limit] + self::ovpnTrafficUser($users[$user] ?? []);
            return $users;
        });
        $this->ovpnClientMenu($user);
    }

    // Строки и кнопки для меню клиента.
    public function ovpnTrafficLine(string $user): string
    {
        $t = $this->ovpnTraffic($user);
        $line = $this->i18n('ovpn traffic total') . ': ↓' . $this->fmtBytes($t['rx']) . ' ↑' . $this->fmtBytes($t['tx'])
            . ' (' . $this->i18n('ovpn traffic since') . ' ' . date('Y-m-d', $t['since']) . ')';
        if ($t['limit'] > 0) {
            $line .= "\n" . ($t['limited'] ? '🚫 ' : '') . $this->i18n('ovpn limit') . ': ' . $this->fmtBytes($t['rx'] + $t['tx'])
                . ' / ' . $this->fmtBytes($t['limit']);
        }
        return $line;
    }
}
