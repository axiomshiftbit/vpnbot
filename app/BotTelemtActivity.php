<?php

// TeleMT: кто подключён сейчас, сколько трафика прошло и с каких адресов
// приходил пользователь. Журнала подключений у ядра нет: управляющий API
// (GET /v1/users) отдаёт только текущее состояние — число соединений, активные
// адреса, адреса за последние 30 с и счётчик байтов, который обнуляется при
// каждом перезапуске ядра (а бот перезапускает его при любой правке
// пользователей). Поэтому cron снимает состояние раз в 20 с и сам накапливает
// трафик и историю адресов; меню читают накопленное.
trait BotTelemtActivity
{
    // Короче 30-секундного окна «недавних» адресов ядра: соединение, которое
    // открылось и закрылось между двумя опросами, всё равно попадёт в журнал.
    private const TELEMT_ACTIVITY_PERIOD = 20;
    // Снимок старше этого возраста не выдаётся за текущее состояние.
    private const TELEMT_ACTIVITY_FRESH = 90;

    public $time_telemttrack = 0;

    public function telemtActivityPath(): string
    {
        return '/config/telemtactivity.json';
    }

    public function getTelemtActivity(): array
    {
        $state = json_decode((string) @file_get_contents($this->telemtActivityPath()), true);
        if (!is_array($state) || !is_array($state['users'] ?? null)) {
            return ['at' => 0, 'boot' => 0, 'users' => []];
        }

        return $state + ['at' => 0, 'boot' => 0];
    }

    // Те же пределы, что у журналов VLESS и WireGuard: 30 дней и 50 последних
    // адресов на пользователя. Число пользователей ограничено конфигом —
    // trackTelemtOnline() хранит записи только существующих.
    public function setTelemtActivity(array $state): void
    {
        $ttl = time() - 2592000;
        foreach ($state['users'] as $name => $user) {
            $ips = array_filter((array) ($user['ips'] ?? []), static fn($rec) => ($rec['last'] ?? 0) >= $ttl);
            if (count($ips) > 50) {
                uasort($ips, static fn($a, $b) => ($b['last'] ?? 0) <=> ($a['last'] ?? 0));
                $ips = array_slice($ips, 0, 50, true);
            }
            $state['users'][$name]['ips'] = $ips;
        }
        $path = $this->telemtActivityPath();
        if ($this->atomicJson($path, $state)) {
            // В журнале адреса пользователей: nginx и остальные его не читают.
            @chmod($path, 0600);
        }
    }

    // Шаг cron и обновление по кнопке: один запрос к API на всех пользователей.
    // Возвращает false, когда свежих данных нет (ядро остановлено или API ещё
    // выключен старым telemt.toml до первого перезапуска).
    public function trackTelemtOnline(bool $force = false): bool
    {
        if (!$force && !empty($this->time_telemttrack) && time() - $this->time_telemttrack < self::TELEMT_ACTIVITY_PERIOD) {
            return false;
        }
        $this->time_telemttrack = time();
        // Остановленный сервис не опрашиваем: его контейнера нет, и каждая
        // попытка ssh держала бы цикл cron до таймаута.
        if (!$this->protocolModuleEnabled('telemt') || !$this->telemtServiceRunning()) {
            return false;
        }
        $names = array_map('strval', array_keys((array) ($this->getPacConf()['telemt_users'] ?? [])));
        if (!$names) {
            return false;
        }
        $api  = $this->telemtApiFetch(['/v1/users', '/v1/system/info', '/v1/stats/users/quota']);
        $rows = $api['/v1/users'] ?? null;
        if (!is_array($rows)) {
            return false;
        }
        $boot = (int) ($api['/v1/system/info']['process_started_at_epoch_secs'] ?? 0);
        // Расход квоты ядро отдаёт только для пользователей с квотой.
        $quota = [];
        foreach ((array) ($api['/v1/stats/users/quota']['users'] ?? []) as $item) {
            if (is_array($item) && is_string($item['username'] ?? null) && is_int($item['used_bytes'] ?? null)) {
                $quota[$item['username']] = max(0, $item['used_bytes']);
            }
        }

        // Меню и cron — разные процессы: без блокировки два снимка подряд
        // дважды прибавили бы один и тот же прирост трафика.
        return (bool) $this->withLock('telemtactivity', function () use ($rows, $names, $boot, $quota) {
            $state = $this->getTelemtActivity();
            $now   = time();
            // Ядро перезапускалось — его счётчик начался с нуля. Без времени
            // запуска остаётся признак «счётчик стал меньше».
            // Сравниваем только два известных времени: иначе первый ответ с
            // временем запуска выглядел бы перезапуском и удвоил бы трафик.
            $restarted = $boot > 0 && (int) $state['boot'] > 0 && abs($boot - (int) $state['boot']) > 2;
            $users = [];
            foreach ($rows as $row) {
                $name = $row['username'] ?? null;
                if (!is_string($name) || !in_array($name, $names, true)) {
                    continue;
                }
                $user = (array) ($state['users'][$name] ?? []) + ['bytes' => 0, 'raw' => 0, 'since' => $now, 'last' => 0, 'ips' => []];
                $raw  = max(0, (int) ($row['total_octets'] ?? 0));
                $prev = $restarted ? 0 : (int) $user['raw'];
                $user['bytes'] += $raw >= $prev ? $raw - $prev : $raw;
                $user['raw']    = $raw;
                $user['conns']  = max(0, (int) ($row['current_connections'] ?? 0));
                $user['quota_used'] = $quota[$name] ?? null;
                $active = self::telemtActivityIps($row['active_unique_ips_list'] ?? []);
                $user['online'] = $active;
                if ($user['conns'] > 0 || $active) {
                    $user['last'] = $now;
                }
                // «Недавние» адреса уже отключились, но были на связи после
                // прошлого опроса — в журнал идут наравне с активными.
                foreach (array_unique(array_merge($active, self::telemtActivityIps($row['recent_unique_ips_list'] ?? []))) as $ip) {
                    if (!isset($user['ips'][$ip])) {
                        $user['ips'][$ip] = ['first' => $now, 'last' => $now, 'count' => 1];
                        continue;
                    }
                    // Новым подключением считается появление после паузы в 5 минут,
                    // как в журналах VLESS и WireGuard: постоянно подключённый
                    // клиент — одно подключение, а не тысячи опросов.
                    if ($now - (int) ($user['ips'][$ip]['last'] ?? 0) > 300) {
                        $user['ips'][$ip]['count'] = (int) ($user['ips'][$ip]['count'] ?? 0) + 1;
                    }
                    $user['ips'][$ip]['last'] = $now;
                }
                $users[$name] = $user;
            }
            // Пользователь есть в конфиге, но ядро его ещё не отдало (не перезапущено):
            // накопленное сохраняем, «онлайн» сбрасываем.
            foreach ($names as $name) {
                if (!isset($users[$name]) && isset($state['users'][$name])) {
                    $users[$name] = ['conns' => 0, 'online' => []] + (array) $state['users'][$name];
                }
            }
            $this->setTelemtActivity(['at' => $now, 'boot' => $boot ?: (int) $state['boot'], 'users' => $users]);

            return true;
        }, 5, false);
    }

    // Отсутствующий файл — установка до появления выключателя: сервис работает.
    public function telemtServiceRunning(): bool
    {
        $flag = @file_get_contents('/config/telemt/service-enabled');

        return $flag === false || trim($flag) === '1';
    }

    // Для меню: свежий снимок без запроса к ядру на каждое нажатие.
    public function telemtActivityRefresh(): void
    {
        if (time() - (int) $this->getTelemtActivity()['at'] >= 5) {
            $this->trackTelemtOnline(true);
        }
    }

    private static function telemtActivityIps($list): array
    {
        return array_values(array_filter((array) $list, static fn($ip) => is_string($ip) && filter_var($ip, FILTER_VALIDATE_IP) !== false));
    }

    // Запись пользователя для меню: null — данных о нём ещё нет.
    // 'fresh' говорит, можно ли верить полям conns/online как текущим.
    public function telemtActivityOf(string $name, ?array $state = null): ?array
    {
        $state ??= $this->getTelemtActivity();
        if (!isset($state['users'][$name])) {
            return null;
        }
        $user = (array) $state['users'][$name] + ['bytes' => 0, 'since' => 0, 'last' => 0, 'conns' => 0, 'online' => [], 'ips' => [], 'quota_used' => null];
        $user['fresh'] = time() - (int) $state['at'] <= self::TELEMT_ACTIVITY_FRESH;
        if (!$user['fresh']) {
            $user['conns'] = 0;
            $user['online'] = [];
        }

        return $user;
    }

    public function telemtActivityForget(string $name, bool $journalOnly = false): void
    {
        $this->withLock('telemtactivity', function () use ($name, $journalOnly) {
            $state = $this->getTelemtActivity();
            if (!isset($state['users'][$name])) {
                return;
            }
            if ($journalOnly) {
                $state['users'][$name]['ips'] = [];
            } else {
                unset($state['users'][$name]);
            }
            $this->setTelemtActivity($state);
        }, 5);
    }

    // Размеры квот для отметок в меню. Повреждённые лимиты останавливают ядро
    // (telemtToml), но список и карточка должны открываться, чтобы это исправить.
    public function telemtActivityQuotas(array $conf): array
    {
        try {
            return array_map(static fn($row) => (int) ($row['quota'] ?? 0), $this->telemtLimitsOf($conf));
        } catch (Throwable $error) {
            return [];
        }
    }

    // Подпись в списке: «👤2» — в сети, два соединения; затем трафик и ⛔,
    // если квота исчерпана и ядро новые соединения не принимает.
    public function telemtActivityTail(?array $user, int $quota): string
    {
        if (!$user) {
            return '';
        }
        $tail = '';
        if ($user['conns'] > 0 || $user['online']) {
            $tail .= ' · 👤' . max(1, (int) $user['conns']);
        }
        if ($user['bytes'] > 0) {
            $tail .= ' · ' . $this->fmtBytes((int) $user['bytes']);
        }
        if ($quota > 0 && $user['quota_used'] !== null && $user['quota_used'] >= $quota) {
            $tail .= ' · ⛔';
        }

        return $tail;
    }

    // Строки карточки пользователя: состояние, адреса, трафик, квота.
    public function telemtActivityLines(string $name, int $quota = 0): array
    {
        $this->telemtActivityRefresh();
        $user = $this->telemtActivityOf($name);
        if ($user === null) {
            return [$this->i18n('telemt activity none')];
        }
        $online = $user['conns'] > 0 || $user['online'];
        if ($online) {
            $line = '🟢 ' . $this->i18n('online') . ' · ' . $this->i18n('connections') . ': ' . (int) $user['conns'];
            if ($user['online']) {
                $line .= "\n" . implode(', ', array_map(static fn($ip) => '<code>' . self::esc($ip) . '</code>', array_slice($user['online'], 0, 20)));
            }
        } else {
            $line = '⚪ ' . $this->i18n($user['fresh'] ? 'offline' : 'telemt activity stale')
                . ($user['last'] ? ' · ' . $this->i18n('last seen') . ': ' . date('d.m.Y H:i', (int) $user['last']) : '');
        }

        $lines = [
            $line,
            $this->i18n('telemt activity traffic') . ': ' . $this->fmtBytes((int) $user['bytes'])
                . ($user['since'] ? ' · ' . $this->i18n('telemt activity since') . ' ' . date('d.m.Y', (int) $user['since']) : ''),
        ];
        if ($quota > 0 && $user['quota_used'] !== null) {
            $lines[] = $this->i18n('telemt limits quota') . ': ' . $this->fmtBytes((int) $user['quota_used']) . ' / ' . $this->fmtBytes($quota)
                . ($user['quota_used'] >= $quota ? "\n" . $this->i18n('telemt limits exhausted') : '');
        }

        return $lines;
    }

    public function telemtUserLog(string $name, int $page = 0, string $relay = '', bool $clear = false): void
    {
        $conf = $this->getPacConf();
        if (!isset($conf['telemt_users'][$name])) { $this->telemtUsers($relay, $page); return; }
        if ($clear) {
            $this->telemtActivityForget($name, true);
            if (!empty($this->input['callback_id'])) {
                $this->answer($this->input['callback_id'], '🗑 ' . $this->i18n('log cleared'));
            }
        } else {
            $this->telemtActivityRefresh();
        }
        $user = $this->telemtActivityOf($name) ?? ['ips' => []];
        $text = ['TeleMT → <b>' . self::esc(mb_strimwidth($name, 0, 256, '…')) . '</b> → ' . $this->i18n('connection log'), ''];
        if (empty($user['ips'])) {
            $text[] = $this->i18n('no log');
        } else {
            $geo    = $this->getGeoCache();
            $before = $geo;
            $text[] = '<code>';
            foreach ($this->connLogCard($name, ['ips' => $user['ips']], $geo, true) as $line) {
                $text[] = $line;
            }
            $text[] = '</code>';
            if ($geo !== $before) {
                $this->setGeoCache($geo);
            }
        }
        $text[] = '';
        $text[] = $this->i18n('telemt activity log note');
        $data = [[['text' => '🔄 ' . $this->i18n('refresh'), 'callback_data' => $this->telemtUserCallback($name, $page, $relay, 'log')]]];
        if (!empty($user['ips'])) {
            $data[] = [['text' => '🗑 ' . $this->i18n('clear log'), 'callback_data' => $this->telemtUserCallback($name, $page, $relay, 'logclear')]];
        }
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => $this->telemtUserCallback($name, $page, $relay)]];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $text), $data);
    }
}
