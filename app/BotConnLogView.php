<?php

/**
 * A user's connection log: by time (default), by site and by device, plus the
 * apps and devices that fetched the subscription and a full text export.
 *
 * Sources: the Xray access log (source IP, destination, time) aggregated in
 * connlog_ip/connlog_dst and, per day, in connlog_day; the subscription
 * requests (User-Agent and the device headers some apps send). A VPN tunnel
 * carries no browser or device data, so nothing else is claimed.
 */
trait BotConnLogView
{
    public const CONNLOG_PAGE_CHARS = 3200;
    public const CONNLOG_GEO_BUDGET = 30;

    // ── Subscription apps and devices ───────────────────────────────────────

    /** Record the app/device of a subscription request. Never blocks the subscription. */
    public function recordSubClient(array $client): void
    {
        $email = (string) ($client['email'] ?? '');
        if ($email === '' || !empty($client['exit_relay'])) return;
        $cut = static fn(string $name): string => mb_substr(trim(preg_replace('~[[:cntrl:]]~u', '', mb_scrub((string) ($_SERVER[$name] ?? ''), 'UTF-8'))), 0, 200);
        $device = ['ua' => $cut('HTTP_USER_AGENT'), 'os' => $cut('HTTP_X_DEVICE_OS'), 'osver' => $cut('HTTP_X_VER_OS'), 'model' => $cut('HTTP_X_DEVICE_MODEL')];
        if (implode('', $device) === '') return;
        $ip = trim((string) ($_SERVER['HTTP_X_REAL_IP'] ?? '')) ?: trim(explode(',', (string) ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? ''))[0]) ?: (string) ($_SERVER['REMOTE_ADDR'] ?? '');
        if (!filter_var($ip, FILTER_VALIDATE_IP)) $ip = '';
        try { $this->storeSubClientRecord($email, $device, $ip); }
        catch (Throwable $error) { error_log('recordSubClient: ' . get_class($error)); }
    }

    /**
     * Readable device from a User-Agent and the X-Device-* headers:
     * ['icon', 'app', 'os', 'model', 'browser'] — empty strings when unknown.
     */
    public static function connLogDevice(array $d): array
    {
        $ua = (string) ($d['ua'] ?? '');
        $app = '';
        $apps = ['Happ', 'v2rayNG', 'v2rayN', 'v2RayTun', 'V2Box', 'Hiddify', 'HiddifyNext', 'Streisand', 'Shadowrocket', 'Stash', 'Quantumult',
            'Surge', 'Loon', 'FoXray', 'Karing', 'NekoBox', 'Nekoray', 'Throne', 'FlClash', 'clash-verge', 'ClashMetaForAndroid', 'Clash',
            'mihomo', 'sing-box', 'SFA', 'SFI', 'SFM', 'SFT', 'Incy', 'Exclave', 'NapsternetV', 'OneClick', 'Prizrak-Box'];
        // The leading "Name/version" usually names the app; otherwise a known
        // name anywhere, as a whole word (Hiddify is not HiddifyNext).
        $known = array_map('strtolower', $apps);
        if (preg_match('~^([A-Za-z][A-Za-z0-9._-]{1,30})(?:/v?([0-9][0-9A-Za-z.+_-]{0,20}))?~', $ua, $m) && in_array(strtolower($m[1]), $known, true)) {
            $app = $m[1] . (isset($m[2]) && $m[2] !== '' ? ' ' . $m[2] : '');
        } else {
            foreach ($apps as $name) {
                if (preg_match('~(?:^|[\s(;/])(' . preg_quote($name, '~') . ')(?=[/ ;)]|$)(?:[/ ]v?([0-9][0-9A-Za-z.+_-]{0,20}))?~i', $ua, $m)) {
                    $app = $m[1] . (isset($m[2]) && $m[2] !== '' ? ' ' . $m[2] : '');
                    break;
                }
            }
        }
        $browser = '';
        if ($app === '' && str_contains($ua, 'Mozilla/')) {
            foreach (['YaBrowser' => 'Yandex Browser', 'SamsungBrowser' => 'Samsung Internet', 'Edg' => 'Edge', 'OPR' => 'Opera',
                'Firefox' => 'Firefox', 'CriOS' => 'Chrome', 'Chrome' => 'Chrome', 'Version' => 'Safari'] as $token => $name) {
                if (preg_match('~' . $token . '/([0-9]+)~', $ua, $m)) { $browser = "$name {$m[1]}"; break; }
            }
        }
        if ($app === '' && $browser === '' && preg_match('~^([A-Za-z][A-Za-z0-9._-]{1,30})/([0-9][0-9A-Za-z.+_-]{0,20})~', $ua, $m)
            && !in_array(strtolower($m[1]), ['mozilla', 'curl', 'wget'], true)) {
            $app = $m[1] . ' ' . $m[2];
        }
        $os = trim((string) ($d['os'] ?? ''));
        $version = trim((string) ($d['osver'] ?? ''));
        if ($os === '') {
            foreach (['~Android[ /]?([0-9][0-9.]*)?~i' => 'Android', '~(?:iPhone|iPad|\biOS\b)(?:.*?OS ([0-9_]+))?~i' => 'iOS',
                '~Windows NT ([0-9.]+)~' => 'Windows', '~Windows~' => 'Windows', '~Mac OS X ([0-9_]+)~' => 'macOS', '~Macintosh|macOS~' => 'macOS',
                '~CFNetwork|Darwin~' => 'iOS/macOS', '~Linux~' => 'Linux'] as $pattern => $name) {
                if (preg_match($pattern, $ua, $m)) {
                    $os = $name;
                    if ($version === '' && !empty($m[1])) $version = str_replace('_', '.', $m[1]);
                    break;
                }
            }
        }
        $os = match (strtolower($os)) { 'ios', 'iphone os', 'ipados' => 'iOS', 'android' => 'Android', 'windows' => 'Windows', 'macos', 'mac os', 'darwin' => 'macOS', 'linux' => 'Linux', default => $os };
        if ($os === 'Windows' && $version === '10.0') $version = '10/11';
        $model = trim((string) ($d['model'] ?? ''));
        $icon = match (true) { in_array($os, ['Android', 'iOS'], true) => '📱', in_array($os, ['Windows', 'macOS', 'Linux'], true) => '💻', $browser !== '' => '🌐', default => '❔' };
        return ['icon' => $icon, 'app' => $app, 'os' => trim($os . ' ' . $version), 'model' => $model, 'browser' => $browser];
    }

    /** "📱 Happ 2.6.1 · iOS 18.1 · iPhone15,2" */
    public function connLogDeviceLabel(array $d): string
    {
        $device = self::connLogDevice($d);
        $parts = array_values(array_filter([$device['app'], $device['browser'] !== '' ? $device['browser'] . $this->t(' (страница подписки в браузере)', ' (subscription page in a browser)') : '',
            $device['os'], $device['model']]));
        return $device['icon'] . ' ' . ($parts ? implode(' · ', array_map(static fn($p) => htmlspecialchars($p, ENT_QUOTES), $parts)) : $this->t('приложение не назвало себя', 'the app did not identify itself'));
    }

    /** Subscription apps of the user, newest first; HWID devices are added when known. */
    public function connLogDevices(array $client): ?array
    {
        try { $rows = $this->storeSubClients((string) ($client['email'] ?? '')); }
        catch (Throwable $error) { $rows = null; }
        $hwid = [];
        try { $hwid = $this->getHwidStorage()[(string) ($client['id'] ?? '')] ?? []; } catch (Throwable $error) {}
        foreach (is_array($hwid) ? $hwid : [] as $info) {
            if (!is_array($info)) continue;
            $device = ['ua' => (string) ($info['user_agent'] ?? ''), 'os' => (string) ($info['device_os'] ?? ''), 'osver' => (string) ($info['os_version'] ?? ''),
                'model' => (string) ($info['device_model'] ?? ''), 'ip' => '', 'first' => (int) ($info['time'] ?? 0), 'last' => (int) ($info['time'] ?? 0), 'count' => 0, 'hwid' => true];
            $same = false;
            foreach ($rows ?? [] as $row) if ([$row['ua'], $row['os'], $row['osver'], $row['model']] === [$device['ua'], $device['os'], $device['osver'], $device['model']]) $same = true;
            if (!$same) $rows[] = $device;
        }
        if ($rows === null) return null;
        usort($rows, static fn($a, $b) => $b['last'] <=> $a['last']);
        return $rows;
    }

    // ── Shaping the history ─────────────────────────────────────────────────

    /** Port 443 is implied; other ports stay visible. */
    public static function connLogHost(string $host): string
    {
        return preg_replace('~:443$~', '', $host) ?? $host;
    }

    /** Site of a host: the registrable domain by a short suffix list; IPs stay as they are. */
    public static function connLogSite(string $host): string
    {
        $name = strtolower(preg_replace('~:\d+$~', '', trim($host, '[]')) ?? $host);
        $name = trim($name, '[].');
        if ($name === '' || filter_var($name, FILTER_VALIDATE_IP)) return $name;
        $labels = explode('.', $name);
        if (count($labels) <= 2) return $name;
        $two = implode('.', array_slice($labels, -2));
        $second = ['co.uk', 'org.uk', 'ac.uk', 'com.au', 'net.au', 'com.br', 'com.tr', 'co.jp', 'ne.jp', 'co.kr', 'com.cn', 'com.hk', 'com.sg', 'com.mx',
            'co.in', 'co.id', 'com.ua', 'com.ru', 'net.ru', 'org.ru', 'msk.ru', 'spb.ru', 'co.za', 'com.ar', 'com.tw', 'com.vn', 'com.my', 'co.il'];
        return in_array($two, $second, true) ? implode('.', array_slice($labels, -3)) : $two;
    }

    /**
     * Rows for the time view: daily history when available, plus hosts known
     * only from the summary (recorded before daily history existed).
     */
    public function connLogTimeline(string $email, array $info): array
    {
        try { $days = $this->storeConnLogDays($email); }
        catch (Throwable $error) { $days = null; }
        $rows = [];
        foreach ($days ?? [] as $row) $rows[] = $row + ['legacy' => false];
        $seen = [];
        foreach ($rows as $row) $seen[$row['host']] = true;
        $summary = [];
        foreach ($info['ips'] ?? [] as $ip => $rec) {
            foreach ($rec['dst'] ?? [] as $host => $d) {
                $host = (string) $host;
                if (isset($seen[$host])) continue;
                $last = (int) ($d['last'] ?? $rec['last'] ?? 0);
                if (!isset($summary[$host]) || $last > $summary[$host]['last']) {
                    $summary[$host] = ['day' => date('Y-m-d', $last), 'host' => $host, 'ip' => (string) $ip, 'first' => $last, 'last' => $last,
                        'count' => (int) ($d['count'] ?? 0) + (int) ($summary[$host]['count'] ?? 0), 'legacy' => true];
                } else {
                    $summary[$host]['count'] += (int) ($d['count'] ?? 0);
                }
            }
        }
        $rows = array_merge($rows, array_values($summary));
        usort($rows, static fn($a, $b) => ($b['last'] <=> $a['last']) ?: strcmp($a['host'], $b['host']));
        return $rows;
    }

    /** Same-day rows of one site merged into one. */
    public static function connLogGroupRows(array $rows): array
    {
        $out = [];
        foreach ($rows as $row) {
            $key = $row['day'] . '|' . self::connLogSite($row['host']) . '|' . (int) $row['legacy'];
            if (!isset($out[$key])) { $out[$key] = $row + ['hosts' => []]; $out[$key]['host'] = self::connLogSite($row['host']); $out[$key]['count'] = 0; }
            $out[$key]['hosts'][$row['host']] = true;
            $out[$key]['first'] = min($out[$key]['first'], $row['first']);
            $out[$key]['last'] = max($out[$key]['last'], $row['last']);
            $out[$key]['count'] += $row['count'];
        }
        $out = array_values($out);
        usort($out, static fn($a, $b) => ($b['last'] <=> $a['last']) ?: strcmp($a['host'], $b['host']));
        return $out;
    }

    /** Hosts over the whole period from the timeline rows (daily history plus summary), most used first. */
    public static function connLogSiteRows(array $rows, bool $group): array
    {
        $out = [];
        foreach ($rows as $row) {
            $key = $group ? self::connLogSite($row['host']) : $row['host'];
            if (!isset($out[$key])) $out[$key] = ['host' => $key, 'first' => $row['first'], 'last' => $row['last'], 'count' => 0, 'hosts' => []];
            $out[$key]['first'] = min($out[$key]['first'], $row['first']);
            $out[$key]['last'] = max($out[$key]['last'], $row['last']);
            $out[$key]['count'] += $row['count'];
            $out[$key]['hosts'][$row['host']] = true;
        }
        $out = array_values($out);
        usort($out, static fn($a, $b) => ($b['count'] <=> $a['count']) ?: ($b['last'] <=> $a['last']));
        return $out;
    }

    /** Hosts of the summary (one source IP or all), most used first. */
    public static function connLogSites(array $info, bool $group): array
    {
        $out = [];
        foreach ($info['ips'] ?? [] as $rec) {
            foreach ($rec['dst'] ?? [] as $host => $d) {
                $key = $group ? self::connLogSite((string) $host) : (string) $host;
                $first = (int) ($d['first'] ?? $d['last'] ?? 0); $last = (int) ($d['last'] ?? 0);
                if (!isset($out[$key])) $out[$key] = ['host' => $key, 'first' => $first, 'last' => $last, 'count' => 0, 'hosts' => []];
                $out[$key]['first'] = min($out[$key]['first'], $first);
                $out[$key]['last'] = max($out[$key]['last'], $last);
                $out[$key]['count'] += (int) ($d['count'] ?? 0);
                $out[$key]['hosts'][(string) $host] = true;
            }
        }
        $out = array_values($out);
        usort($out, static fn($a, $b) => ($b['count'] <=> $a['count']) ?: ($b['last'] <=> $a['last']));
        return $out;
    }

    private function connLogWeekday(int $time): string
    {
        return match ((int) date('N', $time)) {
            1 => $this->t('пн', 'Mon'), 2 => $this->t('вт', 'Tue'), 3 => $this->t('ср', 'Wed'), 4 => $this->t('чт', 'Thu'),
            5 => $this->t('пт', 'Fri'), 6 => $this->t('сб', 'Sat'), default => $this->t('вс', 'Sun'),
        };
    }

    private function connLogAgo(int $time): string
    {
        $diff = max(0, time() - $time);
        if ($diff < 120) return $this->t('только что', 'just now');
        if ($diff < 3600) return intdiv($diff, 60) . $this->t(' мин назад', ' min ago');
        if ($diff < 86400) return intdiv($diff, 3600) . $this->t(' ч назад', ' h ago');
        return intdiv($diff, 86400) . $this->t(' дн назад', ' d ago');
    }

    /** Lines of one view; HTML-escaped. */
    private function connLogLines(string $mode, bool $group, array $client, array $info, array &$geo, int &$budget): array
    {
        $email = (string) $client['email'];
        $lines = [];
        $meta = function (string $host) use (&$geo, &$budget): string {
            $who = $this->dstMeta($host, $geo, $budget);
            return $who !== '' ? '  ' . $who : '';
        };
        if ($mode === 's') {
            foreach (self::connLogSiteRows($this->connLogTimeline($email, $info), $group) as $site) {
                $lines[] = '×' . $site['count'] . '  ' . htmlspecialchars(self::connLogHost($site['host']), ENT_QUOTES)
                    . (count($site['hosts']) > 1 ? $this->t(' (адресов: ', ' (hosts: ') . count($site['hosts']) . ')' : '')
                    . $meta($group ? (string) array_key_first($site['hosts']) : $site['host'])
                    . "\n      " . date('d.m H:i', $site['first']) . ' → ' . date('d.m H:i', $site['last']);
            }
            return $lines;
        }
        if ($mode === 'd') {
            $devices = $this->connLogDevices($client);
            $lines[] = '<b>' . $this->t('Приложения и устройства (по запросам подписки)', 'Apps and devices (from subscription requests)') . '</b>';
            if ($devices === null || $devices === []) {
                $lines[] = $this->t('Подписку ещё не запрашивали после обновления бота, или данных нет.', 'No subscription request recorded since the bot update, or no data.');
            }
            foreach ($devices ?? [] as $device) {
                $lines[] = $this->connLogDeviceLabel($device) . (!empty($device['hwid']) ? ' · HWID' : '')
                    . "\n      " . $this->t('последний запрос ', 'last request ') . date('d.m H:i', $device['last'])
                    . ($device['count'] ? ' · ×' . $device['count'] : '') . ($device['ip'] !== '' ? ' · ' . htmlspecialchars($device['ip'], ENT_QUOTES) : '');
            }
            $lines[] = $this->t('Браузер и модель внутри VPN не видны: их сообщает только приложение при запросе подписки.', 'Browser and model are not visible inside the VPN: only the app reports them when it fetches the subscription.');
            $lines[] = '';
            $lines[] = '<b>' . $this->t('Адреса подключения к VPN', 'VPN source addresses') . '</b>';
            $ips = $info['ips'] ?? [];
            uasort($ips, static fn($a, $b) => ($b['last'] ?? 0) <=> ($a['last'] ?? 0));
            foreach ($ips as $ip => $rec) {
                $fresh = isset($geo[$ip]) && ($geo[$ip]['ts'] ?? 0) > time() - 604800;
                $live = !$fresh && $budget > 0;
                if ($live) $budget--;
                $g = $this->geoLookup((string) $ip, $geo, !$live);
                $flag = $this->countryFlag($g['country'] ?? '');
                $sites = self::connLogSites(['ips' => [$ip => $rec]], true);
                $apps = array_values(array_unique(array_map(fn($d) => self::connLogDevice($d)['app'] ?: self::connLogDevice($d)['browser'],
                    array_filter($devices ?? [], static fn($d) => ($d['ip'] ?? '') === (string) $ip))));
                $lines[] = trim(($flag ? "$flag " : '') . htmlspecialchars((string) $ip, ENT_QUOTES)) . (!empty($g['org']) ? ' — ' . htmlspecialchars((string) $g['org'], ENT_QUOTES) : '')
                    . "\n      " . date('d.m H:i', (int) ($rec['first'] ?? 0)) . ' → ' . date('d.m H:i', (int) ($rec['last'] ?? 0)) . ' · ' . (int) ($rec['count'] ?? 0) . $this->t(' подключений', ' connections')
                    . ($sites ? "\n      " . $this->t('чаще всего: ', 'most used: ') . htmlspecialchars(implode(', ', array_map(static fn($s) => $s['host'], array_slice($sites, 0, 3))), ENT_QUOTES) : '')
                    . (array_filter($apps) ? "\n      " . $this->t('подписку с этого адреса брал: ', 'subscription fetched from here by: ') . htmlspecialchars(implode(', ', array_filter($apps)), ENT_QUOTES) : '');
            }
            return $lines;
        }
        $rows = $this->connLogTimeline($email, $info);
        if ($group) $rows = self::connLogGroupRows($rows);
        $day = null;
        foreach ($rows as $row) {
            if ($row['day'] !== $day) {
                $day = $row['day'];
                $time = strtotime($day . ' 12:00') ?: $row['last'];
                if ($lines) $lines[] = '';
                $lines[] = '📅 <b>' . date('d.m.Y', $time) . ', ' . $this->connLogWeekday($time) . '</b>';
            }
            $span = date('H:i', $row['first']) === date('H:i', $row['last']) ? date('H:i', $row['last']) : date('H:i', $row['first']) . '–' . date('H:i', $row['last']);
            $lines[] = ($row['legacy'] ? date('H:i', $row['last']) : $span) . '  ' . htmlspecialchars(self::connLogHost($row['host']), ENT_QUOTES)
                . ' ×' . $row['count'] . (!empty($row['hosts']) && count($row['hosts']) > 1 ? $this->t(' (адресов: ', ' (hosts: ') . count($row['hosts']) . ')' : '')
                . ($row['legacy'] ? $this->t(' ⏳ до обновления: последнее обращение, всего за период', ' ⏳ before the update: last visit, total for the period') : '')
                . $meta($group ? (string) array_key_first($row['hosts']) : $row['host']);
        }
        return $lines;
    }

    /** Pages of at most CONNLOG_PAGE_CHARS visible characters; lines are never split. */
    public static function connLogPages(array $lines, int $limit = self::CONNLOG_PAGE_CHARS): array
    {
        $pages = [[]]; $size = 0;
        foreach ($lines as $line) {
            $length = mb_strlen(html_entity_decode(strip_tags($line), ENT_QUOTES)) + 1;
            if ($size + $length > $limit && $pages[count($pages) - 1]) { $pages[] = []; $size = 0; }
            $pages[count($pages) - 1][] = $line;
            $size += $length;
        }
        return $pages;
    }

    public function clientLogView(int $i, string $mode = 't', int $page = 0, bool $group = false)
    {
        $client = $this->getXray()['inbounds'][0]['settings']['clients'][$i] ?? null;
        if (empty($client['email'])) {
            $this->update($this->input['chat'], $this->input['message_id'], $this->i18n('no log'), [[['text' => $this->i18n('back'), 'callback_data' => "/userXr $i"]]]);
            return;
        }
        $mode = in_array($mode, ['t', 's', 'd'], true) ? $mode : 't';
        $email = (string) $client['email'];
        $this->trackOnline(); // flush pending access-log lines into history first
        $info = $this->getConnLog()[$email] ?? [];
        $ips = $info['ips'] ?? [];
        $text = ['Menu -> ' . $this->i18n('connection log')];
        $online = false;
        try { $online = isset($this->onlineClients()[$email]); } catch (Throwable $error) {}
        $text[] = '👤 ' . htmlspecialchars($email, ENT_QUOTES) . ($online ? $this->t('   🟢 онлайн сейчас', '   🟢 online now') : '');
        $geo = $this->getGeoCache(); $before = $geo; $budget = self::CONNLOG_GEO_BUDGET;
        if ($ips) {
            $first = min(array_map(static fn($r) => (int) ($r['first'] ?? 0), $ips));
            $last = max(array_map(static fn($r) => (int) ($r['last'] ?? 0), $ips));
            $text[] = $this->t('Период: ', 'Period: ') . date('d.m.Y H:i', $first) . ' — ' . date('d.m.Y H:i', $last);
            $text[] = $this->t('Подключений ', 'Connections ') . array_sum(array_map(static fn($r) => (int) ($r['count'] ?? 0), $ips))
                . $this->t(' · сайтов ', ' · sites ') . count(self::connLogSiteRows($this->connLogTimeline($email, $info), false)) . $this->t(' · адресов (IP) ', ' · source IPs ') . count($ips);
            $text[] = $this->t('Последняя активность: ', 'Last activity: ') . date('d.m H:i', $last) . ' (' . $this->connLogAgo($last) . ')';
        }
        $devices = $this->connLogDevices($client);
        if ($devices) $text[] = $this->t('Устройство: ', 'Device: ') . $this->connLogDeviceLabel($devices[0]);
        $pages = [[]];
        if (!$ips && $mode !== 'd') {
            $text[] = '';
            $text[] = $this->i18n('no log');
        } else {
            $pages = self::connLogPages($this->connLogLines($mode, $group, $client, $info, $geo, $budget));
            $page = max(0, min($page, count($pages) - 1));
            $text[] = '';
            array_push($text, ...$pages[$page]);
        }
        if ($geo !== $before) $this->setGeoCache($geo);
        $g = (int) $group;
        $label = static fn(string $m, string $name) => ($m === $mode ? '• ' : '') . $name;
        $data = [[['text' => $label('t', $this->t('🕒 По времени', '🕒 By time')), 'callback_data' => "/clientLog $i t0 $g"],
            ['text' => $label('s', $this->t('📊 Сайты', '📊 Sites')), 'callback_data' => "/clientLog $i s0 $g"],
            ['text' => $label('d', $this->t('📱 Устройства', '📱 Devices')), 'callback_data' => "/clientLog $i d0 $g"]]];
        if ($mode !== 'd') $data[] = [['text' => $this->t('🧩 Группировать по сайту: ', '🧩 Group by site: ') . ($group ? $this->t('вкл', 'on') : $this->t('выкл', 'off')), 'callback_data' => "/clientLog $i {$mode}0 " . (1 - $g)]];
        if (count($pages) > 1) {
            $data[] = [['text' => '←', 'callback_data' => "/clientLog $i $mode" . ($page > 0 ? $page - 1 : count($pages) - 1) . " $g"],
                ['text' => ($page + 1) . '/' . count($pages), 'callback_data' => "/clientLog $i $mode$page $g"],
                ['text' => '→', 'callback_data' => "/clientLog $i $mode" . ($page < count($pages) - 1 ? $page + 1 : 0) . " $g"]];
        }
        if ($ips) $data[] = [['text' => $this->t('📄 Скачать журнал .txt', '📄 Download log .txt'), 'callback_data' => "/clientLogFile $i"]];
        $row = [['text' => '🔄 ' . $this->i18n('refresh'), 'callback_data' => "/clientLog $i $mode$page $g"]];
        if ($ips) $row[] = ['text' => '🗑 ' . $this->i18n('clear log'), 'callback_data' => "/clientLogClear $i"];
        $data[] = $row;
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => "/userXr $i"]];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $text), $data);
    }

    // ── Text export ─────────────────────────────────────────────────────────

    /** Columns padded by display width (Cyrillic, wide and emoji characters included). */
    public static function connLogTable(array $header, array $rows): string
    {
        $all = array_merge([$header], $rows);
        // A column empty in the header and every row is dropped.
        foreach (array_keys(array_values($header)) as $k) {
            if (array_filter($all, static fn($row) => (string) (array_values($row)[$k] ?? '') !== '') === []) {
                $all = array_map(static function ($row) use ($k) { $row = array_values($row); unset($row[$k]); return array_values($row); }, $all);
                return self::connLogTable($all[0], array_slice($all, 1));
            }
        }
        $widths = [];
        foreach ($all as $row) foreach (array_values($row) as $k => $cell) $widths[$k] = max($widths[$k] ?? 0, mb_strwidth((string) $cell, 'UTF-8'));
        $out = [];
        foreach ($all as $n => $row) {
            $cells = [];
            foreach (array_values($row) as $k => $cell) {
                $cell = (string) $cell;
                $cells[] = $k === count($row) - 1 ? $cell : $cell . str_repeat(' ', $widths[$k] - mb_strwidth($cell, 'UTF-8'));
            }
            $out[] = rtrim(implode('  ', $cells));
            if ($n === 0) $out[] = rtrim(implode('  ', array_map(static fn($w) => str_repeat('-', $w), $widths)));
        }
        return implode("\n", $out);
    }

    /** Full plain-text log in UTF-8; geo labels only from the cache. */
    public function connLogExport(array $client, array $info): string
    {
        $email = (string) $client['email'];
        $clean = static fn($value): string => trim(preg_replace('~[[:cntrl:]]~u', ' ', mb_scrub((string) $value, 'UTF-8')));
        $ips = $info['ips'] ?? [];
        $first = $ips ? min(array_map(static fn($r) => (int) ($r['first'] ?? 0), $ips)) : 0;
        $last = $ips ? max(array_map(static fn($r) => (int) ($r['last'] ?? 0), $ips)) : 0;
        $geo = $this->getGeoCache();
        $owner = function (string $host) use ($geo, $clean): string {
            $name = trim(preg_replace('~:\d+$~', '', $host) ?? $host, '[]');
            $ip = filter_var($name, FILTER_VALIDATE_IP) ? $name : (string) ($geo['host:' . strtolower($name)]['ip'] ?? '');
            $g = $ip !== '' ? ($geo[$ip] ?? []) : [];
            return $clean(trim(($g['country'] ?? '') . ' ' . ($g['org'] ?? '')));
        };
        $out = [];
        $out[] = $this->t('Журнал подключений VPNBot', 'VPNBot connection log');
        $out[] = $this->t('Пользователь: ', 'User: ') . $clean($email);
        $out[] = $this->t('Период: ', 'Period: ') . ($first ? date('d.m.Y H:i', $first) . ' — ' . date('d.m.Y H:i', $last) : '—');
        $out[] = $this->t('Выгружен: ', 'Exported: ') . date('d.m.Y H:i') . $this->t(' (время сервера, ', ' (server time, ') . date_default_timezone_get() . ')';
        $out[] = $this->t('Записи от новых к старым. «до обновления» — адрес известен только по итогам за период (без истории по дням).', 'Newest first. "before update": the host is known only from the period summary (no daily history).');
        $out[] = '';
        $out[] = '== ' . $this->t('Приложения и устройства (по запросам подписки)', 'Apps and devices (from subscription requests)') . ' ==';
        $devices = $this->connLogDevices($client) ?? [];
        $rows = [];
        foreach ($devices as $d) {
            $device = self::connLogDevice($d);
            $rows[] = [date('d.m.Y H:i', $d['last']), $clean($device['app'] ?: $device['browser'] ?: '—'), $clean($device['os'] ?: '—'), $clean($device['model'] ?: '—'),
                $d['count'] ?: '—', $d['ip'] ?: '—', $clean($d['ua'] ?: '—')];
        }
        $out[] = $rows ? self::connLogTable([$this->t('последний запрос', 'last request'), $this->t('приложение', 'app'), $this->t('ОС', 'OS'), $this->t('модель', 'model'),
            $this->t('запросов', 'requests'), 'IP', 'User-Agent'], $rows) : $this->t('нет данных', 'no data');
        $out[] = '';
        $out[] = '== ' . $this->t('Хронология по дням', 'Daily timeline') . ' ==';
        $rows = [];
        foreach ($this->connLogTimeline($email, $info) as $row) {
            $rows[] = [date('d.m.Y', $row['last']), $row['legacy'] ? '—' : date('H:i:s', $row['first']), date('H:i:s', $row['last']), $row['count'],
                $clean($row['host']), $clean($row['ip']), $owner($row['host']) ?: '—', $row['legacy'] ? $this->t('до обновления', 'before update') : ''];
        }
        $out[] = $rows ? self::connLogTable([$this->t('дата', 'date'), $this->t('первое', 'first'), $this->t('последнее', 'last'), $this->t('обращений', 'hits'),
            $this->t('адрес', 'host'), $this->t('IP устройства', 'device IP'), $this->t('владелец адреса', 'host owner'), ''], $rows) : $this->t('нет данных', 'no data');
        $out[] = '';
        $out[] = '== ' . $this->t('Сайты за период', 'Sites over the period') . ' ==';
        $rows = [];
        foreach (self::connLogSiteRows($this->connLogTimeline($email, $info), false) as $site) {
            $rows[] = [$site['count'], date('d.m.Y H:i', $site['first']), date('d.m.Y H:i', $site['last']), $clean($site['host']), $owner($site['host']) ?: '—'];
        }
        $out[] = $rows ? self::connLogTable([$this->t('обращений', 'hits'), $this->t('первое', 'first'), $this->t('последнее', 'last'), $this->t('адрес', 'host'),
            $this->t('владелец адреса', 'host owner')], $rows) : $this->t('нет данных', 'no data');
        $out[] = '';
        $out[] = '== ' . $this->t('Адреса подключения к VPN', 'VPN source addresses') . ' ==';
        uasort($ips, static fn($a, $b) => ($b['last'] ?? 0) <=> ($a['last'] ?? 0));
        $rows = [];
        foreach ($ips as $ip => $rec) {
            $g = $geo[(string) $ip] ?? [];
            $rows[] = [$clean($ip), date('d.m.Y H:i', (int) ($rec['first'] ?? 0)), date('d.m.Y H:i', (int) ($rec['last'] ?? 0)), (int) ($rec['count'] ?? 0),
                $clean(trim(($g['country'] ?? '') . ' ' . ($g['org'] ?? ''))) ?: '—'];
        }
        $out[] = $rows ? self::connLogTable(['IP', $this->t('первое', 'first'), $this->t('последнее', 'last'), $this->t('подключений', 'connections'),
            $this->t('страна и провайдер', 'country and ISP')], $rows) : $this->t('нет данных', 'no data');
        return implode("\n", $out) . "\n";
    }

    public function clientLogFile(int $i): void
    {
        $client = $this->getXray()['inbounds'][0]['settings']['clients'][$i] ?? null;
        if (empty($client['email'])) { $this->clientLogView($i); return; }
        $this->trackOnline();
        $info = $this->getConnLog()[(string) $client['email']] ?? [];
        if (empty($info['ips'])) { $this->clientLogView($i); return; }
        $name = 'connlog-' . (preg_replace('~[^A-Za-z0-9_.-]+~', '_', (string) $client['email']) ?: 'user') . '-' . date('Ymd-Hi') . '.txt';
        $sent = $this->sendFile($this->input['chat'], new CURLStringFile($this->connLogExport($client, $info), $name, 'text/plain; charset=utf-8'),
            $this->t('Журнал подключений: ', 'Connection log: ') . htmlspecialchars((string) $client['email'], ENT_QUOTES));
        if (!empty($this->input['callback_id'])) $this->answer($this->input['callback_id'], empty($sent['ok']) ? $this->t('Файл не отправлен', 'File not sent') : '📄');
    }
}
