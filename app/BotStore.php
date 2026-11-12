<?php

// Хранилище SQLite для данных, которые раньше переписывались целиком на каждой
// записи: устройства HWID (каждая выдача подписки при включённом лимите) и
// журнал подключений Xray (каждый проход cron). Одна база /config/vpnbot.sqlite
// (0600), WAL: php и service пишут в неё одновременно, читатели не ждут.
//
// Без драйвера pdo_sqlite (старый образ php во время обновления, откат) бот
// работает с прежними hwid.json и connlog.json. Выбор детерминирован: php и
// service запускаются из одного образа, раздвоения данных между процессами нет.
// Первое открытие базы один раз переносит JSON (отметка в meta); сами файлы
// остаются как были — образ без SQLite после отката прочитает их состояние на
// момент переноса.
trait BotStore
{
    public const CONNLOG_DAY_HOSTS = 300;
    private ?PDO $storePdo = null;
    private bool $storeOpened = false;

    // Рядом с hwid.json: тесты, подставляющие свой путь, не трогают /config.
    public function storeFile(): string
    {
        return dirname($this->hwid) . '/vpnbot.sqlite';
    }

    public function store(): ?PDO
    {
        if ($this->storeOpened) return $this->storePdo;
        if (!extension_loaded('pdo_sqlite') || !is_dir(dirname($this->storeFile()))) {
            $this->storeOpened = true;
            return null;
        }
        $this->storeOpened = true;
        $umask = umask(077);
        try {
            $pdo = new PDO('sqlite:' . $this->storeFile(), null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 5]);
            $pdo->exec('PRAGMA busy_timeout = 5000');
            $pdo->exec('PRAGMA journal_mode = WAL');
            $pdo->exec('PRAGMA synchronous = NORMAL');
            $pdo->exec('CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)');
            $pdo->exec('CREATE TABLE IF NOT EXISTS hwid (uid TEXT NOT NULL, hwid TEXT NOT NULL, info TEXT NOT NULL, UNIQUE (uid, hwid))');
            $pdo->exec('CREATE TABLE IF NOT EXISTS connlog_ip (email TEXT NOT NULL, ip TEXT NOT NULL, first INTEGER NOT NULL, last INTEGER NOT NULL, count INTEGER NOT NULL, UNIQUE (email, ip))');
            $pdo->exec('CREATE TABLE IF NOT EXISTS connlog_dst (email TEXT NOT NULL, ip TEXT NOT NULL, host TEXT NOT NULL, first INTEGER NOT NULL, last INTEGER NOT NULL, count INTEGER NOT NULL, UNIQUE (email, ip, host))');
            // Приложения, которые скачивают подписку пользователя: User-Agent и
            // заголовки устройства (их шлют Happ, Hiddify и др.), адрес и время.
            $pdo->exec('CREATE TABLE IF NOT EXISTS sub_client (email TEXT NOT NULL, key TEXT NOT NULL, ua TEXT NOT NULL, os TEXT NOT NULL, osver TEXT NOT NULL, model TEXT NOT NULL, ip TEXT NOT NULL, first INTEGER NOT NULL, last INTEGER NOT NULL, count INTEGER NOT NULL, UNIQUE (email, key))');
            // По дням: какие адреса клиент открывал в каждый день (первое и
            // последнее обращение за день, число, адрес устройства). Итоги
            // connlog_dst не дают хронологии, а журнал читают по датам.
            $pdo->exec('CREATE TABLE IF NOT EXISTS connlog_day (email TEXT NOT NULL, day TEXT NOT NULL, host TEXT NOT NULL, ip TEXT NOT NULL, first INTEGER NOT NULL, last INTEGER NOT NULL, count INTEGER NOT NULL, UNIQUE (email, day, host))');
            @chmod($this->storeFile(), 0600);
            $this->storePdo = $pdo;
            $this->storeImport('hwid', $this->hwid, fn(array $data) => $this->storeHwidReplace($data));
            $this->storeImport('connlog', $this->connLogFile(), fn(array $data) => $this->storeConnLogReplace($data));
        } catch (Throwable $e) {
            // Драйвер есть, а база не открывается: JSON в этом случае был бы
            // раздвоением данных, поэтому ошибка видна вызывающему коду.
            // Не кешируем отказ: следующий вызов пробует открыть базу снова.
            error_log('store: ' . $e->getMessage());
            $this->storePdo = null;
            $this->storeOpened = false;
            throw new RuntimeException('SQLite store unavailable', 0, $e);
        } finally {
            umask($umask);
        }
        return $this->storePdo;
    }

    public function storeTransaction(callable $fn)
    {
        $pdo = $this->store();
        // BEGIN IMMEDIATE: запись берёт блокировку сразу, проверка лимита и
        // вставка устройства не разъезжаются между параллельными запросами.
        $pdo->exec('BEGIN IMMEDIATE');
        try {
            $result = $fn($pdo);
            $pdo->exec('COMMIT');
            return $result;
        } catch (Throwable $e) {
            $pdo->exec('ROLLBACK');
            throw $e;
        }
    }

    private function storeImport(string $name, string $file, callable $replace): void
    {
        $this->storeTransaction(function (PDO $pdo) use ($name, $file, $replace) {
            $done = $pdo->prepare('SELECT 1 FROM meta WHERE key = ?');
            $done->execute(["imported:$name"]);
            if ($done->fetchColumn()) return;
            // Повреждённый или недоступный JSON нельзя отмечать как успешно
            // импортированный: после ремонта источника перенос должен повториться.
            $data = is_file($file) ? json_decode((string) file_get_contents($file), true, 512, JSON_THROW_ON_ERROR) : [];
            if (!is_array($data)) throw new RuntimeException('Invalid legacy store: ' . $name);
            $replace($data);
            $pdo->prepare('INSERT INTO meta (key, value) VALUES (?, ?)')->execute(["imported:$name", (string) time()]);
        });
    }

    // ── HWID ────────────────────────────────────────────────────────────────

    private function storeHwidRows(?string $uid = null): array
    {
        $sql = 'SELECT uid, hwid, info FROM hwid' . ($uid === null ? '' : ' WHERE uid = ?') . ' ORDER BY rowid';
        $query = $this->store()->prepare($sql);
        $query->execute($uid === null ? [] : [$uid]);
        $result = [];
        foreach ($query->fetchAll(PDO::FETCH_NUM) as [$user, $hwid, $info]) {
            $result[$user][$hwid] = json_decode($info, true) ?: [];
        }
        return $result;
    }

    private function storeHwidReplace(array $storage): void
    {
        $pdo = $this->store();
        $pdo->exec('DELETE FROM hwid');
        $insert = $pdo->prepare('INSERT INTO hwid (uid, hwid, info) VALUES (?, ?, ?)');
        foreach ($storage as $uid => $devices) {
            foreach (is_array($devices) ? $devices : [] as $hwid => $info) {
                $insert->execute([(string) $uid, (string) $hwid, json_encode(is_array($info) ? $info : [], JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE)]);
            }
        }
    }

    // Проверка лимита и запись устройства одной транзакцией.
    public function hwidRegister(string $uid, string $hwid, int $limit, array $info): bool
    {
        if (!$this->store()) {
            return $this->hwidUpdate(function (array &$storage) use ($uid, $hwid, $limit, $info) {
                $devices = $storage[$uid] ?? [];
                if (!isset($devices[$hwid]) && count($devices) >= $limit) return false;
                $storage[$uid][$hwid] = $info;
                return true;
            });
        }
        return $this->storeTransaction(function (PDO $pdo) use ($uid, $hwid, $limit, $info) {
            $known = $pdo->prepare('SELECT 1 FROM hwid WHERE uid = ? AND hwid = ?');
            $known->execute([$uid, $hwid]);
            if (!$known->fetchColumn()) {
                $count = $pdo->prepare('SELECT COUNT(*) FROM hwid WHERE uid = ?');
                $count->execute([$uid]);
                if ((int) $count->fetchColumn() >= $limit) return false;
            }
            $pdo->prepare('INSERT INTO hwid (uid, hwid, info) VALUES (?, ?, ?) ON CONFLICT (uid, hwid) DO UPDATE SET info = excluded.info')
                ->execute([$uid, $hwid, json_encode($info, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE)]);
            return true;
        });
    }

    // ── Журнал подключений ──────────────────────────────────────────────────

    public function connLogFile(): string
    {
        return dirname($this->hwid) . '/connlog.json';
    }

    private function storeConnLogReplace(array $log): void
    {
        $pdo = $this->store();
        $pdo->exec('DELETE FROM connlog_dst');
        $pdo->exec('DELETE FROM connlog_ip');
        $ip = $pdo->prepare('INSERT INTO connlog_ip (email, ip, first, last, count) VALUES (?, ?, ?, ?, ?)');
        $dst = $pdo->prepare('INSERT INTO connlog_dst (email, ip, host, first, last, count) VALUES (?, ?, ?, ?, ?, ?)');
        foreach ($log as $email => $client) {
            foreach (is_array($client['ips'] ?? null) ? $client['ips'] : [] as $address => $rec) {
                $ip->execute([(string) $email, (string) $address, (int) ($rec['first'] ?? 0), (int) ($rec['last'] ?? 0), (int) ($rec['count'] ?? 0)]);
                foreach (is_array($rec['dst'] ?? null) ? $rec['dst'] : [] as $host => $d) {
                    $dst->execute([(string) $email, (string) $address, (string) $host, (int) ($d['first'] ?? 0), (int) ($d['last'] ?? 0), (int) ($d['count'] ?? 0)]);
                }
            }
        }
        $this->storeConnLogPrune($pdo);
        // A cleared client (or a cleared log) loses its daily history at once.
        $pdo->exec('DELETE FROM connlog_day WHERE email NOT IN (SELECT email FROM connlog_ip)');
    }

    private function storeConnLogRead(): array
    {
        $pdo = $this->store();
        $log = [];
        foreach ($pdo->query('SELECT email, ip, first, last, count FROM connlog_ip ORDER BY rowid')->fetchAll(PDO::FETCH_NUM) as [$email, $ip, $first, $last, $count]) {
            $log[$email]['ips'][$ip] = ['first' => (int) $first, 'last' => (int) $last, 'count' => (int) $count, 'dst' => []];
            $log[$email]['last'] = max((int) $last, $log[$email]['last'] ?? 0);
        }
        foreach ($pdo->query('SELECT email, ip, host, first, last, count FROM connlog_dst ORDER BY rowid')->fetchAll(PDO::FETCH_NUM) as [$email, $ip, $host, $first, $last, $count]) {
            if (!isset($log[$email]['ips'][$ip])) continue;
            $log[$email]['ips'][$ip]['dst'][$host] = ['first' => (int) $first, 'last' => (int) $last, 'count' => (int) $count];
        }
        return $log;
    }

    private function storeConnLogRecord(array $events): void
    {
        $this->storeTransaction(function (PDO $pdo) use ($events) {
            $ip = $pdo->prepare('INSERT INTO connlog_ip (email, ip, first, last, count) VALUES (?, ?, ?, ?, 1)
                ON CONFLICT (email, ip) DO UPDATE SET last = excluded.last, count = count + 1');
            $dst = $pdo->prepare('INSERT INTO connlog_dst (email, ip, host, first, last, count) VALUES (?, ?, ?, ?, ?, 1)
                ON CONFLICT (email, ip, host) DO UPDATE SET last = excluded.last, count = count + 1');
            $day = $pdo->prepare('INSERT INTO connlog_day (email, day, host, ip, first, last, count) VALUES (?, ?, ?, ?, ?, ?, 1)
                ON CONFLICT (email, day, host) DO UPDATE SET first = MIN(first, excluded.first), last = MAX(last, excluded.last),
                ip = CASE WHEN excluded.last >= last THEN excluded.ip ELSE ip END, count = count + 1');
            foreach ($events as $e) {
                $ip->execute([(string) $e['email'], (string) $e['ip'], (int) $e['ts'], (int) $e['ts']]);
                if (!empty($e['dst'])) {
                    $dst->execute([(string) $e['email'], (string) $e['ip'], (string) $e['dst'], (int) $e['ts'], (int) $e['ts']]);
                    $day->execute([(string) $e['email'], date('Y-m-d', (int) $e['ts']), (string) $e['dst'], (string) $e['ip'], (int) $e['ts'], (int) $e['ts']]);
                }
            }
            $this->storeConnLogPrune($pdo);
        });
    }

    // Те же пределы, что у JSON: 30 дней, 50 назначений на адрес (по числу,
    // затем по свежести), 50 адресов на клиента и 200 последних клиентов.
    private function storeConnLogPrune(PDO $pdo): void
    {
        $ttl = time() - 2592000;
        $pdo->prepare('DELETE FROM connlog_dst WHERE last < ?')->execute([$ttl]);
        $pdo->prepare('DELETE FROM connlog_ip WHERE last < ?')->execute([$ttl]);
        $pdo->exec('DELETE FROM connlog_dst WHERE rowid IN (SELECT rowid FROM (SELECT rowid, ROW_NUMBER() OVER
            (PARTITION BY email, ip ORDER BY count DESC, last DESC) AS n FROM connlog_dst) WHERE n > 50)');
        $pdo->exec('DELETE FROM connlog_ip WHERE rowid IN (SELECT rowid FROM (SELECT rowid, ROW_NUMBER() OVER
            (PARTITION BY email ORDER BY last DESC) AS n FROM connlog_ip) WHERE n > 50)');
        $pdo->exec('DELETE FROM connlog_ip WHERE email NOT IN (SELECT email FROM connlog_ip GROUP BY email ORDER BY MAX(last) DESC LIMIT 200)');
        $pdo->exec('DELETE FROM connlog_dst WHERE NOT EXISTS (SELECT 1 FROM connlog_ip i WHERE i.email = connlog_dst.email AND i.ip = connlog_dst.ip)');
        // История по дням: тот же срок и те же клиенты; не больше
        // CONNLOG_DAY_HOSTS адресов за день (по числу, затем по свежести).
        // Окно по всей таблице дорогое: не чаще раза в 10 минут.
        $pdo->prepare('DELETE FROM connlog_day WHERE last < ?')->execute([$ttl]);
        $mark = $pdo->query("SELECT value FROM meta WHERE key = 'connlog_day_prune'")->fetchColumn();
        if ($mark === false || (int) $mark < time() - 600) {
            $pdo->exec('DELETE FROM connlog_day WHERE rowid IN (SELECT rowid FROM (SELECT rowid, ROW_NUMBER() OVER
                (PARTITION BY email, day ORDER BY count DESC, last DESC) AS n FROM connlog_day) WHERE n > ' . self::CONNLOG_DAY_HOSTS . ')');
            $pdo->exec('DELETE FROM connlog_day WHERE email NOT IN (SELECT email FROM connlog_ip)');
            $pdo->prepare("INSERT INTO meta (key, value) VALUES ('connlog_day_prune', ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value")->execute([(string) time()]);
        }
    }

    /** One subscription request: the app and device it came from. */
    public function storeSubClientRecord(string $email, array $device, string $ip): void
    {
        $pdo = $this->store();
        if ($pdo === null) return;
        $fields = [$device['ua'] ?? '', $device['os'] ?? '', $device['osver'] ?? '', $device['model'] ?? ''];
        $key = substr(hash('sha256', implode("\0", $fields)), 0, 16);
        $now = time();
        $this->storeTransaction(function (PDO $pdo) use ($email, $key, $fields, $ip, $now) {
            $pdo->prepare('INSERT INTO sub_client (email, key, ua, os, osver, model, ip, first, last, count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                ON CONFLICT (email, key) DO UPDATE SET ip = excluded.ip, last = excluded.last, count = count + 1')
                ->execute([$email, $key, ...$fields, $ip, $now, $now]);
            $pdo->prepare('DELETE FROM sub_client WHERE last < ?')->execute([$now - 2592000]);
            $pdo->prepare('DELETE FROM sub_client WHERE email = ? AND rowid NOT IN (SELECT rowid FROM sub_client WHERE email = ? ORDER BY last DESC LIMIT 10)')
                ->execute([$email, $email]);
        });
    }

    /** Apps that fetched this user's subscription, newest first; null without SQLite. */
    public function storeSubClients(string $email): ?array
    {
        $pdo = $this->store();
        if ($pdo === null) return null;
        $rows = $pdo->prepare('SELECT ua, os, osver, model, ip, first, last, count FROM sub_client WHERE email = ? ORDER BY last DESC');
        $rows->execute([$email]);
        return array_map(static fn($r) => ['ua' => (string) $r[0], 'os' => (string) $r[1], 'osver' => (string) $r[2], 'model' => (string) $r[3],
            'ip' => (string) $r[4], 'first' => (int) $r[5], 'last' => (int) $r[6], 'count' => (int) $r[7]], $rows->fetchAll(PDO::FETCH_NUM));
    }

    /** Daily history of one client, newest first; null without SQLite. */
    public function storeConnLogDays(string $email): ?array
    {
        $pdo = $this->store();
        if ($pdo === null) return null;
        $rows = $pdo->prepare('SELECT day, host, ip, first, last, count FROM connlog_day WHERE email = ? ORDER BY last DESC LIMIT 5000');
        $rows->execute([$email]);
        return array_map(static fn($r) => ['day' => (string) $r[0], 'host' => (string) $r[1], 'ip' => (string) $r[2],
            'first' => (int) $r[3], 'last' => (int) $r[4], 'count' => (int) $r[5]], $rows->fetchAll(PDO::FETCH_NUM));
    }
}
