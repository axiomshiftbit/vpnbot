<?php

require_once __DIR__ . '/ManagedProtocol.php';

/** PHP owns credentials; the Hysteria supervisor owns runtime counters. */
final class HysteriaUsers
{
    public function __construct(public readonly string $root = '/config/hysteria') {}

    public function read(): array
    {
        $path = $this->root . '/users.json';
        $state = is_file($path) ? ManagedProtocol::readJson($path)
            : ['schema' => 1, 'protocol' => 'hysteria2', 'revision' => 0, 'users' => []];
        self::validate($state);
        return $state;
    }

    public static function validate(array $state): void
    {
        if (($state['schema'] ?? null) !== 1 || ($state['protocol'] ?? '') !== 'hysteria2'
            || !is_int($state['revision'] ?? null) || $state['revision'] < 0
            || !is_array($state['users'] ?? null) || count($state['users']) > 1000) {
            throw new InvalidArgumentException('Повреждено состояние пользователей Hysteria');
        }
        $names = [];
        foreach ($state['users'] as $id => $user) {
            if (!preg_match('/\A[a-f0-9]{16}\z/D', (string) $id) || !is_array($user)
                || !is_string($user['name'] ?? null) || trim($user['name']) === '' || mb_strlen($user['name']) > 60
                || preg_match('/[\x00-\x1f\x7f]/', $user['name']) || isset($names[$user['name']])
                || !is_bool($user['enabled'] ?? null)
                || !is_string($user['password'] ?? null) || !preg_match('/\A[A-Za-z0-9_-]{43}\z/D', $user['password'])
                || !is_string($user['reset'] ?? null) || !preg_match('/\A[a-f0-9]{16}\z/D', $user['reset'])) {
                throw new InvalidArgumentException('Неверные реквизиты пользователя Hysteria');
            }
            foreach (['expires', 'quota'] as $key) {
                if (!array_key_exists($key, $user) || ($user[$key] !== null && (!is_int($user[$key]) || $user[$key] < 1))) {
                    throw new InvalidArgumentException('Неверный срок или квота Hysteria');
                }
            }
            $names[$user['name']] = true;
            AccessPolicy::validate($user);
        }
        if (isset($state['restore_usage'])) {
            $restore = $state['restore_usage'];
            if (!is_array($restore) || !is_string($restore['id'] ?? null)
                || !preg_match('/\A[a-f0-9]{32}\z/D', $restore['id'])) throw new InvalidArgumentException('Неверный снимок расхода Hysteria');
            self::validateUsage($restore);
        }
    }

    public static function validateUsage(array $usage): void
    {
        if (!is_array($usage['users'] ?? null)) throw new InvalidArgumentException('Повреждены счётчики Hysteria');
        foreach ($usage['users'] as $id => $row) {
            if (!preg_match('/\A[a-f0-9]{16}\z/D', (string) $id) || !is_array($row)
                || !is_string($row['reset'] ?? null) || !preg_match('/\A[a-f0-9]{16}\z/D', $row['reset'])) {
                throw new InvalidArgumentException('Повреждены счётчики Hysteria');
            }
            foreach (['upload', 'download'] as $key) {
                if (!is_int($row[$key] ?? null) || $row[$key] < 0) throw new InvalidArgumentException('Повреждены счётчики Hysteria');
            }
        }
    }

    private function locked(callable $action)
    {
        if (!is_dir($this->root) && !@mkdir($this->root, 0700, true) && !is_dir($this->root)) {
            throw new RuntimeException('Не удалось создать каталог Hysteria');
        }
        $old = umask(0077);
        $lock = @fopen($this->root . '/users.lock', 'c');
        umask($old);
        if (!$lock) throw new RuntimeException('Не удалось открыть блокировку Hysteria');
        try {
            if (!flock($lock, LOCK_EX)) throw new RuntimeException('Пользователи Hysteria заняты');
            return $action();
        } finally { flock($lock, LOCK_UN); fclose($lock); }
    }

    public function change(callable $edit): array
    {
        return $this->locked(function () use ($edit) {
            $state = $this->read();
            if ($edit($state) === false) return $state;
            $state['revision']++;
            self::validate($state);
            $encoded = $state;
            if (isset($encoded['restore_usage'])) $encoded['restore_usage']['users'] = (object) $encoded['restore_usage']['users'];
            ManagedProtocol::writeJson($this->root . '/users.json', $encoded);
            return $state;
        });
    }

    public function add(string $name): string
    {
        $id = bin2hex(random_bytes(8));
        $this->change(static function (&$state) use ($id, $name) {
            $state['users'][$id] = ['name' => trim($name), 'enabled' => true,
                'password' => self::password(), 'expires' => null, 'quota' => null,
                'reset' => bin2hex(random_bytes(8))];
        });
        return $id;
    }

    public static function password(): string { return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '='); }

    public function edit(string $id, string $action, $value = null): void
    {
        $this->change(static function (&$state) use ($id, $action, $value) {
            if (!isset($state['users'][$id])) throw new InvalidArgumentException('Пользователь Hysteria удалён');
            $user = &$state['users'][$id];
            switch ($action) {
                case 'toggle': $user['enabled'] = !$user['enabled']; break;
                case 'delete': unset($state['users'][$id]); break;
                case 'rotate': $user['password'] = self::password(); break;
                case 'reset': $user['reset'] = bin2hex(random_bytes(8)); break;
                case 'name': case 'expires': case 'quota': $user[$action] = $value; break;
                default: throw new InvalidArgumentException('Неизвестное действие Hysteria');
            }
        });
    }

    public function usage(): array
    {
        $path = $this->root . '/runtime/usage.json';
        if (!is_file($path)) {
            if ($this->read()['users']) throw new RuntimeException('Статистика Hysteria пока недоступна');
            return ['users' => []];
        }
        $usage = ManagedProtocol::readJson($path);
        self::validateUsage($usage);
        return $usage;
    }

    public function status(): array
    {
        $path = $this->root . '/runtime/status.json';
        return is_file($path) ? ManagedProtocol::readJson($path) : [];
    }

    public function snapshot(): array
    {
        return $this->locked(function () {
            $state = $this->read();
            $pending = $state['restore_usage'] ?? null;
            $usage = $pending && !is_file($this->root . '/runtime/usage.json') ? [] : $this->usage();
            if ($pending && ($usage['restored'] ?? '') !== $pending['id']) $usage = ['users' => $pending['users']];
            foreach ($state['users'] as $id => $user) {
                if (($usage['users'][$id]['reset'] ?? null) !== $user['reset']) {
                    throw new RuntimeException('Дождитесь применения счётчиков Hysteria перед резервным копированием');
                }
            }
            unset($state['restore_usage']);
            return ['state' => $state, 'usage' => $usage];
        });
    }

    public static function validateSnapshot(array $snapshot): array
    {
        if (!is_array($snapshot['state'] ?? null) || !is_array($snapshot['usage'] ?? null)) {
            throw new InvalidArgumentException('Неполный снимок Hysteria');
        }
        self::validate($snapshot['state']);
        self::validateUsage($snapshot['usage']);
        $counters = [];
        foreach ($snapshot['state']['users'] as $id => $user) {
            $row = $snapshot['usage']['users'][$id] ?? null;
            if ($row === null || $row['reset'] !== $user['reset']) {
                throw new InvalidArgumentException('Снимок Hysteria не содержит расход текущего периода');
            }
            $counters[$id] = array_intersect_key($row, array_flip(['upload', 'download', 'reset']));
        }
        return $counters;
    }

    public function restore(array $snapshot): void
    {
        $counters = self::validateSnapshot($snapshot);
        $this->change(static function (&$state) use ($snapshot, $counters) {
            $state['users'] = $snapshot['state']['users'];
            $state['restore_usage'] = ['id' => bin2hex(random_bytes(16)), 'users' => $counters];
        });
    }
}
