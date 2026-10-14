<?php

/**
 * Recoverable display copy; authentication continues to use password_hash.
 *
 * Ключ шифрования выводится из токена бота (app/config.php), а не лежит файлом
 * рядом с шифротекстом: копия в /config/panel — и в резервной копии — без
 * config.php не раскрывает пароль. Прежние установки хранили ключ в
 * password-display.key; такие записи (без префикса v2:) читаются им и
 * переписываются новым ключом, после чего файл ключа удаляется (settle()).
 * Смена токена бота делает копию нечитаемой — как и раньше при её утрате,
 * она появится снова после входа в панель или смены пароля.
 */
final class PanelPasswordVault
{
    private const PREFIX = 'v2:';

    private static function privateFile(string $path, int $max): ?string
    {
        if (is_link($path) || !is_file($path) || (fileperms($path) & 0077) || filesize($path) > $max) return null;
        $data = file_get_contents($path);
        return is_string($data) ? $data : null;
    }

    private static function key(string $secret): ?string
    {
        return $secret === '' ? null : hash_hkdf('sha256', $secret, 32, 'vpnbot panel password display v2');
    }

    private static function decrypt(string $record, string $key, string $hash): ?string
    {
        $data = base64_decode($record, true);
        if (!is_string($data) || strlen($data) < 36 || strlen($data) > 100) return null;
        $plain = openssl_decrypt(substr($data, 28), 'aes-256-gcm', $key, OPENSSL_RAW_DATA, substr($data, 0, 12), substr($data, 12, 16), $hash);
        return is_string($plain) && password_verify($plain, $hash) ? $plain : null;
    }

    /** Под блокировкой читает записи, даёт их изменить и записывает обратно. */
    private static function update(string $directory, callable $fn): bool
    {
        if (is_link($directory) || (!is_dir($directory) && !@mkdir($directory, 0700, true))) return false;
        if (!@chmod($directory, 0700) || is_link($directory . '/password-display.lock')) return false;
        $lock = @fopen($directory . '/password-display.lock', 'c');
        if (!$lock) return false;
        @chmod($directory . '/password-display.lock', 0600);
        try {
            if (!flock($lock, LOCK_EX)) return false;
            $path = $directory . '/password-display.json';
            if (is_link($path)) return false;
            $old = self::privateFile($path, 16384);
            $records = $old === null ? [] : json_decode($old, true, 8);
            if (!is_array($records)) $records = [];
            $records = $fn($records);
            if (!is_array($records)) return false;
            ManagedProtocol::writeJson($path, $records);
            return true;
        } catch (Throwable $e) {
            return false;
        } finally { flock($lock, LOCK_UN); fclose($lock); }
    }

    public static function remember(string $directory, string $plain, string $hash, string $secret): bool
    {
        $key = self::key($secret);
        if ($key === null || strlen($plain) < 8 || strlen($plain) > 72 || !password_verify($plain, $hash)) return false;
        $nonce = random_bytes(12); $tag = '';
        $ciphertext = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, $hash);
        if ($ciphertext === false) return false;
        return self::update($directory, function (array $records) use ($hash, $nonce, $tag, $ciphertext) {
            $id = hash('sha256', $hash); unset($records[$id]);
            $records[$id] = self::PREFIX . base64_encode($nonce . $tag . $ciphertext);
            // Retain previous hashes so a failed pac.json write does not lose the old display copy.
            return array_slice($records, -8, null, true);
        });
    }

    /**
     * Вызывается, когда $hash точно действующий (вход, записанный pac.json,
     * успешный просмотр): прежние записи, зашифрованные файловым ключом,
     * больше не нужны — удаляем их вместе с ключом и стартовым паролем.
     */
    public static function settle(string $directory, string $hash): void
    {
        if ($hash === '' || is_link($directory)) return;
        $id = hash('sha256', $hash);
        $ok = self::update($directory, function (array $records) use ($id) {
            if (!str_starts_with((string) ($records[$id] ?? ''), self::PREFIX)) return null;
            return array_filter($records, fn ($r) => is_string($r) && str_starts_with($r, self::PREFIX));
        });
        if ($ok) {
            foreach (['password-display.key', 'initial_password.txt'] as $name) {
                if (!is_link("$directory/$name")) @unlink("$directory/$name");
            }
        }
    }

    public static function reveal(string $directory, string $hash, string $secret): ?string
    {
        $key = self::key($secret);
        if ($hash === '' || $key === null || is_link($directory)) return null;
        try {
            $json = self::privateFile($directory . '/password-display.json', 16384);
            $records = $json === null ? [] : json_decode($json, true, 8, JSON_THROW_ON_ERROR);
            $record = is_array($records) ? ($records[hash('sha256', $hash)] ?? null) : null;
            if (is_string($record) && str_starts_with($record, self::PREFIX)) {
                return self::decrypt(substr($record, strlen(self::PREFIX)), $key, $hash);
            }
            $plain = null;
            // Запись прежнего формата: ключ лежал файлом рядом.
            $legacy = self::privateFile($directory . '/password-display.key', 32);
            if (is_string($record) && $legacy !== null && strlen($legacy) === 32) {
                $plain = self::decrypt($record, $legacy, $hash);
            }
            // Existing installs may still have the bootstrap password. Never display a stale one.
            if ($plain === null && ($initial = self::privateFile($directory . '/initial_password.txt', 128)) !== null
                && password_verify(rtrim($initial, "\r\n"), $hash)) {
                $plain = rtrim($initial, "\r\n");
            }
            if ($plain !== null && self::remember($directory, $plain, $hash, $secret)) {
                self::settle($directory, $hash);
            }
            return $plain;
        } catch (Throwable $e) {}
        return null;
    }
}
