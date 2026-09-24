<?php

/** Recoverable display copy; authentication continues to use password_hash. */
final class PanelPasswordVault
{
    private static function privateFile(string $path, int $max): ?string
    {
        if (is_link($path) || !is_file($path) || (fileperms($path) & 0077) || filesize($path) > $max) return null;
        $data = file_get_contents($path);
        return is_string($data) ? $data : null;
    }

    public static function remember(string $directory, string $plain, string $hash): bool
    {
        if (strlen($plain) < 8 || strlen($plain) > 72 || !password_verify($plain, $hash)) return false;
        if (is_link($directory) || (!is_dir($directory) && !@mkdir($directory, 0700, true))) return false;
        if (!@chmod($directory, 0700) || is_link($directory . '/password-display.lock')) return false;
        $lock = @fopen($directory . '/password-display.lock', 'c');
        if (!$lock) return false;
        @chmod($directory . '/password-display.lock', 0600);
        try {
            if (!flock($lock, LOCK_EX)) return false;
            $keyPath = $directory . '/password-display.key';
            if (!file_exists($keyPath) && !is_link($keyPath)) {
                $file = @fopen($keyPath, 'x');
                if (!$file) return false;
                @chmod($keyPath, 0600);
                $key = random_bytes(32);
                $ok = fwrite($file, $key) === 32 && fflush($file);
                fclose($file);
                if (!$ok) return false;
            }
            $key = self::privateFile($keyPath, 32);
            if ($key === null || strlen($key) !== 32) return false;
            $nonce = random_bytes(12); $tag = '';
            $ciphertext = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, $hash);
            if ($ciphertext === false) return false;
            $path = $directory . '/password-display.json';
            if (is_link($path)) return false;
            $old = self::privateFile($path, 16384);
            $records = $old === null ? [] : json_decode($old, true, 8);
            if (!is_array($records)) $records = [];
            $id = hash('sha256', $hash); unset($records[$id]);
            $records[$id] = base64_encode($nonce . $tag . $ciphertext);
            // Retain previous hashes so a failed pac.json write does not lose the old display copy.
            $records = array_slice($records, -8, null, true);
            ManagedProtocol::writeJson($path, $records);
            return true;
        } catch (Throwable $e) {
            return false;
        } finally { flock($lock, LOCK_UN); fclose($lock); }
    }

    public static function reveal(string $directory, string $hash): ?string
    {
        if ($hash === '' || is_link($directory)) return null;
        try {
            $key = self::privateFile($directory . '/password-display.key', 32);
            $json = self::privateFile($directory . '/password-display.json', 16384);
            if ($key !== null && strlen($key) === 32 && $json !== null) {
                $records = json_decode($json, true, 8, JSON_THROW_ON_ERROR);
                $record = $records[hash('sha256', $hash)] ?? null;
                $data = is_string($record) ? base64_decode($record, true) : false;
                if (is_string($data) && strlen($data) >= 36 && strlen($data) <= 100) {
                    $plain = openssl_decrypt(substr($data, 28), 'aes-256-gcm', $key, OPENSSL_RAW_DATA, substr($data, 0, 12), substr($data, 12, 16), $hash);
                    if (is_string($plain) && password_verify($plain, $hash)) return $plain;
                }
            }
            // Existing installs may still have the bootstrap password. Never display a stale one.
            $initial = self::privateFile($directory . '/initial_password.txt', 128);
            if ($initial !== null && password_verify(rtrim($initial, "\r\n"), $hash)) {
                $plain = rtrim($initial, "\r\n");
                self::remember($directory, $plain, $hash);
                return $plain;
            }
        } catch (Throwable $e) {}
        return null;
    }
}
