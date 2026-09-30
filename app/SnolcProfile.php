<?php

/** Native SSH profiles: never advertise unsupported Mihomo/NG import. */
final class SnolcProfile
{
    private static function publicKey(string $seed, string $oid): string
    {
        // RFC 8410 PKCS#8/SPKI: OpenSSL is already required by VPNBot.
        $der = hex2bin('302e020100300506032b65' . $oid . '04220420') . $seed;
        $key = openssl_pkey_get_private("-----BEGIN PRIVATE KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PRIVATE KEY-----\n");
        $details = $key ? openssl_pkey_get_details($key) : false;
        $encoded = $details ? preg_replace('/-----[^-]+-----|\s+/', '', $details['key']) : '';
        $public = base64_decode($encoded, true);
        $prefix = hex2bin('302a300506032b65' . $oid . '032100');
        if ($public === false || strlen($public) !== 44 || !str_starts_with($public, $prefix)) throw new RuntimeException('OpenSSL не поддерживает ключи snolc');
        return substr($public, -32);
    }

    public static function profile(array $user, array $settings): array
    {
        $seed = hex2bin($settings['server_seed']);
        if ($seed === false || strlen($seed) !== 32) throw new RuntimeException('Ключи snolc ещё не созданы');
        $derive = static fn($name) => hash_hmac('sha256', 'vpnbot/snolc/' . $name . '/v1', $seed, true);
        $public = self::publicKey($derive('ssh'), '70');
        $ssh = pack('N', 11) . 'ssh-ed25519' . pack('N', 32) . $public;
        return ['schema' => 'vpnbot.snolc.v1', 'version' => '0.0.4', 'name' => $user['name'],
            'server' => ['host' => $settings['host'], 'port' => $settings['port'],
                'server_id' => 'vpnbot-' . substr(hash('sha256', $public), 0, 24),
                'ssh_public_key' => 'ssh-ed25519 ' . base64_encode($ssh),
                'noise_public_key' => bin2hex(self::publicKey($derive('noise'), '6e')),
                'ssh_password' => bin2hex($derive('carrier'))],
            'credential' => bin2hex(base64_decode(strtr($user['password'], '-_', '+/') . '=', true))];
    }

    public static function document(array $profile, string $clientBundle): array
    {
        if (!is_file($clientBundle) || filesize($clientBundle) > 16 * 1024 * 1024) {
            throw new RuntimeException('Комплект клиента ещё не готов. Включите сервис snolc и повторите загрузку ZIP.');
        }
        $path = tempnam(sys_get_temp_dir(), 'snolc-');
        if ($path === false) throw new RuntimeException('Не удалось создать архив snolc');
        try {
            chmod($path, 0600);
            $zip = new ZipArchive();
            if ($zip->open($path, ZipArchive::OVERWRITE) !== true) throw new RuntimeException('Не удалось открыть архив snolc');
            $zip->addFromString('profile.json', json_encode($profile, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR));
            foreach (['client.py', 'snolc_config.py', 'releases.json', 'module-options.json', 'README.txt'] as $name) {
                if (!$zip->addFile(__DIR__ . '/snolc/' . $name, $name)) throw new RuntimeException('Неполный комплект клиента snolc');
            }
            if (!$zip->addFile($clientBundle, 'client-patches.zip')) throw new RuntimeException('Не удалось добавить исправленный клиент snolc');
            if (!$zip->close()) throw new RuntimeException('Не удалось сохранить архив snolc');
            $body = file_get_contents($path);
            if ($body === false) throw new RuntimeException('Не удалось прочитать архив snolc');
            return ['body' => $body, 'extension' => 'zip', 'mime' => 'application/zip'];
        } finally {
            @unlink($path);
        }
    }
}
