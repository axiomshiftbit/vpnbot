<?php

// Парные пресеты xray vlessenc. REALITY-ключи сюда не входят.
final class VlessEncryption
{
    public const MODES = ['native', 'xorpub', 'random'];
    public const KEY_BYTES = ['x25519' => [32, 32], 'mlkem768' => [64, 1184]];

    public static function parseOutput(string $output): array
    {
        $result = [];
        preg_match_all('~^Authentication: (X25519|ML-KEM-768)[^\r\n]*\R'
            . '"decryption": "([^"\r\n]+)"\R"encryption": "([^"\r\n]+)"~m', $output, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $auth = $match[1] === 'X25519' ? 'x25519' : 'mlkem768';
            $settings = ['auth' => $auth, 'mode' => 'native', 'decryption' => $match[2], 'encryption' => $match[3]];
            if (self::pair($settings) !== null) {
                $result[$auth] = $settings;
            }
        }
        return $result;
    }

    public static function pair(array $settings): ?array
    {
        $auth = $settings['auth'] ?? '';
        $mode = $settings['mode'] ?? 'native';
        if (!is_string($auth) || !isset(self::KEY_BYTES[$auth]) || !in_array($mode, self::MODES, true)) {
            return null;
        }
        $pair = [];
        foreach (['decryption' => '600s', 'encryption' => '0rtt'] as $field => $time) {
            $value = $settings[$field] ?? null;
            if (!is_string($value) || !preg_match('~^mlkem768x25519plus\.native\.' . $time . '\.([A-Za-z0-9_-]+)$~D', $value, $match)) {
                return null;
            }
            $key = base64_decode(strtr($match[1], '-_', '+/'), true);
            $length = self::KEY_BYTES[$auth][$field === 'decryption' ? 0 : 1];
            if ($key === false || strlen($key) !== $length
                || rtrim(strtr(base64_encode($key), '+/', '-_'), '=') !== $match[1]) {
                return null;
            }
            $pair[$field] = str_replace('.native.', '.' . $mode . '.', $value);
        }
        return $pair;
    }

    public static function applyServer(array &$config, array $pac): bool
    {
        if (($config['inbounds'][0]['protocol'] ?? '') !== 'vless') {
            unset($config['inbounds'][0]['settings']['decryption']);
            return true;
        }
        if (!isset($pac['vless_encryption'])) {
            // Старые установки и вручную импортированный decryption сохраняем.
            $config['inbounds'][0]['settings']['decryption'] ??= 'none';
            return true;
        }
        $settings = $pac['vless_encryption'];
        if (!is_array($settings)) {
            return false;
        }
        $decryption = 'none';
        if (!empty($settings['enabled'])) {
            $pair = self::pair($settings);
            if ($pair === null || !empty($config['inbounds'][0]['settings']['fallbacks'])) {
                return false;
            }
            // Даже пустой fallbacks несовместим с Encryption в Build() Xray.
            unset($config['inbounds'][0]['settings']['fallbacks']);
            $decryption = $pair['decryption'];
        }
        $config['inbounds'][0]['settings']['decryption'] = $decryption;
        return true;
    }

    // null означает рассинхронизацию: выдавать encryption=none в этом случае нельзя.
    public static function client(array $config, array $pac): ?string
    {
        if (($config['inbounds'][0]['protocol'] ?? 'vless') !== 'vless') {
            return 'none';
        }
        $decryption = $config['inbounds'][0]['settings']['decryption'] ?? 'none';
        if ($decryption === 'none') {
            return empty($pac['vless_encryption']['enabled']) ? 'none' : null;
        }
        $settings = $pac['vless_encryption'] ?? [];
        $pair = is_array($settings) ? self::pair($settings) : null;
        return $pair !== null && !empty($settings['enabled']) && $pair['decryption'] === $decryption
            ? $pair['encryption'] : null;
    }
}
