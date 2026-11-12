<?php

// Адрес Bot API, через который бот ходит в Telegram: api.telegram.org,
// зеркало из TELEGRAM_API в .env или свой ретранслятор на другом сервере
// (Bot::telegramRelay*). Настройка из бота или CLI лежит в config/telegram_api
// и перекрывает .env; в резервную копию она не входит: на новом сервере
// ретранслятор может не пускать его адрес, и бот после восстановления
// остался бы без связи с Telegram.
//
// Токен бота уходит в путь каждого запроса, поэтому адрес принимается только
// https и только из узкого набора символов: без userinfo, query, fragment,
// пробелов и сегментов «.»/«..». Тот же формат проверяет bash в update.sh и
// init.sh (tests/telegram_api_test.py сверяет все три реализации).
final class TelegramApi
{
    public const DEFAULT = 'https://api.telegram.org';
    public const FILE = '/config/telegram_api';
    public const MAX_LENGTH = 255;

    // Значение из бота/CLI или из .env. Без схемы считается https: так
    // TELEGRAM_API всегда записывался в .env (только имя хоста).
    public static function normalize(?string $raw): ?string
    {
        $value = trim((string) $raw);
        if ($value === '' || strlen($value) > self::MAX_LENGTH) return null;
        if (!str_contains($value, '://')) $value = 'https://' . $value;
        $value = rtrim($value, '/');
        if (strlen($value) > self::MAX_LENGTH) return null;
        if (!preg_match('#^https://(?P<host>[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*|\[[0-9A-Fa-f:.]{2,45}\])(?::(?P<port>[1-9][0-9]{0,4}))?(?P<path>(?:/[A-Za-z0-9._~-]{1,64}){0,8})$#D', $value, $m)) return null;
        $host = $m['host'];
        if ($host[0] === '[' && filter_var(substr($host, 1, -1), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) return null;
        $port = $m['port'] ?? '';
        if ($port !== '' && (int) $port > 65535) return null;
        $path = $m['path'] ?? '';
        if (preg_match('~/\.{1,2}(?:/|$)~', $path)) return null;
        return 'https://' . strtolower($host) . ($port !== '' ? ':' . $port : '') . $path;
    }

    // ['url' => адрес, 'source' => file|env|default, 'invalid' => что отвергнуто].
    // Испорченный файл или переменная не ломают бота: остаётся следующий по
    // приоритету источник (официальный адрес Telegram), а меню показывает,
    // какое значение не принято.
    public static function current(?string $file = null, ?string $env = null): array
    {
        $file ??= self::FILE;
        $env ??= (string) getenv('TELEGRAM_API');
        $invalid = [];
        $stored = self::readFile($file);
        if ($stored !== null) {
            if (($url = self::normalize($stored)) !== null) return ['url' => $url, 'source' => 'file', 'invalid' => []];
            $invalid[] = 'file';
        }
        if (trim($env) !== '') {
            if (($url = self::normalize($env)) !== null) return ['url' => $url, 'source' => $url === self::DEFAULT ? 'default' : 'env', 'invalid' => $invalid];
            $invalid[] = 'env';
        }
        return ['url' => self::DEFAULT, 'source' => 'default', 'invalid' => $invalid];
    }

    // Адрес без настройки из бота: на него переключает «сброс».
    public static function fallback(?string $env = null): string
    {
        return self::current('/nonexistent/vpnbot-telegram-api', $env)['url'];
    }

    public static function readFile(string $file): ?string
    {
        if (is_link($file) || !is_file($file)) return null;
        $raw = @file_get_contents($file, false, null, 0, 1024);
        if (!is_string($raw)) return null;
        return trim(strtok($raw . "\n", "\n"));
    }

    // Атомарная запись 0600; пустой $url удаляет настройку.
    public static function save(string $file, ?string $url): bool
    {
        if (is_link($file)) return false;
        if ($url === null) return !file_exists($file) || @unlink($file);
        if (self::normalize($url) !== $url) return false;
        $tmp = $file . '.' . bin2hex(random_bytes(8)) . '.tmp';
        $mask = umask(0077);
        $h = @fopen($tmp, 'x');
        umask($mask);
        if ($h === false) return false;
        $ok = @chmod($tmp, 0600) && fwrite($h, $url . "\n") === strlen($url) + 1 && fflush($h) && fsync($h);
        fclose($h);
        if (!$ok || !@rename($tmp, $file)) { @unlink($tmp); return false; }
        return true;
    }

    // Путь ретранслятора — секрет: в меню и выводе CLI он скрыт.
    public static function mask(string $url): string
    {
        $parts = parse_url($url);
        if (!is_array($parts) || empty($parts['host'])) return '•••';
        $host = str_contains($parts['host'], ':') && $parts['host'][0] !== '[' ? '[' . $parts['host'] . ']' : $parts['host'];
        return 'https://' . $host . (isset($parts['port']) ? ':' . $parts['port'] : '') . (!empty($parts['path']) && $parts['path'] !== '/' ? '/•••' : '');
    }

    public static function botId(string $key): string
    {
        return preg_match('~^([0-9]{5,15}):~', $key, $m) ? $m[1] : '';
    }

    // getMe через $base. Возвращает только категорию результата: тело ответа,
    // адрес и токен не сохраняются и не печатаются.
    public static function probe(string $base, string $key, ?string $proxy = null, int $timeout = 15): array
    {
        if (self::normalize($base) !== $base) return ['ok' => false, 'reason' => 'invalid'];
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => "$base/bot$key/getMe",
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT        => $timeout,
            CURLOPT_PROTOCOLS      => CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);
        if ($proxy) curl_setopt($ch, CURLOPT_PROXY, $proxy);
        $body = curl_exec($ch);
        return self::classify(curl_errno($ch), (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE), $body, $key);
    }

    public static function classify(int $errno, int $code, $body, string $key): array
    {
        if ($errno !== 0 || !is_string($body)) {
            // 35, 51, 58, 60, 77, 83, 90, 91 — ошибки TLS и проверки сертификата curl.
            $reason = in_array($errno, [35, 51, 58, 60, 77, 83, 90, 91], true) ? 'tls' : 'network';
            return ['ok' => false, 'reason' => $reason, 'curl' => $errno];
        }
        $reply = json_decode($body, true);
        // Отказ токена — только JSON Bot API: 401 basic-auth страницы сайта
        // (неверный адрес ретранслятора) — это «ответ не от Bot API».
        if (is_array($reply) && (int) ($reply['error_code'] ?? 0) === 401) return ['ok' => false, 'reason' => 'unauthorized', 'http' => $code];
        if (!is_array($reply) || empty($reply['ok']) || !is_array($reply['result'] ?? null)) return ['ok' => false, 'reason' => 'http', 'http' => $code];
        if ((string) ($reply['result']['id'] ?? '') !== self::botId($key) || empty($reply['result']['is_bot'])) return ['ok' => false, 'reason' => 'mismatch', 'http' => $code];
        return ['ok' => true, 'reason' => 'ok', 'username' => preg_match('~^[A-Za-z0-9_]{1,64}$~D', (string) ($reply['result']['username'] ?? '')) ? $reply['result']['username'] : ''];
    }
}
