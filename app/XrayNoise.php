<?php

require_once __DIR__ . '/Lang.php';

/** Bounded UDP finalmask packets, including Xray 26.9.30 expressions. */
final class XrayNoise
{
    public static function range(string $value, int $min, int $max): int
    {
        if (!preg_match('/\A([0-9]{1,5})(?:-([0-9]{1,5}))?\z/D', $value, $m)
            || (int) $m[1] < $min || (int) ($m[2] ?? $m[1]) < (int) $m[1]
            || (int) ($m[2] ?? $m[1]) > $max) throw new InvalidArgumentException(Lang::t("Диапазон UDP noise: {$min}–{$max}, начало не выше конца", "UDP noise range: {$min}–{$max}, the start not above the end"));
        return (int) ($m[2] ?? $m[1]);
    }

    public static function expression(string $value): int
    {
        if (strlen($value) > 4096) throw new InvalidArgumentException(Lang::t('Слишком длинное выражение UDP noise', 'The UDP noise expression is too long'));
        preg_match_all('/<\s*([a-z]+)(?:\s+([^>]*?))?\s*>/', $value, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE);
        $end = 0; $size = 0;
        foreach ($matches as $m) {
            if (trim(substr($value, $end, $m[0][1] - $end)) !== '') throw new InvalidArgumentException(Lang::t('UDP noise: текст вне <…>', 'UDP noise: text outside <…>'));
            $end = $m[0][1] + strlen($m[0][0]); $kind = $m[1][0]; $arg = trim($m[2][0] ?? '');
            if ($kind === 'b') {
                $hex = preg_replace('/\s+/', '', $arg);
                $hex = preg_replace('/\A0[xX]/', '', $hex);
                if (!preg_match('/\A(?:[0-9a-fA-F]{2})+\z/D', $hex)) throw new InvalidArgumentException(Lang::t('UDP noise: <b> требует байты в hex', 'UDP noise: <b> needs bytes in hex'));
                $size += intdiv(strlen($hex), 2);
            } elseif (in_array($kind, ['r', 'rc', 'rd'], true)) $size += self::range($arg, 0, 1400);
            elseif (in_array($kind, ['t', 'c', 'n'], true) && $arg === '') $size += $kind === 'n' ? 8 : 4;
            else throw new InvalidArgumentException(Lang::t('UDP noise: допустимы <b hex>, <r размер>, <rc размер>, <rd размер>, <t>, <c>, <n>', 'UDP noise: allowed are <b hex>, <r size>, <rc size>, <rd size>, <t>, <c>, <n>'));
        }
        if (!$matches || trim(substr($value, $end)) !== '' || $size < 1 || $size > 1400) {
            throw new InvalidArgumentException(Lang::t('UDP noise: выражение должно давать 1–1400 байт', 'UDP noise: the expression must give 1–1400 bytes'));
        }
        return $size;
    }

    public static function settings(array $options, array $list): array
    {
        $reset = (string) (($options['reset'] ?? '') !== '' ? $options['reset'] : '5-10');
        self::range($reset, 1, 86400);
        if (count($list) > 8) throw new InvalidArgumentException(Lang::t('UDP noise: не более 8 пакетов', 'UDP noise: at most 8 packets'));
        $packets = [];
        foreach ($list as $item) {
            if (!is_array($item)) throw new InvalidArgumentException(Lang::t('Неверный пакет UDP noise', 'Invalid UDP noise packet'));
            foreach (['type', 'packet', 'delay'] as $key) if (isset($item[$key]) && !is_string($item[$key])) throw new InvalidArgumentException(Lang::t('Поля UDP noise должны быть строками', 'UDP noise fields must be strings'));
            $type = ($item['type'] ?? '') ?: 'rand'; $packet = $item['packet'] ?? '';
            $delay = ($item['delay'] ?? '') !== '' ? $item['delay'] : '10-16';
            self::range($delay, 0, 1000);
            if ($type === 'rand') {
                $packet = $packet !== '' ? $packet : '10-20'; self::range($packet, 1, 1400);
                $packets[] = ['rand' => $packet, 'randRange' => '0-255', 'delay' => $delay];
                continue;
            }
            if (!in_array($type, ['str', 'hex', 'base64', 'exp'], true)) throw new InvalidArgumentException(Lang::t('UDP noise: тип rand, str, hex, base64 или exp', 'UDP noise: type rand, str, hex, base64 or exp'));
            if ($packet === '' && $type !== 'exp') continue; // Retain the existing empty-packet editor behavior.
            if ($type === 'exp') self::expression($packet);
            else {
                $decoded = match ($type) {
                    'str' => $packet,
                    'hex' => preg_match('/\A(?:[0-9a-fA-F]{2})+\z/D', $packet) ? hex2bin($packet) : false,
                    'base64' => base64_decode($packet, true),
                };
                if ($decoded === false || strlen($decoded) < 1 || strlen($decoded) > 1400) throw new InvalidArgumentException(Lang::t('UDP noise: неверный пакет или размер вне 1–1400 байт', 'UDP noise: invalid packet or size outside 1–1400 bytes'));
            }
            $packets[] = ['type' => $type, 'packet' => $packet, 'delay' => $delay];
        }
        return ['reset' => $reset, 'noise' => $packets ?: [['rand' => '10-20', 'randRange' => '0-255', 'delay' => '10-16']]];
    }

    public static function dynamicPackets(): array
    {
        return [['type' => 'exp', 'packet' => '<b 0d0a0d0a><t><c><n><rc 20-40><rd 4-8>', 'delay' => '1-3']];
    }
}
