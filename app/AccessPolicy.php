<?php

require_once __DIR__ . '/Lang.php';

/** Optional calendar quotas for independent protocol users; all dates are UTC. */
final class AccessPolicy
{
    public const PERIODS = ['day' => true, 'week' => true, 'month' => true];

    public static function periodLabel(string $period): string
    {
        return match ($period) {
            'day' => Lang::t('Каждый день', 'Every day'),
            'week' => Lang::t('Каждую неделю', 'Every week'),
            default => Lang::t('Каждый месяц', 'Every month'),
        };
    }

    public static function validate(array $user): void
    {
        if (isset($user['quota_schedule'])) {
            $s = $user['quota_schedule'];
            if (!is_array($s) || !is_string($s['period'] ?? null) || !isset(self::PERIODS[$s['period']])
                || !is_int($s['anchor'] ?? null) || !is_int($s['next'] ?? null)
                || $s['anchor'] < 1 || $s['next'] < $s['anchor'] || $s['next'] > 4102444800) {
                throw new InvalidArgumentException(Lang::t('Неверное расписание сброса квоты', 'Invalid quota reset schedule'));
            }
            if (self::next($s['period'], $s['anchor'], $s['next'] - 1) !== $s['next']) {
                throw new InvalidArgumentException(Lang::t('Дата сброса не соответствует расписанию', 'The reset date does not match the schedule'));
            }
        }
        if (isset($user['alerts'])) {
            $a = $user['alerts'];
            if (!is_array($a) || !is_int($a['percent'] ?? null) || $a['percent'] < 0 || $a['percent'] > 100
                || !is_int($a['days'] ?? null) || $a['days'] < 0 || $a['days'] > 365) {
                throw new InvalidArgumentException(Lang::t('Уведомления: 0–100 процентов и 0–365 дней', 'Notifications: 0–100 percent and 0–365 days'));
            }
        }
    }

    public static function date(string $text): int
    {
        $date = DateTimeImmutable::createFromFormat('!Y-m-d H:i', $text, new DateTimeZone('UTC'));
        if (!$date || $date->format('Y-m-d H:i') !== $text || $date->getTimestamp() < 1 || $date->getTimestamp() > 4102444800) {
            throw new InvalidArgumentException(Lang::t('Нужна дата YYYY-MM-DD HH:MM в UTC, до 2100 года', 'A date YYYY-MM-DD HH:MM in UTC before 2100 is needed'));
        }
        return $date->getTimestamp();
    }

    public static function next(string $period, int $anchor, int $now): int
    {
        if (!isset(self::PERIODS[$period])) throw new InvalidArgumentException(Lang::t('Неизвестный период', 'Unknown period'));
        if ($now < $anchor) return $anchor;
        if ($period !== 'month') {
            $step = $period === 'day' ? 86400 : 604800;
            return $anchor + (intdiv($now - $anchor, $step) + 1) * $step;
        }
        $a = (new DateTimeImmutable('@' . $anchor))->setTimezone(new DateTimeZone('UTC'));
        $n = (new DateTimeImmutable('@' . $now))->setTimezone(new DateTimeZone('UTC'));
        $months = ((int) $n->format('Y') - (int) $a->format('Y')) * 12 + (int) $n->format('n') - (int) $a->format('n');
        // Clamp February to its last day, but retain the original day for March.
        $base = $a->setDate((int) $a->format('Y'), (int) $a->format('n'), 1);
        for ($i = $months; $i <= $months + 1; $i++) {
            $month = $base->modify("+$i months");
            $candidate = $month->setDate((int) $month->format('Y'), (int) $month->format('n'), min((int) $a->format('j'), (int) $month->format('t')));
            if ($candidate->getTimestamp() > $now) return $candidate->getTimestamp();
        }
        throw new LogicException(Lang::t('Не удалось вычислить следующий месяц', 'Could not compute the next month'));
    }

    public static function schedule(string $text, int $now): ?array
    {
        if ($text === '0') return null;
        if (!preg_match('/\A(day|week|month) (\d{4}-\d{2}-\d{2} \d{2}:\d{2})\z/D', $text, $m)) {
            throw new InvalidArgumentException(Lang::t('Введите day, week или month и первую дату UTC; либо 0', 'Enter day, week or month and the first UTC date; or 0'));
        }
        $anchor = self::date($m[2]);
        if ($anchor <= $now) throw new InvalidArgumentException(Lang::t('Первый сброс должен быть в будущем', 'The first reset must be in the future'));
        return ['period' => $m[1], 'anchor' => $anchor, 'next' => $anchor];
    }

    public static function resetDue(array &$state, int $now): array
    {
        $reset = [];
        foreach ($state['users'] as $id => &$user) {
            // Linked users share the Xray quota and its existing reset schedule.
            if (isset($user['xray_source']) || !isset($user['quota_schedule'])) continue;
            self::validate($user);
            $s = &$user['quota_schedule'];
            if ($s['next'] > $now) continue;
            $user['reset'] = bin2hex(random_bytes(8));
            $s['next'] = self::next($s['period'], $s['anchor'], $now);
            $reset[] = (string) $id;
            unset($s);
        }
        return $reset;
    }

    public static function bytes(array $user, ?array $row): ?int
    {
        if (!$row || ($row['reset'] ?? '') !== $user['reset']
            || !is_int($row['upload'] ?? null) || !is_int($row['download'] ?? null)
            || $row['upload'] < 0 || $row['download'] < 0
            || $row['upload'] > PHP_INT_MAX - $row['download']) return null;
        return (int) $row['upload'] + (int) $row['download'];
    }

    public static function events(array $user, ?array $row, int $now): array
    {
        self::validate($user);
        if (!$user['enabled'] || isset($user['xray_source'])) return [];
        $alerts = $user['alerts'] ?? ['percent' => 0, 'days' => 0];
        $events = []; $bytes = self::bytes($user, $row);
        if ($alerts['percent'] && $user['quota'] !== null && $bytes !== null
            && $bytes >= $user['quota'] * ($alerts['percent'] / 100)) {
            $events['quota'] = hash('sha256', $user['reset'] . ':' . $user['quota'] . ':' . $alerts['percent']);
        }
        if ($alerts['days'] && $user['expires'] !== null && $user['expires'] <= $now + $alerts['days'] * 86400) {
            $events['expires'] = hash('sha256', $user['expires'] . ':' . $alerts['days']);
        }
        return $events;
    }

    public static function reason(array $user, ?int $bytes, int $now): string
    {
        if (!$user['enabled']) return Lang::t('выключен вручную', 'disabled manually');
        if ($user['expires'] !== null && $user['expires'] <= $now) return Lang::t('срок истёк', 'expired');
        if ($user['quota'] !== null && $bytes === null) return Lang::t('ожидаются счётчики', 'waiting for counters');
        if ($user['quota'] !== null && $bytes >= $user['quota']) return Lang::t('квота исчерпана', 'quota used up');
        return Lang::t('доступен', 'available');
    }
}
