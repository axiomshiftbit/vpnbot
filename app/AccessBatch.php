<?php

require_once __DIR__ . '/Lang.php';

/** A preview contains only identities, non-secret changes and hashes of reviewed rows. */
final class AccessBatch
{
    public static function fingerprint(array $user): string { return hash('sha256', json_encode($user, JSON_THROW_ON_ERROR)); }

    public static function value(string $action, string $text): int|null
    {
        if ($action === 'extend' && preg_match('/\A[0-9]{1,4}\z/D', $text) && (int) $text >= 1 && (int) $text <= 3660) return (int) $text;
        if ($action === 'quota' && preg_match('/\A[0-9]{1,7}(?:[.,][0-9]{1,6})?\z/D', $text) && (float) str_replace(',', '.', $text) <= 1000000) {
            $number = (float) str_replace(',', '.', $text);
            return $number > 0 ? max(1, (int) round($number * 1073741824)) : null;
        }
        if (in_array($action, ['disable', 'reset'], true) && $text === '') return null;
        throw new InvalidArgumentException(Lang::t('Продление: 1–3660 дней. Лимит: 0–1000000 ГиБ', 'Extension: 1–3660 days. Limit: 0–1000000 GiB'));
    }

    public static function preview(array $users, array $ids, string $action, ?int $value, int $now): array
    {
        if (!$ids || count($ids) > 20 || count(array_unique($ids)) !== count($ids)) throw new InvalidArgumentException(Lang::t('Выберите от 1 до 20 пользователей', 'Choose 1 to 20 users'));
        if (!in_array($action, ['extend', 'quota', 'disable', 'reset'], true)) throw new InvalidArgumentException(Lang::t('Неизвестное групповое действие', 'Unknown bulk action'));
        $rows = [];
        foreach ($ids as $id) {
            $user = $users[$id] ?? null; $skip = ''; $after = [];
            if (!$user) $skip = Lang::t('пользователь удалён', 'user deleted');
            elseif (isset($user['xray_source'])) $skip = Lang::t('общий доступ VLESS: изменяется в его карточке', 'shared VLESS access: change it in its card');
            elseif ($action === 'extend' && $user['expires'] === null) $skip = Lang::t('срок не ограничен', 'no expiry');
            else {
                $after = match ($action) {
                    'extend' => ['expires' => max($now, $user['expires']) + $value * 86400],
                    'quota' => ['quota' => $value],
                    'disable' => ['enabled' => false],
                    'reset' => ['reset' => true],
                };
                if ($action !== 'reset' && array_intersect_key($user, $after) === $after) $skip = Lang::t('уже установлено', 'already set');
            }
            $rows[] = ['id' => (string) $id, 'name' => $user['name'] ?? Lang::t('Удалённый пользователь', 'Deleted user'), 'skip' => $skip,
                'before' => $user ? self::fingerprint($user) : '', 'after' => $after];
        }
        return ['action' => $action, 'created' => $now, 'rows' => $rows];
    }

    public static function apply(array &$users, array $preview, int $now): int
    {
        if ($preview['created'] < $now - 600 || $preview['created'] > $now) throw new InvalidArgumentException(Lang::t('Предварительный просмотр устарел; создайте новый', 'The preview is outdated; create a new one'));
        foreach ($preview['rows'] as $row) {
            if ($row['skip'] !== '') continue;
            if (!isset($users[$row['id']]) || !hash_equals($row['before'], self::fingerprint($users[$row['id']]))) {
                throw new InvalidArgumentException(Lang::t('Данные выбранных пользователей изменились. Создайте новый предварительный просмотр', 'The selected users have changed. Create a new preview'));
            }
        }
        $changed = 0;
        foreach ($preview['rows'] as $row) {
            if ($row['skip'] !== '') continue;
            $fields = $row['after'];
            if (isset($fields['reset'])) $fields['reset'] = bin2hex(random_bytes(8));
            $users[$row['id']] = array_replace($users[$row['id']], $fields);
            $changed++;
        }
        return $changed;
    }
}
