<?php

// Валидация clash/mihomo-шаблонов при сохранении (webapp и загрузка файлом).
// Ловит типовые поломки до того, как битый шаблон уедет клиентам по подписке:
// пустые/дублирующиеся имена, ссылки групп в никуда, опечатки в ~плейсхолдерах~.
// errors — шаблон не сохраняем; warnings — сохраняем, но показываем админу.
class ClashTemplateValidator
{
    // Подстановки, которые реально делает bot.php при сборке подписки.
    // Неизвестный ~плейсхолдер~ уедет клиенту как есть — это warning.
    private const KNOWN_PLACEHOLDERS = [
        '~uid~', '~domain~', '~directdomain~', '~cdndomain~', '~short_id~',
        '~email~', '~public_key~', '~server_name~', '~ip~', '~dns~',
        '~dnspath~', '~outbound~', '~pac~', '~block~', '~warp~', '~process~',
        '~package~', '~subnet~', '~fingerprint~', '~ss~', '~t~', '~url~',
        '~warp_ip~', '~warp_mtu~', '~warp_port~', '~warp_private_key~',
        '~warp_public_key~', '~warp_server~',
    ];

    // Встроенные цели clash, на которые группам можно ссылаться без объявления.
    private const BUILTIN_TARGETS = ['DIRECT', 'REJECT', 'REJECT-DROP', 'GLOBAL', 'PASS', 'COMPATIBLE'];

    // Структурные проверки — только для clash/mihomo ($type == 'clash').
    // Для sing/v2ray структура другая — там используем validatePlaceholders().
    public static function validate(array $template): array
    {
        $errors   = [];
        $warnings = [];

        $proxyNames = [];
        if (!isset($template['proxies']) || !is_array($template['proxies']) || $template['proxies'] === []) {
            $errors[] = 'proxies must be a non-empty array';
        } else {
            foreach ($template['proxies'] as $i => $proxy) {
                if (!is_array($proxy)) {
                    $errors[] = "proxies[$i] must be an object";
                    continue;
                }
                $name = trim((string) ($proxy['name'] ?? ''));
                if ($name === '') {
                    $errors[] = "proxies[$i].name is required";
                } elseif (isset($proxyNames[$name])) {
                    $errors[] = "duplicate proxy name: $name";
                } else {
                    $proxyNames[$name] = true;
                }
                if (strtolower(trim((string) ($proxy['type'] ?? ''))) === '') {
                    $warnings[] = "proxies[$i].type is empty";
                }
            }
        }

        $groupNames = [];
        if (!isset($template['proxy-groups']) || !is_array($template['proxy-groups']) || $template['proxy-groups'] === []) {
            $errors[] = 'proxy-groups must be a non-empty array';
        } else {
            // Сначала собираем все имена групп: группы могут ссылаться друг
            // на друга вперёд по списку.
            foreach ($template['proxy-groups'] as $gi => $group) {
                if (!is_array($group)) {
                    $errors[] = "proxy-groups[$gi] must be an object";
                    continue;
                }
                $groupName = trim((string) ($group['name'] ?? ''));
                if ($groupName === '') {
                    $errors[] = "proxy-groups[$gi].name is required";
                } elseif (isset($groupNames[$groupName])) {
                    $errors[] = "duplicate proxy-group name: $groupName";
                } else {
                    $groupNames[$groupName] = true;
                }
            }
            foreach ($template['proxy-groups'] as $gi => $group) {
                if (!is_array($group)) {
                    continue;
                }
                if (empty($group['proxies']) || !is_array($group['proxies'])) {
                    $warnings[] = "proxy-groups[$gi].proxies is empty";
                    continue;
                }
                foreach ($group['proxies'] as $ref) {
                    $ref = trim((string) $ref);
                    // Плейсхолдер (~outbound~ и т.п.) раскроется при сборке —
                    // такие ссылки валидны by design.
                    if ($ref === '' || in_array($ref, self::BUILTIN_TARGETS, true) || str_contains($ref, '~')) {
                        continue;
                    }
                    if (!isset($proxyNames[$ref]) && !isset($groupNames[$ref])) {
                        $errors[] = "proxy-groups[$gi] references unknown proxy/group: $ref";
                    }
                }
            }
        }

        if (isset($template['rules']) && !is_array($template['rules'])) {
            $errors[] = 'rules must be an array when present';
        }

        // Без ~outbound~ генератор подписки не вставит ни одного узла —
        // клиент получит шаблон со статичными прокси. Иногда так и задумано,
        // поэтому warning, не error.
        if (!self::containsPlaceholder($template['proxies'] ?? [], '~outbound~')
            && !self::containsPlaceholder($template['proxy-groups'] ?? [], '~outbound~')) {
            $warnings[] = 'no ~outbound~ placeholder — subscription nodes will not be injected';
        }

        self::scanUnknownPlaceholders($template, '', $warnings);

        return [
            'ok'       => $errors === [],
            'errors'   => $errors,
            'warnings' => $warnings,
        ];
    }

    // Для sing/v2ray: структуру не знаем достаточно строго, проверяем только
    // опечатки в плейсхолдерах.
    public static function validatePlaceholders(array $template): array
    {
        $warnings = [];
        self::scanUnknownPlaceholders($template, '', $warnings);
        return [
            'ok'       => true,
            'errors'   => [],
            'warnings' => $warnings,
        ];
    }

    private static function containsPlaceholder($value, string $placeholder): bool
    {
        if (is_string($value)) {
            return str_contains($value, $placeholder);
        }
        if (!is_array($value)) {
            return false;
        }
        foreach ($value as $v) {
            if (self::containsPlaceholder($v, $placeholder)) {
                return true;
            }
        }
        return false;
    }

    private static function scanUnknownPlaceholders($value, string $path, array &$warnings): void
    {
        if (is_array($value)) {
            foreach ($value as $k => $v) {
                self::scanUnknownPlaceholders($v, $path === '' ? (string) $k : "$path.$k", $warnings);
            }
            return;
        }
        if (!is_string($value)) {
            return;
        }
        if (preg_match_all('/~[a-z_]+~/i', $value, $m)) {
            foreach ($m[0] as $ph) {
                if (!in_array(strtolower($ph), self::KNOWN_PLACEHOLDERS, true)) {
                    $warnings[] = ($path === '' ? '' : "$path: ") . "unknown placeholder $ph";
                }
            }
        }
    }
}
