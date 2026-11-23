<?php

/** A node list that cannot be expanded or sent; the message names the reason for the admin. */
class NodeRoutesException extends RuntimeException {}

/**
 * Shared Block and WARP lists of a managed node. They route all traffic the node
 * receives: main-bot users, external panels and other bots. Entries follow the
 * main bot (domain/full/keyword/regexp/IP, geosite/geoip/ext dat, .srs/.mrs sets);
 * geodata and sets expand here, because the node has neither.
 */
trait BotNodeRoutes
{
    public const NODE_ROUTE_KINDS = ['block', 'warp'];

    /** Source entries of both lists; a node of an earlier version keeps its shared blocks. */
    private function nodeRoutesSource(array $node): array
    {
        $lists = is_array($node['lists'] ?? null) ? $node['lists'] : self::nodeRoutesLegacy($node);
        $result = [];
        foreach (self::NODE_ROUTE_KINDS as $kind) {
            $list = is_array($lists[$kind] ?? null) ? $lists[$kind] : [];
            $result[$kind] = ['routes' => is_array($list['routes'] ?? null) ? $list['routes'] : [],
                'rulesets' => is_array($list['rulesets'] ?? null) ? $list['rulesets'] : []];
        }
        return $result;
    }

    private static function nodeRoutesLegacy(array $node): array
    {
        $policy = ($node['draft'] ?? $node['status']['options'] ?? [])['policy'] ?? [];
        $routes = [];
        foreach ((array) ($policy['bindings']['all'] ?? []) as $row) {
            if (!is_array($row) || ($row['action'] ?? '') !== 'block') continue;
            foreach ((array) ($policy['lists'][$row['list'] ?? ''] ?? []) as $entries) {
                foreach ((array) $entries as $entry) if (is_string($entry) && $entry !== '') $routes[$entry] = 1;
            }
        }
        return ['block' => ['routes' => $routes, 'rulesets' => []]];
    }

    private static function nodeRoutesDigest(array $lists): string
    {
        return hash('sha256', json_encode($lists, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    }

    /** Edited lists that the node has not confirmed yet. */
    private function nodeRoutesPending(array $node): bool
    {
        $lists = $this->nodeRoutesSource($node);
        $empty = !array_filter($lists, static fn($list) => $list['routes'] || $list['rulesets']);
        return ($node['lists_sent'] ?? ($empty ? self::nodeRoutesDigest($lists) : '')) !== self::nodeRoutesDigest($lists);
    }

    private function nodeRoutesWrite(string $id, callable $edit): void
    {
        $this->managedNodeLocked($id, function () use ($id, $edit) {
            $this->managedNodeWrite($id, function (&$node) use ($edit) {
                if (!$node) throw new RuntimeException('Node unavailable');
                $lists = $this->nodeRoutesSource($node);
                $edit($lists);
                $node['lists'] = $lists;
            });
        });
    }

    /** Matcher lists for the node. A broken source must never become a smaller list silently. */
    private function nodeRoutesParts(array $list): array
    {
        $entries = array_filter($list['routes']);
        foreach ($list['rulesets'] as $url => $set) {
            if (!is_array($set) || empty($set['on'])) continue;
            // The node has no copy of the set: refresh it at most daily when applying; a failed refresh keeps the last entries.
            $cache = $this->exitRulesetCache((string) $url);
            if (!($cache['entries'] ?? []) || time() - (int) ($cache['time'] ?? 0) >= 86400) {
                $this->exitRulesetRefresh((string) $url, ['behavior' => ($set['behavior'] ?? 'domain') === 'ipcidr' ? 'ipcidr' : 'domain']);
                $cache = $this->exitRulesetCache((string) $url);
            }
            $items = $cache['entries'] ?? [];
            if (!$items) throw new NodeRoutesException('set');
            foreach ($items as $entry) $entries[$entry] = 1;
        }
        foreach (array_keys($entries) as $raw) {
            $entry = $this->classifyRouteEntry((string) $raw);
            if (!in_array($entry['kind'], ['ext', 'extip', 'geosite', 'geoip'], true)) continue;
            unset($entries[$raw]);
            try { $expanded = $this->nodePolicyDat($entry); } catch (Throwable $e) { throw new NodeRoutesException('dat'); }
            foreach ($expanded as $value) $entries[$value] = 1;
        }
        $parts = [];
        foreach (array_keys($entries) as $raw) {
            $entry = $this->classifyRouteEntry((string) $raw);
            if (!$this->routeEntryUsable($entry)) throw new NodeRoutesException('entry');
            if ($entry['kind'] === 'ip') $parts['ip'][$entry['value']] = true;
            elseif (in_array($entry['kind'], ['full', 'suffix', 'domain', 'regexp', 'keyword'], true)) {
                $parts['domain'][($entry['kind'] === 'keyword' ? 'keyword:' : '') . $this->xrayDomainToken($entry)] = true;
            } else throw new NodeRoutesException('entry');
        }
        return array_map('array_keys', $parts);
    }

    /** The policy a configure request carries: shared lists, or only blocks for older node code. */
    private function nodeRoutesPolicy(array $node, ?array $current): array
    {
        $status = $node['status'] ?? [];
        $lists = $this->nodeRoutesSource($node);
        if (!empty($status['shared_routes'])) {
            $routes = [];
            foreach (self::NODE_ROUTE_KINDS as $kind) if ($parts = $this->nodeRoutesParts($lists[$kind])) $routes[$kind] = $parts;
            $policy = ['routes' => $routes];
        } elseif (!empty($status['named_policy'])) {
            $parts = $this->nodeRoutesParts($lists['block']);
            $policy = $parts ? ['lists' => ['block' => $parts], 'bindings' => ['all' => [['list' => 'block', 'action' => 'block']]]]
                : ['lists' => [], 'bindings' => []];
        } else {
            // Node code without lists still carries the controller IP list.
            $policy = [];
        }
        // The node counts every matcher with 8 bytes of overhead against 3 MiB for both lists together.
        $size = 0;
        array_walk_recursive($policy, static function ($item) use (&$size) { if (is_string($item)) $size += strlen($item) + 8; });
        if ($size > 3 * 1024 * 1024) throw new NodeRoutesException('size');
        $block = $policy['routes']['block'] ?? $policy['lists']['block'] ?? [];
        if ($this->nodeRoutesBlocksProbe($block['domain'] ?? [], $block['ip'] ?? [])) throw new NodeRoutesException('probe');
        // Login revisions follow the controller IP list, not these lists.
        if (isset($current['revision'])) $policy['revision'] = $current['revision'];
        foreach (['controller_ips', 'controller_ips_digest'] as $key) if (isset($current[$key])) $policy[$key] = $current[$key];
        return $policy;
    }

    /**
     * The main bot checks a node (and its WARP) through www.gstatic.com. Blocking it on the node
     * fails every check, so each apply would roll back. IPs are checked as the controller resolves the name.
     */
    protected function nodeRoutesBlocksProbe(array $domains, array $ips): bool
    {
        $host = parse_url(self::EXIT_PROBE_URL, PHP_URL_HOST);
        foreach ($domains as $token) {
            [$type, $value] = array_pad(explode(':', (string) $token, 2), 2, null);
            if ($value === null) { $value = $type; $type = 'keyword'; }
            $hit = match ($type) {
                'full' => $host === $value,
                'domain' => $host === $value || str_ends_with($host, '.' . $value),
                'keyword' => $value !== '' && str_contains($host, $value),
                'regexp' => @preg_match('~' . str_replace('~', '\~', $value) . '~', $host) === 1,
                default => false,
            };
            if ($hit) return true;
        }
        if (!$ips) return false;
        foreach ($this->nodeRoutesProbeAddresses($host) as $address) foreach ($ips as $cidr) if (self::exitIpInCidr($address, (string) $cidr)) return true;
        return false;
    }

    protected function nodeRoutesProbeAddresses(string $host): array
    {
        $addresses = @gethostbynamel($host) ?: [];
        foreach (@dns_get_record($host, DNS_AAAA) ?: [] as $record) if (isset($record['ipv6'])) $addresses[] = $record['ipv6'];
        return $addresses;
    }

    private function nodeRoutesError(Throwable $error): string
    {
        return match ($error instanceof NodeRoutesException ? $error->getMessage() : '') {
            'set' => $this->t('Набор .srs/.mrs недоступен, а сохранённой копии нет. Проверьте ссылку или выключите набор.', 'An .srs/.mrs set is unreachable and has no saved copy. Check the URL or disable the set.'),
            'dat' => $this->t('Категория geosite/geoip/ext недоступна: нет файла .dat или категории. Проверьте источники .dat основного бота.', 'A geosite/geoip/ext category is unavailable: the .dat file or category is missing. Check the main bot’s .dat sources.'),
            'entry' => $this->t('В списке есть запись, которую нельзя передать ноде. Удалите её.', 'The list has an entry that cannot be sent to the node. Delete it.'),
            'size' => $this->t('Списки вместе больше 3 МБ. Уменьшите их.', 'The lists exceed 3 MB together. Make them smaller.'),
            'probe' => $this->t('«Блокировка» задевает www.gstatic.com: через него основной бот проверяет ноду, и каждое применение откатится. Уберите запись, которая его блокирует.',
                'Block covers www.gstatic.com: the main bot checks the node through it, so every apply would roll back. Remove the entry that blocks it.'),
            default => '',
        };
    }

    private static function nodePolicyActive(array $policy): bool
    {
        return !empty($policy['routes']) || !empty($policy['lists']) || !empty($policy['controller_ips']) || !empty($policy['controller_ips_digest']);
    }

    public function nodeRoutesMenu(string $id, string $kind, int $page = 0, string $notice = ''): void
    {
        $node = $this->managedNodes()[$id] ?? null;
        if (!$node || empty($node['connected']) || !in_array($kind, self::NODE_ROUTE_KINDS, true)) { $this->managedNodesMenu(); return; }
        $list = $this->nodeRoutesSource($node)[$kind];
        $status = $node['status'] ?? [];
        $title = $kind === 'block' ? $this->t('⛔ Блокировка', '⛔ Block') : 'WARP';
        $text = [$this->t('Ноды → ', 'Nodes → ') . self::esc($node['name']) . ' → ' . $title,
            $kind === 'block'
                ? $this->t('Нода блокирует эти домены и адреса для всего трафика: пользователей основного бота, внешних панелей и других ботов.',
                    'The node blocks these domains and addresses for all its traffic: main-bot users, external panels and other bots.')
                : $this->t('Эти домены и адреса нода выпускает через свой WARP, остальное — напрямую. Блокировка старше WARP.',
                    'The node sends these domains and addresses through its WARP and everything else directly. Block takes priority over WARP.'),
            $this->t('Нажмите «➕ Добавить», чтобы увидеть примеры правил и скопировать префикс.',
                'Tap ➕ Add for rule examples and prefixes you can copy.')];
        if (empty($status['shared_routes'])) {
            $text[] = $kind === 'warp' || empty($status['named_policy'])
                ? $this->t('⚠️ Код ноды не поддерживает этот список. Обновите код ноды.', '⚠️ The node code does not support this list. Update the node code.')
                : $this->t('⚠️ Старый код ноды применит только блокировку. Обновите код ноды.', '⚠️ Older node code applies only the block list. Update the node code.');
        } elseif ($kind === 'warp' && (($node['draft'] ?? $status['options'] ?? [])['warp_mode'] ?? 'off') === 'off') {
            $text[] = $this->t('⚠️ WARP ноды выключен: записи этого списка идут напрямую. Включите его в «⚙️ Xray и подключение» → «WARP ноды».',
                '⚠️ Node WARP is off: entries of this list go directly. Enable it in ⚙️ Xray and connection → Node WARP.');
        }
        if ($this->nodeRoutesPending($node)) $text[] = $this->t('Есть изменения, которые ещё не применены на ноде.', 'Some changes are not applied on the node yet.');
        if ($notice !== '') $text[] = '<b>' . self::esc($notice) . '</b>';
        $rows = [];
        foreach ($list['routes'] as $entry => $on) $rows[] = ['E', (string) $entry, !empty($on)];
        foreach ($list['rulesets'] as $url => $set) $rows[] = ['S', (string) $url, !empty($set['on'])];
        $pages = max(1, (int) ceil(count($rows) / self::EXIT_PAGE));
        $page = min($pages - 1, max(0, $page));
        $data = [];
        foreach (array_slice($rows, $page * self::EXIT_PAGE, self::EXIT_PAGE) as [$type, $value, $on]) {
            $key = self::exitEntryKey($value);
            $label = ($type === 'S' ? 'set: ' : '') . $value;
            $data[] = [['text' => ($on ? '✅ ' : '⏸ ') . mb_substr($label, 0, 50), 'callback_data' => "/nl$type $id $kind $key $page"],
                ['text' => '✖', 'callback_data' => '/nl' . ($type === 'S' ? 'X' : 'D') . " $id $kind $key $page"]];
        }
        if ($pages > 1) $data[] = [['text' => '←', 'callback_data' => "/nlist $id $kind " . max(0, $page - 1)],
            ['text' => ($page + 1) . "/$pages", 'callback_data' => "/nlist $id $kind $page"],
            ['text' => '→', 'callback_data' => "/nlist $id $kind " . min($pages - 1, $page + 1)]];
        $data[] = [['text' => $this->t('➕ Добавить', '➕ Add'), 'callback_data' => "/nlAdd $id $kind"],
            ['text' => $this->t('📥 Импорт', '📥 Import'), 'callback_data' => "/nlImp $id $kind"],
            ['text' => $this->t('📤 Экспорт', '📤 Export'), 'callback_data' => "/nlExp $id $kind"]];
        if ($rows) $data[] = [['text' => $this->t('🧹 Очистить всё', '🧹 Clear all'), 'callback_data' => "/nlClr $id $kind"]];
        if ($this->nodeRoutesPending($node)) $data[] = [['text' => $this->t('✅ Применить на ноде', '✅ Apply on the node'), 'callback_data' => "/nlApply $id $kind"]];
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => "/node $id"]];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n\n", $text), $data);
    }

    /** E/S toggles an entry or a set, D/X deletes it. */
    public function nodeRoutesToggle(string $id, string $kind, string $key, string $action, int $page): void
    {
        try {
            $this->nodeRoutesWrite($id, function (array &$lists) use ($kind, $key, $action) {
                $field = in_array($action, ['S', 'X'], true) ? 'rulesets' : 'routes';
                foreach (array_keys($lists[$kind][$field]) as $value) {
                    if (self::exitEntryKey((string) $value) !== $key) continue;
                    if ($action === 'D' || $action === 'X') unset($lists[$kind][$field][$value]);
                    elseif ($field === 'routes') $lists[$kind]['routes'][$value] = empty($lists[$kind]['routes'][$value]) ? 1 : 0;
                    else $lists[$kind]['rulesets'][$value]['on'] = empty($lists[$kind]['rulesets'][$value]['on']) ? 1 : 0;
                    return;
                }
            });
            $this->nodeRoutesMenu($id, $kind, $page);
        } catch (Throwable $e) {
            $this->nodeRoutesMenu($id, $kind, $page, $this->t('Изменение не сохранено. Обновите экран.', 'Change not saved. Refresh the screen.'));
        }
    }

    public function nodeRoutesPrompt(string $id, string $kind, bool $import): void
    {
        $this->exitPrompt($import
            ? $this->t("пришлите файл (.txt или .csv экспорта основного бота) или вставьте записи текстом.\nЗаписи добавятся к имеющимся, повторы пропускаются. Строки <code># off: </code> и <code>запись;0</code> — выключенные записи, <code>set: </code> — наборы .srs/.mrs.",
                "send a file (.txt, or the main bot's .csv export) or paste the entries as text.\nEntries are added to the existing ones, duplicates are skipped. <code># off: </code> and <code>entry;0</code> lines are disabled entries, <code>set: </code> lines are .srs/.mrs sets.")
            : $this->t(<<<'RU'
                пришлите правила одним сообщением. Разделяйте записи переносом строки, запятой или пробелом, например <code>vk.com, keyword:reddit</code>.

                <b>Домены и IP</b>
                Нажмите на префикс, чтобы скопировать его вместе с двоеточием.
                <code>domain:</code> — домен и все его поддомены. Записи <code>domain:vk.com</code> и <code>vk.com</code> равнозначны.
                <code>full:</code> — только точное имя, например <code>full:example.com</code>.
                <code>keyword:</code> — подстрока в имени домена, например <code>keyword:reddit</code>.
                <code>regexp:</code> — регулярное выражение для имени домена, например <code>regexp:\.ru$</code>. Каждое выражение пишите на отдельной строке, чтобы пробелы и запятые остались частью шаблона.
                IPv4, IPv6 и сети CIDR вводите без префикса, например <code>192.0.2.0/24</code> или <code>2001:db8::1</code>.

                <b>Категории из .dat</b>
                <code>geosite:</code> — группа доменов, например <code>geosite:youtube</code>.
                <code>geoip:</code> — группа IP-адресов, например <code>geoip:cn</code>.
                Свой файл .dat сначала добавьте в <b>routes → dat</b> основного бота. Используйте имя файла и категорию из него.
                <code>ext:</code> — домены, например <code>ext:dlc.dat:github</code>.
                <code>extip:</code> — IP-адреса, например <code>extip:zkeenip.dat:akamai</code>.

                <b>Наборы .srs и .mrs</b>
                <code>set:</code> — для .srs или доменного .mrs. Для .mrs с IP-подсетями скопируйте <code>set: ipcidr</code>. После префикса поставьте пробел и вставьте HTTPS-ссылку на файл. Каждый набор пишите на отдельной строке.
                RU, <<<'EN'
                send the rules in one message. Separate entries with a new line, comma or space, for example <code>vk.com, keyword:reddit</code>.

                <b>Domains and IPs</b>
                Tap a prefix to copy it with the colon.
                <code>domain:</code> matches a domain and all its subdomains. <code>domain:vk.com</code> and <code>vk.com</code> are equivalent.
                <code>full:</code> matches the exact hostname, for example <code>full:example.com</code>.
                <code>keyword:</code> matches part of a hostname, for example <code>keyword:reddit</code>.
                <code>regexp:</code> matches a hostname using a regular expression, for example <code>regexp:\.ru$</code>. Put each expression on its own line so spaces and commas stay in the pattern.
                Enter IPv4 or IPv6 addresses and CIDR networks without a prefix, for example <code>192.0.2.0/24</code> or <code>2001:db8::1</code>.

                <b>Categories from .dat files</b>
                <code>geosite:</code> matches a group of domains, for example <code>geosite:youtube</code>.
                <code>geoip:</code> matches a group of IP addresses, for example <code>geoip:cn</code>.
                First add your own .dat file under <b>routes → dat</b> in the main bot. Use its filename and a category from that file.
                <code>ext:</code> matches domains, for example <code>ext:dlc.dat:github</code>.
                <code>extip:</code> matches IP addresses, for example <code>extip:zkeenip.dat:akamai</code>.

                <b>.srs and .mrs rule sets</b>
                <code>set:</code> accepts an .srs file or a domain-based .mrs file. For an .mrs file containing IP networks, copy <code>set: ipcidr</code>. Follow the prefix with a space and the HTTPS URL of the file. Put each set on its own line.
                EN),
            'saveNodeRoutes', [$id, $kind]);
    }

    /** Main-bot exports write “entry;1” and “entry;0”; translate them to the route format. */
    private static function nodeRoutesImportText(string $text): string
    {
        $lines = [];
        foreach (preg_split('~\R~', $text) as $line) {
            $trim = trim($line);
            if ($trim !== '' && !str_starts_with($trim, '#') && !preg_match('~^set:~i', $trim) && preg_match('~^(.*);([01]?)$~s', $trim, $m)) {
                // Like the main bot: older exports wrote a disabled entry with an empty flag.
                $line = ($m[2] === '1' ? '' : '# off: ') . trim($m[1]);
            }
            $lines[] = $line;
        }
        return implode("\n", $lines);
    }

    public function saveNodeRoutes($text, $id, $kind): void
    {
        $id = (string) $id; $kind = (string) $kind; $text = (string) $text;
        if (!in_array($kind, self::NODE_ROUTE_KINDS, true)) return;
        if (trim($text) === '' && !empty($this->input['file_id'])) {
            $text = $this->exitImportDownload();
            if ($text === null || !mb_check_encoding($text, 'UTF-8')) { $this->nodeRoutesMenu($id, $kind, 0, $this->t('Файл не прочитан (нужен текст UTF-8 до 2 МБ)', 'File not read (UTF-8 text up to 2 MB is needed)')); return; }
        }
        [$routes, $sets, $bad] = $this->exitImportParse(self::nodeRoutesImportText($text));
        // The node core rejects the whole configuration for one broken pattern; check new patterns with the same core.
        $patterns = array_values(array_filter(array_map('strval', array_keys($routes)), static fn($entry) => str_starts_with(strtolower($entry), 'regexp:')));
        if ($patterns && !$this->exitRulesetCoreAccepts($patterns)) {
            foreach ($patterns as $pattern) if (!$this->exitRulesetCoreAccepts([$pattern])) { unset($routes[$pattern]); $bad++; }
        }
        if (!$routes && !$sets) { $this->nodeRoutesMenu($id, $kind, 0, $this->t('Записей не найдено', 'No entries found') . ($bad ? $this->t(", неверных строк: $bad", ", invalid lines: $bad") : '')); return; }
        $added = $skipped = $setsAdded = 0;
        try {
            $this->nodeRoutesWrite($id, function (array &$lists) use ($kind, $routes, $sets, &$added, &$skipped, &$setsAdded) {
                [$added, $skipped] = $this->exitMergeRoutes($lists[$kind], $routes);
                foreach ($sets as $url => $set) {
                    if (!is_array($set) || isset($lists[$kind]['rulesets'][$url]) || count($lists[$kind]['rulesets']) >= 20) { $skipped++; continue; }
                    $lists[$kind]['rulesets'][$url] = ['on' => empty($set['on']) ? 0 : 1, 'behavior' => ($set['behavior'] ?? 'domain') === 'ipcidr' ? 'ipcidr' : 'domain'];
                    $setsAdded++;
                }
            });
        } catch (Throwable $e) {
            $this->nodeRoutesMenu($id, $kind, 0, $this->t('Записи не сохранены. Обновите экран.', 'Entries not saved. Refresh the screen.'));
            return;
        }
        $this->nodeRoutesMenu($id, $kind, 0, $this->t("записей добавлено $added, наборов $setsAdded", "entries added $added, sets $setsAdded")
            . ($skipped + $bad ? $this->t(', пропущено (повтор или неверная запись): ', ', skipped (duplicate or invalid entry): ') . ($skipped + $bad) : ''));
    }

    public function nodeRoutesExport(string $id, string $kind): void
    {
        $node = $this->managedNodes()[$id] ?? null;
        if (!$node) { $this->managedNodesMenu(); return; }
        $list = $this->nodeRoutesSource($node)[$kind] ?? null;
        if (!$list || (!$list['routes'] && !$list['rulesets'])) { $this->nodeRoutesMenu($id, $kind, 0, $this->t('Экспортировать нечего', 'Nothing to export')); return; }
        $name = trim((string) preg_replace('~[^A-Za-z0-9._-]+~', '_', (string) $node['name']), '_.') ?: $id;
        $text = $this->exitExportText(['name' => $node['name'] . ' · ' . $kind, 'routes' => $list['routes'], 'rulesets' => $list['rulesets']]);
        $this->sendFile($this->input['chat'], new CURLStringFile($text, "node-$kind-$name.txt", 'text/plain'),
            $this->t('Список ноды. Импорт: «📥 Импорт» в списке любой ноды, в маршрутах узла выхода или в списке основного бота.',
                'Node list. Import: 📥 Import in any node list, in exit node routes or in a main-bot list.'));
        $this->nodeRoutesMenu($id, $kind, 0, $this->t('Файл отправлен', 'File sent'));
    }

    public function nodeRoutesClear(string $id, string $kind, bool $confirmed): void
    {
        if (!$confirmed) {
            $this->update($this->input['chat'], $this->input['message_id'], $this->t('Удалить все записи и наборы этого списка?', 'Delete all entries and sets of this list?'),
                [[['text' => $this->t('🧹 Да, очистить', '🧹 Yes, clear'), 'callback_data' => "/nlClrYes $id $kind"]],
                 [['text' => $this->i18n('back'), 'callback_data' => "/nlist $id $kind 0"]]]);
            return;
        }
        try {
            $this->nodeRoutesWrite($id, static function (array &$lists) use ($kind) { $lists[$kind] = ['routes' => [], 'rulesets' => []]; });
            $this->nodeRoutesMenu($id, $kind);
        } catch (Throwable $e) {
            $this->nodeRoutesMenu($id, $kind, 0, $this->t('Список не очищен. Обновите экран.', 'The list was not cleared. Refresh the screen.'));
        }
    }

    /** Sends both lists with the current settings (and the pending settings draft, if any). */
    public function nodeRoutesApply(string $id, string $kind): void
    {
        try {
            $node = $this->managedNodes()[$id] ?? null;
            if (!$node || empty($node['connected']) || $node['job']) throw new RuntimeException('Node is not ready');
            $this->managedNodeSubmit($id, 'configure', $node['draft'] ?? $node['status']['options'], isset($node['draft']) ? ($node['draft_generation'] ?? null) : null);
            $this->managedNodeMenu($id);
        } catch (Throwable $e) {
            $this->nodeRoutesMenu($id, $kind, 0, $this->nodeRoutesError($e) ?: $this->t('Не применено: нода занята, не на связи или отклонила изменение.',
                'Not applied: the node is busy, offline or rejected the change.'));
        }
    }
}
