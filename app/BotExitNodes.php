<?php

require_once __DIR__ . '/ExitNodeLink.php';

// Узлы выхода: выбранные домены выбранных пользователей Xray уходят не в
// интернет с этого сервера, а через другой сервер с vpnbot («узел»), например
// ради другой страны выхода. Маршрут выбирает сервер по пользователю (email) и
// домену (sniffing), поэтому клиентам — Xray, sing-box, Mihomo, Shadowrocket —
// ничего настраивать не нужно.
//
// Устройство:
//  - узел — ссылка пользователя другого бота («Профиль для узла», служебная
//    учётка без срока и лимита); ссылка разбирается строго (ExitNodeLink);
//  - для каждого включённого узла в xray.json: выход vpnbot-exit-<id>,
//    балансировщик с тем же тегом (random + observatory; при отказе узла —
//    fallbackTag direct либо block), служебный SOCKS-вход проверки на 127.0.0.1 внутри xr
//    и правила vpnbot:exit:<id>:* с полем user — только для пользователей, у
//    которых узел включён (client.exit = [id…]);
//  - локальный IPv6 использует выделенный freedom без балансировщика и fallback;
//  - порядок: защитные правила и торренты → блок-лист → узлы → WARP → свои
//    правила; блокировка всегда старше узла;
//  - всё своё помечено префиксами и снимается перед каждой сборкой: удалённый
//    или выключенный узел не оставляет в конфиге ничего.
trait BotExitNodes
{
    public const EXIT_TAG = 'vpnbot-exit-';
    public const EXIT_PROBE_TAG = 'vpnbot-exit-probe-';
    public const EXIT_RULE = 'vpnbot:exit:';
    public const EXIT_UNAVAILABLE = 'vpnbot:exit:unavailable:';
    public const EXIT_PROBE_PORT = 10870;
    public const EXIT_MAX = 8;
    public const EXIT_IPV6_SOURCE = 'fd42:7662:6::9';
    public const EXIT_IPV6_TAG = 'vpnbot-exit-local-ipv6';
    public const EXIT_PROBE_URL = 'https://www.gstatic.com/generate_204';
    // burstObservatory: 3 пробы за 30 с в случайные моменты, окно живости 60 с.
    // Узел «мёртв», только если в окне отказали ВСЕ пробы (обычная observatory
    // хоронит после одной потерянной пробы — YouTube дёргался бы на прямой выход).
    public const EXIT_PING = ['destination' => self::EXIT_PROBE_URL, 'interval' => '10s', 'sampling' => 3, 'timeout' => '5s'];
    public const EXIT_RULESET_DIR = '/logs/exit-rulesets';
    public const EXIT_RULESET_MAX_BYTES = 16 * 1024 * 1024;
    public const EXIT_RULESET_MAX_ENTRIES = 200000;
    // Версия разбора наборов: при её смене кэш разбирается заново, даже если
    // файл источника не изменился.
    public const EXIT_RULESET_PARSER = 2;
    // Домены YouTube без зависимости от geosite.dat (кнопка «YouTube»).
    public const EXIT_YOUTUBE = ['domain:youtube.com', 'domain:googlevideo.com', 'domain:ytimg.com', 'domain:ggpht.com',
        'domain:youtu.be', 'domain:youtube-nocookie.com', 'domain:youtubei.googleapis.com', 'domain:youtubekids.com',
        'domain:yt.be', 'domain:youtube.googleapis.com', 'domain:wide-youtube.l.google.com'];
    // Готовые наборы сервисов (кнопка «Сервисы»): домены без geosite.dat.
    // Ключ — в данных кнопки, поэтому короткий.
    public const EXIT_PRESETS = [
        'yt' => ['YouTube', self::EXIT_YOUTUBE],
        'openai' => ['ChatGPT / OpenAI', ['domain:openai.com', 'domain:chatgpt.com', 'domain:chat.com', 'domain:oaistatic.com',
            'domain:oaiusercontent.com', 'domain:sora.com', 'full:openaiapi-site.azureedge.net', 'full:production-openaicom-storage.azureedge.net',
            'full:chatgpt.livekit.cloud', 'full:host.livekit.cloud', 'full:turn.livekit.cloud']],
        'gemini' => ['Gemini', ['domain:gemini.google.com', 'domain:gemini.google', 'domain:bard.google.com', 'domain:aistudio.google.com',
            'domain:generativelanguage.googleapis.com', 'domain:alkalimakersuite-pa.clients6.google.com', 'domain:makersuite.google.com',
            'domain:ai.google.dev', 'domain:notebooklm.google.com', 'domain:notebooklm.google', 'domain:deepmind.google', 'domain:labs.google',
            'domain:proactivebackend-pa.googleapis.com', 'domain:robinfrontend-pa.googleapis.com']],
        'netflix' => ['Netflix', ['domain:netflix.com', 'domain:netflix.net', 'domain:nflxext.com', 'domain:nflximg.com', 'domain:nflximg.net',
            'domain:nflxso.net', 'domain:nflxvideo.net', 'domain:nflxsearch.net', 'domain:fast.com']],
        'spotify' => ['Spotify', ['domain:spotify.com', 'domain:scdn.co', 'domain:spotifycdn.com', 'domain:spotify.design', 'domain:spoti.fi',
            'domain:spotilocal.com', 'domain:pscdn.co', 'domain:spotify.link', 'domain:byspotify.com', 'domain:spotifycharts.com',
            'full:audio-ak-spotify-com.akamaized.net', 'full:audio4-ak-spotify-com.akamaized.net', 'full:heads-ak-spotify-com.akamaized.net',
            'full:heads4-ak-spotify-com.akamaized.net']],
        'discord' => ['Discord', ['domain:discord.com', 'domain:discord.gg', 'domain:discordapp.com', 'domain:discordapp.net', 'domain:discord.media',
            'domain:discordcdn.com', 'domain:discord.dev', 'domain:discord.new', 'domain:discord.gift', 'domain:discordstatus.com', 'domain:dis.gd',
            'domain:discord.co']],
        'insta' => ['Instagram', ['domain:instagram.com', 'domain:cdninstagram.com', 'domain:instagr.am', 'domain:ig.me', 'domain:igcdn.com',
            'domain:igsonar.com', 'domain:fbcdn.net']],
    ];
    // 10 МБ часто заканчивались до разгона TCP между серверами. Объём больше,
    // но время по-прежнему ограничено 20 с на путь (не более 100 МБ за пробу).
    public const EXIT_SPEED_BYTES = 50000000;
    public const EXIT_SPEED_URL = 'https://speed.cloudflare.com/__down?bytes=50000000';

    public static function exitNodeDefaults(): array
    {
        return ['name' => '', 'link' => '', 'kind' => 'remote', 'fallback' => 'direct', 'enabled' => 1, 'quic' => 'block', 'routes' => [], 'rulesets' => [],
            'auto' => 0, 'created' => 0, 'status' => [], 'sub' => '', 'sub_time' => 0, 'sub_error' => '', 'members' => [], 'choice' => 'auto'];
    }

    private static function exitDirectFallback(array $node): bool
    {
        return ($node['fallback'] ?? '') === 'direct'
            && (($node['kind'] ?? '') !== 'group' || in_array($node['choice'] ?? 'auto', ['auto', 'direct'], true));
    }

    /** id => нормализованный узел; порядок вставки задаёт приоритет и порт проверки. */
    public function exitNodes(?array $p = null): array
    {
        $raw = ($p ?? $this->getPacConf())['exits'] ?? [];
        $nodes = [];
        foreach (is_array($raw) ? $raw : [] as $id => $node) {
            // Ключ из одних цифр PHP хранит числом (и json_decode тоже).
            $id = (string) $id;
            if (!preg_match('~^[a-f0-9]{8}$~D', $id) || !is_array($node) || count($nodes) >= self::EXIT_MAX) continue;
            $node += self::exitNodeDefaults();
            $node['name'] = is_string($node['name']) ? $node['name'] : '';
            $node['link'] = is_string($node['link']) ? $node['link'] : '';
            if (!in_array($node['kind'], ['remote', 'ipv6', 'group'], true)) {
                $node['kind'] = 'remote';
                $node['link'] = '';
                $node['fallback'] = 'block';
            }
            // Отсутствующее поле получает legacy direct через defaults выше;
            // неизвестное значение из импорта не должно ослаблять запрет.
            $node['fallback'] = $node['kind'] === 'ipv6' || $node['fallback'] !== 'direct' ? 'block' : 'direct';
            $node['enabled'] = empty($node['enabled']) ? 0 : 1;
            $node['quic'] = $node['quic'] === 'pass' ? 'pass' : 'block';
            $node['auto'] = empty($node['auto']) ? 0 : 1;
            $node['sub'] = $node['kind'] === 'remote' && is_string($node['sub']) && self::exitRulesetUrlValid($node['sub'], false) ? $node['sub'] : '';
            $node['sub_time'] = (int) $node['sub_time'];
            $node['sub_error'] = is_string($node['sub_error']) ? mb_substr($node['sub_error'], 0, 120) : '';
            foreach (['routes', 'rulesets', 'status'] as $field) $node[$field] = is_array($node[$field]) ? $node[$field] : [];
            $node['members'] = array_values(array_unique(array_filter(is_array($node['members']) ? $node['members'] : [],
                static fn($member) => is_string($member) && preg_match('~^[a-f0-9]{8}$~D', $member) && $member !== $id)));
            if (!is_string($node['choice']) || !preg_match('~^(?:auto|direct|[a-f0-9]{8})$~D', $node['choice'])
                || ($node['choice'] === 'direct' && $node['fallback'] !== 'direct')) $node['choice'] = 'block';
            $nodes[$id] = $node;
        }
        return $nodes;
    }

    /** Узлы с флажком «новым пользователям» — их получает новый пользователь Xray. */
    public function exitAutoNodes(?array $p = null): array
    {
        return array_map('strval', array_keys(array_filter($this->exitNodes($p), static fn($node) => !empty($node['auto']))));
    }

    /** Новый id: всегда с буквой, иначе ключ массива станет числом. */
    public static function exitNewId(): string
    {
        do $id = bin2hex(random_bytes(4)); while (!preg_match('~[a-f]~', $id));
        return $id;
    }

    public function exitNodeOutbound(array $node): ?array
    {
        if (($node['kind'] ?? '') === 'group') return ['protocol' => 'blackhole'];
        if (($node['kind'] ?? '') === 'ipv6') return $this->exitIpv6Outbound();
        try {
            return ExitNodeLink::parse($node['link'])['outbound'];
        } catch (InvalidArgumentException $e) {
            return null;
        }
    }

    /** Настройка сети относится к хосту: чужой бэкап не включает IPv6/Docker. */
    protected function exitIpv6Network(): array
    {
        $p = @json_decode((string) @file_get_contents($this->exitIpv6Marker()), true);
        return is_array($p) && ($p['enabled'] ?? false) === true
            && filter_var($p['public'] ?? '', FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) ? $p : [];
    }

    private function exitIpv6Marker(): string
    {
        return dirname($this->pac) . '/ipv6-egress.json';
    }

    // Compose подключает сеть к xr по одному наличию маркера, даже повреждённого:
    // обычный выход закрепляем за IPv4 по тому же признаку, а не по его разбору.
    protected function exitIpv6Attached(): bool
    {
        return is_file($this->exitIpv6Marker());
    }

    public function exitIpv6Outbound(): array
    {
        $blocked = ['0.0.0.0/0', '2001::/23', '2001:db8::/32', '2002::/16', '3fff::/20'];
        $public = $this->exitIpv6Network()['public'] ?? '';
        if (is_string($public) && filter_var($public, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) $blocked[] = $public . '/128';
        return ['protocol' => 'freedom', 'sendThrough' => self::EXIT_IPV6_SOURCE,
            'settings' => ['domainStrategy' => 'ForceIPv6', 'finalRules' => [
                ['action' => 'block', 'ip' => $blocked, 'blockDelay' => 0],
                ['action' => 'allow', 'ip' => ['2000::/3']],
                ['action' => 'block', 'ip' => ['::/0'], 'blockDelay' => 0],
            ]], 'streamSettings' => ['sockopt' => ['domainStrategy' => 'ForceIPv6']]];
    }

    public function exitIpv6Add(): void
    {
        $id = self::exitNewId();
        $error = $this->applyExitNodes(function (array &$p) use ($id) {
            if (count($this->exitNodes($p)) >= self::EXIT_MAX) return 'exit too many';
            foreach ($this->exitNodes($p) as $node) if ($node['kind'] === 'ipv6') return 'exit duplicate';
            $p['exits'][$id] = ['name' => $this->t('IPv6 этого сервера', 'This server IPv6'), 'kind' => 'ipv6',
                'fallback' => 'block', 'quic' => 'pass', 'created' => time()] + self::exitNodeDefaults();
            return '';
        });
        if ($error !== '') { $this->exitNodesMenu($this->exitError($error)); return; }
        $this->exitNodeMenu($id);
    }

    public function exitFallback(string $id): void
    {
        $error = $this->exitEditNode($id, static function (array &$node) {
            if (($node['kind'] ?? '') === 'ipv6') return '';
            $node['fallback'] = ($node['fallback'] ?? 'direct') === 'direct' ? 'block' : 'direct';
            return '';
        });
        $this->exitNodeMenu($id, $error === '' ? '' : $this->exitError($error));
    }

    // Отпечаток учётки в кнопке: номер строки сдвигается при удалении
    // пользователей, и нажатие в старом сообщении переключило бы чужой профиль.
    public static function exitRelayMark(array $client): string
    {
        return substr(hash('sha256', ($client['email'] ?? '') . ':' . ManagedProtocol::xraySource($client)), 0, 16);
    }

    public function exitRelayIpv6(int $i, string $mark = ''): void
    {
        $error = $this->applyExitNodes(static function (array &$p, array &$x) use ($i, $mark) {
            $client = $x['inbounds'][0]['settings']['clients'][$i] ?? null;
            if (!is_array($client) || empty($client['exit_relay']) || !hash_equals(self::exitRelayMark($client), $mark)) return 'exit stale';
            $x['inbounds'][0]['settings']['clients'][$i]['exit_ipv6'] = empty($x['inbounds'][0]['settings']['clients'][$i]['exit_ipv6']) ? 1 : 0;
            return '';
        });
        $this->exitRelayLink($i, $error === '' ? '' : $this->exitError($error));
    }

    public function exitProbePort(string $id, ?array $p = null): ?int
    {
        $index = array_search($id, array_map('strval', array_keys($this->exitNodes($p))), true);
        return $index === false ? null : self::EXIT_PROBE_PORT + $index;
    }

    /** Узлы, включённые пользователю; служебная учётка узла их не получает. */
    public static function exitClientNodes(array $client): array
    {
        if (!empty($client['exit_relay']) || !is_array($client['exit'] ?? null)) return [];
        return array_values(array_unique(array_filter($client['exit'], static fn($id) => is_string($id) && preg_match('~^[a-f0-9]{8}$~D', $id))));
    }

    /** email пользователей основного входа с этим узлом; отключённые (off) не попадают. */
    public function exitNodeEmails(array $c, string $id): array
    {
        $emails = [];
        foreach ($c['inbounds'][0]['settings']['clients'] ?? [] as $client) {
            $email = $client['email'] ?? null;
            if (!is_string($email) || $email === '' || !empty($client['off']) || !in_array($id, self::exitClientNodes($client), true)) continue;
            $emails[] = $email;
        }
        return array_values(array_unique($emails));
    }

    /** Записи маршрута узла: свои + разложенные наборы правил .srs/.mrs. */
    public function exitNodeEntries(array $node): array
    {
        $entries = array_filter($node['routes'], static fn($on) => !empty($on));
        foreach ($node['rulesets'] as $url => $set) {
            if (!is_array($set) || empty($set['on'])) continue;
            foreach ($this->exitRulesetCache((string) $url)['entries'] ?? [] as $entry) $entries[$entry] = 1;
        }
        return $entries;
    }

    /** Без всех селекторов строгого узла нельзя безопасно выбрать запасной маршрут. */
    public function exitNodeRoutesReady(array $node, ?array $entries = null): bool
    {
        return !$this->exitNodeRouteProblems($node, $entries);
    }

    /** Наборы без кэша и записи без .dat или неверные: из-за них маршруты узла не собрать. */
    public function exitNodeRouteProblems(array $node, ?array $entries = null): array
    {
        $problems = [];
        foreach ($node['rulesets'] as $url => $set) {
            if (!is_array($set) || empty($set['on'])) continue;
            $cached = $this->exitRulesetCache((string) $url)['entries'] ?? [];
            if (!is_array($cached) || !$cached) $problems[] = (string) $url;
        }
        foreach (array_keys($entries ?? $this->exitNodeEntries($node)) as $entry) {
            if (!$this->exitRouteEntryReady((string) $entry)) $problems[] = (string) $entry;
        }
        return $problems;
    }

    public function exitRouteEntryReady(string $entry): bool
    {
        $c = $this->classifyRouteEntry($entry);
        if (!$this->routeEntryUsable($c)) return false;
        if (in_array($c['kind'], ['ext', 'extip'], true)) return $this->datFileReady($c['value']);
        if (in_array($c['kind'], ['geosite', 'geoip'], true)) return $this->datFileReady(self::CORE_DAT[$c['kind']]);
        return true;
    }

    // Записи наборов проверены при разборе и правкой не меняются: правке
    // достаточно наличия кэша наборов и готовности собственных записей узла.
    // С $was (узел до правки, уже строгий) кэш перечитывается только у наборов,
    // которые включила сама правка: файлы кэша бывают по несколько МиБ.
    private function exitStrictProblems(array $node, ?array $was = null): array
    {
        if (empty($node['enabled']) || ($node['fallback'] ?? '') !== 'block') return [];
        if ($was !== null && !empty($was['enabled']) && ($was['fallback'] ?? '') === 'block') {
            foreach (array_keys($node['rulesets']) as $url) if (!empty($was['rulesets'][$url]['on'])) unset($node['rulesets'][$url]);
        }
        return $this->exitNodeRouteProblems($node, array_filter($node['routes']));
    }

    /** Строгий узел: скачать недостающие .dat для записей до их сохранения. */
    private function exitFetchDat(array $entries): void
    {
        $sources = [];
        foreach (array_keys(array_filter($this->getPacConf()['datlist'] ?? [])) as $key) {
            if (preg_match('~^([\w.\-]+\.dat):(https://\S+)$~i', (string) $key, $m)) $sources[strtolower(basename($m[1]))] ??= [basename($m[1]), $m[2]];
        }
        $done = [];
        foreach ($entries as $entry => $on) {
            if (!$on || $this->exitRouteEntryReady((string) $entry)) continue;
            $c = $this->classifyRouteEntry((string) $entry);
            if (isset(self::CORE_DAT[$c['kind']])) {
                // Свой источник встроенного имени в реестре главнее (как в datSync).
                $file = self::CORE_DAT[$c['kind']];
                [$file, $url] = $sources[$file] ?? [$file, self::CORE_DAT_URL[$file]];
            } elseif (in_array($c['kind'], ['ext', 'extip'], true) && isset($sources[$name = strtolower(basename(explode(':', $c['value'], 2)[0]))])) {
                [$file, $url] = $sources[$name];
            } else {
                continue;
            }
            if (isset($done[$file])) continue;
            $done[$file] = true;
            $this->datDownload($file, $url);
        }
    }

    // Каталог кэша наборов; в тестах подменяется, чтобы не тронуть /logs сервера.
    protected function exitRulesetDir(): string
    {
        return self::EXIT_RULESET_DIR;
    }

    public function exitRulesetFile(string $key): string
    {
        return $this->exitRulesetDir() . '/' . substr(hash('sha256', $key), 0, 24) . '.json';
    }

    public function exitRulesetCache(string $key): array
    {
        $data = @json_decode((string) @file_get_contents($this->exitRulesetFile($key)), true);
        return is_array($data) && ($data['key'] ?? null) === $key ? $data : [];
    }

    // Выход «напрямую» для запасного пути: первым его не ставим — первый
    // выход в xray служит маршрутом по умолчанию.
    private function ensureDirectOutbound(array &$c): void
    {
        foreach ($c['outbounds'] ?? [] as $o) if (($o['tag'] ?? '') === 'direct') return;
        $c['outbounds'][] = ['protocol' => 'freedom', 'tag' => 'direct'];
    }

    private function exitRestoreFamilyPolicy(array &$c): void
    {
        if (!is_array($c['outbounds'] ?? null)) return;
        $deny = ['action' => 'block', 'ip' => ['::/0'], 'blockDelay' => 0];
        $legacy = (bool) array_filter($c['outbounds'] ?? [], static fn($o) =>
            str_starts_with((string) ($o['tag'] ?? ''), self::EXIT_TAG)
            && ($o['protocol'] ?? '') === 'freedom' && ($o['sendThrough'] ?? '') === self::EXIT_IPV6_SOURCE);
        foreach ($c['outbounds'] as $k => &$o) {
            if (($o['protocol'] ?? '') !== 'freedom' || ($k !== 0 && ($o['tag'] ?? '') !== 'direct')) continue;
            $saved = $o['_vpnbot_ipv4'] ?? null;
            // Миграция прежнего генератора: узнаваемая тройка рядом с нашим
            // IPv6-выходом. Произвольную ручную ForceIPv4 без неё не снимаем.
            if ($saved === null && $legacy && ($o['settings']['domainStrategy'] ?? '') === 'ForceIPv4'
                && ($o['streamSettings']['sockopt']['domainStrategy'] ?? '') === 'ForceIPv4'
                && ($o['settings']['finalRules'][0] ?? null) === $deny) {
                $saved = ['settings' => null, 'sockopt' => null, 'deny6' => null];
            }
            if (!is_array($saved) || array_diff(['settings', 'sockopt', 'deny6'], array_keys($saved))
                || (!is_null($saved['settings']) && !is_string($saved['settings']))
                || (!is_null($saved['sockopt']) && !is_string($saved['sockopt']))
                || (!is_null($saved['deny6']) && !is_int($saved['deny6']))) continue;
            if (($o['settings']['domainStrategy'] ?? 'ForceIPv4') === 'ForceIPv4') {
                if ($saved['settings'] === null) unset($o['settings']['domainStrategy']);
                else $o['settings']['domainStrategy'] = $saved['settings'];
            }
            if (($o['streamSettings']['sockopt']['domainStrategy'] ?? '') === 'ForceIPv4') {
                if ($saved['sockopt'] === null) unset($o['streamSettings']['sockopt']['domainStrategy']);
                else $o['streamSettings']['sockopt']['domainStrategy'] = $saved['sockopt'];
                if (!$o['streamSettings']['sockopt']) unset($o['streamSettings']['sockopt']);
                if (!$o['streamSettings']) unset($o['streamSettings']);
            }
            $rules = array_values(array_filter($o['settings']['finalRules'] ?? [], static fn($r) => $r !== $deny));
            if ($saved['deny6'] !== null) array_splice($rules, max(0, $saved['deny6']), 0, [$deny]);
            $o['settings']['finalRules'] = $rules;
            unset($o['_vpnbot_ipv4']);
        }
        unset($o);
    }

    public static function exitFreedomStrategies(array &$c, string $version): void
    {
        // Старое ядро 26.7.28 без settings.domainStrategy ломает строгий IPv6
        // даже при sockopt: проверено реальными TCP/UDP. Не судим по .env.
        if (!preg_match('~^(\d+\.\d+\.\d+)~', $version, $m) || version_compare($m[1], '26.9.30', '<')) return;
        foreach ($c['outbounds'] ?? [] as $k => $o) {
            if (($o['protocol'] ?? '') !== 'freedom' ||
                (!isset($o['_vpnbot_ipv4']) && !(str_starts_with((string) ($o['tag'] ?? ''), self::EXIT_TAG)
                    && ($o['sendThrough'] ?? '') === self::EXIT_IPV6_SOURCE))) continue;
            $strategy = $o['settings']['domainStrategy'] ?? null;
            if ($strategy !== null && ($o['streamSettings']['sockopt']['domainStrategy'] ?? null) === $strategy
                && !isset($o['settings']['targetStrategy'])) unset($c['outbounds'][$k]['settings']['domainStrategy']);
        }
    }

    public function ensureExitNodes(array &$c, ?array $p = null): void
    {
        $p = $p ?? $this->getPacConf();
        $this->exitRestoreFamilyPolicy($c);
        $own = static fn($tag) => str_starts_with((string) $tag, self::EXIT_TAG);
        $c['outbounds'] = array_values(array_filter($c['outbounds'] ?? [], static fn($o) => !$own($o['tag'] ?? '')));
        $c['inbounds'] = array_values(array_filter($c['inbounds'] ?? [], static fn($i) => !$own($i['tag'] ?? '')));
        $c['routing']['rules'] = array_values(array_filter($c['routing']['rules'] ?? [],
            static fn($r) => !str_starts_with((string) ($r['ruleTag'] ?? ''), self::EXIT_RULE)));
        if (isset($c['routing']['balancers'])) {
            $c['routing']['balancers'] = array_values(array_filter((array) $c['routing']['balancers'], static fn($b) => !$own($b['tag'] ?? '')));
            if (!$c['routing']['balancers']) unset($c['routing']['balancers']);
        }
        // Проверка живости у ядра одна: при observatory и burstObservatory сразу
        // работает только burst. Чужую (из webapp) не трогаем — добавляем в неё
        // точные теги; своя — та, где кроме наших тегов ничего нет.
        $foreign = null;
        foreach (['burstObservatory', 'observatory'] as $block) {
            if (!is_array($c[$block] ?? null)) continue;
            $left = array_values(array_filter((array) ($c[$block]['subjectSelector'] ?? []), static fn($tag) => !$own($tag)));
            if (!$left) { unset($c[$block]); continue; }
            $c[$block]['subjectSelector'] = $left;
            $foreign ??= $block;
        }

        $probe = $rules = $unavailable = [];
        $balanced = [];
        $ipv6 = $this->exitIpv6Attached();
        $relay = [];
        foreach ($c['inbounds'][0]['settings']['clients'] ?? [] as $client) {
            if (!empty($client['exit_relay']) && !empty($client['exit_ipv6']) && empty($client['off']) && !empty($client['email'])) $relay[] = $client['email'];
        }
        if ($relay) {
            $ipv6 = true;
            $c['outbounds'][] = $this->exitIpv6Outbound() + ['tag' => self::EXIT_IPV6_TAG];
            $rules[] = ['type' => 'field', 'ruleTag' => self::EXIT_RULE . 'relay-ipv6', 'user' => array_values(array_unique($relay)), 'outboundTag' => self::EXIT_IPV6_TAG];
        }
        $index = 0;
        $nodes = $this->exitNodes($p);
        foreach ($nodes as $id => $node) {
            $id = (string) $id;
            $port = self::EXIT_PROBE_PORT + $index++;
            if (empty($node['enabled'])) continue;
            $outbound = $this->exitNodeOutbound($node);
            if ($outbound === null && $node['fallback'] !== 'block') continue;
            // Повреждённая ссылка строгой ноды не должна снимать её маршруты.
            $outbound ??= ['protocol' => 'blackhole'];
            $tag = self::EXIT_TAG . $id;
            $ipv6 = $ipv6 || $node['kind'] === 'ipv6';
            $c['outbounds'][] = $outbound + ['tag' => $tag];
            // Вход проверки: узел напрямую, без запасного пути — «Проверить»
            // должен видеть сам узел, а не обход.
            $c['inbounds'][] = ['tag' => self::EXIT_PROBE_TAG . $id, 'listen' => '127.0.0.1', 'port' => $port,
                'protocol' => 'socks', 'settings' => ['auth' => 'noauth', 'udp' => false]];
            $groupTarget = $groupProbe = null;
            if ($node['kind'] === 'group') {
                $members = [];
                foreach ($node['members'] as $member) {
                    $candidate = $nodes[$member] ?? [];
                    if (($candidate['kind'] ?? '') === 'remote' && !empty($candidate['enabled']) && $this->exitNodeOutbound($candidate) !== null) $members[] = self::EXIT_TAG . $member;
                }
                $this->ensureBlockOutbound($c);
                $this->ensureDirectOutbound($c);
                if ($members) {
                    $balanced = array_merge($balanced, $members);
                    $c['routing']['balancers'][] = ['tag' => $tag, 'selector' => $members, 'strategy' => ['type' => 'leastPing'], 'fallbackTag' => $node['fallback']];
                    $c['routing']['balancers'][] = ['tag' => $tag . '-probe', 'selector' => $members, 'strategy' => ['type' => 'leastPing'], 'fallbackTag' => 'block'];
                }
                $groupTarget = $members ? ['balancerTag' => $tag] : ['outboundTag' => $node['fallback']];
                $groupProbe = $members ? ['balancerTag' => $tag . '-probe'] : ['outboundTag' => 'block'];
                if ($node['choice'] !== 'auto') {
                    $selected = self::EXIT_TAG . $node['choice'];
                    $selected = in_array($selected, $members, true) ? $selected : ($node['choice'] === 'direct' && $node['fallback'] === 'direct' ? 'direct' : 'block');
                    $groupTarget = $groupProbe = ['outboundTag' => $selected];
                }
            }
            $probe[] = ['type' => 'field', 'ruleTag' => self::EXIT_RULE . $id . ':probe',
                'inboundTag' => [self::EXIT_PROBE_TAG . $id]] + ($groupProbe ?? ['outboundTag' => $tag]);
            $emails = $this->exitNodeEmails($c, $id);
            $entries = $this->exitNodeEntries($node);
            if ($emails && $node['fallback'] === 'block' && !$this->exitNodeRoutesReady($node, $entries)) {
                $unavailable[] = ['type' => 'field', 'ruleTag' => self::EXIT_UNAVAILABLE . $id,
                    'user' => $emails, 'outboundTag' => 'block'];
                continue;
            }
            $x = $this->listToXrayRules($entries);
            if (!$emails || (!$x['domain'] && !$x['ip'])) continue;
            $target = $groupTarget ?? ['outboundTag' => $tag];
            if ($node['kind'] === 'remote' && $outbound['protocol'] !== 'blackhole') {
                $c['routing']['balancers'][] = ['tag' => $tag, 'selector' => [$tag], 'strategy' => ['type' => 'random'], 'fallbackTag' => $node['fallback']];
                $target = ['balancerTag' => $tag];
                $balanced[] = $tag;
            }
            // QUIC к доменам узла режем: браузер сразу переходит на TCP, и тот
            // идёт через узел (QUIC внутри TCP-туннеля к тому же медленнее).
            if ($node['quic'] === 'block') {
                foreach (['domain', 'ip'] as $field) if ($x[$field]) $rules[] = ['type' => 'field', 'ruleTag' => self::EXIT_RULE . "$id:quic-$field",
                    'user' => $emails, $field => $x[$field], 'network' => 'udp', 'port' => '443', 'outboundTag' => 'block'];
            }
            foreach (['domain', 'ip'] as $field) if ($x[$field]) $rules[] = ['type' => 'field', 'ruleTag' => self::EXIT_RULE . "$id:$field",
                'user' => $emails, $field => $x[$field]] + $target;
        }
        $rules = array_merge($unavailable, $rules);
        if ($rules) {
            $this->ensureBlockOutbound($c);
            $this->ensureDirectOutbound($c);
            // Ниже блок-листа и правила торрентов (ensureTorrentBlock ставит его
            // в голову раньше нас): блокировка старше узла.
            $position = 0;
            foreach ($c['routing']['rules'] as $k => $rule) {
                if (str_starts_with((string) ($rule['ruleTag'] ?? ''), 'vpnbot:routes:block:')
                    || (($rule['outboundTag'] ?? '') === 'block' && (array) ($rule['protocol'] ?? []) === ['bittorrent'])) $position = $k + 1;
            }
            array_splice($c['routing']['rules'], $position, 0, $rules);
        }
        if ($probe) array_unshift($c['routing']['rules'], ...$probe);
        if ($ipv6) {
            // Добавление IPv6-интерфейса не меняет обычный прямой выход.
            $this->ensureFreedomCompat($c);
            foreach ($c['outbounds'] as $k => &$o) {
                if (($o['protocol'] ?? '') !== 'freedom' || ($k !== 0 && ($o['tag'] ?? '') !== 'direct')) continue;
                $strategy = $o['settings']['domainStrategy'] ?? 'AsIs';
                if (!in_array($strategy, ['AsIs', 'ForceIPv4'], true)) continue;
                $deny6 = ['action' => 'block', 'ip' => ['::/0'], 'blockDelay' => 0];
                $oldDeny = array_search($deny6, $o['settings']['finalRules'], true);
                $o['_vpnbot_ipv4'] = ['settings' => $o['settings']['domainStrategy'] ?? null,
                    'sockopt' => $o['streamSettings']['sockopt']['domainStrategy'] ?? null,
                    'deny6' => $oldDeny === false ? null : $oldDeny];
                $o['settings']['domainStrategy'] = 'ForceIPv4';
                $o['streamSettings']['sockopt']['domainStrategy'] = 'ForceIPv4';
                $o['settings']['finalRules'] = array_values(array_filter($o['settings']['finalRules'], static fn($r) => $r !== $deny6));
                array_unshift($o['settings']['finalRules'], $deny6);
            }
            unset($o);
        }
        if ($balanced) {
            if ($foreign !== null) {
                $c[$foreign]['subjectSelector'] = array_values(array_unique(array_merge($c[$foreign]['subjectSelector'], $balanced)));
            } else {
                $c['burstObservatory'] = ['subjectSelector' => array_values(array_unique($balanced)), 'pingConfig' => self::EXIT_PING];
            }
        }
    }

    /**
     * Изменение узлов одной транзакцией: $edit правит pac (и при нужде xray.json
     * через второй аргумент) и возвращает код ошибки или ''. Ядро не приняло
     * конфиг — прежние pac.json и xray.json остаются.
     */
    public function applyExitNodes(callable $edit): string
    {
        return $this->withLock('xray', function () use ($edit) {
            return $this->withLock('pac', function () use ($edit) {
                $p = $this->getPacConf();
                $x = $this->getXray();
                if (!is_array($p) || !is_array($x)) return 'exit save failed';
                $oldPac = $p;
                $oldXray = $x;
                $error = $edit($p, $x);
                if (is_string($error) && $error !== '') return $error;
                if ($p === $oldPac && $x === $oldXray) return '';
                if ($p !== $oldPac && $this->setPacConf($p) === false) return 'exit save failed';
                if ($this->restartXray($x) === false) {
                    if ($p !== $oldPac) $this->setPacConf($oldPac);
                    return 'exit check failed';
                }
                return '';
            }, 20, 'exit save failed');
        }, 20, 'exit save failed');
    }

    // ── Состояние и проверка узла ───────────────────────────────────────────
    public const EXIT_STATUS_FILE = '/config/exit-nodes.status.json';
    public const EXIT_CRON_PERIOD = 300;
    private int $exitCronAt = 0;
    // Записи, из-за которых exitEditNode отклонил правку строгого узла.
    private array $exitNotReady = [];

    public function exitStatus(): array
    {
        $data = @json_decode((string) @file_get_contents(self::EXIT_STATUS_FILE), true);
        return is_array($data) ? $data : [];
    }

    // Файл общий для php и cron; в тестах подменяется, чтобы не тронуть /config сервера.
    protected function exitStatusWrite(string $id, array $status): void
    {
        $this->withLock('exit-status', function () use ($id, $status) {
            $all = $this->exitStatus();
            $all[$id] = $status;
            $all = array_intersect_key($all, $this->exitNodes() + [$id => 1]);
            $tmp = self::EXIT_STATUS_FILE . '.tmp';
            if (@file_put_contents($tmp, json_encode($all, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) !== false) @rename($tmp, self::EXIT_STATUS_FILE);
            return true;
        }, 5, false);
    }

    /**
     * Проба через служебный вход узла внутри xr: generate_204 (жив ли узел,
     * задержка), cdn-cgi/trace (страна и адрес выхода) и, если $full, страна,
     * которую видит YouTube (INNERTUBE_CONTEXT_GL). В команде нет секретов
     * узла — ssh() при отказе пишет её в журнал.
     */
    public function exitProbe(string $id, bool $full = true): array
    {
        $port = $this->exitProbePort($id);
        $node = $this->exitNodes()[$id] ?? null;
        if ($port === null || $node === null) return ['time' => time(), 'ok' => false, 'error' => 'not found'];
        if (empty($node['enabled'])) return ['time' => time(), 'ok' => false, 'error' => 'disabled'];
        $out = (string) $this->ssh($this->exitProbeCommand($node, $port, $full), 'xr');
        return $this->exitProbeResult($id, $node, $full, $out, $this->sshFailed);
    }

    private function exitProbeCommand(array $node, int $port, bool $full): string
    {
        $proxy = "127.0.0.1:$port";
        // Задержка — время до первого байта generate_204 через узел: time_connect
        // при --socks5-hostname — это подключение к самому входу на 127.0.0.1.
        // Узел не ответил — остальные запросы не делаем (иначе мёртвый узел
        // держал шаг cron ~36 с), а проверяем, открывается ли TCP до его
        // адреса: так видно, лежит ли сервер или он отклоняет подключение.
        $more = "c https://www.cloudflare.com/cdn-cgi/trace | grep -E '^(ip|loc)='; ";
        if ($full) {
            $more .= "c -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36' "
                . "-H 'Accept-Language: en-US,en;q=0.9' https://www.youtube.com/ | head -c 3000000 "
                . "| grep -o '\"INNERTUBE_CONTEXT_GL\":\"[A-Z]*\"' | head -n 1; ";
        }
        $tcp = 'true';
        if (($node['kind'] ?? '') !== 'ipv6') {
            try {
                $parsed = ExitNodeLink::parse($node['link']);
                $tcp = 'if nc -z -w 4 ' . escapeshellarg($parsed['address']) . ' ' . (int) $parsed['port'] . ' 2>/dev/null; then echo tcp=1; else echo tcp=0; fi';
            } catch (InvalidArgumentException $e) {
            }
        }
        $cmd = "c(){ curl -s --socks5-hostname $proxy --max-time 12 \"\$@\"; }; "
            . "r=\$(c -o /dev/null -w 'probe=%{http_code} %{time_starttransfer}' " . self::EXIT_PROBE_URL . "); printf '%s\\n' \"\$r\"; "
            . "case \"\$r\" in probe=204*) $more;; *) $tcp;; esac; ";
        return $cmd . 'true';
    }

    private function exitProbeResult(string $id, array $node, bool $full, string $out, bool $failed): array
    {
        $status = ['time' => time(), 'ok' => false];
        if ($failed) { $status['error'] = 'xray'; $out = ''; }
        if (preg_match('~^probe=(\d{3}) ([0-9.]+)$~m', $out, $m)) {
            $status['http'] = (int) $m[1];
            $status['ms'] = (int) round((float) $m[2] * 1000);
            $status['ok'] = $status['http'] === 204;
        }
        if (preg_match('~^loc=([A-Z]{2})$~m', $out, $m)) $status['loc'] = $m[1];
        if (preg_match('~^ip=([0-9a-fA-F:.]{2,45})$~m', $out, $m)) $status['ip'] = $m[1];
        if (!$failed && ($node['kind'] ?? '') === 'ipv6' && !filter_var($status['ip'] ?? '', FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $status['ok'] = false;
            $status['error'] = 'ipv6';
        }
        $expected = $this->exitIpv6Network()['public'] ?? '';
        if (!$failed && ($node['kind'] ?? '') === 'ipv6' && $expected !== '' && @inet_pton($expected) !== @inet_pton($status['ip'] ?? '')) {
            $status['ok'] = false;
            $status['error'] = 'ipv6 source';
        }
        if (preg_match('~"INNERTUBE_CONTEXT_GL":"([A-Z]{2})"~', $out, $m)) $status['gl'] = $m[1];
        if ($full) $status['full'] = 1;
        if (preg_match('~^tcp=([01])$~m', $out, $m)) $status['tcp'] = (int) $m[1];
        if (!$status['ok'] && empty($status['error'])) {
            $status['error'] = ($status['tcp'] ?? null) === 0 ? 'tcp' : (!empty($status['http']) ? 'http:' . $status['http'] : 'no answer');
        }
        $previous = $this->exitStatus()[$id] ?? [];
        // Страна YouTube из полной проверки живёт до следующей полной.
        if (!$full && isset($previous['gl'])) $status['gl'] = $previous['gl'];
        // Время полной проверки: cron делает её раз в сутки (сигнал о смене
        // страны YouTube), отказ YouTube тоже считается попыткой.
        $status['full_time'] = $full ? $status['time'] : (int) ($previous['full_time'] ?? 0);
        $status['hist'] = self::exitHistoryAdd($previous['hist'] ?? [], $status['time'], $status['ok']);
        $this->exitStatusWrite($id, $status);
        return $status;
    }

    /** Не больше четырёх проб одновременно; вывод каждого узла изолирован. */
    public function exitProbeMany(array $requests): array
    {
        if (count($requests) <= 1) {
            $result = [];
            foreach ($requests as $id => $full) $result[(string) $id] = $this->exitProbe((string) $id, (bool) $full);
            return $result;
        }
        $nodes = $this->exitNodes();
        $commands = $result = [];
        foreach ($requests as $id => $full) {
            $id = (string) $id;
            $port = $this->exitProbePort($id);
            if (!preg_match('~^[a-f0-9]{8}$~D', $id) || $port === null || empty($nodes[$id]['enabled'])) {
                $result[$id] = ['time' => time(), 'ok' => false, 'error' => 'disabled'];
                continue;
            }
            $commands[$id] = $this->exitProbeCommand($nodes[$id], $port, (bool) $full);
        }
        foreach (array_chunk($commands, 4, true) as $batch) {
            // mktemp 0700, результаты не в общем /logs. trap удаляет только
            // созданный каталог; адреса/ключи узлов в вывод не попадают.
            $cmd = 'umask 077; d=$(mktemp -d /tmp/vpnbot-exit-probe.XXXXXX) || exit 1; '
                . 'trap \'rm -rf "$d"\' EXIT; ';
            foreach ($batch as $id => $probe) $cmd .= '( ' . $probe . ' ) > "$d/' . $id . '" 2>/dev/null & ';
            $cmd .= 'wait; ';
            foreach ($batch as $id => $_) $cmd .= 'printf "BEGIN ' . $id . '\\n"; cat "$d/' . $id . '"; printf "\\nEND ' . $id . '\\n"; ';
            $out = (string) $this->ssh($cmd, 'xr');
            $failed = $this->sshFailed;
            foreach ($batch as $id => $_) {
                $found = preg_match('~^BEGIN ' . $id . '\n(.*?)\nEND ' . $id . '$~ms', $out, $m) === 1;
                $result[$id] = $this->exitProbeResult((string) $id, $nodes[$id], (bool) $requests[$id], $found ? $m[1] : '', $failed || !$found);
            }
        }
        return $result;
    }

    // История доступности: [время, 1|0] каждой пробы за последние сутки.
    public const EXIT_HISTORY_SECONDS = 86400;
    public const EXIT_GL_PERIOD = 86400;

    public static function exitHistoryAdd($hist, int $time, bool $ok): array
    {
        $hist = array_values(array_filter(is_array($hist) ? $hist : [], static fn($h) => is_array($h) && count($h) === 2
            && is_int($h[0]) && $h[0] > $time - self::EXIT_HISTORY_SECONDS && $h[0] <= $time));
        $hist[] = [$time, $ok ? 1 : 0];
        return $hist;
    }

    /** «Доступность за 24 ч: 99,3 % (287 проверок) · сбои: 12:05–12:20, 18:40» или ''. */
    public function exitHistoryLine(array $status): string
    {
        $hist = array_values(array_filter((array) ($status['hist'] ?? []), static fn($h) => is_array($h) && count($h) === 2
            && (int) $h[0] > time() - self::EXIT_HISTORY_SECONDS));
        if (!$hist) return '';
        $ok = count(array_filter($hist, static fn($h) => !empty($h[1])));
        $pct = number_format($ok * 100 / count($hist), 1, $this->language === 'en' ? '.' : ',', '');
        $n = count($hist);
        $line = $this->t("Доступность за 24 ч: $pct % (проверок: $n)", "Availability over 24 h: $pct % (checks: $n)");
        // Подряд идущие отказы — один сбой «начало–конец».
        $outages = [];
        foreach ($hist as $k => [$time, $up]) {
            if ($up) continue;
            if ($k > 0 && empty($hist[$k - 1][1]) && $outages) $outages[count($outages) - 1][1] = (int) $time;
            else $outages[] = [(int) $time, (int) $time];
        }
        if ($outages) {
            $shown = array_map(static fn($o) => date('H:i', $o[0]) . ($o[1] !== $o[0] ? '–' . date('H:i', $o[1]) : ''), array_slice($outages, -3));
            $line .= $this->t(' · последние сбои: ', ' · last outages: ') . implode(', ', $shown);
        }
        return $line;
    }

    // В файлах состояния — коды ошибок, текст на языке интерфейса подставляется
    // при показе (язык бота могли сменить после пробы). Старые файлы с
    // готовым текстом показываются как есть.
    public function exitErrorText(string $code): string
    {
        if (str_starts_with($code, 'http:')) return $this->t('узел ответил ', 'node answered ') . substr($code, 5);
        return match ($code) {
            'not found' => $this->t('узел не найден', 'node not found'),
            'disabled' => $this->t('узел выключен', 'node disabled'),
            'xray' => $this->t('нет связи с контейнером Xray', 'no connection to the Xray container'),
            'no answer' => $this->t('узел не ответил', 'node did not answer'),
            'tcp' => $this->t('адрес узла недоступен по TCP: сервер выключен, порт закрыт или адрес сменился', 'the node address is unreachable over TCP: the server is down, the port is closed or the address changed'),
            'ipv6' => $this->t('выход через IPv6 не подтверждён', 'IPv6 egress was not verified'),
            'ipv6 source' => $this->t('выходной IPv6 отличается от настроенного', 'egress IPv6 differs from the configured address'),
            'download' => $this->t('не скачался', 'not downloaded'),
            'parse' => $this->t('не разобран', 'not parsed'),
            'empty' => $this->t('пустой', 'empty'),
            'core' => $this->t('не принят ядром Xray', 'rejected by the Xray core'),
            '' => $this->t('не работает', 'not working'),
            default => $code,
        };
    }

    public function exitStatusLine(string $id, array $node): string
    {
        if (empty($node['enabled'])) return $this->t('⏸ выключен', '⏸ disabled');
        $s = $this->exitStatus()[$id] ?? [];
        if (!$s) return $this->t('⚪ ещё не проверялся', '⚪ not checked yet');
        $line = !empty($s['ok']) ? $this->t('🟢 работает', '🟢 working') : '🔴 ' . self::esc($this->exitErrorText((string) ($s['error'] ?? '')));
        // TCP до узла открывается, а прокси не отвечает — почти всегда ссылка
        // устарела (новые ключи, другой транспорт) или узел ограничивает адрес
        // этого сервера своим межсетевым экраном.
        if (empty($s['ok']) && ($s['tcp'] ?? null) === 1) $line .= $this->t(' (TCP до узла есть: проверьте ссылку, список my_server и режим выхода профиля на узле)', ' (TCP to the node works: check the link, the my_server list and the profile egress mode on the node)');
        if (!empty($s['ok'])) $line .= ' · ' . (int) ($s['ms'] ?? 0) . $this->t(' мс', ' ms');
        if (!empty($s['loc'])) $line .= $this->t(' · выход ', ' · exit ') . self::esc($s['loc']);
        if (!empty($s['gl'])) $line .= $this->t(' · YouTube видит ', ' · YouTube sees ') . self::esc($s['gl']);
        if (!empty($s['ip'])) $line .= ' · ' . self::esc($s['ip']);
        return $line . ' · ' . date('H:i', (int) $s['time']);
    }

    // ── Наборы правил .srs (sing-box) и .mrs (Mihomo) ───────────────────────
    // Серверный Xray этих форматов не читает: бот скачивает набор, раскладывает
    // его на записи маршрута (domain:/full:/keyword:/regexp:/IP) инструментами
    // самих ядер из образа php и кладёт в /logs/exit-rulesets. Не в резервную
    // копию: после восстановления наборы скачаются заново.
    public static function exitRulesetUrlValid(string $url, bool $format = true): bool
    {
        $parts = parse_url($url);
        return is_array($parts) && strtolower($parts['scheme'] ?? '') === 'https' && !empty($parts['host'])
            && !isset($parts['user']) && !isset($parts['pass']) && strlen($url) <= ($format ? 500 : 2000) && !preg_match('~[\s"\'\\\\<>]~', $url)
            && (!$format || in_array(self::ruleSetFormat($url), ['srs', 'mrs'], true));
    }

    // Скачивание с ограничением размера; в тестах подменяется.
    protected function exitRulesetDownload(string $url): ?string
    {
        // Переходы по Location — вручную: каждый адрес проверяется на
        // публичность (выпуски GitHub переадресуют на другой хост, а чужой
        // переход мог бы увести запрос во внутреннюю сеть). Проверенные адреса
        // закрепляются за curl: иначе он разрешил бы имя заново, и имя с
        // коротким TTL успело бы указать внутрь (DNS rebinding).
        for ($hop = 0; $hop <= 3; $hop++) {
            $ips = self::exitRulesetUrlValid($url, false) ? $this->safeExtUrlIps($url) : [];
            if (!$ips) return null;
            $parts = parse_url($url);
            $data = '';
            $location = '';
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_RESOLVE => $this->curlResolveEntries((string) $parts['host'], (int) ($parts['port'] ?? 443), $ips),
                CURLOPT_RETURNTRANSFER => false, CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_PROTOCOLS => CURLPROTO_HTTPS, CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
                CURLOPT_CONNECTTIMEOUT => 15, CURLOPT_TIMEOUT => 90,
                CURLOPT_HEADERFUNCTION => static function ($ch, $header) use (&$location) {
                    if (preg_match('~^location:\s*(\S+)~i', $header, $m)) $location = $m[1];
                    return strlen($header);
                },
                CURLOPT_WRITEFUNCTION => static function ($ch, $chunk) use (&$data) {
                    $data .= $chunk;
                    return strlen($data) > self::EXIT_RULESET_MAX_BYTES ? 0 : strlen($chunk);
                },
            ]);
            $ok = curl_exec($ch);
            $code = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            if ($ok !== true) return null;
            if (in_array($code, [301, 302, 303, 307, 308], true) && $location !== '') {
                $url = str_starts_with($location, '/') ? preg_replace('~^(https://[^/]+).*$~', '$1', $url) . $location : $location;
                continue;
            }
            return $code === 200 && $data !== '' ? $data : null;
        }
        return null;
    }

    // Запуск инструмента ядра; в тестах подменяется.
    protected function exitRulesetTool(array $command): bool
    {
        $command = array_merge(['python3', __DIR__ . '/exit_ruleset.py', 'tool'], $command);
        exec('timeout 120 ' . implode(' ', array_map('escapeshellarg', $command)) . ' >/dev/null 2>&1', $out, $code);
        return $code === 0;
    }

    private function exitRulesetNormalize(string $file, string $format): bool
    {
        $command = ['python3', __DIR__ . '/exit_ruleset.py', 'normalize', $file, "$file.safe", $format];
        exec('timeout 30 ' . implode(' ', array_map('escapeshellarg', $command)) . ' >/dev/null 2>&1', $out, $code);
        return $code === 0 && rename("$file.safe", $file);
    }

    /** Разложить содержимое набора в записи маршрута. null — формат не разобран. */
    public function exitRulesetConvert(string $binary, string $format, string $behavior): ?array
    {
        $dir = sys_get_temp_dir() . '/exit-ruleset-' . bin2hex(random_bytes(6));
        if (!@mkdir($dir, 0700)) return null;
        $in = "$dir/in.$format";
        $outFile = "$dir/out";
        try {
            file_put_contents($in, $binary);
            $entries = $ips = [];
            if ($format === 'srs') {
                if (!$this->exitRulesetTool(['sing-box', 'rule-set', 'decompile', $in, '-o', $outFile])) return null;
                if (!$this->exitRulesetNormalize($outFile, $format)) return null;
                $json = json_decode((string) @file_get_contents($outFile), true);
                if (!is_array($json['rules'] ?? null)) return null;
                foreach ($json['rules'] as $rule) {
                    if (!is_array($rule) || isset($rule['type'])) continue; // логические правила не раскладываются
                    foreach ((array) ($rule['domain'] ?? []) as $v) $entries[] = 'full:' . $v;
                    foreach ((array) ($rule['domain_suffix'] ?? []) as $v) $entries[] = 'domain:' . ltrim((string) $v, '.');
                    foreach ((array) ($rule['domain_keyword'] ?? []) as $v) $entries[] = 'keyword:' . $v;
                    foreach ((array) ($rule['domain_regex'] ?? []) as $v) $entries[] = 'regexp:' . $v;
                    foreach ((array) ($rule['ip_cidr'] ?? []) as $v) $ips[] = (string) $v;
                }
            } else {
                if (!in_array($behavior, ['domain', 'ipcidr'], true)) return null;
                if (!$this->exitRulesetTool(['mihomo', 'convert-ruleset', $behavior, 'mrs', $in, $outFile])) return null;
                if (!$this->exitRulesetNormalize($outFile, 'mrs')) return null;
                foreach (preg_split('~\R~', (string) @file_get_contents($outFile)) as $line) {
                    $line = trim($line);
                    if ($line === '' || str_starts_with($line, '#')) continue;
                    if ($behavior === 'ipcidr') $ips[] = $line;
                    elseif (str_starts_with($line, '+.')) $entries[] = 'domain:' . substr($line, 2);
                    elseif (str_starts_with($line, '*.')) $entries[] = 'regexp:^[^.]+\.' . preg_quote(substr($line, 2), '') . '$';
                    elseif (str_starts_with($line, '.')) $entries[] = 'domain:' . substr($line, 1);
                    else $entries[] = 'full:' . $line;
                }
            }
            // Значение из поля подсетей — только IP/CIDR: строка «bad» иначе
            // прошла бы как домен-суффикс.
            foreach ($ips as $ip) if ($this->classifyRouteEntry($ip)['kind'] === 'ip') $entries[] = $ip;
            $result = [];
            foreach ($entries as $entry) {
                $entry = (string) $entry;
                if (!$this->routeEntryUsable($this->classifyRouteEntry($entry))) continue;
                $result[$entry] = true;
                if (count($result) > self::EXIT_RULESET_MAX_ENTRIES) return null;
            }
            return array_keys($result);
        } finally {
            foreach (glob("$dir/*") ?: [] as $file) @unlink($file);
            @rmdir($dir);
        }
    }

    /** Обновить набор правил; при отказе прежний разобранный набор остаётся. */
    public function exitRulesetRefresh(string $url, array $set): string
    {
        $cache = $this->exitRulesetCache($url);
        $format = self::ruleSetFormat($url);
        $behavior = (string) ($set['behavior'] ?? 'domain');
        $parser = self::EXIT_RULESET_PARSER . ":$format:$behavior";
        $binary = self::exitRulesetUrlValid($url) ? $this->exitRulesetDownload($url) : null;
        // Суточное обновление обычно приносит тот же файл: его записи уже
        // разобраны и проверены ядром, распаковывать заново незачем.
        $same = $binary !== null && ($cache['error'] ?? '') === '' && !empty($cache['entries'])
            && ($cache['parser'] ?? '') === $parser && hash('sha256', $binary) === ($cache['hash'] ?? '');
        $entries = $binary === null ? null : ($same ? $cache['entries'] : $this->exitRulesetConvert($binary, $format, $behavior));
        $error = $binary === null ? 'download' : ($entries === null ? 'parse' : (!$entries ? 'empty' : ''));
        // Записи набора попадают в каждую сборку конфига: битая регулярка из
        // чужого источника сделала бы так, что ядро отвергает любое изменение
        // Xray. Всё, что разобрано заново, сначала проверяет выбранное ядро —
        // и новый файл, и прежний файл после смены версии разбора или типа.
        if ($error === '' && !$same && !$this->exitRulesetCoreAccepts($entries)) $error = 'core';
        $cache = ['key' => $url, 'time' => time(), 'error' => $error]
            + ($error === '' ? ['entries' => $entries, 'hash' => hash('sha256', $binary), 'parser' => $parser]
                : ['entries' => $cache['entries'] ?? [], 'hash' => $cache['hash'] ?? '', 'parser' => $cache['parser'] ?? '']);
        @mkdir($this->exitRulesetDir(), 0700, true);
        $file = $this->exitRulesetFile($url);
        if (@file_put_contents("$file.tmp", json_encode($cache, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)) !== false) @rename("$file.tmp", $file);
        return $error;
    }

    public function exitRulesetCoreAccepts(array $entries): bool
    {
        $x = $this->listToXrayRules(array_fill_keys($entries, 1));
        $rules = [];
        foreach (['domain', 'ip'] as $field) if ($x[$field]) $rules[] = ['type' => 'field', $field => $x[$field], 'outboundTag' => 'direct'];
        return $this->validateXrayConfig(['outbounds' => [['protocol' => 'freedom', 'tag' => 'direct']], 'routing' => ['rules' => $rules]]);
    }

    /** Обновить наборы узла, которым пора (или все при $force); true — записи изменились. */
    public function exitRefreshRulesets(string $id, bool $force = false): bool
    {
        $node = $this->exitNodes()[$id] ?? null;
        if ($node === null) return false;
        $changed = false;
        foreach ($node['rulesets'] as $url => $set) {
            if (!is_array($set) || empty($set['on'])) continue;
            $cache = $this->exitRulesetCache((string) $url);
            // Неудачная попытка повторяется через час, а не через сутки.
            $interval = ($cache['error'] ?? '') !== '' ? 3600 : max(3600, (int) ($set['interval'] ?? 86400));
            if (!$force && $cache && time() - (int) ($cache['time'] ?? 0) < $interval) continue;
            // Записи меняются и без нового файла: разбор заново другой версией
            // или с другим типом набора.
            $mark = static fn(array $c) => ($c['hash'] ?? '') . '|' . ($c['parser'] ?? '');
            $before = $mark($cache);
            $this->exitRulesetRefresh((string) $url, $set);
            if ($mark($this->exitRulesetCache((string) $url)) !== $before) $changed = true;
        }
        return $changed;
    }

    // ── Cron: здоровье узлов и обновление наборов ───────────────────────────
    public function checkExitNodes(): void
    {
        if ($this->exitCronAt && time() - $this->exitCronAt < self::EXIT_CRON_PERIOD) return;
        $this->exitCronAt = time();
        $nodes = array_filter($this->exitNodes(), static fn($node) => !empty($node['enabled']));
        if (!$nodes) return;
        $previous = $this->exitStatus();
        $requests = [];
        foreach ($nodes as $id => $_) $requests[$id] = time() - (int) ($previous[$id]['full_time'] ?? 0) >= self::EXIT_GL_PERIOD;
        $probes = $this->exitProbeMany($requests);
        $restart = false;
        foreach ($nodes as $id => $node) {
            $id = (string) $id;
            $before = $previous[$id] ?? [];
            // Раз в сутки — полная проверка со страной YouTube.
            $full = $requests[$id];
            $now = $probes[$id];
            $name = self::esc($node['name'] !== '' ? $node['name'] : $id);
            // Подписка узла: по расписанию и сразу после отказа — вдруг на узле
            // сменили ключи. Новая ссылка применяется сразу и проверяется.
            if ($node['sub'] !== '' && (empty($now['ok']) || time() - $node['sub_time'] >= self::EXIT_SUB_PERIOD) && $this->exitSubRefresh($id)) {
                $this->notifyAdmins($this->t('🔄 Ссылка узла выхода обновлена по его подписке: ', '🔄 The exit node link was updated from its subscription: ') . $name);
                $now = $this->exitProbe($id, $full);
            }
            if ($before && !empty($before['ok']) !== !empty($now['ok'])) {
                $this->notifyAdmins((!empty($now['ok']) ? $this->t('🟢 Узел выхода снова работает: ', '🟢 Exit node is working again: ')
                    : (!self::exitDirectFallback($node) ? $this->t('🔴 Узел выхода не отвечает, его назначения блокируются (запасного выхода нет): ', '🔴 Exit node is not responding; its destinations are blocked (no fallback): ')
                        : $this->t('🔴 Узел выхода не отвечает, трафик идёт напрямую: ', '🔴 Exit node is not responding, traffic goes direct: ')))
                    . $name);
            }
            // Страна, которую видит YouTube, сменилась: видео и рекомендации
            // пойдут по другой стране, хотя узел работает.
            if ($full && !empty($before['gl']) && !empty($now['gl']) && $before['gl'] !== $now['gl']) {
                $this->notifyAdmins($this->t('🌐 Через узел ', '🌐 Through node ') . $name . $this->t(' YouTube теперь видит страну ', ' YouTube now sees country ')
                    . self::esc($now['gl']) . $this->t(' (было ', ' (was ') . self::esc($before['gl']) . ')');
            }
            $restart = $this->exitRefreshRulesets($id) || $restart;
        }
        if ($restart) {
            $this->withLock('xray', fn() => $this->restartXray($this->getXray()), 20, false);
        }
    }

    // ── Меню ───────────────────────────────────────────────────────────────
    public const EXIT_PAGE = 10;

    public static function exitEntryKey(string $entry): string
    {
        return substr(hash('sha256', 'exit-entry:' . $entry), 0, 10);
    }

    private function exitName(string $id, array $node): string
    {
        return self::esc($node['name'] !== '' ? $node['name'] : $id);
    }

    private function exitWarnings(array $node): array
    {
        $p = $this->getPacConf();
        $warnings = [];
        if (!empty($node['enabled']) && ($node['fallback'] ?? '') === 'block' && !$this->exitNodeRoutesReady($node)) {
            $warnings[] = $this->t('⛔ Не готовы правила строгого узла: нет набора/.dat или есть неверная запись. Трафик назначенных пользователей временно блокируется целиком. Восстановите наборы или явно выключите узел.', '⛔ Strict node rules are unavailable: a set/.dat is missing or an entry is invalid. All traffic of assigned users is temporarily blocked. Restore the sets or explicitly disable the node.');
        }
        if (($node['kind'] ?? '') === 'ipv6') {
            if (empty($this->exitIpv6Network()['enabled'])) $warnings[] = $this->exitIpv6Attached()
                ? $this->t('⚠️ Файл настройки IPv6 (config/ipv6-egress.json) повреждён: повторите подготовку на хосте. Пока он не исправлен, адрес выхода не сверяется с настроенным.', '⚠️ The IPv6 settings file (config/ipv6-egress.json) is damaged: repeat the host preparation. Until it is fixed, the egress address is not compared with the configured one.')
                : $this->t('⚠️ Сеть IPv6 ещё не подготовлена на хосте. Выбранные назначения будут недоступны до настройки сети и firewall; запасного IPv4 нет.', '⚠️ The host IPv6 network is not prepared. Selected destinations remain unavailable until networking and the firewall are configured; there is no IPv4 fallback.');
            $warnings[] = $this->t('Только IPv6: домену нужна AAAA-запись. IPv4/CIDR выбирает маршрут, но не превращает адрес в IPv6.', 'IPv6 only: a domain needs an AAAA record. An IPv4/CIDR rule selects a route but does not translate the address to IPv6.');
        }
        $sniff = $this->sniffingSettings($p, $this->getXray()['inbounds'][0]['sniffing'] ?? null);
        if (empty($sniff['enabled'])) $warnings[] = $this->t('⚠️ Распознавание доменов (sniffing) выключено: правила по доменам не сработают. Включите его в Xray → DPI.', '⚠️ Domain sniffing is off: domain rules will not match. Turn it on in Xray → DPI.');
        elseif (!empty($sniff['routeOnly'])) $warnings[] = $this->t('⚠️ sniffing в режиме routeOnly: на узел уйдёт адрес, полученный на этом сервере, а не домен — видео пойдёт с серверов страны этого сервера.', '⚠️ sniffing is in routeOnly mode: the node receives the address resolved on this server rather than the domain, so video is served from this server\'s country.');
        $warp = array_keys(array_filter($p['warplist'] ?? []));
        // Записи наборов .srs/.mrs попадают в те же правила, что и ручные.
        $entries = array_keys($this->exitNodeEntries($node));
        $both = array_values(array_intersect($entries, $warp));
        // Подписки sing-box и Mihomo отправляют домены WARP в WARP сами (через
        // warpSOCKS5 10.10.0.13), и до правила узла на сервере они доходят уже
        // с адресом WARP: «узел важнее» верно лишь для клиентов Xray.
        if ($both) $warnings[] = $this->t('⚠️ Есть и в списке WARP: клиенты Xray пойдут через узел, а sing-box и Mihomo — в WARP. Оставьте запись в одном списке: ', '⚠️ Also in the WARP list: Xray clients go through the node, while sing-box and Mihomo go to WARP. Keep the entry in one list: ')
            . self::esc(implode(', ', array_slice($both, 0, 5)));
        $block = array_values(array_intersect($entries, array_keys(array_filter($p['blocklist'] ?? []))));
        if ($block) $warnings[] = $this->t('⚠️ Есть и в блок-листе (блокировка важнее): ', '⚠️ Also in the block list (blocking wins): ') . self::esc(implode(', ', array_slice($block, 0, 5)));
        return $warnings;
    }

    public function exitNodesMenu(string $notice = ''): void
    {
        $nodes = $this->exitNodes();
        $text = ['Menu -> ' . $this->i18n('xray') . $this->t(' -> Узлы выхода', ' -> Exit nodes'),
            $this->t('Выбранные назначения пользователей уходят через другой сервер или IPv6 этого сервера. У обычных нод по умолчанию есть прямой запасной выход; его можно отключить. Локальный IPv6 всегда строгий.', 'Selected user destinations leave through another server or this server’s IPv6. Remote nodes default to direct fallback, which can be disabled. Local IPv6 is always strict.')];
        if ($notice !== '') $text[] = "\n<b>" . self::esc($notice) . '</b>';
        $data = [];
        foreach ($nodes as $id => $node) {
            $users = count($this->exitNodeEmails($this->getXray(), $id));
            $text[] = "\n<b>" . $this->exitName($id, $node) . '</b> — ' . $this->exitStatusLine($id, $node) . $this->t(" · пользователей: $users", " · users: $users");
            $data[] = [['text' => ($node['enabled'] ? '🌍 ' : '⏸ ') . ($node['name'] !== '' ? mb_substr($node['name'], 0, 40) : $id), 'callback_data' => "/exit $id"]];
        }
        if (!$nodes) $text[] = $this->t("\nУзлов пока нет. На другом сервере откройте Xray → «Профиль для узла» и вставьте выданную ссылку сюда.", "\nNo nodes yet. On the other server open Xray → Node profile and paste the link it gives here.");
        if (count($nodes) < self::EXIT_MAX) $data[] = [['text' => $this->t('➕ Добавить узел', '➕ Add node'), 'callback_data' => '/exitAdd']];
        if (count($nodes) < self::EXIT_MAX) $data[] = [['text' => $this->t('➕ Группа узлов', '➕ Node group'), 'callback_data' => '/exitGroupAdd']];
        if (count($nodes) < self::EXIT_MAX && !array_filter($nodes, static fn($n) => $n['kind'] === 'ipv6')) $data[] = [['text' => $this->t('➕ IPv6 этого сервера', '➕ This server IPv6'), 'callback_data' => '/exitIpv6Add']];
        $data[] = [['text' => $this->t('🔁 Проверить все', '🔁 Check all'), 'callback_data' => '/exitCheckAll'], ['text' => $this->t('🪪 Профиль для узла', '🪪 Node profile'), 'callback_data' => '/exitRelay']];
        $data[] = [['text' => $this->t('🧭 Куда пойдёт домен', '🧭 Where a domain goes'), 'callback_data' => '/exitWhere']];
        $data[] = $this->menuHelpButton('exitnodes');
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => '/xray']];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $text), $data);
    }

    public function exitNodeMenu(string $id, string $notice = ''): void
    {
        $node = $this->exitNodes()[$id] ?? null;
        if ($node === null) { $this->exitNodesMenu($this->t('Узел не найден', 'Node not found')); return; }
        $x = $this->getXray();
        $routes = count(array_filter($node['routes']));
        $sets = count(array_filter($node['rulesets'], static fn($s) => is_array($s) && !empty($s['on'])));
        $users = count($this->exitNodeEmails($x, $id));
        try { $parsed = ExitNodeLink::parse($node['link']); } catch (InvalidArgumentException $e) { $parsed = null; }
        $text = ['Menu -> ' . $this->i18n('xray') . $this->t(' -> Узлы выхода -> ', ' -> Exit nodes -> ') . $this->exitName($id, $node),
            $this->exitStatusLine($id, $node)];
        if (!empty($node['enabled']) && ($history = $this->exitHistoryLine($this->exitStatus()[$id] ?? [])) !== '') $text[] = $history;
        array_push($text,
            $this->t('Адрес: <code>', 'Address: <code>') . self::esc($node['kind'] === 'group' ? $this->t('группа узлов', 'node group') : ($node['kind'] === 'ipv6' ? $this->t('IPv6 этого сервера', 'This server IPv6') : ($parsed ? $parsed['address'] . ':' . $parsed['port'] : $this->t('ссылка не разбирается', 'link cannot be parsed')))) . '</code>'
                . ($parsed ? ' · ' . self::esc($parsed['outbound']['protocol'] . '/' . $parsed['outbound']['streamSettings']['network'] . '/' . $parsed['outbound']['streamSettings']['security']) : ''),
            $this->t("Маршрутов: $routes · наборов правил: $sets · пользователей: $users", "Routes: $routes · rule sets: $sets · users: $users"),
            $node['kind'] === 'group' ? $this->t('Трафик группы учитывается у её узлов.', 'Group traffic is counted at its member nodes.') : $this->exitTrafficLine($id),
            $this->t('QUIC к доменам узла: ', 'QUIC to node domains: ') . ($node['quic'] === 'block' ? $this->t('блокируется (браузер сразу идёт по TCP через узел)', 'blocked (the browser goes over TCP through the node right away)') : $this->t('пропускается', 'allowed')),
            !self::exitDirectFallback($node) ? $this->t('При отказе: блокировать, без запасного выхода', 'On failure: block, no fallback') : $this->t('При отказе узла: напрямую с этого сервера', 'If the node fails: direct from this server'),
            $this->t('Новым пользователям: ', 'For new users: ') . ($node['auto'] ? $this->t('включается сразу', 'enabled at once') : $this->t('не включается', 'not enabled')));
        if ($node['kind'] === 'remote') $text[] = $this->exitSubLine($node);
        if ($node['kind'] === 'group') $text[] = $this->t('Выбор: ', 'Selection: ') . self::esc($node['choice'] === 'auto' ? $this->t('живой узел с минимальной задержкой', 'live node with the lowest latency') : $node['choice']);
        if (!$users) $text[] = $this->t('ℹ️ Узел пока ни у кого не включён: «Пользователи» или карточка пользователя.', 'ℹ️ The node is not enabled for anyone yet: use Users or a user card.');
        if (!$routes && !$sets) $text[] = $this->t('ℹ️ Маршрутов нет: «Маршруты» → например «YouTube».', 'ℹ️ No routes: Routes → for example YouTube.');
        array_push($text, ...$this->exitWarnings($node));
        if ($notice !== '') $text[] = "\n<b>" . self::esc($notice) . '</b>';
        $data = [
            [['text' => $this->t('🔍 Проверить', '🔍 Check'), 'callback_data' => "/exitCheck $id"], ['text' => $this->t('⚡ Скорость', '⚡ Speed'), 'callback_data' => "/exitSpeed $id"],
                ['text' => $this->t('🔄 Обновить', '🔄 Refresh'), 'callback_data' => "/exitRefresh $id"]],
            [['text' => ($node['enabled'] ? $this->t('✅ Включён', '✅ Enabled') : $this->t('⏸ Выключен', '⏸ Disabled')), 'callback_data' => "/exitToggle $id"],
                ['text' => 'QUIC: ' . ($node['quic'] === 'block' ? $this->t('блок', 'block') : $this->t('пропуск', 'allow')), 'callback_data' => "/exitQuic $id"]],
            [['text' => $this->t("🧭 Маршруты ($routes)", "🧭 Routes ($routes)"), 'callback_data' => "/exitRoutes $id 0"], ['text' => $this->t("📦 Наборы .srs/.mrs ($sets)", "📦 Sets .srs/.mrs ($sets)"), 'callback_data' => "/exitSets $id"]],
            [['text' => $this->t("👥 Пользователи ($users)", "👥 Users ($users)"), 'callback_data' => "/exitUsers $id 0"],
                ['text' => $this->t('🆕 Новым: ', '🆕 New users: ') . ($node['auto'] ? $this->t('да', 'yes') : $this->t('нет', 'no')), 'callback_data' => "/exitAuto $id"]],
            [['text' => $this->t('✏️ Имя', '✏️ Name'), 'callback_data' => "/exitName $id"], ['text' => $this->t('🔗 Заменить ссылку', '🔗 Replace link'), 'callback_data' => "/exitLink $id"],
                ['text' => $this->t('🗑 Удалить', '🗑 Delete'), 'callback_data' => "/exitDel $id"]],
            [['text' => $this->t('🧹 Сбросить счётчик трафика', '🧹 Reset the traffic counter'), 'callback_data' => "/exitTraf $id"]],
            [['text' => $this->t('🔄 Подписка узла: ', '🔄 Node subscription: ') . ($node['sub'] !== '' ? $this->t('вкл', 'on') : $this->t('нет', 'none')), 'callback_data' => "/exitSub $id"]],
            $this->menuHelpButton('exitnodes'),
            [['text' => $this->i18n('back'), 'callback_data' => '/exits']],
        ];
        if ($node['kind'] !== 'remote') {
            $data[4] = array_values(array_filter($data[4], static fn($b) => !str_starts_with($b['callback_data'], '/exitLink ')));
            unset($data[6]);
            if ($node['kind'] === 'group') $data[5] = [['text' => $this->t('⚖️ Состав и выбор узла', '⚖️ Members and selection'), 'callback_data' => "/exitGroup $id"]];
            $data = array_values($data);
        }
        if ($node['kind'] !== 'ipv6') {
            array_splice($data, 4, 0, [[['text' => $node['fallback'] === 'block' ? $this->t('При отказе: блок', 'On failure: block') : $this->t('При отказе: напрямую', 'On failure: direct'), 'callback_data' => "/exitFallback $id"]]]);
        }
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $text), $data);
    }

    // Трафик узла с последнего сброса: накопленное при прежних запусках Xray
    // (global) и текущий запуск сверх отметки сброса. Вместе с пробами живости.
    public function exitTraffic(string $id, ?array $stats = null): array
    {
        $e = ($stats ?? $this->getXrayStats())['exits'][$id] ?? [];
        $sum = [];
        foreach (['up', 'down'] as $dir) $sum[$dir] = (int) ($e['global'][$dir] ?? 0) + max(0, (int) ($e['session'][$dir] ?? 0) - (int) ($e['base'][$dir] ?? 0));
        return $sum + ['since' => (int) ($e['since'] ?? 0)];
    }

    public function exitTrafficLine(string $id): string
    {
        $t = $this->exitTraffic($id);
        if (!$t['since']) return $this->t('Трафик через узел: ещё не подсчитан (обновляется раз в минуту)', 'Traffic through the node: not counted yet (updated once a minute)');
        return $this->t('Трафик через узел с ', 'Traffic through the node since ') . date('d.m.Y H:i', $t['since']) . ': ↑' . $this->getBytes($t['up']) . ' ↓' . $this->getBytes($t['down']);
    }

    public function exitTrafficReset(string $id): void
    {
        if (!isset($this->exitNodes()[$id])) { $this->exitNodesMenu($this->t('Узел не найден', 'Node not found')); return; }
        $p = $this->getXrayStats();
        $e = $p['exits'][$id] ?? [];
        $p['exits'][$id] = ['session' => $e['session'] ?? ['up' => 0, 'down' => 0], 'global' => ['up' => 0, 'down' => 0],
            'base' => $e['session'] ?? ['up' => 0, 'down' => 0], 'since' => time()];
        $this->setXrayStats($p);
        $this->exitNodeMenu($id, $this->t('Счётчик трафика узла сброшен', 'The node traffic counter was reset'));
    }

    private function exitPrompt(string $text, string $callback, array $args): void
    {
        $r = $this->send($this->input['chat'], "@{$this->input['username']} $text", $this->input['message_id'], reply: $this->i18n('enter value'));
        $this->stashReply($r, ['start_message' => $this->input['message_id'], 'start_callback' => $this->input['callback_id'] ?? '',
            'callback' => $callback, 'args' => $args]);
    }

    public function exitAddPrompt(): void
    {
        $this->exitPrompt($this->t("вставьте ссылку из «Профиля для узла» другого сервера (vless:// или trojan://).\n", "paste the link from the other server's Node profile (vless:// or trojan://).\n")
            . $this->t('Сообщение со ссылкой бот сразу удалит.', 'The bot deletes the message with the link right away.'), 'saveExitAdd', []);
    }

    /** Проверка адреса узла: публичный и не этот же сервер (петля). '' — подходит. */
    public function exitAddressProblem(string $address): string
    {
        if (!$this->xdriveHostPublic('https://' . (str_contains($address, ':') ? "[$address]" : $address))) return $this->t('адрес узла не публичный или не разрешается', 'the node address is not public or does not resolve');
        // Свои имена: основной домен, его алиасы и домен для ссылок (CDN);
        // свои адреса: IPv4 и настроенный публичный IPv6. Узел на них — петля.
        $p = $this->getPacConf();
        $own = array_filter(array_merge([(string) ($p['domain'] ?? ''), (string) ($p['linkdomain'] ?? '')],
            array_map('strval', (array) ($p['domain_aliases'] ?? []))));
        $host = strtolower(rtrim($address, '.'));
        foreach (array_map('strtolower', $own) as $name) {
            if ($host === $name || str_ends_with($host, ".$name")) return $this->t('это адрес этого же сервера', 'this is the address of this very server');
        }
        $ips = array_values(array_filter([(string) ($this->ip ?? ''), (string) ($this->exitIpv6Network()['public'] ?? '')]));
        // Домен, разрешающийся в адрес этого сервера, — тоже он сам.
        $resolved = filter_var($address, FILTER_VALIDATE_IP) ? [$address] : $this->xdriveResolve($address);
        foreach ($resolved as $ip) {
            foreach ($ips as $mine) if (@inet_pton((string) $ip) !== false && @inet_pton((string) $ip) === @inet_pton($mine)) {
                return $ip === $address ? $this->t('это адрес этого же сервера', 'this is the address of this very server')
                    : $this->t('адрес узла указывает на этот же сервер', 'the node address points to this very server');
            }
        }
        return '';
    }

    public function saveExitAdd($link): void
    {
        try { $parsed = ExitNodeLink::parse((string) $link); } catch (InvalidArgumentException $e) { $this->exitNodesMenu($this->t('Ссылка не подходит: ', 'The link does not fit: ') . $e->getMessage()); return; }
        if (($problem = $this->exitAddressProblem($parsed['address'])) !== '') { $this->exitNodesMenu($this->t('Узел не добавлен: ', 'Node not added: ') . $problem); return; }
        $id = self::exitNewId();
        $error = $this->applyExitNodes(function (array &$p) use ($id, $parsed, $link) {
            if (count($this->exitNodes($p)) >= self::EXIT_MAX) return 'exit too many';
            foreach ($this->exitNodes($p) as $node) if ($node['link'] === trim((string) $link)) return 'exit duplicate';
            $p['exits'][$id] = ['name' => $parsed['remark'] !== '' ? $parsed['remark'] : $this->t('узел ', 'node ') . (count($this->exitNodes($p)) + 1),
                'link' => trim((string) $link), 'created' => time()] + self::exitNodeDefaults();
            return '';
        });
        if ($error !== '') { $this->exitNodesMenu($this->exitError($error)); return; }
        $this->exitProbe($id, true);
        $this->exitNodeMenu($id, $this->t('Узел добавлен. Добавьте маршруты и включите его пользователям.', 'Node added. Add routes and enable it for users.'));
    }

    public function exitError(string $code): string
    {
        return match ($code) {
            'exit too many' => $this->t('Узлов не больше ', 'Nodes at most ') . self::EXIT_MAX,
            'exit duplicate' => $this->t('Такой узел уже есть', 'This node already exists'),
            'exit check failed' => $this->t('Ядро Xray не приняло изменение — оставлены прежние настройки (проверьте записи regexp: и .dat)', 'The Xray core rejected the change; the previous settings are kept (check regexp: and .dat entries)'),
            'exit not found' => $this->t('Узел не найден', 'Node not found'),
            'exit stale' => $this->t('Список изменился — ничего не сделано. Откройте меню заново и нажмите кнопку ещё раз.', 'The list has changed, nothing was done. Open the menu again and tap the button again.'),
            'exit not ready' => $this->t('Не сохранено: у строгого узла не готовы записи (нет .dat, набор не скачан или запись неверна), и весь трафик его пользователей был бы заблокирован. Исправьте или удалите: ', 'Not saved: the strict node has unavailable entries (missing .dat, set not downloaded or invalid entry), so all traffic of its users would be blocked. Fix or remove: ')
                . implode(', ', array_map(static fn($e) => mb_substr($e, 0, 80), array_slice($this->exitNotReady, 0, 3))) . (count($this->exitNotReady) > 3 ? ' …' : ''),
            default => $this->t('Не удалось сохранить', 'Could not save'),
        };
    }

    // Общая правка одного узла: $edit(array &$node) → '' или код ошибки.
    private function exitEditNode(string $id, callable $edit): string
    {
        return $this->applyExitNodes(function (array &$p) use ($id, $edit) {
            if (!isset($this->exitNodes($p)[$id])) return 'exit not found';
            $node = $was = $this->exitNodes($p)[$id];
            $before = $this->exitStrictProblems($node);
            $error = $edit($node);
            if (is_string($error) && $error !== '') return $error;
            // Неготовая запись строгого узла закрыла бы его пользователям весь
            // трафик: такую правку не сохраняем. Прежние сбои (кэш пропал сам)
            // не мешают править узел — их показывает карточка.
            $this->exitNotReady = array_values(array_diff($this->exitStrictProblems($node, $was), $before));
            if ($this->exitNotReady) return 'exit not ready';
            $p['exits'][$id] = $node;
            return '';
        });
    }

    public function exitToggle(string $id): void
    {
        $error = $this->exitEditNode($id, static function (array &$node) { $node['enabled'] = $node['enabled'] ? 0 : 1; return ''; });
        $this->exitNodeMenu($id, $error === '' ? '' : $this->exitError($error));
    }

    public function exitGroupAdd(): void
    {
        $id = self::exitNewId();
        $error = $this->applyExitNodes(function (array &$p) use ($id) {
            if (count($this->exitNodes($p)) >= self::EXIT_MAX) return 'exit too many';
            $p['exits'][$id] = ['kind' => 'group', 'name' => $this->t('Группа узлов', 'Node group'),
                'fallback' => 'block', 'created' => time()] + self::exitNodeDefaults();
            return '';
        });
        if ($error !== '') { $this->exitNodesMenu($this->exitError($error)); return; }
        $this->exitGroupMenu($id);
    }

    public function exitGroupMenu(string $id, string $notice = ''): void
    {
        $nodes = $this->exitNodes();
        $group = $nodes[$id] ?? null;
        if (($group['kind'] ?? '') !== 'group') { $this->exitNodesMenu(); return; }
        $text = [$this->t('⚖️ Группа: ', '⚖️ Group: ') . $this->exitName($id, $group),
            $this->t('Включите в состав обычные удалённые узлы. Автоматический режим выбирает живой узел с минимальной задержкой. Сами узлы должны быть включены; их маршруты и список пользователей не копируются в группу.', 'Choose remote member nodes. Automatic mode selects a live node with the lowest latency. Members must be enabled; their routes and user lists are not copied to the group.'),
            $this->t('Ручной выбор действует на новые соединения. Если выбранный узел выключен, удалён или сломан — трафик блокируется. Прямой выход доступен только при включённом запасном прямом выходе.', 'Manual selection affects new connections. A disabled, deleted or broken selected node blocks traffic. Direct selection is available only when direct fallback is enabled.'),
            $this->t('Текущий выбор: ', 'Current selection: ') . self::esc($group['choice'])];
        if ($notice !== '') $text[] = self::esc($notice);
        $data = [[['text' => ($group['choice'] === 'auto' ? '✅ ' : '') . $this->t('Автоматически: минимальная задержка', 'Automatic: lowest latency'), 'callback_data' => "/exitChoice $id auto"]]];
        foreach ($nodes as $member => $node) {
            if ($node['kind'] !== 'remote') continue;
            $selected = in_array((string) $member, $group['members'], true);
            $row = [['text' => ($selected ? '✅ ' : '☐ ') . ($node['enabled'] ? '' : '⏸ ') . ($node['name'] ?: $member), 'callback_data' => "/exitMember $id $member"]];
            if ($selected) $row[] = ['text' => ($group['choice'] === (string) $member ? '✅ ' : '') . $this->t('Выбрать', 'Select'), 'callback_data' => "/exitChoice $id $member"];
            $data[] = $row;
        }
        if ($group['fallback'] === 'direct') $data[] = [['text' => $this->t('Напрямую с этого сервера', 'Direct from this server'), 'callback_data' => "/exitChoice $id direct"]];
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => "/exit $id"]];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n\n", $text), $data);
    }

    public function exitGroupMember(string $id, string $member): void
    {
        $error = $this->applyExitNodes(function (array &$p) use ($id, $member) {
            $nodes = $this->exitNodes($p);
            if (($nodes[$id]['kind'] ?? '') !== 'group' || ($nodes[$member]['kind'] ?? '') !== 'remote') return 'exit not found';
            $members = $nodes[$id]['members'];
            $p['exits'][$id]['members'] = in_array($member, $members, true) ? array_values(array_diff($members, [$member])) : [...$members, $member];
            // Removing a manually chosen member deliberately leaves its choice:
            // generation blocks traffic until an administrator selects a target.
            return '';
        });
        $this->exitGroupMenu($id, $error === '' ? '' : $this->exitError($error));
    }

    public function exitGroupChoice(string $id, string $choice): void
    {
        $error = $this->exitEditNode($id, static function (array &$node) use ($choice) {
            if ($node['kind'] !== 'group') return 'exit not found';
            if ($choice !== 'auto' && !($choice === 'direct' && $node['fallback'] === 'direct') && !in_array($choice, $node['members'], true)) return 'exit stale';
            $node['choice'] = $choice;
            return '';
        });
        $this->exitGroupMenu($id, $error === '' ? '' : $this->exitError($error));
    }

    public function exitQuic(string $id): void
    {
        $error = $this->exitEditNode($id, static function (array &$node) { $node['quic'] = $node['quic'] === 'block' ? 'pass' : 'block'; return ''; });
        $this->exitNodeMenu($id, $error === '' ? '' : $this->exitError($error));
    }

    public function exitAuto(string $id): void
    {
        $error = $this->exitEditNode($id, static function (array &$node) { $node['auto'] = $node['auto'] ? 0 : 1; return ''; });
        $this->exitNodeMenu($id, $error === '' ? '' : $this->exitError($error));
    }

    public function exitCheck(string $id): void
    {
        $s = $this->exitProbe($id, true);
        $this->exitNodeMenu($id, !empty($s['ok']) ? $this->t('Проверено: узел работает', 'Checked: the node is working') : $this->t('Проверено: ', 'Checked: ') . $this->exitErrorText((string) ($s['error'] ?? '')));
    }

    /**
     * Скорость: одна загрузка EXIT_SPEED_BYTES через вход проверки узла и одна
     * напрямую из контейнера xr. ['node' => [...], 'direct' => [...]], где
     * mbps — по фактически скачанному, даже если загрузку оборвал таймаут.
     */
    public function exitSpeed(string $id): array
    {
        $port = $this->exitProbePort($id);
        $node = $this->exitNodes()[$id] ?? null;
        if ($port === null || $node === null) return ['error' => 'not found'];
        if (empty($node['enabled'])) return ['error' => 'disabled'];
        $cmd = "s(){ curl -s -o /dev/null --max-time 20 -w '%{http_code} %{size_download} %{time_total}' \"\$@\" " . self::EXIT_SPEED_URL . "; rc=\$?; printf ' %s\\n' \"\$rc\"; }; "
            . "printf 'node='; s --noproxy '' --socks5-hostname 127.0.0.1:$port; printf 'direct='; s --noproxy '*'; true";
        $out = (string) $this->ssh($cmd, 'xr');
        if ($this->sshFailed) return ['error' => 'xray'];
        $result = [];
        foreach (['node', 'direct'] as $way) {
            if (!preg_match('~^' . $way . '=(\d{3}) ([0-9.]+) ([0-9.]+) (\d{1,3})$~m', $out, $m)) { $result[$way] = ['ok' => false, 'http' => 0]; continue; }
            $bytes = (float) $m[2];
            $time = (float) $m[3];
            $code = (int) $m[4];
            $full = (int) $bytes >= self::EXIT_SPEED_BYTES;
            // Код 28 — наше ограничение времени: уже принятые байты пригодны
            // для оценки. Обрыв TCP, ошибка TLS и короткий ответ HTTP 200 — нет.
            $result[$way] = ['ok' => $m[1] === '200' && $bytes > 0 && $time > 0 && (($code === 0 && $full) || $code === 28),
                'http' => (int) $m[1], 'curl' => $code, 'bytes' => (int) $bytes, 'seconds' => $time,
                'mbps' => $time > 0 ? round($bytes * 8 / $time / 1e6, 1) : 0.0, 'full' => $full];
        }
        return $result;
    }

    public function exitSpeedText(array $r): string
    {
        if (isset($r['error'])) return $this->t('Скорость не измерена: ', 'Speed not measured: ') . $this->exitErrorText((string) $r['error']);
        $part = function (array $w): string {
            if (empty($w['ok'])) return $this->t('не скачалось', 'download failed')
                . (!empty($w['curl']) ? " (curl {$w['curl']})" : (!empty($w['http']) ? " (HTTP {$w['http']})" : ''));
            $mbps = number_format((float) $w['mbps'], 1, $this->language === 'en' ? '.' : ',', '');
            $seconds = round((float) ($w['seconds'] ?? 0), 1);
            return $this->t("$mbps Мбит/с", "$mbps Mbit/s") . (empty($w['full']) ? $this->t(" (за $seconds с скачано ", " (in $seconds s got ") . round($w['bytes'] / 1e6, 1) . $this->t(' МБ)', ' MB)') : '');
        };
        return $this->t('Скорость до Cloudflare (до 50 МБ на путь): через узел ', 'Speed to Cloudflare (up to 50 MB per path): through the node ') . $part($r['node'] ?? [])
            . $this->t(' · напрямую ', ' · direct ') . $part($r['direct'] ?? [])
            . $this->t("\nОценка одного соединения с учётом подключения; скорость YouTube может отличаться.", "\nSingle-connection estimate including connection setup; YouTube speed may differ.");
    }

    public function exitSpeedCheck(string $id): void
    {
        if (!empty($this->input['callback_id'])) $this->answer($this->input['callback_id'], $this->t('Измеряю скорость, до 40 секунд…', 'Measuring speed, up to 40 seconds…'));
        $this->exitNodeMenu($id, $this->exitSpeedText($this->exitSpeed($id)));
    }

    public function exitRefresh(string $id): void
    {
        $changed = $this->exitRefreshRulesets($id, true);
        if ($changed) $this->withLock('xray', fn() => $this->restartXray($this->getXray()), 20, false);
        $s = $this->exitProbe($id, true);
        $this->exitNodeMenu($id, $this->t('Обновлено: наборы правил ', 'Refreshed: rule sets ') . ($changed ? $this->t('изменились', 'changed') : $this->t('без изменений', 'unchanged')) . $this->t(', узел ', ', node ') . (!empty($s['ok']) ? $this->t('работает', 'working') : $this->t('не работает', 'not working')));
    }

    public function exitCheckAll(): void
    {
        $this->exitProbeMany(array_fill_keys(array_keys(array_filter($this->exitNodes(), static fn($n) => !empty($n['enabled']))), true));
        $this->exitNodesMenu($this->t('Проверено', 'Checked'));
    }

    public function exitNamePrompt(string $id): void
    {
        $this->exitPrompt($this->t('новое имя узла (до 40 символов):', 'new node name (up to 40 characters):'), 'saveExitName', [$id]);
    }

    public function saveExitName($name, $id): void
    {
        $name = trim(preg_replace('~[\x00-\x1f\x7f<>&]~u', '', (string) $name) ?? '');
        $error = $name === '' ? 'exit empty' : $this->exitEditNode((string) $id, static function (array &$node) use ($name) { $node['name'] = mb_substr($name, 0, 40); return ''; });
        $this->exitNodeMenu((string) $id, $error === '' ? $this->t('Имя сохранено', 'Name saved') : ($error === 'exit empty' ? $this->t('Пустое имя', 'Empty name') : $this->exitError($error)));
    }

    public function exitLinkPrompt(string $id): void
    {
        $this->exitPrompt($this->t("новая ссылка узла (после «Новых ключей» или смены транспорта на узле).\nМаршруты и пользователи сохранятся. Сообщение бот удалит.", "new node link (after New keys or a transport change on the node).\nRoutes and users are kept. The bot deletes the message."), 'saveExitLink', [$id]);
    }

    public function saveExitLink($link, $id): void
    {
        if (($this->exitNodes()[(string) $id]['kind'] ?? '') !== 'remote') { $this->exitNodeMenu((string) $id); return; }
        try { $parsed = ExitNodeLink::parse((string) $link); } catch (InvalidArgumentException $e) { $this->exitNodeMenu((string) $id, $this->t('Ссылка не подходит: ', 'The link does not fit: ') . $e->getMessage()); return; }
        if (($problem = $this->exitAddressProblem($parsed['address'])) !== '') { $this->exitNodeMenu((string) $id, $this->t('Не сохранено: ', 'Not saved: ') . $problem); return; }
        $error = $this->exitEditNode((string) $id, static function (array &$node) use ($link) { $node['link'] = trim((string) $link); return ''; });
        if ($error === '') $this->exitProbe((string) $id, true);
        $this->exitNodeMenu((string) $id, $error === '' ? $this->t('Ссылка заменена', 'Link replaced') : $this->exitError($error));
    }

    // ── Подписка узла: ссылка обновляется сама ─────────────────────────────
    // Как «подписки на выходы» в 3x-ui: узел задаётся адресом подписки его
    // «Профиля для узла» (base64, формат v2rayNG). После «Новых ключей» или
    // смены транспорта на узле его прежняя ссылка перестаёт работать — бот сам
    // берёт новую из подписки: раз в 6 часов и сразу после отказа проверки.
    // Скачивание — тем же защищённым путём, что внешние подписки (https,
    // только публичные адреса, проверка каждой переадресации); новая ссылка
    // проходит те же проверки, что вставленная руками.
    public const EXIT_SUB_PERIOD = 21600;

    public function exitSubLine(array $node): string
    {
        if ($node['sub'] === '') return $this->t('Подписка узла: нет — ссылку меняете вручную', 'Node subscription: none, you replace the link by hand');
        $line = $this->t('Подписка узла: ссылка обновляется сама', 'Node subscription: the link updates itself');
        if ($node['sub_time']) $line .= $this->t(' · проверено ', ' · checked ') . date('d.m H:i', $node['sub_time']);
        if ($node['sub_error'] !== '') $line .= ' · ⚠️ ' . self::esc($node['sub_error']);
        return $line;
    }

    /** Ссылка узла из подписки: ['link' => …] или ['error' => текст]. */
    public function exitSubFetch(string $url): array
    {
        if (!self::exitRulesetUrlValid($url, false)) return ['error' => $this->t('нужен адрес https://', 'an https:// address is needed')];
        $links = $this->doFetchExtSub($url);
        if (is_string($links)) return ['error' => $links];
        $problem = $this->t('в подписке нет подходящей ссылки vless:// или trojan://', 'the subscription has no suitable vless:// or trojan:// link');
        foreach ($links as $link) {
            try { $parsed = ExitNodeLink::parse((string) $link); } catch (InvalidArgumentException $e) { continue; }
            if (($p = $this->exitAddressProblem($parsed['address'])) !== '') { $problem = $p; continue; }
            return ['link' => trim((string) $link)];
        }
        return ['error' => $problem];
    }

    public function exitSubPrompt(string $id): void
    {
        $this->exitPrompt($this->t("адрес подписки профиля для узла (https://…). На сервере-узле: Xray → Узлы выхода → «Профиль для узла» → профиль → «Подписка для автообновления».\nБот будет сам заменять ссылку узла, если там сменят ключи или транспорт. <code>0</code> — отключить.",
            "the node profile subscription address (https://…). On the node server: Xray → Exit nodes → Node profile → the profile → Subscription for auto-update.\nThe bot will replace the node link itself if keys or the transport change there. <code>0</code> turns it off."), 'saveExitSub', [$id]);
    }

    public function saveExitSub($text, $id): void
    {
        $id = (string) $id;
        $url = trim((string) $text);
        if (($this->exitNodes()[$id]['kind'] ?? '') !== 'remote') { $this->exitNodeMenu($id); return; }
        if ($url === '0' || $url === '') {
            $error = $this->exitEditNode($id, static function (array &$node) { $node['sub'] = ''; $node['sub_time'] = 0; $node['sub_error'] = ''; return ''; });
            $this->exitNodeMenu($id, $error === '' ? $this->t('Подписка узла отключена', 'Node subscription turned off') : $this->exitError($error));
            return;
        }
        $got = $this->exitSubFetch($url);
        if (isset($got['error'])) { $this->exitNodeMenu($id, $this->t('Подписка не сохранена: ', 'Subscription not saved: ') . $got['error']); return; }
        $changed = false;
        $error = $this->exitEditNode($id, static function (array &$node) use ($url, $got, &$changed) {
            $changed = $node['link'] !== $got['link'];
            $node['sub'] = $url; $node['sub_time'] = time(); $node['sub_error'] = ''; $node['link'] = $got['link'];
            return '';
        });
        if ($error === '' && $changed) $this->exitProbe($id, true);
        $this->exitNodeMenu($id, $error !== '' ? $this->exitError($error)
            : ($changed ? $this->t('Подписка сохранена, ссылка узла обновлена из неё', 'Subscription saved, the node link was updated from it') : $this->t('Подписка сохранена, ссылка узла совпадает', 'Subscription saved, the node link is the same')));
    }

    /** Обновить ссылку узла из подписки; true — ссылка сменилась (конфиг уже применён). */
    public function exitSubRefresh(string $id): bool
    {
        $node = $this->exitNodes()[$id] ?? null;
        if ($node === null || $node['sub'] === '') return false;
        $got = $this->exitSubFetch($node['sub']);
        $changed = false;
        $error = $this->exitEditNode($id, static function (array &$n) use ($got, $node, &$changed) {
            // Скачивание происходит вне блокировки; запоздавший ответ не
            // должен отменять новую подписку или вручную заменённую ссылку.
            if ($n['sub'] !== $node['sub'] || $n['link'] !== $node['link']) return 'exit stale';
            $n['sub_time'] = time();
            $n['sub_error'] = (string) ($got['error'] ?? '');
            if (isset($got['link']) && $got['link'] !== $n['link']) { $n['link'] = $got['link']; $changed = true; }
            return '';
        });
        return $error === '' && $changed;
    }

    public function exitDelete(string $id, bool $confirmed = false): void
    {
        $node = $this->exitNodes()[$id] ?? null;
        if ($node === null) { $this->exitNodesMenu($this->t('Узел не найден', 'Node not found')); return; }
        if (!$confirmed) {
            $this->update($this->input['chat'], $this->input['message_id'],
                $this->t('Удалить узел <b>', 'Delete node <b>') . $this->exitName($id, $node) . $this->t('</b>? Его маршруты удалятся, у пользователей он выключится.', '</b>? Its routes are deleted and it is turned off for users.'),
                [[['text' => $this->t('🗑 Да, удалить', '🗑 Yes, delete'), 'callback_data' => "/exitDelYes $id"], ['text' => $this->i18n('back'), 'callback_data' => "/exit $id"]]]);
            return;
        }
        $error = $this->applyExitNodes(function (array &$p, array &$x) use ($id) {
            if (!isset($p['exits'][$id])) return 'exit not found';
            unset($p['exits'][$id]);
            if (!$p['exits']) unset($p['exits']);
            foreach ($x['inbounds'][0]['settings']['clients'] ?? [] as $k => $client) {
                if (!is_array($client['exit'] ?? null)) continue;
                $left = array_values(array_diff($client['exit'], [$id]));
                if ($left) $x['inbounds'][0]['settings']['clients'][$k]['exit'] = $left;
                else unset($x['inbounds'][0]['settings']['clients'][$k]['exit']);
            }
            return '';
        });
        if ($error === '') {
            foreach (array_keys($node['rulesets']) as $url) $this->exitRulesetForget((string) $url);
        }
        $this->exitNodesMenu($error === '' ? $this->t('Узел удалён', 'Node deleted') : $this->exitError($error));
    }

    // ── Маршруты узла ──────────────────────────────────────────────────────
    public function exitRoutesMenu(string $id, int $page = 0, string $notice = ''): void
    {
        $node = $this->exitNodes()[$id] ?? null;
        if ($node === null) { $this->exitNodesMenu($this->t('Узел не найден', 'Node not found')); return; }
        $entries = array_keys($node['routes']);
        $pages = max(1, (int) ceil(count($entries) / self::EXIT_PAGE));
        $page = max(0, min($page, $pages - 1));
        $text = ['Menu -> ' . $this->i18n('xray') . $this->t(' -> Узлы выхода -> ', ' -> Exit nodes -> ') . $this->exitName($id, $node) . $this->t(' -> Маршруты', ' -> Routes'),
            $this->t('Нажмите на запись, чтобы выключить или включить её; ✖ — удалить.', 'Tap an entry to turn it off or on; ✖ deletes it.')];
        if ($notice !== '') $text[] = "\n<b>" . self::esc($notice) . '</b>';
        $data = [];
        foreach (array_slice($entries, $page * self::EXIT_PAGE, self::EXIT_PAGE) as $entry) {
            $key = self::exitEntryKey((string) $entry);
            $c = $this->classifyRouteEntry((string) $entry);
            $wait = in_array($c['kind'], ['ext', 'extip'], true) && !$this->datFileReady($c['value'])
                || in_array($c['kind'], ['geosite', 'geoip'], true) && !$this->datFileReady(self::CORE_DAT[$c['kind']]);
            $data[] = [['text' => ($node['routes'][$entry] ? '✅ ' : '⏸ ') . ($wait ? '⏳ ' : '') . mb_substr((string) $entry, 0, 50), 'callback_data' => "/exitRt $id $key"],
                ['text' => '✖', 'callback_data' => "/exitRtDel $id $key"]];
        }
        if ($pages > 1) {
            $nav = [];
            if ($page > 0) $nav[] = ['text' => '←', 'callback_data' => "/exitRoutes $id " . ($page - 1)];
            $nav[] = ['text' => ($page + 1) . "/$pages", 'callback_data' => "/exitRoutes $id $page"];
            if ($page < $pages - 1) $nav[] = ['text' => '→', 'callback_data' => "/exitRoutes $id " . ($page + 1)];
            $data[] = $nav;
        }
        $data[] = [['text' => $this->t('➕ Добавить', '➕ Add'), 'callback_data' => "/exitRtAdd $id"], ['text' => '▶️ YouTube', 'callback_data' => "/exitYt $id"],
            ['text' => $this->t('📚 Сервисы', '📚 Services'), 'callback_data' => "/exitPresets $id"]];
        $data[] = [['text' => $this->t('📋 Копировать из WARP', '📋 Copy from WARP'), 'callback_data' => "/exitCopy $id warp"], ['text' => $this->t('📦 Перенести из WARP', '📦 Move from WARP'), 'callback_data' => "/exitCopy $id move"]];
        $data[] = [['text' => $this->t('📋 Копировать из списка VPN (pac)', '📋 Copy from the VPN list (pac)'), 'callback_data' => "/exitCopy $id pac"]];
        $data[] = [['text' => $this->t('📋 В другой узел', '📋 To another node'), 'callback_data' => "/exitCopyTo $id"],
            ['text' => $this->t('📤 Экспорт', '📤 Export'), 'callback_data' => "/exitExport $id"], ['text' => $this->t('📥 Импорт', '📥 Import'), 'callback_data' => "/exitImport $id"]];
        if ($entries) $data[] = [['text' => $this->t('🧹 Очистить всё', '🧹 Clear all'), 'callback_data' => "/exitRtClear $id"]];
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => "/exit $id"]];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $text), $data);
    }

    public function exitRouteAddPrompt(string $id): void
    {
        $this->exitPrompt($this->t("записи маршрута через узел.\n\n<b>Префиксы</b> (нажмите на слово, чтобы скопировать):\n", "route entries through the node.\n\n<b>Prefixes</b> (tap a word to copy it):\n")
            . $this->t("<code>domain:</code> — домен и все его поддомены, напр. domain:youtube.com\n", "<code>domain:</code>: a domain and all its subdomains, e.g. domain:youtube.com\n")
            . $this->t("<code>full:</code> — точное совпадение домена, напр. full:www.youtube.com\n", "<code>full:</code>: an exact domain match, e.g. full:www.youtube.com\n")
            . $this->t("<code>keyword:</code> — совпадение по подстроке, напр. keyword:youtube\n", "<code>keyword:</code>: a substring match, e.g. keyword:youtube\n")
            . $this->t("<code>regexp:</code> — регулярное выражение, напр. regexp:.*\\.ru\$\n", "<code>regexp:</code>: a regular expression, e.g. regexp:.*\\.ru\$\n")
            . $this->t("<code>geosite:</code> / <code>geoip:</code> — категории встроенных .dat, напр. geosite:youtube\n", "<code>geosite:</code> / <code>geoip:</code>: categories of the built-in .dat, e.g. geosite:youtube\n")
            . $this->t("<code>ext:</code> / <code>extip:</code> — категории своих .dat из Vless → routes → dat, напр. ext:dlc.dat:youtube\n", "<code>ext:</code> / <code>extip:</code>: categories of your own .dat from Vless → routes → dat, e.g. ext:dlc.dat:youtube\n")
            . $this->t("без префикса — домен-суффикс; IPv4/IPv6[/cidr] — как есть.\n\n", "no prefix: a domain suffix; IPv4/IPv6[/cidr]: as is.\n\n")
            . $this->t("<b>Как вводить:</b> в столбик или через запятую либо пробел; записи <code>regexp:</code> — каждую с новой строки.\n", "<b>How to enter:</b> one per line, or separated by commas or spaces; put each <code>regexp:</code> entry on its own line.\n")
            . $this->t('Наборы правил sing-box (.srs) и Mihomo (.mrs) — в «Наборы .srs/.mrs».', 'sing-box (.srs) and Mihomo (.mrs) rule sets are under Sets .srs/.mrs.'), 'saveExitRoutes', [$id]);
    }

    /** Добавить записи (запись => 1|0) к маршрутам узла без повторов; [добавлено, пропущено, не готовы для строгого узла]. */
    public function exitMergeRoutes(array &$node, array $entries): array
    {
        $added = $skipped = 0;
        $unready = [];
        $seen = [];
        foreach (array_keys($node['routes']) as $key) if (($canon = $this->routeEntryCanonKey((string) $key)) !== '') $seen[$canon] = true;
        foreach ($entries as $entry => $on) {
            $entry = trim((string) $entry);
            $c = $this->classifyRouteEntry($entry);
            $canon = $this->routeEntryCanonKey($entry);
            if ($entry === '' || mb_strlen($entry) > 300 || !$this->routeEntryUsable($c) || isset($seen[$canon])) { $skipped++; continue; }
            if (count($node['routes']) >= 2000) { $skipped++; continue; }
            // Строгому узлу запись без .dat закрыла бы весь трафик его пользователей.
            if ($on && ($node['fallback'] ?? '') === 'block' && !$this->exitRouteEntryReady($entry)) { $unready[] = $entry; continue; }
            $node['routes'][$entry] = $on ? 1 : 0;
            $seen[$canon] = true;
            $added++;
        }
        return [$added, $skipped, $unready];
    }

    /** Строгий ли узел (запасного выхода нет): локальный IPv6 или «При отказе: блок». */
    private function exitStrict(string $id): bool
    {
        return ($this->exitNodes()[$id]['fallback'] ?? '') === 'block';
    }

    private function exitUnreadyNote(array $unready): string
    {
        if (!$unready) return '';
        return $this->t(', не принято (строгий узел: нет .dat, набор не скачан или пуст): ', ', not accepted (strict node: missing .dat, set not downloaded or empty): ')
            . count($unready) . ' — ' . implode(', ', array_map(static fn($e) => mb_substr((string) $e, 0, 80), array_slice($unready, 0, 3))) . (count($unready) > 3 ? ' …' : '');
    }

    public function saveExitRoutes($text, $id, array $preset = []): bool
    {
        $entries = $preset ?: $this->splitRouteInput((string) $text);
        $added = $skipped = 0;
        $unready = [];
        // Ключи массива: числовая строка («123») стала бы числом — берём по одной.
        $map = [];
        $dups = 0;
        foreach ($entries as $entry) {
            $entry = trim((string) $entry);
            if (isset($map[$entry])) { $dups++; continue; }
            $map[$entry] = 1;
        }
        // Строгому узлу .dat нужен сразу: без него запись не будет принята.
        if ($this->exitStrict((string) $id)) $this->exitFetchDat($map);
        $error = $this->exitEditNode((string) $id, function (array &$node) use ($map, $dups, &$added, &$skipped, &$unready) {
            [$added, $skipped, $unready] = $this->exitMergeRoutes($node, $map);
            $skipped += $dups;
            return '';
        });
        $this->exitRoutesMenu((string) $id, PHP_INT_MAX, $error !== '' ? $this->exitError($error) : $this->t("Добавлено: $added", "Added: $added") . ($skipped ? $this->t(", пропущено (повтор или неверная запись): $skipped", ", skipped (duplicate or invalid entry): $skipped") : '') . $this->exitUnreadyNote($unready));
        return $error === '';
    }

    /**
     * Записи из списков Vless → routes. «Перенести из WARP» копирует и убирает
     * их из WARP: подписки sing-box и Mihomo отправляют домены WARP в WARP
     * сами, и до узла такие домены бы не дошли.
     */
    public function exitCopyRoutes(string $id, string $from): void
    {
        $list = $from === 'pac' ? 'includelist' : 'warplist';
        $entries = array_map('strval', array_keys(array_filter($this->getPacConf()[$list] ?? [])));
        if (!$entries) { $this->exitRoutesMenu($id, 0, $from === 'pac' ? $this->t('Список VPN (pac) пуст', 'The VPN list (pac) is empty') : $this->t('Список WARP пуст', 'The WARP list is empty')); return; }
        if (!$this->saveExitRoutes('', $id, $entries)) return;
        if ($from !== 'move' || !isset($this->exitNodes()[$id])) return;
        // Повтор не включает уже выключенный маршрут. Удалять такой домен
        // из WARP нельзя: в узле он тоже не действует, трафик ушёл бы напрямую.
        $moved = array_values(array_intersect($entries, array_map('strval', array_keys(array_filter($this->exitNodes()[$id]['routes'])))));
        $ok = $this->changeRouteList('warplist', static function (&$warp) use ($moved) {
            foreach ($moved as $entry) unset($warp[$entry]);
        });
        $this->exitRoutesMenu($id, PHP_INT_MAX, $ok ? $this->t('Перенесено из WARP: ', 'Moved from WARP: ') . count($moved) : $this->t('Скопировано, но убрать из WARP не удалось', 'Copied, but removing from WARP failed'));
    }

    public function exitYoutube(string $id): void
    {
        $this->saveExitRoutes('', $id, self::EXIT_YOUTUBE);
    }

    // Набор считается добавленным, если у узла есть все его записи (в любом
    // состоянии). Повторное нажатие убирает записи набора.
    public function exitPresetState(array $node, string $key): bool
    {
        $have = [];
        foreach (array_keys($node['routes']) as $entry) $have[$this->routeEntryCanonKey((string) $entry)] = true;
        foreach (self::EXIT_PRESETS[$key][1] as $entry) if (!isset($have[$this->routeEntryCanonKey($entry)])) return false;
        return true;
    }

    public function exitPresetsMenu(string $id, string $notice = ''): void
    {
        $node = $this->exitNodes()[$id] ?? null;
        if ($node === null) { $this->exitNodesMenu($this->t('Узел не найден', 'Node not found')); return; }
        $text = ['Menu -> ' . $this->i18n('xray') . $this->t(' -> Узлы выхода -> ', ' -> Exit nodes -> ') . $this->exitName($id, $node) . $this->t(' -> Сервисы', ' -> Services'),
            $this->t('Нажмите на сервис, чтобы добавить его домены в маршруты узла; ✅ — уже добавлен, повторное нажатие убирает его записи.', 'Tap a service to add its domains to the node routes; ✅ means it is added, tapping again removes its entries.')];
        if ($notice !== '') $text[] = "\n<b>" . self::esc($notice) . '</b>';
        $data = [];
        foreach (array_chunk(array_keys(self::EXIT_PRESETS), 2) as $pair) {
            $data[] = array_map(fn($key) => ['text' => ($this->exitPresetState($node, $key) ? '✅ ' : '➕ ') . self::EXIT_PRESETS[$key][0], 'callback_data' => "/exitPre $id $key"], $pair);
        }
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => "/exitRoutes $id 0"]];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $text), $data);
    }

    public function exitPresetToggle(string $id, string $key): void
    {
        if (!isset(self::EXIT_PRESETS[$key])) { $this->exitPresetsMenu($id); return; }
        [$title, $entries] = self::EXIT_PRESETS[$key];
        $node = $this->exitNodes()[$id] ?? null;
        if ($node === null) { $this->exitNodesMenu($this->t('Узел не найден', 'Node not found')); return; }
        $remove = $this->exitPresetState($node, $key);
        $count = 0;
        $error = $this->exitEditNode($id, function (array &$node) use ($entries, $remove, &$count) {
            if ($remove) {
                $drop = array_flip(array_map(fn($e) => $this->routeEntryCanonKey($e), $entries));
                foreach (array_keys($node['routes']) as $entry) {
                    if (isset($drop[$this->routeEntryCanonKey((string) $entry)])) { unset($node['routes'][$entry]); $count++; }
                }
                return '';
            }
            [$count] = $this->exitMergeRoutes($node, array_fill_keys($entries, 1));
            return '';
        });
        $this->exitPresetsMenu($id, $error !== '' ? $this->exitError($error) : ($remove ? $this->t("$title: убрано записей $count", "$title: removed $count entries")
            : $this->t("$title: добавлено записей $count", "$title: added $count entries")));
    }

    // ── Копирование, экспорт и импорт маршрутов ─────────────────────────────
    public const EXIT_IMPORT_MAX_BYTES = 2 * 1024 * 1024;

    /** Выбор узла, в который скопировать маршруты и наборы этого узла. */
    public function exitCopyToMenu(string $id): void
    {
        $node = $this->exitNodes()[$id] ?? null;
        if ($node === null) { $this->exitNodesMenu($this->t('Узел не найден', 'Node not found')); return; }
        $others = array_filter($this->exitNodes(), static fn($n, $other) => (string) $other !== $id, ARRAY_FILTER_USE_BOTH);
        if (!$others) { $this->exitRoutesMenu($id, 0, $this->t('Другого узла нет: добавьте второй узел', 'There is no other node: add a second one')); return; }
        $text = ['Menu -> ' . $this->i18n('xray') . $this->t(' -> Узлы выхода -> ', ' -> Exit nodes -> ') . $this->exitName($id, $node) . $this->t(' -> В другой узел', ' -> To another node'),
            $this->t('Маршруты и наборы .srs/.mrs этого узла добавятся к выбранному (повторы пропускаются, его записи остаются). Пользователи не копируются.', 'Routes and .srs/.mrs sets of this node are added to the chosen one (duplicates are skipped, its own entries stay). Users are not copied.')];
        $data = [];
        foreach ($others as $other => $n) $data[] = [['text' => '🌍 ' . mb_substr($n['name'] !== '' ? $n['name'] : (string) $other, 0, 40), 'callback_data' => "/exitCopyTo $id $other"]];
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => "/exitRoutes $id 0"]];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $text), $data);
    }

    public function exitCopyTo(string $from, string $to): void
    {
        $source = $this->exitNodes()[$from] ?? null;
        if ($source === null || $from === $to || !isset($this->exitNodes()[$to])) { $this->exitNodesMenu($this->t('Узел не найден', 'Node not found')); return; }
        $this->exitImportInto($to, $source['routes'], $source['rulesets'], $this->t('Скопировано из ', 'Copied from ') . ($source['name'] !== '' ? $source['name'] : $from) . ': ');
    }

    /** Текст экспорта: запись на строку, выключенные — «# off: », наборы — «set: [тип] ссылка». */
    public function exitExportText(array $node): string
    {
        $lines = ['# vpnbot exit node routes: ' . preg_replace('~[\r\n]~', ' ', $node['name']), '# ' . date('Y-m-d H:i')];
        foreach ($node['routes'] as $entry => $on) $lines[] = ($on ? '' : '# off: ') . $entry;
        foreach ($node['rulesets'] as $url => $set) {
            if (!is_array($set)) continue;
            $behavior = self::ruleSetFormat((string) $url) === 'mrs' ? ($set['behavior'] ?? 'domain') . ' ' : '';
            $lines[] = (empty($set['on']) ? '# off: ' : '') . 'set: ' . $behavior . $url;
        }
        return implode("\n", $lines) . "\n";
    }

    /** Разбор текста экспорта: [маршруты запись => 1|0, наборы ссылка => набор, неверных строк]. */
    public function exitImportParse(string $text): array
    {
        $routes = $sets = [];
        $bad = 0;
        foreach (preg_split('~\R~', $text) as $line) {
            $line = trim($line);
            $on = 1;
            if (preg_match('~^#\s*off:\s*(.+)$~i', $line, $m)) { $line = trim($m[1]); $on = 0; }
            if ($line === '' || str_starts_with($line, '#')) continue;
            if (preg_match('~^set:\s*(?:(domain|ipcidr)\s+)?(\S+)$~i', $line, $m)) {
                if (!self::exitRulesetUrlValid($m[2])) { $bad++; continue; }
                $sets[$m[2]] = ['on' => $on, 'behavior' => strtolower($m[1] ?: 'domain'), 'interval' => 86400];
                continue;
            }
            foreach ($this->splitRouteInput($line) as $entry) $routes[(string) $entry] ??= $on;
        }
        return [$routes, $sets, $bad];
    }

    /** Добавить маршруты и наборы в узел $id и показать итог. */
    private function exitImportInto(string $id, array $routes, array $sets, string $prefix = ''): void
    {
        $added = $skipped = $setsAdded = 0;
        $newSets = $unready = [];
        // Набор с тем же адресом уже мог быть разобран для другого узла.
        $this->exitRulesetPrefetch($id, $sets, false);
        if ($this->exitStrict($id)) $this->exitFetchDat($routes);
        $error = $this->exitEditNode($id, function (array &$node) use ($routes, $sets, &$added, &$skipped, &$setsAdded, &$newSets, &$unready) {
            [$added, $skipped, $unready] = $this->exitMergeRoutes($node, $routes);
            foreach ($sets as $url => $set) {
                if (!is_array($set) || isset($node['rulesets'][$url]) || count($node['rulesets']) >= 20) continue;
                if (!empty($set['on']) && $node['fallback'] === 'block' && !($this->exitRulesetCache((string) $url)['entries'] ?? [])) { $unready[] = (string) $url; continue; }
                $node['rulesets'][$url] = ['on' => empty($set['on']) ? 0 : 1, 'behavior' => ($set['behavior'] ?? 'domain') === 'ipcidr' ? 'ipcidr' : 'domain',
                    'interval' => max(3600, (int) ($set['interval'] ?? 86400))];
                $newSets[$url] = $node['rulesets'][$url];
                $setsAdded++;
            }
            return '';
        });
        $this->exitRoutesMenu($id, 0, $error !== '' ? $this->exitError($error)
            : $prefix . $this->t("маршрутов добавлено $added, наборов $setsAdded", "routes added $added, sets $setsAdded") . ($skipped ? $this->t(", пропущено (повтор или неверная запись): $skipped", ", skipped (duplicate or invalid entry): $skipped") : '') . $this->exitUnreadyNote($unready));
    }

    public function exitExport(string $id): void
    {
        $node = $this->exitNodes()[$id] ?? null;
        if ($node === null) { $this->exitNodesMenu($this->t('Узел не найден', 'Node not found')); return; }
        if (!$node['routes'] && !$node['rulesets']) { $this->exitRoutesMenu($id, 0, $this->t('Экспортировать нечего: маршрутов и наборов нет', 'Nothing to export: no routes or sets')); return; }
        $file = 'exit-routes-' . (trim((string) preg_replace('~[^A-Za-z0-9._-]+~', '_', $node['name']), '_.') ?: $id) . '.txt';
        $this->sendFile($this->input['chat'], new CURLStringFile($this->exitExportText($node), $file, 'text/plain'),
            $this->t('Маршруты узла ', 'Routes of node ') . $this->exitName($id, $node) . $this->t('. Импорт: Маршруты → «Импорт» на любом узле или сервере.', '. Import: Routes → Import on any node or server.'));
        $this->exitRoutesMenu($id, 0, $this->t('Файл отправлен', 'File sent'));
    }

    public function exitImportPrompt(string $id): void
    {
        $this->exitPrompt($this->t("пришлите файл экспорта маршрутов (.txt) или вставьте записи текстом.\nЗаписи добавятся к имеющимся, повторы пропускаются. Строки <code># off: </code> — выключенные записи, <code>set: </code> — наборы .srs/.mrs.", "send a route export file (.txt) or paste the entries as text.\nEntries are added to the existing ones, duplicates are skipped. <code># off: </code> lines are disabled entries, <code>set: </code> lines are .srs/.mrs sets."),
            'saveExitImport', [$id]);
    }

    // Файл из Telegram; в тестах подменяется.
    protected function exitImportDownload(): ?string
    {
        if (empty($this->input['file_id'])) return null;
        $r = $this->request('getFile', ['file_id' => $this->input['file_id']]);
        if (empty($r['ok']) || !is_string($r['result']['file_path'] ?? null) || ($r['result']['file_size'] ?? 0) > self::EXIT_IMPORT_MAX_BYTES) return null;
        // В адресе файла — токен бота: предупреждение PHP не должно уйти в журнал.
        $data = @file_get_contents($this->file . $r['result']['file_path'], false, null, 0, self::EXIT_IMPORT_MAX_BYTES + 1);
        return is_string($data) && strlen($data) <= self::EXIT_IMPORT_MAX_BYTES ? $data : null;
    }

    public function saveExitImport($text, $id): void
    {
        $id = (string) $id;
        $text = (string) $text;
        if (trim($text) === '' && !empty($this->input['file_id'])) {
            $text = $this->exitImportDownload();
            if ($text === null || !mb_check_encoding($text, 'UTF-8')) { $this->exitRoutesMenu($id, 0, $this->t('Файл не прочитан (нужен текст UTF-8 до 2 МБ)', 'File not read (UTF-8 text up to 2 MB is needed)')); return; }
        }
        [$routes, $sets, $bad] = $this->exitImportParse($text);
        if (!$routes && !$sets) { $this->exitRoutesMenu($id, 0, $this->t('Записей не найдено', 'No entries found') . ($bad ? $this->t(", неверных строк: $bad", ", invalid lines: $bad") : '')); return; }
        $this->exitImportInto($id, $routes, $sets, $this->t('Импорт: ', 'Import: ') . ($bad ? $this->t("неверных строк $bad, ", "invalid lines $bad, ") : ''));
    }

    // Кэш набора общий для узлов с одинаковой ссылкой: удаляется, только когда
    // набор не нужен больше ни одному узлу.
    private function exitRulesetForget(string $url, ?array $p = null): void
    {
        foreach ($this->exitNodes($p) as $node) if (isset($node['rulesets'][$url])) return;
        @unlink($this->exitRulesetFile($url));
    }

    private function exitFindEntry(array $node, string $key, string $field = 'routes'): ?string
    {
        foreach (array_keys($node[$field]) as $entry) if (hash_equals(self::exitEntryKey((string) $entry), $key)) return (string) $entry;
        return null;
    }

    // Удалить все записи маршрутов узла; наборы .srs/.mrs и пользователи остаются.
    public function exitRoutesClear(string $id, bool $confirmed = false): void
    {
        $node = $this->exitNodes()[$id] ?? null;
        if ($node === null) { $this->exitNodesMenu($this->t('Узел не найден', 'Node not found')); return; }
        if (!$node['routes']) { $this->exitRoutesMenu($id, 0, $this->t('Маршрутов нет', 'No routes')); return; }
        if (!$confirmed) {
            $this->update($this->input['chat'], $this->input['message_id'],
                $this->t('Удалить все маршруты узла <b>', 'Delete all routes of node <b>') . $this->exitName($id, $node) . '</b> (' . count($node['routes']) . ')?'
                . $this->t(' Наборы .srs/.mrs и пользователи не меняются.', ' Sets .srs/.mrs and users do not change.'),
                [[['text' => $this->t('🧹 Да, очистить', '🧹 Yes, clear'), 'callback_data' => "/exitRtClearYes $id"], ['text' => $this->i18n('back'), 'callback_data' => "/exitRoutes $id 0"]]]);
            return;
        }
        $error = $this->exitEditNode($id, function (array &$node) {
            $node['routes'] = [];
            return '';
        });
        $this->exitRoutesMenu($id, 0, $error === '' ? $this->t('Все маршруты удалены', 'All routes deleted') : $this->exitError($error));
    }

    public function exitRouteToggle(string $id, string $key, bool $delete = false): void
    {
        $page = 0;
        $node = $this->exitNodes()[$id] ?? null;
        $entry = $node === null || $delete ? null : $this->exitFindEntry($node, $key);
        if ($entry !== null && empty($node['routes'][$entry]) && $this->exitStrict($id)) $this->exitFetchDat([$entry => 1]);
        $error = $this->exitEditNode($id, function (array &$node) use ($key, $delete, &$page) {
            $entry = $this->exitFindEntry($node, $key);
            if ($entry === null) return '';
            $page = intdiv((int) array_search($entry, array_keys($node['routes']), true), self::EXIT_PAGE);
            if ($delete) unset($node['routes'][$entry]);
            else $node['routes'][$entry] = $node['routes'][$entry] ? 0 : 1;
            return '';
        });
        $this->exitRoutesMenu($id, $page, $error === '' ? '' : $this->exitError($error));
    }

    // ── Наборы правил узла ─────────────────────────────────────────────────
    public function exitSetsMenu(string $id, string $notice = ''): void
    {
        $node = $this->exitNodes()[$id] ?? null;
        if ($node === null) { $this->exitNodesMenu($this->t('Узел не найден', 'Node not found')); return; }
        $text = ['Menu -> ' . $this->i18n('xray') . $this->t(' -> Узлы выхода -> ', ' -> Exit nodes -> ') . $this->exitName($id, $node) . $this->t(' -> Наборы правил', ' -> Rule sets'),
            $this->t('Наборы sing-box (.srs) и Mihomo (.mrs) по ссылке https://. Бот сам скачивает их, раскладывает на домены и подсети и обновляет раз в сутки (и по «Обновить» в карточке узла).', 'sing-box (.srs) and Mihomo (.mrs) sets by https:// link. The bot downloads them itself, expands them into domains and subnets and refreshes them once a day (and on Refresh in the node card).')];
        if ($notice !== '') $text[] = "\n<b>" . self::esc($notice) . '</b>';
        $data = [];
        foreach ($node['rulesets'] as $url => $set) {
            if (!is_array($set)) continue;
            $cache = $this->exitRulesetCache((string) $url);
            $state = !$cache ? $this->t('⏳ не скачан', '⏳ not downloaded') : (($cache['error'] ?? '') !== '' ? '⚠️ ' . $this->exitErrorText((string) $cache['error']) : $this->t('записей: ', 'entries: ') . count($cache['entries'] ?? []));
            $shown = mb_strlen((string) $url) > 90 ? mb_substr((string) $url, 0, 60) . '…' . mb_substr((string) $url, -25) : (string) $url;
            $text[] = "\n" . (!empty($set['on']) ? '✅' : '⏸') . ' <code>' . self::esc($shown) . '</code> — ' . self::esc($state)
                . (self::ruleSetFormat((string) $url) === 'mrs' ? ' · ' . self::esc((string) ($set['behavior'] ?? 'domain')) : '');
            $key = self::exitEntryKey((string) $url);
            // Тип .mrs в подписи: geosite/x.mrs и geoip/x.mrs иначе неразличимы.
            $data[] = [['text' => (!empty($set['on']) ? '✅ ' : '⏸ ') . mb_substr(basename((string) parse_url((string) $url, PHP_URL_PATH)), 0, 40)
                . (self::ruleSetFormat((string) $url) === 'mrs' ? ' · ' . (string) ($set['behavior'] ?? 'domain') : ''), 'callback_data' => "/exitSet $id $key"],
                ['text' => '✖', 'callback_data' => "/exitSetDel $id $key"]];
        }
        $data[] = [['text' => $this->t('➕ Добавить набор', '➕ Add set'), 'callback_data' => "/exitSetAdd $id"]];
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => "/exit $id"]];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $text), $data);
    }

    public function exitSetAddPrompt(string $id): void
    {
        $this->exitPrompt($this->t("ссылка https:// на набор .srs или .mrs, по одной на строку.\n", "an https:// link to a .srs or .mrs set, one per line.\n")
            . $this->t('Для .mrs перед ссылкой можно указать тип: <code>ipcidr https://…/x.mrs</code> (по умолчанию <code>domain</code>).', 'For .mrs you can put the type before the link: <code>ipcidr https://…/x.mrs</code> (default <code>domain</code>).'),
            'saveExitSets', [$id]);
    }

    public function saveExitSets($text, $id): void
    {
        $added = $bad = 0;
        $new = [];
        foreach (array_filter(array_map('trim', preg_split('~\R~', (string) $text))) as $line) {
            $behavior = 'domain';
            if (preg_match('~^(domain|ipcidr)\s+(\S+)$~', $line, $m)) [$behavior, $line] = [$m[1], $m[2]];
            if (!self::exitRulesetUrlValid($line)) { $bad++; continue; }
            $new[$line] = ['on' => 1, 'behavior' => $behavior, 'interval' => 86400];
        }
        // Наборы скачиваются и разбираются до сохранения узла: тогда Xray
        // перезапускается один раз и сразу с их записями.
        $this->exitRulesetPrefetch((string) $id, $new, true);
        $unready = [];
        $error = !$new ? '' : $this->exitEditNode((string) $id, function (array &$node) use ($new, &$added, &$unready) {
            foreach ($new as $url => $set) {
                if (isset($node['rulesets'][$url]) || count($node['rulesets']) >= 20) continue;
                // Строгий узел с нескачанным набором закрыл бы весь трафик своих пользователей.
                if ($node['fallback'] === 'block' && !($this->exitRulesetCache((string) $url)['entries'] ?? [])) { $unready[] = (string) $url; continue; }
                $node['rulesets'][$url] = $set;
                $added++;
            }
            return '';
        });
        $this->exitSetsMenu((string) $id, $error !== '' ? $this->exitError($error) : $this->t("Добавлено: $added", "Added: $added") . ($bad ? $this->t(", не подошло (нужна https:// ссылка на .srs или .mrs): $bad", ", did not fit (an https:// link to .srs or .mrs is needed): $bad") : '') . $this->exitUnreadyNote($unready));
    }

    /**
     * Скачать и разобрать включённые наборы, которые узел $id ещё не содержит
     * (места считаются, как при добавлении: выключенный набор тоже занимает).
     * $force — заново, даже если набор уже в кэше (добавление ссылки вручную);
     * иначе берётся кэш другого узла.
     */
    private function exitRulesetPrefetch(string $id, array $sets, bool $force): void
    {
        $node = $this->exitNodes()[$id] ?? null;
        if ($node === null) return;
        $free = 20 - count($node['rulesets']);
        foreach ($sets as $url => $set) {
            if ($free <= 0) break;
            if (!is_array($set) || isset($node['rulesets'][$url])) continue;
            $free--;
            if (!empty($set['on']) && ($force || !$this->exitRulesetCache((string) $url))) $this->exitRulesetRefresh((string) $url, $set);
        }
    }

    public function exitSetToggle(string $id, string $key, bool $delete = false): void
    {
        $removed = null;
        // Включаемый набор строгого узла скачиваем заранее: без кэша правка отклоняется.
        $node = $this->exitNodes()[$id] ?? null;
        $url = $node === null || $delete ? null : $this->exitFindEntry($node, $key, 'rulesets');
        if ($url !== null && empty($node['rulesets'][$url]['on']) && $this->exitStrict($id) && !($this->exitRulesetCache($url)['entries'] ?? [])) {
            $this->exitRulesetRefresh($url, $node['rulesets'][$url]);
        }
        $error = $this->exitEditNode($id, function (array &$node) use ($key, $delete, &$removed) {
            $url = $this->exitFindEntry($node, $key, 'rulesets');
            if ($url === null) return '';
            if ($delete) { unset($node['rulesets'][$url]); $removed = $url; }
            else $node['rulesets'][$url]['on'] = empty($node['rulesets'][$url]['on']) ? 1 : 0;
            return '';
        });
        if ($error === '' && $removed !== null) $this->exitRulesetForget($removed);
        $this->exitSetsMenu($id, $error === '' ? '' : $this->exitError($error));
    }

    // ── Пользователи узла ──────────────────────────────────────────────────
    public function exitUsersMenu(string $id, int $page = 0, string $notice = ''): void
    {
        $node = $this->exitNodes()[$id] ?? null;
        if ($node === null) { $this->exitNodesMenu($this->t('Узел не найден', 'Node not found')); return; }
        $clients = $this->getXray()['inbounds'][0]['settings']['clients'] ?? [];
        $list = array_filter($clients, static fn($c) => is_array($c) && empty($c['exit_relay']));
        $pages = max(1, (int) ceil(count($list) / self::EXIT_PAGE));
        $page = max(0, min($page, $pages - 1));
        $text = ['Menu -> ' . $this->i18n('xray') . $this->t(' -> Узлы выхода -> ', ' -> Exit nodes -> ') . $this->exitName($id, $node) . $this->t(' -> Пользователи', ' -> Users'),
            $this->t('Маршрут через узел работает только у отмеченных. Служебные учётки узлов здесь не показываются.', 'The route through the node works only for the checked users. Node service accounts are not shown here.')];
        if ($notice !== '') $text[] = "\n<b>" . self::esc($notice) . '</b>';
        $data = [];
        foreach (array_slice($list, $page * self::EXIT_PAGE, self::EXIT_PAGE, true) as $i => $client) {
            $on = in_array($id, self::exitClientNodes($client), true);
            $data[] = [['text' => ($on ? '✅ ' : '⬜ ') . mb_substr((string) ($client['email'] ?? '—'), 0, 40) . (!empty($client['off']) ? ' ⛔' : ''),
                'callback_data' => "/exitU $id " . self::exitClientKey($client) . " $page"]];
        }
        if ($pages > 1) {
            $nav = [];
            if ($page > 0) $nav[] = ['text' => '←', 'callback_data' => "/exitUsers $id " . ($page - 1)];
            $nav[] = ['text' => ($page + 1) . "/$pages", 'callback_data' => "/exitUsers $id $page"];
            if ($page < $pages - 1) $nav[] = ['text' => '→', 'callback_data' => "/exitUsers $id " . ($page + 1)];
            $data[] = $nav;
        }
        $data[] = [['text' => $this->t('✅ Включить всем', '✅ Enable for all'), 'callback_data' => "/exitAll $id on"], ['text' => $this->t('⬜ Выключить всем', '⬜ Disable for all'), 'callback_data' => "/exitAll $id off"]];
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => "/exit $id"]];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $text), $data);
    }

    // Пользователь в кнопке — отпечаток email, а не номер: список мог
    // измениться, пока меню открыто, и узел включился бы не тому.
    public static function exitClientKey(array $client): string
    {
        return substr(hash('sha256', 'exit-user:' . (string) ($client['email'] ?? '')), 0, 10);
    }

    /** Включить/выключить узел пользователям; $only — ключи exitClientKey или номера, null — всем обычным. */
    public function exitSetUsers(string $id, ?array $only, ?bool $on): string
    {
        return $this->applyExitNodes(function (array &$p, array &$x) use ($id, $only, $on) {
            if (!isset($this->exitNodes($p)[$id])) return 'exit not found';
            foreach ($x['inbounds'][0]['settings']['clients'] ?? [] as $i => $client) {
                if (!is_array($client) || !empty($client['exit_relay'])) continue;
                if ($only !== null && !in_array($i, $only, true) && !in_array(self::exitClientKey($client), $only, true)) continue;
                $nodes = self::exitClientNodes($client);
                $want = $on ?? !in_array($id, $nodes, true);
                $nodes = $want ? array_values(array_unique([...$nodes, $id])) : array_values(array_diff($nodes, [$id]));
                if ($nodes) $x['inbounds'][0]['settings']['clients'][$i]['exit'] = $nodes;
                else unset($x['inbounds'][0]['settings']['clients'][$i]['exit']);
            }
            return '';
        });
    }

    public function exitUserToggle(string $id, string $key, int $page = 0): void
    {
        $error = $this->exitSetUsers($id, [$key], null);
        $this->exitUsersMenu($id, $page, $error === '' ? '' : $this->exitError($error));
    }

    public function exitAllUsers(string $id, bool $on): void
    {
        $error = $this->exitSetUsers($id, null, $on);
        $this->exitUsersMenu($id, 0, $error === '' ? ($on ? $this->t('Включено всем', 'Enabled for all') : $this->t('Выключено всем', 'Disabled for all')) : $this->exitError($error));
    }

    // Карточка пользователя → его узлы. У служебной учётки «Профиль для узла»
    // своих узлов нет: вместо пустого списка — её назначение и переход к
    // профилю (ссылка для основного сервера, режим выхода).
    public function exitUserMenu(int $i, string $notice = ''): void
    {
        $client = $this->getXray()['inbounds'][0]['settings']['clients'][$i] ?? null;
        if (!is_array($client)) { $this->xray(); return; }
        $text = ['Menu -> ' . $this->i18n('xray') . ' -> ' . self::esc((string) ($client['email'] ?? '')) . $this->t(' -> Узлы выхода', ' -> Exit nodes')];
        if ($notice !== '') $text[] = "\n<b>" . self::esc($notice) . '</b>';
        $data = [];
        if (!empty($client['exit_relay'])) {
            $text[] = $this->t('Это служебная учётка «Профиль для узла»: через неё другой сервер с vpnbot выпускает трафик своих пользователей через этот сервер. Узлы этого сервера ей не назначаются (защита от петли).',
                'This is a “Node profile” service account: another vpnbot server sends its users’ traffic out through this server with it. This server’s nodes are not assigned to it (loop protection).');
            $text[] = $this->t('Выход: ', 'Egress: ') . (!empty($client['exit_ipv6']) ? $this->t('только IPv6 этого сервера', 'this server’s IPv6 only') : $this->t('обычный', 'normal'))
                . $this->t('. Ссылка, подписка и режим выхода — в профиле.', '. The link, subscription and egress mode are in the profile.');
            $data[] = [['text' => $this->t('🪪 Открыть профиль для узла', '🪪 Open the node profile'), 'callback_data' => "/exitRelayLink $i"]];
        } else {
            $mine = self::exitClientNodes($client);
            $key = self::exitClientKey($client);
            foreach ($this->exitNodes() as $id => $node) {
                $id = (string) $id;
                $data[] = [['text' => (in_array($id, $mine, true) ? '✅ ' : '⬜ ') . mb_substr($node['name'] !== '' ? $node['name'] : $id, 0, 40)
                    . ($node['enabled'] ? '' : $this->t(' (выключен)', ' (disabled)')), 'callback_data' => "/exitUT $i $id $key"]];
            }
            if (!$this->exitNodes()) $text[] = $this->t('Узлов нет: Xray → Узлы выхода.', 'No nodes: Xray → Exit nodes.');
        }
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => "/userXr $i"]];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $text), $data);
    }

    public function exitUserNodeToggle(int $i, string $id, string $key = ''): void
    {
        $client = $this->getXray()['inbounds'][0]['settings']['clients'][$i] ?? null;
        // Кнопка несёт отпечаток пользователя: после удаления кого-то из
        // списка номер $i указывает на другого человека.
        if (!is_array($client) || $key === '' || !hash_equals(self::exitClientKey($client), $key)) { $this->exitUserMenu($i, $this->exitError('exit stale')); return; }
        $error = $this->exitSetUsers($id, [$key], null);
        $this->exitUserMenu($i, $error === '' ? '' : $this->exitError($error));
    }

    // ── «Куда пойдёт домен» ────────────────────────────────────────────────
    // Ответ даёт само ядро: временный Xray в контейнере xr получает правила
    // сервера в том же порядке, по одному SOCKS-входу на каждого проверяемого
    // пользователя (w<k>) и по выходу-«чёрной дыре» на каждое правило (r<n>).
    // Поля user и inboundTag бот заменяет входами, сеть и порт сверяет сам
    // (TCP 443); правила с полями, которые без настоящего соединения не
    // проверить (source, protocol, process…), не участвуют. Журнал доступа
    // ядра показывает, какое правило сработало («->»), или выход по
    // умолчанию («>>»). Домен проверяется так же, как его видит сервер,
    // включая geosite/ext и IPIfNonMatch.
    public const EXIT_TRACE_MAX_CASES = 8;
    public const EXIT_TRACE_FIELDS = ['type', 'ruleTag', 'domain', 'ip', 'port', 'network', 'inboundTag', 'user', 'outboundTag', 'balancerTag', 'domainMatcher'];

    /** Домен или адрес из ввода (ссылку, «host:порт», «host/путь» тоже принимает); null — не подходит. */
    public static function exitTraceTarget(string $raw): ?string
    {
        $raw = trim($raw);
        if (preg_match('~^[a-z][a-z0-9+.-]*://~i', $raw)) $raw = (string) parse_url($raw, PHP_URL_HOST);
        $raw = preg_replace('~[/?#].*$~s', '', $raw) ?? '';
        if (preg_match('~^\[([0-9a-f:.]+)\](?::\d+)?$~i', $raw, $m)) $raw = $m[1];
        elseif (substr_count($raw, ':') === 1) $raw = explode(':', $raw)[0];
        $raw = strtolower(trim($raw, ". \t"));
        if (filter_var($raw, FILTER_VALIDATE_IP) !== false) return $raw;
        return preg_match('~^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$~D', $raw) ? $raw : null;
    }

    public static function exitPortMatches($spec, int $port): bool
    {
        foreach (preg_split('~\s*,\s*~', trim(is_array($spec) ? implode(',', $spec) : (string) $spec)) as $part) {
            if (preg_match('~^(\d+)\s*-\s*(\d+)$~', $part, $m) && $port >= (int) $m[1] && $port <= (int) $m[2]) return true;
            if (preg_match('~^\d+$~', $part) && (int) $part === $port) return true;
        }
        return false;
    }

    public static function exitUserMatches(array $users, string $email): bool
    {
        foreach ($users as $user) {
            $user = (string) $user;
            if ($user === $email) return true;
            if (str_starts_with($user, 'regexp:') && @preg_match('~' . str_replace('~', '\~', substr($user, 7)) . '~', $email) === 1) return true;
        }
        return false;
    }

    public static function exitIpInCidr(string $ip, string $cidr): bool
    {
        [$net, $bits] = array_pad(explode('/', $cidr, 2), 2, null);
        $a = @inet_pton($ip);
        $b = @inet_pton((string) $net);
        if ($a === false || $b === false || strlen($a) !== strlen($b)) return false;
        $bits = $bits === null || $bits === '' ? strlen($a) * 8 : max(0, min(strlen($a) * 8, (int) $bits));
        $bytes = intdiv($bits, 8);
        if (substr($a, 0, $bytes) !== substr($b, 0, $bytes)) return false;
        if ($bits % 8 === 0) return true;
        $mask = (0xff << (8 - $bits % 8)) & 0xff;
        return (ord($a[$bytes]) & $mask) === (ord($b[$bytes]) & $mask);
    }

    /** Временный конфиг: $cases — [['label' => …, 'email' => string|null], …]. */
    public function exitTraceConfig(array $x, array $cases, int $base, string $dir): array
    {
        $main = (string) ($x['inbounds'][0]['tag'] ?? '');
        $rules = [['type' => 'field', 'inboundTag' => ['trace-dns'], 'outboundTag' => 'trace-dns-out']];
        $outbounds = [['protocol' => 'blackhole', 'tag' => 'r-default'], ['protocol' => 'freedom', 'tag' => 'trace-dns-out']];
        foreach ($x['routing']['rules'] ?? [] as $n => $r) {
            if (!is_array($r) || array_diff(array_keys($r), self::EXIT_TRACE_FIELDS)) continue;
            if (isset($r['network']) && !in_array('tcp', preg_split('~\s*,\s*~', strtolower(is_array($r['network']) ? implode(',', $r['network']) : (string) $r['network'])), true)) continue;
            if (isset($r['port']) && !self::exitPortMatches($r['port'], 443)) continue;
            if (isset($r['inboundTag']) && !in_array($main, (array) $r['inboundTag'], true)) continue;
            $tags = [];
            foreach ($cases as $k => $case) {
                if (!isset($r['user']) || ($case['email'] !== null && self::exitUserMatches((array) $r['user'], (string) $case['email']))) $tags[] = "w$k";
            }
            if (!$tags) continue;
            $rule = ['type' => 'field', 'inboundTag' => $tags, 'outboundTag' => "r$n"];
            foreach (['domain', 'ip', 'domainMatcher'] as $field) if (isset($r[$field])) $rule[$field] = $r[$field];
            $rules[] = $rule;
            $outbounds[] = ['protocol' => 'blackhole', 'tag' => "r$n"];
        }
        $inbounds = [];
        foreach (array_keys($cases) as $k) $inbounds[] = ['tag' => "w$k", 'listen' => '127.0.0.1', 'port' => $base + $k, 'protocol' => 'socks', 'settings' => ['auth' => 'noauth', 'udp' => false]];
        // Запросы DNS самого ядра (IPIfNonMatch) — мимо проверяемых правил.
        $dns = is_array($x['dns'] ?? null) ? $x['dns'] : ['servers' => ['localhost']];
        $dns['tag'] = 'trace-dns';
        $routing = ['domainStrategy' => $x['routing']['domainStrategy'] ?? 'AsIs', 'rules' => $rules];
        if (isset($x['routing']['domainMatcher'])) $routing['domainMatcher'] = $x['routing']['domainMatcher'];
        return ['log' => ['loglevel' => 'warning', 'access' => "$dir/access.log", 'error' => "$dir/error.log"],
            'dns' => $dns, 'inbounds' => $inbounds, 'outbounds' => $outbounds, 'routing' => $routing];
    }

    // /logs общий с xr: ядро читает конфиг и пишет журналы туда. В тестах подменяется.
    protected function exitTraceRoot(): string
    {
        return '/logs';
    }

    /** k => номер сработавшего правила xray.json, -1 — выход по умолчанию, null — ответа ядра нет; null целиком — ядро не запустилось. */
    public function exitTrace(string $target, array $cases): ?array
    {
        $x = $this->getXray();
        if (!is_array($x) || !$cases) return null;
        $base = random_int(41000, 48000);
        $dir = $this->exitTraceRoot() . '/.exit-trace-' . bin2hex(random_bytes(6));
        if (!@mkdir($dir, 0700)) return null;
        try {
            $json = json_encode($this->exitTraceConfig($x, $cases, $base, $dir), JSON_UNESCAPED_SLASHES);
            if ($json === false || @file_put_contents("$dir/config.json", $json) === false) return null;
            $host = str_contains($target, ':') ? "[$target]" : $target;
            $curl = '';
            foreach (array_keys($cases) as $k) $curl .= 'curl -s -o /dev/null --max-time 5 --socks5-hostname 127.0.0.1:' . ($base + $k) . ' ' . escapeshellarg("https://$host/") . '; ';
            $bin = self::XRAY_BINARIES[$this->xrayCoreSelection()];
            $out = (string) $this->ssh('XRAY_LOCATION_ASSET=/logs/geodata timeout 60 ' . escapeshellarg($bin) . ' run -c ' . escapeshellarg("$dir/config.json")
                . ' >/dev/null 2>&1 & p=$!; i=0; while [ $i -lt 300 ] && ! grep -q " started" ' . escapeshellarg("$dir/error.log") . ' 2>/dev/null; do sleep 0.1; i=$((i+1)); done; '
                . 'grep -q " started" ' . escapeshellarg("$dir/error.log") . ' 2>/dev/null && printf TRACE_STARTED; ' . $curl
                . 'sleep 0.5; kill $p 2>/dev/null; wait $p 2>/dev/null; true', 'xr');
            if ($this->sshFailed || !str_contains($out, 'TRACE_STARTED')) return null;
            $result = array_fill_keys(array_keys($cases), null);
            preg_match_all('~\[w(\d+) (?:->|>>) r(-default|\d+)\]~', (string) @file_get_contents("$dir/access.log"), $m, PREG_SET_ORDER);
            foreach ($m as [, $k, $rule]) if (array_key_exists((int) $k, $result) && $result[(int) $k] === null) $result[(int) $k] = $rule === '-default' ? -1 : (int) $rule;
            return $result;
        } finally {
            foreach (glob("$dir/*") ?: [] as $file) @unlink($file);
            @rmdir($dir);
        }
    }

    /** Запись списка, которой подходит домен или адрес: ['entry' => …, 'exact' => bool] или null. */
    public function exitTraceEntry(string $host, array $entries): ?array
    {
        $ip = filter_var($host, FILTER_VALIDATE_IP) !== false;
        $category = null;
        foreach ($entries as $entry) {
            $c = $this->classifyRouteEntry((string) $entry);
            $v = strtolower($c['value']);
            $hit = match ($c['kind']) {
                'domain', 'suffix' => !$ip && $v !== '' && ($host === $v || str_ends_with($host, ".$v")),
                'full' => !$ip && $host === $v,
                'keyword' => !$ip && $v !== '' && str_contains($host, $v),
                'regexp' => !$ip && $c['value'] !== '' && @preg_match('~' . str_replace('~', '\~', $c['value']) . '~', $host) === 1,
                'ip' => $ip && self::exitIpInCidr($host, $c['value']),
                default => false,
            };
            if ($hit) return ['entry' => (string) $entry, 'exact' => true];
            if (in_array($c['kind'], ['geosite', 'geoip', 'ext', 'extip'], true)) $category ??= (string) $entry;
        }
        return $category === null ? null : ['entry' => $category, 'exact' => false];
    }

    /** Пользователи для проверки: заданный или «без узлов» и по одному пользователю каждого узла. */
    public function exitTraceCases(?string $email): array
    {
        $x = $this->getXray();
        if ($email !== null) {
            foreach ($x['inbounds'][0]['settings']['clients'] ?? [] as $client) {
                $have = (string) ($client['email'] ?? '');
                if ($have !== '' && strcasecmp($have, $email) === 0) return [['label' => $have, 'email' => $have, 'off' => !empty($client['off'])]];
            }
            return [];
        }
        $cases = [['label' => $this->t('пользователь без узлов', 'a user without nodes'), 'email' => null, 'off' => false]];
        foreach ($this->exitNodes() as $id => $node) {
            if (empty($node['enabled']) || count($cases) >= self::EXIT_TRACE_MAX_CASES) continue;
            $emails = $this->exitNodeEmails($x, (string) $id);
            if ($emails) $cases[] = ['label' => $this->t('пользователи узла ', 'users of node ') . ($node['name'] !== '' ? $node['name'] : (string) $id) . " ({$emails[0]})", 'email' => $emails[0], 'off' => false];
        }
        return $cases;
    }

    /** Строки ответа для одного пользователя по номеру правила. */
    public function exitTraceDescribe(?int $rule, string $host): string
    {
        if ($rule === null) return $this->t('ядро не ответило', 'the core did not answer');
        $x = $this->getXray();
        $p = $this->getPacConf();
        if ($rule < 0) {
            return $this->exitTraceOutbound((string) ($x['outbounds'][0]['tag'] ?? 'direct'))
                . $this->t("\n   ни одно правило не подошло — выход по умолчанию", "\n   no rule matched: the default outbound");
        }
        $r = $x['routing']['rules'][$rule] ?? [];
        $to = (string) ($r['balancerTag'] ?? $r['outboundTag'] ?? '');
        $tag = (string) ($r['ruleTag'] ?? '');
        $text = $this->exitTraceOutbound($to);
        $entries = null;
        if (preg_match('~^vpnbot:routes:(block|warp):~', $tag, $m)) {
            $text .= "\n   " . ($m[1] === 'block' ? $this->t('правило: блок-лист (Vless → routes)', 'rule: block list (Vless → routes)') : $this->t('правило: список WARP (Vless → routes)', 'rule: WARP list (Vless → routes)'));
            $entries = array_keys(array_filter($p[$m[1] === 'block' ? 'blocklist' : 'warplist'] ?? []));
        } elseif (preg_match('~^' . preg_quote(self::EXIT_RULE, '~') . '([a-f0-9]{8}):~', $tag, $m) && ($node = $this->exitNodes($p)[$m[1]] ?? null)) {
            $text .= "\n   " . $this->t('правило: маршруты узла', 'rule: node routes');
            $entries = array_keys($this->exitNodeEntries($node));
        } else {
            $text .= "\n   " . ($tag !== '' ? $this->t('правило ', 'rule ') . '<code>' . self::esc($tag) . '</code>' : $this->t('правило №', 'rule #') . ($rule + 1) . $this->t(' в xray.json (без метки)', ' in xray.json (no tag)'));
        }
        if ($entries !== null && ($hit = $this->exitTraceEntry($host, $entries)) !== null) {
            $text .= $hit['exact'] ? $this->t(', запись ', ', entry ') . '<code>' . self::esc($hit['entry']) . '</code>'
                : $this->t(', одна из категорий .dat (например <code>', ', one of the .dat categories (e.g. <code>') . self::esc($hit['entry']) . '</code>)';
        } elseif ($entries !== null && filter_var($host, FILTER_VALIDATE_IP) === false && isset($r['ip']) && !isset($r['domain'])) {
            $text .= $this->t(', по адресу, в который разрешился домен', ', by the address the domain resolved to');
        }
        return $text;
    }

    private function exitTraceOutbound(string $to): string
    {
        if ($to === self::EXIT_IPV6_TAG) {
            return '🌍 ' . $this->t('через IPv6 этого сервера (профиль для узла «Выход: только IPv6»)', 'through this server’s IPv6 (node profile “Egress: IPv6 only”)');
        }
        if (str_starts_with($to, self::EXIT_TAG)) {
            $id = substr($to, strlen(self::EXIT_TAG));
            $node = $this->exitNodes()[$id] ?? null;
            $line = '🌍 ' . $this->t('через узел ', 'through node ') . '<b>' . ($node ? $this->exitName($id, $node) : self::esc($id)) . '</b>';
            $s = $this->exitStatus()[$id] ?? [];
            if ($s && empty($s['ok'])) $line .= $node && !self::exitDirectFallback($node)
                ? $this->t(' — сейчас узел не отвечает, поэтому соединение будет закрыто (запасного выхода нет)', ': the node is not answering now, so the connection will be closed (no fallback)')
                : $this->t(' — сейчас узел не отвечает, поэтому напрямую', ': the node is not answering now, so direct');
            if ($node && $node['quic'] === 'block') $line .= $this->t("\n   QUIC (UDP 443) к нему блокируется: браузер перейдёт на TCP", "\n   QUIC (UDP 443) to it is blocked: the browser switches to TCP");
            return $line;
        }
        return match ($to) {
            'block' => '🚫 ' . $this->t('блокируется', 'blocked'),
            'warp' => '☁️ WARP',
            'direct' => '➡️ ' . $this->t('напрямую с этого сервера', 'direct from this server'),
            default => '➡️ ' . $this->t('выход ', 'outbound ') . '<code>' . self::esc($to) . '</code>',
        };
    }

    public function exitWherePrompt(): void
    {
        $this->exitPrompt($this->t("домен или адрес, а через пробел — пользователь Xray (необязательно).\nНапример: <code>www.youtube.com</code> или <code>chatgpt.com alice</code>.\nБез пользователя бот покажет маршрут для пользователя без узлов и для пользователей каждого узла.",
            "a domain or address and, after a space, an Xray user (optional).\nFor example: <code>www.youtube.com</code> or <code>chatgpt.com alice</code>.\nWithout a user the bot shows the route for a user without nodes and for users of each node."), 'saveExitWhere', []);
    }

    public function saveExitWhere($text): void
    {
        $parts = preg_split('~\s+~', trim((string) $text), 2);
        $target = self::exitTraceTarget((string) ($parts[0] ?? ''));
        $lines = ['Menu -> ' . $this->i18n('xray') . $this->t(' -> Узлы выхода -> Куда пойдёт домен', ' -> Exit nodes -> Where a domain goes')];
        if ($target === null) {
            $lines[] = $this->t('Не похоже на домен или адрес: ', 'This does not look like a domain or address: ') . '<code>' . self::esc(mb_substr((string) ($parts[0] ?? ''), 0, 100)) . '</code>';
        } else {
            $user = isset($parts[1]) ? trim($parts[1]) : null;
            $cases = $this->exitTraceCases($user === '' ? null : $user);
            $lines[] = '<code>' . self::esc($target) . '</code>' . $this->t(' — TCP 443, как запрос видит этот сервер', ': TCP 443, as this server sees the request');
            if (!$cases) {
                $lines[] = $this->t('Пользователь не найден: ', 'User not found: ') . '<code>' . self::esc(mb_substr((string) $user, 0, 60)) . '</code>';
            } elseif (($result = $this->exitTrace($target, $cases)) === null) {
                $lines[] = $this->t('Проверка не удалась: временный Xray в контейнере xr не запустился.', 'The check failed: the temporary Xray in the xr container did not start.');
            } else {
                foreach ($cases as $k => $case) {
                    $lines[] = "\n<b>" . self::esc($case['label']) . '</b>' . (!empty($case['off']) ? $this->t(' (отключён)', ' (disabled)') : '') . ":\n" . $this->exitTraceDescribe($result[$k] ?? null, $target);
                }
                $lines[] = $this->t("\nКлиенты sing-box и Mihomo сами отправляют домены из списка WARP в WARP, а домены, которые приложение шлёт мимо VPN, до сервера не доходят.",
                    "\nsing-box and Mihomo clients send WARP-list domains to WARP by themselves, and domains an app sends outside the VPN never reach the server.");
            }
        }
        $data = [[['text' => $this->t('🧭 Другой домен', '🧭 Another domain'), 'callback_data' => '/exitWhere']], [['text' => $this->i18n('back'), 'callback_data' => '/exits']]];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $lines), $data);
    }

    // ── Этот сервер как узел: «Профиль для узла» ───────────────────────────
    // Служебная учётка без срока и лимита трафика. Её трафик никогда не уходит
    // на узлы этого бота (exitClientNodes ей пусто) — так связка двух ботов,
    // указывающих друг на друга, не превращается в петлю.
    public function exitRelayMenu(string $notice = ''): void
    {
        $clients = $this->getXray()['inbounds'][0]['settings']['clients'] ?? [];
        $text = ['Menu -> ' . $this->i18n('xray') . $this->t(' -> Профиль для узла', ' -> Node profile'),
            $this->t('Этот сервер станет узлом выхода для другого бота: создайте служебную учётку и вставьте её ссылку на основном сервере в Xray → Узлы выхода → «Добавить узел».', 'This server becomes an exit node for another bot: create a service account and paste its link on the main server in Xray → Exit nodes → Add node.'),
            $this->t('Учётка без срока и лимита; её трафик никогда не уходит на узлы этого сервера (защита от петли).', 'The account has no expiry or limit; its traffic never goes to this server\'s nodes (loop protection).'),
            $this->t('⚠️ Добавьте адрес основного сервера в список «своих» адресов межсетевого экрана этого сервера (my_server в профилях nftables nftables). Иначе с его адреса пройдёт не больше 30 одновременных соединений и 30 новых в секунду — весь трафик его пользователей идёт с одного адреса и упрётся в этот лимит.', '⚠️ Add the main server address to this server’s firewall list of own addresses (my_server in the nftables nftables profiles). Otherwise its address gets at most 30 concurrent connections and 30 new ones per second: all its users’ traffic comes from one address and hits that limit.')];
        if ($notice !== '') $text[] = "\n<b>" . self::esc($notice) . '</b>';
        $data = [];
        foreach ($clients as $i => $client) {
            if (empty($client['exit_relay'])) continue;
            $data[] = [['text' => '🪪 ' . mb_substr((string) ($client['email'] ?? '—'), 0, 40) . (!empty($client['off']) ? ' ⛔' : ''), 'callback_data' => "/exitRelayLink $i"]];
        }
        $data[] = [['text' => $this->t('➕ Создать профиль для узла', '➕ Create node profile'), 'callback_data' => '/exitRelayAdd']];
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => '/exits']];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $text), $data);
    }

    public function exitRelayAddPrompt(): void
    {
        $this->exitPrompt($this->t('имя профиля для узла, например имя основного сервера (латиница, цифры, точка, дефис):', 'node profile name, e.g. the name of the main server (Latin letters, digits, dot, hyphen):'), 'saveExitRelay', []);
    }

    public function saveExitRelay($name): void
    {
        // «node-» бот добавляет сам; введённый с ним же префикс не удваиваем.
        $name = 'node-' . preg_replace('~^node-~i', '', trim((string) $name));
        if (!preg_match('~^node-[A-Za-z0-9][A-Za-z0-9._-]{0,30}$~D', $name)) { $this->exitRelayMenu($this->t('Имя: латиница, цифры, точка, дефис, до 30 символов', 'Name: Latin letters, digits, dot, hyphen, up to 30 characters')); return; }
        $index = null;
        $error = $this->applyExitNodes(function (array &$p, array &$x) use ($name, &$index) {
            foreach ($x['inbounds'][0]['settings']['clients'] ?? [] as $client) if (($client['email'] ?? '') === $name) return 'exit duplicate';
            $client = ['id' => self::xrayUuid(), 'email' => $name, 'subtoken' => bin2hex(random_bytes(16)), 'exit_relay' => 1];
            if (($p['transport'] ?? '') === 'Reality') $client['flow'] = 'xtls-rprx-vision';
            if (($p['transport'] ?? '') === 'trojan-grpc') $client['password'] = bin2hex(random_bytes(16));
            $x['inbounds'][0]['settings']['clients'][] = $client;
            $index = count($x['inbounds'][0]['settings']['clients']) - 1;
            return '';
        });
        if ($error !== '' || $index === null) { $this->exitRelayMenu($error === 'exit duplicate' ? $this->t('Профиль с таким именем уже есть', 'A profile with this name already exists') : $this->exitError($error)); return; }
        $this->exitRelayLink($index, $this->t('Профиль создан', 'Profile created'));
    }

    public function exitRelayLink(int $i, string $notice = ''): void
    {
        $client = $this->getXray()['inbounds'][0]['settings']['clients'][$i] ?? null;
        if (!is_array($client) || empty($client['exit_relay'])) { $this->exitRelayMenu($this->t('Профиль не найден', 'Profile not found')); return; }
        $link = (string) $this->linkXray($i);
        $text = ['Menu -> ' . $this->i18n('xray') . $this->t(' -> Профиль для узла -> ', ' -> Node profile -> ') . self::esc((string) $client['email'])];
        if ($notice !== '') $text[] = '<b>' . self::esc($notice) . '</b>';
        $text[] = $link !== '' ? $this->t("Ссылка для основного сервера (Xray → Узлы выхода → «Добавить узел»):\n<pre><code>", "Link for the main server (Xray → Exit nodes → Add node):\n<pre><code>") . self::esc($link) . '</code></pre>'
            : $this->t('Ссылку не выдать: текущий транспорт Xray её не поддерживает.', 'No link: the current Xray transport does not support it.');
        if ($link !== '') {
            $pac = $this->getPacConf();
            $hash = $this->getHashBot();
            $sub = (empty($this->nginxGetTypeCert()) ? 'http' : 'https') . '://' . $this->getDomain(($pac['transport'] ?? '') != 'Reality') . "/pac$hash/"
                . base64_encode(serialize(['h' => $hash, 't' => 'vl', 's' => $this->sidOf($client)]));
            $text[] = $this->t("Подписка для автообновления (основной сервер: карточка узла → «🔄 Подписка узла»; после «Новых ключей» или смены транспорта он сам возьмёт новую ссылку):\n<pre><code>", "Subscription for auto-update (main server: node card → 🔄 Node subscription; after New keys or a transport change it takes the new link itself):\n<pre><code>")
                . self::esc($sub) . '</code></pre>';
        }
        $text[] = $this->t('Отозвать доступ — удалить профиль кнопкой ниже или отключить эту учётку в списке пользователей Xray.', 'To revoke access, delete the profile with the button below or disable this account in the Xray user list.');
        $data = [
            [['text' => !empty($client['exit_ipv6']) ? $this->t('Выход: только IPv6', 'Egress: IPv6 only') : $this->t('Выход: обычный', 'Egress: normal'), 'callback_data' => "/exitRelayIpv6 $i " . self::exitRelayMark($client)]],
            [['text' => $this->t('🗑 Удалить профиль', '🗑 Delete profile'), 'callback_data' => "/exitRelayDel $i"]],
            [['text' => $this->i18n('back'), 'callback_data' => '/exitRelay']],
        ];
        if (!empty($client['exit_ipv6'])) $text[] = $this->t('Для этой учётки весь разрешённый трафик выходит только через IPv6 этого сервера. На основном сервере выберите «При отказе: блок». Нужна подготовленная сеть IPv6; домену нужна AAAA-запись.', 'All permitted traffic for this account exits only through this server’s IPv6. Select “On failure: block” on the main server. The IPv6 network must be prepared; domains need AAAA records.');
        if (!empty($client['exit_ipv6']) && empty($this->exitIpv6Network()['enabled'])) {
            $text[] = $this->exitIpv6Attached()
                ? $this->t('⚠️ Файл настройки IPv6 (config/ipv6-egress.json) повреждён: повторите подготовку на хосте.', '⚠️ The IPv6 settings file (config/ipv6-egress.json) is damaged: repeat the host preparation.')
                : $this->t('⚠️ Сеть IPv6 на этом сервере не подготовлена: сейчас весь трафик этого профиля блокируется. Подготовьте сеть по README или верните «Выход: обычный».', '⚠️ The IPv6 network is not prepared on this server: all traffic of this profile is blocked now. Prepare the network as described in the README or switch back to “Egress: normal”.');
        }
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $text), $data);
    }

    // Имя и идентификатор доступа: старое подтверждение не удаляет новый
    // профиль, созданный с тем же именем и оказавшийся на том же месте.
    public function exitRelayDelete(int $i, string $mark = ''): void
    {
        $client = $this->getXray()['inbounds'][0]['settings']['clients'][$i] ?? null;
        if (!is_array($client) || empty($client['exit_relay'])) { $this->exitRelayMenu($this->t('Профиль не найден', 'Profile not found')); return; }
        $source = ManagedProtocol::xraySource($client);
        $expected = self::exitRelayMark($client);
        if ($mark === '') {
            $this->update($this->input['chat'], $this->input['message_id'],
                $this->t('Удалить профиль для узла <b>', 'Delete node profile <b>') . self::esc((string) ($client['email'] ?? '')) . $this->t('</b>? Основной сервер, где он добавлен узлом, больше не сможет через него выходить.', '</b>? The main server that added it as a node can no longer exit through it.'),
                [[['text' => $this->t('🗑 Да, удалить', '🗑 Yes, delete'), 'callback_data' => "/exitRelayDelYes $i $expected"], ['text' => $this->i18n('back'), 'callback_data' => "/exitRelayLink $i"]]]);
            return;
        }
        if (!hash_equals($expected, $mark)) { $this->exitRelayMenu($this->t('Профиль не найден', 'Profile not found')); return; }
        if (!$this->delxr($i, false, $source)) {
            $this->exitRelayMenu($this->t('Не удалось удалить профиль. Прежний доступ сохранён.', 'Could not delete the profile. The previous access is preserved.'));
            return;
        }
        $this->exitRelayMenu($this->t('Профиль удалён', 'Profile deleted'));
    }
}
