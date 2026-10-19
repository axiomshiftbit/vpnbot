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
//    fallbackTag direct), служебный SOCKS-вход проверки на 127.0.0.1 внутри xr
//    и правила vpnbot:exit:<id>:* с полем user — только для пользователей, у
//    которых узел включён (client.exit = [id…]);
//  - порядок: защитные правила и торренты → блок-лист → узлы → WARP → свои
//    правила; блокировка всегда старше узла;
//  - всё своё помечено префиксами и снимается перед каждой сборкой: удалённый
//    или выключенный узел не оставляет в конфиге ничего.
trait BotExitNodes
{
    public const EXIT_TAG = 'vpnbot-exit-';
    public const EXIT_PROBE_TAG = 'vpnbot-exit-probe-';
    public const EXIT_RULE = 'vpnbot:exit:';
    public const EXIT_PROBE_PORT = 10870;
    public const EXIT_MAX = 8;
    public const EXIT_PROBE_URL = 'https://www.gstatic.com/generate_204';
    // burstObservatory: 3 пробы за 30 с в случайные моменты, окно живости 60 с.
    // Узел «мёртв», только если в окне отказали ВСЕ пробы (обычная observatory
    // хоронит после одной потерянной пробы — YouTube дёргался бы на прямой выход).
    public const EXIT_PING = ['destination' => self::EXIT_PROBE_URL, 'interval' => '10s', 'sampling' => 3, 'timeout' => '5s'];
    public const EXIT_RULESET_DIR = '/logs/exit-rulesets';
    public const EXIT_RULESET_MAX_BYTES = 16 * 1024 * 1024;
    public const EXIT_RULESET_MAX_ENTRIES = 200000;
    // Домены YouTube без зависимости от geosite.dat (кнопка «YouTube»).
    public const EXIT_YOUTUBE = ['domain:youtube.com', 'domain:googlevideo.com', 'domain:ytimg.com', 'domain:ggpht.com',
        'domain:youtu.be', 'domain:youtube-nocookie.com', 'domain:youtubei.googleapis.com', 'domain:youtubekids.com',
        'domain:yt.be', 'domain:youtube.googleapis.com', 'domain:wide-youtube.l.google.com'];

    public static function exitNodeDefaults(): array
    {
        return ['name' => '', 'link' => '', 'enabled' => 1, 'quic' => 'block', 'routes' => [], 'rulesets' => [],
            'created' => 0, 'status' => []];
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
            $node['enabled'] = empty($node['enabled']) ? 0 : 1;
            $node['quic'] = $node['quic'] === 'pass' ? 'pass' : 'block';
            foreach (['routes', 'rulesets', 'status'] as $field) $node[$field] = is_array($node[$field]) ? $node[$field] : [];
            $nodes[$id] = $node;
        }
        return $nodes;
    }

    /** Новый id: всегда с буквой, иначе ключ массива станет числом. */
    public static function exitNewId(): string
    {
        do $id = bin2hex(random_bytes(4)); while (!preg_match('~[a-f]~', $id));
        return $id;
    }

    public function exitNodeOutbound(array $node): ?array
    {
        try {
            return ExitNodeLink::parse($node['link'])['outbound'];
        } catch (InvalidArgumentException $e) {
            return null;
        }
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

    public function exitRulesetFile(string $key): string
    {
        return self::EXIT_RULESET_DIR . '/' . substr(hash('sha256', $key), 0, 24) . '.json';
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

    public function ensureExitNodes(array &$c, ?array $p = null): void
    {
        $p = $p ?? $this->getPacConf();
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
        // свой префикс; своя — та, где кроме нашего префикса ничего нет.
        $foreign = null;
        foreach (['burstObservatory', 'observatory'] as $block) {
            if (!is_array($c[$block] ?? null)) continue;
            $left = array_values(array_diff((array) ($c[$block]['subjectSelector'] ?? []), [self::EXIT_TAG]));
            if (!$left) { unset($c[$block]); continue; }
            $c[$block]['subjectSelector'] = $left;
            $foreign ??= $block;
        }

        $probe = $rules = [];
        $balanced = false;
        $index = 0;
        foreach ($this->exitNodes($p) as $id => $node) {
            $id = (string) $id;
            $port = self::EXIT_PROBE_PORT + $index++;
            if (empty($node['enabled']) || ($outbound = $this->exitNodeOutbound($node)) === null) continue;
            $tag = self::EXIT_TAG . $id;
            $c['outbounds'][] = $outbound + ['tag' => $tag];
            // Вход проверки: узел напрямую, без запасного пути — «Проверить»
            // должен видеть сам узел, а не обход.
            $c['inbounds'][] = ['tag' => self::EXIT_PROBE_TAG . $id, 'listen' => '127.0.0.1', 'port' => $port,
                'protocol' => 'socks', 'settings' => ['auth' => 'noauth', 'udp' => false]];
            $probe[] = ['type' => 'field', 'ruleTag' => self::EXIT_RULE . $id . ':probe',
                'inboundTag' => [self::EXIT_PROBE_TAG . $id], 'outboundTag' => $tag];
            $emails = $this->exitNodeEmails($c, $id);
            $x = $this->listToXrayRules($this->exitNodeEntries($node));
            if (!$emails || (!$x['domain'] && !$x['ip'])) continue;
            $c['routing']['balancers'][] = ['tag' => $tag, 'selector' => [$tag], 'strategy' => ['type' => 'random'], 'fallbackTag' => 'direct'];
            $balanced = true;
            // QUIC к доменам узла режем: браузер сразу переходит на TCP, и тот
            // идёт через узел (QUIC внутри TCP-туннеля к тому же медленнее).
            if ($node['quic'] === 'block') {
                foreach (['domain', 'ip'] as $field) if ($x[$field]) $rules[] = ['type' => 'field', 'ruleTag' => self::EXIT_RULE . "$id:quic-$field",
                    'user' => $emails, $field => $x[$field], 'network' => 'udp', 'port' => '443', 'outboundTag' => 'block'];
            }
            foreach (['domain', 'ip'] as $field) if ($x[$field]) $rules[] = ['type' => 'field', 'ruleTag' => self::EXIT_RULE . "$id:$field",
                'user' => $emails, $field => $x[$field], 'balancerTag' => $tag];
        }
        if ($rules) {
            $this->ensureBlockOutbound($c);
            $this->ensureDirectOutbound($c);
            $position = 0;
            foreach ($c['routing']['rules'] as $k => $rule) {
                if (str_starts_with((string) ($rule['ruleTag'] ?? ''), 'vpnbot:routes:block:')) $position = $k + 1;
            }
            array_splice($c['routing']['rules'], $position, 0, $rules);
        }
        if ($probe) array_unshift($c['routing']['rules'], ...$probe);
        if ($balanced) {
            if ($foreign !== null) {
                $c[$foreign]['subjectSelector'] = array_values(array_unique(array_merge($c[$foreign]['subjectSelector'], [self::EXIT_TAG])));
            } else {
                $c['burstObservatory'] = ['subjectSelector' => [self::EXIT_TAG], 'pingConfig' => self::EXIT_PING];
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

    public function exitStatus(): array
    {
        $data = @json_decode((string) @file_get_contents(self::EXIT_STATUS_FILE), true);
        return is_array($data) ? $data : [];
    }

    private function exitStatusWrite(string $id, array $status): void
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
        if ($port === null || $node === null) return ['time' => time(), 'ok' => false, 'error' => 'узел не найден'];
        if (empty($node['enabled'])) return ['time' => time(), 'ok' => false, 'error' => 'узел выключен'];
        $proxy = "127.0.0.1:$port";
        $cmd = "c(){ curl -s --socks5-hostname $proxy --max-time 12 \"\$@\"; }; "
            . "c -o /dev/null -w 'probe=%{http_code} %{time_connect} %{time_starttransfer}\\n' " . self::EXIT_PROBE_URL . '; '
            . "c https://www.cloudflare.com/cdn-cgi/trace | grep -E '^(ip|loc)='; ";
        if ($full) {
            $cmd .= "c -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36' "
                . "-H 'Accept-Language: en-US,en;q=0.9' https://www.youtube.com/ | head -c 3000000 "
                . "| grep -o '\"INNERTUBE_CONTEXT_GL\":\"[A-Z]*\"' | head -n 1; ";
        }
        $out = (string) $this->ssh($cmd . 'true', 'xr');
        $status = ['time' => time(), 'ok' => false];
        if ($this->sshFailed) return $status + ['error' => 'нет связи с контейнером Xray'];
        if (preg_match('~^probe=(\d{3}) ([0-9.]+) ([0-9.]+)$~m', $out, $m)) {
            $status['http'] = (int) $m[1];
            $status['connect_ms'] = (int) round((float) $m[2] * 1000);
            $status['ttfb_ms'] = (int) round((float) $m[3] * 1000);
            $status['ok'] = $status['http'] === 204;
        }
        if (preg_match('~^loc=([A-Z]{2})$~m', $out, $m)) $status['loc'] = $m[1];
        if (preg_match('~^ip=([0-9a-fA-F:.]{2,45})$~m', $out, $m)) $status['ip'] = $m[1];
        if (preg_match('~"INNERTUBE_CONTEXT_GL":"([A-Z]{2})"~', $out, $m)) $status['gl'] = $m[1];
        if ($full) $status['full'] = 1;
        if (!$status['ok']) $status['error'] = !empty($status['http']) ? 'узел ответил ' . $status['http'] : 'узел не ответил';
        $previous = $this->exitStatus()[$id] ?? [];
        // Страна YouTube из полной проверки живёт до следующей полной.
        if (!$full && isset($previous['gl'])) $status['gl'] = $previous['gl'];
        $this->exitStatusWrite($id, $status);
        return $status;
    }

    public function exitStatusLine(string $id, array $node): string
    {
        if (empty($node['enabled'])) return '⏸ выключен';
        $s = $this->exitStatus()[$id] ?? [];
        if (!$s) return '⚪ ещё не проверялся';
        $line = !empty($s['ok']) ? '🟢 работает' : '🔴 ' . self::esc($s['error'] ?? 'не работает');
        if (!empty($s['ok'])) $line .= ' · ' . (int) ($s['connect_ms'] ?? 0) . ' мс';
        if (!empty($s['loc'])) $line .= ' · выход ' . self::esc($s['loc']);
        if (!empty($s['gl'])) $line .= ' · YouTube видит ' . self::esc($s['gl']);
        return $line . ' · ' . date('H:i', (int) $s['time']);
    }

    // ── Наборы правил .srs (sing-box) и .mrs (Mihomo) ───────────────────────
    // Серверный Xray этих форматов не читает: бот скачивает набор, раскладывает
    // его на записи маршрута (domain:/full:/keyword:/regexp:/IP) инструментами
    // самих ядер из образа php и кладёт в /logs/exit-rulesets. Не в резервную
    // копию: после восстановления наборы скачаются заново.
    public static function exitRulesetUrlValid(string $url): bool
    {
        $parts = parse_url($url);
        return is_array($parts) && strtolower($parts['scheme'] ?? '') === 'https' && !empty($parts['host'])
            && !isset($parts['user']) && !isset($parts['pass']) && strlen($url) <= 500 && !preg_match('~[\s"\'\\\\<>]~', $url)
            && in_array(self::ruleSetFormat($url), ['srs', 'mrs'], true);
    }

    // Скачивание с ограничением размера; в тестах подменяется.
    protected function exitRulesetDownload(string $url): ?string
    {
        if (!$this->xdriveHostPublic($url)) return null;
        $data = '';
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => false, CURLOPT_FOLLOWLOCATION => true, CURLOPT_MAXREDIRS => 3,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS, CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_CONNECTTIMEOUT => 15, CURLOPT_TIMEOUT => 90, CURLOPT_FAILONERROR => true,
            CURLOPT_WRITEFUNCTION => static function ($ch, $chunk) use (&$data) {
                $data .= $chunk;
                return strlen($data) > self::EXIT_RULESET_MAX_BYTES ? 0 : strlen($chunk);
            },
        ]);
        $ok = curl_exec($ch);
        curl_close($ch);
        return $ok === true && $data !== '' ? $data : null;
    }

    // Запуск инструмента ядра; в тестах подменяется.
    protected function exitRulesetTool(array $command): bool
    {
        exec('timeout 120 ' . implode(' ', array_map('escapeshellarg', $command)) . ' >/dev/null 2>&1', $out, $code);
        return $code === 0;
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
        $binary = self::exitRulesetUrlValid($url) ? $this->exitRulesetDownload($url) : null;
        $entries = $binary === null ? null : $this->exitRulesetConvert($binary, $format, (string) ($set['behavior'] ?? 'domain'));
        $error = $binary === null ? 'не скачался' : ($entries === null ? 'не разобран' : (!$entries ? 'пустой' : ''));
        $cache = ['key' => $url, 'time' => time(), 'error' => $error]
            + ($error === '' ? ['entries' => $entries, 'hash' => hash('sha256', $binary)] : ['entries' => $cache['entries'] ?? [], 'hash' => $cache['hash'] ?? '']);
        @mkdir(self::EXIT_RULESET_DIR, 0700, true);
        $file = $this->exitRulesetFile($url);
        if (@file_put_contents("$file.tmp", json_encode($cache, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)) !== false) @rename("$file.tmp", $file);
        return $error;
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
            $interval = max(3600, (int) ($set['interval'] ?? 86400));
            if (!$force && $cache && time() - (int) ($cache['time'] ?? 0) < $interval) continue;
            $before = $cache['hash'] ?? '';
            $this->exitRulesetRefresh((string) $url, $set);
            if (($this->exitRulesetCache((string) $url)['hash'] ?? '') !== $before) $changed = true;
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
        $restart = false;
        foreach ($nodes as $id => $node) {
            $before = $this->exitStatus()[$id] ?? [];
            $now = $this->exitProbe($id, false);
            if ($before && !empty($before['ok']) !== !empty($now['ok'])) {
                $this->notifyAdmins((!empty($now['ok']) ? '🟢 Узел выхода снова работает: ' : '🔴 Узел выхода не отвечает, трафик идёт напрямую: ')
                    . self::esc($node['name'] !== '' ? $node['name'] : $id));
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
        $sniff = $this->sniffingSettings($p, $this->getXray()['inbounds'][0]['sniffing'] ?? null);
        if (empty($sniff['enabled'])) $warnings[] = '⚠️ Распознавание доменов (sniffing) выключено: правила по доменам не сработают. Включите его в Xray → DPI.';
        elseif (!empty($sniff['routeOnly'])) $warnings[] = '⚠️ sniffing в режиме routeOnly: на узел уйдёт адрес, полученный на этом сервере, а не домен — видео пойдёт с серверов страны этого сервера.';
        $warp = array_keys(array_filter($p['warplist'] ?? []));
        $both = array_intersect(array_keys(array_filter($node['routes'])), $warp);
        // Подписки sing-box и Mihomo отправляют домены WARP в WARP сами (через
        // warpSOCKS5 10.10.0.13), и до правила узла на сервере они доходят уже
        // с адресом WARP: «узел важнее» верно лишь для клиентов Xray.
        if ($both) $warnings[] = '⚠️ Есть и в списке WARP: клиенты Xray пойдут через узел, а sing-box и Mihomo — в WARP. Оставьте запись в одном списке: '
            . self::esc(implode(', ', array_slice($both, 0, 5)));
        $block = array_intersect(array_keys(array_filter($node['routes'])), array_keys(array_filter($p['blocklist'] ?? [])));
        if ($block) $warnings[] = '⚠️ Есть и в блок-листе (блокировка важнее): ' . self::esc(implode(', ', array_slice($block, 0, 5)));
        return $warnings;
    }

    public function exitNodesMenu(string $notice = ''): void
    {
        $nodes = $this->exitNodes();
        $text = ['Menu -> ' . $this->i18n('xray') . ' -> Узлы выхода',
            'Выбранные домены выбранных пользователей уходят через другой сервер с vpnbot. Если узел не отвечает — напрямую с этого сервера.'];
        if ($notice !== '') $text[] = "\n<b>" . self::esc($notice) . '</b>';
        $data = [];
        foreach ($nodes as $id => $node) {
            $users = count($this->exitNodeEmails($this->getXray(), $id));
            $text[] = "\n<b>" . $this->exitName($id, $node) . '</b> — ' . $this->exitStatusLine($id, $node) . " · пользователей: $users";
            $data[] = [['text' => ($node['enabled'] ? '🌍 ' : '⏸ ') . ($node['name'] !== '' ? mb_substr($node['name'], 0, 40) : $id), 'callback_data' => "/exit $id"]];
        }
        if (!$nodes) $text[] = "\nУзлов пока нет. На другом сервере откройте Xray → «Профиль для узла» и вставьте выданную ссылку сюда.";
        if (count($nodes) < self::EXIT_MAX) $data[] = [['text' => '➕ Добавить узел', 'callback_data' => '/exitAdd']];
        $data[] = [['text' => '🔁 Проверить все', 'callback_data' => '/exitCheckAll'], ['text' => '🪪 Профиль для узла', 'callback_data' => '/exitRelay']];
        $data[] = $this->menuHelpButton('exitnodes');
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => '/xray']];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $text), $data);
    }

    public function exitNodeMenu(string $id, string $notice = ''): void
    {
        $node = $this->exitNodes()[$id] ?? null;
        if ($node === null) { $this->exitNodesMenu('Узел не найден'); return; }
        $x = $this->getXray();
        $routes = count(array_filter($node['routes']));
        $sets = count(array_filter($node['rulesets'], static fn($s) => is_array($s) && !empty($s['on'])));
        $users = count($this->exitNodeEmails($x, $id));
        try { $parsed = ExitNodeLink::parse($node['link']); } catch (InvalidArgumentException $e) { $parsed = null; }
        $text = ['Menu -> ' . $this->i18n('xray') . ' -> Узлы выхода -> ' . $this->exitName($id, $node),
            $this->exitStatusLine($id, $node),
            'Адрес: <code>' . self::esc($parsed ? $parsed['address'] . ':' . $parsed['port'] : 'ссылка не разбирается') . '</code>'
                . ($parsed ? ' · ' . self::esc($parsed['outbound']['protocol'] . '/' . $parsed['outbound']['streamSettings']['network'] . '/' . $parsed['outbound']['streamSettings']['security']) : ''),
            "Маршрутов: $routes · наборов правил: $sets · пользователей: $users",
            $this->exitTrafficLine($id),
            'QUIC к доменам узла: ' . ($node['quic'] === 'block' ? 'блокируется (браузер сразу идёт по TCP через узел)' : 'пропускается'),
            'При отказе узла: напрямую с этого сервера'];
        if (!$users) $text[] = 'ℹ️ Узел пока ни у кого не включён: «Пользователи» или карточка пользователя.';
        if (!$routes && !$sets) $text[] = 'ℹ️ Маршрутов нет: «Маршруты» → например «YouTube».';
        array_push($text, ...$this->exitWarnings($node));
        if ($notice !== '') $text[] = "\n<b>" . self::esc($notice) . '</b>';
        $data = [
            [['text' => '🔍 Проверить', 'callback_data' => "/exitCheck $id"], ['text' => '🔄 Обновить', 'callback_data' => "/exitRefresh $id"]],
            [['text' => ($node['enabled'] ? '✅ Включён' : '⏸ Выключен'), 'callback_data' => "/exitToggle $id"],
                ['text' => 'QUIC: ' . ($node['quic'] === 'block' ? 'блок' : 'пропуск'), 'callback_data' => "/exitQuic $id"]],
            [['text' => "🧭 Маршруты ($routes)", 'callback_data' => "/exitRoutes $id 0"], ['text' => "📦 Наборы .srs/.mrs ($sets)", 'callback_data' => "/exitSets $id"]],
            [['text' => "👥 Пользователи ($users)", 'callback_data' => "/exitUsers $id 0"]],
            [['text' => '✏️ Имя', 'callback_data' => "/exitName $id"], ['text' => '🔗 Заменить ссылку', 'callback_data' => "/exitLink $id"],
                ['text' => '🗑 Удалить', 'callback_data' => "/exitDel $id"]],
            $this->menuHelpButton('exitnodes'),
            [['text' => $this->i18n('back'), 'callback_data' => '/exits']],
        ];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $text), $data);
    }

    // Счётчики выхода узла в ядре: с последнего запуска Xray, вместе с пробами.
    public function exitTrafficLine(string $id): string
    {
        if (empty($this->exitNodes()[$id]['enabled'])) return 'Трафик через узел: —';
        $stats = $this->xrayStatCounters();
        if ($stats === null) return 'Трафик через узел: нет данных';
        $name = 'outbound>>>' . self::EXIT_TAG . $id . '>>>traffic>>>';
        return 'Трафик через узел с запуска Xray: ↑' . $this->getBytes($stats[$name . 'uplink'] ?? 0)
            . ' ↓' . $this->getBytes($stats[$name . 'downlink'] ?? 0);
    }

    private function exitPrompt(string $text, string $callback, array $args): void
    {
        $r = $this->send($this->input['chat'], "@{$this->input['username']} $text", $this->input['message_id'], reply: $this->i18n('enter value'));
        $this->stashReply($r, ['start_message' => $this->input['message_id'], 'start_callback' => $this->input['callback_id'] ?? '',
            'callback' => $callback, 'args' => $args]);
    }

    public function exitAddPrompt(): void
    {
        $this->exitPrompt("вставьте ссылку из «Профиля для узла» другого сервера (vless:// или trojan://).\n"
            . 'Сообщение со ссылкой бот сразу удалит.', 'saveExitAdd', []);
    }

    /** Проверка адреса узла: публичный и не этот же сервер (петля). '' — подходит. */
    public function exitAddressProblem(string $address): string
    {
        if (!$this->xdriveHostPublic('https://' . (str_contains($address, ':') ? "[$address]" : $address))) return 'адрес узла не публичный или не разрешается';
        $own = array_filter([(string) ($this->ip ?? ''), (string) ($this->getPacConf()['domain'] ?? '')]);
        if (in_array(strtolower($address), array_map('strtolower', $own), true)) return 'это адрес этого же сервера';
        return '';
    }

    public function saveExitAdd($link): void
    {
        try { $parsed = ExitNodeLink::parse((string) $link); } catch (InvalidArgumentException $e) { $this->exitNodesMenu('Ссылка не подходит: ' . $e->getMessage()); return; }
        if (($problem = $this->exitAddressProblem($parsed['address'])) !== '') { $this->exitNodesMenu('Узел не добавлен: ' . $problem); return; }
        $id = self::exitNewId();
        $error = $this->applyExitNodes(function (array &$p) use ($id, $parsed, $link) {
            if (count($this->exitNodes($p)) >= self::EXIT_MAX) return 'exit too many';
            foreach ($this->exitNodes($p) as $node) if ($node['link'] === trim((string) $link)) return 'exit duplicate';
            $p['exits'][$id] = ['name' => $parsed['remark'] !== '' ? $parsed['remark'] : 'узел ' . (count($this->exitNodes($p)) + 1),
                'link' => trim((string) $link), 'created' => time()] + self::exitNodeDefaults();
            return '';
        });
        if ($error !== '') { $this->exitNodesMenu($this->exitError($error)); return; }
        $this->exitProbe($id, true);
        $this->exitNodeMenu($id, 'Узел добавлен. Добавьте маршруты и включите его пользователям.');
    }

    public function exitError(string $code): string
    {
        return match ($code) {
            'exit too many' => 'Узлов не больше ' . self::EXIT_MAX,
            'exit duplicate' => 'Такой узел уже есть',
            'exit check failed' => 'Ядро Xray не приняло изменение — оставлены прежние настройки (проверьте записи regexp: и .dat)',
            'exit not found' => 'Узел не найден',
            default => 'Не удалось сохранить',
        };
    }

    // Общая правка одного узла: $edit(array &$node) → '' или код ошибки.
    private function exitEditNode(string $id, callable $edit): string
    {
        return $this->applyExitNodes(function (array &$p) use ($id, $edit) {
            if (!isset($this->exitNodes($p)[$id])) return 'exit not found';
            $node = $this->exitNodes($p)[$id];
            $error = $edit($node);
            if (is_string($error) && $error !== '') return $error;
            $p['exits'][$id] = $node;
            return '';
        });
    }

    public function exitToggle(string $id): void
    {
        $error = $this->exitEditNode($id, static function (array &$node) { $node['enabled'] = $node['enabled'] ? 0 : 1; return ''; });
        $this->exitNodeMenu($id, $error === '' ? '' : $this->exitError($error));
    }

    public function exitQuic(string $id): void
    {
        $error = $this->exitEditNode($id, static function (array &$node) { $node['quic'] = $node['quic'] === 'block' ? 'pass' : 'block'; return ''; });
        $this->exitNodeMenu($id, $error === '' ? '' : $this->exitError($error));
    }

    public function exitCheck(string $id): void
    {
        $s = $this->exitProbe($id, true);
        $this->exitNodeMenu($id, !empty($s['ok']) ? 'Проверено: узел работает' : 'Проверено: ' . ($s['error'] ?? 'узел не работает'));
    }

    public function exitRefresh(string $id): void
    {
        $changed = $this->exitRefreshRulesets($id, true);
        if ($changed) $this->withLock('xray', fn() => $this->restartXray($this->getXray()), 20, false);
        $s = $this->exitProbe($id, true);
        $this->exitNodeMenu($id, 'Обновлено: наборы правил ' . ($changed ? 'изменились' : 'без изменений') . ', узел ' . (!empty($s['ok']) ? 'работает' : 'не работает'));
    }

    public function exitCheckAll(): void
    {
        foreach (array_keys(array_filter($this->exitNodes(), static fn($n) => !empty($n['enabled']))) as $id) $this->exitProbe($id, true);
        $this->exitNodesMenu('Проверено');
    }

    public function exitNamePrompt(string $id): void
    {
        $this->exitPrompt('новое имя узла (до 40 символов):', 'saveExitName', [$id]);
    }

    public function saveExitName($name, $id): void
    {
        $name = trim(preg_replace('~[\x00-\x1f\x7f<>&]~u', '', (string) $name) ?? '');
        $error = $name === '' ? 'exit empty' : $this->exitEditNode((string) $id, static function (array &$node) use ($name) { $node['name'] = mb_substr($name, 0, 40); return ''; });
        $this->exitNodeMenu((string) $id, $error === '' ? 'Имя сохранено' : ($error === 'exit empty' ? 'Пустое имя' : $this->exitError($error)));
    }

    public function exitLinkPrompt(string $id): void
    {
        $this->exitPrompt("новая ссылка узла (после «Новых ключей» или смены транспорта на узле).\nМаршруты и пользователи сохранятся. Сообщение бот удалит.", 'saveExitLink', [$id]);
    }

    public function saveExitLink($link, $id): void
    {
        try { $parsed = ExitNodeLink::parse((string) $link); } catch (InvalidArgumentException $e) { $this->exitNodeMenu((string) $id, 'Ссылка не подходит: ' . $e->getMessage()); return; }
        if (($problem = $this->exitAddressProblem($parsed['address'])) !== '') { $this->exitNodeMenu((string) $id, 'Не сохранено: ' . $problem); return; }
        $error = $this->exitEditNode((string) $id, static function (array &$node) use ($link) { $node['link'] = trim((string) $link); return ''; });
        if ($error === '') $this->exitProbe((string) $id, true);
        $this->exitNodeMenu((string) $id, $error === '' ? 'Ссылка заменена' : $this->exitError($error));
    }

    public function exitDelete(string $id, bool $confirmed = false): void
    {
        $node = $this->exitNodes()[$id] ?? null;
        if ($node === null) { $this->exitNodesMenu('Узел не найден'); return; }
        if (!$confirmed) {
            $this->update($this->input['chat'], $this->input['message_id'],
                'Удалить узел <b>' . $this->exitName($id, $node) . '</b>? Его маршруты удалятся, у пользователей он выключится.',
                [[['text' => '🗑 Да, удалить', 'callback_data' => "/exitDelYes $id"], ['text' => $this->i18n('back'), 'callback_data' => "/exit $id"]]]);
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
            foreach (array_keys($node['rulesets']) as $url) @unlink($this->exitRulesetFile((string) $url));
        }
        $this->exitNodesMenu($error === '' ? 'Узел удалён' : $this->exitError($error));
    }

    // ── Маршруты узла ──────────────────────────────────────────────────────
    public function exitRoutesMenu(string $id, int $page = 0, string $notice = ''): void
    {
        $node = $this->exitNodes()[$id] ?? null;
        if ($node === null) { $this->exitNodesMenu('Узел не найден'); return; }
        $entries = array_keys($node['routes']);
        $pages = max(1, (int) ceil(count($entries) / self::EXIT_PAGE));
        $page = max(0, min($page, $pages - 1));
        $text = ['Menu -> ' . $this->i18n('xray') . ' -> Узлы выхода -> ' . $this->exitName($id, $node) . ' -> Маршруты',
            'Нажмите на запись, чтобы выключить или включить её; ✖ — удалить.'];
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
        $data[] = [['text' => '➕ Добавить', 'callback_data' => "/exitRtAdd $id"], ['text' => '▶️ YouTube', 'callback_data' => "/exitYt $id"]];
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => "/exit $id"]];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $text), $data);
    }

    public function exitRouteAddPrompt(string $id): void
    {
        $this->exitPrompt("записи маршрута через узел.\n\n<b>Префиксы</b> (нажмите на слово, чтобы скопировать):\n"
            . "<code>domain:</code> — домен и все его поддомены, напр. domain:youtube.com\n"
            . "<code>full:</code> — точное совпадение домена, напр. full:www.youtube.com\n"
            . "<code>keyword:</code> — совпадение по подстроке, напр. keyword:youtube\n"
            . "<code>regexp:</code> — регулярное выражение, напр. regexp:.*\\.ru\$\n"
            . "<code>geosite:</code> / <code>geoip:</code> — категории встроенных .dat, напр. geosite:youtube\n"
            . "<code>ext:</code> / <code>extip:</code> — категории своих .dat из Vless → routes → dat, напр. ext:dlc.dat:youtube\n"
            . "без префикса — домен-суффикс; IPv4/IPv6[/cidr] — как есть.\n\n"
            . "<b>Как вводить:</b> в столбик или через запятую либо пробел; записи <code>regexp:</code> — каждую с новой строки.\n"
            . 'Наборы правил sing-box (.srs) и Mihomo (.mrs) — в «Наборы .srs/.mrs».', 'saveExitRoutes', [$id]);
    }

    public function saveExitRoutes($text, $id, array $preset = []): void
    {
        $entries = $preset ?: $this->splitRouteInput((string) $text);
        $added = $skipped = 0;
        $error = $this->exitEditNode((string) $id, function (array &$node) use ($entries, &$added, &$skipped) {
            $seen = [];
            foreach (array_keys($node['routes']) as $key) if (($canon = $this->routeEntryCanonKey((string) $key)) !== '') $seen[$canon] = true;
            foreach ($entries as $entry) {
                $entry = trim((string) $entry);
                $c = $this->classifyRouteEntry($entry);
                $canon = $this->routeEntryCanonKey($entry);
                if ($entry === '' || mb_strlen($entry) > 300 || !$this->routeEntryUsable($c) || isset($seen[$canon])) { $skipped++; continue; }
                if (count($node['routes']) >= 2000) { $skipped++; continue; }
                $node['routes'][$entry] = 1;
                $seen[$canon] = true;
                $added++;
            }
            return '';
        });
        $this->exitRoutesMenu((string) $id, PHP_INT_MAX, $error !== '' ? $this->exitError($error) : "Добавлено: $added" . ($skipped ? ", пропущено (повтор или неверная запись): $skipped" : ''));
    }

    public function exitYoutube(string $id): void
    {
        $this->saveExitRoutes('', $id, self::EXIT_YOUTUBE);
    }

    private function exitFindEntry(array $node, string $key, string $field = 'routes'): ?string
    {
        foreach (array_keys($node[$field]) as $entry) if (hash_equals(self::exitEntryKey((string) $entry), $key)) return (string) $entry;
        return null;
    }

    public function exitRouteToggle(string $id, string $key, bool $delete = false): void
    {
        $page = 0;
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
        if ($node === null) { $this->exitNodesMenu('Узел не найден'); return; }
        $text = ['Menu -> ' . $this->i18n('xray') . ' -> Узлы выхода -> ' . $this->exitName($id, $node) . ' -> Наборы правил',
            'Наборы sing-box (.srs) и Mihomo (.mrs) по ссылке https://. Бот сам скачивает их, раскладывает на домены и подсети и обновляет раз в сутки (и по «Обновить» в карточке узла).'];
        if ($notice !== '') $text[] = "\n<b>" . self::esc($notice) . '</b>';
        $data = [];
        foreach ($node['rulesets'] as $url => $set) {
            if (!is_array($set)) continue;
            $cache = $this->exitRulesetCache((string) $url);
            $state = !$cache ? '⏳ не скачан' : (($cache['error'] ?? '') !== '' ? '⚠️ ' . $cache['error'] : count($cache['entries'] ?? []) . ' записей');
            $text[] = "\n" . (!empty($set['on']) ? '✅' : '⏸') . ' <code>' . self::esc((string) $url) . '</code> — ' . self::esc($state)
                . (self::ruleSetFormat((string) $url) === 'mrs' ? ' · ' . self::esc((string) ($set['behavior'] ?? 'domain')) : '');
            $key = self::exitEntryKey((string) $url);
            $data[] = [['text' => (!empty($set['on']) ? '✅ ' : '⏸ ') . mb_substr(basename((string) parse_url((string) $url, PHP_URL_PATH)), 0, 40), 'callback_data' => "/exitSet $id $key"],
                ['text' => '✖', 'callback_data' => "/exitSetDel $id $key"]];
        }
        $data[] = [['text' => '➕ Добавить набор', 'callback_data' => "/exitSetAdd $id"]];
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => "/exit $id"]];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $text), $data);
    }

    public function exitSetAddPrompt(string $id): void
    {
        $this->exitPrompt("ссылка https:// на набор .srs или .mrs, по одной на строку.\n"
            . 'Для .mrs перед ссылкой можно указать тип: <code>ipcidr https://…/x.mrs</code> (по умолчанию <code>domain</code>).',
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
        $error = !$new ? '' : $this->exitEditNode((string) $id, static function (array &$node) use ($new, &$added) {
            foreach ($new as $url => $set) {
                if (isset($node['rulesets'][$url]) || count($node['rulesets']) >= 20) continue;
                $node['rulesets'][$url] = $set;
                $added++;
            }
            return '';
        });
        if ($error === '' && $added) {
            foreach ($new as $url => $set) $this->exitRulesetRefresh($url, $set);
            $this->withLock('xray', fn() => $this->restartXray($this->getXray()), 20, false);
        }
        $this->exitSetsMenu((string) $id, $error !== '' ? $this->exitError($error) : "Добавлено: $added" . ($bad ? ", не подошло (нужна https:// ссылка на .srs или .mrs): $bad" : ''));
    }

    public function exitSetToggle(string $id, string $key, bool $delete = false): void
    {
        $removed = null;
        $error = $this->exitEditNode($id, function (array &$node) use ($key, $delete, &$removed) {
            $url = $this->exitFindEntry($node, $key, 'rulesets');
            if ($url === null) return '';
            if ($delete) { unset($node['rulesets'][$url]); $removed = $url; }
            else $node['rulesets'][$url]['on'] = empty($node['rulesets'][$url]['on']) ? 1 : 0;
            return '';
        });
        if ($error === '' && $removed !== null) @unlink($this->exitRulesetFile($removed));
        $this->exitSetsMenu($id, $error === '' ? '' : $this->exitError($error));
    }

    // ── Пользователи узла ──────────────────────────────────────────────────
    public function exitUsersMenu(string $id, int $page = 0, string $notice = ''): void
    {
        $node = $this->exitNodes()[$id] ?? null;
        if ($node === null) { $this->exitNodesMenu('Узел не найден'); return; }
        $clients = $this->getXray()['inbounds'][0]['settings']['clients'] ?? [];
        $list = array_filter($clients, static fn($c) => is_array($c) && empty($c['exit_relay']));
        $pages = max(1, (int) ceil(count($list) / self::EXIT_PAGE));
        $page = max(0, min($page, $pages - 1));
        $text = ['Menu -> ' . $this->i18n('xray') . ' -> Узлы выхода -> ' . $this->exitName($id, $node) . ' -> Пользователи',
            'Маршрут через узел работает только у отмеченных. Служебные учётки узлов здесь не показываются.'];
        if ($notice !== '') $text[] = "\n<b>" . self::esc($notice) . '</b>';
        $data = [];
        foreach (array_slice($list, $page * self::EXIT_PAGE, self::EXIT_PAGE, true) as $i => $client) {
            $on = in_array($id, self::exitClientNodes($client), true);
            $data[] = [['text' => ($on ? '✅ ' : '⬜ ') . mb_substr((string) ($client['email'] ?? '—'), 0, 40) . (!empty($client['off']) ? ' ⛔' : ''),
                'callback_data' => "/exitU $id $i $page"]];
        }
        if ($pages > 1) {
            $nav = [];
            if ($page > 0) $nav[] = ['text' => '←', 'callback_data' => "/exitUsers $id " . ($page - 1)];
            $nav[] = ['text' => ($page + 1) . "/$pages", 'callback_data' => "/exitUsers $id $page"];
            if ($page < $pages - 1) $nav[] = ['text' => '→', 'callback_data' => "/exitUsers $id " . ($page + 1)];
            $data[] = $nav;
        }
        $data[] = [['text' => '✅ Включить всем', 'callback_data' => "/exitAll $id on"], ['text' => '⬜ Выключить всем', 'callback_data' => "/exitAll $id off"]];
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => "/exit $id"]];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $text), $data);
    }

    /** Включить/выключить узел пользователям; $only — индексы, null — всем обычным. */
    public function exitSetUsers(string $id, ?array $only, ?bool $on): string
    {
        return $this->applyExitNodes(function (array &$p, array &$x) use ($id, $only, $on) {
            if (!isset($this->exitNodes($p)[$id])) return 'exit not found';
            foreach ($x['inbounds'][0]['settings']['clients'] ?? [] as $i => $client) {
                if (!is_array($client) || !empty($client['exit_relay']) || ($only !== null && !in_array($i, $only, true))) continue;
                $nodes = self::exitClientNodes($client);
                $want = $on ?? !in_array($id, $nodes, true);
                $nodes = $want ? array_values(array_unique([...$nodes, $id])) : array_values(array_diff($nodes, [$id]));
                if ($nodes) $x['inbounds'][0]['settings']['clients'][$i]['exit'] = $nodes;
                else unset($x['inbounds'][0]['settings']['clients'][$i]['exit']);
            }
            return '';
        });
    }

    public function exitUserToggle(string $id, int $i, int $page = 0): void
    {
        $error = $this->exitSetUsers($id, [$i], null);
        $this->exitUsersMenu($id, $page, $error === '' ? '' : $this->exitError($error));
    }

    public function exitAllUsers(string $id, bool $on): void
    {
        $error = $this->exitSetUsers($id, null, $on);
        $this->exitUsersMenu($id, 0, $error === '' ? ($on ? 'Включено всем' : 'Выключено всем') : $this->exitError($error));
    }

    // Карточка пользователя → его узлы.
    public function exitUserMenu(int $i, string $notice = ''): void
    {
        $client = $this->getXray()['inbounds'][0]['settings']['clients'][$i] ?? null;
        if (!is_array($client)) { $this->xray(); return; }
        $text = ['Menu -> ' . $this->i18n('xray') . ' -> ' . self::esc((string) ($client['email'] ?? '')) . ' -> Узлы выхода'];
        if (!empty($client['exit_relay'])) $text[] = 'Это служебная учётка узла: маршруты через узлы ей не назначаются.';
        if ($notice !== '') $text[] = "\n<b>" . self::esc($notice) . '</b>';
        $data = [];
        $mine = self::exitClientNodes($client);
        foreach ($this->exitNodes() as $id => $node) {
            $id = (string) $id;
            if (!empty($client['exit_relay'])) break;
            $data[] = [['text' => (in_array($id, $mine, true) ? '✅ ' : '⬜ ') . mb_substr($node['name'] !== '' ? $node['name'] : $id, 0, 40)
                . ($node['enabled'] ? '' : ' (выключен)'), 'callback_data' => "/exitUT $i $id"]];
        }
        if (!$this->exitNodes()) $text[] = 'Узлов нет: Xray → Узлы выхода.';
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => "/userXr $i"]];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $text), $data);
    }

    public function exitUserNodeToggle(int $i, string $id): void
    {
        $error = $this->exitSetUsers($id, [$i], null);
        $this->exitUserMenu($i, $error === '' ? '' : $this->exitError($error));
    }

    // ── Этот сервер как узел: «Профиль для узла» ───────────────────────────
    // Служебная учётка без срока и лимита трафика. Её трафик никогда не уходит
    // на узлы этого бота (exitClientNodes ей пусто) — так связка двух ботов,
    // указывающих друг на друга, не превращается в петлю.
    public function exitRelayMenu(string $notice = ''): void
    {
        $clients = $this->getXray()['inbounds'][0]['settings']['clients'] ?? [];
        $text = ['Menu -> ' . $this->i18n('xray') . ' -> Профиль для узла',
            'Этот сервер станет узлом выхода для другого бота: создайте служебную учётку и вставьте её ссылку на основном сервере в Xray → Узлы выхода → «Добавить узел».',
            'Учётка без срока и лимита; её трафик никогда не уходит на узлы этого сервера (защита от петли).',
            '⚠️ Если межсетевой экран пускает VPN только «своим» адресам (список my_server), добавьте туда адрес основного сервера — иначе его соединения будут ограничены как чужие.'];
        if ($notice !== '') $text[] = "\n<b>" . self::esc($notice) . '</b>';
        $data = [];
        foreach ($clients as $i => $client) {
            if (empty($client['exit_relay'])) continue;
            $data[] = [['text' => '🪪 ' . mb_substr((string) ($client['email'] ?? '—'), 0, 40) . (!empty($client['off']) ? ' ⛔' : ''), 'callback_data' => "/exitRelayLink $i"]];
        }
        $data[] = [['text' => '➕ Создать профиль для узла', 'callback_data' => '/exitRelayAdd']];
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => '/exits']];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $text), $data);
    }

    public function exitRelayAddPrompt(): void
    {
        $this->exitPrompt('имя профиля для узла, например имя основного сервера (латиница, цифры, точка, дефис):', 'saveExitRelay', []);
    }

    public function saveExitRelay($name): void
    {
        $name = 'node-' . trim((string) $name);
        if (!preg_match('~^node-[A-Za-z0-9][A-Za-z0-9._-]{0,30}$~D', $name)) { $this->exitRelayMenu('Имя: латиница, цифры, точка, дефис, до 30 символов'); return; }
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
        if ($error !== '' || $index === null) { $this->exitRelayMenu($error === 'exit duplicate' ? 'Профиль с таким именем уже есть' : $this->exitError($error)); return; }
        $this->exitRelayLink($index, 'Профиль создан');
    }

    public function exitRelayLink(int $i, string $notice = ''): void
    {
        $client = $this->getXray()['inbounds'][0]['settings']['clients'][$i] ?? null;
        if (!is_array($client) || empty($client['exit_relay'])) { $this->exitRelayMenu('Профиль не найден'); return; }
        $link = (string) $this->linkXray($i);
        $text = ['Menu -> ' . $this->i18n('xray') . ' -> Профиль для узла -> ' . self::esc((string) $client['email'])];
        if ($notice !== '') $text[] = '<b>' . self::esc($notice) . '</b>';
        $text[] = $link !== '' ? "Ссылка для основного сервера (Xray → Узлы выхода → «Добавить узел»):\n<pre><code>" . self::esc($link) . '</code></pre>'
            : 'Ссылку не выдать: текущий транспорт Xray её не поддерживает.';
        $text[] = 'Отозвать доступ — удалить или отключить эту учётку в списке пользователей Xray.';
        $data = [[['text' => $this->i18n('back'), 'callback_data' => '/exitRelay']]];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $text), $data);
    }
}
