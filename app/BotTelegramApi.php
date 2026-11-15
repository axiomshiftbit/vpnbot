<?php

// Связь с Telegram Bot API: адрес, через который ходит этот бот, и
// ретранслятор Bot API для ботов на других серверах (Menu → config →
// Telegram API, CLI app/tgapi.php, make tgapi).
//
// Ретранслятор — блок location в server-блоке домена nginx (только с
// сертификатом Let's Encrypt): https://<домен>/<префикс>/bot<token>/<метод> →
// https://api.telegram.org/bot<token>/<метод>. Защита:
//   - префикс — 128 случайных бит, не связан с хэшем бота из ссылок подписок;
//   - пропускаются только боты из списка (числовой ID — часть токена до
//     двоеточия) и только пути Bot API: методы и /file/bot…; остальное — 404,
//     как у любого несуществующего пути, ответ Telegram не запрашивается;
//   - необязательный список адресов клиентов (allow/deny);
//   - TLS до api.telegram.org проверяется (proxy_ssl_verify on, имя
//     api.telegram.org): подменённый DNS или перехват канала не получают
//     токены;
//   - журнал без пути и query (там токен и текст сообщений), error_log
//     выключен: nginx пишет в него строку запроса целиком;
//   - лимиты запросов и соединений на адрес, размер тела 52 МБ (лимит
//     загрузки Bot API — 50 МБ), только GET и POST.
// Имя api.telegram.org резолвится при запросе (resolver Docker): недоступный
// DNS при старте не мешает nginx подняться.
trait BotTelegramApi
{
    public string $telegramApiFile = TelegramApi::FILE;
    public ?string $telegramApiStamp = null;

    public const TG_RELAY_BEGIN = '# vpnbot-tg-relay-begin';
    public const TG_RELAY_END = '# vpnbot-tg-relay-end';
    public const TG_RELAY_ZONES_BEGIN = '# vpnbot-tg-relay-zones-begin';
    public const TG_RELAY_ZONES_END = '# vpnbot-tg-relay-zones-end';
    public const TG_RELAY_GUARD_BEGIN = '# vpnbot-tg-relay-guard-begin';
    public const TG_RELAY_GUARD_END = '# vpnbot-tg-relay-guard-end';
    public const TG_RELAY_MAX = 16;
    public const TG_RELAY_RATE = 30;
    public const TG_RELAY_BURST = 90;
    public const TG_RELAY_CONN = 32;
    public const TG_RELAY_LOG = 'nginx_tgrelay_access';

    // ── Адрес Bot API этого бота ───────────────────────────────────────────

    public function telegramApiUse(string $url): void
    {
        $this->api = "$url/bot{$this->key}/";
        $this->file = "$url/file/bot{$this->key}/";
        $this->telegramApiStamp = $this->telegramApiFileStamp();
    }

    public function telegramApiFileStamp(): string
    {
        clearstatcache(true, $this->telegramApiFile);
        $s = @lstat($this->telegramApiFile);
        return is_array($s) ? "{$s['ino']}:{$s['size']}:{$s['mtime']}" : 'none';
    }

    // Настройку меняют бот, CLI и другие процессы (cron, polling живут долго):
    // перечитываем адрес, когда файл изменился.
    public function telegramApiRefresh(): void
    {
        if ($this->telegramApiStamp === null || $this->telegramApiFileStamp() === $this->telegramApiStamp) return;
        $this->telegramApiUse(TelegramApi::current($this->telegramApiFile)['url']);
    }

    public function telegramApiBase(): string
    {
        return TelegramApi::current($this->telegramApiFile)['url'];
    }

    public function telegramApiProbeText(array $probe): string
    {
        return match ($probe['reason'] ?? '') {
            'ok' => $this->t('Bot API отвечает, токен принят', 'Bot API answers, the token is accepted'),
            'invalid' => $this->t('неверный адрес: нужен https://имя[:порт][/путь] без пробелов, логина, ? и #', 'invalid address: use https://name[:port][/path] without spaces, login, ? or #'),
            'tls' => $this->t('сертификат сервера не прошёл проверку TLS', 'the server certificate failed TLS verification'),
            'network' => $this->t('нет соединения: DNS, сеть, firewall или тайм-аут', 'no connection: DNS, network, firewall or timeout'),
            'unauthorized' => $this->t('Telegram отверг токен бота (401)', 'Telegram rejected the bot token (401)'),
            'mismatch' => $this->t('ответ не относится к этому боту', 'the answer does not belong to this bot'),
            'write' => $this->t('не удалось сохранить настройку', 'the setting could not be saved'),
            default => $this->t('ответ не от Bot API', 'the answer is not from Bot API') . (!empty($probe['http']) ? ' (HTTP ' . (int) $probe['http'] . ')' : '')
                . $this->t('. Для ретранслятора проверьте адрес и что ID этого бота разрешён на нём', '. For a relay, check the address and that this bot ID is allowed there'),
        };
    }

    public function telegramApiProbe(string $url): array
    {
        return TelegramApi::probe($url, (string) $this->key, getenv('TELEGRAM_PROXY') ?: null);
    }

    // Новый адрес сохраняется только после успешного getMe через него:
    // иначе бот сам отрезал бы себя от Telegram.
    public function telegramApiSetUrl(string $raw): array
    {
        $url = TelegramApi::normalize($raw);
        if ($url === null) return [false, $this->telegramApiProbeText(['reason' => 'invalid'])];
        $probe = $this->telegramApiProbe($url);
        if (empty($probe['ok'])) return [false, $this->t('адрес не сохранён: ', 'the address is not saved: ') . $this->telegramApiProbeText($probe)];
        if (!TelegramApi::save($this->telegramApiFile, $url)) return [false, $this->telegramApiProbeText(['reason' => 'write'])];
        $this->telegramApiUse($url);
        return [true, $this->t('адрес Bot API сохранён: ', 'Bot API address saved: ') . TelegramApi::mask($url)];
    }

    public function telegramApiResetUrl(bool $force = false): array
    {
        $target = TelegramApi::fallback();
        if (!$force) {
            $probe = $this->telegramApiProbe($target);
            if (empty($probe['ok'])) return [false, $this->t('сброс отменён, ', 'reset cancelled, ') . TelegramApi::mask($target) . ': ' . $this->telegramApiProbeText($probe)];
        }
        if (!TelegramApi::save($this->telegramApiFile, null)) return [false, $this->telegramApiProbeText(['reason' => 'write'])];
        $this->telegramApiUse($target);
        return [true, $this->t('используется адрес по умолчанию: ', 'the default address is used: ') . TelegramApi::mask($target)];
    }

    public function telegramApiCheck(): array
    {
        $url = $this->telegramApiBase();
        $probe = $this->telegramApiProbe($url);
        return [!empty($probe['ok']), TelegramApi::mask($url) . ': ' . $this->telegramApiProbeText($probe)];
    }

    public function telegramApiSourceText(array $state): string
    {
        return match ($state['source']) {
            'file' => $this->t('задан в боте', 'set in the bot'),
            'env' => $this->t('из TELEGRAM_API в .env', 'from TELEGRAM_API in .env'),
            default => $this->t('по умолчанию', 'default'),
        };
    }

    // ── Ретранслятор на Cloudflare Workers ────────────────────────────────
    //
    // Для сервера без своего второго сервера: Worker в бесплатном аккаунте
    // Cloudflare пересылает запросы бота в api.telegram.org. Скрипт
    // создаётся под этого бота: случайный префикс 128 бит и ID бота; любой
    // другой путь, бот или метод — 404 без обращения к Telegram. Заголовки
    // клиента (адрес, cookie, cf-*) в Telegram не уходят. Cloudflare видит
    // токен и сообщения бота — об этом говорят меню и справка.
    private const TG_WORKER_JS = <<<'JS'
// VPNBot: ретранслятор Telegram Bot API на Cloudflare Workers.
// Адрес для бота: https://<адрес этого Worker>/__PREFIX__
//   Menu → config → Telegram API → Адрес Bot API → указать адрес ретранслятора
//   или на сервере: make tgapi cmd="api-set https://<адрес Worker>/__PREFIX__"
// Пропускает к api.telegram.org только запросы Bot API бота __BOT__;
// остальное получает 404. Cloudflare видит токен и сообщения бота.
//
// VPNBot: Telegram Bot API relay on Cloudflare Workers.
// Address for the bot: https://<this Worker address>/__PREFIX__
//   Menu → config → Telegram API → Bot API address → set the relay address
//   or on the server: make tgapi cmd="api-set https://<Worker address>/__PREFIX__"
// Passes only Bot API requests of bot __BOT__ to api.telegram.org;
// everything else gets 404. Cloudflare sees the bot token and messages.
const PREFIX = '/__PREFIX__';
const BOT = '__BOT__';
const PATH = /^\/(?:file\/)?bot([0-9]{5,15}):[A-Za-z0-9_-]{30,64}\/[A-Za-z0-9_.\/-]{1,512}$/;

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const path = url.pathname.startsWith(PREFIX + '/') ? url.pathname.slice(PREFIX.length) : '';
    const bot = PATH.exec(path);
    if (!bot || bot[1] !== BOT || path.includes('..') || !['GET', 'POST'].includes(request.method)) {
      return new Response('Not Found', { status: 404 });
    }
    const headers = new Headers();
    for (const name of ['content-type', 'content-length']) {
      const value = request.headers.get(name);
      if (value) headers.set(name, value);
    }
    const init = { method: request.method, headers, redirect: 'manual' };
    if (request.method === 'POST') init.body = request.body;
    const answer = await fetch('https://api.telegram.org' + path + url.search, init);
    const out = new Headers();
    for (const name of ['content-type', 'content-disposition']) {
      const value = answer.headers.get(name);
      if (value) out.set(name, value);
    }
    return new Response(answer.body, { status: answer.status, headers: out });
  },
};

JS;

    public static function telegramWorkerScript(string $prefix, string $botId): string
    {
        if (!preg_match('~^[a-f0-9]{32}$~D', $prefix) || !preg_match('~^[0-9]{5,15}$~D', $botId)) {
            throw new InvalidArgumentException('Cloudflare Worker: prefix or bot ID');
        }
        return strtr(self::TG_WORKER_JS, ['__PREFIX__' => $prefix, '__BOT__' => $botId]);
    }

    // [префикс, скрипт]. Префикс не хранится: адрес с ним администратор
    // задаёт боту сам, после проверки getMe он ляжет в config/telegram_api.
    public function telegramWorker(): array
    {
        $prefix = bin2hex(random_bytes(16));
        return [$prefix, self::telegramWorkerScript($prefix, TelegramApi::botId((string) $this->key))];
    }

    public function telegramWorkerSteps(string $prefix): string
    {
        return $this->t(
            "1. dash.cloudflare.com → Workers &amp; Pages → Create → Worker (Start with Hello World) → Deploy.\n2. Edit code: удалите пример, вставьте файл целиком → Deploy.\n3. Скопируйте адрес вида <code>https://имя.аккаунт.workers.dev</code> (или подключите свой домен: Settings → Domains &amp; Routes).\n4. Здесь: Адрес Bot API → указать адрес ретранслятора → <code>https://адрес-worker/$prefix</code>. Бот сохранит его только после успешной проверки getMe.",
            "1. dash.cloudflare.com → Workers &amp; Pages → Create → Worker (Start with Hello World) → Deploy.\n2. Edit code: delete the sample, paste the whole file → Deploy.\n3. Copy the address like <code>https://name.account.workers.dev</code> (or attach your domain: Settings → Domains &amp; Routes).\n4. Here: Bot API address → set the relay address → <code>https://worker-address/$prefix</code>. The bot saves it only after a successful getMe check."
        );
    }

    public function telegramWorkerSend()
    {
        if (!$this->telegramApiOwnerAllowed()) return;
        [$prefix, $script] = $this->telegramWorker();
        $caption = '☁️ Cloudflare Worker' . "\n\n" . $this->telegramWorkerSteps($prefix) . "\n\n⚠ "
            . $this->t('Cloudflare видит токен и сообщения бота. Путь с префиксом — секрет, как пароль.', 'Cloudflare sees the bot token and messages. The path with the prefix is a secret, like a password.');
        $r = $this->sendFile($this->input['chat'], new CURLStringFile($script, 'vpnbot-telegram-worker.js', 'text/javascript'), $caption);
        return $this->telegramApiClientMenu(!empty($r['ok'])
            ? '✅ ' . $this->t('скрипт Worker отправлен файлом', 'the Worker script is sent as a file')
            : '❌ ' . $this->t('не удалось отправить файл', 'could not send the file'));
    }

    // ── Ретранслятор: настройка ───────────────────────────────────────────

    public static function telegramRelayCidr(string $value): ?string
    {
        $value = trim($value);
        if (!self::ipOrCidr($value)) return null;
        [$ip, $mask] = array_pad(explode('/', $value, 2), 2, null);
        $bin = inet_pton($ip);
        if ($bin === false) return null;
        $bits = strlen($bin) * 8;
        $mask = $mask === null ? $bits : (int) $mask;
        if ($mask < 0 || $mask > $bits) return null;
        // Сеть приводится к началу диапазона: nginx иначе предупреждает о
        // значимых младших битах, а в списке появились бы дубликаты.
        $out = '';
        for ($i = 0; $i < strlen($bin); $i++) {
            $keep = max(0, min(8, $mask - $i * 8));
            $out .= chr(ord($bin[$i]) & ((0xff << (8 - $keep)) & 0xff));
        }
        $text = inet_ntop($out);
        return $mask === $bits ? $text : "$text/$mask";
    }

    public static function telegramRelayNormalize($relay): array
    {
        $relay = is_array($relay) ? $relay : [];
        $prefix = is_string($relay['prefix'] ?? null) && preg_match('~^[0-9a-f]{32}$~D', $relay['prefix']) ? $relay['prefix'] : '';
        $bots = [];
        foreach ((array) ($relay['bots'] ?? []) as $bot) {
            if (is_scalar($bot) && preg_match('~^[1-9][0-9]{4,14}$~D', (string) $bot)) $bots[(string) $bot] = (string) $bot;
        }
        $ips = [];
        foreach ((array) ($relay['ips'] ?? []) as $ip) {
            if (is_string($ip) && ($cidr = self::telegramRelayCidr($ip)) !== null) $ips[$cidr] = $cidr;
        }
        $bots = array_slice(array_values($bots), 0, self::TG_RELAY_MAX);
        return [
            'enabled' => !empty($relay['enabled']) && $prefix !== '' && $bots !== [],
            'prefix' => $prefix,
            'bots' => $bots,
            'ips' => array_slice(array_values($ips), 0, self::TG_RELAY_MAX),
        ];
    }

    public function telegramRelayConf(): array
    {
        return self::telegramRelayNormalize($this->getPacConf()['tg_relay'] ?? []);
    }

    public function telegramRelayNginxPath(): string
    {
        return dirname($this->xrayConf) . '/nginx.conf';
    }

    public function telegramRelayNginxText(): string
    {
        $path = $this->telegramRelayNginxPath();
        return is_file($path) ? (string) file_get_contents($path) : '';
    }

    // Server-блок домена появляется в nginx.conf, только когда у домена есть
    // сертификат Let's Encrypt (cloakNginx раскомментирует #-domain).
    public static function telegramRelayDomainBlock(string $text): bool
    {
        return (bool) preg_match('~^[ \t]*##domain[ \t]*\r?\n.*?^[ \t]*include location\.conf;.*?^[ \t]*##domain[ \t]*$~ms', $text);
    }

    public static function telegramRelayActiveIn(string $text, array $relay): bool
    {
        return $relay['prefix'] !== '' && str_contains($text, self::TG_RELAY_BEGIN)
            && str_contains($text, 'location ^~ /' . $relay['prefix'] . '/ {');
    }

    public static function telegramRelayLocation(array $relay, string $indent): string
    {
        $p = $relay['prefix'];
        $bots = implode('|', $relay['bots']);
        $token = 'bot(?:' . $bots . '):[A-Za-z0-9_-]{30,64}';
        $lines = [
            self::TG_RELAY_BEGIN,
            "location ^~ /$p/ {",
            '    access_log /logs/' . self::TG_RELAY_LOG . ' vpnbot_tgrelay;',
            '    error_log /dev/null;',
            '    log_not_found off;',
            '    limit_req zone=vpnbot_tgrelay burst=' . self::TG_RELAY_BURST . ' nodelay;',
            '    limit_req_status 429;',
            '    limit_conn vpnbot_tgrelay_conn ' . self::TG_RELAY_CONN . ';',
            '    limit_conn_status 429;',
        ];
        foreach ($relay['ips'] as $ip) $lines[] = "    allow $ip;";
        if ($relay['ips']) $lines[] = '    deny all;';
        array_push($lines,
            '    location ~ "^/' . $p . '/(?:' . $token . '/[A-Za-z][A-Za-z0-9_]{0,63}|file/' . $token . '/[A-Za-z0-9_-][A-Za-z0-9_./-]{0,255})$" {',
            '        limit_except GET POST { deny all; }',
            '        client_max_body_size 52m;',
            '        client_body_buffer_size 128k;',
            '        proxy_request_buffering off;',
            '        proxy_buffering off;',
            '        resolver 127.0.0.11 valid=300s ipv6=off;',
            '        resolver_timeout 5s;',
            '        set $vpnbot_tgrelay_host api.telegram.org;',
            '        rewrite ^/' . $p . '(/.*)$ $1 break;',
            '        proxy_pass https://$vpnbot_tgrelay_host;',
            '        proxy_http_version 1.1;',
            '        proxy_set_header Host api.telegram.org;',
            '        proxy_set_header Connection "";',
            '        proxy_set_header X-Forwarded-For "";',
            '        proxy_set_header X-Real-IP "";',
            '        proxy_set_header Forwarded "";',
            '        proxy_ssl_server_name on;',
            '        proxy_ssl_name api.telegram.org;',
            '        proxy_ssl_verify on;',
            '        proxy_ssl_verify_depth 4;',
            '        proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;',
            '        proxy_ssl_protocols TLSv1.2 TLSv1.3;',
            '        proxy_redirect off;',
            '        proxy_connect_timeout 10s;',
            '        proxy_send_timeout 120s;',
            '        proxy_read_timeout 120s;',
            '        proxy_next_upstream off;',
            '    }',
            '    return 404;',
            '}',
            self::TG_RELAY_END,
        );
        return implode('', array_map(static fn($line) => $indent . $line . "\n", $lines));
    }

    // Клиент с устаревшим адресом (ретранслятор выключен, префикс сменён,
    // опечатка) шлёт /…/bot<token>/… в обычный server-блок, и тот записал бы
    // путь с токеном в nginx_domain_access/nginx_ip_access. Такие пути
    // отвечают 404 и пишутся без пути. Блок ставится, как только у
    // ретранслятора появился префикс, и остаётся после выключения.
    public static function telegramRelayGuard(string $indent): string
    {
        return implode('', array_map(static fn($line) => $indent . $line . "\n", [
            self::TG_RELAY_GUARD_BEGIN,
            'location ~ "/(?:file/)?bot[0-9]{5,15}:[A-Za-z0-9_-]{30,64}(?:/|$)" {',
            '    access_log /logs/' . self::TG_RELAY_LOG . ' vpnbot_tgrelay;',
            '    error_log /dev/null;',
            '    return 404;',
            '}',
            self::TG_RELAY_GUARD_END,
        ]));
    }

    public static function telegramRelayZones(): string
    {
        return implode("\n", [
            '    ' . self::TG_RELAY_ZONES_BEGIN,
            '    limit_req_zone $binary_remote_addr zone=vpnbot_tgrelay:1m rate=' . self::TG_RELAY_RATE . 'r/s;',
            '    limit_conn_zone $binary_remote_addr zone=vpnbot_tgrelay_conn:1m;',
            // Без $uri/$request/$args и Referer: в пути запроса лежит токен бота.
            '    log_format vpnbot_tgrelay \'$remote_addr [$time_local] "$request_method" \'',
            '                              \'$status $upstream_status $body_bytes_sent $request_time\';',
            '    ' . self::TG_RELAY_ZONES_END,
        ]) . "\n";
    }

    // Убирает прежние блоки ретранслятора и, если он включён и есть
    // server-блок домена, ставит новые. Остальной текст не меняется.
    public static function telegramRelayNginx(string $text, array $relay): string
    {
        $relay = self::telegramRelayNormalize($relay);
        foreach ([[self::TG_RELAY_BEGIN, self::TG_RELAY_END], [self::TG_RELAY_ZONES_BEGIN, self::TG_RELAY_ZONES_END],
            [self::TG_RELAY_GUARD_BEGIN, self::TG_RELAY_GUARD_END]] as [$begin, $end]) {
            $text = (string) preg_replace('~^[ \t]*' . preg_quote($begin, '~') . '[ \t]*\r?\n.*?^[ \t]*' . preg_quote($end, '~') . '[ \t]*(?:\r?\n|\z)~ms', '', $text);
        }
        // Ретранслятор ни разу не включали — nginx.conf не меняется вовсе.
        if ($relay['prefix'] === '' || !preg_match('~^http[ \t]*\{[ \t]*\r?\n~m', $text)) return $text;
        if ($relay['enabled'] && self::telegramRelayDomainBlock($text)) {
            $done = false;
            $text = (string) preg_replace_callback('~^[ \t]*##domain[ \t]*\r?\n.*?^[ \t]*##domain[ \t]*$~ms', static function ($region) use ($relay, &$done) {
                if ($done) return $region[0];
                return (string) preg_replace_callback('~^([ \t]*)include location\.conf;~m', static function ($line) use ($relay, &$done) {
                    if ($done) return $line[0];
                    $done = true;
                    return self::telegramRelayLocation($relay, $line[1]) . $line[0];
                }, $region[0]);
            }, $text);
        }
        // Закомментированные include (копии #-domain без сертификата) не
        // совпадают: перед ними стоит «#».
        $guarded = 0;
        $text = (string) preg_replace_callback('~^([ \t]*)include location\.conf;~m', static function ($line) use (&$guarded) {
            $guarded++;
            return self::telegramRelayGuard($line[1]) . $line[0];
        }, $text);
        if ($guarded === 0) return $text;
        return (string) preg_replace('~^http[ \t]*\{[ \t]*\r?\n~m', '$0' . str_replace(['\\', '$'], ['\\\\', '\\$'], self::telegramRelayZones()), $text, 1);
    }

    // Сохраняет настройку и применяет её к nginx. При отказе nginx -t или
    // reload возвращается прежняя настройка: nginx.conf откатывает сам
    // editProtocolProxyConfig.
    public function telegramRelayApply(array $relay): bool
    {
        $relay = self::telegramRelayNormalize($relay);
        $before = $this->pacConfUpdate(function (&$conf) use ($relay) {
            $before = $conf;
            $conf['tg_relay'] = $relay;
            return $before;
        });
        $path = $this->telegramRelayNginxPath();
        $ok = is_file($path) && $this->editProtocolProxyConfig($path, 'ng', static fn($text) => self::telegramRelayNginx($text, $relay));
        if (!$ok) {
            if (!$this->restorePacFields($before, ['tg_relay' => $relay], ['tg_relay'])) throw new RuntimeException($this->t('Настройки изменились; восстановление предыдущего состояния не подтверждено', 'Settings changed; restoration of the previous state is unconfirmed'));
        }
        return $ok;
    }

    public function telegramRelayDomain(): string
    {
        return (string) ($this->getPacConf()['domain'] ?? '');
    }

    public function telegramRelayUrl(?array $relay = null): string
    {
        $relay ??= $this->telegramRelayConf();
        $domain = $this->telegramRelayDomain();
        return $domain !== '' && $relay['prefix'] !== '' ? "https://$domain/{$relay['prefix']}" : '';
    }

    // ['state' => off|on|pending|nodomain, ...] — фактическое состояние по nginx.conf.
    public function telegramRelayStatus(): array
    {
        $relay = $this->telegramRelayConf();
        $text = $this->telegramRelayNginxText();
        if (!$relay['enabled']) $state = 'off';
        elseif (self::telegramRelayActiveIn($text, $relay)) $state = 'on';
        elseif (!self::telegramRelayDomainBlock($text)) $state = 'nodomain';
        else $state = 'pending';
        return ['state' => $state, 'relay' => $relay];
    }

    public function telegramRelayStateText(string $state): string
    {
        return match ($state) {
            'on' => $this->t('работает', 'active'),
            'nodomain' => $this->t('включён, но не действует: нужен домен с сертификатом Let\'s Encrypt', 'on, but inactive: a domain with a Let\'s Encrypt certificate is required'),
            'pending' => $this->t('включён, но не применён в nginx: включите ещё раз', 'on, but not applied in nginx: turn it on again'),
            default => $this->t('выключен', 'off'),
        };
    }

    // Изменение ретранслятора. Возвращает [успех, сообщение без HTML].
    public function telegramRelayChange(string $op, string $value = ''): array
    {
        $lock = @fopen(dirname($this->telegramRelayNginxPath()) . '/tg_relay.lock', 'c');
        if ($lock === false || !flock($lock, LOCK_EX)) return [false, $this->t('настройка занята другим процессом', 'the setting is busy')];
        try {
            $relay = $this->telegramRelayConf();
            $before = $relay;
            switch ($op) {
                case 'on':
                    if ($relay['bots'] === []) return [false, $this->t('сначала добавьте хотя бы один ID бота', 'add at least one bot ID first')];
                    if (!self::telegramRelayDomainBlock($this->telegramRelayNginxText())) return [false, $this->telegramRelayStateText('nodomain')];
                    if ($relay['prefix'] === '') $relay['prefix'] = bin2hex(random_bytes(16));
                    $relay['enabled'] = true;
                    break;
                case 'off':
                    $relay['enabled'] = false;
                    break;
                case 'rotate':
                    $relay['prefix'] = bin2hex(random_bytes(16));
                    break;
                case 'bot-add':
                    if (!preg_match('~^[1-9][0-9]{4,14}$~D', $value)) return [false, $this->t('ID бота — число из 5–15 цифр (часть токена до двоеточия)', 'a bot ID is a number of 5–15 digits (the token part before the colon)')];
                    if (in_array($value, $relay['bots'], true)) return [true, $this->t('этот бот уже разрешён', 'this bot is already allowed')];
                    if (count($relay['bots']) >= self::TG_RELAY_MAX) return [false, $this->t('разрешено не больше 16 ботов', 'at most 16 bots are allowed')];
                    $relay['bots'][] = $value;
                    break;
                case 'bot-del':
                    $relay['bots'] = array_values(array_filter($relay['bots'], static fn($b) => $b !== $value));
                    break;
                case 'ip-add':
                    $cidr = self::telegramRelayCidr($value);
                    if ($cidr === null) return [false, $this->t('нужен адрес IPv4/IPv6 или сеть CIDR, например 203.0.113.5 или 2001:db8::/48', 'an IPv4/IPv6 address or CIDR network is required, e.g. 203.0.113.5 or 2001:db8::/48')];
                    if (in_array($cidr, $relay['ips'], true)) return [true, $this->t('этот адрес уже в списке', 'this address is already listed')];
                    if (count($relay['ips']) >= self::TG_RELAY_MAX) return [false, $this->t('в списке не больше 16 адресов', 'at most 16 addresses are allowed')];
                    $relay['ips'][] = $cidr;
                    break;
                case 'ip-del':
                    $cidr = self::telegramRelayCidr($value) ?? $value;
                    $relay['ips'] = array_values(array_filter($relay['ips'], static fn($ip) => $ip !== $cidr));
                    break;
                default:
                    return [false, 'unknown operation'];
            }
            // Последний бот удалён — ретранслятор выключается: без списка он
            // пропускал бы токены любых ботов.
            if ($relay['bots'] === []) $relay['enabled'] = false;
            // «Включить» повторно ставит блок, если его нет в nginx.conf
            // (состояние «включён, но не применён»).
            $reapply = $op === 'on' && !self::telegramRelayActiveIn($this->telegramRelayNginxText(), self::telegramRelayNormalize($relay));
            if (self::telegramRelayNormalize($relay) === $before && !$reapply) return [true, $this->t('без изменений', 'no changes')];
            if (!$this->telegramRelayApply($relay)) return [false, $this->t('nginx не принял конфигурацию; прежняя настройка сохранена', 'nginx rejected the configuration; the previous setting is kept')];
            $after = $this->telegramRelayStatus();
            $message = $this->t('сохранено; ретранслятор: ', 'saved; relay: ') . $this->telegramRelayStateText($after['state']);
            if ($op === 'rotate') $message .= '. ' . $this->t('Прежний адрес больше не работает: укажите новый на серверах-клиентах', 'The previous address no longer works: set the new one on the client servers');
            return [true, $message];
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    // ── Меню ───────────────────────────────────────────────────────────────

    public function telegramApiMenu(string $section = '', string $action = '', string $arg = '', string $notice = '')
    {
        if ($section === 'client') {
            if (in_array($action, ['set', 'reset', 'worker'], true) && !$this->telegramApiOwnerAllowed()) return;
            if ($action === 'set') return $this->telegramApiPrompt('client');
            if ($action === 'check') { [$ok, $msg] = $this->telegramApiCheck(); return $this->telegramApiClientMenu(($ok ? '✅ ' : '❌ ') . $msg); }
            if ($action === 'reset') { [$ok, $msg] = $this->telegramApiResetUrl(); return $this->telegramApiClientMenu(($ok ? '✅ ' : '❌ ') . $msg); }
            if ($action === 'worker') return $this->telegramWorkerSend();
            return $this->telegramApiClientMenu($notice);
        }
        if ($section === 'relay') {
            if ($action === 'bot' || $action === 'ip') return $this->telegramApiPrompt($action);
            if ($action === 'rotate' && $arg !== 'yes') {
                $text = 'Menu -> ' . $this->i18n('config') . ' -> Telegram API -> ' . $this->t('ретранслятор', 'relay') . "\n\n⚠ "
                    . $this->t('Будет создан новый адрес ретранслятора. Прежний сразу перестанет работать: боты, которые ходят через него, потеряют связь с Telegram, пока вы не укажете им новый адрес.',
                        'A new relay address will be created. The previous one stops working at once: bots that use it lose Telegram until you give them the new address.');
                return $this->update($this->input['chat'], $this->input['message_id'], $text, [
                    [['text' => '🔄 ' . $this->t('создать новый адрес', 'create a new address'), 'callback_data' => '/tgapi relay rotate yes']],
                    [['text' => $this->i18n('cancel'), 'callback_data' => '/tgapi relay']],
                ]);
            }
            $ops = ['on' => 'on', 'off' => 'off', 'rotate' => 'rotate', 'delbot' => 'bot-del'];
            if (isset($ops[$action])) {
                [$ok, $msg] = $this->telegramRelayChange($ops[$action], $arg);
                return $this->telegramApiRelayMenu(($ok ? '✅ ' : '❌ ') . $msg);
            }
            if ($action === 'delip') {
                foreach ($this->telegramRelayConf()['ips'] as $ip) {
                    if (substr(hash('sha256', $ip), 0, 8) === $arg) {
                        [$ok, $msg] = $this->telegramRelayChange('ip-del', $ip);
                        return $this->telegramApiRelayMenu(($ok ? '✅ ' : '❌ ') . $msg);
                    }
                }
            }
            return $this->telegramApiRelayMenu($notice);
        }
        $state = TelegramApi::current($this->telegramApiFile);
        $status = $this->telegramRelayStatus();
        $text = ['Menu -> ' . $this->i18n('config') . ' -> Telegram API'];
        if ($notice !== '') $text[] = self::esc($notice);
        $text[] = '';
        $text[] = '<b>' . $this->t('Связь этого бота с Telegram', 'This bot\'s connection to Telegram') . '</b>';
        $text[] = $this->t('Адрес: ', 'Address: ') . '<code>' . self::esc(TelegramApi::mask($state['url'])) . '</code> (' . $this->telegramApiSourceText($state) . ')';
        $text[] = '';
        $text[] = '<b>' . $this->t('Ретранслятор для других ботов', 'Relay for other bots') . '</b>';
        $text[] = $this->t('Состояние: ', 'State: ') . $this->telegramRelayStateText($status['state']);
        return $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $text), [
            [['text' => '🔌 ' . $this->t('Адрес Bot API этого бота', 'Bot API address of this bot'), 'callback_data' => '/tgapi client']],
            [['text' => '📡 ' . $this->t('Ретранслятор', 'Relay') . ': ' . $this->i18n($status['relay']['enabled'] ? 'on' : 'off'), 'callback_data' => '/tgapi relay']],
            $this->menuHelpButton('tgapi'),
            [['text' => $this->i18n('back'), 'callback_data' => '/menu config']],
        ]);
    }

    public function telegramApiClientMenu(string $notice = '')
    {
        $owner = $this->isOwner();
        $state = TelegramApi::current($this->telegramApiFile);
        $text = ['Menu -> ' . $this->i18n('config') . ' -> Telegram API -> ' . $this->t('адрес Bot API', 'Bot API address')];
        if ($notice !== '') $text[] = self::esc($notice);
        $text[] = '';
        $text[] = $this->t('Адрес: ', 'Address: ') . '<code>' . self::esc(TelegramApi::mask($state['url'])) . '</code> (' . $this->telegramApiSourceText($state) . ')';
        if (in_array('file', $state['invalid'], true)) $text[] = '⚠ ' . $this->t('значение в config/telegram_api не принято — используется следующий источник', 'the value in config/telegram_api is rejected; the next source is used');
        if (in_array('env', $state['invalid'], true)) $text[] = '⚠ ' . $this->t('TELEGRAM_API в .env не принят — используется api.telegram.org', 'TELEGRAM_API in .env is rejected; api.telegram.org is used');
        $text[] = $this->t('Прокси TELEGRAM_PROXY: ', 'TELEGRAM_PROXY: ') . (getenv('TELEGRAM_PROXY') ? $this->t('задан', 'set') : $this->t('нет', 'none'));
        $text[] = $this->t('ID этого бота: ', 'This bot ID: ') . '<code>' . self::esc(TelegramApi::botId((string) $this->key)) . '</code>';
        $text[] = '';
        $text[] = $this->t('Ретранслятор нужен, если с этого сервера не открывается api.telegram.org. На сервере с ретранслятором добавьте ID этого бота, затем укажите здесь его адрес. Новый адрес сохраняется только после успешной проверки getMe через него.',
            'Use a relay when this server cannot reach api.telegram.org. Add this bot ID on the relay server, then enter its address here. A new address is saved only after a successful getMe through it.');
        $text[] = $this->t('Нет второго сервера — подойдёт Worker в бесплатном аккаунте Cloudflare: кнопка ниже пришлёт готовый скрипт.', 'No second server? A Worker in a free Cloudflare account works too: the button below sends a ready script.');
        $text[] = '⚠ ' . $this->t('Ретранслятор получает токен и все сообщения бота: указывайте только свой сервер или свой Worker.', 'The relay receives the bot token and all messages: use only your own server or your own Worker.');
        $data = [
            [['text' => '✏️ ' . $this->t('указать адрес ретранслятора', 'set the relay address'), 'callback_data' => '/tgapi client set']],
            [['text' => '✅ ' . $this->t('проверить связь', 'check the connection'), 'callback_data' => '/tgapi client check']],
            [['text' => '☁️ ' . $this->t('ретранслятор на Cloudflare Workers', 'relay on Cloudflare Workers'), 'callback_data' => '/tgapi client worker']],
        ];
        if (!$owner) {
            $data = [$data[1]];
            $text[] = $this->t('Адрес Bot API может менять только владелец через Telegram.', 'Only the owner can change the Bot API address through Telegram.');
        }
        if ($owner && ($state['source'] === 'file' || in_array('file', $state['invalid'], true))) {
            $data[] = [['text' => '↩️ ' . $this->t('вернуть ', 'go back to ') . TelegramApi::mask(TelegramApi::fallback()), 'callback_data' => '/tgapi client reset']];
        }
        $data[] = $this->menuHelpButton('tgapi');
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => '/tgapi']];
        return $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $text), $data);
    }

    public function telegramApiRelayMenu(string $notice = '')
    {
        $status = $this->telegramRelayStatus();
        $relay = $status['relay'];
        $text = ['Menu -> ' . $this->i18n('config') . ' -> Telegram API -> ' . $this->t('ретранслятор', 'relay')];
        if ($notice !== '') $text[] = self::esc($notice);
        $text[] = '';
        $text[] = $this->t('Состояние: ', 'State: ') . $this->telegramRelayStateText($status['state']);
        if ($status['state'] === 'on' && ($url = $this->telegramRelayUrl($relay)) !== '') {
            $text[] = $this->t('Адрес (секрет, как пароль): ', 'Address (secret, like a password): ') . '<code>' . self::esc($url) . '</code>';
        }
        $text[] = $this->t('Разрешённые боты: ', 'Allowed bots: ') . ($relay['bots'] ? '<code>' . implode('</code>, <code>', $relay['bots']) . '</code>' : $this->t('нет', 'none'));
        $text[] = $this->t('Адреса клиентов: ', 'Client addresses: ') . ($relay['ips'] ? '<code>' . implode('</code>, <code>', array_map([self::class, 'esc'], $relay['ips'])) . '</code>' : $this->t('любые', 'any'));
        $text[] = '';
        $text[] = $this->t('Ретранслятор пропускает к api.telegram.org только запросы Bot API разрешённых ботов и проверяет сертификат Telegram. Путь запроса с токеном в журнал не пишется. Он видит токены и сообщения проходящих ботов: используйте только свой сервер.',
            'The relay passes only Bot API requests of the allowed bots to api.telegram.org and verifies the Telegram certificate. Request paths with tokens are not logged. It sees the tokens and messages of the bots passing through: use only your own server.');
        $data = [[[
            'text' => ($relay['enabled'] ? '✅ ' : '⬜ ') . $this->t('ретранслятор', 'relay') . ': ' . $this->i18n($relay['enabled'] ? 'on' : 'off'),
            'callback_data' => '/tgapi relay ' . ($relay['enabled'] ? 'off' : 'on'),
        ]]];
        $row = [['text' => '+ ' . $this->t('ID бота', 'bot ID'), 'callback_data' => '/tgapi relay bot']];
        foreach ($relay['bots'] as $bot) $row[] = ['text' => "❌ $bot", 'callback_data' => "/tgapi relay delbot $bot"];
        foreach (array_chunk($row, 3) as $chunk) $data[] = $chunk;
        $row = [['text' => '+ IP', 'callback_data' => '/tgapi relay ip']];
        foreach ($relay['ips'] as $ip) $row[] = ['text' => "❌ $ip", 'callback_data' => '/tgapi relay delip ' . substr(hash('sha256', $ip), 0, 8)];
        foreach (array_chunk($row, 2) as $chunk) $data[] = $chunk;
        if ($relay['prefix'] !== '') $data[] = [['text' => '🔄 ' . $this->t('новый адрес', 'new address'), 'callback_data' => '/tgapi relay rotate']];
        $data[] = $this->menuHelpButton('tgapi');
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => '/tgapi']];
        return $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $text), $data);
    }

    public function telegramApiPrompt(string $kind)
    {
        if ($kind === 'client' && !$this->telegramApiOwnerAllowed()) return;
        $question = match ($kind) {
            'client' => $this->t('отправьте адрес ретранслятора вида https://домен/префикс (его показывает бот на сервере ретранслятора)', 'send the relay address like https://domain/prefix (the bot on the relay server shows it)'),
            'bot' => $this->t('отправьте числовой ID бота — часть его токена до двоеточия; секретную часть токена отправлять не нужно', 'send the numeric bot ID, the part of its token before the colon; do not send the secret part'),
            default => $this->t('отправьте IPv4/IPv6 адрес или сеть CIDR сервера-клиента', 'send the IPv4/IPv6 address or CIDR network of the client server'),
        };
        $r = $this->send($this->input['chat'], "@{$this->input['username']} $question", $this->input['message_id'], reply: $question);
        $this->stashReply($r, [
            'start_message' => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback' => 'telegramApiReply',
            'args' => [$kind],
        ]);
    }

    public function telegramApiReply($text, string $kind = '')
    {
        if ($kind === 'client' && !$this->telegramApiOwnerAllowed()) return;
        $text = trim((string) $text);
        if ($kind === 'client') {
            [$ok, $msg] = $this->telegramApiSetUrl($text);
            return $this->telegramApiClientMenu(($ok ? '✅ ' : '❌ ') . $msg);
        }
        if ($kind === 'bot') {
            // Вставленный целиком токен: берём только ID, секрет не сохраняем
            // и не показываем (сообщение администратора бот уже удалил).
            $pasted = (bool) preg_match('~^([0-9]{5,15}):\S+$~D', $text, $m);
            [$ok, $msg] = $this->telegramRelayChange('bot-add', $pasted ? $m[1] : $text);
            if ($pasted) $msg .= '. ' . $this->t('Из сообщения взят только ID; если токен мог попасть к посторонним, замените его у @BotFather', 'Only the ID was taken from the message; if the token could have leaked, replace it at @BotFather');
            return $this->telegramApiRelayMenu(($ok ? '✅ ' : '❌ ') . $msg);
        }
        if ($kind === 'ip') {
            [$ok, $msg] = $this->telegramRelayChange('ip-add', $text);
            return $this->telegramApiRelayMenu(($ok ? '✅ ' : '❌ ') . $msg);
        }
    }

    // ── CLI: php /app/tgapi.php <команда> (make tgapi cmd="…") ─────────────

    private function telegramApiOwnerAllowed(): bool
    {
        if ($this->isOwner()) return true;
        $notice = $this->t('Адрес Bot API может менять только владелец через Telegram.', 'Only the owner can change the Bot API address through Telegram.');
        if (!empty($this->input['callback_id'])) $this->answer($this->input['callback_id'], $notice, true);
        elseif (!empty($this->input['chat'])) $this->send($this->input['chat'], $notice);
        return false;
    }

    public function telegramApiCli(array $args, $out = STDOUT): int
    {
        $cmd = (string) ($args[0] ?? 'help');
        $value = (string) ($args[1] ?? '');
        $print = static function (string $line) use ($out) { fwrite($out, $line . "\n"); };
        $result = static function (array $r) use ($print): int { $print(($r[0] ? 'OK: ' : 'ERROR: ') . $r[1]); return $r[0] ? 0 : 1; };
        $relayOps = ['relay-on' => 'on', 'relay-off' => 'off', 'relay-rotate' => 'rotate', 'relay-bot-add' => 'bot-add',
            'relay-bot-del' => 'bot-del', 'relay-ip-add' => 'ip-add', 'relay-ip-del' => 'ip-del'];
        switch (true) {
            case $cmd === 'status':
                $state = TelegramApi::current($this->telegramApiFile);
                $status = $this->telegramRelayStatus();
                $print('api: ' . TelegramApi::mask($state['url']) . ' (' . $this->telegramApiSourceText($state) . ')');
                foreach ($state['invalid'] as $bad) $print('api rejected: ' . ($bad === 'file' ? 'config/telegram_api' : 'TELEGRAM_API'));
                $print('bot id: ' . TelegramApi::botId((string) $this->key));
                $print('relay: ' . $this->telegramRelayStateText($status['state']));
                $print('relay bots: ' . ($status['relay']['bots'] ? implode(', ', $status['relay']['bots']) : '-'));
                $print('relay clients: ' . ($status['relay']['ips'] ? implode(', ', $status['relay']['ips']) : 'any'));
                $print('relay url: ' . ($status['relay']['prefix'] !== '' && $this->telegramRelayDomain() !== '' ? TelegramApi::mask($this->telegramRelayUrl($status['relay'])) . ' (make tgapi cmd=relay-url)' : '-'));
                return 0;
            case $cmd === 'api-check':
                return $result($this->telegramApiCheck());
            case $cmd === 'api-set' && $value !== '':
                return $result($this->telegramApiSetUrl($value));
            case $cmd === 'api-reset':
                return $result($this->telegramApiResetUrl($value === '--force'));
            case $cmd === 'cf-worker':
                fwrite($out, $this->telegramWorker()[1]);
                return 0;
            case $cmd === 'relay-url':
                $url = $this->telegramRelayUrl();
                if ($url === '' || $this->telegramRelayStatus()['state'] !== 'on') { $print('ERROR: ' . $this->telegramRelayStateText($this->telegramRelayStatus()['state'])); return 1; }
                $print($url);
                return 0;
            case isset($relayOps[$cmd]) && (in_array($cmd, ['relay-on', 'relay-off', 'relay-rotate'], true) || $value !== ''):
                return $result($this->telegramRelayChange($relayOps[$cmd], $value));
            default:
                foreach ([
                    'status                  ' . $this->t('адрес Bot API и состояние ретранслятора', 'Bot API address and relay state'),
                    'api-check               ' . $this->t('проверить getMe через текущий адрес', 'check getMe through the current address'),
                    'api-set <url>           ' . $this->t('ходить через ретранслятор (после проверки getMe)', 'use a relay (after a getMe check)'),
                    'api-reset [--force]     ' . $this->t('вернуть TELEGRAM_API из .env или api.telegram.org', 'go back to TELEGRAM_API from .env or api.telegram.org'),
                    'cf-worker               ' . $this->t('скрипт ретранслятора для Cloudflare Workers (адрес — в его первых строках)', 'relay script for Cloudflare Workers (the address is in its first lines)'),
                    'relay-on | relay-off    ' . $this->t('включить или выключить ретранслятор', 'turn the relay on or off'),
                    'relay-bot-add <id>      ' . $this->t('разрешить бота (ID — часть токена до двоеточия)', 'allow a bot (ID is the token part before the colon)'),
                    'relay-bot-del <id>      ' . $this->t('запретить бота', 'remove a bot'),
                    'relay-ip-add <ip/cidr>  ' . $this->t('пускать только с этих адресов', 'accept only these addresses'),
                    'relay-ip-del <ip/cidr>  ' . $this->t('убрать адрес', 'remove an address'),
                    'relay-rotate            ' . $this->t('новый секретный адрес', 'new secret address'),
                    'relay-url               ' . $this->t('показать полный адрес (секрет)', 'print the full address (secret)'),
                ] as $line) $print($line);
                return $cmd === 'help' ? 0 : 2;
        }
    }
}
