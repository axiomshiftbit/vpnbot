<?php
// Адрес Bot API (TelegramApi) и ретранслятор Telegram API (BotTelegramApi):
// разбор адресов, приоритет источников, блок nginx на настоящем шаблоне,
// отказ nginx -t с откатом, меню ru/en, ввод, CLI. Токен бота нигде не
// должен попадать в вывод.
require_once __DIR__ . '/../app/bot.php';
set_error_handler(static function ($level, $message, $file, $line) { if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line); return true; });

$checks = 0;
function check(bool $condition, string $label): void { global $checks; $checks++; if (!$condition) { fwrite(STDERR, "FAIL: $label\n"); exit(1); } }

const SECRET = 'AAHsyntheticSECRETpart0123456789abcdefXYZ';
const KEY = '1234567890:' . SECRET;

$root = sys_get_temp_dir() . '/vpnbot-tgapi-' . bin2hex(random_bytes(6));
mkdir($root, 0700, true);
register_shutdown_function(static fn() => exec('rm -rf ' . escapeshellarg($root)));

// ── TelegramApi::normalize ───────────────────────────────────────────────
$ok = [
    'api.telegram.org' => 'https://api.telegram.org',
    'https://API.Telegram.org/' => 'https://api.telegram.org',
    '  tg.example.org//  ' => 'https://tg.example.org',
    'tg-audit:8443' => 'https://tg-audit:8443',
    'https://relay.example.com/0123456789abcdef0123456789abcdef' => 'https://relay.example.com/0123456789abcdef0123456789abcdef',
    'https://relay.example.com:8443/a/b_c.d~e-f' => 'https://relay.example.com:8443/a/b_c.d~e-f',
    'https://[2001:db8::1]:8443/x' => 'https://[2001:db8::1]:8443/x',
    'https://203.0.113.7/p' => 'https://203.0.113.7/p',
    'https://x.y:65535' => 'https://x.y:65535',
];
foreach ($ok as $in => $out) check(TelegramApi::normalize($in) === $out, "normalize $in");
foreach (['', ' ', 'http://tg.example.org', 'ftp://x.y', 'HTTPS://x.y', 'https://user@x.y', 'https://u:p@x.y/a', 'https://x.y/a?b=1',
    'https://x.y/#f', 'https://x.y/a b', 'https://x.y/../a', 'https://x.y/a/..', 'https://x.y/./a', 'https://x.y/a%2e', 'https://x.y:0',
    'https://x.y:65536', 'https://x.y:08443', 'https://-x.y', 'https://x-.y', 'https://[zz::1]', 'https://[::1', "https://x.y\n/a",
    "https://x.y/a\"b", "https://x.y/a'b", 'https://x.y/a;b', 'https://x.y/a\\b', 'https://x.y/' . str_repeat('a', 65), 'https://x.y' . str_repeat('/a', 9),
    'https://' . str_repeat('a', 250) . '.y', 'https://x.y/a$b', 'https://x.y/a{b}', 'https://x_y.z'] as $bad) {
    check(TelegramApi::normalize($bad) === null, 'reject ' . json_encode($bad));
}

// ── источник: файл → .env → по умолчанию ─────────────────────────────────
$file = "$root/telegram_api";
check(TelegramApi::current($file, '') === ['url' => TelegramApi::DEFAULT, 'source' => 'default', 'invalid' => []], 'нет ничего — по умолчанию');
check(TelegramApi::current($file, 'api.telegram.org')['source'] === 'default', 'значение .env по умолчанию не показывается как «из .env»');
check(TelegramApi::current($file, 'mirror.example.org')['url'] === 'https://mirror.example.org' && TelegramApi::current($file, 'mirror.example.org')['source'] === 'env', '.env');
check(TelegramApi::current($file, 'http://bad.example')['invalid'] === ['env'] && TelegramApi::current($file, 'http://bad.example')['url'] === TelegramApi::DEFAULT, 'плохой .env — официальный адрес');
check(TelegramApi::save($file, 'https://relay.example.com/abc'), 'save');
check((fileperms($file) & 0777) === 0600, 'файл 0600');
check(TelegramApi::current($file, 'mirror.example.org') === ['url' => 'https://relay.example.com/abc', 'source' => 'file', 'invalid' => []], 'файл перекрывает .env');
check(!TelegramApi::save($file, 'https://Relay.example.com/abc'), 'save принимает только нормализованный адрес');
check(!TelegramApi::save($file, 'http://relay.example.com'), 'save отвергает http');
file_put_contents($file, "http://evil.example/x\n");
$cur = TelegramApi::current($file, 'mirror.example.org');
check($cur['url'] === 'https://mirror.example.org' && $cur['invalid'] === ['file'], 'испорченный файл — следующий источник');
check(TelegramApi::save($file, null) && !file_exists($file), 'null удаляет настройку');
symlink('/etc/hostname', $file);
check(TelegramApi::current($file, '')['source'] === 'default' && !TelegramApi::save($file, 'https://x.y'), 'символьная ссылка не читается и не перезаписывается');
unlink($file);
check(TelegramApi::fallback('mirror.example.org') === 'https://mirror.example.org' && TelegramApi::fallback('') === TelegramApi::DEFAULT, 'fallback без файла');
check(TelegramApi::mask('https://relay.example.com/0123456789abcdef') === 'https://relay.example.com/•••', 'путь скрыт');
check(TelegramApi::mask('https://api.telegram.org') === 'https://api.telegram.org', 'без пути — как есть');
check(TelegramApi::mask('https://[2001:db8::1]:8443/x') === 'https://[2001:db8::1]:8443/•••', 'IPv6 с портом');
check(TelegramApi::botId(KEY) === '1234567890' && TelegramApi::botId('bad') === '', 'botId');
check(TelegramApi::probe('http://x.y', KEY)['reason'] === 'invalid', 'probe не идёт по ненормализованному адресу');
check(TelegramApi::classify(0, 401, '<html><title>401 Authorization Required</title></html>', KEY)['reason'] === 'http', '401 страницы сайта — не отказ токена');
check(TelegramApi::classify(0, 401, '{"ok":false,"error_code":401,"description":"Unauthorized"}', KEY)['reason'] === 'unauthorized', '401 Bot API — отказ токена');
check(TelegramApi::classify(0, 200, '{"ok":true,"result":{"id":1234567890,"is_bot":true,"username":"x_bot"}}', KEY) === ['ok' => true, 'reason' => 'ok', 'username' => 'x_bot'], 'getMe этого бота');
check(TelegramApi::classify(0, 200, '{"ok":true,"result":{"id":999999,"is_bot":true}}', KEY)['reason'] === 'mismatch', 'ответ другого бота');
check(TelegramApi::classify(0, 200, '{"ok":true,"result":{"id":1234567890,"is_bot":false}}', KEY)['reason'] === 'mismatch', 'не бот');
check(TelegramApi::classify(0, 200, '{"ok":true,"result":{"id":1234567890,"is_bot":true,"username":"<b>"}}', KEY)['username'] === '', 'имя бота фильтруется');
check(TelegramApi::classify(60, 0, false, KEY)['reason'] === 'tls' && TelegramApi::classify(7, 0, false, KEY)['reason'] === 'network' && TelegramApi::classify(28, 0, false, KEY)['reason'] === 'network', 'категории curl');
check(TelegramApi::classify(0, 502, '<html>502</html>', KEY) === ['ok' => false, 'reason' => 'http', 'http' => 502], '502 ретранслятора');

// ── ретранслятор: нормализация ──────────────────────────────────────────
check(Bot::telegramRelayCidr('10.1.2.3/8') === '10.0.0.0/8', 'CIDR к началу сети');
check(Bot::telegramRelayCidr('2001:db8::1/48') === '2001:db8::/48', 'CIDR IPv6');
check(Bot::telegramRelayCidr('203.0.113.5') === '203.0.113.5' && Bot::telegramRelayCidr(' 2001:DB8::5 ') === '2001:db8::5', 'адрес');
check(Bot::telegramRelayCidr('203.0.113.5/32') === '203.0.113.5', '/32 — адрес');
foreach (['1.2.3.4; deny all', '1.2.3.4/33', 'x', '1.2.3.4/-1', '::1/129', '1.2.3.4 5.6.7.8', '', '1.2.3.4/'] as $bad) check(Bot::telegramRelayCidr($bad) === null, "CIDR reject $bad");
$n = Bot::telegramRelayNormalize(['enabled' => true, 'prefix' => '../etc', 'bots' => ['123456'], 'ips' => []]);
check($n['prefix'] === '' && $n['enabled'] === false, 'плохой префикс выключает');
$n = Bot::telegramRelayNormalize(['enabled' => true, 'prefix' => str_repeat('a', 32), 'bots' => ['0123456', '1234', '1234567890123456', '123456;', 123456, '123456', ['x'], '777777'], 'ips' => ['10.1.2.3/8', 'bad', '10.0.0.0/8', 5]]);
check($n['bots'] === ['123456', '777777'] && $n['ips'] === ['10.0.0.0/8'] && $n['enabled'], 'боты и адреса фильтруются и не повторяются');
check(Bot::telegramRelayNormalize(['enabled' => true, 'prefix' => str_repeat('a', 32), 'bots' => []])['enabled'] === false, 'без ботов выключен');
check(Bot::telegramRelayNormalize('junk') === ['enabled' => false, 'prefix' => '', 'bots' => [], 'ips' => []], 'мусор');
$many = Bot::telegramRelayNormalize(['bots' => array_map(static fn($i) => (string) (100000 + $i), range(1, 30))]);
check(count($many['bots']) === 16, 'не больше 16 ботов');

// ── блок nginx на настоящем шаблоне ─────────────────────────────────────
class RelayBot extends Bot
{
    public array $conf = [];
    public array $updated = [];
    public array $sent = [];
    public array $stashed = [];
    public array $ssh = [];
    public bool $nginxValid = true;
    public bool $nginxReload = true;
    public array $probes = [];
    public array $probeResult = ['ok' => true, 'reason' => 'ok'];

    public function __construct(string $language = 'ru')
    {
        $this->key = KEY;
        $this->ip = '203.0.113.9';
        $this->language = $language;
        Lang::$en = $language === 'en';
        require __DIR__ . '/../app/i18n.php';
        $this->i18n = $i;
        $this->input = ['chat' => 1, 'message_id' => 2, 'callback_id' => 3, 'callback' => '', 'username' => 'admin'];
    }
    public function isOwner(): bool { return true; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }

    public function getPacConf() { return $this->conf; }
    public function setPacConf(array $conf) { $this->conf = $conf; }
    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false)
    { $this->sent[] = [$text, $button, $reply]; return ['ok' => true, 'result' => ['message_id' => 50]]; }
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML')
    { $this->updated[] = [$text, $button]; return ['ok' => true]; }
    public function stashReply($r, array $state) { $this->stashed[] = $state; }
    public function telegramApiProbe(string $url): array { $this->probes[] = $url; return $this->probeResult; }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
    {
        $this->ssh[] = [$service, $cmd];
        if (str_contains($cmd, 'VPNBOT_STAGED')) return 'VPNBOT_STAGED';
        if (str_contains($cmd, 'nginx -t -c ')) return $this->nginxValid ? 'VPNBOT_VALID' : '';
        if (str_contains($cmd, 'VPNBOT_APPLIED')) return $this->nginxReload ? 'VPNBOT_APPLIED' : '';
        return '';
    }
    public function last(): array { return end($this->updated) ?: ['', []]; }
    public array $files = [];
    public bool $fileOk = true;
    public function sendFile($chat, $id_url_cFile, $caption = false, $to = false)
    { $this->files[] = [$id_url_cFile, $caption]; return ['ok' => $this->fileOk]; }
}

$template = file_get_contents(__DIR__ . '/../config/nginx_default.conf');
$bot = new RelayBot();
preg_match_all('~#-domain.+?#-domain~s', $template, $m);
$domainText = $template;
foreach ($m[0] as $v) $domainText = preg_replace('~#-domain.+?#-domain~s', $bot->uncomment($v, 'domain'), $domainText, 1);
check(Bot::telegramRelayDomainBlock($domainText) && !Bot::telegramRelayDomainBlock($template), 'server-блок домена распознаётся только раскомментированным');

$prefix = '0123456789abcdef0123456789abcdef';
$relay = ['enabled' => true, 'prefix' => $prefix, 'bots' => ['123456789', '987654321'], 'ips' => []];
$out = Bot::telegramRelayNginx($domainText, $relay);
check(substr_count($out, Bot::TG_RELAY_BEGIN) === 1 && substr_count($out, Bot::TG_RELAY_ZONES_BEGIN) === 1 && substr_count($out, Bot::TG_RELAY_GUARD_BEGIN) === 2, 'по одному блоку, защита в двух server-блоках');
$guard = substr($out, strpos($out, Bot::TG_RELAY_GUARD_BEGIN), strpos($out, Bot::TG_RELAY_GUARD_END) - strpos($out, Bot::TG_RELAY_GUARD_BEGIN));
check(str_contains($guard, 'return 404;') && str_contains($guard, 'access_log /logs/nginx_tgrelay_access vpnbot_tgrelay;') && str_contains($guard, 'error_log /dev/null;'), 'защита: 404 и журнал без пути');
preg_match('#location ~ "(.+?)" \{#', $guard, $gm);
$gre = '~' . str_replace('~', '\~', $gm[1]) . '~';
foreach (['/ffff/bot123456789:' . SECRET . '/getMe', '/x/file/bot123456789:' . SECRET . '/a.txt', '/bot123456789:' . SECRET] as $path) check(preg_match($gre, $path) === 1, "защита ловит $path");
foreach (['/pac' . $prefix . '/abc', '/webapp/index.html', '/ws12345678/session/1', '/dns-query12345678', '/bot123456789:short/getMe'] as $path) check(preg_match($gre, $path) === 0, "защита не трогает $path");
check(strpos($out, 'location ~ /\\.') < strpos($out, Bot::TG_RELAY_GUARD_BEGIN), 'защита после правила точечных файлов');
check(Bot::telegramRelayNginx($out, $relay) === $out, 'повторное применение ничего не меняет');
$off = Bot::telegramRelayNginx($out, ['enabled' => false] + $relay);
check(!str_contains($off, Bot::TG_RELAY_BEGIN) && substr_count($off, Bot::TG_RELAY_GUARD_BEGIN) === 2 && substr_count($off, Bot::TG_RELAY_ZONES_BEGIN) === 1, 'выключен после использования: ретранслятора нет, защита журналов в обоих server-блоках');
check(Bot::telegramRelayNginx($out, ['enabled' => false, 'prefix' => ''] + $relay) === $domainText, 'без префикса текст исходный');
check(Bot::telegramRelayNginx($domainText, ['enabled' => false, 'prefix' => '', 'bots' => []]) === $domainText, 'ни разу не включали — nginx.conf не меняется');
$noLe = Bot::telegramRelayNginx($template, $relay);
check(!str_contains($noLe, Bot::TG_RELAY_BEGIN) && substr_count($noLe, Bot::TG_RELAY_GUARD_BEGIN) === 1, 'без домена с LE ретранслятора нет, защита в server-блоке по IP');
check(!str_contains(Bot::telegramRelayNginx($domainText, ['bots' => []] + $relay), Bot::TG_RELAY_BEGIN), 'без ботов ретранслятора нет');
check(Bot::telegramRelayNginx($off, ['enabled' => false] + $relay) === $off, 'выключенное состояние устойчиво');
$region = preg_match('~^[ \t]*##domain[ \t]*\n(.*?)^[ \t]*##domain~ms', $out, $r) ? $r[1] : '';
check(str_contains($region, "location ^~ /$prefix/ {"), 'location внутри server-блока домена');
check(strpos($region, Bot::TG_RELAY_END) < strpos($region, 'include location.conf;'), 'перед include location.conf');
$default = substr($out, 0, strpos($out, '##domain'));
check(!str_contains(substr($default, strpos($default, 'server {')), "location ^~ /$prefix/"), 'не в server-блоке по IP с самоподписанным сертификатом');
check(preg_match('~^http \{\n    ' . preg_quote(Bot::TG_RELAY_ZONES_BEGIN, '~') . '~m', $out) === 1, 'зоны сразу после http {');
$block = substr($out, strpos($out, Bot::TG_RELAY_BEGIN), strpos($out, Bot::TG_RELAY_END) - strpos($out, Bot::TG_RELAY_BEGIN));
$zones = substr($out, strpos($out, Bot::TG_RELAY_ZONES_BEGIN), strpos($out, Bot::TG_RELAY_ZONES_END) - strpos($out, Bot::TG_RELAY_ZONES_BEGIN));
foreach (['proxy_ssl_verify on;', 'proxy_ssl_name api.telegram.org;', 'proxy_ssl_server_name on;', 'proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;',
    'proxy_ssl_verify_depth 4;', 'error_log /dev/null;', 'access_log /logs/nginx_tgrelay_access vpnbot_tgrelay;', 'limit_except GET POST { deny all; }',
    'client_max_body_size 52m;', 'resolver 127.0.0.11 valid=300s ipv6=off;', 'proxy_set_header Host api.telegram.org;', 'return 404;',
    'bot(?:123456789|987654321):[A-Za-z0-9_-]{30,64}', 'limit_req zone=vpnbot_tgrelay', 'limit_conn vpnbot_tgrelay_conn', 'proxy_next_upstream off;'] as $needle) {
    check(str_contains($block, $needle), "в блоке: $needle");
}
check(!str_contains($block, 'proxy_ssl_verify off') && !str_contains($block, 'allow ') && !str_contains($block, 'deny all;' . "\n" . '    location'), 'без проверки TLS и без списка адресов не бывает');
check(!preg_match('~\$(?:uri|request_uri|request|args|query_string|http_referer|arg_\w+|http_user_agent)\b~', $zones) && str_contains($zones, '$request_method'), 'формат журнала без пути, query и Referer');
check(preg_match('#^[ \t]*location ~ "\^/' . $prefix . '/\(\?:bot#m', $block) === 1, 'вложенная regex-локация привязана к префиксу');
$withIps = Bot::telegramRelayNginx($domainText, ['ips' => ['203.0.113.5', '2001:db8::/48']] + $relay);
check(str_contains($withIps, "    allow 203.0.113.5;\n") && str_contains($withIps, "allow 2001:db8::/48;") && preg_match('~allow 2001:db8::/48;\n[ \t]*deny all;~', $withIps) === 1, 'allow + deny all');
// Попытки протащить директивы через настройки.
$evil = Bot::telegramRelayNginx($domainText, ['enabled' => true, 'prefix' => $prefix . '/ { } location / {', 'bots' => ['123456'], 'ips' => []]);
check($evil === $domainText, 'префикс с директивами не принимается');
$evil = Bot::telegramRelayNginx($domainText, ['enabled' => true, 'prefix' => $prefix, 'bots' => ['123456|.*', '123456'], 'ips' => ['1.2.3.4; allow all']]);
check(str_contains($evil, 'bot(?:123456):') && !str_contains($evil, '123456|.*') && !str_contains($evil, 'allow all') && !str_contains($evil, 'allow '), 'бот и адрес с директивами отброшены');
// Другие правки nginx.conf не задевают блок (их регулярки ищут /pac, /ws, /grpc, /tlgrm, @php).
$guarded = Bot::nginxPhpMultipartGuard(Bot::xrayNginxRoutes($out, ['inbounds' => [['port' => 443, 'streamSettings' => ['network' => 'ws', 'security' => 'none']]]]));
$flat = static fn(string $v): string => preg_replace('~\s+~', ' ', $v);
check(str_contains($guarded, $block) && substr_count($flat($guarded), $flat($guard)) === 2, 'xrayNginxRoutes и multipart guard не меняют блоки');
// Регулярка вложенной локации принимает пути Bot API и только их.
preg_match('#location ~ "(.+?)" \{#', $block, $lm);
$re = '~' . str_replace('~', '\~', $lm[1]) . '~';
foreach (["/$prefix/bot123456789:" . SECRET . '/getMe', "/$prefix/bot987654321:" . SECRET . '/sendMessage', "/$prefix/file/bot123456789:" . SECRET . '/documents/file_12.json'] as $path) check(preg_match($re, $path) === 1, "пропуск $path");
foreach (["/$prefix/bot111111111:" . SECRET . '/getMe', "/$prefix/bot123456789:short/getMe", "/$prefix/bot123456789:" . SECRET . '/', "/$prefix/bot123456789:" . SECRET . '/get-Me',
    "/$prefix/admin", "/$prefix/bot123456789:" . SECRET . '/getMe/x', "/{$prefix}x/bot123456789:" . SECRET . '/getMe', "/$prefix/file/bot123456789:" . SECRET . '/'] as $path) check(preg_match($re, $path) === 0, "отказ $path");

// ── включение, отказ nginx, откат ───────────────────────────────────────
mkdir("$root/config");
$bot->xrayConf = "$root/config/xray.json";
$bot->telegramApiFile = "$root/config/telegram_api";
file_put_contents("$root/config/nginx.conf", $domainText);
check($bot->telegramRelayStatus()['state'] === 'off', 'выключен по умолчанию');
[$okOn, $msg] = $bot->telegramRelayChange('on');
check(!$okOn && str_contains($msg, 'ID бота'), 'без ботов не включается');
[$okAdd] = $bot->telegramRelayChange('bot-add', '12345');
check($okAdd && $bot->telegramRelayConf()['bots'] === ['12345'], 'бот добавлен');
check(!$bot->telegramRelayChange('bot-add', '123:abc')[0] && !$bot->telegramRelayChange('bot-add', '0012345')[0], 'неверный ID');
check($bot->telegramRelayChange('bot-add', '12345')[0] && count($bot->telegramRelayConf()['bots']) === 1, 'повтор не дублирует');
check(file_get_contents("$root/config/nginx.conf") === $domainText, 'пока выключен, nginx не меняется');
$bot->ssh = [];
[$okOn, $msg] = $bot->telegramRelayChange('on');
$conf = $bot->telegramRelayConf();
check($okOn && $conf['enabled'] && preg_match('~^[0-9a-f]{32}$~', $conf['prefix']) === 1, 'включён, префикс случайный');
check($bot->telegramRelayStatus()['state'] === 'on' && str_contains(file_get_contents("$root/config/nginx.conf"), "location ^~ /{$conf['prefix']}/ {"), 'блок применён');
$staged = '';
foreach ($bot->ssh as [$service, $cmd]) if (preg_match("~printf %s '([A-Za-z0-9+/=]+)' \\| base64 -d~", $cmd, $sm)) $staged .= $sm[1];
check($staged !== '' && base64_decode($staged) === file_get_contents("$root/config/nginx.conf"), 'nginx -t проверял именно записанный текст');
check(count(array_filter($bot->ssh, static fn($c) => $c[0] !== 'ng')) === 0, 'команды только в контейнер ng');
$prefixOn = $conf['prefix'];
$beforeFail = file_get_contents("$root/config/nginx.conf");
$bot->nginxValid = false;
[$okIp, $msg] = $bot->telegramRelayChange('ip-add', '203.0.113.5');
check(!$okIp && $bot->telegramRelayConf()['ips'] === [] && file_get_contents("$root/config/nginx.conf") === $beforeFail, 'nginx -t отказал — настройка и файл прежние');
$bot->nginxValid = true;
$bot->nginxReload = false;
[$okIp] = $bot->telegramRelayChange('ip-add', '203.0.113.5');
check(!$okIp && $bot->telegramRelayConf()['ips'] === [] && file_get_contents("$root/config/nginx.conf") === $beforeFail, 'reload отказал — файл откатан');
$bot->nginxReload = true;
check($bot->telegramRelayChange('ip-add', '203.0.113.0/24')[0] && $bot->telegramRelayConf()['ips'] === ['203.0.113.0/24'], 'адрес добавлен');
check(!$bot->telegramRelayChange('ip-add', '1.2.3.4; allow all')[0], 'адрес с директивой отвергнут');
check($bot->telegramRelayChange('rotate')[0] && $bot->telegramRelayConf()['prefix'] !== $prefixOn && !str_contains(file_get_contents("$root/config/nginx.conf"), $prefixOn), 'новый адрес, старый удалён из nginx');
check($bot->telegramRelayChange('ip-del', '203.0.113.7/24')[0] && $bot->telegramRelayConf()['ips'] === [], 'удаление по той же сети');
check($bot->telegramRelayChange('bot-del', '12345')[0] && !$bot->telegramRelayConf()['enabled'] && !str_contains(file_get_contents("$root/config/nginx.conf"), Bot::TG_RELAY_BEGIN), 'последний бот удалён — выключен и убран из nginx');
file_put_contents("$root/config/nginx.conf", $template);
$bot->telegramRelayChange('bot-add', '12345');
[$okOn, $msg] = $bot->telegramRelayChange('on');
check(!$okOn && str_contains($msg, 'Let\'s Encrypt'), 'без домена с LE не включается');
$bot->conf['tg_relay'] = ['enabled' => true, 'prefix' => $prefix, 'bots' => ['12345'], 'ips' => []];
check($bot->telegramRelayStatus()['state'] === 'nodomain', 'включён в настройке, но домена нет');
file_put_contents("$root/config/nginx.conf", $domainText);
check($bot->telegramRelayStatus()['state'] === 'pending', 'включён, но не применён');
[$okOn] = $bot->telegramRelayChange('on');
check($okOn && $bot->telegramRelayStatus()['state'] === 'on', '«включить» повторно ставит блок, которого нет в nginx');
check($bot->telegramRelayChange('on') === [true, 'без изменений'], 'уже применён — без изменений');

// ── меню ────────────────────────────────────────────────────────────────
$route = '~^/tgapi(?: (client|relay)(?: (set|check|reset|worker|on|off|bot|delbot|ip|delip|rotate)(?: ([0-9]{5,15}|[a-f0-9]{8}|yes))?)?)?$~D';
check(str_contains(file_get_contents(__DIR__ . '/../app/bot.php'), "preg_match('" . $route . "'"), 'маршрут в action() совпадает с тестом');
$allButtons = static function (array $rows): array { $out = []; foreach ($rows as $row) foreach ($row as $b) $out[] = $b['callback_data']; return $out; };
foreach (['ru', 'en'] as $lang) {
    $menuBot = new RelayBot($lang);
    $menuBot->xrayConf = "$root/config/xray.json";
    $menuBot->telegramApiFile = "$root/config/telegram_api";
    $menuBot->conf = ['domain' => 'relay.example.com', 'tg_relay' => ['enabled' => true, 'prefix' => $prefix, 'bots' => ['12345'], 'ips' => ['203.0.113.5']]];
    file_put_contents("$root/config/nginx.conf", Bot::telegramRelayNginx($domainText, $menuBot->conf['tg_relay']));
    foreach ([['', '', ''], ['client', '', ''], ['relay', '', ''], ['relay', 'rotate', '']] as [$section, $action, $arg]) {
        $menuBot->telegramApiMenu($section, $action, $arg);
        [$text, $buttons] = $menuBot->last();
        check(!str_contains($text, SECRET) && !str_contains(json_encode($buttons), SECRET), "$lang $section/$action: токена нет");
        check($lang === 'ru' ? preg_match('~[а-я]~u', $text) === 1 : preg_match('~[а-яё]~iu', $text . json_encode($buttons, JSON_UNESCAPED_UNICODE)) === 0, "$lang $section/$action: язык");
        foreach ($allButtons($buttons) as $cb) {
            check(strlen($cb) <= 64 && (preg_match($route, $cb) === 1 || in_array($cb, ['/menu config'], true) || str_starts_with($cb, '/menuhelp tgapi ')), "$lang кнопка $cb");
        }
    }
    $menuBot->telegramApiMenu('relay');
    [$text, $buttons] = $menuBot->last();
    check(str_contains($text, "https://relay.example.com/$prefix"), "$lang адрес ретранслятора показан, когда он работает");
    check(in_array('/tgapi relay delip ' . substr(hash('sha256', '203.0.113.5'), 0, 8), $allButtons($buttons), true) && in_array('/tgapi relay delbot 12345', $allButtons($buttons), true), "$lang кнопки удаления");
    $menuBot->telegramApiMenu('client');
    [$text] = $menuBot->last();
    check(str_contains($text, '<code>1234567890</code>'), "$lang ID этого бота показан");
    $menuBot->telegramApiMenu();
    [$text] = $menuBot->last();
    check(!str_contains($text, $prefix), "$lang главный экран без префикса");
    $help = $menuBot->menuHelpContent('tgapi');
    check($help && $help[1] === '/tgapi' && count($help[2]) === 6, "$lang справка");
    foreach ($help[2] as $title => $page) check(!str_contains($page, SECRET) && ($lang === 'ru' || preg_match('~[а-яё]~iu', $title . $page) === 0), "$lang справка $title");
}
$menuBot->conf['tg_relay']['enabled'] = false;
$menuBot->telegramApiMenu('relay');
check(!str_contains($menuBot->last()[0], $prefix), 'выключенный ретранслятор не показывает адрес');

// ── ввод ────────────────────────────────────────────────────────────────
$menuBot = new RelayBot();
$menuBot->xrayConf = "$root/config/xray.json";
$menuBot->telegramApiFile = "$root/config/telegram_api";
file_put_contents("$root/config/nginx.conf", $domainText);
$menuBot->telegramApiMenu('relay', 'bot');
check(($menuBot->stashed[0]['callback'] ?? '') === 'telegramApiReply' && $menuBot->stashed[0]['args'] === ['bot'], 'запрос ввода ID');
$menuBot->telegramApiReply('5555555:' . SECRET, 'bot');
check($menuBot->telegramRelayConf()['bots'] === ['5555555'] && !str_contains(json_encode($menuBot->conf), SECRET) && !str_contains(json_encode($menuBot->updated, JSON_UNESCAPED_UNICODE), SECRET), 'из вставленного токена взят только ID');
check(str_contains($menuBot->last()[0], '@BotFather'), 'совет заменить токен');
$menuBot->telegramApiReply('not-an-ip', 'ip');
check(str_starts_with($menuBot->last()[0], 'Menu') && str_contains($menuBot->last()[0], '❌'), 'неверный адрес');

// ── адрес Bot API этого бота ────────────────────────────────────────────
$client = new RelayBot();
$client->telegramApiFile = "$root/client_api";
$client->telegramApiUse(TelegramApi::current($client->telegramApiFile, '')['url']);
check($client->api === 'https://api.telegram.org/bot' . KEY . '/' && $client->file === 'https://api.telegram.org/file/bot' . KEY . '/', 'адреса по умолчанию');
[$okSet, $msg] = $client->telegramApiSetUrl('https://user@relay.example.com/x');
check(!$okSet && $client->probes === [], 'неверный адрес не проверяется и не сохраняется');
$client->probeResult = ['ok' => false, 'reason' => 'network'];
[$okSet, $msg] = $client->telegramApiSetUrl('relay.example.com/' . $prefix);
check(!$okSet && !file_exists("$root/client_api") && $client->probes === ["https://relay.example.com/$prefix"], 'неудачная проверка — не сохранено');
check(!str_contains($msg, $prefix), 'сообщение без префикса');
$client->probeResult = ['ok' => true, 'reason' => 'ok'];
[$okSet, $msg] = $client->telegramApiSetUrl('relay.example.com/' . $prefix . '/');
check($okSet && TelegramApi::readFile("$root/client_api") === "https://relay.example.com/$prefix" && !str_contains($msg, $prefix), 'сохранено, в сообщении путь скрыт');
check($client->api === "https://relay.example.com/$prefix/bot" . KEY . '/' && $client->file === "https://relay.example.com/$prefix/file/bot" . KEY . '/', 'бот сразу ходит через ретранслятор');
// Другой процесс (CLI, cron) меняет настройку — request() подхватывает её.
$other = new RelayBot();
$other->telegramApiFile = "$root/client_api";
$other->telegramApiUse(TelegramApi::current($other->telegramApiFile, '')['url']);
TelegramApi::save("$root/client_api", 'https://relay2.example.com/p');
$other->telegramApiRefresh();
check($other->api === 'https://relay2.example.com/p/bot' . KEY . '/', 'изменение файла подхвачено');
$client->probeResult = ['ok' => false, 'reason' => 'network'];
[$okReset] = $client->telegramApiResetUrl();
check(!$okReset && file_exists("$root/client_api"), 'сброс без связи отменён');
[$okReset] = $client->telegramApiResetUrl(true);
check($okReset && !file_exists("$root/client_api") && str_starts_with($client->api, 'https://api.telegram.org/bot'), 'сброс --force');
$noStamp = new RelayBot();
$noStamp->api = 'file:///tmp/x/';
$noStamp->telegramApiRefresh();
check($noStamp->api === 'file:///tmp/x/', 'без телеграм-адреса из конструктора refresh ничего не меняет');
check(str_contains($client->telegramApiProbeText(['reason' => 'http', 'http' => 404]), 'ID этого бота'), 'подсказка про разрешённый ID');

// ── CLI ─────────────────────────────────────────────────────────────────
$cli = new RelayBot('en');
$cli->xrayConf = "$root/config/xray.json";
$cli->telegramApiFile = "$root/client_api";
$cli->conf = ['domain' => 'relay.example.com', 'tg_relay' => ['enabled' => true, 'prefix' => $prefix, 'bots' => ['12345'], 'ips' => []]];
file_put_contents("$root/config/nginx.conf", Bot::telegramRelayNginx($domainText, $cli->conf['tg_relay']));
$run = static function (array $args) use ($cli): array { $h = fopen('php://memory', 'w+'); $code = $cli->telegramApiCli($args, $h); rewind($h); return [$code, stream_get_contents($h)]; };
[$code, $outText] = $run(['help']);
check($code === 0 && str_contains($outText, 'relay-bot-add') && str_contains($outText, 'api-set'), 'help');
[$code, $outText] = $run(['status']);
check($code === 0 && str_contains($outText, 'relay: active') && !str_contains($outText, $prefix) && !str_contains($outText, SECRET), 'status скрывает префикс и токен');
[$code, $outText] = $run(['relay-url']);
check($code === 0 && trim($outText) === "https://relay.example.com/$prefix", 'relay-url печатает полный адрес');
check($run(['bogus'])[0] === 2 && $run(['relay-bot-add'])[0] === 2 && $run(['api-set'])[0] === 2, 'неверные команды — код 2');
[$code, $outText] = $run(['relay-off']);
check($code === 0 && !$cli->telegramRelayConf()['enabled'] && $run(['relay-url'])[0] === 1, 'relay-off');
[$code] = $run(['relay-bot-add', '7777777']);
check($code === 0 && in_array('7777777', $cli->telegramRelayConf()['bots'], true), 'relay-bot-add');

// ── Cloudflare Worker ───────────────────────────────────────────────────
$script = Bot::telegramWorkerScript(str_repeat('ab', 16), '1234567890');
check(!str_contains($script, '__PREFIX__') && !str_contains($script, '__BOT__') && substr_count($script, str_repeat('ab', 16)) === 5, 'скрипт: префикс подставлен');
check(str_contains($script, "const BOT = '1234567890';") && str_contains($script, "'https://api.telegram.org' + path"), 'скрипт: ID бота и адрес Telegram');
check(!str_contains($script, SECRET) && !preg_match('~[а-яё]~iu', preg_replace('~^//.*$~m', '', $script)), 'скрипт: без токена, кириллица только в комментариях');
foreach ([['short', '1234567890'], [str_repeat('AB', 16), '1234567890'], [str_repeat('ab', 16), "1'; x"], [str_repeat('ab', 16), '12']] as [$p, $b]) {
    try { Bot::telegramWorkerScript($p, $b); check(false, "скрипт отвергает $p/$b"); } catch (InvalidArgumentException $e) { check(true, 'отказ'); }
}
check(TelegramApi::normalize('https://vpnbot-relay.example.workers.dev/' . str_repeat('ab', 16)) === 'https://vpnbot-relay.example.workers.dev/' . str_repeat('ab', 16), 'адрес Worker с префиксом принимается');
foreach (['ru', 'en'] as $lang) {
    $wb = new RelayBot($lang);
    $wb->telegramApiFile = "$root/worker_api";
    $wb->telegramApiMenu('client', 'worker');
    [$file, $caption] = $wb->files[0];
    check($file instanceof CURLStringFile && $file->postname === 'vpnbot-telegram-worker.js', "$lang worker: файл");
    check(preg_match("~const PREFIX = '/([a-f0-9]{32})';~", $file->data, $pm) === 1 && str_contains($caption, $pm[1]) && str_contains($file->data, "const BOT = '1234567890';"), "$lang worker: префикс в файле и подписи");
    check(mb_strlen(strip_tags($caption)) <= 1024 && !str_contains($caption . $file->data, SECRET), "$lang worker: подпись в пределах Telegram, без токена");
    check($lang === 'ru' || preg_match('~[а-яё]~iu', $caption) === 0, "$lang worker: язык подписи");
    check(str_contains($wb->last()[0], '✅') && !file_exists("$root/worker_api"), "$lang worker: адрес бота не меняется");
    $wb->fileOk = false;
    $wb->telegramApiMenu('client', 'worker');
    check(str_contains($wb->last()[0], '❌'), "$lang worker: отказ отправки виден");
    $wb->telegramApiMenu('client');
    check(in_array('/tgapi client worker', $allButtons($wb->last()[1]), true), "$lang worker: кнопка");
}
$wb->telegramApiMenu('client', 'worker');
check(!str_contains($wb->files[1][0]->data, $pm[1]), 'каждая кнопка — новый префикс');
[$code, $outText] = $run(['cf-worker']);
check($code === 0 && str_starts_with($outText, '// VPNBot') && str_contains($outText, "const BOT = '1234567890';") && preg_match("~const PREFIX = '/[a-f0-9]{32}';~", $outText) === 1, 'CLI cf-worker');
check(str_contains($run(['help'])[1], 'cf-worker'), 'help: cf-worker');

// ── CLI-файл не исполняется через веб ───────────────────────────────────
check(str_starts_with(trim(substr(file_get_contents(__DIR__ . '/../app/tgapi.php'), 5)), '//') && str_contains(file_get_contents(__DIR__ . '/../app/tgapi.php'), "PHP_SAPI !== 'cli'"), 'tgapi.php только для CLI');

echo "telegram_api_test: $checks checks OK\n";
