<?php
// XDRIVE: настройки, вход в xray.json, профиль клиента, проверка хранилища, меню.
require_once __DIR__ . '/../app/bot.php';
set_error_handler(static function ($level, $message, $file, $line) { if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line); return true; });

function xdKey(int $bytes): string { return rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '='); }
function xdVlessenc(): string
{
    return "Authentication: X25519, not Post-Quantum\n\"decryption\": \"mlkem768x25519plus.native.600s." . xdKey(32) . "\"\n\"encryption\": \"mlkem768x25519plus.native.0rtt." . xdKey(32) . "\"\n\n"
        . "Authentication: ML-KEM-768, Post-Quantum\n\"decryption\": \"mlkem768x25519plus.native.600s." . xdKey(64) . "\"\n\"encryption\": \"mlkem768x25519plus.native.0rtt." . xdKey(1184) . "\"\n";
}

// Хранилище WebDAV в памяти: те же четыре действия, что выполняет ядро.
class XdStorage
{
    public array $files = [];
    public array $deny = [];
    public string $prefix = 'd';
    public string $login = 'disk-user';
    public string $password = 'app-pass-9';
    public bool $folder = true;
    public array $log = [];
    public function handle(string $method, string $url, array $headers, ?string $body): array
    {
        $this->log[] = "$method $url";
        if (!in_array('Authorization: Basic ' . base64_encode("$this->login:$this->password"), $headers, true)) return [401, ''];
        if (in_array($method, $this->deny, true)) return [403, ''];
        $path = (string) parse_url($url, PHP_URL_PATH);
        if (!$this->folder) return [404, ''];
        if ($method === 'PROPFIND') {
            $items = "<$this->prefix:response><$this->prefix:href>$path</$this->prefix:href></$this->prefix:response>";
            foreach (array_keys($this->files) as $name) $items .= "<$this->prefix:response><$this->prefix:href>$path" . rawurlencode($name) . "</$this->prefix:href></$this->prefix:response>";
            return [207, "<?xml version=\"1.0\"?><$this->prefix:multistatus>$items</$this->prefix:multistatus>"];
        }
        $name = rawurldecode(basename($path));
        if ($method === 'PUT') { $this->files[$name] = (string) $body; return [201, '']; }
        if ($method === 'GET') return isset($this->files[$name]) ? [200, $this->files[$name]] : [404, ''];
        if ($method === 'DELETE') { unset($this->files[$name]); return [204, '']; }
        return [405, ''];
    }
}

class XdBot extends Bot
{
    public array $confPac = ['transport' => 'Reality', 'xray_core' => 'origin'];
    public array $confXray = [];
    public array $inventory = ['origin' => '26.9.30', 'origin2' => '26.9.9', 'origin3' => '26.7.28', 'fork' => '26.10.6-2241'];
    public array $resolved = ['webdav.example-disk.net' => ['93.184.216.34'], 'inner.example-disk.net' => ['10.10.0.7'], 'mixed.example-disk.net' => ['93.184.216.34', '192.168.1.5']];
    public bool $valid = true; public bool $restartOk = true; public bool $sshOk = true;
    public int $restarts = 0; public int $keygens = 0; public int $validations = 0;
    public array $messages = []; public array $buttons = []; public array $files = []; public array $answers = []; public array $prompt = [];
    public ?XdStorage $storage = null; public array $google = [];
    public function __construct()
    {
        $this->input = ['chat' => 1, 'from' => 1, 'message_id' => 5, 'callback_id' => 'cb', 'username' => 'admin'];
        $this->language = 'ru';
        require __DIR__ . '/../app/i18n.php';
        $this->i18n = $i;
        $this->confXray = ['inbounds' => [
            ['tag' => 'vless_tls', 'port' => 443, 'protocol' => 'vless', 'sniffing' => ['enabled' => true, 'destOverride' => ['http', 'tls']],
                'settings' => ['decryption' => 'none', 'clients' => [
                    ['id' => '11111111-1111-4111-8111-111111111111', 'email' => 'alice', 'flow' => 'xtls-rprx-vision', 'level' => 0],
                    ['id' => '22222222-2222-4222-8222-222222222222', 'email' => 'bob/..\\x', 'flow' => 'xtls-rprx-vision'],
                ]]],
            ['tag' => 'api', 'listen' => '127.0.0.1', 'port' => 8080, 'protocol' => 'dokodemo-door', 'settings' => ['address' => '127.0.0.1']],
        ], 'outbounds' => [['tag' => 'direct', 'protocol' => 'freedom']], 'routing' => ['rules' => []]];
    }
    public function getPacConf() { return $this->confPac; }
    public function setPacConf(array $conf) { $this->confPac = $conf; return true; }
    public function getXray() { return $this->confXray; }
    public function restartXray($c, $norestart = false)
    {
        $this->restarts++;
        if (!$this->restartOk) return false;
        // Как настоящий restartXray(): вход пересобирается по сохранённым настройкам.
        $this->ensureXdriveInbound($c, $this->confPac);
        $this->confXray = $c;
        return true;
    }
    public function validateXrayConfig(array $config, string $binary = 'xray'): bool { $this->validations++; return $this->valid; }
    public function xrayCoreInventory(): array { return $this->inventory; }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
    {
        $this->sshFailed = !$this->sshOk;
        if ($cmd !== 'xray vlessenc' || $service !== 'xr') throw new RuntimeException('неожиданная команда: ' . $cmd);
        $this->keygens++;
        return $this->sshOk ? xdVlessenc() : '';
    }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
    protected function xdriveResolve(string $host): array { return $this->resolved[$host] ?? []; }
    protected function xdriveHttp(string $method, string $url, array $headers = [], ?string $body = null): array
    {
        if (str_contains($url, 'googleapis.com')) { $this->google[] = [$method, $url, $body]; return array_shift($this->googleAnswers) ?? [0, '']; }
        return $this->storage ? $this->storage->handle($method, $url, $headers, $body) : [0, ''];
    }
    public array $googleAnswers = [];
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML') { $this->messages[] = $text; $this->buttons = is_array($button) ? $button : []; }
    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false) { $this->messages[] = $text; return ['result' => ['message_id' => 9]]; }
    public function answer($callback_id, $textNotify = false, $notify = false) { $this->answers[] = $textNotify; }
    public function sendFile($chat, $id_url_cFile, $caption = false, $to = false) { $this->files[] = [$id_url_cFile, $caption]; return ['ok' => true]; }
    public function stashReply($r, array $state) { $this->prompt = $state; }
    public function callbacks(): array { $all = []; foreach ($this->buttons as $row) foreach ($row as $button) $all[$button['callback_data']] = $button['text']; return $all; }
}

$failures = [];
$check = static function (bool $ok, string $name) use (&$failures): void { if (!$ok) $failures[] = $name; };
$webdav = ['service' => 'webdav', 'url' => 'https://webdav.example-disk.net', 'folder' => 'vpnbot-xdrive', 'secrets' => ['disk-user', 'app-pass-9']];
$tag = static fn(array $c) => array_values(array_filter($c['inbounds'], static fn($i) => ($i['tag'] ?? '') === 'xdrive'));

// --- Настройки и их проверка ---------------------------------------------
$bot = new XdBot();
$s = $bot->xdriveSettings();
$check($s['enabled'] === 0 && $s['service'] === 'webdav' && $s['poll'] === 500 && $s['secrets'] === [], 'настройки по умолчанию: выключено');
$check($bot->xdriveSettings(['xdrive' => ['service' => 'dropbox', 'poll' => 5, 'secrets' => 'x', 'enc' => 'y', 'url' => []]]) == ['enabled' => 0, 'service' => 'webdav', 'url' => '', 'folder' => '',
    'secrets' => [], 'template' => '', 'poll' => 500, 'enc' => []], 'испорченные настройки приводятся к безопасным');
$check($bot->xdriveSettings(['xdrive' => ['poll' => 999999]])['poll'] === 10000, 'интервал опроса ограничен сверху');
foreach (['https://webdav.yandex.ru' => 'https://webdav.yandex.ru', 'https://cloud.example.com/remote.php/dav/files/user/' => 'https://cloud.example.com/remote.php/dav/files/user',
    ' http://dav.example.com:8080 ' => 'http://dav.example.com:8080'] as $input => $expected) {
    $check(Bot::xdriveWebdavUrl($input) === $expected, "адрес принят: $input");
}
foreach (['', 'webdav.yandex.ru', 'ftp://dav.example.com', 'https://user:pass@dav.example.com', 'https://dav.example.com/?a=1', 'https://dav.example.com/#x',
    'https://dav.example.com/{folder}', 'https://dav.example.com/a b', 'https://', "https://dav.example.com/\"x", 'https://dav.example.com/' . str_repeat('a', 300)] as $input) {
    $check(Bot::xdriveWebdavUrl($input) === null, 'адрес отклонён: ' . substr($input, 0, 40));
}
foreach (['vpnbot-xdrive' => true, 'a' => true, 'x.y_z-1' => true, '' => false, '.hidden' => false, 'a/b' => false, 'папка' => false, 'a b' => false, '{folder}' => false, '../x' => false, "x\n" => false] as $folder => $ok) {
    $check(Bot::xdriveFolderOk((string) $folder) === $ok, 'имя папки: ' . json_encode((string) $folder));
}
foreach (['https://webdav.example-disk.net' => true, 'https://93.184.216.34' => true, 'https://inner.example-disk.net' => false, 'https://mixed.example-disk.net' => false,
    'https://10.10.0.5' => false, 'https://127.0.0.1' => false, 'https://192.168.1.1' => false, 'https://169.254.169.254' => false, 'https://[::1]' => false,
    'https://172.16.0.1' => false, 'https://100.64.0.1' => false, 'https://100.127.255.254' => false, 'https://100.128.0.0' => true,
    'https://unknown.example-disk.net' => false] as $url => $public) {
    $check($bot->xdriveHostPublic($url) === $public, 'внешнее ли хранилище: ' . $url);
}
$full = $bot->xdriveSettings(['xdrive' => $webdav]);
$check($bot->xdriveProblems($full) === [], 'полные настройки WebDAV без замечаний');
$check($bot->xdriveProblems($bot->xdriveSettings()) === ['xdrive need url', 'xdrive need folder', 'xdrive need login'], 'пустые настройки WebDAV: все три замечания');
$check($bot->xdriveProblems(['url' => 'https://inner.example-disk.net'] + $full) === ['xdrive private url'], 'хранилище во внутренней сети отклоняется');
$check($bot->xdriveProblems(['secrets' => ['only-login']] + $full) === ['xdrive need login'] && $bot->xdriveProblems(['secrets' => ['a', '']] + $full) === ['xdrive need login'], 'логин без пароля недостаточен');
$google = $bot->xdriveSettings(['xdrive' => ['service' => 'gdrive', 'folder' => '1AbC_dEfGhIjKlMnOpQrStUvWxYz012', 'secrets' => ['id.apps.googleusercontent.com', 'GOCSPX-secret', '1//refresh-token']]]);
$check($bot->xdriveProblems($google) === [], 'полные настройки Google Drive без замечаний');
$check($bot->xdriveProblems(['folder' => 'моя папка', 'secrets' => ['a', 'b']] + $google) === ['xdrive need folder id', 'xdrive need google keys'], 'Google Drive: нужен ID папки и три ключа');
$template = ['auth' => ['type' => 'static', 'header' => ['X-Key' => '{secret0}']], 'put' => ['method' => 'PUT', 'url' => 'https://webdav.example-disk.net/api/{folder}/{name}'],
    'get' => ['method' => 'GET', 'url' => 'https://webdav.example-disk.net/api/{folder}/{name}'], 'delete' => ['method' => 'DELETE', 'url' => 'https://webdav.example-disk.net/api/{folder}/{name}'],
    'list' => ['method' => 'GET', 'url' => 'https://webdav.example-disk.net/api/{folder}?prefix={prefix}', 'namesRegex' => '"name":"([^"]+)"']];
$custom = $bot->xdriveSettings(['xdrive' => ['service' => 'template', 'folder' => 'bucket', 'secrets' => ['k1'], 'template' => json_encode($template)]]);
$check($bot->xdriveProblems($custom) === [], 'корректный свой шаблон без замечаний');
foreach (['не JSON' => '{', 'список вместо объекта' => '[1]', 'нет list' => json_encode(array_diff_key($template, ['list' => 1])),
    'нет namesRegex' => json_encode(['list' => ['method' => 'GET', 'url' => 'https://webdav.example-disk.net/x']] + $template),
    'не http' => json_encode(['put' => ['method' => 'PUT', 'url' => 'file:///etc/passwd']] + $template)] as $name => $value) {
    $check($bot->xdriveProblems(['template' => $value] + $custom) === ['xdrive need template'], "шаблон отклонён: $name");
}
$check($bot->xdriveProblems(['template' => json_encode(['get' => ['method' => 'GET', 'url' => 'https://10.10.0.9/{name}']] + $template)] + $custom) === ['xdrive private url'], 'шаблон с внутренним адресом отклонён');

// --- streamSettings ---------------------------------------------------------
$stream = Bot::xdriveStream($full);
$check($stream['method'] === 'xdrive' && $stream['xdriveSettings']['service'] === 'template' && $stream['xdriveSettings']['remoteFolder'] === 'vpnbot-xdrive'
    && $stream['xdriveSettings']['secrets'] === ['disk-user', 'app-pass-9'], 'WebDAV описывается шаблоном ядра');
$t = $stream['xdriveSettings']['template'];
$check($t['flatten'] === true && $t['auth'] === ['type' => 'basic', 'username' => '{secret0}', 'password' => '{secret1}']
    && $t['put'] === ['method' => 'PUT', 'url' => 'https://webdav.example-disk.net/{folder}/{name}'] && $t['list']['method'] === 'PROPFIND'
    && $t['list']['url'] === 'https://webdav.example-disk.net/{folder}/' && $t['list']['headers'] === ['Depth' => '1'], 'шаблон WebDAV: адреса и вход');
$check(!str_contains(json_encode($t), 'app-pass-9') && !str_contains(json_encode($t), 'disk-user'), 'в шаблоне только подстановки, не сами учётные данные');
foreach (['d', 'D', 'lp1'] as $prefix) {
    preg_match_all('~' . Bot::XDRIVE_WEBDAV_NAMES . '~', "<$prefix:href>/remote.php/dav/files/u/vpnbot-xdrive/</$prefix:href><$prefix:href>/remote.php/dav/files/u/vpnbot-xdrive/sessions~1-ab</$prefix:href>", $m);
    $check($m[1] === ['sessions~1-ab'], "имена из PROPFIND с префиксом $prefix: папка сама не попадает");
}
preg_match_all('~' . Bot::XDRIVE_WEBDAV_NAMES . '~', '<href>/dav/x/streams~ab~c2s~000000001</href>', $m);
$check($m[1] === ['streams~ab~c2s~000000001'], 'имена из PROPFIND без префикса пространства имён');
$check(!isset($stream['xdriveSettings']['maxPollIntervalMs']) && Bot::xdriveStream(['poll' => 3000] + $full)['xdriveSettings']['maxPollIntervalMs'] === 3000, 'интервал опроса пишется только если изменён');
$check(Bot::xdriveStream($google)['xdriveSettings'] === ['remoteFolder' => '1AbC_dEfGhIjKlMnOpQrStUvWxYz012', 'service' => 'Google Drive',
    'secrets' => ['id.apps.googleusercontent.com', 'GOCSPX-secret', '1//refresh-token']], 'Google Drive: папка и три ключа по порядку');
$check(Bot::xdriveStream($custom)['xdriveSettings']['template'] === $template, 'свой шаблон передаётся ядру объектом');

// --- Включение ---------------------------------------------------------------
$bot = new XdBot();
$check($bot->applyXdrive(['enabled' => 1] + $webdav) === '', 'включение с полными настройками проходит');
$in = $tag($bot->confXray);
$check(count($in) === 1 && $bot->keygens === 1 && $bot->validations === 1 && $bot->restarts === 1, 'ключи созданы один раз, конфиг проверен ядром, Xray перезапущен');
$check($bot->xdriveActive() && $bot->xdriveCoreReady() && !isset($bot->confPac['xdrive']['cores']), 'вход работает; сведения о ядре в настройках не хранятся');
$pair = VlessEncryption::pair($bot->confPac['xdrive']['enc']);
$check($pair !== null && $bot->confPac['xdrive']['enc']['auth'] === 'mlkem768', 'ключи шифрования — ML-KEM-768');
$check($in[0]['protocol'] === 'vless' && $in[0]['settings']['decryption'] === $pair['decryption'] && $in[0]['settings']['decryption'] !== 'none', 'вход XDRIVE всегда с шифрованием VLESS');
$check($in[0]['settings']['clients'] === [['id' => '11111111-1111-4111-8111-111111111111', 'email' => 'alice', 'level' => 0],
    ['id' => '22222222-2222-4222-8222-222222222222', 'email' => 'bob/..\\x']], 'пользователи те же, flow не переносится');
$check($in[0]['streamSettings'] === Bot::xdriveStream($bot->xdriveSettings()) && $in[0]['sniffing'] === $bot->confXray['inbounds'][0]['sniffing'], 'транспорт и sniffing как у основного входа');
$check($bot->confXray['inbounds'][0]['tag'] === 'vless_tls' && $bot->confXray['inbounds'][0]['settings']['decryption'] === 'none', 'основной вход не тронут');
// Повторная сборка и новые пользователи.
$c = $bot->confXray;
$c['inbounds'][0]['settings']['clients'][] = ['id' => '33333333-3333-4333-8333-333333333333', 'email' => 'carol'];
unset($c['inbounds'][0]['settings']['clients'][0]);
$bot->ensureXdriveInbound($c);
$bot->ensureXdriveInbound($c);
$check(count($tag($c)) === 1 && array_column($tag($c)[0]['settings']['clients'], 'email') === ['bob/..\\x', 'carol'], 'вход пересобирается без дублей и повторяет список пользователей');
$check($bot->keygens === 1 && $bot->applyXdrive(['poll' => 2000] + $bot->confPac['xdrive']) === '' && $bot->keygens === 1
    && VlessEncryption::pair($bot->confPac['xdrive']['enc']) === $pair, 'изменение настроек ключи не меняет');
$check($tag($bot->confXray)[0]['streamSettings']['xdriveSettings']['maxPollIntervalMs'] === 2000, 'новый интервал опроса дошёл до конфига');
$check($bot->applyXdrive($bot->confPac['xdrive'], true) === '' && $bot->keygens === 2 && VlessEncryption::pair($bot->confPac['xdrive']['enc']) != $pair, '«Новые ключи» меняют ключи');
// Ядро без транспорта и не-VLESS вход: вход не отдаётся, остальное работает.
foreach (['origin2', 'origin3'] as $core) {
    $c = $bot->confXray;
    $bot->ensureXdriveInbound($c, ['xray_core' => $core] + $bot->confPac);
    $check($tag($c) === [] && count($c['inbounds']) === 2, "ядро $core без XDRIVE: вход убран, чтобы Xray запустился");
}
$c = $bot->confXray;
$bot->ensureXdriveInbound($c, ['xray_core' => 'fork'] + $bot->confPac);
$check(count($tag($c)) === 1, 'форк 26.10.6 знает XDRIVE');
$c = $bot->confXray; $c['inbounds'][0]['protocol'] = 'trojan';
$bot->ensureXdriveInbound($c);
$check($tag($c) === [], 'основной вход не VLESS: вход XDRIVE не создаётся');
$c = $bot->confXray; $c['inbounds'][0]['settings']['clients'] = [];
$bot->ensureXdriveInbound($c);
$check($tag($c) === [], 'без пользователей вход не создаётся');
$c = $bot->confXray;
$bot->ensureXdriveInbound($c, ['xdrive' => ['enc' => ['auth' => 'mlkem768', 'decryption' => 'x', 'encryption' => 'y']] + $bot->confPac['xdrive']] + $bot->confPac);
$check($tag($c) === [], 'испорченные ключи: вход не создаётся, шифрование не снимается');
// Выключение.
$check($bot->applyXdrive(['enabled' => 0] + $bot->confPac['xdrive']) === '' && $tag($bot->confXray) === [] && !$bot->xdriveActive(), 'выключение убирает вход');
$check(VlessEncryption::pair($bot->confPac['xdrive']['enc']) !== null, 'ключи при выключении сохраняются: прежние профили заработают после включения');

// --- Отказы при включении ------------------------------------------------
$refusals = [
    'xdrive need folder' => static function (XdBot $b, array &$s) { $s['folder'] = ''; },
    'xdrive private url' => static function (XdBot $b, array &$s) { $s['url'] = 'https://inner.example-disk.net'; },
    'xdrive unresolved' => static function (XdBot $b, array &$s) { $s['url'] = 'https://no-such-name.example-disk.net'; },
    'xdrive needs vless' => static function (XdBot $b, array &$s) { $b->confXray['inbounds'][0]['protocol'] = 'trojan'; },
    'xdrive core old' => static function (XdBot $b, array &$s) { $b->confPac['xray_core'] = 'origin2'; },
    'xdrive keys failed' => static function (XdBot $b, array &$s) { $b->sshOk = false; },
    'xdrive check failed' => static function (XdBot $b, array &$s) { $b->valid = false; },
    'xdrive save failed' => static function (XdBot $b, array &$s) { $b->restartOk = false; },
];
foreach ($refusals as $expected => $prepare) {
    $b = new XdBot();
    $settings = ['enabled' => 1] + $webdav;
    $prepare($b, $settings);
    $before = [$b->confPac, $b->confXray];
    $check($b->applyXdrive($settings) === $expected, "отказ: $expected");
    $check($b->confPac === $before[0] && $b->confXray === $before[1], "после отказа «{$expected}» настройки и конфиг прежние");
}
$b = new XdBot(); $b->inventory = [];
$check($b->applyXdrive(['enabled' => 1] + $webdav) === 'xdrive core old', 'контейнер xr не ответил о версиях: не включаем вслепую');
// Настройки пришли из резервной копии другого сервера, а здесь образ со старым ядром:
// вход не создаётся, и Xray запускается.
$b = new XdBot(); $b->inventory = ['origin' => '26.9.9', 'fork' => '26.9.5-0936'];
$b->confPac['xdrive'] = ['enabled' => 1] + $bot->confPac['xdrive'];
$c = $b->confXray;
$b->ensureXdriveInbound($c);
$check(!empty($b->confPac['xdrive']['enabled']) && $tag($c) === [] && !$b->xdriveActive(), 'включённый XDRIVE из копии на сервере со старым ядром не ломает Xray');
$b->xdriveMenu();
$check(str_contains(end($b->messages), 'включён, но не работает'), 'меню объясняет, что вход не работает');

// --- Гейты ядра распространяются на вход XDRIVE ------------------------------
$bot = new XdBot();
$bot->applyXdrive(['enabled' => 1] + $webdav);
$c = $bot->confXray;
$bot->ensureWgGuard($c);
$guarded = array_merge(...array_map(static fn($rule) => (array) ($rule['inboundTag'] ?? []), $c['routing']['rules']));
$check(in_array('xdrive', $guarded, true) && in_array('vless_tls', $guarded, true), 'запрет доступа во внутреннюю сеть действует и на вход XDRIVE');
$source = file_get_contents(__DIR__ . '/../app/bot.php');
$restart = substr($source, strpos($source, 'public function restartXray('), 6000);
$check(strpos($restart, '$this->ensureXdriveInbound($c, $pac);') !== false
    && strpos($restart, '$this->ensureXdriveInbound($c, $pac);') < strpos($restart, '$this->ensureTorrentBlock($c, $pac);')
    && strpos($restart, '$this->ensureXdriveInbound($c, $pac);') < strpos($restart, '$this->ensureWgGuard($c);')
    && strpos($restart, 'VlessEncryption::applyServer($c, $pac)') < strpos($restart, '$this->ensureXdriveInbound($c, $pac);'), 'вход собирается до гейтов и при каждом перезапуске Xray');

// --- Профиль клиента ---------------------------------------------------------
$alice = $bot->confXray['inbounds'][0]['settings']['clients'][0];
$profile = $bot->xdriveClientConfig($alice);
$out = $profile['outbounds'][0];
$check($out['protocol'] === 'vless' && $out['settings']['vnext'][0]['users'] === [['id' => $alice['id'], 'encryption' => VlessEncryption::pair($bot->confPac['xdrive']['enc'])['encryption']]], 'профиль: свой идентификатор и ключ шифрования');
$check($out['streamSettings'] === $tag($bot->confXray)[0]['streamSettings'], 'профиль и сервер смотрят в одну папку одним способом');
$check(array_column($profile['inbounds'], 'port') === [10808, 10809] && array_unique(array_column($profile['inbounds'], 'listen')) === ['127.0.0.1'], 'локальные SOCKS и HTTP только на своём компьютере');
$json = json_encode($profile);
$check(!str_contains($json, '22222222-2222') && !str_contains($json, $bot->confPac['xdrive']['enc']['decryption']), 'в профиле нет чужих идентификаторов и серверного ключа');
$check(!isset($out['settings']['vnext'][0]['users'][0]['flow']) && !isset($out['streamSettings']['security']), 'без flow и без TLS: их у транспорта нет');
$check($bot->xdriveClientConfig(['email' => 'no-id']) === null && $bot->xdriveClientConfig($alice, ['xdrive' => ['enabled' => 0] + $bot->confPac['xdrive']]) === null
    && $bot->xdriveClientConfig($alice, ['xdrive' => ['folder' => ''] + $bot->confPac['xdrive']]) === null, 'профиль не выдаётся без идентификатора, при выключенном или неполном XDRIVE');

// --- Проверка хранилища ----------------------------------------------------
$probe = static function (callable $prepare) use ($full): array {
    $b = new XdBot(); $b->storage = new XdStorage(); $b->storage->files = ['sessions~1-ab' => ''];
    $prepare($b->storage);
    return [$b->xdriveProbe($full), $b->storage];
};
[$result, $storage] = $probe(static function () {});
$check($result === '' && $storage->files === ['sessions~1-ab' => ''], 'рабочее хранилище: проверка проходит и убирает пробный файл, чужие не трогает');
$check(array_map(static fn($line) => strtok($line, ' '), $storage->log) === ['PROPFIND', 'PUT', 'GET', 'PROPFIND', 'DELETE'], 'проверка выполняет те же действия, что ядро');
$check(count(array_filter($storage->log, static fn($line) => !str_starts_with(substr($line, strpos($line, ' ') + 1), 'https://webdav.example-disk.net/vpnbot-xdrive/'))) === 0, 'проверка не выходит за пределы папки XDRIVE');
foreach ([
    'xdrive probe auth' => static function (XdStorage $s) { $s->password = 'other'; },
    'xdrive probe folder' => static function (XdStorage $s) { $s->folder = false; },
    'xdrive probe write' => static function (XdStorage $s) { $s->deny = ['PUT']; },
    'xdrive probe delete' => static function (XdStorage $s) { $s->deny = ['DELETE']; },
    'xdrive probe denied' => static function (XdStorage $s) { $s->deny = ['PROPFIND']; },
] as $expected => $prepare) {
    $check($probe($prepare)[0] === ($expected === 'xdrive probe denied' ? 'xdrive probe auth' : $expected), "проверка хранилища: $expected");
}
foreach (['D', 'lp1'] as $prefix) $check($probe(static function (XdStorage $s) use ($prefix) { $s->prefix = $prefix; })[0] === '', "список понимается с префиксом $prefix");
$b = new XdBot();
$check($b->xdriveProbe($full) === 'xdrive probe unreachable', 'хранилище не отвечает');
$check($b->xdriveProbe($b->xdriveSettings()) === 'xdrive probe incomplete' && $b->xdriveProbe($custom) === 'xdrive probe template', 'неполные настройки и свой шаблон не проверяются запросами');
$b = new XdBot(); $b->googleAnswers = [[200, '{"access_token":"ya29.token"}'], [200, '{"files":[]}']];
$check($b->xdriveProbe($google) === '' && $b->google[0][0] === 'POST' && str_contains($b->google[0][2], 'grant_type=refresh_token')
    && str_contains(urldecode($b->google[1][1]), "'1AbC_dEfGhIjKlMnOpQrStUvWxYz012' in parents and trashed = false"), 'Google Drive: вход по Refresh Token и доступ к папке');
foreach (['xdrive probe auth' => [[400, '{"error":"invalid_grant"}']], 'xdrive probe folder' => [[200, '{"access_token":"t"}'], [404, '']],
    'xdrive probe denied' => [[200, '{"access_token":"t"}'], [403, '']], 'xdrive probe unreachable' => []] as $expected => $answers) {
    $b = new XdBot(); $b->googleAnswers = $answers;
    $check($b->xdriveProbe($google) === $expected, "Google Drive: $expected");
}

// --- Меню ------------------------------------------------------------------
$bot = new XdBot();
$bot->xdriveMenu();
$text = end($bot->messages);
$check(str_contains($text, 'XDRIVE') && isset($bot->callbacks()['/xdriveToggle'], $bot->callbacks()['/xdriveSet url'], $bot->callbacks()['/xdriveProbe'], $bot->callbacks()['/menuhelp xdrive 0'], $bot->callbacks()['/xray']), 'меню: переключатель, поля, проверка, справка, назад');
$check(!isset($bot->callbacks()['/xdriveUsers 0']), 'профили недоступны, пока XDRIVE выключен');
$enter = static function (XdBot $b, string $field, string $value): void { $b->xdriveSet($field); $b->saveXdrive($value, $b->prompt['args'][0]); };
$enter($bot, 'url', 'https://webdav.example-disk.net/');
$enter($bot, 'folder', '/vpnbot-xdrive/');
$enter($bot, 'secret0', ' disk-user ');
$enter($bot, 'secret1', 'app-pass-9');
$check($bot->prompt['callback'] === 'saveXdrive' && $bot->confPac['xdrive']['url'] === 'https://webdav.example-disk.net' && $bot->confPac['xdrive']['folder'] === 'vpnbot-xdrive'
    && $bot->confPac['xdrive']['secrets'] === ['disk-user', 'app-pass-9'] && empty($bot->confPac['xdrive']['enabled']), 'поля заполняются по одному, вход при этом выключен');
$check($bot->restarts === 0 && $bot->validations === 0 && $tag($bot->confXray) === [], 'заполнение выключенных настроек Xray не перезапускает');
$bot->xdriveMenu();
$check(!str_contains(end($bot->messages) . json_encode($bot->buttons, JSON_UNESCAPED_UNICODE), 'app-pass-9') && !str_contains(json_encode($bot->buttons, JSON_UNESCAPED_UNICODE), 'disk-user'), 'логин и пароль хранилища в меню скрыты');
$enter($bot, 'url', 'не адрес');
$check($bot->confPac['xdrive']['url'] === '' && str_contains(end($bot->messages), 'Задайте адрес WebDAV'), 'неверный адрес не сохраняется, причина названа');
$enter($bot, 'url', 'https://webdav.example-disk.net');
$bot->storage = new XdStorage();
$bot->xdriveProbeMenu();
$check(str_contains(end($bot->messages), 'Хранилище работает'), 'кнопка проверки сообщает об успехе');
$bot->xdriveToggle();
$check(!empty($bot->confPac['xdrive']['enabled']) && count($tag($bot->confXray)) === 1 && str_contains(end($bot->messages), 'XDRIVE включён') && isset($bot->callbacks()['/xdriveUsers 0']), 'включение из меню');
$enter($bot, 'poll', '3000');
$check($tag($bot->confXray)[0]['streamSettings']['xdriveSettings']['maxPollIntervalMs'] === 3000 && !empty($bot->confPac['xdrive']['enabled']), 'изменение включённой настройки сразу применяется');
$enter($bot, 'folder', 'плохое имя');
$check(empty($bot->confPac['xdrive']['enabled']) && $tag($bot->confXray) === [], 'негодное значение выключает вход, а не ломает Xray');
$enter($bot, 'folder', 'vpnbot-xdrive');
$bot->xdriveToggle();
$keys = $bot->confPac['xdrive']['enc'];
$bot->xdriveRotate();
$check($bot->confPac['xdrive']['enc'] != $keys && str_contains(end($bot->messages), 'Старые профили больше не работают'), '«Новые ключи» из меню');
// Профили.
$bot->xdriveUsers(0);
$keyAlice = Bot::xdriveClientKey($bot->confXray['inbounds'][0]['settings']['clients'][0]);
$keyBob = Bot::xdriveClientKey($bot->confXray['inbounds'][0]['settings']['clients'][1]);
$check(($bot->callbacks()["/xdriveProfile $keyAlice"] ?? '') === 'alice' && isset($bot->callbacks()["/xdriveProfile $keyBob"], $bot->callbacks()['/xdrive'])
    && preg_match('~^[a-f0-9]{16}$~', $keyAlice) && $keyAlice !== $keyBob && !str_contains($keyAlice, '1111'), 'список пользователей: кнопка несёт отпечаток, а не идентификатор');
// Список изменился, пока меню открыто: кнопка по-прежнему ведёт к тому же пользователю.
array_unshift($bot->confXray['inbounds'][0]['settings']['clients'], ['id' => '44444444-4444-4444-8444-444444444444', 'email' => 'dave']);
$bot->xdriveProfile($keyBob);
[$file, $caption] = end($bot->files);
$sent = json_decode($file->data, true);
$check($file->postname === 'xdrive-bob_.._x.json' && $file->mime === 'application/json' && $sent['outbounds'][0]['settings']['vnext'][0]['users'][0]['id'] === '22222222-2222-4222-8222-222222222222'
    && !str_contains($file->data, '11111111-1111') && str_contains((string) $caption, 'Не пересылайте'), 'профиль отправляется файлом; имя файла безопасно; чужих данных нет');
$bot->xdriveProfile('0000000000000000');
$bot->xdriveProfile(Bot::xdriveClientKey(['id' => 'удалённый']));
$check(count($bot->files) === 1 && str_contains((string) end($bot->answers), 'недоступен'), 'несуществующий или удалённый пользователь: файла нет');
// Смена хранилища сбрасывает доступы и выключает вход, ключи шифрования остаются.
$keys = $bot->confPac['xdrive']['enc'];
$bot->xdriveService('gdrive');
$check($bot->confPac['xdrive']['service'] === 'gdrive' && $bot->confPac['xdrive']['secrets'] === [] && $bot->confPac['xdrive']['url'] === '' && empty($bot->confPac['xdrive']['enabled'])
    && $tag($bot->confXray) === [] && $bot->confPac['xdrive']['enc'] === $keys, 'смена хранилища: прежние доступы не переносятся');
$enter($bot, 'secret2', 'refresh');
$check($bot->confPac['xdrive']['secrets'] === ['', '', 'refresh'], 'ключи Google заполняются в любом порядке');
$bot->xdriveService('template');
$enter($bot, 'secrets', "k1\n\n  k2  \n");
$check($bot->confPac['xdrive']['secrets'] === ['k1', 'k2'], 'секреты шаблона: по одному на строку');
$bot->xdriveSet('enabled');
$bot->xdriveService('dropbox');
$check($bot->confPac['xdrive']['service'] === 'template', 'неизвестные поле и хранилище игнорируются');

// --- Словарь и справка -----------------------------------------------------
$module = file_get_contents(__DIR__ . '/../app/BotXdrive.php');
preg_match_all("~'(xdrive [a-z0-9 ]+)'~", $module, $used);
$keys = array_unique($used[1]);
foreach (['url', 'folder', 'template', 'secrets', 'poll', 'secret'] as $field) $keys[] = 'xdrive hint ' . $field;
require __DIR__ . '/../app/i18n.php';
foreach ($keys as $key) {
    if ($key === 'xdrive hint ') continue;
    $check(!empty($i[$key]['ru']) && !empty($i[$key]['en']) && preg_match('~[А-Яа-я]~u', $i[$key]['ru']), "перевод есть: $key");
}
$help = $bot->menuHelpContent('xdrive');
$check($help[0] === 'XDRIVE' && $help[1] === '/xdrive' && count($help[2]) === 9, 'справка: девять страниц, возврат в меню XDRIVE');
foreach ($help[2] as $title => $page) {
    $check(preg_match('~[А-Яа-я]~u', $title . $page) && !preg_match('~\b(the|and|with|storage)\b~i', $page) && mb_strlen($page) < 3500, "страница справки на русском и помещается в сообщение: $title");
    $check(substr_count($page, '<b>') === substr_count($page, '</b>') && substr_count($page, '<code>') === substr_count($page, '</code>'), "разметка страницы закрыта: $title");
}
$bot->language = 'en';
$check($bot->menuHelpContent('xdrive')[2] === $help[2], 'справка XDRIVE одна и та же при любом языке бота — русская');
$all = implode("\n", $help[2]);
foreach (['26.9.30', 'webdav.yandex.ru', 'Пароли приложений', 'Refresh Token', 'namesRegex', '10808', 'Новые ключи', 'Опрос в простое', 'Проверить хранилище'] as $needle) {
    $check(str_contains($all, $needle), "справка упоминает: $needle");
}
$routes = substr($source, strpos($source, "case preg_match('~^/xdrive$~'"), 1800);
foreach (['xdriveMenu', 'xdriveToggle', 'xdriveService', 'xdriveSet', 'xdriveProbeMenu', 'xdriveRotate', 'xdriveUsers', 'xdriveProfile'] as $method) {
    $check(str_contains($routes, '$this->' . $method . '('), "маршрут подключён: $method");
}

// --- Сбой DNS не выключает работающий вход --------------------------------
$b = new XdBot();
$check($b->applyXdrive(['enabled' => 1] + $webdav) === '', 'DNS: вход включён при разрешающемся имени');
$restarts = $b->restarts;
$b->resolved = [];
$check($b->xdriveProblems($b->xdriveSettings()) === ['xdrive unresolved'], 'DNS: неразрешающееся имя — отдельное замечание, а не «внутренний адрес»');
$enter($b, 'poll', '3000');
$check(!empty($b->xdriveSettings()['enabled']) && $b->xdriveSettings()['poll'] === 3000, 'DNS: правка другого поля при сбое DNS не выключает XDRIVE');
$check($b->xdriveActive($b->confPac, $b->confXray) && count(array_filter($b->confXray['inbounds'], static fn($in) => ($in['tag'] ?? '') === 'xdrive')) === 1, 'DNS: вход остаётся в конфиге ядра');
$check($b->xdriveClientConfig($b->confXray['inbounds'][0]['settings']['clients'][0]) !== null, 'DNS: профиль клиента выдаётся и при сбое DNS');
$check($b->xdriveProbe($b->xdriveSettings()) === 'xdrive probe incomplete', 'DNS: проверка хранилища при сбое DNS не выполняется');
$enter($b, 'url', 'https://other-name.example-disk.net/dav');
$check(str_contains($b->xdriveSettings()['url'], 'webdav.example-disk.net') && !empty($b->xdriveSettings()['enabled']), 'DNS: новый адрес, который не разрешается, не принимается, прежний остаётся');
$b->resolved = ['webdav.example-disk.net' => ['10.10.0.7']];
$enter($b, 'poll', '4000');
$check(empty($b->xdriveSettings()['enabled']), 'DNS: имя, ставшее внутренним адресом, по-прежнему выключает XDRIVE');
$check($b->xdriveClientConfig($b->confXray['inbounds'][0]['settings']['clients'][0]) === null, 'DNS: и профиль с внутренним адресом не выдаётся');

foreach ($failures as $failure) echo "FAIL: $failure\n";
if ($failures) exit(1);
echo "xdrive_test OK\n";
