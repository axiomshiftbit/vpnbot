<?php
// Профили IPsec для iOS и macOS: L2TP (.mobileconfig) и IKEv2 с подключением по требованию.
require_once __DIR__ . '/../app/bot.php';
set_error_handler(static function ($level, $message, $file, $line) { if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line); return true; });

class IpsecProfileBot extends Bot
{
    public array $t_l2tp = ['alice' => ['pass' => 'p<a>&"s\'s$1', 'disabled' => false], 'bob' => ['pass' => 'b0b', 'disabled' => true]];
    public array $t_ikev2 = ['alice' => ['pass' => 'k<e>&y$2', 'disabled' => false]];
    public string $t_psk = 'psk+/=<&>"key';
    public string $t_ca = 'Q0EtREVSLWJhc2U2NA==';
    public array $t_ports = ['ike' => 500, 'natt' => 4500];
    public array $t_messages = []; public array $t_files = []; public array $t_buttons = []; public array $t_menus = [];
    public function __construct()
    {
        $this->input = ['chat' => 1, 'from' => 7, 'message_id' => 5, 'callback_id' => 'cb', 'username' => 'admin', 'callback' => '', 'message' => ''];
        $this->language = 'ru';
        require __DIR__ . '/../app/i18n.php';
        $this->i18n = $i;
    }
    public function getL2tpUsers() { return $this->t_l2tp; }
    public function getIkev2Users() { return $this->t_ikev2; }
    public function getIpsecPsk() { return $this->t_psk; }
    public function ikev2CaB64() { return $this->t_ca; }
    public function ipsecPorts() { return $this->t_ports; }
    public function ipsecHost() { return '203.0.113.9'; }
    public function getL2tpOnline() { return []; }
    public function getIkev2Status() { return []; }
    public function ipsecLastSeen($user) { return null; }
    public function menu($type = false, $arg = false, $return = false) { $this->t_menus[] = $type; }
    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false, $entities = false, $forum = false) { $this->t_messages[] = [$chat, $text]; return ['ok' => true]; }
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML') { $this->t_messages[] = [$chat, $text]; $this->t_buttons = $button ?: []; return ['ok' => true]; }
    public function sendFile($chat, $id_url_cFile, $caption = false, $to = false) { $this->t_files[] = [$chat, $id_url_cFile, $caption]; return ['ok' => true]; }
    public function route(string $callback): void { $this->input['callback'] = $callback; $this->action(); }
}

// Разбор plist из того подмножества, что выдаёт бот; любая лишняя или
// незакрытая конструкция — исключение.
function plistParse(string $xml)
{
    if (!preg_match('~^<\?xml version="1\.0" encoding="UTF-8"\?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1\.0//EN" "http://www\.apple\.com/DTDs/PropertyList-1\.0\.dtd">\n<plist version="1\.0">(.*)</plist>$~s', $xml, $m)) {
        throw new RuntimeException('plist envelope');
    }
    preg_match_all('~<(dict|array)>|</(dict|array)>|<(key|string|integer|data)>([^<]*)</\3>|<(true|false)/>|([^<\s][^<]*)~', $m[1], $tokens, PREG_SET_ORDER);
    $position = 0;
    $value = plistValue($tokens, $position);
    if ($position !== count($tokens)) throw new RuntimeException('plist trailing content');
    return $value;
}
function plistValue(array $tokens, int &$position)
{
    $token = $tokens[$position++] ?? null;
    if ($token === null || ($token[6] ?? '') !== '') throw new RuntimeException('plist stray text');
    if (($token[5] ?? '') !== '') return $token[5] === 'true';
    if (($token[3] ?? '') !== '') {
        $text = html_entity_decode($token[4], ENT_QUOTES | ENT_XML1);
        return match ($token[3]) { 'integer' => (int) $text, 'data' => ['data' => base64_decode($text, true)], 'string' => $text,
            default => throw new RuntimeException('plist key outside dict') };
    }
    if ($token[1] === 'array') {
        $items = [];
        while (($tokens[$position][2] ?? '') !== 'array') $items[] = plistValue($tokens, $position);
        $position++;
        return $items;
    }
    if ($token[1] === 'dict') {
        $items = [];
        while (($tokens[$position][2] ?? '') !== 'dict') {
            $key = $tokens[$position++] ?? null;
            if (($key[3] ?? '') !== 'key' || isset($items[$key[4]])) throw new RuntimeException('plist dict key');
            $items[$key[4]] = plistValue($tokens, $position);
        }
        $position++;
        return $items;
    }
    throw new RuntimeException('plist unexpected closing tag');
}
// Строгая проверка тем же разбором, что у Apple-совместимых средств, если есть python3.
function plistStrict(string $xml): ?array
{
    if (trim((string) @shell_exec('command -v python3 2>/dev/null')) === '') return null;
    $process = proc_open(['python3', '-c', 'import sys,plistlib,json,base64;print(json.dumps(plistlib.loads(sys.stdin.buffer.read()),default=lambda b:{"data":base64.b64encode(b).decode()}))'],
        [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    fwrite($pipes[0], $xml); fclose($pipes[0]);
    $out = stream_get_contents($pipes[1]); $error = stream_get_contents($pipes[2]);
    if (proc_close($process) !== 0) throw new RuntimeException('plistlib rejected the profile: ' . $error);
    return json_decode($out, true);
}

$checks = 0;
function check(bool $condition, string $label): void { global $checks; $checks++; if (!$condition) { fwrite(STDERR, "FAIL: $label\n"); exit(1); } }
function buttonsOf(array $rows): array { $all = []; foreach ($rows as $row) foreach ($row as $button) $all[$button['callback_data']] = $button['text']; return $all; }

// --- L2TP: содержимое профиля
$bot = new IpsecProfileBot();
check($bot->sendL2tpProfile('alice') === true, 'l2tp profile is sent');
[$chat, $file, $caption] = $bot->t_files[0];
check($chat === 7 && $file->postname === 'alice-l2tp.mobileconfig' && $file->mime === 'application/x-apple-aspen-config', 'l2tp file goes to the admin who asked, with the Apple type');
$plist = plistParse($file->data);
$vpn = $plist['PayloadContent'][0];
check($plist['PayloadType'] === 'Configuration' && count($plist['PayloadContent']) === 1, 'l2tp profile has a single VPN payload');
check($vpn['PayloadType'] === 'com.apple.vpn.managed' && $vpn['VPNType'] === 'L2TP', 'payload is an L2TP VPN');
check($vpn['IPSec']['AuthenticationMethod'] === 'SharedSecret' && $vpn['IPSec']['SharedSecret'] === ['data' => $bot->t_psk], 'PSK is carried as data and survives special characters');
check($vpn['PPP']['AuthName'] === 'alice' && $vpn['PPP']['AuthPassword'] === $bot->t_l2tp['alice']['pass'], 'login and password survive XML escaping');
check($vpn['PPP']['CommRemoteAddress'] === '203.0.113.9' && $vpn['PPP']['TokenCard'] === false, 'server address is set');
check($vpn['IPv4']['OverridePrimary'] === 1, 'all traffic goes through the tunnel');
check(!str_contains($file->data, $bot->t_psk) && !str_contains($file->data, $bot->t_l2tp['alice']['pass']), 'raw secrets with XML metacharacters are never written unescaped');
$strict = plistStrict($file->data);
check($strict === null || ($strict['PayloadContent'][0]['PPP']['AuthPassword'] === $bot->t_l2tp['alice']['pass']
    && base64_decode($strict['PayloadContent'][0]['IPSec']['SharedSecret']['data']) === $bot->t_psk), 'strict plist parser reads the same values');
$uuid = '~^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-a[0-9a-f]{3}-[0-9a-f]{12}$~D';
check(preg_match($uuid, $plist['PayloadUUID']) && preg_match($uuid, $vpn['PayloadUUID']) && $plist['PayloadUUID'] !== $vpn['PayloadUUID'], 'payload UUIDs are valid and distinct');

// --- L2TP: повторная выдача обновляет профиль, а не плодит новые; IKEv2 не задевается
$again = new IpsecProfileBot();
$again->sendL2tpProfile('alice');
check($again->t_files[0][1]->data === $file->data, 'repeated issue gives the same profile');
$ikev2 = plistParse($bot->ikev2Mobileconfig('alice', 'x', '203.0.113.9', $bot->t_ca));
check($ikev2['PayloadUUID'] !== $plist['PayloadUUID'] && $ikev2['PayloadIdentifier'] !== $plist['PayloadIdentifier']
    && $ikev2['PayloadContent'][0]['PayloadUUID'] !== $vpn['PayloadUUID'] && $ikev2['PayloadContent'][0]['PayloadIdentifier'] !== $vpn['PayloadIdentifier'],
    'L2TP profile does not replace the IKEv2 profile of the same user');

// --- L2TP: отказы
foreach ([['ike' => 1500, 'natt' => 4500], ['ike' => 500, 'natt' => 14500]] as $ports) {
    $bot = new IpsecProfileBot(); $bot->t_ports = $ports;
    check($bot->sendL2tpProfile('alice') === false && !$bot->t_files && str_contains($bot->t_messages[0][1], '500') && str_contains($bot->t_messages[0][1], 'IKEv2'), 'non-standard ports: explained, no dead profile');
}
$bot = new IpsecProfileBot(); $bot->t_psk = '';
check($bot->sendL2tpProfile('alice') === false && !$bot->t_files && $bot->t_messages, 'no PSK: no profile');
$bot = new IpsecProfileBot();
check($bot->sendL2tpProfile('mallory') === false && !$bot->t_files, 'unknown user: no profile');
check($bot->sendL2tpProfile('alice</string>') === false && !$bot->t_files, 'markup instead of a name: no profile');

// --- L2TP: кнопка и маршрут
$bot = new IpsecProfileBot();
$bot->l2tpClientMenu('alice');
$buttons = buttonsOf($bot->t_buttons);
check(($buttons['/getL2tpProfile alice'] ?? '') === '.mobileconfig' && isset($buttons['/getL2tpCreds alice']), 'client menu offers the profile next to the credentials');
check(count($buttons) === 7, 'no other button of the L2TP client menu is lost');
$bot = new IpsecProfileBot();
$bot->route('/getL2tpProfile alice');
check(count($bot->t_files) === 1 && $bot->t_files[0][1]->postname === 'alice-l2tp.mobileconfig', 'callback is routed to the profile');

// --- IKEv2: обычный профиль не изменился ни на байт
$bot = new IpsecProfileBot();
$plain = $bot->ikev2Mobileconfig('alice', $bot->t_ikev2['alice']['pass'], '203.0.113.9', $bot->t_ca);
$demand = $bot->ikev2Mobileconfig('alice', $bot->t_ikev2['alice']['pass'], '203.0.113.9', $bot->t_ca, true);
check(hash('sha256', $plain) === 'baf4e9a4ed80180c770bdd24360c8f2198bda22689cf7c49a0073ab8cb2d88b8', 'regular IKEv2 profile is byte-identical to the one issued before');
$p = plistParse($plain); $d = plistParse($demand);
check(!isset($p['PayloadContent'][0]['IKEv2']['OnDemandEnabled']) && !isset($p['PayloadContent'][0]['IKEv2']['OnDemandRules']) && !str_contains($plain, 'OnDemand'), 'regular profile never connects by itself');
check($d['PayloadContent'][0]['IKEv2']['OnDemandEnabled'] === 1 && $d['PayloadContent'][0]['IKEv2']['OnDemandRules'] === [['Action' => 'Connect']], 'on-demand keys sit inside the IKEv2 dictionary');
$without = $d; unset($without['PayloadContent'][0]['IKEv2']['OnDemandEnabled'], $without['PayloadContent'][0]['IKEv2']['OnDemandRules']);
check($without === $p, 'on-demand profile differs from the regular one only by the two keys');
check($d['PayloadContent'][0]['IKEv2']['AuthPassword'] === $bot->t_ikev2['alice']['pass'] && $d['PayloadContent'][1]['PayloadContent'] === ['data' => base64_decode($bot->t_ca)], 'password and CA are intact');
check($d['PayloadContent'][0]['IKEv2']['EnablePFS'] === 0, 'PFS stays off: server-side rekeying breaks the native client');
$strict = plistStrict($demand);
check($strict === null || $strict['PayloadContent'][0]['IKEv2']['OnDemandRules'] === [['Action' => 'Connect']], 'strict plist parser accepts the on-demand profile');

// --- IKEv2: выдача и меню
$bot->sendIkev2Profile('alice');
check($bot->t_files[0][1]->postname === 'alice.mobileconfig' && $bot->t_files[0][1]->data === $plain && $bot->t_files[0][2] === false, 'regular button: same file name, no caption');
$bot->sendIkev2Profile('alice', true);
check($bot->t_files[1][1]->postname === 'alice-ondemand.mobileconfig' && $bot->t_files[1][1]->data === $demand, 'on-demand button gives the on-demand profile');
check(is_string($bot->t_files[1][2]) && str_contains($bot->t_files[1][2], 'Подключать по запросу') && mb_strlen($bot->t_files[1][2]) <= 1024, 'caption tells how to stop the auto-connect and fits Telegram');
$bot = new IpsecProfileBot();
$bot->route('/getIkev2Profile alice');
$bot->route('/ikev2Auto alice');
$bot->route('/getIkev2Profile alice ondemand');
$bot->route('/ikev2Auto');
check(array_map(static fn($f) => $f[1]->postname, $bot->t_files) === ['alice.mobileconfig', 'alice-ondemand.mobileconfig'], 'routes: plain, on-demand, nothing for malformed suffixes');
$bot = new IpsecProfileBot(); $bot->t_ca = '';
check($bot->sendIkev2Profile('alice', true) === false && !$bot->t_files, 'no CA: no profile');
$bot = new IpsecProfileBot();
check($bot->sendIkev2Profile('mallory', true) === false && !$bot->t_files, 'unknown IKEv2 user: no profile');
$bot->ikev2ClientMenu('alice');
$buttons = buttonsOf($bot->t_buttons);
check(($buttons['/getIkev2Profile alice'] ?? '') === '.mobileconfig' && ($buttons['/getIkev2Sswan alice'] ?? '') === '.sswan', 'regular buttons are unchanged');
check(str_contains($buttons['/ikev2Auto alice'] ?? '', 'автоподключение') && count($buttons) === 9, 'on-demand is a separate button; nothing else is lost');
// Логин бывает до 40 символов, а Telegram отклоняет всё меню, если данные хоть одной кнопки длиннее 64 байт.
$long = str_repeat('u', 40);
foreach (['ikev2' => 'ikev2ClientMenu', 'l2tp' => 'l2tpClientMenu'] as $kind => $menu) {
    $bot = new IpsecProfileBot();
    $bot->t_ikev2[$long] = $bot->t_l2tp[$long] = ['pass' => 'x', 'disabled' => false];
    $bot->$menu($long);
    $data = array_keys(buttonsOf($bot->t_buttons));
    check(count($data) >= 7 && max(array_map('strlen', $data)) <= 64, "$kind client menu fits Telegram limits with the longest login");
}
$bot = new IpsecProfileBot();

foreach (['l2tp profile ports', 'ikev2 on demand', 'ikev2 on demand hint'] as $key) {
    foreach (['en', 'ru'] as $language) { $bot->language = $language; check($bot->i18n($key) !== $key && $bot->i18n($key) !== '', "translation $key/$language"); }
}

echo "ipsec profiles: $checks checks passed\n";
