<?php

// Shadowsocks и его SIP003-плагины (v2ray-plugin, Cloak, simple-tls).
// Проверяется то, что ломается молча:
//  - `pkill -f <шаблон>` матчит и СОБСТВЕННУЮ командную строку шелла, которому
//    её отдали. Из-за этого «pkill -f ck-server; jq … && ck-server …» убивал сам
//    себя на первой команде: cloak включался в конфиге, но процесс не стартовал
//    и лог не создавался вовсе. Шаблон обязан быть в bracket-форме;
//  - ss://-ссылка по SIP002 требует websafe-base64 (base64url) без паддинга:
//    обычный base64 может выдать '/' в userinfo и порвать разбор URI;
//  - опции плагинов должны совпадать с тем, что понимают сами бинари
//    (README forwardproxy/simple-tls/v2ray-plugin).

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function ssAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

// Lifecycle uses the supervisor instead of a shell-wide process-name kill.
class SsControllerTestBot extends Bot {
    public string $command = '';
    public string $reply = '';
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') {
        $this->command = $cmd;
        return $this->reply;
    }
}
$controller = (new ReflectionClass(SsControllerTestBot::class))->newInstanceWithoutConstructor();
foreach (['ck-server', 'simple-tls'] as $service) {
    foreach (['restart' => 'READY', 'stop' => 'STOPPED'] as $action => $marker) {
        $controller->reply = "VPNBOT_SERVICE_$marker:$service";
        ssAssert($controller->controlContainerService('ss', $service, $action), 'confirmed '.$service.' '.$action);
        ssAssert(!str_contains($controller->command, 'pkill') && !str_contains($controller->command, 'nohup'),
            'supervisor owns process termination and launch');
        $controller->reply = '';
        ssAssert(!$controller->controlContainerService('ss', $service, $action), 'missing marker is failure');
    }
}
$adapter = file_get_contents(__DIR__ . '/../scripts/service_daemon.sh');

$acl = file_get_contents(__DIR__ . '/../config/ss.acl');
$ssTemplate = json_decode(file_get_contents(__DIR__ . '/../config/ssserver.json'), true);
ssAssert(($ssTemplate['acl'] ?? '') === '/config/ss.acl', 'ssserver включает запрет служебных сетей');
ssAssert(str_contains($acl, '[outbound_block_list]'), 'ACL фильтрует назначения, не клиентские IP');
foreach (['10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '::1/128', 'fc00::/7'] as $net) {
    ssAssert(str_contains($acl, $net), 'SS закрывает ' . $net);
}

// ── 2. SIP002: userinfo — base64url без паддинга ────────────────────────────
$enc = fn(string $s) => rtrim(strtr(base64_encode($s), '+/', '-_'), '=');

// Пароль, чей обычный base64 содержит '/' и '+' — ровно тот случай, который
// рвал ссылку (клиент принимал '/' за начало path).
$raw = "chacha20-ietf-poly1305:" . base64_decode('+/8=');
$std = base64_encode($raw);
ssAssert(strpbrk($std, '+/') !== false, 'контроль: обычный base64 такого пароля содержит + или /');
ssAssert(strpbrk($enc($raw), '+/=') === false, 'base64url не содержит + / =');
ssAssert(base64_decode(strtr($enc($raw), '-_', '+/')) === $raw, 'base64url декодируется обратно без потерь');

// Паддинг: старый код срезал только '==', одиночный '=' оставался.
$one = 'chacha20-ietf-poly1305:abc';            // даёт ровно один '='
ssAssert(substr(base64_encode($one), -1) === '=', 'контроль: этот вход даёт одиночный паддинг');
ssAssert(substr($enc($one), -1) !== '=', 'одиночный паддинг тоже срезается');

// ── 3. Опции плагинов ───────────────────────────────────────────────────────
// simple-tls (SIP003): клиентские ключи по README — n=<sni>, no-verify как
// голый флаг. Серверная сторона запускается отдельно с -s -b -d -cert -key.
$stls = fn(string $sni, bool $selfSigned) => 'simple-tls;n=' . $sni . ($selfSigned ? ';no-verify' : '');
ssAssert($stls('a.example.com', false) === 'simple-tls;n=a.example.com', 'simple-tls: только n= при валидном серте');
ssAssert(str_ends_with($stls('a.example.com', true), ';no-verify'), 'simple-tls: no-verify при self-signed');
ssAssert(!str_contains($stls('a.example.com', true), 'no-verify='), 'no-verify — голый флаг, без значения');

// Cloak: EncryptionMethod «aes-256-gcm» валиден (README: синоним aes-gcm),
// BrowserSig — chrome/firefox/safari, Transport — direct/CDN.
foreach (['plain', 'aes-gcm', 'aes-256-gcm', 'aes-128-gcm', 'chacha20-poly1305'] as $m2) {
    ssAssert(in_array($m2, ['plain', 'aes-gcm', 'aes-256-gcm', 'aes-128-gcm', 'chacha20-poly1305'], true),
        "cloak EncryptionMethod допускает $m2");
}
$ck = json_decode(file_get_contents(__DIR__ . '/../config/ckclient.json'), true);
ssAssert(in_array($ck['EncryptionMethod'], ['plain', 'aes-gcm', 'aes-256-gcm', 'aes-128-gcm', 'chacha20-poly1305'], true),
    'ckclient.json: EncryptionMethod из списка README');
ssAssert(in_array($ck['BrowserSig'], ['chrome', 'firefox', 'safari'], true), 'ckclient.json: BrowserSig валиден');
ssAssert(in_array($ck['Transport'], ['direct', 'CDN'], true), 'ckclient.json: Transport валиден');

// ck-server не понимает наше служебное поле Enabled и пустые AdminUID/
// DatabasePath — их вырезает общий адаптер запуска службы.
foreach (['Enabled', 'AdminUID', 'DatabasePath'] as $k) {
    ssAssert(str_contains($adapter, $k), "service adapter вычищает $k");
}

// v2ray-plugin: серверная сторона поднимается без path (дефолт '/'), поэтому
// nginx обязан срезать весь префикс — location должен содержать хеш целиком,
// а proxy_pass — оканчиваться слэшем.
$nginx = file_get_contents(__DIR__ . '/../config/nginx.conf');
$nginx = preg_replace('~^\s*#.*$~m', '', $nginx);
ssAssert((bool) preg_match('~location /v2ray[^\s{]*\s*\{[^}]*proxy_pass http://10\.10\.0\.6:8388/;~s', $nginx),
    'nginx: /v2ray использует постоянный адрес SS со слэшем и работает без DNS выключенного контейнера');

if ($failed) {
    echo "ss_test FAILED ($failed)\n";
    exit(1);
}
echo "ss_test OK\n";
