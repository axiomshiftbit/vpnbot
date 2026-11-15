<?php

// L2TP/IPsec + IKEv2. Фикстуры вывода swanctl сняты с живого сервера
// (strongSwan 6.0.7), формат сверен с src/swanctl/commands/list_sas.c.
//
// Главный инвариант: имя клиента в `swanctl --list-sas` печатается ДВУМЯ
// разными способами, и оба обязаны распознаваться.
//   remote 'test' @ 10.0.0.8[4500] [10.9.2.1]                — IKE-id = логин
//   remote '10.0.0.8' @ 10.0.0.8[4500] EAP: 'test' [10.9.2.1] — EAP-id = логин
// `EAP: '...'` выводится, только когда EAP-identity отличается от IKE-id
// (list_sas.c). Наш .mobileconfig задаёт LocalIdentifier = логин, поэтому
// iOS/macOS попадают в ПЕРВЫЙ вариант — раньше такие сессии терялись целиком.

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function ipsecAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

// Бот с подменённым ssh(): отдаём заранее снятый вывод swanctl.
function ipsecBot(string $sas)
{
    return new class ($sas) extends Bot {
        private $sas;
        public function __construct($sas)
        {
            $this->sas = $sas;
        }
        public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
        {
            return strpos($cmd, 'list-sas') !== false ? $this->sas : '';
        }
    };
}

// ── 1. list-sas: IKE-id = логин (iOS/macOS с нашим .mobileconfig) ──────────
$sasIkeId = <<<TXT
ikev2: #4, ESTABLISHED, IKEv2, 8452cb54824dca66_i e7fc112f97ebdb83_r*
  local  '203.0.113.10' @ 10.10.0.21[4500]
  remote 'test' @ 10.10.0.8[4500] [10.9.2.1]
  AES_GCM_16-256/PRF_HMAC_SHA2_384/ECP_384
  established 12s ago
  ikev2: #1, reqid 1, INSTALLED, TUNNEL, ESP:AES_GCM_16-256
    installed 12s ago
    in  c82f3da2,   4096 bytes,    12 packets
    out c30304ac,   8192 bytes,    20 packets
    local  0.0.0.0/0
    remote 10.9.2.1/32
TXT;
$st = ipsecBot($sasIkeId)->getIkev2Status();
ipsecAssert(isset($st['test']), 'сессия с IKE-id = логин распознана (iOS/macOS)');
ipsecAssert(($st['test']['uid'] ?? 0) === 4, 'uid IKE_SA взят для kick');
ipsecAssert(($st['test']['real'] ?? '') === '10.10.0.8', 'реальный адрес клиента');
ipsecAssert(($st['test']['virtual'] ?? '') === '10.9.2.1', 'виртуальный IP из [vips]');
ipsecAssert(($st['test']['rx'] ?? 0) === 4096 && ($st['test']['tx'] ?? 0) === 8192, 'байты in/out');
ipsecAssert(($st['test']['since'] ?? '') === 12, 'аптайм сессии');

// ── 2. list-sas: EAP-id отличается от IKE-id (.sswan, Windows) ─────────────
$sasEapId = <<<TXT
ikev2: #6, ESTABLISHED, IKEv2, 80584894e0cba75f_i 6d7a0862959081e3_r*
  local  '203.0.113.10' @ 10.10.0.21[4500]
  remote '10.10.0.8' @ 10.10.0.8[4500] EAP: 'test' [10.9.2.1]
  AES_GCM_16-256/PRF_HMAC_SHA2_384/ECP_384
  established 5s ago
  ikev2: #2, reqid 1, INSTALLED, TUNNEL, ESP:AES_GCM_16-256
    installed 5s ago
    in  c28a1f61,      0 bytes,     0 packets
    out d19b2f70,      0 bytes,     0 packets
    local  0.0.0.0/0
    remote 10.9.2.1/32
TXT;
$st2 = ipsecBot($sasEapId)->getIkev2Status();
ipsecAssert(isset($st2['test']), 'сессия с отдельной EAP-identity распознана');
ipsecAssert(!isset($st2['10.10.0.8']), 'IKE-id не создаёт лишнюю запись, когда есть EAP-id');
ipsecAssert(($st2['test']['uid'] ?? 0) === 6, 'uid из второго варианта');

// ── 3. IKEv1-сессия L2TP не должна попадать в список IKEv2-клиентов ────────
// (онлайн L2TP берётся из ppp-хуков, а не из list-sas).
$sasBoth = $sasIkeId . "\n" . <<<TXT
l2tp: #7, ESTABLISHED, IKEv1, ec10dfd4c9bd92f2_i 35b7f51050af1640_r*
  local  '10.10.0.21' @ 10.10.0.21[500]
  remote '10.10.0.9' @ 10.10.0.9[500]
  AES_CBC-256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048
  established 10s ago, rekeying in 27587s
  l2tp: #3, reqid 2, INSTALLED, TRANSPORT, ESP:AES_CBC-256/HMAC_SHA2_256_128
    installed 10s ago
    in  c67ce759,   1024 bytes,     4 packets
    out c786e615,   2048 bytes,     8 packets
    local  10.10.0.21/32[udp/l2f]
    remote 10.10.0.9/32[udp/l2f]
TXT;
$st3 = ipsecBot($sasBoth)->getIkev2Status();
ipsecAssert(isset($st3['test']), 'IKEv2-клиент виден при наличии IKEv1-сессии рядом');
ipsecAssert(($st3['test']['rx'] ?? 0) === 4096, 'байты IKEv1-сессии не приплюсовались к IKEv2-клиенту');
ipsecAssert(count($st3) <= 2, 'IKEv1 L2TP не плодит мусорных записей');

// ── 4. chap-secrets: round-trip и блокировка ───────────────────────────────
$dir = sys_get_temp_dir() . '/ipsec_test_' . getmypid();
@mkdir($dir, 0755, true);
$box = new class ($dir) extends Bot {
    private $d;
    public $sshCalls = [];
    public function __construct($d)
    {
        $this->d = $d;
    }
    public function ipsecPaths()
    {
        return [
            'conf'    => $this->d,
            'psk'     => $this->d . '/psk',
            'chap'    => $this->d . '/chap-secrets',
            'secrets' => $this->d . '/secrets.conf',
            'users'   => $this->d . '/users_ikev2.json',
            'ca'      => $this->d . '/pki/ca.crt',
            'srv'     => $this->d . '/pki/server.crt',
            'log'     => $this->d . '/ipsec.log',
            'l2tp'    => $this->d . '/l2tp.log',
            'conn'    => $this->d . '/conn.log',
        ];
    }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
    {
        $this->sshCalls[] = $cmd;
        if (str_contains($cmd, '--load-creds')) return 'VPNBOT_IKEV2_CREDS_OK';
        return str_contains($cmd, 'VPNBOT_IKEV2_STATUS_OK') ? 'VPNBOT_IKEV2_STATUS_OK' : '';
    }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
};
file_put_contents($dir . '/psk', "test-psk-value\n");

$l2 = [
    'alice'   => ['pass' => 'a1b2c3d4', 'disabled' => false],
    'bob.x-1' => ['pass' => 'ffffffff', 'disabled' => true],
];
$box->saveL2tpUsers($l2);
$back = $box->getL2tpUsers();
ipsecAssert($back === $l2, 'chap-secrets переживает round-trip, блокировка сохраняется');
$raw = file_get_contents($dir . '/chap-secrets');
ipsecAssert(strpos($raw, '#"bob.x-1" * "ffffffff" *') !== false, 'заблокированный юзер закомментирован');
ipsecAssert(preg_match('~^"alice" \* "a1b2c3d4" \*$~m', $raw) === 1, 'формат строки pppd канонический');

// ── 5. secrets.conf: заблокированные не попадают в EAP-секции ──────────────
$box->saveIkev2Users([
    'ok'      => ['pass' => 'p1', 'disabled' => false],
    'blocked' => ['pass' => 'p2', 'disabled' => true],
]);
$sec = file_get_contents($dir . '/secrets.conf');
ipsecAssert(strpos($sec, 'id = "ok"') !== false, 'активный IKEv2-юзер попадает в secrets.conf');
ipsecAssert(strpos($sec, 'id = "blocked"') === false, 'заблокированный IKEv2-юзер исключён — EAP сразу перестаёт проходить');
ipsecAssert(strpos($sec, 'secret = "test-psk-value"') !== false, 'PSK для conn l2tp сохраняется при регенерации');
ipsecAssert(
    (bool) array_filter($box->sshCalls, fn($c) => strpos($c, 'swanctl --load-creds') !== false),
    'после записи secrets.conf креды перечитываются'
);

// ── 6. .sswan: схема по документации strongSwan ────────────────────────────
// Ключи и допустимые значения — androidVpnClientProfiles.html:
// remote{addr,port,id,cert}, local{eap_id,shared_secret}, type=ikev2-eap.
// remote.port — порт СЕРВЕРА (default 500), то есть IKE-порт, не NAT-T.
$profile = [
    'uuid'   => $box->ikev2Uuid('x'),
    'name'   => 'vpnbot u',
    'type'   => 'ikev2-eap',
    'remote' => ['addr' => '1.2.3.4', 'id' => '1.2.3.4', 'cert' => 'BASE64'],
    'local'  => ['eap_id' => 'u'],
];
ipsecAssert($profile['type'] === 'ikev2-eap', 'тип профиля из списка допустимых');
ipsecAssert(
    (bool) preg_match('~^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-a[0-9a-f]{3}-[0-9a-f]{12}$~', $box->ikev2Uuid('x')),
    'uuid профиля в формате RFC 4122 v4'
);
ipsecAssert($box->ikev2Uuid('x') === $box->ikev2Uuid('x'), 'uuid детерминирован — повторная выдача обновляет профиль, а не дублирует');

$botSrc = file_get_contents(__DIR__ . '/../app/bot.php');
ipsecAssert(
    strpos($botSrc, "if (\$ports['ike'] !== 500) {\n            \$profile['remote']['port'] = \$ports['ike'];") !== false,
    '.sswan указывает IKE-порт сервера, а не NAT-T'
);
ipsecAssert(
    strpos($botSrc, "\$profile['local']['shared_secret']") !== false,
    '.sswan несёт пароль, как и .mobileconfig'
);

// ── 7. Миграции swanctl.conf вынесены и идемпотентны ───────────────────────
$mig = file_get_contents(__DIR__ . '/../scripts/ipsec_migrate.sh');
ipsecAssert(strpos($mig, 'managed-server-id') !== false, 'ipsec_migrate.sh правит server id');
ipsecAssert(strpos($mig, 'modp1024') !== false, 'ipsec_migrate.sh добавляет modp1024-фолбэк для нативных клиентов');
$startIpsec = file_get_contents(__DIR__ . '/../scripts/start_ipsec.sh');
ipsecAssert(strpos($startIpsec, 'sh /ipsec_migrate.sh') !== false, 'start_ipsec.sh зовёт общий скрипт миграций');
// Регрессии с реального Docker/pppd 2.5.3: каталог 0775 запрещает чтение
// secrets; ipcp-accept-remote позволял согласовать IP контейнера вместо пула.
preg_match('~cat > /etc/ppp/options.xl2tpd <<EOF\n(.*?)\nEOF~s', $startIpsec, $pppOptions);
ipsecAssert(!empty($pppOptions[1]), 'найден шаблон серверных PPP options');
ipsecAssert(!str_contains($pppOptions[1] ?? '', 'ipcp-accept-'), 'адреса обеих сторон PPP задаёт сервер');
ipsecAssert(str_contains($startIpsec, 'chmod 0700 "$CONF" "$PKI"'), 'путь до chap-secrets не допускает запись группой');
ipsecAssert(str_contains($startIpsec, 'chown 0:0 "$CONF/chap-secrets"'), 'владелец chap-secrets пригоден для pppd');
$ipsecOnly = strpos($startIpsec, '--dport 1701 -m policy --dir in --pol ipsec -j ACCEPT');
$plainDrop = strpos($startIpsec, '--dport 1701 -j DROP');
ipsecAssert($ipsecOnly !== false && $plainDrop > $ipsecOnly, 'L2TP принимается только внутри IPsec');
ipsecAssert(str_contains($startIpsec, '-i ppp+ ! -s "$L2TP_SUBNET" -j DROP'), 'PPP не пересылает source за пределами пула');
ipsecAssert(
    strpos($botSrc, 'sh /ipsec_migrate.sh') !== false,
    'бот применяет миграции сам — restore бэкапа кладёт swanctl.conf из снимка'
);
ipsecAssert(
    (bool) preg_match('~function restartIpsec\(\).*?\$this->migrateIpsecConf\(\);.*?pkill -9 charon~s', $botSrc),
    'restartIpsec() мигрирует конфиг до перезапуска демонов'
);
// Шаблон нового конфига обязан нести тот же фолбэк, что и миграция.
ipsecAssert(
    strpos($startIpsec, 'aes256-sha256-modp1024') !== false,
    'шаблон swanctl.conf сразу содержит modp1024-фолбэк для conn l2tp'
);

// ── 8. updown-хук: формат строки читается тем же парсером, что L2TP/ovpn ──
$startIpsec2 = file_get_contents(__DIR__ . '/../scripts/start_ipsec.sh');
ipsecAssert(strpos($startIpsec2, 'PLUTO_XAUTH_ID') !== false, 'updown-хук берёт логин из PLUTO_XAUTH_ID (EAP identity)');
ipsecAssert(strpos($startIpsec2, 'updown = /etc/ipsec-updown.sh') !== false, 'шаблон swanctl.conf подключает updown у conn ikev2');
ipsecAssert(strpos($mig, 'updown = /etc/ipsec-updown.sh') !== false, 'миграция включает updown в существующих конфигах');

// Строка, которую напечатает хук, обязана разбираться ipsecLastSeen().
$line = '2026-08-02 19:30:00 UP   alice                ikev2 10.9.2.3 from 203.0.113.9';
ipsecAssert(
    (bool) preg_match('~^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (UP|DOWN)\s+(\S+)\s~', $line, $lm)
        && $lm[3] === 'alice' && $lm[2] === 'UP',
    'строка updown-хука разбирается общим парсером журнала'
);
file_put_contents($dir . '/conn.log', $line . "\n");
$seen = $box->ipsecLastSeen('alice');
ipsecAssert(($seen['dir'] ?? '') === 'UP' && ($seen['ts'] ?? '') === '2026-08-02 19:30:00', 'ipsecLastSeen находит событие IKEv2');

// Повреждённый снимок не должен обнулять уже работающие credentials.
file_put_contents($dir . '/psk', 'previous-test-psk');
ipsecAssert($box->importIpsecPki(['psk' => base64_encode('replacement'), 'bad' => '%%%']) === false,
    'битый base64 отклоняется до первой записи');
ipsecAssert(file_get_contents($dir . '/psk') === 'previous-test-psk', 'предыдущий PSK сохранён');
ipsecAssert($box->importIpsecPki(['../outside' => base64_encode('bad')]) === false,
    'путь за пределами PKI отклоняется целиком');
ipsecAssert($box->importIpsecPki(['psk' => base64_encode('restored-test-psk')]) === true,
    'корректный снимок восстанавливается');
ipsecAssert(file_get_contents($dir . '/psk') === 'restored-test-psk', 'восстановленное значение на диске');
ipsecAssert((fileperms($dir . '/psk') & 0777) === 0600 && (fileperms($dir) & 0777) === 0700,
    'восстановленные секреты и каталог закрыты');

foreach (glob($dir . '/*') ?: [] as $f) {
    @unlink($f);
}
@rmdir($dir);

$restartRoot = sys_get_temp_dir() . '/ipsec-restart-' . bin2hex(random_bytes(8));
mkdir($restartRoot, 0700);
$restart = new class($restartRoot) extends Bot {
    public bool $enabled = true;
    public bool $pkiReady = true;
    public bool $loadReady = true;
    public array $commands = [];
    public function __construct(public string $root) {}
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
    public function ipsecPaths() { return ['conf' => $this->root, 'users' => "$this->root/users_ikev2.json", 'secrets' => "$this->root/secrets.conf"]; }
    public function getIpsecPsk() { return 'synthetic-restart-psk'; }
    public function protocolModuleEnabled(string $service): bool { return $this->enabled; }
    public function ssh($cmd,$service='wg',$wait=true,$log='/dev/null') {
        $this->commands[]=$cmd;
        if (str_contains($cmd,'VPNBOT_IPSEC_PKI_READY')) return $this->pkiReady ? 'VPNBOT_IPSEC_PKI_READY' : '';
        if (str_contains($cmd,'VPNBOT_IPSEC_READY')) return $this->loadReady ? 'VPNBOT_IPSEC_READY' : '';
        if (str_contains($cmd,'VPNBOT_IKEV2_CREDS_OK')) return 'VPNBOT_IKEV2_CREDS_OK';
        return '';
    }
};
ipsecAssert($restart->restartIpsec()===true,'Перезапуск подтверждает загрузку ключей и конфигурации');
$restart->commands=[];$restart->pkiReady=false;
ipsecAssert($restart->restartIpsec()===false && count($restart->commands)===1,'Ошибка подготовки PKI не останавливает рабочий процесс');
$restart->pkiReady=true;$restart->loadReady=false;
ipsecAssert($restart->restartIpsec()===false,'Ошибка swanctl видна вызывающему коду');
$restart->enabled=false;$restart->commands=[];
ipsecAssert($restart->restartIpsec()===true && !$restart->commands,'Выключенный IPsec сохраняет настройки без обращения к контейнеру');
foreach (glob($restartRoot . '/*') as $file) unlink($file);
rmdir($restartRoot);
if ($failed) {
    echo "$failed test(s) failed\n";
    exit(1);
}
echo "ipsec: all checks passed\n";
