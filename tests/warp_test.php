<?php

// WARP. Проверено на живом сервере, поэтому фикстуры и допущения — не
// теоретические:
//   * контейнер wp содержит ТОЛЬКО wgcf + wg + microsocks; warp-cli/warp-svc
//     там нет, поэтому вся старая реализация offWarp() была no-op;
//   * microsocks слушает 0.0.0.0 и не умеет ACL, а до него доходит любой
//     контейнер сети проекта. `ip route get 10.10.0.13` изнутри контейнеров:
//        xray -> src 10.10.0.9   (единственный легитимный потребитель)
//        openvpn  -> src 10.10.0.19
//        ipsec    -> src 10.10.0.21
//        wireguard-> src 10.10.0.14
//     Клиент VPN маскируется под адрес СВОЕГО контейнера, то есть все они
//     выглядели как обычный внутренний источник и получали открытый SOCKS5
//     без пароля (проверено: через него отвечал внутренний adguard).

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function warpAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

$startWp = file_get_contents(__DIR__ . '/../scripts/start_wp.sh');
$probe   = file_get_contents(__DIR__ . '/../scripts/warp_probe.sh');
$fixup   = file_get_contents(__DIR__ . '/../scripts/warp_fixup.sh');
$botSrc  = file_get_contents(__DIR__ . '/../app/bot.php');

// ── 1. SOCKS закрыт от всех, кроме петли и xray ────────────────────────────
warpAssert(strpos($startWp, 'iptables -A WARP_SOCKS -j DROP') !== false, 'по умолчанию доступ к SOCKS запрещён');
warpAssert(strpos($startWp, 'iptables -A WARP_SOCKS -i lo -j ACCEPT') !== false, 'петля разрешена (probe + healthcheck)');
warpAssert(
    (bool) preg_match('~for ip in \$SOCKS_ALLOW; do\s*\n\s*iptables -A WARP_SOCKS -s "\$ip" -j ACCEPT~', $startWp),
    'разрешены только адреса из allowlist'
);
// Правило обязано стоять ПЕРЕД остальными в INPUT и заводиться идемпотентно.
warpAssert(strpos($startWp, 'iptables -I INPUT -p tcp --dport "$SOCKS_PORT" -j WARP_SOCKS') !== false, 'переход в цепочку вставляется в начало INPUT');
warpAssert(strpos($startWp, 'iptables -C INPUT -p tcp --dport "$SOCKS_PORT" -j WARP_SOCKS') !== false, 'переход не дублируется при рестарте');
warpAssert(strpos($startWp, 'iptables -F WARP_SOCKS') !== false, 'цепочка очищается перед наполнением — правила не копятся');
// Фильтр должен подниматься ДО самого microsocks, иначе есть окно, когда
// прокси уже слушает, а ограничений ещё нет.
warpAssert(
    strpos($startWp, 'iptables -A WARP_SOCKS -j DROP') < strpos($startWp, 'microsocks -p "$SOCKS_PORT" &'),
    'фильтр ставится раньше запуска microsocks'
);

// ── 2. Allowlist: резолв, фолбэк, override ─────────────────────────────────
// Логика `${WARP_SOCKS_ALLOW:-${XRAY_IPS:-10.10.0.9}}` — проверяем её на sh.
$sh = function (string $env) {
    $out = [];
    exec($env . ' sh -c \'SOCKS_ALLOW="${WARP_SOCKS_ALLOW:-${XRAY_IPS:-10.10.0.9}}"; printf "%s" "$SOCKS_ALLOW"\'', $out);
    return trim(implode('', $out));
};
warpAssert($sh('XRAY_IPS="10.10.0.9 "') === '10.10.0.9', 'берётся адрес из docker-DNS');
warpAssert($sh('') === '10.10.0.9', 'при неудачном резолве — фолбэк на штатный адрес xray');
warpAssert($sh('WARP_SOCKS_ALLOW="10.20.0.5 10.20.0.6" XRAY_IPS="10.10.0.9"') === '10.20.0.5 10.20.0.6', 'override перекрывает резолв');
warpAssert(
    strpos($startWp, "XRAY_IPS=\$(getent hosts xr") < strpos($startWp, "printf 'nameserver 1.1.1.1"),
    'резолв идёт ДО перезаписи resolv.conf, пока docker-DNS ещё доступен'
);

// ── 3. Выключатель: флаг обязан переживать watchdog ────────────────────────
warpAssert(strpos($startWp, 'warp_disabled()') !== false, 'скрипт умеет читать флаг warpoff');
warpAssert(
    substr_count($startWp, 'if warp_disabled; then') >= 2,
    'флаг проверяется и на старте, и в watchdog (иначе сторож поднимет туннель обратно)'
);
// Ищем именно ВЫЗОВЫ (строковые литералы команд), а не упоминания в
// комментариях: warp-cli/warp-svc в образе wp отсутствуют.
warpAssert(
    !preg_match('~[\'"][^\'"\n]*warp-(cli|svc)~', $botSrc),
    'в боте не осталось вызовов warp-cli/warp-svc — их нет в образе wp'
);
warpAssert(
    strpos($botSrc, "wg-quick down /etc/warp/wgcf-profile.conf") !== false,
    'выключение делается тем же способом, что и включение (wg-quick)'
);

// ── 4. Секреты не утекают в чат ────────────────────────────────────────────
warpAssert(
    strpos($botSrc, "file_get_contents('/etc/warp/wgcf-account.toml')") === false,
    'меню не читает wgcf-account.toml (в нём private_key и access_token аккаунта)'
);
warpAssert(
    !preg_match('~\$text\[\] = "<pre>\$[ac]</pre>";~', $botSrc),
    'профиль и аккаунт больше не печатаются в чат целиком'
);
warpAssert(strpos($startWp, 'chmod 600 "$WGCF_TOML"') !== false, 'аккаунт wgcf получает права 0600');

// ── 5. Профиль: разбор и фиксапы ───────────────────────────────────────────
warpAssert(strpos($fixup, "sed -i '/^DNS[[:space:]]*=/d'") !== false, 'DNS= вырезается (resolvconf ломает wg-quick в docker)');
warpAssert(strpos($fixup, 'PersistentKeepalive') !== false, 'PersistentKeepalive добавляется — по нему probe судит о живости');
// IPv6 удаляется ИЗ СПИСКА, а не строкой целиком: wgcf >= 2.2.31 пишет
// "Address = <v4>, <v6>" одной строкой, и delete-sed снёс бы и v4.
$tmp = tempnam(sys_get_temp_dir(), 'wgcf');
file_put_contents($tmp, "[Interface]\nPrivateKey = k\nAddress = 172.16.0.2/32, 2606:4700:110:8a:b:c:d:e/128\nDNS = 1.1.1.1\nMTU = 1280\n[Peer]\nPublicKey = p\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = engage.cloudflareclient.com:2408\n");
exec('WGCF_CONF=' . escapeshellarg($tmp) . ' sh ' . escapeshellarg(__DIR__ . '/../scripts/warp_fixup.sh') . ' 2>&1', $o, $rc);
$fixed = file_get_contents($tmp);
warpAssert($rc === 0, 'warp_fixup.sh отрабатывает без ошибок');
warpAssert((bool) preg_match('~^Address = 172\.16\.0\.2/32\s*$~m', $fixed), 'v4-адрес уцелел, v6 вырезан из списка');
warpAssert((bool) preg_match('~^AllowedIPs = 0\.0\.0\.0/0\s*$~m', $fixed), 'v4-маршрут уцелел, ::/0 вырезан');
warpAssert(!preg_match('~^DNS~m', $fixed), 'строка DNS удалена');
warpAssert((bool) preg_match('~^PersistentKeepalive = 25$~m', $fixed), 'keepalive добавлен');
// Повторный прогон ничего не должен менять.
$before = $fixed;
exec('WGCF_CONF=' . escapeshellarg($tmp) . ' sh ' . escapeshellarg(__DIR__ . '/../scripts/warp_fixup.sh') . ' 2>&1');
warpAssert(file_get_contents($tmp) === $before, 'warp_fixup.sh идемпотентен');

// getWarpProfile() обязан разобрать этот же файл.
$box = new class ($tmp) extends Bot {
    private $f;
    public function __construct($f)
    {
        $this->f = $f;
        $this->warpprofile = null;
    }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
    {
        return file_get_contents($this->f);
    }
};
$prof = $box->getWarpProfile();
warpAssert(is_array($prof), 'профиль разобран');
warpAssert(($prof['server'] ?? '') === 'engage.cloudflareclient.com', 'endpoint-хост');
warpAssert(($prof['port'] ?? 0) === 2408, 'endpoint-порт');
warpAssert(($prof['ip'] ?? '') === '172.16.0.2', 'адрес интерфейса без маски');
warpAssert(($prof['mtu'] ?? 0) === 1280, 'mtu');
@unlink($tmp);

// ── 6. Проба живости ───────────────────────────────────────────────────────
warpAssert(strpos($probe, 'socks5h://127.0.0.1') !== false, 'проба ходит через сам SOCKS (socks5h — резолв в туннеле)');
warpAssert(strpos($probe, "warp=(on|plus)") !== false, 'проба требует именно warp=on|plus, а не просто ответ');
warpAssert(strpos($probe, 'sort -n | tail -1') !== false, 'fallback берёт свежайший handshake среди пиров');
warpAssert(strpos($botSrc, "socks5h://wp:1080") !== false, 'статус в боте тоже читается через socks5h');
warpAssert(!preg_match('~curl -m 1 -x socks5://wp:1080~', $botSrc), 'у проверки статуса больше не однесекундный таймаут');

if ($failed) {
    echo "$failed test(s) failed\n";
    exit(1);
}
echo "warp: all checks passed\n";
