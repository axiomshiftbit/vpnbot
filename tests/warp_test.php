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
// прокси уже слушает, а ограничений ещё нет. Запуск теперь идёт через
// socks_start(), поэтому сравниваем с местом ВЫЗОВА, а не определения функции.
warpAssert(
    strpos($startWp, 'iptables -A WARP_SOCKS -j DROP') < strpos($startWp, 'if tunnel_up; then'),
    'фильтр ставится раньше запуска microsocks'
);

// ── 1b. Kill-switch: прокси живёт только вместе с туннелем ─────────────────
// microsocks слушал независимо от состояния wgcf-profile, а правила выше
// ограничивают только ВХОД в прокси. Без туннеля у контейнера остаётся
// обычный default route через docker-bridge, и трафик xray из outbound «warp»
// уходил с публичного IP сервера — молча, без следа в логах.
warpAssert(strpos($startWp, 'socks_start()') !== false && strpos($startWp, 'socks_stop()') !== false,
    'запуск и остановка прокси вынесены в функции');
warpAssert((bool) preg_match('~if tunnel_up; then\s*\n\s*socks_start~', $startWp),
    'на старте прокси поднимается только при живом туннеле');
warpAssert(strpos($startWp, 'warp_up || echo') !== false,
    'код возврата поднятия туннеля на старте проверяется');
warpAssert((bool) preg_match('~warp_up\(\)[^}]*wg-quick up "\$WGCF_CONF" \|\| return 1~s', $startWp),
    'warp_up() возвращает ошибку, если wg-quick не отработал');
warpAssert(strpos($startWp, 'latest-handshakes') !== false && strpos($startWp, 'warp_up()') !== false,
    'warp_up() ждёт настоящего рукопожатия: wg-quick up успешен и при мёртвом endpoint');
// Именно окно bounce'а и было главной утечкой.
warpAssert(
    strpos($startWp, 'socks_stop') < strpos($startWp, 'wg-quick down "$WGCF_CONF" 2>/dev/null
        if warp_up; then'),
    'при пере-поднятии туннеля прокси гасится ДО wg-quick down'
);
warpAssert((bool) preg_match('~if warp_disabled; then\s*\n\s*socks_stop~', $startWp),
    'при warpoff прокси закрыт: отказ вместо выхода мимо туннеля');

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

// ── 4. Меню warp: профиль и аккаунт показываются целиком ───────────────────
// Осознанное решение владельца: ключи из меню копируют в сторонние клиенты.
// Тест фиксирует это как намеренное поведение, чтобы вывод не «оптимизировали»
// обратно, и одновременно требует, чтобы чтение не падало на свежей установке.
warpAssert(
    (bool) preg_match('~\$text\[\] = "<pre>\$a</pre>";~', $botSrc),
    'wgcf-account.toml печатается в меню целиком'
);
warpAssert(
    (bool) preg_match('~\$text\[\] = "<pre>\$c</pre>";~', $botSrc),
    'wgcf-profile.conf печатается в меню целиком'
);
warpAssert(
    (bool) preg_match("~@file_get_contents\('/etc/warp/wgcf-account\.toml'\)~", $botSrc)
        && (bool) preg_match("~@file_get_contents\('/etc/warp/wgcf-profile\.conf'\)~", $botSrc),
    'файлы читаются с подавлением warning — на свежей установке их ещё нет'
);
warpAssert(
    strpos($botSrc, '"key: <code>" . ($p[\'warp\'] ?? \'\')') !== false,
    'лицензионный ключ показывается полностью, без Undefined-key при его отсутствии'
);
// Приложение бота работает от root (config/unit.json: "user": "root"),
// поэтому 0600 на файлах warp не мешает меню их прочитать.
warpAssert(
    strpos(file_get_contents(__DIR__ . '/../config/unit.json'), '"user": "root"') !== false,
    'unit запускает приложение от root — иначе профиль 0600 не прочитался бы'
);
warpAssert(strpos($startWp, 'chmod 600 "$WGCF_TOML"') !== false, 'аккаунт wgcf получает права 0600 на диске');

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

// ── 5b. Смена ключа не должна терять оплаченный аккаунт ────────────────────
// wgcf register — сетевой вызов к API Cloudflare, он падает. Раньше перед ним
// стоял rm -f обоих файлов, и на упавшей регистрации аккаунт с оплаченным
// WARP+ исчезал безвозвратно (private_key/token взять негде).
$addWarp = '';
if (preg_match('~public function addWarpPlus\(.*?\n    \}~s', $botSrc, $m)) {
    $addWarp = $m[0];
}
warpAssert($addWarp !== '', 'addWarpPlus найден');
warpAssert(strpos($addWarp, 'rm -f /etc/warp/wgcf-profile.conf') === false, 'старый аккаунт больше не удаляется безвозвратно');
warpAssert(strpos($addWarp, 'mv "$f" ".bak/$f"') !== false, 'старые файлы уходят в .bak до регистрации');
warpAssert(strpos($addWarp, '$restore = function ()') !== false, 'есть восстановление прежнего аккаунта');
// КАЖДЫЙ ранний выход после бэкапа обязан восстановить аккаунт, иначе часть
// веток по-прежнему оставляла бы пользователя без WARP+.
$afterBackup = substr($addWarp, strpos($addWarp, '$restore = function ()'));
$earlyExits  = preg_match_all('~\n\s+return;\n~', $afterBackup);
$restores    = substr_count($afterBackup, '$restore();');
warpAssert($restores >= $earlyExits - 1, "все ранние выходы восстанавливают аккаунт ($restores restore на $earlyExits return)");
warpAssert(strpos($addWarp, "rm -rf /etc/warp/.bak") !== false, 'на успешном пути бэкап убирается');
warpAssert(
    strpos($afterBackup, '$restore();') < strpos($afterBackup, "rm -rf /etc/warp/.bak"),
    'очистка .bak идёт последней, после всех точек восстановления'
);

// ── 5c. Персональный WARP-аккаунт на каждого клиента ───────────────────────
// Общий серверный ключ в клиентских конфигах означал бы, что сессии выбивают
// друг друга: у пира в WireGuard ровно один endpoint, и handshake с нового
// источника переписывает предыдущий.
$wdir = sys_get_temp_dir() . '/warpcli_' . getmypid();
@mkdir($wdir . '/clients', 0755, true);
$wbox = new class ($wdir) extends Bot {
    public $cmds = [];
    private $root;
    public function __construct($root)
    {
        $this->root       = $root;
        $this->warpclients = [];
    }
    public function warpClientDir($email)
    {
        return $this->root . '/clients/' . substr(sha1($email), 0, 8);
    }
    public function getPacConf(): array
    {
        return ['warp' => 'AAAA-BBBB-CCCC'];
    }
    // Эмулируем контейнер wp: команда register/generate «создаёт» профиль.
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
    {
        $this->cmds[] = $cmd;
        if (strpos($cmd, 'wgcf register') !== false
            && preg_match('~mkdir -p \x27([^\x27]+)\x27~', $cmd, $m)) {
            @mkdir($m[1], 0755, true);
            file_put_contents($m[1] . '/wgcf-profile.conf',
                "[Interface]\nPrivateKey = CLIENTKEY\nAddress = 172.16.0.7/32\nMTU = 1280\n"
                . "[Peer]\nPublicKey = PEERKEY\nAllowedIPs = 0.0.0.0/0\nEndpoint = engage.cloudflareclient.com:2408\n");
        }
        return '';
    }
};
$p1 = $wbox->warpClientProfile('alice@example.com');
warpAssert(is_array($p1) && ($p1['private-key'] ?? '') === 'CLIENTKEY', 'клиенту заводится персональный профиль');
$cmd = implode("\n", $wbox->cmds);
warpAssert(strpos($cmd, '--config wgcf-account.toml') !== false, 'wgcf работает в отдельном каталоге клиента (--config)');
warpAssert(strpos($cmd, '--profile wgcf-profile.conf') !== false, 'профиль пишется туда же (--profile)');
warpAssert(strpos($cmd, 'sh /warp_fixup.sh') !== false, 'к клиентскому профилю применяются те же фиксапы');
warpAssert(strpos($cmd, 'chmod 600') !== false, 'ключи клиента лежат с правами 0600');
warpAssert(strpos($cmd, 'license_key = "AAAA-BBBB-CCCC"') !== false, 'лицензионный ключ применяется и к клиентскому аккаунту');
warpAssert(strpos($cmd, '--name') !== false, 'устройство подписывается именем клиента (видно в панели 1.1.1.1)');

// Второй вызов не должен снова ходить в API.
$n = count($wbox->cmds);
$wbox->warpClientProfile('alice@example.com');
warpAssert(count($wbox->cmds) === $n, 'повторный вызов берёт готовый профиль из кэша');

// Разные клиенты — разные каталоги и, значит, разные ключи.
warpAssert(
    $wbox->warpClientDir('alice@example.com') !== $wbox->warpClientDir('bob@example.com'),
    'у разных клиентов разные каталоги аккаунтов'
);
$bot2 = (new ReflectionClass(Bot::class))->newInstanceWithoutConstructor();
warpAssert(
    !preg_match('~[^a-zA-Z0-9_./\-]~', $bot2->warpClientDir("a b;rm -rf /\n\$(id)")),
    'имя каталога санитайзится — email уходит в shell-команду'
);
warpAssert(
    $bot2->warpClientDir('x@y') === $bot2->warpClientDir('x@y'),
    'путь детерминирован'
);
warpAssert(
    $bot2->warpClientDir('a_b') !== $bot2->warpClientDir('a-b'),
    'разные email не схлопываются в один каталог после санитайза'
);

// Пустой email не должен приводить к общему каталогу на всех.
warpAssert($bot2->warpClientProfile('') === false, 'без email персональный профиль не выдаётся');

// Профиль генерируется ЛЕНИВО: только когда шаблон реально просит ключ.
warpAssert(
    strpos($botSrc, "str_contains(\$json, '~warp_private_key~')") !== false,
    'регистрация только при наличии warp-тега в шаблоне'
);
// Удаление клиента убирает и его аккаунт.
warpAssert(
    (bool) preg_match('~deleteHwidUser\(.*\n.*\n.*\n.*\n.*deleteWarpClient~', $botSrc),
    'delxr() удаляет персональный WARP-аккаунт клиента'
);
warpAssert(strpos($botSrc, "rm -rf ' . escapeshellarg(\$this->warpClientDir(\$email))") !== false, 'каталог клиента удаляется через escapeshellarg');

foreach (glob($wdir . '/clients/*/*') ?: [] as $f) {
    @unlink($f);
}
foreach (glob($wdir . '/clients/*') ?: [] as $d) {
    @rmdir($d);
}
@rmdir($wdir . '/clients');
@rmdir($wdir);

// ── 6. Проба живости ───────────────────────────────────────────────────────
warpAssert(strpos($probe, 'socks5h://127.0.0.1') !== false, 'проба ходит через сам SOCKS (socks5h — резолв в туннеле)');
warpAssert(strpos($probe, "warp=(on|plus)") !== false, 'проба требует именно warp=on|plus, а не просто ответ');
warpAssert(strpos($probe, 'sort -n | tail -1') !== false, 'fallback берёт свежайший handshake среди пиров');
warpAssert(strpos($botSrc, "socks5h://wp:1080") !== false, 'статус в боте тоже читается через socks5h');
warpAssert(!preg_match('~curl -m 1 -x socks5://wp:1080~', $botSrc), 'у проверки статуса больше не однесекундный таймаут');

// ── 7. Egress-ACL прокси ───────────────────────────────────────────────────
// Аудит 2026-08-19: вход в microsocks обязан быть открыт для xray (иначе у
// клиента отваливается ВЕСЬ WARP-маршрут — гейт бота держит для этого точечное
// правило), поэтому ограничение обязано стоять на ВЫХОДЕ: CONNECT в docker-сеть
// проекта через прокси запрещён.
warpAssert(strpos($startWp, 'WARP_SOCKS_OUT') !== false, 'у прокси есть цепочка ограничения исходящих');
warpAssert(strpos($startWp, '-d "$net" -j REJECT') !== false || strpos($startWp, '-d "$net" -j DROP') !== false,
    'исходящие в перечисленные сети отвергаются');
warpAssert(strpos($startWp, 'WARP_SOCKS_DENY_OUT:-10.10.0.0/16') !== false,
    'по умолчанию закрыта вся docker-сеть проекта');
$estPos = strpos($startWp, 'ESTABLISHED,RELATED -j ACCEPT');
$rejPos = strpos($startWp, '-d "$net" -j REJECT');
warpAssert($estPos !== false && $rejPos !== false && $estPos < $rejPos,
    'ответы на установленные сессии (ssh бота, ответы прокси) пропускаются РАНЬШЕ запрета');
warpAssert(strpos($startWp, 'WARP_SOCKS_OUT -o lo -j ACCEPT') !== false,
    'петля (healthcheck, warp_probe, docker-DNS) не задета');
warpAssert(preg_match('~if iptables -A WARP_SOCKS_OUT -m conntrack.*\n.*-m state~', $startWp) === 1,
    'без conntrack/state правило DENY не ставится вовсе — иначе оборвались бы ответные пакеты');

if ($failed) {
    echo "$failed test(s) failed\n";
    exit(1);
}
echo "warp: all checks passed\n";
