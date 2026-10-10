<?php
// WARP через MASQUE, часть бота: переключение режима и транспорта, кнопка
// «включить», смена ключа WARP+, возврат из копии, меню и справка.
//
// Команды бота исполняются по-настоящему вместе со скриптами контейнера
// (warp_masque.sh, warp_fixup.sh); подменены только wgcf, curl, ядро прокси,
// wg и сторож контейнера: он здесь — функция, которая после сигнала бота
// (touch /run/warp-kick) пишет отметку режима, как это делает start_wp.sh.
require_once __DIR__ . '/../app/bot.php';
set_error_handler(static function ($level, $message, $file, $line) { if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line); return true; });

foreach (['jq', 'openssl'] as $tool) {
    if (trim((string) shell_exec("command -v $tool 2>/dev/null")) === '') {
        echo "warp_masque_bot_test SKIP: нужен $tool\n";
        exit(0);
    }
}

class WarpMasqueBot extends Bot
{
    public array $t_commands = [];
    public array $t_sent = [];
    public array $t_menu = [];
    public array $t_buttons = [];
    public string $t_fail = '';
    public string $t_api = 'ok';
    public string $t_trace = 'on';
    public string $t_core = '26.10.10';
    public bool $t_noScript = false;
    public bool $t_transportFailure = false;
    public bool $t_renderMenu = false;
    public array $t_linkOk = ['wireguard' => true, 'masque' => true];
    public bool $t_probeOk = true;
    public int $t_pauses = 0;

    public function __construct(public string $root)
    {
        $this->pac = "$root/pac.json";
        $this->input = ['chat' => 1, 'from' => 1, 'message_id' => 1, 'callback_id' => 'cb', 'username' => 'admin', 'callback' => '', 'message' => ''];
        $this->language = 'ru';
        require __DIR__ . '/../app/i18n.php';
        $this->i18n = $i;
    }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
    protected function warpPause(int $seconds): void { $this->t_pauses++; }
    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false, $entities = false, $forum = false) { $this->t_sent[] = [$text, $button]; return []; }
    public function sendDraft($chat, $draft_id, $text = '', $mode = 'HTML') {}
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML') { $this->t_menu[] = $text; $this->t_buttons = $button ?: []; return []; }
    public function warpVersion(): string { return 'wgcf 2.3.0'; }
    public function getWarpProfile() { return false; }
    public function warp() { if ($this->t_renderMenu) parent::warp(); }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
    {
        $this->t_commands[] = $cmd;
        $this->sshFailed = $this->t_transportFailure;
        if ($this->t_transportFailure) return '';
        $run = strtr($cmd, [
            '/etc/warp' => "$this->root/warp",
            '/warp_fixup.sh' => realpath(__DIR__ . '/../scripts/warp_fixup.sh'),
            '/warp_masque.sh' => $this->t_noScript ? "$this->root/absent.sh" : realpath(__DIR__ . '/../scripts/warp_masque.sh'),
            '/warp_probe.sh' => "$this->root/bin/probe",
            '/run/' => "$this->root/run/",
        ]);
        $env = getenv();
        $env['PATH'] = "$this->root/bin:" . $env['PATH'];
        $env += ['WARP_TEST_ROOT' => $this->root, 'WARP_TEST_FAIL' => $this->t_fail, 'WARP_TEST_API' => $this->t_api, 'WARP_TEST_TRACE' => $this->t_trace,
            'WARP_TEST_CORE' => $this->t_core, 'WARP_TEST_PROBE' => $this->t_probeOk ? '1' : '0', 'WGCF_CONF' => "$this->root/warp/wgcf-profile.conf",
            'WARP_MASQUE_DIR' => "$this->root/warp/masque", 'WARP_PAC' => $this->pac, 'WARP_RUN_DIR' => "$this->root/run"];
        $p = proc_open(['sh', '-c', $run], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'a']], $pipes, null, $env);
        fclose($pipes[0]); $out = stream_get_contents($pipes[1]); fclose($pipes[1]); proc_close($p);
        if (str_contains($cmd, 'warp-kick')) $this->watchdog();
        return $out;
    }
    // То, что делает сторож start_wp.sh, получив сигнал: переключает режим
    // по флагам pac.json и ставит отметку, только если туннель поднялся.
    public function watchdog(): void
    {
        $p = $this->getPacConf();
        $mode = $this->warpMode($p);
        @unlink("$this->root/run/warp-mode");
        if ($mode === 'masque' || !empty($p['warpoff']) || empty($this->t_linkOk['wireguard'])) @unlink("$this->root/up");
        if (!empty($p['warpoff']) || empty($this->t_linkOk[$mode])) return;
        if ($mode === 'wireguard') touch("$this->root/up");
        file_put_contents("$this->root/run/warp-mode", self::warpModeMark($mode, $this->warpMasqueH2($p)) . "\n");
    }
    public function route(string $callback): void { $this->input['callback'] = $callback; $this->action(); }
    public function ran(string $needle): int { return count(array_filter($this->t_commands, static fn($c) => str_contains($c, $needle))); }
    public function calls(string $needle): int { return substr_count((string) @file_get_contents("$this->root/calls"), $needle); }
    public function device(): string { return (string) (json_decode((string) @file_get_contents("$this->root/warp/masque/device.json"), true)['id'] ?? ''); }
    public function lastText(): string { return (string) (end($this->t_sent)[0] ?? ''); }
}

$root = sys_get_temp_dir() . '/vpnbot-warp-masque-' . bin2hex(random_bytes(6));
mkdir("$root/bin", 0700, true);
$fake = <<<'SH'
#!/bin/sh
name=${0##*/}
printf '%s %s\n' "$name" "$*" >> "$WARP_TEST_ROOT/calls"
arg_after() { want=$1; shift; while [ $# -gt 1 ]; do if [ "$1" = "$want" ]; then printf '%s' "$2"; return 0; fi; shift; done; return 1; }
case "$name" in
  probe) [ "$WARP_TEST_PROBE" = 1 ]; exit $? ;;
  pkill) exit 0 ;;
  sleep) case "$1" in 1) exit 0 ;; *) exec /bin/sleep "$@" ;; esac ;;
  wg-quick)
    case "$1" in
      up) [ "$WARP_TEST_FAIL" != up ] || exit 1; touch "$WARP_TEST_ROOT/up" ;;
      down) rm -f "$WARP_TEST_ROOT/up" ;;
    esac ;;
  wg)
    [ -f "$WARP_TEST_ROOT/up" ] || exit 1
    case "$3" in
      latest-handshakes) [ "$WARP_TEST_FAIL" = handshake ] || printf 'PEER\t1760000000\n' ;;
      fwmark) echo 0xca6c ;;
    esac ;;
  wgcf)
    config=$(arg_after --config "$@") || config=wgcf-account.toml
    masque=0; case "$*" in *vpnbot-masque*) masque=1 ;; esac; case "$config" in */masque*) masque=1 ;; esac
    case "$1" in
      register)
        [ "$WARP_TEST_FAIL" != register ] || exit 1
        { [ "$WARP_TEST_FAIL" != masque-register ] || [ "$masque" = 0 ]; } || exit 1
        [ ! -s "$config" ] || exit 1
        n=$(cat "$WARP_TEST_ROOT/devices" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > "$WARP_TEST_ROOT/devices"
        printf "access_token = 'token-%s'\ndevice_id = 'device-%s'\nlicense_key = 'free'\nprivate_key = 'NEW-WG-KEY'\n" "$n" "$n" > "$config" ;;
      update)
        [ "$WARP_TEST_FAIL" != update ] || exit 1
        { [ "$WARP_TEST_FAIL" != masque-update ] || [ "$masque" = 0 ]; } || exit 1 ;;
      generate) printf '[Interface]\nPrivateKey = NEW\nAddress = 172.16.0.2/32\n[Peer]\nPublicKey = PEER\nEndpoint = engage.cloudflareclient.com:2408\nAllowedIPs = 0.0.0.0/0\n' > wgcf-profile.conf ;;
    esac ;;
  warp-socks|warp-masque-check)
    case "$1" in
      version) echo "Xray $WARP_TEST_CORE (Xray, Penetrates Everything.) test" ;;
      run) [ "$2" != -test ] || exit 0; touch "$WARP_TEST_ROOT/check-ran"; exec /bin/sleep 20 ;;
    esac ;;
  curl)
    url=''; for a in "$@"; do case "$a" in http*) url=$a ;; esac; done
    case "$url" in
      *cdn-cgi/trace) [ "$WARP_TEST_TRACE" = none ] || printf 'warp=%s\n' "$WARP_TEST_TRACE"; exit 0 ;;
    esac
    cat > /dev/null
    out=$(arg_after -o "$@"); key=$(arg_after -d "$@" | jq -r .key)
    [ "$WARP_TEST_API" != http500 ] || { printf 500; exit 0; }
    id=$(printf '%s' "$url" | sed 's|.*/reg/||')
    jq -n --arg id "$id" --arg key "$key" --arg public "$(cat "$WARP_TEST_ROOT/endpoint.pub.pem")" '{
      id: $id, key: $key, key_type: "secp256r1", tunnel_type: "masque", warp_enabled: true, account: {account_type: "free", warp_plus: true},
      config: {peers: [{public_key: $public, endpoint: {v4: "162.159.198.2:0", v6: "[2606:4700:103::2]:0"}}], interface: {addresses: {v4: "172.16.0.2", v6: "2606:4700::2"}}}}' > "$out"
    printf 200 ;;
esac
SH;
foreach (['wgcf', 'wg-quick', 'wg', 'pkill', 'sleep', 'curl', 'warp-socks', 'probe'] as $name) { file_put_contents("$root/bin/$name", $fake); chmod("$root/bin/$name", 0700); }
exec('openssl ecparam -name prime256v1 -genkey -noout 2>/dev/null | openssl pkey -pubout -out ' . escapeshellarg("$root/endpoint.pub.pem") . ' 2>/dev/null');

$failures = []; $checks = 0;
$check = static function ($ok, string $name) use (&$failures, &$checks) { $checks++; if (!$ok) $failures[] = $name; };
$remove = static function ($path) use (&$remove) {
    if (is_dir($path) && !is_link($path)) { foreach (array_diff(scandir($path), ['.', '..']) as $f) $remove("$path/$f"); rmdir($path); }
    elseif (file_exists($path) || is_link($path)) unlink($path);
};
// Сервер в заданном состоянии: режим, включён ли WARP, есть ли устройство MASQUE.
$reset = static function (string $mode = 'wireguard', bool $off = false, bool $account = false, string $license = '') use ($root, $remove): WarpMasqueBot {
    foreach (['warp', 'run', 'up', 'calls', 'devices', 'check-ran', 'pac.json'] as $f) $remove("$root/$f");
    mkdir("$root/warp"); mkdir("$root/run");
    $b = new WarpMasqueBot($root);
    $b->setPacConf(['domain' => 'example.test'] + ($license !== '' ? ['warp' => $license] : []) + ($off ? ['warpoff' => 1] : []) + ($mode === 'masque' ? ['warp_mode' => 'masque'] : []));
    file_put_contents("$root/warp/wgcf-account.toml", 'ORIGINAL ACCOUNT');
    file_put_contents("$root/warp/wgcf-profile.conf", 'ORIGINAL PROFILE');
    if ($account) {
        $b->ssh(($license !== '' ? "WARP_LICENSE_KEY='$license' " : "WARP_LICENSE_KEY='' ") . 'sh /warp_masque.sh register && sh /warp_masque.sh commit', 'wp');
    }
    $b->watchdog();
    $b->t_commands = []; @unlink("$root/calls");
    return $b;
};

try {
    // ---- режим по настройкам ------------------------------------------------
    $b = $reset();
    $check($b->warpMode([]) === 'wireguard' && $b->warpMode(['warp_mode' => 'masque']) === 'masque' && $b->warpMode(['warp_mode' => 'other']) === 'wireguard', 'режим по умолчанию — WireGuard, неизвестное значение тоже');
    $check(Bot::warpModeMark('masque', false) === 'masque h3' && Bot::warpModeMark('masque', true) === 'masque h2' && Bot::warpModeMark('wireguard', true) === 'wireguard', 'отметка режима совпадает с тем, что пишет сторож');
    $start = file_get_contents(__DIR__ . '/../scripts/start_wp.sh');
    $check(str_contains($start, 'if [ "$1" = masque ]; then echo "masque $2"; else echo wireguard; fi') && str_contains($start, 'mode_name "$MODE" "$ALPN" > /run/warp-mode'), 'сторож пишет отметку в том же виде');

    // ---- образ не готов ------------------------------------------------------
    $b = $reset(); $b->t_noScript = true; $b->warpSwitchMode();
    $check($b->warpMode() === 'wireguard' && str_contains($b->lastText(), 'не поддерживает MASQUE') && $b->calls('wgcf') === 0, 'контейнер без скрипта режима: отказ с объяснением, ничего не тронуто');
    $b = $reset(); $b->t_core = '26.9.30'; $b->warpSwitchMode();
    $check($b->warpMode() === 'wireguard' && str_contains($b->lastText(), '26.10.10') && str_contains($b->lastText(), '<code>26.9.30</code>'), 'старое ядро в контейнере: отказ с версией');
    $b = $reset(); $b->t_transportFailure = true; $b->warpSwitchMode();
    $check($b->warpMode() === 'wireguard' && str_contains($b->lastText(), 'не отвечает'), 'контейнер недоступен: отказ, режим прежний');
    $b = $reset(); $b->setPacConf(['warp' => 'not a key!'] + $b->getPacConf()); $b->warpSwitchMode();
    $check($b->warpMode() === 'wireguard' && $b->calls('wgcf') === 0, 'в настройках лежит не ключ WARP+: команда с ним не собирается');
    // Значение из настроек подставляется в команду оболочки: кавычка в нём не должна её разорвать.
    $b = $reset(); $b->setPacConf(['warp' => "x'; touch $root/pwned; '"] + $b->getPacConf()); $b->warpSwitchMode();
    $check(!file_exists("$root/pwned") && $b->ran('pwned') === 0 && $b->warpMode() === 'wireguard', 'ключ с кавычкой не попадает в команду оболочки');
    $b = $reset('masque', true, true); $b->setPacConf(['warp' => "x'; touch $root/pwned; '"] + $b->getPacConf()); $b->addWarpPlus("y'; touch $root/pwned; '");
    $check(!file_exists("$root/pwned") && $b->ran('pwned') === 0, 'и новый ключ с кавычкой отклоняется до любых команд');

    // ---- WireGuard → MASQUE --------------------------------------------------
    $b = $reset();
    $b->warpSwitchMode();
    $check($b->warpMode() === 'masque' && str_contains($b->lastText(), '✅') && str_contains($b->lastText(), 'MASQUE (HTTP/3)'), 'первое переключение на MASQUE');
    $check($b->calls('wgcf register') === 1 && $b->device() === 'device-1' && !file_exists("$root/warp/masque/.pending") && !is_dir("$root/warp/masque.old"), 'устройство зарегистрировано один раз и подтверждено');
    $check(is_file("$root/check-ran") && trim(file_get_contents("$root/run/warp-mode")) === 'masque h3', 'перед переключением было пробное подключение, сторож отметил режим');
    $order = array_values(array_filter(array_map(static fn($c) => str_contains($c, 'register') ? 'register' : (str_contains($c, ' check ') ? 'check' : (str_contains($c, 'warp-kick') ? 'kick' : null)), $b->t_commands)));
    $check($order === ['register', 'check', 'kick'], 'порядок: регистрация, пробное подключение, и только потом сигнал сторожу');
    $check(file_get_contents("$root/warp/wgcf-account.toml") === 'ORIGINAL ACCOUNT', 'аккаунт WireGuard не тронут');
    $check($b->ran('WARP_LICENSE_STRICT=1') === 1, 'регистрация по просьбе администратора строгая к ключу WARP+');

    $b = $reset('wireguard', false, true);
    $b->warpSwitchMode();
    $check($b->warpMode() === 'masque' && $b->calls('wgcf register') === 0 && is_file("$root/check-ran"), 'устройство уже есть: повторной регистрации нет, проба есть');

    $b = $reset('wireguard', false, true);
    $b->setPacConf(['warp' => 'NEW-KEY-1'] + $b->getPacConf());
    $before = $b->device();
    $b->warpSwitchMode();
    $check($b->warpMode() === 'masque' && $b->calls('wgcf register') === 1 && $b->device() !== $before && $b->calls('wgcf update') === 1, 'ключ WARP+ сменили после регистрации: устройство перерегистрировано с новым ключом');

    // ---- отказы до переключения: работающий режим не затронут ---------------
    $b = $reset(); $b->t_trace = 'off';
    $b->warpSwitchMode();
    $check($b->warpMode() === 'wireguard' && str_contains($b->lastText(), 'Пробное подключение') && !is_dir("$root/warp/masque"), 'MASQUE с сервера недоступен: режим прежний, новое устройство убрано');
    $check($b->ran('warp-kick') === 0 && is_file("$root/up") && $b->calls('wg-quick') === 0, 'WireGuard при этом не останавливался, сторож не тревожился');
    $b = $reset('wireguard', false, true); $b->t_trace = 'none'; $kept = $b->device();
    $b->warpSwitchMode();
    $check($b->warpMode() === 'wireguard' && $b->device() === $kept, 'проба не прошла при уже существующем устройстве: оно остаётся');
    $b = $reset(); $b->t_fail = 'masque-register';
    $b->warpSwitchMode();
    $check($b->warpMode() === 'wireguard' && str_contains($b->lastText(), 'не зарегистрировано') && !is_file("$root/check-ran") && $b->ran('warp-kick') === 0, 'регистрация не удалась: до пробы и переключения не дошло');
    $b = $reset('wireguard', false, false, 'PLUS-KEY'); $b->t_fail = 'masque-update';
    $b->warpSwitchMode();
    $check($b->warpMode() === 'wireguard' && !is_dir("$root/warp/masque"), 'ключ WARP+ не применился к устройству MASQUE: отказ, а не тихий бесплатный тариф');
    $b = $reset(); $b->t_api = 'http500';
    $b->warpSwitchMode();
    $check($b->warpMode() === 'wireguard' && !is_dir("$root/warp/masque"), 'Cloudflare отклонил привязку ключа: режим прежний');

    // ---- сторож не смог поднять новый режим: возврат ------------------------
    $b = $reset(); $b->t_linkOk['masque'] = false;
    $b->warpSwitchMode();
    $check($b->warpMode() === 'wireguard' && str_contains($b->lastText(), 'возвращён прежний') && $b->ran('warp-kick') === 2, 'MASQUE не поднялся после переключения: настройка возвращена, сторож разбужен дважды');
    $check(trim((string) @file_get_contents("$root/run/warp-mode")) === 'wireguard' && $b->t_pauses >= 5, 'после возврата снова работает WireGuard; бот ждал, а не сдался сразу');
    $b = $reset(); $b->t_probeOk = false;
    $b->warpSwitchMode();
    $check($b->warpMode() === 'wireguard', 'отметка режима есть, но проба через прокси молчит: MASQUE рабочим не считается');

    // ---- MASQUE → WireGuard ---------------------------------------------------
    $b = $reset('masque', false, true);
    $b->warpSwitchMode();
    $check($b->warpMode() === 'wireguard' && str_contains($b->lastText(), 'WireGuard') && $b->calls('wgcf register') === 0 && !is_file("$root/check-ran"), 'обратно на WireGuard: без обращений к Cloudflare и без пробы');
    $check($b->device() !== '', 'устройство MASQUE сохраняется для следующего раза');
    $b = $reset('masque', false, true); $b->t_linkOk['wireguard'] = false;
    $b->warpSwitchMode();
    $check($b->warpMode() === 'masque' && str_contains($b->lastText(), 'возвращён прежний') && trim((string) @file_get_contents("$root/run/warp-mode")) === 'masque h3', 'WireGuard не поднялся (заблокирован): возврат в MASQUE');
    $b = $reset('masque', false, true); $b->t_probeOk = false;
    $b->warpSwitchMode();
    $check($b->warpMode() === 'wireguard', 'для WireGuard достаточно отметки сторожа: она ставится только после рукопожатия');

    // ---- выключенный WARP: меняется только настройка ------------------------
    $b = $reset('wireguard', true);
    $b->warpSwitchMode();
    $check($b->warpMode() === 'masque' && !empty($b->getPacConf()['warpoff']) && $b->t_pauses === 0 && is_file("$root/check-ran"), 'при выключенном WARP режим меняется без ожидания, но проба MASQUE всё равно идёт');

    // ---- транспорт MASQUE -----------------------------------------------------
    $b = $reset('masque', false, true);
    $b->warpMasqueHttp();
    $check($b->warpMasqueH2() && str_contains($b->lastText(), 'MASQUE (HTTP/2)') && trim(file_get_contents("$root/run/warp-mode")) === 'masque h2' && $b->ran(' check h2') === 1, 'HTTP/3 → HTTP/2 с пробой нового транспорта');
    $b->warpMasqueHttp();
    $check(!$b->warpMasqueH2() && !array_key_exists('warp_masque_h2', $b->getPacConf()) && $b->ran(' check h3') === 1, 'и обратно: флаг убирается из настроек');
    $b = $reset('masque', false, true); $b->t_trace = 'off';
    $b->warpMasqueHttp();
    $check(!$b->warpMasqueH2() && $b->ran('warp-kick') === 0 && str_contains($b->lastText(), 'транспорт не изменён'), 'новый транспорт недоступен: работающий не затронут');
    $b = $reset('masque', false, true); $b->t_linkOk['masque'] = false;
    $b->warpMasqueHttp();
    $check(!$b->warpMasqueH2() && $b->ran('warp-kick') === 2, 'транспорт не поднялся: настройка возвращена');
    $b = $reset('wireguard');
    $b->warpMasqueHttp();
    $check(!$b->t_commands && !$b->t_sent, 'в режиме WireGuard кнопка транспорта ничего не делает');

    // ---- включение и выключение в режиме MASQUE -----------------------------
    $b = $reset('masque', true, true);
    $b->offWarp();
    $check(empty($b->getPacConf()['warpoff']) && trim(file_get_contents("$root/run/warp-mode")) === 'masque h3' && $b->calls('wg-quick up') === 0, 'включение в MASQUE: без wg-quick up, по ответу пробы');
    $b = $reset('masque', true, true); $b->t_probeOk = false;
    $b->offWarp();
    $check(!empty($b->getPacConf()['warpoff']) && str_contains($b->lastText(), 'по MASQUE не поднялся') && $b->ran('pkill -x warp-socks') === 1, 'включение не удалось: переключатель снова выключен, прокси остановлен');
    $b = $reset('masque', false, true);
    $b->offWarp();
    $check(!empty($b->getPacConf()['warpoff']) && $b->ran('pkill -x warp-socks') === 1 && $b->ran('warp-kick') === 0, 'выключение в MASQUE останавливает прокси сразу');
    $b = $reset('wireguard', true);
    $b->offWarp();
    $check(empty($b->getPacConf()['warpoff']) && $b->calls('wg-quick up') === 1, 'в режиме WireGuard кнопка «включить» работает по-прежнему');

    // ---- смена ключа WARP+ в режиме MASQUE -----------------------------------
    $b = $reset('masque', false, true, 'OLD-KEY'); $old = $b->device();
    $b->addWarpPlus('NEW-KEY');
    $check($b->getPacConf()['warp'] === 'NEW-KEY' && $b->device() !== $old && !file_exists("$root/warp/masque/.pending") && !is_dir("$root/warp/masque.old"), 'новый ключ: устройство MASQUE перерегистрировано и подтверждено');
    $check(str_contains(file_get_contents("$root/warp/wgcf-account.toml"), 'NEW-WG-KEY') && $b->calls('wg-quick up') === 0 && $b->warpMode() === 'masque', 'аккаунт WireGuard тоже обновлён, но туннель WireGuard не поднимался');
    $check(empty($b->getPacConf()['warpoff']) && $b->ran('warp-kick') === 1 && !is_dir("$root/warp/.bak") && $b->ran(' check h3') === 1, 'после смены: проба, сигнал сторожу, копия убрана');
    $check(hash('sha256', 'NEW-KEY') === trim(file_get_contents("$root/warp/masque/license.sha256")), 'устройство MASQUE помнит новый ключ');
    foreach (['masque-register' => 'регистрация MASQUE', 'masque-update' => 'ключ на устройстве MASQUE'] as $fail => $label) {
        $b = $reset('masque', false, true, 'OLD-KEY'); $old = $b->device(); $b->t_fail = $fail;
        $b->addWarpPlus('NEW-KEY');
        $check($b->getPacConf()['warp'] === 'OLD-KEY' && $b->device() === $old && file_get_contents("$root/warp/wgcf-account.toml") === 'ORIGINAL ACCOUNT' && $b->warpMode() === 'masque',
            "смена ключа, отказ ($label): прежний ключ, прежнее устройство MASQUE и прежний аккаунт WireGuard");
        $check(empty($b->getPacConf()['warpoff']) && !is_dir("$root/warp/.bak") && $b->calls('wg-quick up') === 0, "смена ключа, отказ ($label): WARP снова включён, туннель WireGuard не поднимался");
    }
    $b = $reset('masque', false, true, 'OLD-KEY'); $old = $b->device(); $b->t_trace = 'off';
    $b->addWarpPlus('NEW-KEY');
    $check($b->getPacConf()['warp'] === 'OLD-KEY' && $b->device() === $old && !file_exists("$root/warp/masque/.pending"), 'смена ключа, проба нового устройства не прошла: откат к прежнему устройству');
    $b = $reset('masque', true, true, 'OLD-KEY'); $b->t_trace = 'off';
    $b->addWarpPlus('NEW-KEY');
    $check($b->getPacConf()['warp'] === 'NEW-KEY' && !empty($b->getPacConf()['warpoff']) && $b->ran(' check ') === 0, 'при выключенном WARP ключ меняется без пробы, выключатель остаётся');
    $b = $reset('wireguard', false, true, 'OLD-KEY'); $old = $b->device();
    $b->addWarpPlus('NEW-KEY');
    $check($b->device() === $old && $b->calls('wg-quick up') === 1, 'в режиме WireGuard смена ключа устройство MASQUE не трогает (перерегистрируется при переключении)');

    // ---- оборванная смена ключа в режиме MASQUE ------------------------------
    $b = $reset('masque', false, true); $old = $b->device();
    $b->ssh("WARP_LICENSE_KEY='' sh /warp_masque.sh register", 'wp');
    mkdir("$root/warp/.bak", 0700); file_put_contents("$root/warp/.bak/wgcf-account.toml", 'PAID ACCOUNT');
    $pending = $b->device(); $b->t_commands = []; @unlink("$root/calls");
    $b->warpBackup('restore');
    $check($b->device() === $old && $pending !== $old && file_get_contents("$root/warp/wgcf-account.toml") === 'PAID ACCOUNT' && $b->calls('wg-quick up') === 0 && $b->ran('warp-kick') === 1,
        'возврат из копии в MASQUE: прежнее устройство MASQUE и аккаунт WireGuard, без wg-quick up');
    $b = $reset('masque', false, true);
    $b->ssh("WARP_LICENSE_KEY='' sh /warp_masque.sh register", 'wp'); $pending = $b->device();
    mkdir("$root/warp/.bak", 0700);
    $b->warpBackup('drop');
    $check($b->device() === $pending && !file_exists("$root/warp/masque/.pending") && !is_dir("$root/warp/masque.old") && !is_dir("$root/warp/.bak"), 'удаление копии подтверждает новое устройство MASQUE');

    // ---- маршруты, меню, справка ----------------------------------------------
    $b = $reset('masque', false, true); $b->t_renderMenu = true;
    $b->route('/warpMasqueHttp');
    $check($b->warpMasqueH2(), 'кнопка транспорта подключена');
    $b->route('/warpMode');
    $check($b->warpMode() === 'wireguard', 'кнопка режима подключена');
    $b = $reset('masque', false, true); $b->t_renderMenu = true;
    $b->warp();
    $text = end($b->t_menu); $data = [];
    foreach ($b->t_buttons as $row) foreach ($row as $button) $data[$button['callback_data']] = $button['text'];
    $check(str_contains($text, 'режим: <b>MASQUE (HTTP/3)</b>') && str_contains($text, 'устройство MASQUE: <code>device-1…</code>') && str_contains($text, '<code>162.159.198.2</code>') && str_contains($text, 'тариф <code>free</code>'), 'меню в MASQUE: режим, устройство, узел и тариф');
    $check(str_contains($text, "status: <pre>warp=on</pre>") && $b->ran('socks5h://127.0.0.1:1080') === 1 && $b->ran('wgcf trace') === 0, 'состояние в MASQUE берётся через прокси, а не напрямую');
    $check(!str_contains($text, 'рукопожатие') && !str_contains($text, 'профиль не найден') && !str_contains($text, 'PRIVATE') && !str_contains($text, 'token-'), 'в MASQUE нет строк WireGuard и нет секретов устройства');
    $check(($data['/warpMode'] ?? '') === 'режим: MASQUE (HTTP/3) → WireGuard' && ($data['/warpMasqueHttp'] ?? '') === 'транспорт MASQUE: HTTP/3 → HTTP/2', 'кнопки режима и транспорта говорят, что произойдёт');
    $check(isset($data['/warpPlus'], $data['/offWarp'], $data['/menuhelp warp 0'], $data['/menu']), 'прежние кнопки меню на месте');
    $b = $reset(); $b->t_renderMenu = true;
    $b->warp();
    $text = end($b->t_menu); $data = [];
    foreach ($b->t_buttons as $row) foreach ($row as $button) $data[$button['callback_data']] = $button['text'];
    $check(str_contains($text, 'режим: <b>WireGuard</b>') && ($data['/warpMode'] ?? '') === 'режим: WireGuard → MASQUE' && !isset($data['/warpMasqueHttp']) && $b->ran('wgcf trace') === 1, 'меню в WireGuard: кнопки транспорта нет, состояние как раньше');
    $b->language = 'en';
    $b->warp();
    $check(str_contains(end($b->t_menu), 'mode: <b>WireGuard</b>'), 'меню на английском');

    // Страницы о MASQUE только на русском — на обоих языках интерфейса одни и те же.
    $b->language = 'en';
    $english = $b->menuHelpContent('warp')[2];
    $b->language = 'ru';
    [$title, $back, $pages] = $b->menuHelpContent('warp');
    $check($title === 'WARP' && $back === '/warp' && count($pages) === 5, 'в справке WARP пять страниц, возврат в меню WARP');
    foreach (['Режим: WireGuard или MASQUE', 'MASQUE: транспорт, ключ и неполадки'] as $name) {
        $check(isset($pages[$name]) && ($english[$name] ?? null) === $pages[$name], "страница справки есть и одинакова на обоих языках: $name");
    }
    $help = $pages['Режим: WireGuard или MASQUE'] . "\n" . $pages['MASQUE: транспорт, ключ и неполадки'];
    foreach (['MASQUE', 'WireGuard', 'HTTP/2', 'HTTP/3', '443', 'маршрутизации', 'пробное подключение', 'ss через warp', '26.10.10', 'утечки'] as $word) {
        $check(str_contains($help, $word), "справка рассказывает про: $word");
    }
    foreach ($pages as $name => $body) {
        $check(mb_strlen("$name\n\n$body") < 3900, "страница справки помещается в сообщение: $name");
        foreach (['b', 'code', 'i'] as $tag) $check(substr_count($body, "<$tag>") === substr_count($body, "</$tag>"), "разметка справки сбалансирована: $name");
    }
    $help = implode("\n", $b->menuHelpContent('warp')[2]);
    foreach (['warp mode', 'warp masque transport'] as $key) $check(str_contains($help, $b->i18n($key)), "справка называет кнопку как меню: $key");
    $source = file_get_contents(__DIR__ . '/../app/bot.php') . file_get_contents(__DIR__ . '/../app/BotWarpMasque.php');
    preg_match_all("~i18n\\('(warp m[a-z ]+)'\\)~", $source, $used);
    $check(count(array_unique($used[1])) >= 12, 'ключи сообщений режима найдены в коде');
    foreach (array_unique($used[1]) as $key) foreach (['en', 'ru'] as $language) { $b->language = $language; $check($b->i18n($key) !== $key && $b->i18n($key) !== '', "перевод $key/$language"); }
} finally {
    exec('pkill -f ' . escapeshellarg($root) . ' 2>/dev/null');
    $remove($root);
}
foreach ($failures as $failure) echo "FAIL: $failure\n";
echo 'warp_masque_bot: ' . ($checks - count($failures)) . "/$checks\n";
exit($failures ? 1 : 0);
