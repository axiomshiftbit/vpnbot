<?php
require_once __DIR__ . '/managed_protocol_fixture.php';
require_once __DIR__ . '/../app/bot.php';

function mpCheck(bool $ok, string $name): void { if (!$ok) throw new RuntimeException($name); }
function mpRemove(string $path): void {
    if (is_dir($path)) { foreach (scandir($path) as $f) if ($f !== '.' && $f !== '..') mpRemove("$path/$f"); rmdir($path); }
    else unlink($path);
}
class ManagedTestBot extends Bot {
    public array $commands = [];
    public array $conf = [];
    public bool $valid = true;
    public bool $applied = true;
    public function __construct() {}
    public function getPacConf() { return $this->conf + self::PAC_DEFAULTS; }
    public function getHashSubdomain($subdomain) { return substr(hash('sha256', $subdomain), 0, 8); }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') {
        $lock = fopen(dirname($this->upstreamFile) . '/upstream.lock', 'c');
        mpCheck(flock($lock, LOCK_EX | LOCK_NB), 'Сетевой вызов не удерживает блокировку');
        fclose($lock);
        $this->commands[] = $cmd;
        if (str_contains($cmd, 'VPNBOT_STAGED')) return 'VPNBOT_STAGED';
        return str_contains($cmd, 'VPNBOT_VALID') ? ($this->valid ? 'VPNBOT_VALID' : '') : ($this->applied ? 'VPNBOT_APPLIED' : '');
    }
}
$root = sys_get_temp_dir() . '/vpnbot-managed-' . bin2hex(random_bytes(6)); mkdir($root, 0700);
try {
    $m = new ManagedProtocol('anytls', $root);
    mpCheck(!$m->read()['enabled'], 'Новая установка не активирует протокол');
    $m->configure(['host' => 'vpn.example', 'sni' => 'vpn.example'], true);
    $a = managedProtocolFixtureUser($m, 'Одинаковое имя'); $b = managedProtocolFixtureUser($m, 'Одинаковое имя'); $s = $m->read();
    mpCheck($a !== $b && $s['users'][$a]['password'] !== $s['users'][$b]['password'] && $s['users'][$a]['token'] !== $s['users'][$b]['token'], 'Независимая идентичность');
    $before = $s['users'][$a]; $m->user($a, ['name' => 'Новое имя']);
    $numericId = $s;
    $numericId['users'] = ['1234567890123456' => $before];
    $m->validate($numericId);
    mpCheck(is_int(array_key_first($numericId['users'])), 'PHP приводит цифровой ID к int; это допустимый случайный hex ID');
    mpCheck($m->read()['users'][$a]['password'] === $before['password'], 'Имя не меняет авторизацию');
    $bytes = file_get_contents($m->directory() . '/desired.json');
    foreach ([['port' => 0], ['port' => 8443], ['listen_port' => 8444], ['sni' => '127.0.0.1'], ['listen_port' => 65536], ['host' => "bad\nname"], ['private_key' => '/certs/../key']] as $settings) {
        try { $m->configure($settings); throw new LogicException('invalid accepted'); } catch (InvalidArgumentException $e) {}
        mpCheck(file_get_contents($m->directory() . '/desired.json') === $bytes, 'Неверный ввод не меняет файл');
    }
    $m->user($a, [], 'rotate'); $after = $m->read()['users'][$a];
    mpCheck($before['token'] !== $after['token'] && $before['password'] !== $after['password'], 'Ротация секрета и подписки');
    mpCheck(str_starts_with($m->profile($a, 'uri'), 'anytls://'), 'Официальная схема');
    $profile = $m->profile($a, 'singbox');
    mpCheck($profile['outbounds'][0]['tls']['enabled'] && empty($profile['outbounds'][0]['tls']['insecure']), 'TLS проверяется');
    mpCheck($profile['inbounds'][0]['listen'] === '127.0.0.1', 'Локальный прокси закрыт от LAN');
    $m->user($a, ['quota' => 1024]);
    ManagedProtocol::writeJson($m->directory() . '/runtime/usage.json', ['users' => [$a => ['upload' => 100, 'download' => 924, 'reset' => $after['reset'], 'last' => ['upload' => 100]], $b => ['upload' => 0, 'download' => 0, 'reset' => $m->read()['users'][$b]['reset']]]]);
    mpCheck(!$m->allowed($m->read()['users'][$a], $a), 'Квота на границе закрывает выдачу');
    $snapshot = $m->snapshot();
    mpCheck(!isset($snapshot['usage']['users'][$a]['last']), 'Снимок не переносит базу счётчиков другого процесса');
    $m->user($a, [], 'reset');
    mpCheck($m->allowed($m->read()['users'][$a], $a), 'Сброс квоты сразу разрешает экспорт, пока supervisor хранит старые счётчики');
    $m->user($a, [], 'delete'); $m->restore($snapshot);
    mpCheck(isset($m->read()['users'][$a], $m->read()['restore_usage']['id']), 'Восстановление сохраняет ID и заказывает восстановление расхода');
    $m->user($b, ['expires' => time() - 1]);
    mpCheck(!$m->allowed($m->read()['users'][$b], $b), 'Срок закрывает выдачу без крона');
    if (function_exists('pcntl_fork')) {
        $children = [];
        for ($i = 0; $i < 12; $i++) {
            $pid = pcntl_fork();
            if ($pid === 0) { managedProtocolFixtureUser($m, 'Параллельный ' . $i); exit(0); }
            $children[] = $pid;
        }
        foreach ($children as $pid) { pcntl_waitpid($pid, $status); mpCheck(pcntl_wexitstatus($status) === 0, 'Параллельная запись завершилась'); }
        mpCheck(count($m->read()['users']) === 14, 'Ни одного потерянного доступа при RMW');
    }
    $modules = new ProtocolModules("$root/modules.json");
    mpCheck($modules->enabled('oc') && !$modules->enabled('anytls'), 'Прежние протоколы сохранены по умолчанию');
    $modules->set('ikev2', false); mpCheck($modules->enabled('ipsec') && $modules->enabled('l2tp'), 'L2TP удерживает общий контейнер');
    $modules->set('l2tp', false); mpCheck(!$modules->enabled('ipsec'), 'Оба выключены — контейнер не нужен');
    $modules->set('ikev2', true); mpCheck($modules->enabled('ipsec'), 'Повторное включение IKEv2');
    $modules->set('ipsec', false); mpCheck(!$modules->enabled('ikev2'), 'Общий выключатель закрывает IKEv2');
    $beforeModules = $modules->read();
    try { $modules->setMany(['oc' => false, 'ovpn' => 'invalid']); throw new LogicException('invalid module set'); } catch (InvalidArgumentException $e) {}
    mpCheck($modules->read() === $beforeModules, 'Ошибка в групповом восстановлении не меняет часть модулей');
    $bot = new ManagedTestBot(); $bot->protocolModulesFile = "$root/modules.json";
    $modules->set('oc', false); $modules->set('ovpn', false);
    $buttons = $bot->filterProtocolButtons([[['text'=>'OC','callback_data'=>'/menu oc'],['text'=>'WG','callback_data'=>'/menu wg']], [['callback_data'=>'/menu ikev2']]]);
    mpCheck(count($buttons) === 1 && count($buttons[0]) === 1 && $buttons[0][0]['text'] === 'WG', 'Меню отключённых протоколов скрыто');
    $bot->upstreamFile = "$root/upstream.conf"; file_put_contents($bot->upstreamFile, 'old');
    $inode = fileinode($bot->upstreamFile);
    mpCheck($bot->editUpstream(fn() => 'new'), 'Валидный upstream применяется');
    clearstatcache(); mpCheck(fileinode($bot->upstreamFile) === $inode, 'Сохранён inode bind mount');
    $bot->valid = false; mpCheck(!$bot->editUpstream(fn() => 'invalid') && file_get_contents($bot->upstreamFile) === 'new', 'Неверный upstream не заменяет рабочий');
    $bot->valid = true; $bot->applied = false;
    mpCheck(!$bot->editUpstream(fn() => 'failed') && file_get_contents($bot->upstreamFile) === 'new', 'Ошибка reload восстанавливает файл');
    mpCheck((fileperms($m->directory() . '/desired.json') & 0777) === 0600, 'Секреты с правами 0600');
    file_put_contents($m->directory() . '/desired.json', '{broken');
    try { managedProtocolFixtureUser($m, 'Не затирать повреждение'); throw new LogicException('corrupt accepted'); } catch (RuntimeException $e) {}
    mpCheck(file_get_contents($m->directory() . '/desired.json') === '{broken', 'Повреждение не заменяется пустым состоянием');
    $mieru = new ManagedProtocol('mieru', $root);
    $mieru->configure(['host' => 'vpn.example.com'], true);
    $mid = managedProtocolFixtureUser($mieru, 'Mieru < & имя');
    $native = $mieru->profile($mid, 'native');
    mpCheck($native['profiles'][0]['user']['name'] === $mid && !isset($native['profiles'][0]['tls']), 'Mieru: независимая авторизация без TLS');
    mpCheck(str_starts_with($mieru->profile($mid, 'uri'), 'mierus://') && str_starts_with($mieru->profile($mid, 'native-uri'), 'mieru://'), 'Две официальные схемы Mieru');
    $mieru->user($mid, ['rolling_quota' => ['days' => 30, 'megabytes' => 10240]]);
    $ms = $mieru->read();
    mpCheck($ms['config']['users'][0]['quotas'][0]['days'] === 30 && !$ms['config']['users'][0]['allowPrivateIP'], 'Периодическая квота и private policy Mieru');
    $mieru->configure(['transport' => 'UDP']);
    mpCheck($mieru->profile($mid, 'mihomo')['proxies'][0]['transport'] === 'UDP', 'UDP Mieru согласован с сервером');
    $mp = $mieru->profile($mid, 'mihomo');
    mpCheck($mp['proxies'][0]['udp'] && $mp['rules'] === ['MATCH,VPN', 'MATCH,REJECT'], 'Mieru UDP проходит прокси; пропуск правила не открывает DIRECT');
    try { $mieru->profile($mid, 'singbox'); throw new LogicException('unsupported client'); } catch (InvalidArgumentException $e) {}
    try { $mieru->configure(['port' => 443]); throw new LogicException('reserved port'); } catch (InvalidArgumentException $e) {}
    mpCheck($mieru->read()['settings']['port'] === 24445, 'Отказ сохраняет действующий порт');
    $tuic = new ManagedProtocol('tuic', $root);
    $tuic->configure(['host' => 'tuic.example.com', 'sni' => 'tuic.example.com'], true);
    $tid = managedProtocolFixtureUser($tuic, 'TUIC отдельно'); $tu = $tuic->read()['users'][$tid];
    $tp = $tuic->profile($tid, 'mihomo')['proxies'][0];
    mpCheck($tp['uuid'] === $tu['uuid'] && !isset($tp['token']) && !$tp['reduce-rtt'] && !$tp['skip-cert-verify'], 'TUIC v5, UUID, TLS и 0-RTT');
    $tuic->user($tid, [], 'rotate');
    mpCheck($tuic->read()['users'][$tid]['uuid'] !== $tu['uuid'] && $tuic->read()['users'][$tid]['password'] !== $tu['password'], 'Ротация обоих секретов TUIC');
    $tuic->configure(['udp_mode' => 'quic']);
    $tp = $tuic->profile($tid, 'singbox')['outbounds'][0];
    mpCheck($tp['udp_relay_mode'] === 'quic' && !isset($tp['udp_over_stream']), 'Режимы UDP TUIC не смешиваются');
    mpCheck($tuic->read()['config']['inbounds'][0]['type'] === 'tuic' && $m->protocol === 'anytls', 'Входы протоколов независимы');
    $shadow = new ManagedProtocol('shadowtls', $root);
    $shadow->configure(['host' => 'vpn.example.com', 'sni' => 'cover.example.com'], true);
    $sid = managedProtocolFixtureUser($shadow, 'Два слоя'); $su = $shadow->read()['users'][$sid];
    $sp = $shadow->profile($sid, 'singbox'); $sc = $shadow->read()['config'];
    mpCheck($sp['outbounds'][0]['detour'] === 'shadowtls' && $sp['outbounds'][1]['version'] === 3, 'Связка SS2022 → ShadowTLS v3');
    mpCheck($sc['inbounds'][0]['strict_mode'] && $sc['inbounds'][0]['wildcard_sni'] === 'off'
        && $sc['inbounds'][1]['listen'] === '127.0.0.1' && $sc['inbounds'][1]['network'] === 'tcp', 'Ограниченный handshake и закрытый внутренний SS');
    mpCheck($sp['route']['rules'][0]['action'] === 'reject' && !$shadow->profile($sid, 'mihomo')['proxies'][0]['udp'], 'TCP-only явно закрывает UDP');
    $shadow->user($sid, [], 'rotate-inner'); $inner = $shadow->read()['users'][$sid];
    mpCheck($inner['password'] === $su['password'] && $inner['ss_key'] !== $su['ss_key'] && $inner['token'] !== $su['token'], 'Независимая ротация внутреннего ключа');
    $shadow->user($sid, [], 'rotate-outer'); $outer = $shadow->read()['users'][$sid];
    mpCheck($outer['password'] !== $inner['password'] && $outer['ss_key'] === $inner['ss_key'], 'Независимая ротация внешнего пароля');
    $shadow->configure(['udp_over_tcp' => true]);
    mpCheck($shadow->profile($sid, 'singbox')['outbounds'][0]['udp_over_tcp']['version'] === 2
        && $shadow->profile($sid, 'mihomo')['proxies'][0]['udp-over-tcp'], 'Экспорт UoT v2 согласован');
    try { $shadow->configure(['ss_server_key' => 'invalid']); throw new LogicException('invalid key'); } catch (InvalidArgumentException $e) {}
    try { $shadow->profile($sid, 'uri'); throw new LogicException('lossy export'); } catch (InvalidArgumentException $e) {}
    $bot->protocolRoot = "$root/backup"; $bot->protocolCertRoot = "$root/certs"; mkdir($bot->protocolCertRoot, 0700);
    $bot->upstreamFile = "$root/unused-upstream.conf";
    $tls = $bot->protocolStore('anytls');
    $tls->configure(['host' => 'vpn.example', 'sni' => 'vpn.example', 'certificate' => '/certs/custom/cert.pem', 'private_key' => '/certs/custom/key.pem'], true);
    $tls->configureOptions('client', ['fingerprint' => 'chrome', 'idle_session_timeout' => '30s']);
    $tlsId = managedProtocolFixtureUser($tls, 'TLS backup');
    mkdir("$root/certs/custom", 0700);
    $key = openssl_pkey_new(['private_key_bits' => 2048]);
    $csr = openssl_csr_new(['commonName' => 'vpn.example'], $key);
    $certificate = openssl_csr_sign($csr, null, $key, 2);
    openssl_x509_export($certificate, $certPem); openssl_pkey_export($key, $keyPem);
    file_put_contents("$root/certs/custom/cert.pem", $certPem); file_put_contents("$root/certs/custom/key.pem", $keyPem);
    $backup = $bot->exportManagedProtocols();
    mpCheck(count($backup['certificates']) === 2, 'Backup включает выбранную нестандартную TLS-пару');
    unlink("$root/certs/custom/cert.pem");
    $incompleteRejected = false;
    try { $bot->exportManagedProtocols(); } catch (RuntimeException $e) { $incompleteRejected = true; }
    mpCheck($incompleteRejected, 'Неполная TLS-пара не выдаётся как пригодная резервная копия');
    unlink("$root/certs/custom/key.pem"); rmdir("$root/certs/custom");
    $tls->configureOption('', null);
    $bot->importManagedProtocols($backup);
    mpCheck(file_get_contents("$root/certs/custom/key.pem") === $keyPem && (fileperms("$root/certs/custom/key.pem") & 0777) === 0600, 'Восстановление TLS-пары на пустой каталог с закрытыми правами');
    mpCheck($tls->read()['settings']['options']['client'] === ['fingerprint' => 'chrome', 'idle_session_timeout' => '30s'], 'Штатный backup/restore сохраняет дополнительные параметры клиентов');
    $badBackup = $backup; $badBackup['certificates']['/certs/unrelated.key'] = base64_encode('not allowed');
    $beforeRestore = $tls->read();
    try { $bot->importManagedProtocols($badBackup); throw new LogicException('foreign certificate'); } catch (InvalidArgumentException $e) {}
    mpCheck($tls->read() === $beforeRestore && !file_exists("$root/certs/unrelated.key"), 'Посторонний файл отклоняется до восстановления состояния');
    $badBackup = $backup; $badBackup['certificates']['/certs/custom/key.pem'] = base64_encode('broken key');
    try { $bot->importManagedProtocols($badBackup); throw new LogicException('invalid pair'); } catch (InvalidArgumentException $e) {}
    mpCheck(file_get_contents("$root/certs/custom/key.pem") === $keyPem && $tls->read() === $beforeRestore, 'Неверная TLS-пара не портит рабочие файлы и доступы');
    foreach (["-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n", "-----BEGIN CERTIFICATE-----\ntruncated\n"] as $brokenChain) {
        $badBackup = $backup;
        $badBackup['certificates']['/certs/custom/cert.pem'] = base64_encode($certPem . $brokenChain);
        $rejected = false;
        try { $bot->importManagedProtocols($badBackup); } catch (InvalidArgumentException $error) { $rejected = true; }
        mpCheck($rejected && file_get_contents("$root/certs/custom/key.pem") === $keyPem && $tls->read() === $beforeRestore, 'Повреждённая TLS-цепочка отвергается до восстановления');
    }
    $bot->protocolRoot = "$root/self-host";
    $bot->conf = ['domain' => 'first.example.test'];
    $bot->configureProtocolSelfHost('anytls'); $bot->configureProtocolSelfHost('shadowtls');
    $at = $bot->protocolStore('anytls'); $st = $bot->protocolStore('shadowtls');
    $initial = $at->read();
    mpCheck($initial['settings']['sni'] === $bot->getHashSubdomain('at') . '.first.example.test'
        && $initial['settings']['cover_host'] === 'first.example.test', 'AnyTLS: собственный сайт и автоматический отдельный поддомен');
    mpCheck($initial['config']['inbounds'][0]['fallback_server_name'] === 'first.example.test'
        && $initial['config']['inbounds'][0]['tls']['alpn'] === ['http/1.1'], 'AnyTLS: HTTP-сайт после штатного fallback');
    mpCheck($initial['config']['inbounds'][0]['fallback_address'] === '10.10.0.2:10443', 'AnyTLS: собственный сайт доступен без публичного hairpin');
    mpCheck($st->read()['settings']['sni'] === 'first.example.test'
        && $st->read()['settings']['port'] === 24447, 'ShadowTLS: свой сайт и отдельный порт');
    mpCheck($st->read()['config']['inbounds'][0]['handshake']['server'] === '10.10.0.2'
        && $st->read()['config']['inbounds'][0]['handshake']['server_port'] === 10443, 'ShadowTLS: внутренний TLS-маршрут к своему сайту');
    $bot->configureProtocolSelfHost('anytls');
    mpCheck($at->read()['revision'] === $initial['revision'], 'Повторный выбор авто не перезапускает неизменённое ядро');
    $bot->conf['domain'] = 'second.example.test'; $bot->syncManagedSelfHosts();
    mpCheck($at->read()['settings']['cover_host'] === 'second.example.test'
        && $st->read()['settings']['sni'] === 'second.example.test', 'Другой сервер получает свой домен');
    $st->configure(['self_hosted' => false, 'sni' => 'manual.example.test']);
    $bot->conf['domain'] = 'third.example.test'; $bot->syncManagedSelfHosts();
    mpCheck($st->read()['settings']['sni'] === 'manual.example.test', 'Ручное прикрытие не заменяется автоматически');
    foreach (['https://example.test', '127.0.0.1', $at->read()['settings']['sni'], "example.test\nHost: evil", null] as $host) {
        try { $at->configure(['cover_host' => $host]); throw new LogicException('invalid cover accepted'); } catch (InvalidArgumentException $e) {}
    }
    $modules->set('tt', false);
    mpCheck(!$modules->enabled('tt') && $bot->filterProtocolButtons([[['text' => 'TT', 'callback_data' => '/menu tt']]]) === [], 'TrustTunnel отключается и исчезает из меню');
    $modules->set('tt', true);
    mpCheck($modules->enabled('tt'), 'TrustTunnel включается обратно');
    $bot->protocolNginxFile = "$root/nginx.conf";
    $originalNginx = "http {\n server {\n  listen 10.10.0.2:443 ssl proxy_protocol default_server;\n }\n server {\n  listen 10.10.0.2:443 ssl proxy_protocol;\n }\n}\n";
    file_put_contents($bot->protocolNginxFile, $originalNginx);
    $bot->applied = true;
    $bot->prepareProtocolSelfHost(); $preparedNginx = file_get_contents($bot->protocolNginxFile);
    mpCheck(substr_count($preparedNginx, 'listen 10.10.0.2:10443 ssl') === 2, 'Внутренний TLS сохраняет оба виртуальных хоста');
    $bot->prepareProtocolSelfHost();
    mpCheck(file_get_contents($bot->protocolNginxFile) === $preparedNginx, 'Подготовка внутреннего маршрута идемпотентна');
    file_put_contents($bot->protocolNginxFile, $originalNginx); $bot->applied = false;
    try { $bot->prepareProtocolSelfHost(); throw new LogicException('reload failure accepted'); } catch (RuntimeException $e) {}
    mpCheck(file_get_contents($bot->protocolNginxFile) === $originalNginx, 'Ошибка reload сохраняет прежний сайт');
    $selfHostBackup = $bot->exportManagedProtocols();
    $at->configure(['self_hosted' => false, 'cover_host' => '']);
    $beforeRestore = $at->read();
    try { $bot->importManagedProtocols($selfHostBackup); throw new LogicException('restore without website'); } catch (RuntimeException $e) {}
    mpCheck($at->read() === $beforeRestore, 'Нельзя восстановить авто-прикрытие без рабочего внутреннего маршрута');
    $bot->applied = true;
    $bot->importManagedProtocols($selfHostBackup);
    mpCheck($at->read()['settings']['self_hosted'] && file_get_contents($bot->protocolNginxFile) === $preparedNginx,
        'Восстановление авто-прикрытия подготавливает внутренний TLS-маршрут');
    echo "managed_protocol_test OK\n";
} finally { mpRemove($root); }
