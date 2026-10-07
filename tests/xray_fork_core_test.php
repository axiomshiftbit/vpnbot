<?php

// Контракт между ботом и НАСТОЯЩИМ форк-ядром Jolymmiles/Xray-core.
//
// smux_test.php проверяет правила SMuxConfig.Build() по их пересказу на PHP.
// Здесь те же конфиги отдаются самому бинарнику: расхождение пересказа с ядром
// после обновления форка иначе всплывает только на сервере — ядро не стартует.
// Заодно сверяется то, что бот читает из бинарника (версия, сборка REALITY).

require_once __DIR__ . '/../app/bot.php';

$binary = getenv('XRAY_FORK_TEST_BINARY');
if (!$binary) {
    echo "xray_fork_core_test SKIP: задайте XRAY_FORK_TEST_BINARY для проверки форк-ядром\n";
    exit(0);
}
if (!is_executable($binary)) {
    throw new RuntimeException('XRAY_FORK_TEST_BINARY не исполняемый файл');
}

$checks = 0;
function fcAssert(bool $ok, string $message): void
{
    global $checks;
    $checks++;
    if (!$ok) {
        throw new RuntimeException('xray_fork_core_test: ' . $message);
    }
}

function fcRun(array $command): array
{
    $process = proc_open($command, [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    $output = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);

    return [proc_close($process), $output];
}

$work = sys_get_temp_dir() . '/vpnbot-fork-core-' . bin2hex(random_bytes(6));
mkdir($work, 0700);
function fcAccepts(array $config): bool
{
    global $binary, $work;
    $file = $work . '/config.json';
    file_put_contents($file, json_encode($config, JSON_UNESCAPED_SLASHES));
    [$code] = fcRun([$binary, 'run', '-test', '-config', $file]);

    return $code === 0;
}

class ForkCoreTestBot extends Bot
{
    public string $binary;
    public function __construct() {}
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
    {
        $this->sshFailed = false;
        $cmd = 'PATH=' . escapeshellarg(dirname($this->binary) . ':' . getenv('PATH')) . '; '
            . str_replace('/usr/local/bin/xray', escapeshellarg($this->binary), $cmd);

        return (string) shell_exec($cmd . ' 2>/dev/null');
    }
}

try {
    // ── Версия и сборка ──────────────────────────────────────────────────────
    [$code, $out] = fcRun([$binary, 'version']);
    $line = strtok($out, "\n");
    fcAssert($code === 0 && preg_match('~^Xray\s+v?([0-9][\w.+-]*)\s~', (string) $line, $m) === 1,
        'первая строка version читается инвентаризацией ядер бота');
    $version = $m[1];
    $pin = preg_match('~^XRAY_FORK_VERSION=v?(\S+)$~m', (string) file_get_contents(__DIR__ . '/../.env'), $p) ? $p[1] : '';
    fcAssert($pin !== '' && $version === $pin, "версия ядра $version совпадает с пином $pin из .env");

    $raw = (string) file_get_contents($binary);
    if (version_compare($version, '26.10.5', '>=')) {
        // Без http2legacy XHTTP поверх HTTP/2 открывает соединение на каждый
        // запрос, пока висит рукопожатие; автор форка тестирует только с тегом.
        // Точные строки Go build info: регулярное выражение по бинарнику в
        // десятки мегабайт упирается в лимиты PCRE.
        fcAssert(str_contains($raw, "build\t-tags=http2legacy\n"), 'ядро собрано с тегом http2legacy');
        fcAssert(str_contains($raw, "=>\t./third_party/reality\t"), 'REALITY собран из дерева форка');
    }
    $symlink = $work . '/xray';
    symlink($binary, $symlink);
    $bot = new ForkCoreTestBot();
    $bot->binary = $symlink;
    $probe = $bot->xrayCoreProbe(true);
    fcAssert(str_starts_with($probe['version'], 'Xray ' . $version), 'проба бота читает версию ядра');
    fcAssert(preg_match('~^v0\.0\.0-\d{14}-[0-9a-f]+$~D', $probe['reality']) === 1, 'проба бота находит сборку REALITY в бинарнике');
    fcAssert($probe['reality_local'] === version_compare($version, '26.10.5', '>='),
        'проба отличает REALITY из дерева форка от апстримного модуля');

    // ── Серверный блок sing-mux из меню ──────────────────────────────────────
    $server = static fn(array $inbound) => [
        'inbounds' => [$inbound + ['protocol' => 'vless', 'listen' => '127.0.0.1', 'port' => 24443,
            'settings' => ['decryption' => 'none', 'clients' => [['id' => '11111111-2222-4333-8444-555555555555']]]]],
        'outbounds' => [['protocol' => 'freedom']],
    ];
    fcAssert(fcAccepts($server([])), 'базовый серверный конфиг принят');
    $rates = ['100 Mbps', '1 Gbps', '524288 bps', '800 Kbps', '65536 Bps', '12'];
    $frames = [Bot::SMUX_H2MUX_FRAME_MIN, 65536, Bot::SMUX_H2MUX_FRAME_MAX];
    foreach ($rates as $rate) {
        foreach ([0, ...$frames] as $frame) {
            $pac = ['xray_core' => 'fork', 'smux' => ['enabled' => 1, 'h2mux_frame' => $frame,
                'brutal' => ['enabled' => 1, 'up' => $rate, 'down' => $rate]]];
            $c = $server([]);
            $bot->ensureSmuxInbound($c, $pac);
            fcAssert(Bot::smuxRate($rate) === $rate, "ставка «{$rate}» допустима для меню");
            fcAssert(isset($c['inbounds'][0]['smux']['brutal-opts']), 'включённый Brutal попадает в конфиг сервера');
            fcAssert(fcAccepts($c), "ядро принимает серверный smux: ставка «{$rate}», кадр {$frame}");
        }
    }
    // То, что меню не пропускает, ядро обязано отвергать: иначе пересказ правил
    // в smuxRate()/smuxFrameSize() устарел.
    foreach (['1 Kbps', '65535 Bps', '10 mbit', '-5 Mbps'] as $rate) {
        fcAssert(Bot::smuxRate($rate) !== $rate, "меню отклоняет ставку «{$rate}»");
        fcAssert(!fcAccepts($server(['smux' => ['brutal-opts' => ['enabled' => true, 'up' => $rate, 'down' => '100 Mbps']]])),
            "ядро отвергает ставку Brutal «{$rate}»");
    }
    foreach ([Bot::SMUX_H2MUX_FRAME_MIN - 1, Bot::SMUX_H2MUX_FRAME_MAX + 1] as $frame) {
        fcAssert(Bot::smuxFrameSize($frame) === 0, "меню отклоняет размер кадра {$frame}");
        fcAssert(!fcAccepts($server(['smux' => ['h2muxMaxReadFrameSize' => $frame]])), "ядро отвергает размер кадра {$frame}");
    }

    // ── Клиентский блок sing-mux для Xray-клиента ────────────────────────────
    $client = static fn(array $smux) => [
        'inbounds' => [['protocol' => 'socks', 'listen' => '127.0.0.1', 'port' => 24480, 'settings' => ['udp' => true]]],
        'outbounds' => [['protocol' => 'vless', 'smux' => $smux, 'settings' => ['vnext' => [['address' => '127.0.0.1',
            'port' => 24443, 'users' => [['id' => '11111111-2222-4333-8444-555555555555', 'encryption' => 'none']]]]]]],
    ];
    $limits = [['max_streams' => 8], ['max_streams' => 0, 'max_connections' => 4, 'min_streams' => 2],
        ['max_streams' => 0, 'max_connections' => 0, 'min_streams' => 0], []];
    foreach (['smux', 'h2mux'] as $protocol) {
        foreach (['off', 'auto', 'require'] as $half) {
            foreach ([0, 1] as $padding) {
                foreach ([0, 1] as $brutal) {
                    foreach ($limits as $limit) {
                        $settings = $limit + ['enabled' => 1, 'protocol' => $protocol, 'half_close' => $half,
                            'padding' => $padding, 'only_tcp' => $padding, 'brutal' => ['enabled' => $brutal]];
                        $block = $bot->smuxBlock(['xray_core' => 'fork', 'smux' => $settings], 's');
                        fcAssert(fcAccepts($client($block)), 'ядро принимает клиентский smux: ' . json_encode($settings));
                    }
                }
            }
        }
    }
    // Правила, ради которых smuxBlock() перестраивает значения.
    fcAssert(!fcAccepts($client(['enabled' => true, 'protocol' => 'smux', 'maxStreams' => 8, 'maxConnections' => 4])),
        'ядро отвергает maxStreams вместе с maxConnections');
    fcAssert(!fcAccepts($client(['enabled' => true, 'protocol' => 'h2mux', 'logicalHalfClose' => 'auto'])),
        'ядро отвергает logicalHalfClose с h2mux');
    fcAssert(!fcAccepts($client(['enabled' => true, 'protocol' => 'yamux'])), 'ядро отвергает yamux');

    // ── Возможности апстрима 26.9.30, доступные форку после слияния ──────────
    if (version_compare($version, '26.9.30', '>=')) {
        $pac = ['xray_core' => 'fork', 'finalmask' => ['enabled' => 1, 'fragment' => ['enabled' => 0],
            'noise' => ['enabled' => 1, 'reset' => '5-10', 'list' => [
                ['type' => 'exp', 'packet' => XrayNoise::dynamicPackets()[0]['packet'], 'delay' => '10-16']]]]];
        $c = $server(['streamSettings' => ['network' => 'raw']]);
        $bot->ensureFinalmaskInbound($c, $pac);
        fcAssert(isset($c['inbounds'][0]['streamSettings']['finalmask']['udp']), 'UDP noise exp попадает в конфиг сервера');
        fcAssert(fcAccepts($c), 'форк принимает UDP noise с выражениями (апстрим 26.9.30)');
    }
    // ── Mux.Cool поверх XHTTP: ключи KeepAlive и клиентский блок ─────────────
    if (version_compare($version, Bot::XHTTP_MUX_FORK_MIN, '>=')) {
        $pac = ['xray_core' => 'fork', 'transport' => 'xhttp', 'xhttp_mux' => ['enabled' => 1]];
        $xhttp = static fn(array $extra) => $server(['streamSettings' => ['network' => 'xhttp',
            'xhttpSettings' => ['mode' => 'auto', 'path' => '/ws', 'extra' => $extra]]]);
        $c = $xhttp(['xPaddingBytes' => '100-1000', 'scMaxBufferedPosts' => 30,
            'scMaxEachPostBytes' => 1000000, 'scStreamUpServerSecs' => '20-80']);
        $bot->ensureXhttpMuxInbound($c, $pac);
        fcAssert(isset($c['inbounds'][0]['streamSettings']['xhttpSettings']['extra']['muxKeepAliveSecs']),
            'KeepAlive попадает в серверный конфиг XHTTP');
        fcAssert(fcAccepts($c), 'ядро принимает серверный XHTTP с KeepAlive Mux.Cool');
        // Неизвестный ключ ядро молча пропустило бы: отказ на мусорном значении
        // доказывает, что эти ключи оно действительно разбирает.
        foreach (array_keys(Bot::XHTTP_MUX_KEEPALIVE) as $key) {
            fcAssert(!fcAccepts($xhttp([$key => 'not-a-range'])), "ядро разбирает ключ $key");
        }
        $mux = $bot->xhttpMuxClient($pac);
        $out = $client([]);
        unset($out['outbounds'][0]['smux']);
        $out['outbounds'][0]['mux'] = $mux;
        $out['outbounds'][0]['streamSettings'] = ['network' => 'xhttp', 'security' => 'tls',
            'xhttpSettings' => ['host' => 'vpn.example.test', 'mode' => 'packet-up', 'path' => '/ws',
                'extra' => $bot->xhttpClientExtra()],
            'tlsSettings' => ['serverName' => 'vpn.example.test', 'alpn' => ['h2', 'http/1.1'], 'fingerprint' => 'chrome']];
        fcAssert($mux !== null && fcAccepts($out), 'ядро принимает клиентский XHTTP с Mux.Cool');
        $out['outbounds'][0]['smux'] = $bot->smuxBlock(['xray_core' => 'fork', 'smux' => ['enabled' => 1]], 's');
        fcAssert(!fcAccepts($out), 'ядро отвергает Mux.Cool и SMUX на одном выходе');
    }
    echo "xray_fork_core_test OK ($checks проверок форк-ядром $version)\n";
} finally {
    foreach (glob($work . '/*') as $file) { unlink($file); }
    rmdir($work);
}
