<?php
// Node card details and the node snapshot file: download, upload, rejection.
require __DIR__ . '/managed_nodes_test.php';

const CARD_KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHxSsv0vbj6kPZ1e0Qa6AnrV0gvTq4bH9Y8bqc4mKcB9';

class CardFixtureBot extends ManagedFixtureBot
{
    public array $sent = []; public array $imported = []; public array $exitState = []; public ?array $online = [];
    public array $stats = []; public ?string $upload = null; public bool $sendOk = true; public string $controllerKey = CARD_KEY;
    public function exitStatus(): array { return $this->exitState; }
    public function getXrayStats() { return $this->stats; }
    protected function managedNodeOnlineUsers(): ?array { return $this->online; }
    protected function managedNodeImportDownload(): ?string { return $this->upload; }
    public function sendFile($chat, $file, $caption = false, $to = false) {
        $this->sent[] = [$chat, $file->data, $file->postname, (string) $caption];
        return $this->sendOk ? ['ok' => true, 'result' => ['message_id' => 9]] : ['ok' => false];
    }
    protected function managedNodeTransport(string $id, string $action, $value = null): array {
        if ($action === 'public') return ['public_key' => $this->controllerKey];
        if ($action === 'import') {
            $this->imported[] = json_encode($value, JSON_UNESCAPED_SLASHES);
            file_put_contents($this->managedNodeRoot . "/$id/snapshot.json", json_encode($value['snapshot'], JSON_UNESCAPED_SLASHES));
            return ['hash' => str_repeat('e', 16)];
        }
        if ($action === 'saved') {
            $raw = (string) file_get_contents($this->managedNodeRoot . "/$id/snapshot.json");
            return ['snapshot' => json_decode($raw, true), 'hash' => substr(hash('sha256', $raw), 0, 16)];
        }
        return parent::managedNodeTransport($id, $action, $value);
    }
}

$root = sys_get_temp_dir() . '/vpnbot-card-' . bin2hex(random_bytes(6));
mkdir("$root/aabbccdd", 0700, true);
$snapshotJson = '{"schema":1,"options":{"transport":"ws","amnezia":{"parameters":{}}},"identity":{"uuid":"x"},"peers":[],"images":{"xr":"ghcr.io/axiomshiftbit/vpnbot-xr@sha256:' . str_repeat('a', 64) . '"},"tls":{}}';
$make = static function () use ($root, $snapshotJson): CardFixtureBot {
    file_put_contents("$root/aabbccdd/snapshot.json", $snapshotJson);
    $b = new CardFixtureBot();
    $b->managedNodeRoot = $root;
    $b->pacState['managed_nodes']['aabbccdd']['job'] = null;
    $b->pacState['managed_nodes']['aabbccdd']['checked'] = time();
    $b->pacState['managed_nodes']['aabbccdd']['backup_time'] = 1700000000;
    $b->remoteStatus['pending'] = null;
    $b->pacState['managed_nodes']['aabbccdd']['status']['pending'] = null;
    $b->input['file_id'] = 'document';
    return $b;
};
$card = static function (CardFixtureBot $b): string { $b->managedNodeMenu('aabbccdd'); return end($b->screens)[0]; };

try {
    // Never checked: no claims at all.
    $b = $make();
    $b->pacState['managed_nodes']['aabbccdd']['status'] = [];
    $check($b->managedNodeCardDetails('aabbccdd', $b->pacState['managed_nodes']['aabbccdd']) === [], 'unchecked node gets no details');
    // Old node: no invented commit or server data.
    $b = $make();
    $text = $card($b);
    $check(str_contains($text, 'коммит не сообщается') && str_contains($text, 'код ноды их ещё не сообщает'), 'old node: version and server data marked unknown');

    // New node: versions, server, per-server connections from the node status.
    $status = &$b->pacState['managed_nodes']['aabbccdd']['status'];
    $status['options']['core'] = 'origin';
    $status['cores'] = ['origin' => '26.11.9'];
    $status['code'] = ['source' => str_repeat('1', 40), 'upgrade' => true, 'origin' => 'button', 'verified' => true, 'images' => str_repeat('2', 40)];
    $status['host'] = ['cpus' => 2, 'uptime' => 3 * 86400 + 4 * 3600, 'load' => [0.12, 0.2, 0.3],
        'memory' => ['total' => 2147483648, 'available' => 1073741824], 'disk' => ['total' => 21474836480, 'free' => 10737418240],
        'network' => ['rx' => 1073741824, 'tx' => 2147483648],
        'servers' => [['address' => '198.51.100.7', 'role' => 'main', 'tcp' => 2, 'udp' => false],
                      ['address' => '198.51.100.8', 'role' => 'vpn', 'tcp' => 0, 'udp' => true],
                      ['address' => '198.51.100.9', 'role' => 'vpn', 'tcp' => 0, 'udp' => false],
                      ['address' => '<b>x', 'role' => 'vpn', 'tcp' => 9, 'udp' => true]],
        'local' => 1, 'other' => 3];
    unset($status);
    $b->exitState = ['aabbccdd' => ['ok' => true, 'ms' => 45, 'loc' => 'FI', 'gl' => 'RU', 'ip' => '203.0.113.5', 'time' => time(), 'hist' => [[time(), 1]]]];
    $b->stats = ['exits' => ['aabbccdd' => ['global' => ['up' => 1024, 'down' => 2048], 'session' => ['up' => 0, 'down' => 0], 'base' => ['up' => 0, 'down' => 0], 'since' => 1700000000]]];
    $b->xrayState['inbounds'][0]['settings']['clients'] = [
        ['email' => 'alice', 'exit' => ['aabbccdd']], ['email' => 'bob', 'exit' => ['aabbccdd']],
        ['email' => 'carol', 'exit' => ['aabbccdd'], 'off' => true], ['email' => 'dave', 'exit' => []]];
    $b->online = ['alice' => ['ips' => []], 'dave' => ['ips' => []]];
    $text = $card($b);
    $check(str_contains($text, 'код <code>1111111</code> · образы <code>2222222</code> · Xray 26.11.9'), 'card shows code, images and core');
    $check(str_contains($text, 'работает 3 д 4 ч') && str_contains($text, 'нагрузка 0,12 / 2 CPU') && str_contains($text, 'память: свободно 1 GB из 2 GB')
        && str_contains($text, 'сеть с загрузки: ↓1 GB ↑2 GB'), 'card shows node server metrics');
    $check(str_contains($text, '🟢 основной бот <code>198.51.100.7</code> — TCP 2') && str_contains($text, '🟢 VPN-сервер <code>198.51.100.8</code> — UDP WG/AWG')
        && str_contains($text, '⚫ VPN-сервер <code>198.51.100.9</code> — нет соединений'), 'card shows each permitted server online state');
    $check(!str_contains($text, '<b>x'), 'invalid server address is not rendered');
    $check(str_contains($text, 'Внутри AmneziaWG (локально): TCP 1') && str_contains($text, 'вне списка: 3'), 'card shows local and unexpected connections');
    $check(str_contains($text, 'YouTube видит RU') && str_contains($text, 'выход FI') && str_contains($text, '45 мс') && str_contains($text, 'Доступность за 24 ч'), 'card shows the main bot traffic check with YouTube country');
    $check(str_contains($text, '↑1 KB ↓2 KB'), 'card shows main bot traffic through the node');
    $check(str_contains($text, 'через ноду: 2, онлайн сейчас: 1 — alice') && !str_contains($text, 'carol'), 'card shows assigned and online users only');
    $b->online = null;
    $check(str_contains($card($b), 'онлайн: нет данных'), 'unreadable online state is not guessed');
    // Unknown values from a node without conntrack/proc stay unknown.
    $b->pacState['managed_nodes']['aabbccdd']['status']['host']['servers'] = [['address' => '198.51.100.7', 'role' => 'main', 'tcp' => null, 'udp' => null]];
    $check(str_contains($card($b), '⚪ основной бот <code>198.51.100.7</code> — нет данных'), 'unknown connection state shown as no data');
    $b->pacState['managed_nodes']['aabbccdd']['status']['host']['servers'] = [['address' => '198.51.100.7', 'role' => 'main', 'tcp' => 0, 'udp' => null],
        ['address' => '198.51.100.8', 'role' => 'vpn', 'tcp' => 1, 'udp' => null]];
    $text = $card($b);
    $check(str_contains($text, '⚪ основной бот <code>198.51.100.7</code> — TCP-соединений нет; UDP: нет данных') && str_contains($text, '🟢 VPN-сервер <code>198.51.100.8</code> — TCP 1'), 'kernel without conntrack: UDP never claimed absent');
    // Manual install, changed files, images not from a bundle.
    $b->pacState['managed_nodes']['aabbccdd']['status']['code'] = ['source' => null, 'upgrade' => true, 'origin' => 'manual', 'verified' => false, 'images' => null];
    $text = $card($b);
    $check(str_contains($text, 'коммит не определён') && str_contains($text, 'изменены после установки') && str_contains($text, 'не из последнего скачанного комплекта'), 'manual or modified code reported honestly');
    $b->managedNodeMaintenance('aabbccdd');
    [$text, $rows] = end($b->screens);
    $buttons = json_encode($rows, JSON_UNESCAPED_UNICODE);
    $check(str_contains($text, 'Кнопки обновления обновляют и код, и образы') && str_contains($buttons, '/nodeExport aabbccdd') && str_contains($buttons, '/nodeImport aabbccdd'), 'maintenance shows version and both file buttons');
    $b->language = 'en';
    $text = $card($b);
    $check(str_contains($text, 'Connected servers') && str_contains($text, 'Main bot users routed') && mb_strlen($text) < 4096, 'English card fits Telegram');
    $b->language = 'ru';

    // Download: fresh snapshot, private chat, file bound to the controller key.
    $b = $make();
    $b->managedNodeExport('aabbccdd');
    $check(str_contains(end($b->screens)[0], 'личный чат') && $b->sent === [], 'export asks for confirmation first');
    $b->managedNodeExport('aabbccdd', true);
    $check(count($b->sent) === 1 && $b->sent[0][0] === 1 && str_ends_with($b->sent[0][2], '.json') && str_contains($b->sent[0][3], 'храните как пароль'), 'file sent to the private chat with a warning');
    $check(in_array('snapshot', $b->events, true) && str_contains(end($b->screens)[0], 'Свежая копия'), 'reachable node gets a fresh snapshot');
    $file = json_decode($b->sent[0][1], true);
    $check($file['type'] === 'vpnbot-node-snapshot' && $file['controller_key'] === CARD_KEY && !isset($file['key']) && !str_contains($b->sent[0][1], 'PRIVATE KEY'), 'file holds the public binding only');
    $check(str_contains($b->sent[0][1], '"tls": {}') && str_contains($b->sent[0][1], '"parameters": {}'), 'empty JSON objects stay objects in the file');
    $downloaded = $b->sent[0][1];
    // Busy node: the last saved snapshot with its date.
    $b = $make();
    $b->pacState['managed_nodes']['aabbccdd']['job'] = ['id' => str_repeat('c', 32), 'phase' => 'waiting'];
    $b->managedNodeExport('aabbccdd', true);
    $check(count($b->sent) === 1 && !in_array('snapshot', $b->events, true) && str_contains(end($b->screens)[0], 'последняя сохранённая копия от 2023-11-14'), 'busy node sends the dated saved snapshot');
    $b = $make(); $b->input['from'] = -100;
    $b->managedNodeExport('aabbccdd', true);
    $check($b->sent === [] && str_contains(end($b->screens)[0], 'Файл не отправлен'), 'group chat never receives the file');
    $b = $make(); $b->sendOk = false;
    $b->managedNodeExport('aabbccdd', true);
    $check(str_contains(end($b->screens)[0], 'Файл не отправлен'), 'failed delivery reported');
    $b = $make(); unlink("$root/aabbccdd/snapshot.json");
    $b->managedNodeExport('aabbccdd', true);
    $check($b->sent === [] && str_contains(end($b->screens)[0], 'нет сохранённой копии'), 'missing snapshot reported');

    // Upload: verified file replaces the saved snapshot and leads to restore.
    $b = $make();
    file_put_contents("$root/aabbccdd/snapshot.json", '{"schema":1,"options":{},"identity":{},"peers":[],"images":{},"tls":{"other":"x"}}');
    $b->upload = $downloaded;
    $b->managedNodeImportFile('', 'aabbccdd');
    $check(count($b->imported) === 1 && str_contains($b->imported[0], '"tls":{}') && str_contains($b->imported[0], '"parameters":{}'), 'upload passes the snapshot with objects intact');
    $check($b->pacState['managed_nodes']['aabbccdd']['backup_time'] === json_decode($downloaded, true)['snapshot_time'] && json_decode($downloaded, true)['snapshot_time'] > 1700000000, 'snapshot time taken from the file');
    $check(str_contains(json_encode(end($b->screens)[1]), '/nodeRestore aabbccdd ') && !in_array('submit', $b->events, true), 'upload offers restore and changes nothing on the node');
    // Rejections: foreign node, edited, damaged, not a node file, unreadable.
    $edited = str_replace('"transport": "ws"', '"transport": "xhttp"', $downloaded);
    $other = str_replace(CARD_KEY, 'ssh-ed25519 ' . str_repeat('B', 68), $downloaded);
    $check($edited !== $downloaded && $other !== $downloaded, 'rejection fixtures differ from the download');
    foreach (['foreign' => [$other, 'другой ноды'], 'edited' => [$edited, 'контрольная сумма'], 'json' => ['{"pac":{}}', 'не файл копии'],
              'text' => ['not json', 'не файл копии'], 'read' => [null, 'не прочитан']] as $case => [$upload, $needle]) {
        $b = $make(); $b->upload = $upload;
        $b->managedNodeImportFile('', 'aabbccdd');
        $check($b->imported === [] && str_contains(end($b->screens)[0], $needle), 'upload rejected: ' . $case);
    }
    $b = $make(); $b->upload = $downloaded; unset($b->input['file_id']);
    $b->managedNodeImportFile('/etc/passwd', 'aabbccdd');
    $check($b->imported === [] && str_contains(end($b->screens)[0], 'не прочитан'), 'text answer is never treated as a path or file');
    $check(str_contains(end($b->screens)[0], (Bot::NODE_FILE_MAX_BYTES / 1048576) . ' МиБ'), 'import error shows the actual document limit');
    $b->language = 'en';
    $b->managedNodeImportFile('', 'aabbccdd');
    $check(str_contains(end($b->screens)[0], 'Send a .json document up to ' . intdiv(Bot::NODE_FILE_MAX_BYTES, 1048576) . ' MiB.'),
        'English import error shows the actual document limit');
    $b = $make(); $b->upload = $downloaded; $b->input['file_id'] = 'document';
    $b->managedNodeImportFile('моя копия', 'aabbccdd');
    $check(count($b->imported) === 1, 'document with a caption is accepted');
    $b = $make(); $b->upload = $downloaded; $b->pacState['managed_nodes']['aabbccdd']['job'] = ['id' => str_repeat('c', 32), 'phase' => 'waiting'];
    $b->managedNodeImportFile('', 'aabbccdd');
    $check($b->imported === [] && str_contains(end($b->screens)[0], 'нода занята'), 'upload refused during an operation');
    $b = $make(); $b->upload = $downloaded; $b->pacState['managed_nodes']['aabbccdd']['connected'] = false;
    $b->managedNodeImportFile('', 'aabbccdd');
    $check(count($b->imported) === 1 && str_contains(end($b->screens)[0], 'Привяжите SSH'), 'upload before rebind keeps restore for later');

    // Pretty indentation alone can push a valid 3 MiB named policy over the Telegram file importer limit.
    $b = $make();
    $b->pacState['managed_nodes']['aabbccdd']['connected'] = false;
    $snapshot = json_decode($snapshotJson);
    $domains = [];
    for ($i = 0; $i < 185000; $i++) $domains[] = 'full:' . base_convert((string)$i, 10, 36) . '.test';
    $snapshot->options->policy = ['lists'=>['bulk'=>['domain'=>$domains]],
        'bindings'=>['all'=>[['list'=>'bulk','action'=>'block']]], 'revision'=>str_repeat('b',32)];
    file_put_contents("$root/aabbccdd/snapshot.json", json_encode($snapshot, JSON_UNESCAPED_SLASHES));
    $b->managedNodeExport('aabbccdd', true);
    $b->upload = $b->sent[0][1] ?? '';
    $check($b->upload !== '' && strlen($b->upload) <= Bot::NODE_FILE_MAX_BYTES, 'large exported snapshot fits the file importer');
    $b->managedNodeImportFile('', 'aabbccdd');
    $import = json_decode($b->imported[0] ?? '{}');
    $check(($import->snapshot->options->policy->lists->bulk->domain ?? []) === $domains, 'large named list survives export and re-import');
    unset($snapshot, $domains, $import);
    // Full backup caption: fresh or earlier snapshot per node, never a silent stale copy.
    $b = $make();
    $b->pacState['managed_nodes']['aabbccdd']['backup_time'] = time();
    $check(str_contains($b->managedNodeBackupCaption(time() - 5), '(свежая)'), 'backup caption marks a refreshed snapshot');
    $b->pacState['managed_nodes']['aabbccdd']['backup_time'] = 1700000000;
    $caption = $b->managedNodeBackupCaption(time() - 5);
    $check(str_contains($caption, 'копия от 2023-11-14') && str_contains($caption, 'прежняя'), 'backup caption warns about an earlier snapshot');
    $b->pacState['managed_nodes']['aabbccdd']['connected'] = false;
    $check(str_contains($b->managedNodeBackupCaption(time()), 'без копии'), 'backup caption for a node that is not connected');
    unset($b->pacState['managed_nodes']);
    $check($b->managedNodeBackupCaption(time()) === '', 'no nodes, no caption');
    foreach (['/nodeExport aabbccdd', '/nodeExport aabbccdd yes', '/nodeImport aabbccdd'] as $callback) $check(strlen($callback) <= 64, 'callback fits');
    // Main-server IP blocks: tell the admin when the node does not enforce them yet.
    $b = $make();
    $b->pacState['managed_nodes']['aabbccdd']['status']['running'] = true;
    $exit = ['policy' => ['revision' => str_repeat('c', 32), 'controller_ips' => ['11.77.1.0/24'], 'lists' => [], 'bindings' => []]];
    $guardLine = static fn(array $node) => Closure::bind(fn() => $this->managedNodeIpGuardLine($node, $exit), $b, Bot::class)();
    $node = $b->pacState['managed_nodes']['aabbccdd'];
    $check($guardLine($node) === '', 'no main-server IP blocks: no guard line');
    $b->xrayState['routing']['rules'][] = ['type' => 'field', 'ruleTag' => 'vpnbot:routes:block:ip', 'ip' => ['11.77.1.0/24'], 'outboundTag' => 'block'];
    $check(str_contains($guardLine($node), 'Обновите код ноды'), 'node code without the guard asks for an update');
    $node['status']['controller_ip_guard'] = true;
    $check($guardLine($node) === '', 'confirmed list: no guard line');
    $b->xrayState['routing']['rules'][0]['ip'][] = '198.51.100.0/24';
    $check(str_contains($guardLine($node), 'не подтверждены нодой') && !str_contains($guardLine($node), 'черновик'), 'changed list waits for node confirmation');
    $node['draft'] = $node['status']['options'] ?? [];
    $check(str_contains($guardLine($node), 'примените или сбросьте'), 'a pending draft is named as the delay');
} finally {
    foreach (glob("$root/aabbccdd/*") ?: [] as $path) unlink($path);
    @rmdir("$root/aabbccdd"); @rmdir($root);
}
echo "PASS $checks managed node card checks\n";
