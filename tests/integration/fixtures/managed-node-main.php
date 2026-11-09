<?php
/** Native fixture: real Bot controller, SSH helper, exit generator and Xray. */
require '/lab/app/bot.php';
umask(0077);
class NativeManagedBot extends Bot {
    public int $testProbePort = 0;
    public function __construct() {
        $this->pac = '/work/pac.json'; $this->htpasswd = '/work/webapp/.htpasswd';
        $this->backupWarpRoot = '/work/warp'; $this->telemtDecoyDir = '/work/decoy';
        $this->input = ['chat' => 1, 'from' => 1, 'message_id' => 1, 'callback_id' => 'fixture', 'username' => 'fixture'];
        $this->language = 'ru'; require '/lab/app/i18n.php'; $this->i18n = $i;
    }
    public function getPacConf() { return json_decode(file_get_contents($this->pac), true, 64, JSON_THROW_ON_ERROR); }
    public function setPacConf(array $p) { return file_put_contents($this->pac, json_encode($p, JSON_THROW_ON_ERROR)) !== false; }
    public function getXray() {
        return is_file('/work/core.json') ? json_decode(file_get_contents('/work/core.json'), true) :
            ['log' => ['loglevel' => 'none'], 'inbounds' => [], 'outbounds' => [['tag' => 'direct', 'protocol' => 'freedom']], 'routing' => ['rules' => []]];
    }
    public function restartXray($c, $norestart = false) {
        $this->ensureExitNodes($c, $this->getPacConf());
        $c['log'] = ['loglevel' => 'debug', 'error' => '/work/client.log'];
        file_put_contents('/work/candidate.json', json_encode($c, JSON_THROW_ON_ERROR));
        exec('/lab/x31 run -test -c /work/candidate.json >/dev/null 2>&1', $unused, $code);
        if ($code) { echo 'FAIL native client core validation'.PHP_EOL; return false; }
        if (is_file('/work/client.pid')) exec('kill '.(int)file_get_contents('/work/client.pid').' 2>/dev/null');
        rename('/work/candidate.json', '/work/core.json');
        exec('nohup /lab/x31 run -c /work/core.json >/dev/null 2>&1 & echo $!', $pid, $code);
        file_put_contents('/work/client.pid', (string)(int)end($pid));
        $deadline = microtime(true) + 5;
        do {
            exec('kill -0 '.(int)end($pid).' 2>/dev/null', $unused, $code);
            if ($code !== 0) return false;
            $ready = true;
            foreach ($c['inbounds'] ?? [] as $inbound) {
                $socket = @stream_socket_client('tcp://127.0.0.1:'.(int)$inbound['port'], $errno, $error, .1);
                if ($socket === false) { $ready = false; break; }
                fclose($socket);
            }
            if ($ready) return true;
            usleep(50000);
        } while (microtime(true) < $deadline);
        return false;
    }
    public function exitProbe(string $id, bool $full = true): array {
        $curl = curl_init('http://11.77.0.128:18089/probe');
        curl_setopt_array($curl, [CURLOPT_PROXY => 'socks5h://127.0.0.1:'.($this->testProbePort ?: $this->exitProbePort($id)),
            CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 4, CURLOPT_NOPROXY => '']);
        $body = curl_exec($curl);
        if ($body !== "managed-main-pass\n") {
            echo 'RETRY native traffic curl code '.curl_errno($curl).' HTTP '.(int)curl_getinfo($curl, CURLINFO_RESPONSE_CODE).PHP_EOL;
        }
        curl_close($curl);
        return ['ok' => $body === "managed-main-pass\n"];
    }
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML') {}
    public function notifyAdmins(string $text): void {}
    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false) {
        file_put_contents('/work/peer-link.txt', $text); return ['ok' => true];
    }
    public function sendFile($chat, $file, $caption = false, $to = false) {
        if (!($file instanceof CURLStringFile)) throw new RuntimeException('unexpected export');
        file_put_contents('/work/peer-'.(str_ends_with($file->postname, '.json') ? 'outbound.json' : 'subscription.txt'), $file->data);
        return ['ok' => true];
    }
    protected function managedNodeTransport(string $id, string $action, $value = null): array {
        if ($action === 'rpc' && ($value['action'] ?? '') === 'submit') file_put_contents('/work/last-request.json', json_encode($value['request'], JSON_THROW_ON_ERROR));
        try {
            $result = parent::managedNodeTransport($id, $action, $value);
            return $result;
        } catch (Throwable $error) {
            echo 'RETRY native transport '.($action === 'rpc' ? $value['action'] : $action).' at '.basename($error->getFile()).':'.$error->getLine().PHP_EOL;
            throw $error;
        }
    }
    public function transport(string $action, $value = null): array { return $this->managedNodeTransport('aabbccdd', $action, $value); }
}
function verify($ok, $name) { echo ($ok ? 'PASS ' : 'FAIL ').$name.PHP_EOL; if (!$ok) throw new RuntimeException('fixture assertion'); }
try {
    $bot = new NativeManagedBot();
    switch ($argv[1] ?? '') {
        case 'init':
            $bot->setPacConf(['transport' => 'Reality', 'xray_core' => 'origin',
                'managed_nodes' => ['aabbccdd' => ['name' => 'native', 'connected' => false]]]);
            file_put_contents('/work/controller.pub', $bot->transport('public')['public_key']);
            break;
        case 'connect':
            $bot->saveManagedNodeEndpoint('11.77.0.4 2222 '.trim(file_get_contents('/work/host.pub')), 'aabbccdd');
            verify($bot->managedNodes()['aabbccdd']['connected'], 'main bot enrolls node over pinned SSH');
            verify($bot->exitProbe('aabbccdd')['ok'], 'main generated route carries real traffic');
            break;
        case 'configure':
            $options = $bot->managedNodes()['aabbccdd']['status']['options'];
            $options['xray']['encryption'] = ['auth' => 'mlkem768', 'mode' => 'random'];
            $bot->managedNodeSubmit('aabbccdd', 'configure', $options);
            verify(!empty($bot->managedNodes()['aabbccdd']['job']), 'main saves asynchronous node job');
            break;
        case 'vpn-sources':
            // The card screen: list input -> draft -> Apply, as an administrator does it.
            $bot->managedNodeVpnSourcesMenu('aabbccdd');
            $bot->saveManagedNodeField('11.77.0.200 2606:4700:4700::200', 'aabbccdd', 'vpn_sources');
            verify(($bot->managedNodes()['aabbccdd']['draft']['vpn_sources'] ?? null) === ['11.77.0.200', '2606:4700:4700::200'], 'VPN-only list saved in the draft');
            $bot->managedNodeApply('aabbccdd');
            verify(!empty($bot->managedNodes()['aabbccdd']['job']) && !isset($bot->managedNodes()['aabbccdd']['draft']), 'VPN-only list submitted to the node');
            break;
        case 'vpn-sources-applied':
            verify(($bot->managedNodes()['aabbccdd']['status']['options']['vpn_sources'] ?? null) === ['11.77.0.200', '2606:4700:4700::200'], 'node reports the applied VPN-only list');
            break;
        case 'wg-enable':
        case 'wg-disable':
        case 'awg-enable':
        case 'awg-disable':
            $options = $bot->managedNodes()['aabbccdd']['status']['options'];
            $enable = str_ends_with($argv[1], '-enable');
            $channel = str_starts_with($argv[1], 'awg-') ? 'amnezia' : 'wireguard';
            $options[$channel] = ['enabled' => $enable, 'active' => $enable, 'mtu' => 1280];
            $bot->managedNodeSubmit('aabbccdd', 'configure', $options);
            verify(!empty($bot->managedNodes()['aabbccdd']['job']), 'main submits backup channel switch');
            break;
        case 'wg-rotate':
        case 'awg-rotate':
            $bot->managedNodeSubmit('aabbccdd', 'rotate', $argv[1] === 'awg-rotate' ? 'amnezia' : 'wireguard');
            verify(!empty($bot->managedNodes()['aabbccdd']['job']), 'main submits WireGuard identity rotation');
            break;
        case 'wg-traffic':
            verify($bot->exitNodeOutbound($bot->exitNodes()['aabbccdd'])['protocol'] === 'wireguard', 'main route selects WireGuard');
            verify($bot->exitProbe('aabbccdd')['ok'], 'WireGuard passes traffic while VLESS port is blocked');
            break;
        case 'awg-traffic':
            verify(($bot->exitNodes()['aabbccdd']['managed_profile']['channel'] ?? '') === 'amnezia', 'main selects Amnezia carrier');
            verify($bot->exitProbe('aabbccdd')['ok'], 'Amnezia carries real traffic while public VLESS is blocked');
            break;
        case 'vless-traffic':
            verify($bot->exitNodeOutbound($bot->exitNodes()['aabbccdd'])['protocol'] === 'vless', 'main returns to VLESS');
            verify($bot->exitProbe('aabbccdd')['ok'], 'VLESS traffic restored after disabling backup');
            break;
        case 'poll':
            $bot->checkManagedNodes();
            if ($bot->managedNodes()['aabbccdd']['job']) exit(2);
            if (!empty($bot->managedNodes()['aabbccdd']['error'])) echo 'FAIL controller result '.(in_array($bot->managedNodes()['aabbccdd']['error'], ['rolled_back', 'probe_failed']) ? $bot->managedNodes()['aabbccdd']['error'] : 'other').PHP_EOL;
            verify(empty($bot->managedNodes()['aabbccdd']['error']), 'main confirms successful node change');
            verify($bot->exitProbe('aabbccdd')['ok'], 'confirmed node carries real traffic');
            break;
        case 'backup':
            $extra = $bot->backupExtraFiles();
            verify(count($extra) === 4, 'main backup includes SSH identity endpoint and node snapshot');
            file_put_contents('/work/backup.json', json_encode(['pac' => $bot->getPacConf(), 'extra' => $extra], JSON_THROW_ON_ERROR));
            break;
        case 'delete':
            $bot->exitDelete('aabbccdd', true);
            verify(!isset($bot->managedNodes()['aabbccdd']) && !isset($bot->exitNodes()['aabbccdd']), 'native deletion removes controller card and route together');
            verify(!is_dir('/ssh/nodes/aabbccdd'), 'native deletion removes local SSH identity and snapshot');
            // Only the archived controller key stays (nodes/retired/...): the
            // server still trusts it, and re-adding the server reuses it.
            $extra = array_keys($bot->backupExtraFiles());
            verify(count($extra) === 2 && !array_filter($extra, static fn($path) => !preg_match('~^nodes/retired/[a-f0-9]{32}/key(?:\.pub)?$~D', $path)),
                'deleted node keeps only its archived controller key in later backups');
            break;
        case 'ssh-edit':
            $before = file_get_contents('/ssh/nodes/aabbccdd/endpoint.json');
            $routes = $bot->exitNodes();
            $bot->saveManagedNodeSsh('11.77.0.2 2223', 'aabbccdd');
            verify(file_get_contents('/ssh/nodes/aabbccdd/endpoint.json') === $before, 'failed SSH port change keeps previous endpoint');
            $bot->saveManagedNodeSsh('11.77.0.2 2222', 'aabbccdd');
            $after = json_decode(file_get_contents('/ssh/nodes/aabbccdd/endpoint.json'), true, 64, JSON_THROW_ON_ERROR);
            verify($after['address'] === '11.77.0.2', 'SSH address changed after actual pinned RPC check');
            verify($bot->transport('rpc', ['action' => 'ping']) === ['schema' => 1], 'new SSH endpoint actually controls the node');
            verify($bot->exitNodes() === $routes && $bot->exitProbe('aabbccdd')['ok'], 'SSH endpoint change preserves VPN profile and traffic');
            break;
        case 'ssh6-edit':
            $before = file_get_contents('/ssh/nodes/aabbccdd/endpoint.json');
            $routes = $bot->exitNodes();
            $pinPath = '/ssh/hosts/xr/ssh_host_ed25519_key.pub';
            $pin = file_get_contents($pinPath);
            $wrong = $bot->transport('public')['public_key'];
            try {
                file_put_contents($pinPath, $wrong);
                $bot->saveManagedNodeSsh('2606:4700:4700::1111 2222', 'aabbccdd');
                verify(file_get_contents('/ssh/nodes/aabbccdd/endpoint.json') === $before, 'incorrect IPv6 hop host pin preserves previous endpoint');
            } finally { file_put_contents($pinPath, $pin); }
            $rejected = false;
            try { $bot->transport('connect', ['address' => '2606:4700:4700::1111', 'port' => 2222, 'host_key' => $wrong]); }
            catch (Throwable $error) { $rejected = true; }
            verify($rejected && file_get_contents('/ssh/nodes/aabbccdd/endpoint.json') === $before, 'incorrect end-to-end node host pin rejected through IPv6 hop');
            $bot->saveManagedNodeSsh('2606:4700:4700::1111 2222', 'aabbccdd');
            $after = json_decode(file_get_contents('/ssh/nodes/aabbccdd/endpoint.json'), true, 64, JSON_THROW_ON_ERROR);
            verify($after['address'] === '2606:4700:4700::1111', 'IPv4-only PHP saves IPv6 SSH endpoint after real proxy handshake');
            verify($bot->transport('rpc', ['action' => 'ping']) === ['schema' => 1], 'pinned IPv6 SSH hop reaches actual node RPC');
            verify($bot->exitNodes() === $routes && $bot->exitProbe('aabbccdd')['ok'], 'IPv6 SSH management preserves VPN data traffic');
            break;
        case 'cold-rebind':
            $oldEndpoint = json_decode(file_get_contents('/ssh/nodes/aabbccdd/endpoint.json'), true, 64, JSON_THROW_ON_ERROR);
            $oldSnapshot = hash_file('sha256', '/ssh/nodes/aabbccdd/snapshot.json');
            $newPin = trim(file_get_contents('/work/new-host.pub'));
            verify($oldEndpoint['host_key'] !== $newPin, 'reinstalled fixture has a different SSH host identity');
            $denied = false;
            try { $bot->transport('rpc', ['action' => 'ping']); }
            catch (Throwable $error) { $denied = true; }
            verify($denied, 'old host pin rejects the reinstalled node');
            verify(!$bot->exitProbe('aabbccdd')['ok'], 'fresh node rejects the previous VPN identity');
            $method = method_exists($bot, 'saveManagedNodeRebind') ? 'saveManagedNodeRebind' : 'saveManagedNodeEndpoint';
            $bot->$method('11.77.0.4 2222 '.$newPin, 'aabbccdd');
            $current = json_decode(file_get_contents('/ssh/nodes/aabbccdd/endpoint.json'), true, 64, JSON_THROW_ON_ERROR);
            verify($current['host_key'] === $newPin, 'existing card accepts an explicitly verified replacement host pin');
            $bot->managedNodeBackupRefresh();
            verify(hash_file('sha256', '/ssh/nodes/aabbccdd/snapshot.json') === $oldSnapshot, 'backup refresh preserves recovery source instead of fresh default state');
            verify($bot->transport('rpc', ['action' => 'ping']) === ['schema' => 1], 'replacement host is controlled using the saved controller SSH key');
            break;
        case 'cold-restored':
            verify(empty($bot->managedNodes()['aabbccdd']['recovery_required']), 'successful restoration clears recovery state');
            $backup = json_decode(file_get_contents('/work/backup.json'), true, 64, JSON_THROW_ON_ERROR);
            verify($bot->exitNodes()['aabbccdd']['link'] === $backup['pac']['exits']['aabbccdd']['link'], 'restored node retains the original controller identity');
            verify($bot->exitProbe('aabbccdd')['ok'], 'restored controller passes traffic after reinstall');
            $bot->testProbePort = 10873;
            verify($bot->exitProbe('aabbccdd')['ok'] || $bot->exitProbe('aabbccdd')['ok'], 'previously exported external peer profile works after reinstall and restore');
            break;
        case 'restore':
            $backup = json_decode(file_get_contents('/work/backup.json'), true, 64, JSON_THROW_ON_ERROR);
            foreach (glob('/ssh/nodes/aabbccdd/*') as $file) unlink($file);
            if (is_dir('/ssh/nodes/aabbccdd')) rmdir('/ssh/nodes/aabbccdd');
            $bot->setPacConf(['xray_core' => 'origin']);
            $bot->restoreBackupExtraFiles($backup['extra']);
            $bot->setPacConf($backup['pac']);
            verify($bot->transport('rpc', ['action' => 'ping']) === ['schema' => 1], 'restored SSH identity reconnects with host pin');
            verify($bot->restartXray($bot->getXray()), 'restored main routes accepted by Xray');
            if ($bot->managedNodes()['aabbccdd']['job']) echo "PASS restored operation metadata awaits reconciliation\n";
            else verify($bot->exitProbe('aabbccdd')['ok'], 'restored main routes carry real traffic');
            break;
        case 'node-restore':
            $bot->managedNodeRestore('aabbccdd');
            verify(empty($bot->managedNodes()['aabbccdd']['job']), 'opening restore menu leaves node unchanged');
            $hash = $bot->transport('saved')['hash'];
            $bot->managedNodeRestore('aabbccdd', $hash);
            verify(!empty($bot->managedNodes()['aabbccdd']['job']), 'main submits cached full node restoration');
            break;
        case 'restart':
            verify($bot->restartXray($bot->getXray()) && $bot->exitProbe('aabbccdd')['ok'], 'controller restart preserves node traffic');
            verify($bot->transport('rpc', ['action' => 'status'])['running'], 'node remains manageable after restart');
            break;
        case 'rotate':
        case 'submit-restart':
            $bot->managedNodeSubmit('aabbccdd', $argv[1] === 'rotate' ? 'rotate' : 'restart', $argv[1] === 'rotate' ? 'controller' : null);
            verify(!empty($bot->managedNodes()['aabbccdd']['job']), 'maintenance submitted');
            break;
        case 'peer-add':
            $bot->saveManagedNodePeerAdd('external-panel', 'aabbccdd');
            verify(!empty($bot->managedNodes()['aabbccdd']['job']), 'external peer creation submitted by main bot');
            break;
        case 'peer-export':
            $peers = $bot->managedNodes()['aabbccdd']['status']['peers'];
            $peer = array_values(array_filter($peers, static fn($p) => $p['name'] === 'external-panel'))[0];
            $key = Bot::exitEntryKey($peer['id']);
            foreach (['/work/peer-link.txt', '/work/peer-outbound.json', '/work/peer-subscription.txt'] as $file) @unlink($file);
            foreach (['link', 'json', 'sub'] as $format) $bot->managedNodePeerExport('aabbccdd', $key, $format);
            $out = json_decode(file_get_contents('/work/peer-outbound.json'), true, 64, JSON_THROW_ON_ERROR);
            verify($out['settings']['vnext'][0]['users'][0]['id'] === $peer['id'], 'exported JSON contains dedicated external identity');
            $link = html_entity_decode(strip_tags(file_get_contents('/work/peer-link.txt')), ENT_QUOTES);
            verify(base64_decode(file_get_contents('/work/peer-subscription.txt'), true) === $link."\n", 'link JSON and subscription exports agree');
            $client = ['log' => ['loglevel' => 'none'], 'inbounds' => [['listen' => '127.0.0.1', 'port' => 10873, 'protocol' => 'socks']], 'outbounds' => [$out]];
            file_put_contents('/work/peer-client.json', json_encode($client, JSON_THROW_ON_ERROR));
            exec('/lab/x31 run -test -c /work/peer-client.json >/dev/null 2>&1', $unused, $code);
            verify($code === 0, 'exported peer profile accepted by actual core');
            if (is_file('/work/peer.pid')) exec('kill '.(int)file_get_contents('/work/peer.pid').' 2>/dev/null');
            exec('nohup /lab/x31 run -c /work/peer-client.json >/dev/null 2>&1 & echo $!', $pid);
            file_put_contents('/work/peer.pid', (string)(int)end($pid)); usleep(300000);
            $bot->testProbePort = 10873;
            verify($bot->exitProbe('aabbccdd')['ok'] || $bot->exitProbe('aabbccdd')['ok'], 'external peer passes real traffic');
            break;
        case 'peer-off':
        case 'peer-rotate':
        case 'peer-delete':
            $peer = array_values(array_filter($bot->managedNodes()['aabbccdd']['status']['peers'], static fn($p) => $p['name'] === 'external-panel'))[0];
            $bot->managedNodePeerAction('aabbccdd', Bot::exitEntryKey($peer['id']), substr($argv[1], 5), true);
            verify(!empty($bot->managedNodes()['aabbccdd']['job']), 'external peer maintenance submitted');
            break;
        case 'peer-revoked':
            $bot->testProbePort = 10873;
            verify(!$bot->exitProbe('aabbccdd')['ok'], 'revoked external identity cannot pass traffic');
            $bot->testProbePort = 0;
            verify($bot->exitProbe('aabbccdd')['ok'], 'external peer revocation preserves main bot traffic');
            break;
        case 'await-rollback':
            $bot->checkManagedNodes();
            $node = $bot->managedNodes()['aabbccdd'];
            if (($node['job']['phase'] ?? '') !== 'wait_rollback') exit(2);
            verify($node['error'] === 'probe_failed', 'real traffic failure prevents node confirmation');
            break;
        case 'rolled-back':
            $bot->checkManagedNodes();
            $node = $bot->managedNodes()['aabbccdd'];
            if ($node['job']) exit(2);
            verify(($node['error'] ?? '') === 'rolled_back', 'watchdog rolls back after real confirmation deadline');
            verify($bot->exitProbe('aabbccdd')['ok'] || $bot->exitProbe('aabbccdd')['ok'], 'original client carries traffic after automatic rollback');
            break;
        default: throw new RuntimeException('unknown fixture action');
    }
} catch (Throwable $error) {
    // No messages, arguments, traces, profiles or credentials from subprocesses.
    echo 'FAIL native main controller stage '.($argv[1] ?? 'missing').' at '.basename($error->getFile()).':'.$error->getLine().' ('.get_class($error).')'.PHP_EOL;
    exit(1);
}
