<?php
// Только синтетический стенд bootstrap.py. Полная копия остаётся в /logs,
// наружу выводятся имена проверок и булевы результаты, без содержимого копии.
if (getenv('TELEGRAM_API') !== 'tg-audit:8443') throw new RuntimeException('Synthetic stand required');
require '/app/config.php'; require '/app/bot.php'; require '/app/i18n.php';
set_error_handler(static function ($level, $message, $file, $line) {
    if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line);
    return false;
});
$b = new Bot($c['key'], $i);
$b->transport = new class {
    public function call($method, $data, $json = 0) { return ['ok' => true, 'result' => ['message_id' => 1, 'chat' => ['id' => 1]]]; }
};
$b->admin = true;
$b->input = ['chat' => 1, 'from' => 1, 'message_id' => 1, 'callback_id' => 'audit', 'username' => 'audit', 'text' => 'audit'];
$file = '/logs/audit1031-full-backup.json';
$checks = [];
function verify(bool $ok, string $name): void {
    global $checks;
    $checks[$name] = $ok;
    if (!$ok) throw new RuntimeException($name);
}
try {
    switch ($argv[1] ?? '') {
        case 'save-baseline':
            $copy = $b->export();
            verify(is_string($copy), 'baseline-export');
            file_put_contents('/logs/audit1031-baseline.json', $copy);
            chmod('/logs/audit1031-baseline.json', 0600);
            break;
        case 'restore-baseline':
            $b->update = '/logs/audit1031-baseline.json';
            verify($b->importFile($b->update) === true, 'baseline-restored');
            break;
        case 'seed':
            verify(extension_loaded('pdo_sqlite'), 'sqlite-runtime');
            $b->changeTransport('xhttp');
            $b->ensureDefaultTemplates();
            $p = $b->getPacConf();
            unset($p['singtemplates']['15_dns_google']);
            $p['singtemplates']['15_direct']['log']['level'] = 'debug';
            $p['relays']['audit-relay'] = ['address' => '198.51.100.8', 'awg_address' => '2001:db8::8', 'portmap' => []];
            $p['ip_limit'] = 300; $p['ip_count'] = 2;
            $p['hwid_limit_enabled'] = 1; $p['hwid_device_count'] = 2;
            $name = array_key_first($p['telemt_users']);
            verify(is_string($name), 'telemt-user-exists');
            $p['telemt_user_limits'][$name] = ['quota' => 1073741824, 'ips' => 2, 'period' => 'monthly'];
            $b->setPacConf($p);
            $x = $b->getXray();
            $uid = $x['inbounds'][0]['settings']['clients'][0]['id'];
            $x['inbounds'][0]['settings']['clients'][0]['hwid_limit'] = 2;
            $x['inbounds'][0]['settings']['clients'][0]['traffic'] = 1073741824;
            verify($b->restartXray($x) === true, 'real-xray-accepts-seed');
            $b->setHwidStorage([$uid => ['audit-a' => ['time' => 1], 'audit-b' => ['time' => 2]]]);
            $now = time();
            $quota = ['last_reset_epoch_secs' => $now, 'users' => [$name => ['used_bytes' => 123456,
                'last_reset_epoch_secs' => $now, 'quota_period' => 'monthly', 'period_cursor_epoch_secs' => $now]]];
            $b->telemtQuotaRestore($quota, $p);
            verify($b->telemtQuotaRead($b->getPacConf())['users'][$name]['used_bytes'] === 123456, 'real-telemt-quota-seeded');
            $copy = $b->export();
            verify(is_string($copy), 'full-export');
            file_put_contents($file, $copy); chmod($file, 0600);
            break;
        case 'mutate':
            $p = $b->getPacConf(); $p['relays'] = []; $p['singtemplates'] = []; $p['installed_templates'] = [];
            $p['ip_count'] = 9; $p['hwid_device_count'] = 9;
            $b->setPacConf($p); $b->setHwidStorage([]);
            $x = $b->getXray();
            $x['inbounds'][0]['settings']['clients'][0]['id'] = '00000000-0000-4000-8000-000000000099';
            verify($b->restartXray($x) === true, 'real-xray-accepts-changed-identity');
            $b->changeTransport('Websocket');
            verify($b->getPacConf()['transport'] === 'Websocket', 'transport-changed-before-restore');
            // Имитируем чистую БД отдельным действием после завершения CLI.
            break;
        case 'restore':
            $b->update = $file;
            verify($b->importFile($file) === true, 'full-import-real-services');
            break;
        case 'verify':
            $copy = json_decode(file_get_contents($file), true, 512, JSON_THROW_ON_ERROR);
            $p = $b->getPacConf();
            foreach (['singtemplates', 'clashtemplates', 'installed_templates', 'relays', 'ip_limit', 'ip_count',
                'hwid_limit_enabled', 'hwid_device_count', 'telemt_user_limits', 'transport'] as $key) {
                verify(($p[$key] ?? null) === ($copy['pac'][$key] ?? null), 'restored-' . $key);
            }
            verify($b->getHwidStorage() === $copy['hwid'], 'restored-hwid-in-sqlite');
            $uid = array_key_first($copy['hwid']);
            verify(!$b->hwidRegister($uid, 'audit-third', 2, []), 'restored-hwid-limit-enforced');
            $x = $b->getXray();
            verify($x['inbounds'][0]['settings']['clients'] === $copy['xray']['inbounds'][0]['settings']['clients'], 'restored-xray-identities-and-limits');
            verify($x['inbounds'][0]['streamSettings']['network'] === 'xhttp', 'restored-xhttp');
            verify($b->xhttpClientMode() === 'stream-up', 'restored-nginx-http2');
            verify($b->telemtQuotaRead($p) === $copy['telemt_quota'], 'restored-telemt-usage-and-calendar');
            $b->ensureDefaultTemplates();
            verify($b->getPacConf()['singtemplates'] === $copy['pac']['singtemplates'], 'edited-and-deleted-templates-stay-restored');
            $data = $b->relayTemplateData($p);
            verify(in_array('198.51.100.8/32', $data['ips'], true) && in_array('2001:db8::8/128', $data['ips'], true), 'restored-relay-expands-without-cache');
            break;
        default: throw new RuntimeException('Unknown fixture action');
    }
    echo json_encode(['ok' => true, 'checks' => $checks]) . "\n";
} catch (Throwable $e) {
    // Сообщение исключения может включать данные runtime: выводим только тип.
    echo json_encode(['ok' => false, 'checks' => $checks, 'error_type' => get_class($e), 'line' => $e->getLine()]) . "\n";
    exit(1);
}
