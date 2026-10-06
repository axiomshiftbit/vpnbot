<?php
umask(0077);
require '/app/config.php';
require '/app/bot.php';
require '/app/i18n.php';
require '/app/calc.php';
class CycleTransport {
    public int $calls = 0;
    public function call($method, $data, $json = 0) {
        $this->calls++;
        return ['ok'=>true, 'result'=>['message_id'=>$this->calls, 'chat'=>['id'=>1]]];
    }
}
class CycleBot extends Bot {
    public array $errors = [];
    public function protocolError(string $message, string $back = '/protocolModules', string $retry = ''): void {
        $this->errors[] = $message;
    }
}
$warnings = [];
set_error_handler(function ($level, $message, $file, $line) use (&$warnings) {
    if (error_reporting() & $level) $warnings[] = ['level'=>$level, 'file'=>basename($file), 'line'=>$line];
    return true;
});
$b = new CycleBot($c['key'], $i);
$b->transport = new CycleTransport();
$b->admin = true;
$b->input = ['chat'=>1,'from'=>1,'message_id'=>1,'callback_id'=>'audit','username'=>'audit','text'=>'audit'];
$module = $argv[2] ?? 'telemt';
if (!isset(ProtocolModules::DEFAULTS[$module])) throw new RuntimeException('Invalid fixture module');
if (($argv[1] ?? '') === 'toggle') {
    $b->input['callback'] = isset(ManagedProtocol::NAMES[$module]) && $module !== 'masque'
        ? "/protocol $module toggle" : "/protocolModules $module";
    $b->action();
}
if (($argv[1] ?? '') === 'setup' && isset(ManagedProtocol::NAMES[$module])) {
    $store = $b->protocolStore($module);
    $state = $store->read();
    if ($state['settings']['host'] === '') {
        $store->configure(['host'=>'vpn.example.test', 'sni'=>'vpn.example.test',
            'certificate'=>'/certs/self_public', 'private_key'=>'/certs/self_private'], false);
    }
    $b->syncXrayProtocolUsers();
}
$settings = (new ProtocolModules($b->protocolModulesFile))->read();
$managed = isset(ManagedProtocol::NAMES[$module]) ? $b->protocolStore($module)->read() : null;
echo json_encode(['module'=>$module, 'requested'=>$settings[$module], 'enabled'=>$b->protocolModuleEnabled($module),
    'users'=>$managed === null ? null : count($managed['users']),
    'active_users'=>$managed === null ? null : count(array_filter($managed['users'], static fn($u)=>$u['enabled'])),
    'errors'=>$b->errors, 'warnings'=>$warnings, 'transport_calls'=>$b->transport->calls], JSON_UNESCAPED_UNICODE) . "\n";
