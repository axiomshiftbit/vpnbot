<?php
// Actual Bot mutation. The controller transport is docker exec, not SSH.
require '/audit-source/app/bot.php';
class NativeClassicProxy extends Bot
{
    public int $menus = 0;
    public function __construct() {
        $this->pac = '/config/pac.json'; $this->language = 'ru';
        $this->input = ['chat' => 1, 'message_id' => 1];
    }
    public function menu($type = false, $arg = false, $return = false) { $this->menus++; }
    public function protocolModuleEnabled(string $name): bool { return in_array($name, ['ss', 'proxy'], true); }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') {
        echo json_encode(['rpc' => ['cmd' => $cmd, 'service' => $service]]), "\n"; flush();
        $response = json_decode((string)fgets(STDIN), true, 512, JSON_THROW_ON_ERROR);
        $this->sshFailed = !($response['ok'] ?? false);
        return (string)($response['output'] ?? '');
    }
}
$b = new NativeClassicProxy();
$values = json_decode(file_get_contents('/config/generations.json'), true, 512, JSON_THROW_ON_ERROR);
try { $ok = $b->sspwdch($values['new']) !== false; }
catch (Throwable $error) { $ok = false; }
echo json_encode(['result' => ['ok' => $ok, 'menus' => $b->menus]]), "\n";
