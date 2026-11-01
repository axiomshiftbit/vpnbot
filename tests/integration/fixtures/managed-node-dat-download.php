<?php
/** Actual HTTPS downloads and importFile with the real Xray config checker. */
require '/lab/tests/integration/fixtures/managed-node-dat.php';
class DatRestoreNative extends NativeDatBot {
    public function __construct() {
        parent::__construct();
        $this->update = '/work/restore.json';
        $this->pacState = ['language' => 'ru', 'limitpage' => 5, 'transport' => 'Reality'];
        $this->xrayState = ['inbounds' => [], 'outbounds' => [['tag' => 'direct', 'protocol' => 'freedom']], 'routing' => ['rules' => []]];
    }
    public function datDir(): string { return '/work/downloaded'; }
    public function validateXrayConfig(array $c, string $binary = 'xray'): bool {
        file_put_contents('/work/candidate.json', json_encode($c, JSON_THROW_ON_ERROR));
        exec('XRAY_LOCATION_ASSET=/work/downloaded /xray run -test -c /work/candidate.json >/dev/null 2>&1', $unused, $code);
        return $code === 0;
    }
    public function restoreBackupXray(array $config): bool { return $this->validateXrayConfig($config) && $this->restartXray($config); }
    public function xrayUpdateRules(?array $previousPac = null) { return $this->restartXray($this->xrayState); }
    public function restartNaive() { return true; }
    public function pacUpdate($import = '') {}
    public function adguardXrayClients() {}
    public function setUpstreamDomain($domain) {}
    public function setUpstreamDomainOcserv($domain) {}
    public function setUpstreamDomainNaive($domain) {}
    public function dnsttStart() { return true; }
    public function cloakNginx() {}
    public function protocolModuleEnabled(string $service): bool { return false; }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') { return ''; }
}
$failures = [];
function downloadCheck($ok, $name): void {
    global $failures;
    echo ($ok ? 'PASS ' : 'FAIL ') . $name . PHP_EOL;
    if (!$ok) $failures[] = $name;
}
try {
    mkdir('/work/downloaded', 0700);
    $bot = new DatRestoreNative();
    $url = 'https://11.77.0.128:18443/services.dat';
    $base = $bot->xrayState;
    $snapshot = ['pac' => $bot->pacState + ['datlist' => ['services.dat:'.$url => 1]], 'xray' => $base];
    $snapshot['xray']['routing']['rules'][] = ['type' => 'field', 'domain' => ['ext:services.dat:video'], 'outboundTag' => 'direct'];
    file_put_contents('/work/serve/services.dat', siteBlob('video'));
    file_put_contents($bot->update, json_encode($snapshot, JSON_THROW_ON_ERROR));
    downloadCheck($bot->importFile($bot->update), 'fresh restore downloads DAT over verified HTTPS');
    downloadCheck($bot->datReadMeta('services.dat')['verified'] ?? false, 'restore checks published DAT checksum');
    downloadCheck($bot->validateXrayConfig($snapshot['xray']), 'restored DAT is accepted by real Xray');
    $before = hash_file('sha256', $bot->datPath('services.dat'));
    file_put_contents('/work/serve/services.dat', '<html>bad mirror</html>');
    $changed = false;
    downloadCheck($bot->datSync(true, $changed) !== [] && !$changed && hash_file('sha256', $bot->datPath('services.dat')) === $before,
        'HTML mirror response preserves last good DAT');
    file_put_contents('/work/serve/services.dat', siteBlob('unrelated'));
    downloadCheck($bot->datSync(true, $changed) !== [] && hash_file('sha256', $bot->datPath('services.dat')) === $before,
        'missing active category preserves last good DAT');
    unlink('/work/serve/services.dat');
    downloadCheck($bot->datSync(true, $changed) !== [] && hash_file('sha256', $bot->datPath('services.dat')) === $before,
        'unavailable URL preserves last good DAT');
    // A failed source must not be reported as a completely restored backup,
    // even when an older valid cache lets the previous Xray config run.
    downloadCheck(!$bot->importFile($bot->update), 'unavailable registered source reports incomplete restore with existing cache');
    unlink($bot->datPath('services.dat'));
    $bot->xrayState = $base;
    downloadCheck(!$bot->importFile($bot->update) && $bot->xrayState === $base,
        'missing required DAT refuses fresh restore and keeps prior Xray');
    file_put_contents('/work/serve/services.dat', siteBlob('video'));
    downloadCheck($bot->importFile($bot->update), 'recovered URL completes restore on retry');
    downloadCheck(!$bot->datHttpGet('https://127.0.0.1:18443/services.dat', [], 4096, 2)['ok'], 'download guard rejects private endpoint');
    downloadCheck(!$bot->datHttpGet('https://11.77.0.128:18443/redirect.dat', [], 4096, 2)['ok'], 'download guard rejects HTTPS redirect into loopback');
} catch (Throwable $error) {
    echo 'FAIL DAT restore fixture at '.basename($error->getFile()).':'.$error->getLine().' ('.get_class($error).')'.PHP_EOL;
    exit(1);
}
exit($failures ? 1 : 0);
