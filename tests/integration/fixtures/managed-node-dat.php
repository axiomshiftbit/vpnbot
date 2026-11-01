<?php
/** Native Xray validation of DAT categories selected for an exit node. */
require '/lab/tests/managed_nodes_test.php';
umask(0077);
function datVerify(bool $ok, string $name): void {
    echo ($ok ? 'PASS ' : 'FAIL ') . $name . PHP_EOL;
    if (!$ok) throw new RuntimeException('fixture assertion');
}
function pb(int $number, string $value): string {
    $length = strlen($value); $size = '';
    do { $b = $length & 127; $length >>= 7; $size .= chr($b | ($length ? 128 : 0)); } while ($length);
    return chr($number << 3 | 2) . $size . $value;
}
function siteBlob(string $category): string {
    return pb(1, pb(1, strtoupper($category)) . pb(2, "\x08\x02" . pb(2, 'video.example.org')));
}
function ipBlob(): string {
    return pb(1, pb(1, 'RU') . pb(2, pb(1, inet_pton('198.51.100.0')) . "\x10\x18"));
}
class NativeDatBot extends ManagedFixtureBot {
    public function datDir(): string { return '/work/geodata'; }
    public function validateXrayConfig(array $c, string $binary = 'xray'): bool {
        file_put_contents('/work/candidate.json', json_encode($c, JSON_THROW_ON_ERROR));
        exec('XRAY_LOCATION_ASSET=/work/geodata /xray run -test -c /work/candidate.json >/dev/null 2>&1', $unused, $code);
        return $code === 0;
    }
    public function restartXray($c, $norestart = false) {
        $this->ensureExitNodes($c, $this->pacState);
        if (!$this->validateXrayConfig($c)) return false;
        $this->xrayState = $c;
        return true;
    }
}
try {
    mkdir('/work/geodata', 0700, true);
    foreach (['services.dat' => siteBlob('video'), 'networks.dat' => ipBlob(), 'geosite.dat' => siteBlob('youtube'), 'geoip.dat' => ipBlob()] as $file => $content) {
        file_put_contents('/work/geodata/'.$file, $content);
    }
    $bot = new NativeDatBot(); $id = 'aabbccdd';
    $bot->xrayState['inbounds'][] = ['tag' => 'vless_reality', 'listen' => '127.0.0.1', 'port' => 12345, 'protocol' => 'vless',
        'settings' => ['decryption' => 'none', 'clients' => [['id' => '22222222-2222-4222-8222-222222222222', 'email' => 'fixture', 'exit' => [$id]]]],
        'streamSettings' => ['network' => 'tcp', 'security' => 'none']];
    datVerify($bot->restartXray($bot->xrayState), 'baseline real core accepts node');
    foreach ([['services.dat', 'd', 'video', 'ext:services.dat:video'], ['networks.dat', 'i', 'ru', 'extip:networks.dat:ru'],
              ['geosite.dat', 'd', 'youtube', 'geosite:youtube'], ['geoip.dat', 'i', 'ru', 'geoip:ru']] as [$file, $type, $category, $entry]) {
        $bot->exitDatToggle($id, $bot->datFileKey($file), $type, 0, Bot::exitEntryKey($category));
        datVerify(!empty($bot->pacState['exits'][$id]['routes'][$entry]), 'real core accepts '.$type.' category from '.$file);
    }
    $rules = json_encode($bot->xrayState['routing']['rules']);
    datVerify(str_contains($rules, 'ext:services.dat:video') && str_contains($rules, 'ext:networks.dat:ru') && str_contains($rules, 'geosite:youtube') && str_contains($rules, 'geoip:ru'), 'all four DAT categories reach active node routing');
    $before = $bot->pacState;
    datVerify($bot->datCategoryError($bot->classifyRouteEntry('extip:services.dat:video')) !== null, 'shared main-bot validation rejects domain DAT as IP');
    datVerify($bot->datCategoryError($bot->classifyRouteEntry('ext:networks.dat:ru')) !== null, 'shared main-bot validation rejects IP DAT as domains');
    $bot->exitDatToggle($id, $bot->datFileKey('services.dat'), 'i', 0, Bot::exitEntryKey('video'));
    datVerify($bot->pacState === $before, 'wrong DAT content type rejected without losing routes');
    $bot->pacState['exits'][$id]['routes']['extip:services.dat:video'] = 0;
    $bot->exitDatToggle($id, $bot->datFileKey('services.dat'), 'i', 0, Bot::exitEntryKey('video'));
    $reenableSafe = empty($bot->pacState['exits'][$id]['routes']['extip:services.dat:video']);
    $bot->pacState = $before; $bot->restartXray($bot->xrayState);
    file_put_contents('/work/geodata/type-change.dat', pb(1, pb(1, 'VIDEO') . pb(2, pb(1, inet_pton('198.51.100.0')) . "\x10\x18")));
    $replacementSafe = !$bot->validateDatReplacement('services.dat', 'type-change.dat');
    echo ($reenableSafe ? 'PASS ' : 'FAIL ').'disabled wrong-type category cannot be re-enabled'.PHP_EOL;
    echo ($replacementSafe ? 'PASS ' : 'FAIL ').'active DAT cannot change from domains to IP on update'.PHP_EOL;
    datVerify($reenableSafe && $replacementSafe, 'DAT type guards cover existing routes and asset updates');
    file_put_contents('/work/geodata/new.dat', siteBlob('unrelated'));
    datVerify(!$bot->validateDatReplacement('services.dat', 'new.dat'), 'replacement missing active node category rejected by core');
    file_put_contents('/work/geodata/new.dat', siteBlob('video') . siteBlob('additional'));
    datVerify($bot->validateDatReplacement('services.dat', 'new.dat'), 'replacement retaining active node category accepted by core');
    $backup = json_decode(json_encode(['pac' => $bot->pacState, 'xray' => $bot->xrayState], JSON_THROW_ON_ERROR), true);
    $bot = new NativeDatBot(); $bot->pacState = $backup['pac'];
    datVerify($bot->restartXray($backup['xray']), 'restored node route configuration accepted by core with restored assets');
    datVerify($bot->datRefCount($bot->pacState, 'services.dat') === 1 && $bot->datRefCount($bot->pacState, 'networks.dat') === 1, 'restored node DAT references retained');
    unlink('/work/geodata/services.dat');
    datVerify(!$bot->validateXrayConfig($backup['xray']), 'core refuses restored configuration when required DAT asset is absent');
    file_put_contents('/work/geodata/services.dat', siteBlob('video'));
    datVerify($bot->restartXray($backup['xray']), 'restoring DAT asset restores valid node configuration');
} catch (Throwable $e) {
    echo 'FAIL native DAT fixture at line '.$e->getLine().' ('.get_class($e).')'.PHP_EOL;
    exit(1);
}
