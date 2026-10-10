<?php
umask(0077);
require '/app/config.php';
require '/app/bot.php';
require '/app/i18n.php';
require '/app/calc.php';
class AuditTransport {
    public int $calls = 0;
    public array $messages = [];
    public function call($method, $data, $json = 0) {
        $this->calls++;
        if (is_array($data) && isset($data['text'])) $this->messages[]=$data['text'];
        if (is_array($data) && ($data['document'] ?? null) instanceof CURLStringFile) {
            $dir='/logs/audit-files';
            if (!is_dir($dir)) mkdir($dir,0700,true);
            file_put_contents($dir.'/'.basename($data['document']->postname),$data['document']->data);
        }
        return ['ok'=>true,'result'=>['message_id'=>$this->calls,'chat'=>['id'=>1]]];
    }
}
$warnings=[];
set_error_handler(function($severity,$message,$file,$line) use (&$warnings) {
    if (error_reporting() & $severity) {
        $warnings[]=['level'=>$severity,'message'=>preg_replace('~[A-Za-z0-9_+/=-]{24,}~','<redacted>',$message),'file'=>basename($file),'line'=>$line];
    }
    return true;
});
$b=new Bot($c['key'],$i);
$b->transport=new AuditTransport();
$b->admin=true;
$b->input=['chat'=>1,'from'=>1,'message_id'=>1,'callback_id'=>'audit','username'=>'audit','text'=>'audit'];
$action=$argv[1] ?? '';
$result=[];
switch ($action) {
    case 'update-permissions':
        $b->restart();$result=[];
        foreach (['key','curl','reload_message','pipe'] as $name) {
            clearstatcache(true,'/update/'.$name);
            $result[$name]=(fileperms('/update/'.$name)&0777)===0600;
            file_put_contents('/update/'.$name,'');
        }
        break;
    case 'import-setup':
        $x=$b->getXray();$p=$b->getPacConf();
        $relay="Реле / + & # 🇷🇺";
        $state=['email'=>$x['inbounds'][0]['settings']['clients'][0]['email'],'relay'=>$relay,
            'relays'=>$p['relays'] ?? [],'sub_rate_max'=>$p['sub_rate_max'] ?? 30];
        file_put_contents('/logs/audit-import-state.json',json_encode($state));
        $x['inbounds'][0]['settings']['clients'][0]['email']="Audit 🇷🇺 / + & # ' <node>";$b->saveXray($x);
        $p['relays'][$relay]=['address'=>'203.0.113.10','awg_address'=>'','portmap'=>[]];
        $p['sub_rate_max']=300;$b->setPacConf($p);
        $b->userXr(0);$origin=end($b->transport->messages);
        $b->relaySub(0,$relay);$via=end($b->transport->messages);
        $links=[];
        foreach (['origin'=>$origin,'relay'=>$via] as $mode=>$html) {
            preg_match_all('~<a href="([^"]+)">import://([^<]+)</a>~',$html,$matches,PREG_SET_ORDER);
            foreach ($matches as $m) $links[$mode][$m[2]]=html_entity_decode($m[1],ENT_QUOTES,'UTF-8');
        }
        file_put_contents('/logs/audit-import-links.json',json_encode(['links'=>$links,'relay'=>$relay,
            'name'=>$x['inbounds'][0]['settings']['clients'][0]['email']]));
        $result=['origin_links'=>count($links['origin'] ?? []),'relay_links'=>count($links['relay'] ?? [])];
        break;
    case 'import-restore':
        $state=json_decode(file_get_contents('/logs/audit-import-state.json'),true);
        $x=$b->getXray();$x['inbounds'][0]['settings']['clients'][0]['email']=$state['email'];$b->saveXray($x);
        $p=$b->getPacConf();$p['relays']=$state['relays'];$p['sub_rate_max']=$state['sub_rate_max'];$b->setPacConf($p);
        $result=['restored'=>true];
        break;
    case 'dnstt-identity-save':
        $snapshot=json_decode($b->export(),true);
        file_put_contents('/logs/audit-dnstt-backup.json',json_encode(['dnstt'=>$snapshot['dnstt']]));
        $result=['saved'=>!empty($snapshot['dnstt']['ssh_private'])];
        break;
    case 'dnstt-identity-restore':
        $b->update='/logs/audit-dnstt-backup.json';$b->importFile($b->update);
        $result=['error_messages'=>count(array_filter($b->transport->messages,fn($v)=>str_contains($v,'❌')))];
        break;
    case 'backup-save':
        $snapshot=$b->export();
        if ($snapshot===false) throw new RuntimeException('Export failed');
        file_put_contents('/logs/audit-full-backup.json',$snapshot);
        $v=json_decode($snapshot,true);$result=['sections'=>count($v),'dnstt_ssh'=>!empty($v['dnstt']['ssh_private']),'ovpn_files'=>count($v['ovpn'] ?? []),'ipsec_files'=>count($v['ipsec'] ?? [])];
        break;
    case 'backup-restore':
        $b->update='/logs/audit-full-backup.json';$restored=$b->importFile($b->update);
        $result=['ok'=>$restored===true,'error_messages'=>count(array_filter($b->transport->messages,fn($v)=>str_contains($v,'❌')))];
        break;
    case 'ipsec-bad-restore':
        $old=hash_file('sha256','/config/ipsec/psk');
        $accepted=$b->importIpsecPki(['psk'=>base64_encode('must-not-apply'),'broken'=>'%%%']);
        $result=['rejected'=>$accepted===false,'preserved'=>hash_file('sha256','/config/ipsec/psk')===$old];
        break;
    case 'xray-bad-restart':
        $x=$b->getXray();$old=hash_file('sha256',$b->xrayConf);
        $x['inbounds'][0]['streamSettings']['network']='invalid-network';
        $result=['rejected'=>$b->restartXray($x)===false,'preserved'=>hash_file('sha256',$b->xrayConf)===$old];
        break;
    case 'menus':
        foreach (['wg','pac','adguard','config','ss','lang','oc','naive','hy','tt','ovpn','l2tp','ikev2','mirror'] as $menu) {
            $start=count($warnings);
            try { $b->menu($menu,0); $result[$menu]=['ok'=>true,'warnings'=>count($warnings)-$start]; }
            catch (Throwable $e) { $result[$menu]=['ok'=>false,'exception'=>get_class($e),'file'=>basename($e->getFile()),'line'=>$e->getLine()]; }
        }
        break;
    case 'wg-rotate':
        $b->promptInstWG((int)($argv[2] ?? 0));
        $b->rotateAllPeerKeys(0,true);
        break;
    case 'wg-flags':
        $b->promptInstWG((int)($argv[2] ?? 0));
        $b->toggleRandomTrailers(0);
        $b->toggleDisableCookies(0);
        break;
    case 'ipsec-init':
        if (!isset($b->getL2tpUsers()['auditl2'])) $b->addl2us('auditl2');
        if (!isset($b->getIkev2Users()['auditike'])) $b->addik2us('auditike');
        $result=['l2tp_users'=>count($b->getL2tpUsers()),'ikev2_users'=>count($b->getIkev2Users())];
        break;
    case 'ike-status':
        $state=$b->getIkev2Status()['auditike'] ?? [];
        $result=['online'=>(bool)$state,'virtual'=>$state['virtual'] ?? '', 'rx'=>$state['rx'] ?? 0,'tx'=>$state['tx'] ?? 0];
        break;
    case 'ike-disable':
        $b->disableIkev2User('auditike');
        break;
    case 'ike-enable':
        $b->enableIkev2User('auditike');
        break;
    case 'l2-status':
        $state=$b->getL2tpOnline()['auditl2'] ?? [];
        $result=['online'=>(bool)$state,'virtual'=>$state['ip'] ?? ''];
        break;
    case 'l2-disable':
        $b->disableL2tpUser('auditl2');
        break;
    case 'l2-enable':
        $b->enableL2tpUser('auditl2');
        break;
    case 'l2-profile':
    case 'ike-profile':
    case 'ike-profile-auto':
        // Профиль несёт пароль и PSK: в каталог журналов стенда не пишется.
        $capture=new class {
            public int $calls=0; public $document=null; public array $messages=[];
            public function call($method,$data,$json=0) {
                $this->calls++;
                if (is_array($data) && ($data['document'] ?? null) instanceof CURLStringFile) $this->document=$data['document'];
                return ['ok'=>true,'result'=>['message_id'=>$this->calls,'chat'=>['id'=>1]]];
            }
        };
        $b->transport=$capture;
        $sent=$action==='l2-profile' ? $b->sendL2tpProfile('auditl2') : $b->sendIkev2Profile('auditike',$action==='ike-profile-auto');
        $result=['sent'=>$sent===true,'name'=>$capture->document?->postname,'xml'=>$capture->document?->data];
        break;
    case 'ovpn-proto':
        $b->toggleOvpnProto(); $result=['proto'=>$b->getOvpnProto()];
        break;
    case 'ovpn-revoke':
        $b->delOvpnUser('auditov',true);
        break;
    case 'ovpn-pki-save':
        file_put_contents('/logs/audit-ovpn-pki.json',json_encode($b->exportOvpnPki()));
        break;
    case 'ovpn-pki-restore':
        $result=['ok'=>$b->importOvpnPki(json_decode(file_get_contents('/logs/audit-ovpn-pki.json'),true))];
        $b->restartOvpn();
        break;
    case 'ovpn-init':
        if (!in_array('auditov',$b->getOvpnUsers(),true)) $b->addovus('auditov');
        $result=['users'=>count($b->getOvpnUsers())];
        break;
    case 'ovpn-export':
        $result=['ok'=>$b->sendOvpnConfigFile('auditov')];
        break;
    case 'ovpn-status':
        $state=$b->getOvpnStatus()['auditov'] ?? [];
        $result=['online'=>(bool)$state,'state'=>$state];
        break;
    case 'ovpn-disable':
        $b->disableOvpnUser('auditov');
        break;
    case 'ovpn-enable':
        $b->enableOvpnUser('auditov');
        break;
    case 'oc-init':
        $b->addocus('auditoc');
        $b->disableOcCamouflage();
        $result=['users'=>count($b->getClientsOc())];
        break;
    case 'oc-delete':
        $i=array_search('auditoc',$b->getClientsOc(),true);
        if ($i!==false) $b->deloc($i);
        break;
    case 'oc-export':
        $p=$b->getPacConf();
        file_put_contents('/logs/audit-oc.json',json_encode(['user'=>'auditoc','password'=>$p['ocserv_users']['auditoc'] ?? '', 'host'=>$b->getHashSubdomain('oc').'.vpnbot.test']));
        break;
    case 'oc-route':
        $b->setUpstreamDomainOcserv('vpnbot.test');
        break;
    case 'tls-self':
        $p=$b->getPacConf();$p['letsencrypt']='self';$b->setPacConf($p);$b->cloakNginx();
        break;
    case 'telemt-web-config':
        $p=$b->getPacConf();$p['letsencrypt']='letsencrypt';$p['telemt_web']=1;$p['telemt_web_secret_mode']=$argv[2] ?? 'dd';$p['telemt_web_carrier']=$argv[3] ?? 'https-lanes';$p['telemt_web_negotiation']='off';$p['telemt_user_enabled']['auditmt']=true;$b->setPacConf($p);$b->telemtWebSync();$b->cloakNginx();
        break;
    case 'warp-toggle':
        $b->offWarp();
        $result=['off'=>!empty($b->getPacConf()['warpoff'])];
        break;
    case 'warp-status':
        $result=$b->warpStatus();
        break;
    case 'ad-export':
        $p=$b->getPacConf();$xr=$b->getXray();$ad=yaml_parse_file('/config/AdGuardHome.yaml');
        file_put_contents('/logs/audit-ad.json',json_encode(['password'=>$p['adpswd'],'hash'=>$b->getHashBot(),'domain'=>$p['domain'],'doh_id'=>$b->dohClientId($xr['inbounds'][0]['settings']['clients'][0]['id']),'tls'=>$ad['tls'],'dns'=>$ad['dns']]));
        break;
    case 'ad-sync':
        $b->adguardSync();$b->adguardXrayClients();
        break;
    case 'naive-rotate':
        $b->genNaivePass();
        break;
    case 'telemt-init':
        $b->telemtUserAdd('auditmt');
        break;
    case 'telemt-mode':
        $b->telemtSetMode($argv[2]);
        break;
    case 'telemt-toggle':
        $b->telemtToggleUser('auditmt');
        break;
    case 'telemt-rotate':
        $b->telemtRegen('auditmt');
        break;
    case 'telemt-export':
        $p=$b->getPacConf();
        file_put_contents('/logs/audit-telemt.json',json_encode(['secret'=>$p['telemt_users']['auditmt'],'mode'=>$b->telemtModeOf($p),'sni'=>$p['telemt_domain'] ?? 'www.google.com','link'=>$b->linkTelemt('auditmt'),'web'=>$b->linkTelemtWeb('auditmt')]));
        break;
    case 'telemt-web':
        $b->telemtWebToggle();
        break;
    case 'telemt-diag':
        $p=$b->getPacConf();$p['telemt_beobachten']=1;$b->setPacConf($p);$b->restartTelemt();
        $result=$b->telemtApiFetch(['/v1/health']);
        break;
    case 'ss-init':
        if (!empty($b->getSSConfig()['plugin'])) $b->v2ray();
        if (!empty($b->getCloakConfig()['Enabled'])) $b->cloak();
        if (!empty($b->getStlsConfig()['Enabled'])) $b->simpleTls();
        $b->sspwdch(bin2hex(random_bytes(16)),true);
        break;
    case 'ss-mode':
        $mode=$argv[2] ?? 'plain';
        if (!empty($b->getSSConfig()['plugin']) && $mode!=='v2ray') $b->v2ray();
        if (!empty($b->getCloakConfig()['Enabled']) && $mode!=='cloak') $b->cloak();
        if (!empty($b->getStlsConfig()['Enabled']) && $mode!=='simple-tls') $b->simpleTls();
        if ($mode==='v2ray' && empty($b->getSSConfig()['plugin'])) $b->v2ray();
        if ($mode==='cloak' && empty($b->getCloakConfig()['Enabled'])) $b->cloak();
        if ($mode==='simple-tls' && empty($b->getStlsConfig()['Enabled'])) $b->simpleTls();
        break;
    case 'ss-export':
        file_put_contents('/logs/audit-ss.json',json_encode(['link'=>$b->buildSSLink($b->getHashBot())]));
        break;
    case 'ss-rotate':
        $b->sspwdch(bin2hex(random_bytes(16)),true);
        break;
    case 'dnstt-init':
        $b->setdnsttPassword(bin2hex(random_bytes(16)));
        $b->setdnsttDomain('t.vpnbot.test');
        break;
    case 'dnstt-disable':
        $b->setdnsttPassword('');
        break;
    case 'dnstt-reload':
        $result=['ok'=>$b->dnsttStart()];
        break;
    case 'dnstt-export':
        $p=$b->getPacConf();
        file_put_contents('/logs/audit-dnstt.json',json_encode(['domain'=>$p['dnsttDomain'],'password'=>$p['dnsttPassword'],'public_key'=>trim(file_get_contents('/config/dnstt/server.pub'))]));
        break;
    case 'hy-init':
        $b->genHyPass();
        break;
    case 'hy-obfs':
        $b->toggleHyObfs();
        break;
    case 'hy-export':
        $p=$b->getPacConf();
        file_put_contents('/logs/audit-hy.json',json_encode(['password'=>$p['hysteria_pass'] ?? '', 'obfs'=>$p['hysteria_obfs'] ?? '', 'link'=>$b->linkHysteria()]));
        break;
    case 'naive-init':
        $b->chnplogin('auditnp');
        $b->genNaivePass();
        $b->setUpstreamDomainNaive('vpnbot.test');
        break;
    case 'naive-export':
        $p=$b->getPacConf();
        file_put_contents('/logs/audit-naive.json',json_encode(['user'=>$p['naive']['user'],'password'=>$p['naive']['pass'], 'host'=>$b->getHashSubdomain('np').'.vpnbot.test']));
        break;
    case 'tt-init':
        $p=$b->getPacConf();$p['domain']='vpnbot.test';$b->setPacConf($p);
        if (!isset($b->getClientsTt()['audittt'])) $b->addttus('audittt');
        else $b->restartTt();
        $result=['users'=>count($b->getClientsTt()),'running'=>$b->ttRunning(),'blockers'=>$b->ttBlockers()];
        break;
    case 'tt-rotate':
        $b->genTtPass('audittt');
        break;
    case 'tt-delete':
        $b->delttus('audittt',true);
        break;
    case 'tt-export':
        $b->getTtConfig('audittt');
        break;
    case 'wg-mihomo':
        $inst=(int)($argv[2] ?? 0);$b->promptInstWG($inst);
        $p=$b->getPacConf();$p['mihomo_awg3']=1;$b->setPacConf($p);
        $clients=$b->readClients();$node=$b->getAwgClient($clients[0]['interface']['PrivateKey']);
        file_put_contents('/logs/audit-wg-mihomo.json',json_encode($node));
        break;
    case 'xray-status':
        $p=$b->getPacConf();$probe=$b->xrayCoreProbe(true);
        $result=['core'=>$b->xrayCore(),'version'=>$b->getXrayVersion(),'new_reality'=>$probe['new_reality'] ?? null,'transport'=>$p['transport'] ?? '', 'reality_domain'=>$p['reality']['domain'] ?? ''];
        break;
    case 'xray-hwid-on':
        $p=$b->getPacConf();$p['hwid_limit_enabled']=1;$p['hwid_device_count']=1;$b->setPacConf($p);
        $x=$b->getXray();$cl=$x['inbounds'][0]['settings']['clients'][0];$b->hwidUpdate(function (&$v) use ($cl) {unset($v[$cl['id']]);});
        break;
    case 'xray-hwid-off':
        $p=$b->getPacConf();$p['hwid_limit_enabled']=0;$b->setPacConf($p);
        break;
    case 'xray-sub-info':
        $x=$b->getXray();$cl=$x['inbounds'][0]['settings']['clients'][0];
        file_put_contents('/logs/audit-sub-info.json',json_encode(['prefix'=>'/pac'.$b->getHashBot(),'sid'=>$b->sidOf($cl),'uuid'=>$cl['id']]));
        break;
    case 'xray-quota':
        $b->xrayStatsUser();$b->saveTrafficXr('0.000001',0);$b->checkTrafficLimits();
        $cl=$b->getXray()['inbounds'][0]['settings']['clients'][0];$result=['quota_blocked'=>!empty($cl['off']) && !empty($cl['traffic_off'])];
        break;
    case 'xray-quota-reset':
        $b->saveTrafficXr('0',0);$b->resetXrUser(0);
        break;
    case 'xray-expire':
        $x=$b->getXray();$x['inbounds'][0]['settings']['clients'][0]['time']=time()-60;$b->saveXray($x);$b->shutdownClientXr();
        $result=['disabled'=>!empty($b->getXray()['inbounds'][0]['settings']['clients'][0]['off'])];
        break;
    case 'xray-enable':
        if (!empty($b->getXray()['inbounds'][0]['settings']['clients'][0]['off'])) $b->switchXr(0,1);
        break;
    case 'xray-token-rotate':
        $p=$b->getPacConf();$p['subtoken_strict']=1;$b->setPacConf($p);$b->rotateSubToken(0);
        break;
    case 'xray-route-block':
        $p=$b->getPacConf();$p['blocklist']['domain:example.com']=true;$b->setPacConf($p);$b->xrayUpdateRules();
        break;
    case 'xray-route-unblock':
        $p=$b->getPacConf();unset($p['blocklist']['domain:example.com']);$b->setPacConf($p);$b->xrayUpdateRules();
        break;
    case 'xray-core':
        $result=$b->applyXrayCore($argv[2]);
        break;
    case 'xray-encryption':
        $result=['error'=>$b->applyVlessEncryption($argv[2],$argv[3] ?? 'native')];
        break;
    case 'xray-smux':
        $p=$b->getPacConf();$p['smux']=$b->smuxSettings($p);$p['smux']['protocol']=$argv[2];$p['smux']['enabled']=$argv[2]!=='off';$p['smux']['brutal']['enabled']=0;$b->setPacConf($p);$b->syncSmuxLive($p);
        break;
    case 'xray-xhttp-mux':
        $result=['error'=>$b->applyXhttpMux($argv[2]==='on'),'enabled'=>!empty($b->getPacConf()['xhttp_mux']['enabled'])];
        break;
    case 'wg-export':
        $b->promptInstWG((int)($argv[2] ?? 0));
        $clients=$b->readClients();
        if (empty($clients[0])) throw new RuntimeException('No test peer');
        file_put_contents('/logs/audit-wg'.(int)($argv[2] ?? 0).'.conf',$b->createConfig($clients[0]));
        $result=['type'=>$b->getWGType(),'clients'=>count($clients)];
        break;
    case 'wg-toggle':
        $b->promptInstWG((int)($argv[2] ?? 0));
        $b->switchClient(0);
        $result=['disabled'=>!empty($b->readClients()[0]['# off'])];
        break;
    case 'wg-mode':
        $b->promptInstWG((int)($argv[2] ?? 0));
        $want=(int)($argv[3] ?? 0);
        $p=$b->getPacConf();
        if ((bool)($p[$b->getInstanceWG(1).'amnezia'] ?? false) !== ($want>0)) $b->switchAmnezia(silent:true);
        if ($want>0) $b->setAmneziaProto($want);
        $result=['type'=>$b->getWGType()];
        break;
    case 'restart-xray':
        $result=['restarted'=>$b->restartXray($b->getXray())];
        break;
    case 'wg-create':
        $inst=(int)($argv[2] ?? 0);
        $b->createPeer(false,'audit-',$inst);
        $result=['peers'=>count($b->readConfig()['peers'] ?? []),'calls'=>$b->transport->calls,
            'key_generation_error'=>(bool)array_filter($b->transport->messages,fn($m)=>str_contains($m,'не удалось сгенерировать ключи'))];
        break;
    case 'init-xray':
        $b->changeTransport('Websocket');
        if (empty($b->getXray()['inbounds'][0]['settings']['clients'])) $b->addxrus('audit');
        if (empty($b->getXray()['inbounds'][0]['settings']['clients'])) {
            throw new RuntimeException('Fresh Xray user was not created');
        }
        $b->cloakNginx();
        break;
    case 'transport':
        if (!in_array($argv[2],['Websocket','trojan-grpc','xhttp','Reality'],true)) exit(2);
        $b->changeTransport($argv[2]);
        break;
    case 'export':
        $dir='/logs/audit-profiles';
        if (!is_dir($dir)) mkdir($dir,0700,true);
        $x=$b->getXray();
        $client=$x['inbounds'][0]['settings']['clients'][0];
        foreach (['s'=>'xray','cl'=>'mihomo','si'=>'sing-box'] as $type=>$name) {
            $_GET=['t'=>$type,'s'=>$b->sidOf($client)];
            $body=$b->subscription(true);
            $profile=$type==='cl'?yaml_parse($body):json_decode($body,true);
            file_put_contents("$dir/$name.json",json_encode($profile,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));
            $result[$name]=is_array($profile);
        }
        file_put_contents("$dir/share-link.txt",$b->linkXray(0));
        $result['transport']=$b->getPacConf()['transport'];
        break;
    // XDRIVE: те же действия, что выполняют кнопки меню.
    case 'xdrive-enable':
        $error=$b->applyXdrive(['enabled'=>1,'service'=>'webdav','url'=>$argv[2],'folder'=>$argv[3],'secrets'=>[$argv[4],$argv[5]]]);
    case 'xdrive-state':
        $x=$b->getXray();$in=array_values(array_filter($x['inbounds'],fn($v)=>($v['tag']??'')==='xdrive'));
        $result=['error'=>$error??'','active'=>$b->xdriveActive(null,$x),'inbounds'=>count($in),
            'clients'=>array_column($in[0]['settings']['clients']??[],'email'),'main'=>array_column($x['inbounds'][0]['settings']['clients']??[],'email'),
            'encrypted'=>($in[0]['settings']['decryption']??'none')!=='none','core_ready'=>$b->xdriveCoreReady()];
        break;
    case 'xdrive-probe':
        $result=['error'=>$b->xdriveProbe($b->xdriveSettings())];
        break;
    case 'xdrive-profile':
        $client=$b->getXray()['inbounds'][0]['settings']['clients'][(int)$argv[2]];
        $b->xdriveProfile(Bot::xdriveClientKey($client));
        $result=['files'=>array_values(array_map('basename',glob('/logs/audit-files/xdrive-*.json')))];
        break;
    case 'xdrive-rotate':
        $result=['error'=>$b->applyXdrive($b->xdriveSettings(),true)];
        break;
    case 'xdrive-disable':
        $result=['error'=>$b->applyXdrive(['enabled'=>0]+$b->xdriveSettings())];
        break;
    case 'xdrive-menu':
        $b->xdriveMenu();$text=implode("\n",$b->transport->messages);
        $s=$b->xdriveSettings();
        $result=['shown'=>str_contains($text,'XDRIVE'),'secret_hidden'=>!str_contains($text,$s['secrets'][1]??'-'),'problems'=>$b->xdriveProblems($s)];
        break;
    default:
        exit(2);
}
echo json_encode(['action'=>$action,'result'=>$result,'api_calls'=>$b->transport->calls,'warnings'=>$warnings],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES),"\n";

if ($warnings) file_put_contents('/logs/audit-php85-warnings.jsonl',json_encode(['action'=>$action,'warnings'=>$warnings],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES)."\n",FILE_APPEND);

if ($warnings) exit(91);
