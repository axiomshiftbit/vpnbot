<?php

class Bot
{
    public $input;
    public $adguard;
    public $update;
    public $ip;
    public $limit;
    public $key;
    public $file;
    public $dns;
    public $mtu;
    public $logs;
    public $reg;
    public $pool;
    public $hwid;
    public $api;
    public $clients;
    public $clients1;
    public $pac;
    public $i18n;
    public $language;
    public $selfupdate;
    public $last;
    public $dontshowcron;
    public $input_raw;
    public $wg;
    public $time;
    public $time2;
    public $time3;
    public $time_xray_stats;
    public $admin;
    public $ports;
    public $warpprofile;

    public function __construct($key, $i18n)
    {
        $api = getenv('TELEGRAM_API') ?: 'api.telegram.org';
        $this->key      = $key;
        $this->api      = "https://$api/bot$key/";
        $this->file     = "https://$api/file/bot$key/";
        $this->clients  = '/config/clients.json';
        $this->clients1 = '/config/clients1.json';
        $this->pac      = '/config/pac.json';
        $this->ip       = getenv('IP');
        $this->i18n     = $i18n;
        $this->language = $this->getPacConf()['language'] ?: 'en';
        $this->dns      = '1.1.1.1, 8.8.8.8';
        $this->mtu      = 1350;
        $this->limit    = $this->getPacConf()['limitpage'] ?: 5;
        $this->adguard  = '/config/AdGuardHome.yaml';
        $this->update   = '/update/json';
        $this->hwid     = '/config/hwid.json';
        $this->logs = [
            'nginx_default_access',
            'nginx_domain_access',
            'upstream_access',
            'xray',
            'telemt',
        ];
        $this->reg = '~' . implode('|', [
            'GET / HTTP',
            'GET /favicon.ico HTTP',
            preg_quote($this->getHashBot(1))
        ]) . '~';
        $this->ports = [
            'hy'    => '443/udp',
            'wg'    => '51820/udp',
            'wg1'   => '51820/udp',
            'ss'    => '8388',
            'tg'    => '443',
            'ad'    => '853',
            'dnstt' => '53/udp',
            'telemt' => '443',
        ];
    }

    public function input($data = false)
    {
        $this->admin     = false;
        $this->input_raw = $input = $data ?: json_decode(file_get_contents('php://input'), true);
        $this->input     = [
            'message'           => $input['callback_query']['message']['text'] ?? $input['message']['text'] ?? $input['channel_post']['text'] ?? '',
            'message_id'        => $input['callback_query']['message']['message_id'] ?? $input['message']['message_id'] ?? $input['channel_post']['message_id'],
            'chat'              => $input['message']['chat']['id'] ?? $input['callback_query']['message']['chat']['id'] ?? $input['channel_post']['chat']['id'] ?? $input['my_chat_member']['chat']['id'],
            'from'              => $input['message']['from']['id'] ?? $input['inline_query']['from']['id'] ?? $input['callback_query']['from']['id'] ?? $input['channel_post']['chat']['id'] ?? $input['my_chat_member']['from']['id'],
            'username'          => $input['message']['from']['username'] ?? $input['inline_query']['from']['username'] ?? $input['callback_query']['from']['username'],
            'query'             => $input['inline_query']['query'] ?? '',
            'inlid'             => $input['inline_query']['id'] ?? '',
            'group'             => !empty($input['message']['chat']['type']) && 'group' == $input['message']['chat']['type'],
            'sticker_id'        => $input['message']['sticker']['file_id'] ?? false,
            'channel'           => !empty($input['channel_post']['message_id']),
            'callback'          => $input['callback_query']['data'] ?? false,
            'callback_id'       => $input['callback_query']['id'] ?? false,
            'photo'             => $input['message']['photo'] ?? false,
            'file_name'         => $input['message']['document']['file_name'] ?? false,
            'file_id'           => $input['message']['document']['file_id'] ?? false,
            'caption'           => $input['message']['caption'] ?? false,
            'reply'             => $input['message']['reply_to_message']['message_id'] ?? false,
            'reply_from'        => $input['message']['reply_to_message']['from']['id'] ??  $input['callback_query']['message']['reply_to_message']['from']['id'] ?? false,
            'reply_text'        => $input['message']['reply_to_message']['text'] ?? false,
            'new_member_id'     => $input['my_chat_member']['new_chat_member']['user']['id'] ?? false,
            'new_member_status' => $input['my_chat_member']['new_chat_member']['status'] ?? false,
        ];
        $this->auth();
        if ($this->admin) {
            $this->session();
            $this->action();
        }
        $this->callbackCheck();
    }

    public function auth()
    {
        $file = __DIR__ . '/config.php';
        require $file;
        if (empty($c['admin'])) {
            $c['admin'] = [$this->input['from']];
            file_put_contents($file, "<?php\n\n\$c = " . var_export($c, true) . ";\n");
        } elseif (!is_array($c['admin'])) {
            $c['admin'] = [$c['admin']];
            file_put_contents($file, "<?php\n\n\$c = " . var_export($c, true) . ";\n");
        }
        if (in_array($this->input['from'], $c['admin'])) {
            $this->admin = true;
        }
    }

    public function callbackCheck()
    {
        if (empty($this->callback) && !empty($this->input['callback_id'])) {
            $this->answer($this->input['callback_id'], $GLOBALS['debug'] ? $this->input['callback'] : false);
        }
    }

    public function session()
    {
        session_id($this->input['from']);
        @session_start();
        if (!empty($_SESSION['reply'])) {
            if (empty($this->input['reply'])) {
                foreach ($_SESSION['reply'] as $k => $v) {
                    $this->delete($this->input['chat'], $k);
                }
                unset($_SESSION['reply']);
            }
        }
    }

    public function sd($var, $log = false, $json = false, $raw = false)
    {
        if ($log) {
            if ($json) {
                file_put_contents('/logs/debug', json_encode($var, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
            } elseif ($raw) {
                file_put_contents('/logs/debug', $var);
            } else {
                file_put_contents('/logs/debug', var_export($var, true));
            }
        } else {
            $this->send($this->input['chat'], var_export($var, true), $this->input['message_id']);
        }
    }

    public function action()
    {
        switch (true) {
            // смена айпи сервера
            case preg_match('~^/menu$~', $this->input['message'], $m):
            case preg_match('~^/start$~', $this->input['message'], $m):
            case preg_match('~^/menu$~', $this->input['callback'], $m):
            case preg_match('~^/menu (?P<type>addpeer) (?P<arg>(?:-)?\d+)$~', $this->input['callback'], $m):
            case preg_match('~^/menu (?P<type>wg) (?P<arg>(?:-)?\d+)$~', $this->input['callback'], $m):
            case preg_match('~^/menu (?P<type>client) (?P<arg>\d+(?:_(?:-)?\d+)?)$~', $this->input['callback'], $m):
            case preg_match('~^/menu (?P<type>pac|adguard|config|ss|lang|oc|naive|mirror|update|hy|tt|ovpn)$~', $this->input['callback'], $m):
                $this->menu(type: $m['type'] ?? false, arg: $m['arg'] ?? false);
                break;
            case preg_match('~^/changeWG (\d+)$~', $this->input['callback'], $m):
                $this->changeWG($m[1]);
                break;
            case preg_match('~^/changeTransport(?: ([\w-]+))?$~', $this->input['callback'], $m):
                $this->changeTransport($m[1] ?? false);
                break;
            case preg_match('~^/changeFingerprint(?: (\w+))?$~', $this->input['callback'], $m):
                $this->changeFingerprint($m[1] ?? false);
                break;
            case preg_match('~^/fingerprintMenu$~', $this->input['callback'], $m):
                $this->fingerprintMenu();
                break;
            case preg_match('~^/mirror$~', $this->input['message'], $m):
                $this->menu('mirror');
                break;
            case preg_match('~^/mainOutbound$~', $this->input['callback'], $m):
                $this->mainOutbound();
                break;
            case preg_match('~^/importIps (.+)$~', $this->input['callback'], $m):
                $this->importIps($m[1]);
                break;
            case preg_match('~^/setAsVlessTransport (?P<arg>\d+(?:_(?:-)?\d+)?)$~', $this->input['callback'], $m):
                $this->setAsVlessTransport(...explode('_', $m['arg']));
                break;
            case preg_match('~^/switchBanIp$~', $this->input['callback'], $m):
                $this->switchBanIp();
                break;
            case preg_match('~^/switchMonthlyStats$~', $this->input['callback'], $m):
                $this->switchMonthlyStats();
                break;
            case preg_match('~^/setIpLimit$~', $this->input['callback'], $m):
                $this->setIpLimit();
                break;
            case preg_match('~^/hwidLimit$~', $this->input['callback'], $m):
                $this->hwidLimit();
                break;
            case preg_match('~^/toggleHwidLimit(?: (\w+))?$~', $this->input['callback'], $m):
                $this->toggleHwidLimit($m[1] ?? null);
                break;
            case preg_match('~^/setHwidDevices(?: (\w+))?$~', $this->input['callback'], $m):
                $this->setHwidDevices($m[1] ?? null);
                break;
            case preg_match('~^/changePort(?: (\w+))?$~', $this->input['callback'], $m):
                $this->changePort($m[1] ?? null);
                break;
            case preg_match('~^/hwidUser (\d+)(?:_(\d+))?$~', $this->input['callback'], $m):
                $this->hwidUser($m[1], $m[2] ?? 0);
                break;
            case preg_match('~^/hwidUserToggle (\d+)$~', $this->input['callback'], $m):
                $this->hwidUserToggle($m[1]);
                break;
            case preg_match('~^/hwidUserDefault (\d+)$~', $this->input['callback'], $m):
                $this->hwidUserDefault($m[1]);
                break;
            case preg_match('~^/setHwidUserLimit (\d+)$~', $this->input['callback'], $m):
                $this->setHwidUserLimit($m[1]);
                break;
            case preg_match('~^/hwidUserDel (\d+)_(\d+) (.+)$~', $this->input['callback'], $m):
                $this->hwidUserDel($m[1], $m[2], $m[3]);
                break;
            case preg_match('~^/searchLogs (.+)$~', $this->input['message'], $m):
                $this->searchLogs($m[1]);
                break;
            case preg_match('~^/searchLogs (.+?)(?:\s(.+?))?(?:\s(.+?))?(?:\s(.+?))?$~', $this->input['callback'], $m):
                $this->searchLogs($m[1], $m[2], $m[3], $m[4]);
                break;
            case preg_match('~^/switchSilence$~', $this->input['callback'], $m):
                $this->switchSilence();
                break;
            case preg_match('~^/switchScanIp$~', $this->input['callback'], $m):
                $this->switchScanIp();
                break;
            case preg_match('~^/choiceVless (\d+)_(\d+)_(\d+)$~', $this->input['callback'], $m):
                $this->choiceVless($m[1], $m[2], $m[3]);
                break;
            case preg_match('~^/setVlessLink (\d+)_(\d+)_(\d+)$~', $this->input['callback'], $m):
                $this->setVlessLink($m[1], $m[2], $m[3]);
                break;
            case preg_match('~^/unsetVlessLink (\d+)_(\d+)$~', $this->input['callback'], $m):
                $this->unsetVlessLink($m[1], $m[2]);
                break;
            case preg_match('~^/autoScanTimeout$~', $this->input['callback'], $m):
                $this->autoScanTimeout();
                break;
            case preg_match('~^/autoupdate$~', $this->input['callback'], $m):
                $this->autoupdate();
                break;
            case preg_match('~^/ports$~', $this->input['callback'], $m):
                $this->ports();
                break;
            case preg_match('~^/analysisIp(?:\s(\d+))?$~', $this->input['callback'], $m):
                $this->analysisIp($m[1] ?: 0);
                break;
            case preg_match('~^/ipMenu$~', $this->input['callback'], $m):
                $this->ipMenu();
                break;
            case preg_match('~^/status$~', $this->input['callback'], $m):
                $this->serverStatus();
                break;
            case preg_match('~^/onlines$~', $this->input['callback'], $m):
                $this->onlinesView();
                break;
            case preg_match('~^/cleanDeny(?:\s(\d))?$~', $this->input['callback'], $m):
                $this->cleanDeny($m[1]);
                break;
            case preg_match('~^/denyList (.+?)(?:\s(\d))?$~', $this->input['callback'], $m):
                $this->denyList($m[1], $m[2] ?: 0);
                break;
            case preg_match('~^/cleanLogs (.+?)(?:\s(1))?$~', $this->input['callback'], $m):
                $this->cleanLogs($m[1], $m[2]);
                break;
            case preg_match('~^/allowIp (.+?) (\d+)(?:\s(\d+))?$~', $this->input['callback'], $m):
                $this->allowIp($m[1], $m[2], $m[3]);
                break;
            case preg_match('~^/searchIp (.+)$~', $this->input['callback'], $m):
                $this->searchIp($m[1]);
                break;
            case preg_match('~^/searchSuspiciousIp (.+)$~', $this->input['callback'], $m):
                $this->searchSuspiciousIp($m[1]);
                break;
            case preg_match('~^/denyIp (.+?)(?:\s(.+?)\s(\d+?)\s(\d))?$~', $this->input['callback'], $m):
                $this->denyIp($m[1], $m[2], $m[3], $m[4]);
                break;
            case preg_match('~^/whiteIp (.+?)(?:\s(.+?)\s(\d+?)\s(\d))?$~', $this->input['callback'], $m):
                $this->whiteIp($m[1], $m[2], $m[3], $m[4]);
                break;
            case preg_match('~^/adgFillAllowedClients(?: (\d+))?$~', $this->input['callback'], $m):
                $this->adgFillAllowedClients($m[1] ?: false);
                break;
            case preg_match('~^/appOutbound$~', $this->input['callback'], $m):
                $this->appOutbound();
                break;
            case preg_match('~^/domainsOutbound$~', $this->input['callback'], $m):
                $this->domainsOutbound();
                break;
            case preg_match('~^/finalOutbound$~', $this->input['callback'], $m):
                $this->finalOutbound();
                break;
            case preg_match('~^/processOutbound$~', $this->input['callback'], $m):
                $this->processOutbound();
                break;
            case preg_match('~^/offWarp$~', $this->input['callback'], $m):
                $this->offWarp();
                break;
            case preg_match('~^/addSubdomain$~', $this->input['callback'], $m):
                $this->addSubdomain();
                break;
            case preg_match('~^/addLinkDomain$~', $this->input['callback'], $m):
                $this->addLinkDomain();
                break;
            case preg_match('~^/id$~', $this->input['message'], $m):
                $this->send($this->input['chat'], "your id: {$this->input['from']}\nchat id: {$this->input['chat']}", $this->input['message_id']);
                break;
            case preg_match('~^/adguardChBr$~', $this->input['callback'], $m):
                $this->adguardChBr();
                break;
            case preg_match('~^/mtproto$~', $this->input['callback'], $m):
                $this->mtproto();
                break;
            case preg_match('~^/telemt$~', $this->input['callback'] ?: $this->input['message'], $m):
                $this->telemt(!empty($this->input['callback']));
                break;
            case preg_match('~^/telemtUsers$~', $this->input['callback'], $m):
                $this->telemtUsers();
                break;
            case preg_match('~^/telemtSettings$~', $this->input['callback'], $m):
                $this->telemtSettings();
                break;
            case preg_match('~^/telemtMasking$~', $this->input['callback'], $m):
                $this->telemtMasking();
                break;
            case preg_match('~^/telemtDiagnostics$~', $this->input['callback'], $m):
                $this->telemtDiagnostics();
                break;
            case preg_match('~^/telemtAddUser$~', $this->input['callback'], $m):
                $this->telemtAddUser();
                break;
            case preg_match('~^/telemtToggleUser (\w+)$~', $this->input['callback'], $m):
                $this->telemtToggleUser($m[1]);
                break;
            case preg_match('~^/telemtDelUser (\w+)$~', $this->input['callback'], $m):
                $this->telemtDelUser($m[1]);
                break;
            case preg_match('~^/telemtRegen (\w+)$~', $this->input['callback'], $m):
                $this->telemtRegen($m[1]);
                break;
            case preg_match('~^/telemtQr (\w+)$~', $this->input['callback'], $m):
                $this->telemtQr($m[1]);
                break;
            case preg_match('~^/telemtDomain$~', $this->input['callback'], $m):
                $this->telemtDomain();
                break;
            case preg_match('~^/telemtToggle ([a-z0-9_]+) ([a-z]+)$~', $this->input['callback'], $m):
                $this->telemtToggle($m[1], $m[2]);
                break;
            case preg_match('~^/telemtCycleBeobachtenMinutes$~', $this->input['callback'], $m):
                $this->telemtCycleBeobachtenMinutes();
                break;
            case preg_match('~^/telemtShowBeobachten$~', $this->input['callback'], $m):
                $this->telemtShowBeobachten();
                break;
            case preg_match('~^/telemtReport$~', $this->input['callback'], $m):
                $this->telemtReport();
                break;
            case preg_match('~^/deleteAll (\w+)$~', $this->input['callback'], $m):
                $this->deleteAll($m[1]);
                break;
            case preg_match('~^/exportList (\w+)$~', $this->input['callback'], $m):
                $this->exportList($m[1]);
                break;
            case preg_match('~^/hidePort (\w+)$~', $this->input['callback'], $m):
                $this->hidePort($m[1]);
                break;
            case preg_match('~^/deleteYes (\w+)$~', $this->input['callback'], $m):
                $this->deleteYes($m[1]);
                break;
            case preg_match('~^/addCommunityFilter$~', $this->input['callback'], $m):
                $this->addCommunityFilter();
                break;
            case preg_match('~^/addLegizFilter$~', $this->input['callback'], $m):
                $this->addLegizFilter();
                break;
            case preg_match('~^/pacMenu (\d+)$~', $this->input['callback'], $m):
                $this->pacMenu($m[1]);
                break;
            case preg_match('~^/applyupdatebot$~', $this->input['callback'], $m):
                $this->applyupdatebot();
                break;
            case preg_match('~^/restart$~', $this->input['callback'], $m):
                $this->restart();
                break;
            case preg_match('~^/branches$~', $this->input['callback'], $m):
                $this->branches();
                break;
            case preg_match('~^/changeBranch (\d+)$~', $this->input['callback'], $m):
                $this->changeBranch($m[1]);
                break;
            case preg_match('~^/getMirror$~', $this->input['callback'], $m):
                $this->getMirror();
                break;
            case preg_match('~^/logs$~', $this->input['callback'], $m):
                $this->logs();
                break;
            case preg_match('~^/dnstt$~', $this->input['callback'] ?: $this->input['message'], $m):
                $this->dnstt(!empty($this->input['callback']));
                break;
            case preg_match('~^/dnsttDownload$~', $this->input['callback'], $m):
                $this->dnsttDownload();
                break;
            case preg_match('~^/dnsttDomain$~', $this->input['callback'], $m):
                $this->dnsttDomain();
                break;
            case preg_match('~^/dnsttPassword$~', $this->input['callback'], $m):
                $this->dnsttPassword();
                break;
            case preg_match('~^/setdnsttDomain (\w+)$~', $this->input['callback'], $m):
                $this->setdnsttDomain($m[1]);
                break;
            case preg_match('~^/setdnsttPassword (\w+)$~', $this->input['callback'], $m):
                $this->setdnsttPassword($m[1]);
                break;
            case preg_match('~^/getLog (?P<arg>\d+(?:_(?:-)?\d+)?)$~', $this->input['callback'], $m):
                $this->getLog(...explode('_', $m['arg']));
                break;
            case preg_match('~^/clearLog (?P<arg>\d+(?:_(?:-)?\d+)?)$~', $this->input['callback'], $m):
                $this->clearLog(...explode('_', $m['arg']));
                break;
            case preg_match('~^/cleanLog$~', $this->input['callback'], $m):
                $this->cleanLog();
                break;
            case preg_match('~^/delLog (?P<arg>\d+(?:_(?:-)?\d+)?)$~', $this->input['callback'], $m):
                $this->delLog(...explode('_', $m['arg']));
                break;
            case preg_match('~^/debug$~', $this->input['message'], $m):
                $this->debug();
                break;
            case preg_match('~^/backup$~', $this->input['callback'], $m):
                $this->backup();
                break;
            case preg_match('~^/generateSecret$~', $this->input['callback'], $m):
                $this->generateSecret();
                break;
            case preg_match('~^/setSecret$~', $this->input['callback'], $m):
                $this->setSecret();
                break;
            case preg_match('~^/defaultDNS (?P<arg>\d+(?:_(?:-)?\d+)?)$~', $this->input['callback'], $m):
                $this->defaultDNS(...explode('_', $m['arg']));
                break;
            case preg_match('~^/defaultMTU (?P<arg>\d+(?:_(?:-)?\d+)?)$~', $this->input['callback'], $m):
                $this->defaultMTU(...explode('_', $m['arg']));
                break;
            case preg_match('~^/subnet (?P<arg>-?\d+(?:_-?\d+)?(?:_\d)?)$~', $this->input['callback'], $m):
                $this->subnet(...explode('_', $m['arg']));
                break;
            case preg_match('~^/subnetAdd (?P<arg>-?\d+(?:_-?\d+)?(?:_-?\d+)?)$~', $this->input['callback'], $m):
                $this->subnetAdd(...explode('_', $m['arg']));
                break;
            case preg_match('~^/subnetDelete (?P<arg>-?\d+(?:_-?\d+)?(?:_-?\d+)?(?:_-?\d+)?)$~', $this->input['callback'], $m):
                $this->subnetDelete(...explode('_', $m['arg']));
                break;
            case preg_match('~^/addSubnets (?P<arg>-?\d+(?:_(?:-)?\d+)?)$~', $this->input['callback'], $m):
                $this->addSubnets(...explode('_', $m['arg']));
                break;
            case preg_match('~^/changeAllowedIps (?P<arg>\d+(?:_(?:-)?\d+)?)$~', $this->input['callback'], $m):
                $this->changeAllowedIps(...explode('_', $m['arg']));
                break;
            case preg_match('~^/changeMTU (?P<arg>\d+(?:_(?:-)?\d+)?)$~', $this->input['callback'], $m):
                $this->changeMTU(...explode('_', $m['arg']));
                break;
            case preg_match('~^/calc$~', $this->input['callback'], $m):
                $this->calc();
                break;
            case preg_match('~^/changeIps (?P<arg>\w+(?:_(?:-)?\d+)?)$~', $this->input['callback'], $m):
                $this->changeIps(...explode('_', $m['arg']));
                break;
            case preg_match('~^/selfssl$~', $this->input['callback'], $m):
                $this->selfssl();
                break;
            case preg_match('~^/sspswd$~', $this->input['callback'], $m):
                $this->sspswd();
                break;
            case preg_match('~^/ssGenPswd$~', $this->input['callback'], $m):
                $this->sspwdch(bin2hex(random_bytes(16)));
                break;
            case preg_match('~^/changeCamouflage$~', $this->input['callback'], $m):
                $this->changeCamouflage();
                break;
            case preg_match('~^/changeOcDomain$~', $this->input['callback'], $m):
                $this->changeOcDomain();
                break;
            case preg_match('~^/changeOcPass$~', $this->input['callback'], $m):
                $this->changeOcPass();
                break;
            case preg_match('~^/changeNaiveUser$~', $this->input['callback'], $m):
                $this->changeNaiveUser();
                break;
            case preg_match('~^/changeNaiveSubdomain$~', $this->input['callback'], $m):
                $this->changeNaiveSubdomain();
                break;
            case preg_match('~^/changeNaivePass$~', $this->input['callback'], $m):
                $this->changeNaivePass();
                break;
            case preg_match('~^/changeHysteriaPass$~', $this->input['callback'], $m):
                $this->changeHysteriaPass();
                break;
            case preg_match('~^/genHyPass$~', $this->input['callback'], $m):
                $this->genHyPass();
                break;
            case preg_match('~^/changeHySNI$~', $this->input['callback'], $m):
                $this->changeHySNI();
                break;
            case preg_match('~^/toggleHyObfs$~', $this->input['callback'], $m):
                $this->toggleHyObfs();
                break;
            case preg_match('~^/genHyObfs$~', $this->input['callback'], $m):
                $this->genHyObfs();
                break;
            case preg_match('~^/hyMasqMenu$~', $this->input['callback'], $m):
                $this->hyMasqMenu();
                break;
            case preg_match('~^/setHyMasq (\d+)$~', $this->input['callback'], $m):
                $this->setHyMasq($m[1]);
                break;
            case preg_match('~^/changeHyBw$~', $this->input['callback'], $m):
                $this->changeHyBw();
                break;
            case preg_match('~^/toggleHyInsecure$~', $this->input['callback'], $m):
                $this->toggleHyInsecure();
                break;
            case preg_match('~^/addTtUser$~', $this->input['callback'], $m):
                $this->addTtUser();
                break;
            case preg_match('~^/changeTtPass (\S+)$~', $this->input['callback'], $m):
                $this->changeTtPass($m[1]);
                break;
            case preg_match('~^/genTtPass (\S+)$~', $this->input['callback'], $m):
                $this->genTtPass($m[1]);
                break;
            case preg_match('~^/delttus (\S+)$~', $this->input['callback'], $m):
                $this->delttus($m[1]);
                break;
            case preg_match('~^/getTtConfig (\S+)$~', $this->input['callback'], $m):
                $this->getTtConfig($m[1]);
                break;
            case preg_match('~^/addOvpnUser$~', $this->input['callback'], $m):
                $this->addOvpnUser();
                break;
            case preg_match('~^/delOvpnUser (\S+)$~', $this->input['callback'], $m):
                $this->delOvpnUser($m[1]);
                break;
            case preg_match('~^/getOvpnConfig (\S+)$~', $this->input['callback'], $m):
                $this->getOvpnConfig($m[1]);
                break;
            case preg_match('~^/kickOvpn (\S+)$~', $this->input['callback'], $m):
                $this->kickOvpn($m[1]);
                break;
            case preg_match('~^/disableOvpnUser (\S+)$~', $this->input['callback'], $m):
                $this->disableOvpnUser($m[1]);
                break;
            case preg_match('~^/enableOvpnUser (\S+)$~', $this->input['callback'], $m):
                $this->enableOvpnUser($m[1]);
                break;
            case preg_match('~^/toggleOvpnIsolation$~', $this->input['callback'], $m):
                $this->toggleOvpnIsolation();
                break;
            case preg_match('~^/toggleOvpnProto$~', $this->input['callback'], $m):
                $this->toggleOvpnProto();
                break;
            case preg_match('~^/showOvpnLog$~', $this->input['callback'], $m):
                $this->showOvpnLog();
                break;
            case preg_match('~^/showOvpnConnLog$~', $this->input['callback'], $m):
                $this->showOvpnConnLog();
                break;
            case preg_match('~^/refreshOvpn$~', $this->input['callback'], $m):
                $this->refreshOvpn();
                break;
            case preg_match('~^/ovpnClientMenu (\S+)$~', $this->input['callback'], $m):
                $this->ovpnClientMenu($m[1]);
                break;
            case preg_match('~^/changeOcDns$~', $this->input['callback'], $m):
                $this->changeOcDns();
                break;
            case preg_match('~^/addOcUser$~', $this->input['callback'], $m):
                $this->addOcUser();
                break;
            case preg_match('~^/changeOcExpose$~', $this->input['callback'], $m):
                $this->changeOcExpose();
                break;
            case preg_match('~^/addXrUser$~', $this->input['callback'], $m):
                $this->addXrUser();
                break;
            case preg_match('~^/renameXrUser (\d+)$~', $this->input['callback'], $m):
                $this->renameXrUser($m[1]);
                break;
            case preg_match('~^/changeXrPwd (\d+)$~', $this->input['callback'], $m):
                $this->changeXrPwd($m[1]);
                break;
            case preg_match('~^/genXrPwd (\d+)$~', $this->input['callback'], $m):
                // empty password makes setXrPwd auto-generate (bin2hex(random_bytes(16)))
                $this->setXrPwd('', $m[1]);
                break;
            case preg_match('~^/resetXrUser (\d+)$~', $this->input['callback'], $m):
                $this->resetXrUser($m[1]);
                break;
            case preg_match('~^/resetXrStats$~', $this->input['callback'], $m):
                $this->resetXrStats();
                break;
            case preg_match('~^/regenAllXr$~', $this->input['callback'], $m):
                $this->regenAllXr();
                break;
            case preg_match('~^/regenRealityXr$~', $this->input['callback'], $m):
                $this->regenRealityXr();
                break;
            case preg_match('~^/regenIdXr (\d+)$~', $this->input['callback'], $m):
                $this->regenIdXr($m[1]);
                break;
            case preg_match('~^/v2ray$~', $this->input['callback'], $m):
                $this->v2ray();
                break;
            case preg_match('~^/cloak$~', $this->input['callback'], $m):
                $this->cloak();
                break;
            case preg_match('~^/cloakPort$~', $this->input['callback'], $m):
                $this->changeCloakPort();
                break;
            case preg_match('~^/cloakDomain$~', $this->input['callback'], $m):
                $this->changeCloakDomain();
                break;
            case preg_match('~^/cloakRegen$~', $this->input['callback'], $m):
                $this->regenCloakKeys();
                break;
            case preg_match('~^/cloakMethod$~', $this->input['callback'], $m):
                $this->cycleCloakMethod();
                break;
            case preg_match('~^/ckUsers$~', $this->input['callback'], $m):
                $this->menuCkUsers();
                break;
            case preg_match('~^/ckUser ([a-f0-9]{12})$~', $this->input['callback'], $m):
                $this->ckUserMenu($m[1]);
                break;
            case preg_match('~^/addCloakUser$~', $this->input['callback'], $m):
                $this->addCloakUser();
                break;
            case preg_match('~^/delCloakUser ([a-f0-9]{12})$~', $this->input['callback'], $m):
                $this->delCloakUser($m[1]);
                break;
            case preg_match('~^/qrCloakUser ([a-f0-9]{12})$~', $this->input['callback'], $m):
                $this->qrCloakUser($m[1]);
                break;
            case preg_match('~^/simpleTls$~', $this->input['callback'], $m):
                $this->simpleTls();
                break;
            case preg_match('~^/stlsPort$~', $this->input['callback'], $m):
                $this->changeStlsPort();
                break;
            case preg_match('~^/stlsSNI$~', $this->input['callback'], $m):
                $this->changeStlsSNI();
                break;
            case preg_match('~^/checkdns$~', $this->input['callback'], $m):
                $this->checkdns();
                break;
            case preg_match('~^/adguardpsswd$~', $this->input['callback'], $m):
                $this->adguardpsswd();
                break;
            case preg_match('~^/setAdguardKey$~', $this->input['callback'], $m):
                $this->setAdguardKey();
                break;
            case preg_match('~^/addadmin$~', $this->input['callback'], $m):
                $this->enterAdmin();
                break;
            case preg_match('~^/enterPage$~', $this->input['callback'], $m):
                $this->enterPage();
                break;
            case preg_match('~^/adguardreset$~', $this->input['callback'], $m):
                $this->adguardreset();
                break;
            case preg_match('~^/addupstream$~', $this->input['callback'], $m):
                $this->addupstream();
                break;
            case preg_match('~^/checkurl$~', $this->input['callback'], $m):
                $this->checkurl();
                break;
            case preg_match('~^/setSSL (\w+)$~', $this->input['callback'], $m):
                $this->setSSL($m[1]);
                break;
            case preg_match('~^/lang (\w+)$~', $this->input['callback'], $m):
                $this->setLang($m[1]);
                break;
            case preg_match('~^/deletessl$~', $this->input['callback'], $m):
                $this->deleteSSL();
                break;
            case preg_match('~^/download (\d+)$~', $this->input['callback'], $m):
                $this->downloadPeer($m[1]);
                break;
            case preg_match('~^/dw (\w+) (\w+)$~', $this->input['callback'], $m):
                $this->dw($m[1], $m[2]);
                break;
            case preg_match('~^/deloc (\d+)$~', $this->input['callback'], $m):
                $this->deloc($m[1]);
                break;
            case preg_match('~^/userXr (\d+)$~', $this->input['callback'], $m):
                $this->userXr($m[1]);
                break;
            case preg_match('~^/choiceTemplate (.+)$~', $this->input['callback'], $m):
                $this->choiceTemplate($m[1]);
                break;
            case preg_match('~^/templateUser (\w+) (\d+)$~', $this->input['callback'], $m):
                $this->templateUser($m[1], $m[2]);
                break;
            case preg_match('~^/timerXr (\d+)$~', $this->input['callback'], $m):
                $this->timerXr($m[1]);
                break;
            case preg_match('~^/switchXr (\d+)$~', $this->input['callback'], $m):
                $this->switchXr($m[1]);
                break;
            case preg_match('~^/delxr (\d+)$~', $this->input['callback'], $m):
                $this->delxr($m[1]);
                break;
            case preg_match('~^/listXr (\d+)$~', $this->input['callback'], $m):
                $this->listXr($m[1]);
                break;
            case preg_match('~^/switchTorrent (\d+)$~', $this->input['callback'], $m):
                $this->switchTorrent($m[1]);
                break;
            case preg_match('~^/switchEndpoint (\d+)$~', $this->input['callback'], $m):
                $this->switchEndpoint($m[1]);
                break;
            case preg_match('~^/switchAmnezia (-?\d+)$~', $this->input['callback'], $m):
                $this->switchAmnezia($m[1]);
                break;
            case preg_match('~^/resetAmnezia (-?\d+)$~', $this->input['callback'], $m):
                $this->resetAmnezia($m[1]);
                break;
            case preg_match('~^/reduceAmnezia (-?\d+)$~', $this->input['callback'], $m):
                $this->reduceAmnezia($m[1]);
                break;
            case preg_match('~^/amneziaTemplates (-?\d+)$~', $this->input['callback'], $m):
                $this->amneziaTemplates($m[1]);
                break;
            case preg_match('~^/amneziaTemplate (\w+) (-?\d+)$~', $this->input['callback'], $m):
                $this->applyAmneziaTemplate($m[1], $m[2]);
                break;
            case preg_match('~^/setAmneziaI1 (-?\d+)$~', $this->input['callback'], $m):
                $this->setAmneziaI1($m[1]);
                break;
            case preg_match('~^/rotateAmnezia (-?\d+)$~', $this->input['callback'], $m):
                $this->rotateAmneziaJunk(false, $m[1]);
                break;
            case preg_match('~^/setAmneziaRotation (-?\d+)$~', $this->input['callback'], $m):
                $this->setAmneziaRotation($m[1]);
                break;
            case preg_match('~^/switchExchange (\d+)$~', $this->input['callback'], $m):
                $this->switchExchange($m[1]);
                break;
            case preg_match('~^/blinkmenuswitch$~', $this->input['callback'], $m):
                $this->blinkmenuswitch();
                break;
            case preg_match('~^/switchClient (?P<arg>\d+(?:_(?:-)?\d+)?)$~', $this->input['callback'], $m):
                $this->switchClient(...explode('_', $m['arg']));
                $this->menu('client', $m['arg']);
                break;
            case preg_match('~^/deladmin (\d+)$~', $this->input['callback'], $m):
                $this->delAdmin($m[1]);
                break;
            case preg_match('~^/qr (\d+)$~', $this->input['callback'], $m):
                $this->qrPeer($m[1]);
                break;
            case preg_match('~^/qrSS$~', $this->input['callback'], $m):
                $this->qrSS();
                break;
            case preg_match('~^/qrXray (\d+)(?:_(\d+))?$~', $this->input['callback'], $m):
                $this->qrXray($m[1], $m[2] ?: false);
                break;
            case preg_match('~^/qrMtproto$~', $this->input['callback'], $m):
                $this->qrMtproto();
                break;
            case preg_match('~^/delupstream (\d+)$~', $this->input['callback'], $m):
                $this->delupstream($m[1]);
                break;
            case preg_match('~^/delete (?P<arg>\d+(?:_(?:-)?\d+)?)$~', $this->input['callback'], $m):
                $this->deletePeer(...explode('_', $m['arg']));
                break;
            case preg_match('~^/dns (?P<arg>\d+(?:_(?:-)?\d+)?)$~', $this->input['callback'], $m):
                $this->dnsPeer(...explode('_', $m['arg']));
                break;
            case preg_match('~^/deletedns (?P<arg>\d+(?:_(?:-)?\d+)?)$~', $this->input['callback'], $m):
                $this->deletednsPeer(...explode('_', $m['arg']));
                break;
            case preg_match('~^/deldomain$~', $this->input['callback'], $m):
                $this->delDomain();
                break;
            case preg_match('~^/addNipdomain$~', $this->input['callback'], $m):
                $this->addNipdomain();
                break;
            case preg_match('~^/(?P<action>change|delete)(?P<typelist>\w+) (?P<arg>\d+)(?: (?P<page>\d+))?$~', $this->input['callback'], $m):
                $this->listPacChange($m['typelist'], $m['action'], $m['arg'], $m['page'] ?: 0);
                break;
            case preg_match('~^/paczapret$~', $this->input['callback'], $m):
                $this->pacZapret();
                break;
            case preg_match('~^/pacupdate$~', $this->input['callback'], $m):
                $this->pacUpdate();
                break;
            case preg_match('~^/add$~', $this->input['callback'], $m):
                $this->addPeer(); // добавление клиента "весь траффик"
                break;
            case preg_match('~^/add_ips$~', $this->input['callback'], $m):
                $this->addips(); // ответ с предложением ввести список подсетей
                break;
            case preg_match('~^/domain$~', $this->input['callback'], $m):
                $this->domain();
                break;
            case preg_match('~^/warp$~', $this->input['callback'], $m):
                $this->warp();
                break;
            case preg_match('~^/warpPlus$~', $this->input['callback'], $m):
                $this->warpPlus();
                break;
            case preg_match('~^/xray(?: (\d+))?$~', $this->input['callback'], $m):
                $this->xray($m[1] ?: 0);
                break;
            case preg_match('~^/xtlsblock(?: (\d+))?$~', $this->input['callback'], $m):
                $this->xtlsblock($m[1] ?: 0);
                break;
            case preg_match('~^/routes(?: (\d+))?$~', $this->input['callback'], $m):
                $this->routes($m[1] ?: 0);
                break;
            case preg_match('~^/tun$~', $this->input['callback'], $m):
                $this->tun();
                break;
            case preg_match('~^/tunpackage(?: (\d+))?$~', $this->input['callback'], $m):
                $this->tunpackage($m[1] ?: 0);
                break;
            case preg_match('~^/tunpackagemode$~', $this->input['callback'], $m):
                $this->tunpackagemode();
                break;
            case preg_match('~^/tunprocessmode$~', $this->input['callback'], $m):
                $this->tunprocessmode();
                break;
            case preg_match('~^/tunprocess(?: (\d+))?$~', $this->input['callback'], $m):
                $this->tunprocess($m[1] ?: 0);
                break;
            case preg_match('~^/xtlswarp(?: (\d+))?$~', $this->input['callback'], $m):
                $this->xtlswarp($m[1] ?: 0);
                break;
            case preg_match('~^/xtlsproxy(?: (\d+))?$~', $this->input['callback'], $m):
                $this->xtlsproxy($m[1] ?: 0);
                break;
            case preg_match('~^/xtlsapp(?: (\d+))?$~', $this->input['callback'], $m):
                $this->xtlsapp($m[1] ?: 0);
                break;
            case preg_match('~^/xtlsprocess(?: (\d+))?$~', $this->input['callback'], $m):
                $this->xtlsprocess($m[1] ?: 0);
                break;
            case preg_match('~^/xtlssubnet(?: (\d+))?$~', $this->input['callback'], $m):
                $this->xtlssubnet($m[1] ?: 0);
                break;
            case preg_match('~^/xtlsrulesset(?: (\d+))?$~', $this->input['callback'], $m):
                $this->xtlsrulesset($m[1] ?: 0);
                break;
            case preg_match('~^/templateCopy (\w+)(?: (.+))?$~', $this->input['callback'], $m):
                $this->templateCopy($m[1], $m[2]);
                break;
            case preg_match('~^/delTemplate (\w+)(?: (.+))?$~', $this->input['callback'], $m):
                $this->delTemplate($m[1], $m[2]);
                break;
            case preg_match('~^/downloadOrigin (\w+)$~', $this->input['callback'], $m):
                $this->downloadOrigin($m[1]);
                break;
            case preg_match('~^/downloadTemplate (\w+)(?: (.+))?$~', $this->input['callback'], $m):
                $this->downloadTemplate($m[1], $m[2]);
                break;
            case preg_match('~^/defaultTemplate (\w+)(?: (.+))?$~', $this->input['callback'], $m):
                $this->defaultTemplate($m[1], $m[2]);
                break;
            case preg_match('~^/templates (\w+)$~', $this->input['callback'], $m):
                $this->templates($m[1]);
                break;
            case preg_match('~^/templateAdd (\w+)$~', $this->input['callback'], $m):
                $this->templateAdd($m[1]);
                break;
            case preg_match('~^/changeFakeDomain$~', $this->input['callback'], $m):
                $this->changeFakeDomain();
                break;
            case preg_match('~^/autoCleanLogs$~', $this->input['callback'], $m):
                $this->autoCleanLogs();
                break;
            case preg_match('~^/selfFakeDomain$~', $this->input['callback'], $m):
                $this->selfFakeDomain();
                break;
            case preg_match('~^/changeTGDomain$~', $this->input['callback'], $m):
                $this->changeTGDomain();
                break;
            case preg_match('~^/setTGAdtag$~', $this->input['callback'], $m):
                $this->changeTGAdtag();
                break;
            case preg_match('~^/include (\w+)$~', $this->input['callback'], $m):
                $this->include($m[1]);
                break;
            case preg_match('~^/exclude (\d+)$~', $this->input['callback'], $m):
                $this->exclude($m[1]);
                break;
            case preg_match('~^/reverse (\d+)$~', $this->input['callback'], $m):
                $this->reverse($m[1]);
                break;
            case preg_match('~^/subzones (\d+)$~', $this->input['callback'], $m):
                $this->subzones($m[1]);
                break;
            case preg_match('~^/proxy$~', $this->input['callback'], $m):
                $this->proxy();
                break;
            case preg_match('~^/addOverrideHtml$~', $this->input['callback'], $m):
                $this->addOverrideHtml();
                break;
            case preg_match('~^/export$~', $this->input['callback'], $m):
                $this->pinBackup();
                break;
            case preg_match('~^/import$~', $this->input['callback'], $m):
                $this->import();
                break;
            case preg_match('~^/importList (\w+)$~', $this->input['callback'], $m):
                $this->importList($m[1]);
                break;
            case preg_match('~^/rename (?P<arg>\d+(?:_(?:-)?\d+)?)$~', $this->input['callback'], $m):
                $this->rename(...explode('_', $m['arg']));
                break;
            case preg_match('~^/timer (?P<arg>\d+(?:_(?:-)?\d+)?)$~', $this->input['callback'], $m):
                $this->timer(...explode('_', $m['arg']));
                break;
            case !empty($this->input['reply']):
                $this->reply();
                break;
        }
    }

    public function generateSecret()
    {
        $this->secretSet(exec('head -c 16 /dev/urandom | xxd -ps'));
    }

    public function setSecret()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter key or 0 for stop mtproto",
            $this->input['message_id'],
            reply: 'enter key or 0 for stop mtproto',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'secretSet',
            'args'           => [],
        ];
    }

    public function secretSet($secret)
    {
        file_put_contents('/config/mtprotosecret', $secret);
        $this->restartTG();
        $this->mtproto();
    }

    public function setTelegramDomain($domain)
    {
        file_put_contents('/config/mtprotodomain', $domain);
        $this->restartTG();
        $this->mtproto();
    }

    public function setTelegramAdtag($adtag)
    {
        $adtag = trim($adtag);
        if ($adtag === '0') {
            $adtag = '';
        } elseif (!preg_match('~^[a-f0-9]{32}$~i', $adtag)) {
            $this->update($this->input['chat'], $this->input['message_id'], 'wrong adtag');
            sleep(2);
            $this->mtproto();
            return;
        }
        file_put_contents('/config/mtprotoadtag', strtolower($adtag));
        $this->restartTG();
        $this->mtproto();
    }

    public function restartTG()
    {
        $secret     = file_get_contents('/config/mtprotosecret');
        $fakedomain = file_get_contents('/config/mtprotodomain') ?: 'yandex.ru';
        $adtag      = trim(file_exists('/config/mtprotoadtag') ? file_get_contents('/config/mtprotoadtag') : '');
        $this->ssh('pkill mtproto-proxy', 'tg');
        if (preg_match('~^\w{32}$~', $secret)) {
            $proxyTag = $adtag ? " -P " . escapeshellarg($adtag) : '';
            $this->ssh("mtproto-proxy --domain $fakedomain -u nobody -H 443 --nat-info 10.10.0.8:{$this->ip} -S $secret --aes-pwd /proxy-secret /proxy-multi.conf -M 1$proxyTag", 'tg', false, '/logs/mtproto');
        }
    }

    // ── telemt (TeleMT) ─────────────────────────────────────────────────
    // Отдельный MTProto-прокси (Rust, fake-TLS) из проекта telemt/telemt.
    // Не пересекается со встроенным MTProto (restartTG) — это вторая,
    // независимая кнопка. Конфиг хранится в pac-conf (telemt_*), сам
    // telemt.toml перегенерируется при каждом рестарте.
    public function telemtBool(array $conf, string $key, bool $default = false): bool
    {
        return array_key_exists($key, $conf) ? !empty($conf[$key]) : $default;
    }

    // Дефолты masking-флагов telemt. mask_shape_hardening у telemt включён по
    // умолчанию (дёшево, работает только на mask-пути, ломает shape-анализ при
    // активном пробинге) — не глушим его на свежем конфиге. Остальные — off.
    public function telemtMaskDefault(string $key): bool
    {
        return $key === 'telemt_mask_hardening';
    }

    public function telemtInt(array $conf, string $key, int $default, int $min, int $max): int
    {
        $value = (int) ($conf[$key] ?? $default);
        return max($min, min($max, $value));
    }

    public function telemtState(bool $enabled): string
    {
        return $this->i18n($enabled ? 'on' : 'off');
    }

    public function telemtToml($conf = false)
    {
        [$conf] = $this->normalizeTelemtUsers($conf ?: $this->getPacConf());
        $domain = $conf['telemt_domain'] ?? 'www.google.com';
        $users  = $conf['telemt_users'] ?? [];
        $userEnabled = is_array($conf['telemt_user_enabled'] ?? null) ? $conf['telemt_user_enabled'] : [];
        $beobachten = $this->telemtBool($conf, 'telemt_beobachten', false);
        $beobachtenMinutes = $this->telemtInt($conf, 'telemt_beobachten_minutes', 10, 1, 1440);
        $maskHardening = $this->telemtBool($conf, 'telemt_mask_hardening', $this->telemtMaskDefault('telemt_mask_hardening'));
        $maskTiming = $this->telemtBool($conf, 'telemt_mask_timing', $this->telemtMaskDefault('telemt_mask_timing'));
        // telemt отказывается стартовать, если aggressive/blur включены без
        // mask_shape_hardening (load.rs: "requires mask_shape_hardening = true").
        // UI-тоггл держит инвариант, но импортированный бэкап или правленый
        // pac-conf могут принести несогласованную пару — гасим её здесь, в
        // единственном месте, которое генерирует telemt.toml.
        $maskAggressive = $maskHardening && $this->telemtBool($conf, 'telemt_mask_aggressive', $this->telemtMaskDefault('telemt_mask_aggressive'));
        $maskBlur = $maskHardening && $this->telemtBool($conf, 'telemt_mask_blur', $this->telemtMaskDefault('telemt_mask_blur'));
        $announce = $this->ip;
        $b      = fn($v) => $v ? 'true' : 'false';
        $q      = fn($v) => json_encode((string) $v, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        $showLink = implode(', ', array_map($q, array_keys($users)));
        $t  = "show_link = [$showLink]\n\n";
        $t .= "[general]\n";
        // log_level/disable_colors — поля [general] (а не top-level: там telemt
        // их игнорирует). disable_colors убирает ANSI-escape из /logs/telemt;
        // env NO_COLOR telemt не читает, только этот ключ.
        $t .= "log_level = \"normal\"\n";
        $t .= "disable_colors = true\n";
        $t .= "prefer_ipv6 = false\n";
        $t .= "fast_mode = true\n";
        $t .= "beobachten = " . $b($beobachten) . "\n";
        $t .= "beobachten_minutes = $beobachtenMinutes\n";
        // beobachten пишет наблюдения JA3/JA4 в файл (НЕ в HTTP-API). Кладём
        // его в data-path (/telemt/data ⇄ host ./config/telemt/data ⇄ php
        // /config/telemt/data), чтобы бот читал журнал напрямую, без API.
        $t .= "beobachten_file = " . $q('/telemt/data/beobachten.txt') . "\n";
        $t .= "use_middle_proxy = false\n\n";
        $t .= "[general.modes]\n";
        $t .= "classic = false\n";
        $t .= "secure = false\n";
        $t .= "tls = true\n\n";
        $t .= "[server]\n";
        // В бридж-сети vpnbot telemt всегда слушает 443 внутри контейнера;
        // наружу порт пробрасывается через override (setPort), как у tg.
        $t .= "port = 443\n";
        $t .= "listen_addr_ipv4 = \"0.0.0.0\"\n\n";
        // Управляющий HTTP-API нужен боту для расширенной диагностики
        // (/v1/* эндпоинты: health, stats, security posture). Включаем его
        // ТОЛЬКО когда включён beobachten, и строго на loopback внутри
        // контейнера (listen 127.0.0.1 + whitelist). Наружу 9091 НЕ
        // публикуется (нет ports: в compose), дополнительно режется nft на
        // хосте; бот ходит к API по ssh изнутри контейнера. auth_header пуст —
        // loopback-изоляции network namespace достаточно (как в upstream
        // prod-образе). Когда диагностика выключена — сокет не открывается.
        $t .= "[server.api]\n";
        $t .= "enabled = " . $b($beobachten) . "\n";
        $t .= "listen = \"127.0.0.1:9091\"\n";
        $t .= "whitelist = [\"127.0.0.1/32\", \"::1/128\"]\n\n";
        $t .= "[[server.listeners]]\n";
        $t .= "ip = \"0.0.0.0\"\n";
        $t .= "announce_ip = " . $q($announce) . "\n\n";
        $t .= "[censorship]\n";
        $t .= "tls_domain = " . $q($domain) . "\n";
        $t .= "mask = true\n";
        $t .= "mask_port = 443\n";
        $t .= "fake_cert_len = 2048\n";
        $t .= "tls_emulation = true\n";
        // Реализм server-flight на КЛИЕНТСКОМ пути FakeTLS (не cover-path):
        // настоящие TLS 1.3 серверы шлют NewSessionTicket в конце handshake.
        // Эмулируем 2 как additive fallback к захваченному TLS-профилю, чтобы
        // ранний серверный flight выглядел аутентично для DPI. Клиенты
        // Telegram принимают это штатно (стандартный TLS), совместимость не
        // страдает. alpn_enforce и server_hello_delay уже хороши по дефолту.
        $t .= "tls_new_session_tickets = 2\n";
        $t .= "mask_shape_hardening = " . $b($maskHardening) . "\n";
        $t .= "mask_shape_bucket_floor_bytes = 512\n";
        $t .= "mask_shape_bucket_cap_bytes = 4096\n";
        $t .= "mask_shape_hardening_aggressive_mode = " . $b($maskAggressive) . "\n";
        $t .= "mask_shape_above_cap_blur = " . $b($maskBlur) . "\n";
        $t .= "mask_shape_above_cap_blur_max_bytes = 512\n";
        $t .= "mask_timing_normalization_enabled = " . $b($maskTiming) . "\n";
        $t .= "mask_timing_normalization_floor_ms = 180\n";
        $t .= "mask_timing_normalization_ceiling_ms = 320\n\n";
        $t .= "[access]\n";
        $t .= "replay_check_len = 65536\n";
        $t .= "ignore_time_skew = false\n\n";
        $disabledUsers = array_filter(
            array_keys($users),
            fn($name) => array_key_exists($name, $userEnabled) && empty($userEnabled[$name])
        );
        if ($disabledUsers) {
            $t .= "[access.user_enabled]\n";
            foreach ($disabledUsers as $name) {
                $t .= $q($name) . " = false\n";
            }
            $t .= "\n";
        }
        $t .= "[access.users]\n";
        foreach ($users as $name => $secret) {
            $t .= $q($name) . " = " . $q($secret) . "\n";
        }
        $t .= "\n[[upstreams]]\n";
        $t .= "type = \"direct\"\n";
        $t .= "enabled = true\n";
        $t .= "weight = 10\n";
        return $t;
    }

    public function restartTelemt()
    {
        [$conf, $changed] = $this->normalizeTelemtUsers($this->getPacConf());
        if ($changed) {
            $this->setPacConf($conf);
        }
        @mkdir('/config/telemt/data', 0755, true);
        file_put_contents('/config/telemt/telemt.toml', $this->telemtToml($conf));
        $this->ssh('pkill -9 -x telemt; while pgrep -x telemt >/dev/null; do sleep 0.2; done', 'telemt');
        if (!empty($conf['telemt_users'])) {
            $this->ssh('telemt run --data-path /telemt/data /telemt/telemt.toml', 'telemt', false, '/logs/telemt');
        }
    }

    public function telemtSecret()
    {
        return bin2hex(random_bytes(16));
    }

    public function normalizeTelemtUsers(array $conf): array
    {
        if (!isset($conf['telemt_users'])) {
            $changed = isset($conf['telemt_user_enabled']);
            unset($conf['telemt_user_enabled']);
            return [$conf, $changed];
        }
        if (!is_array($conf['telemt_users'])) {
            $conf['telemt_users'] = [];
            unset($conf['telemt_user_enabled']);
            return [$conf, true];
        }
        if (!$conf['telemt_users']) {
            if (!empty($conf['telemt_user_enabled'])) {
                $conf['telemt_user_enabled'] = [];
                return [$conf, true];
            }
            return [$conf, false];
        }

        $changed = false;
        $seen    = [];
        $mtproto = '';
        if (is_file('/config/mtprotosecret')) {
            $mtproto = strtolower(trim((string) file_get_contents('/config/mtprotosecret')));
        }

        foreach ($conf['telemt_users'] as $name => $secret) {
            $secret = strtolower(trim((string) $secret));
            if (
                !preg_match('~^[a-f0-9]{32}$~', $secret)
                || isset($seen[$secret])
                || ($mtproto !== '' && hash_equals($mtproto, $secret))
            ) {
                do {
                    $secret = $this->telemtSecret();
                } while (isset($seen[$secret]) || ($mtproto !== '' && hash_equals($mtproto, $secret)));
                $changed = true;
            } elseif ($conf['telemt_users'][$name] !== $secret) {
                $changed = true;
            }

            $conf['telemt_users'][$name] = $secret;
            $seen[$secret] = true;
        }
        if (!is_array($conf['telemt_user_enabled'] ?? null)) {
            $conf['telemt_user_enabled'] = [];
        }
        foreach (array_keys($conf['telemt_user_enabled']) as $name) {
            if (!array_key_exists($name, $conf['telemt_users'])) {
                unset($conf['telemt_user_enabled'][$name]);
                $changed = true;
            }
        }

        return [$conf, $changed];
    }

    public function linkTelemt($name)
    {
        [$conf, $changed] = $this->normalizeTelemtUsers($this->getPacConf());
        if ($changed) {
            $this->setPacConf($conf);
            $this->restartTelemt();
        }
        $secret = $conf['telemt_users'][$name] ?? '';
        $domain = $conf['telemt_domain'] ?? 'www.google.com';
        $dhex   = bin2hex($domain);
        $p      = $this->getPorts()['telemt']['port'];
        $ip     = $this->getDomain();
        return 'tg://proxy?' . http_build_query([
            'server' => $ip,
            'port'   => $p,
            'secret' => "ee$secret$dhex",
        ], '', '&', PHP_QUERY_RFC3986);
    }

    public function restartXray($c, $norestart = false)
    {
        $c['inbounds'][0]['settings']['clients'] = array_values($c['inbounds'][0]['settings']['clients']);
        $c['log']['access'] = '/logs/xray';
        foreach ($c['inbounds'] as $v) {
            if ($v['tag'] == 'api') {
                $api = true;
                break;
            }
        }
        if (empty($api)) {
            $c['inbounds'][] = [
                "listen"   => "127.0.0.1",
                "port"     => 8080,
                "protocol" => "dokodemo-door",
                "settings" => [
                    "address" => "127.0.0.1"
                ],
                "tag" => "api"
            ];
        }
        foreach ($c['routing']['rules'] as $v) {
            if ($v['outboundTag'] == 'api') {
                $rule = true;
                break;
            }
        }
        if (empty($rule)) {
            $c['routing']['rules'][] = [
                "inboundTag"  => ["api"],
                "outboundTag" => "api",
                "type"        => "field"
            ];
        }

        foreach ($c['inbounds'] as $v) {
            if ($v['tag'] == 'wg-in') {
                $wg = true;
                break;
            }
        }
        if (empty($wg)) {
            $c['inbounds'][] = [
                "port"     => 10808,
                "protocol" => "socks",
                "settings" => [
                    "auth" => "noauth",
                    "udp"  => true,
                    "ip"   => "0.0.0.0"
                ],
                "tag"      => "wg-in",
                "sniffing" => [
                    "destOverride" => [
                        "http",
                        "tls",
                        "quic"
                    ],
                    "enabled" => true
                ]
            ];
        }
        $c['stats'] = new stdClass();
        $c['api'] = [
            'services' => ['StatsService'],
            'tag'      => 'api'
        ];
        $l = new stdClass();
        $l->{'0'} = [
            "statsUserUplink"   => true,
            "statsUserDownlink" => true
        ];
        $c['policy']['levels'] = $l;
        $c['policy']['system'] = [
            "statsInboundUplink"    => true,
            "statsInboundDownlink"  => true,
            "statsOutboundUplink"   => true,
            "statsOutboundDownlink" => true
        ];
        if (empty($norestart)) {
            $this->collectSession();
            file_put_contents('/config/xray.json', json_encode($c, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
            $this->ssh('pkill xray', 'xr');
            $this->ssh('xray run -config /xray.json > /dev/null 2>&1 &', 'xr');
        } else {
            file_put_contents('/config/xray.json', json_encode($c, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        }
    }

    public function collectSession() {
        $p = $this->getXrayStats();
        $p['global'] = [
            'download' => $p['global']['download'] + $p['session']['download'],
            'upload'   => $p['global']['upload'] + $p['session']['upload'],
        ];
        $p['session'] = [
            'download' => 0,
            'upload'   => 0,
        ];
        foreach ($p['users'] as $k => $v) {
            $p['users'][$k]['global']['download']  += $v['session']['download'];
            $p['users'][$k]['session']['download']  = 0;
            $p['users'][$k]['global']['upload']    += $v['session']['upload'];
            $p['users'][$k]['session']['upload']    = 0;
        }
        $this->setXrayStats($p);
    }

    public function linkMtproto()
    {
        $s  = file_get_contents('/config/mtprotosecret');
        $p  = $this->getPorts()['tg']['port'];
        $d  = trim(file_get_contents('/config/mtprotodomain') ?: 'yandex.ru');
        $d  = exec("echo $d | tr -d '\\n' | xxd -ps -c 200");
        $ip = $this->getDomain();
        return "https://t.me/proxy?server=$ip&port=$p&secret=ee$s$d";
    }

    public function mtproto()
    {
        $d      = file_get_contents('/config/mtprotodomain') ?: 'yandex.ru';
        $adtag  = trim(file_exists('/config/mtprotoadtag') ? file_get_contents('/config/mtprotoadtag') : '');
        $st     = $this->ssh('pgrep mtproto-proxy', 'tg') ? 'on' : 'off';
        $text[] = "Menu -> MTProto\n";
        $text[] = "status: $st\n";
        $text[] = "fake domain: <code>$d</code>\n";
        $text[] = "adtag: <code>" . ($adtag ?: 'off') . "</code>\n";
        if ($st == 'on') {
            $text[] = $this->linkMtproto();
        }
        $data[] = [
            [
                'text'          => $this->i18n('generateSecret'),
                'callback_data' => "/generateSecret",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('setSecret'),
                'callback_data' => "/setSecret",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('changeFakeDomain'),
                'callback_data' => "/changeTGDomain",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('setAdTag'),
                'callback_data' => "/setTGAdtag",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('show QR'),
                'callback_data' => "/qrMtproto",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/menu",
            ],
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            implode("\n", $text ?: ['...']),
            $data ?: false,
        );
    }

    public function setLang($lang)
    {
        $conf = $this->getPacConf();
        $this->language = $conf['language'] = $lang;
        $this->setPacConf($conf);
        $this->menu('config');
    }

    public function checkurl()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter url",
            $this->input['message_id'],
            reply: 'enter url',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'urlcheck',
            'args'           => [],
        ];
    }

    public function urlcheck($url)
    {
        if (file_exists(__DIR__ . '/zapretlists/mpac')) {
            $domains = explode("\n", file_get_contents(__DIR__ . '/zapretlists/mpac'));
            foreach ($domains as $k => $v) {
                if (preg_match("~$v~", $url)) {
                    $flag = 1;
                    break;
                }
            }
            if ($flag) {
                $text = "$url\nmatch";
            } else {
                $text = "$url\nnot match";
            }
        } else {
            $text = 'no file, update pac';
        }
        $this->update($this->input['chat'], $this->input['message_id'], $text);
        sleep(3);
        $this->menu('pac');
    }

    public function sspswd()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter password",
            $this->input['message_id'],
            reply: 'enter password',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'sspwdch',
            'args'           => [],
        ];
    }

    public function ssPswdCheck()
    {
        $c = $this->getSSConfig();
        if (empty($c['password']) || ($c['password'] == 'test')) {
            $this->sspwdch(password_hash(time(), PASSWORD_DEFAULT), 1);
        }
    }

    public function changeCamouflage()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter camouflage key",
            $this->input['message_id'],
            reply: 'enter camouflage key',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'chockey',
            'args'           => [],
        ];
    }

    public function changeOcDomain()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter subdomain",
            $this->input['message_id'],
            reply: 'enter subdomain',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'chOcSubdomain',
            'args'           => [],
        ];
    }

    public function changeOcDns()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter dns",
            $this->input['message_id'],
            reply: 'enter password',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'chocdns',
            'args'           => [],
        ];
    }

    public function changeOcPass()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter pass",
            $this->input['message_id'],
            reply: 'enter password',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'chocpass',
            'args'           => [],
        ];
    }

    public function changeNaiveUser()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter login",
            $this->input['message_id'],
            reply: 'enter login',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'chnplogin',
            'args'           => [],
        ];
    }

    public function changeNaiveSubdomain()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter subdomain",
            $this->input['message_id'],
            reply: 'enter subdomain',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'chNpSubdomain',
            'args'           => [],
        ];
    }

    public function changeNaivePass()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter password",
            $this->input['message_id'],
            reply: 'enter password',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'chnppass',
            'args'           => [],
        ];
    }

    public function changeHysteriaPass()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter password",
            $this->input['message_id'],
            reply: 'enter password',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'chhypass',
            'args'           => [],
        ];
    }

    public function addOcUser()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter name",
            $this->input['message_id'],
            reply: 'enter name',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'addocus',
            'args'           => [],
        ];
    }

    public function addXrUser()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter name",
            $this->input['message_id'],
            reply: 'enter name:uuid [,name:uuid]',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'addxrus',
            'args'           => [],
        ];
    }

    public function renameXrUser($i)
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter name",
            $this->input['message_id'],
            reply: 'enter password',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'renXrUs',
            'args'           => [$i],
        ];
    }

    public function addOverrideHtml()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} attach html",
            $this->input['message_id'],
            reply: 'attach html',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'setOverrideHtml',
            'args'           => [],
        ];
    }

    public function setOverrideHtml()
    {
        $r = $this->request('getFile', ['file_id' => $this->input['file_id']]);
        if (!empty($f = file_get_contents($this->file . $r['result']['file_path']))) {
            file_put_contents('/app/webapp/override.html', $f);
        }
    }

    public function restartOcserv($conf)
    {
        file_put_contents('/config/ocserv.conf', $conf);
        $this->ssh('pkill ocserv', 'oc');
        $pac = $this->getPacConf();
        if (!empty($pac['ocserv']) && !empty($this->getHashSubdomain('oc'))) {
            $this->ssh('ocserv -c /etc/ocserv/ocserv.conf', 'oc');
        }
    }

    public function restartNaive()
    {
        $pac = $this->getPacConf();
        $this->ssh('pkill caddy', 'np');
        $c = file_get_contents('/config/Caddyfile');
        $t = preg_replace('~^(\t+)?basic_auth[^\n]+~sm', '$1basic_auth ' . ($pac['naive']['user'] ?? '_') . ' ' . ($pac['naive']['pass'] ?? '__'), $c);
        file_put_contents('/config/Caddyfile', $t);
        if (!empty($pac['naive']['pass']) && !empty($this->getHashSubdomain('np'))) {
            $this->ssh('caddy run -c /config/Caddyfile', 'np', false);
        }
    }

    public function restartHysteria()
    {
        $pac = $this->getPacConf();
        $this->ssh('pkill hysteria', 'hy');
        $c   = yaml_parse_file('/config/hysteria.yaml');
        $c['auth']['password'] = $pac['hysteria_pass'] ?? '';

        // Salamander obfs — XOR-обфускация QUIC-пакетов общим секретом, ломает
        // QUIC-фингерпринтинг и активные пробы. Пароль ОБЯЗАН совпадать у всех
        // клиентов (идёт в hy2://-ссылку). Пусто = obfs выключен.
        if (!empty($pac['hysteria_obfs'])) {
            $c['obfs'] = [
                'type'       => 'salamander',
                'salamander' => ['password' => $pac['hysteria_obfs']],
            ];
        } else {
            unset($c['obfs']);
        }

        // bandwidth включает congestion control Brutal (агрессивный, лучше на
        // потерях/перегруженных каналах). Без значений — остаётся BBR.
        if (!empty($pac['hysteria_bw_up']) && !empty($pac['hysteria_bw_down'])) {
            $c['bandwidth'] = [
                'up'   => $pac['hysteria_bw_up'],
                'down' => $pac['hysteria_bw_down'],
            ];
        } else {
            unset($c['bandwidth']);
        }

        // Masquerade decoy host (server-only): reverse-proxy для зондов на тот
        // же UDP-порт. Кастомный hysteria_sni имеет приоритет над доменом; см.
        // chHySNI()/setHyMasq(). Это НЕ клиентский TLS SNI (тот = домен).
        $sni = !empty($pac['hysteria_sni']) ? $pac['hysteria_sni'] : $this->getDomain();
        if (!empty($sni)) {
            $c['masquerade']['type']                 = 'proxy';
            $c['masquerade']['proxy']['url']         = "https://$sni";
            $c['masquerade']['proxy']['rewriteHost'] = true;
        }
        yaml_emit_file('/config/hysteria.yaml', $c);
        if (!empty($pac['hysteria_pass'])) {
            $this->ssh('hysteria server -c /config/hysteria.yaml', 'hy', false, '/logs/hysteria');
        }
    }

    // Список реальных decoy-сайтов для masquerade. Указывать на реальный
    // сторонний сайт (а не на собственный IP/nip.io) — иначе зонд видит не
    // убедительную легенду. Используется hyMasqMenu()/setHyMasq().
    public function hyMasqPresets()
    {
        return [
            'www.bing.com',
            'news.ycombinator.com',
            'www.cloudflare.com',
            'www.microsoft.com',
            'www.apple.com',
            'mirror.gcr.io',
        ];
    }

    // hy2://-ссылка для клиента. host/port — внешние (домен:порт-проброс),
    // sni добавляем только при коннекте по IP без домена. obfs/insecure
    // прокидываем из pac. Возвращает '' если нет пароля или порт скрыт.
    public function linkHysteria()
    {
        $pac   = $this->getPacConf();
        $ports = $this->getPorts();
        $port  = $ports['hy']['enable'] ? $ports['hy']['port'] : null;
        $pass  = $pac['hysteria_pass'] ?? '';
        if (empty($pass) || empty($port)) {
            return '';
        }
        $domain = $this->getDomain();
        $host   = $domain ?: $this->ip;
        $q = [];
        // Клиентский TLS SNI = домен сертификата. Указываем ВСЕГДА, когда домен
        // известен: многие клиенты не подставляют SNI из host автоматически
        // при импорте ссылки, а без верного SNI (совпадающего с сертификатом)
        // валидация TLS у клиента падает. При коннекте по IP без домена SNI
        // опускаем — там self-signed, клиент идёт с insecure.
        if (!empty($domain)) {
            $q['sni'] = $domain;
        }
        if (!empty($pac['hysteria_insecure'])) {
            $q['insecure'] = '1';
        }
        if (!empty($pac['hysteria_obfs'])) {
            $q['obfs']          = 'salamander';
            $q['obfs-password'] = $pac['hysteria_obfs'];
        }
        $query = $q ? '?' . http_build_query($q) : '';
        // #fragment — отображаемое имя подключения в клиенте; без него поле
        // имени пустое. Используем хост (домен/IP) как узнаваемую метку.
        $name = '#' . rawurlencode($host);
        return 'hysteria2://' . rawurlencode($pass) . "@$host:$port/$query$name";
    }

    public function chocdns($dns)
    {
        $c = file_get_contents('/config/ocserv.conf');
        $t = preg_replace('~^dns[^\n]+~sm', "dns = $dns", $c);
        $this->restartOcserv($t);
        $this->menu('oc');
    }

    public function chOcSubdomain($domain)
    {
        $pac = $this->getPacConf();
        if ($domain == -1) {
            unset($pac["oc_domain"]);
        } else {
            $pac["oc_domain"] = $domain;
        }
        $this->setPacConf($pac);
        $this->chocdomain($pac['domain']);
        $this->setUpstreamDomainOcserv($pac['domain']);
        $this->menu('oc');
    }

    public function chNpSubdomain($domain)
    {
        $pac = $this->getPacConf();
        if ($domain == -1) {
            unset($pac['np_domain']);
        } else {
            $pac['np_domain'] = $domain;
        }
        $this->setPacConf($pac);
        $this->restartNaive();
        $this->setUpstreamDomainNaive($pac['domain']);
        $this->menu('naive');
    }

    public function chnplogin($user)
    {
        $pac = $this->getPacConf();
        $pac['naive']['user'] = $user;
        $this->setPacConf($pac);
        $this->restartNaive();
        $this->menu('naive');
    }

    public function chnppass($pass)
    {
        $pac = $this->getPacConf();
        $pac['naive']['pass'] = $pass;
        $this->setPacConf($pac);
        $this->restartNaive();
        $this->menu('naive');
    }

    public function chhypass($pass)
    {
        $pac = $this->getPacConf();
        if (!empty($pass)) {
            $pac['hysteria_pass'] = $pass;
        } else {
            unset($pac['hysteria_pass']);
        }
        $this->setPacConf($pac);
        $this->restartHysteria();
        $this->menu('hy');
    }

    // Генерация случайного пароля для hysteria (32 hex-символа, как у SS).
    // Переиспользуем chhypass(): он сохраняет pac, рестартит демон и
    // перерисовывает меню.
    public function genHyPass()
    {
        $this->chhypass(bin2hex(random_bytes(16)));
    }

    public function changeHySNI()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter hysteria SNI / masquerade host (e.g. {$this->getDomain()})",
            $this->input['message_id'],
            reply: 'enter hysteria SNI',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'chHySNI',
            'args'           => [],
        ];
    }

    // SNI hysteria — это host в masquerade.proxy.url (decoy-сайт для
    // неаутентифицированных запросов). Храним кастомный выбор в pac, чтобы
    // restartHysteria() не затирал его доменом. Пустой ввод сбрасывает на
    // домен по умолчанию.
    public function chHySNI($name)
    {
        $name = trim($name);
        $pac  = $this->getPacConf();
        if ($name === '') {
            unset($pac['hysteria_sni']);
        } elseif (preg_match('~^[A-Za-z0-9.-]+$~', $name)) {
            $pac['hysteria_sni'] = $name;
        } else {
            return $this->menu('hy');
        }
        $this->setPacConf($pac);
        $this->restartHysteria();
        $this->menu('hy');
    }

    // Salamander obfs on/off. При включении генерируем пароль, если его нет;
    // при выключении НЕ стираем пароль (чтобы повторное включение вернуло тот
    // же секрет) — просто помечаем выключенным пустым значением.
    public function toggleHyObfs()
    {
        $pac = $this->getPacConf();
        if (!empty($pac['hysteria_obfs'])) {
            $pac['hysteria_obfs_saved'] = $pac['hysteria_obfs'];
            unset($pac['hysteria_obfs']);
        } else {
            $pac['hysteria_obfs'] = $pac['hysteria_obfs_saved'] ?? bin2hex(random_bytes(12));
        }
        $this->setPacConf($pac);
        $this->restartHysteria();
        $this->menu('hy');
    }

    // Сгенерировать новый obfs-пароль (только когда obfs включён). После смены
    // все клиенты должны обновить obfs-password из новой hy2://-ссылки.
    public function genHyObfs()
    {
        $pac = $this->getPacConf();
        if (empty($pac['hysteria_obfs'])) {
            return $this->menu('hy');
        }
        $pac['hysteria_obfs'] = bin2hex(random_bytes(12));
        $this->setPacConf($pac);
        $this->restartHysteria();
        $this->menu('hy');
    }

    // Подменю выбора decoy-сайта для masquerade из пресетов + ручной ввод.
    public function hyMasqMenu()
    {
        $pac     = $this->getPacConf();
        $current = !empty($pac['hysteria_sni']) ? $pac['hysteria_sni'] : $this->getDomain();
        $text    = "Menu -> Hysteria -> " . $this->i18n('masquerade') . "\n\n"
                 . $this->i18n('masquerade host') . ": <code>$current</code>\n\n"
                 . "<i>" . $this->i18n('masquerade hint') . "</i>";
        $data = [];
        foreach ($this->hyMasqPresets() as $i => $host) {
            $mark   = ($host === $current) ? '✅ ' : '';
            $data[] = [[
                'text'          => "$mark$host",
                'callback_data' => "/setHyMasq $i",
            ]];
        }
        $data[] = [[
            'text'          => $this->i18n('change sni') . ' (custom)',
            'callback_data' => "/changeHySNI",
        ]];
        $data[] = [[
            'text'          => $this->i18n('back'),
            'callback_data' => "/menu hy",
        ]];
        $this->update($this->input['chat'], $this->input['message_id'], $text, $data);
    }

    public function setHyMasq($i)
    {
        $presets = $this->hyMasqPresets();
        $i       = (int) $i;
        if (!isset($presets[$i])) {
            return $this->hyMasqMenu();
        }
        $pac = $this->getPacConf();
        $pac['hysteria_sni'] = $presets[$i];
        $this->setPacConf($pac);
        $this->restartHysteria();
        $this->hyMasqMenu();
    }

    public function changeHyBw()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter bandwidth: up down (mbps), e.g. 200 200 — empty = BBR (auto)",
            $this->input['message_id'],
            reply: 'enter bandwidth',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'chHyBw',
            'args'           => [],
        ];
    }

    // Парсим "up down" в mbps. Пусто/0 → удаляем bandwidth (Brutal off → BBR).
    public function chHyBw($text)
    {
        $pac = $this->getPacConf();
        $nums = preg_split('~[\s,]+~', trim((string) $text), -1, PREG_SPLIT_NO_EMPTY);
        $up   = (int) ($nums[0] ?? 0);
        $down = (int) ($nums[1] ?? $nums[0] ?? 0);
        if ($up <= 0 || $down <= 0) {
            unset($pac['hysteria_bw_up'], $pac['hysteria_bw_down']);
        } else {
            $pac['hysteria_bw_up']   = "$up mbps";
            $pac['hysteria_bw_down'] = "$down mbps";
        }
        $this->setPacConf($pac);
        $this->restartHysteria();
        $this->menu('hy');
    }

    // Флаг insecure для клиентской hy2://-ссылки (нужен при self-signed серте,
    // иначе TLS-handshake клиента падает). На сервер не влияет.
    public function toggleHyInsecure()
    {
        $pac = $this->getPacConf();
        if (!empty($pac['hysteria_insecure'])) {
            unset($pac['hysteria_insecure']);
        } else {
            $pac['hysteria_insecure'] = 1;
        }
        $this->setPacConf($pac);
        $this->menu('hy');
    }

    public function chockey($pass)
    {
        $c = file_get_contents('/config/ocserv.conf');
        $t = preg_replace('~^camouflage_secret[^\n]+~sm', "camouflage_secret = \"$pass\"", $c);
        $this->restartOcserv($t);
        $this->menu('oc');
    }

    public function chocdomain($domain)
    {
        $oc = $this->getHashSubdomain('oc');
        $c  = file_get_contents('/config/ocserv.conf');
        $t  = preg_replace('~^default-domain[^\n]+~sm', "default-domain = $oc.$domain", $c);
        $this->restartOcserv($t);
    }

    public function chocpass($pass)
    {
        $pac = $this->getPacConf();
        $pac['ocserv'] = $pass;
        $this->setPacConf($pac);
        $clients = $this->getClientsOc();
        foreach ($clients as $k => $v) {
            $this->ssh("echo '$pass' | ocpasswd -c /etc/ocserv/ocserv.passwd $v", 'oc');
        }
        $this->restartOcserv(file_get_contents('/config/ocserv.conf'));
        $this->menu('oc');
    }

    public function sspwdch($pass, $nomenu = false)
    {
        $this->ssh('pkill sslocal', 'proxy');
        $this->ssh('pkill ssserver', 'ss');
        $c = $this->getSSConfig();
        $l = $this->getSSLocalConfig();
        $c['password'] = $l['password'] = $pass;
        file_put_contents('/config/ssserver.json', json_encode($c, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        file_put_contents('/config/sslocal.json', json_encode($l, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        $this->ssh('ssserver -v -d -c /config.json', 'ss');
        $this->ssh('sslocal -v -d -c /config.json', 'proxy');

        if (empty($nomenu)) {
            $this->menu('ss');
        }
    }

    public function v2ray()
    {
        $this->ssh('pkill sslocal', 'proxy');
        $this->ssh('pkill ssserver', 'ss');
        $ssl = $this->nginxGetTypeCert();
        $c = $this->getSSConfig();
        $l = $this->getSSLocalConfig();
        $domain = $this->getPacConf()['domain'] ?: $this->ip;
        if ($c['plugin']) {
            unset($c['plugin']);
            unset($c['plugin_opts']);
            unset($l['plugin']);
            unset($l['plugin_opts']);
            // ssserver ВСЕГДА слушает внутренний 8388 (start_ss.sh хардкодит его,
            // docker маппит host:EXT->ss:8388), а sslocal в proxy-контейнере
            // коннектится к ss:8388. Внешний порт идёт только в ss://-ссылку
            // (buildSSLink/menuSS), а не в конфиг демонов — иначе ssserver
            // забиндит не тот порт и plain SS станет недоступен снаружи.
            $ssport           = (int) (getenv('SSPORT') ?: 8388);
            $l['server']      = 'ss';
            $l['server_port'] = $ssport;
            $c['server_port'] = $ssport;
        } else {
            // v2ray и cloak/simple-tls конфликтуют: при v2ray ssserver работает
            // через плагин и не отдаёт plain SS на 8388, поэтому глушим оба.
            $ck = $this->getCloakConfig();
            if (!empty($ck['Enabled'])) {
                $ck['Enabled'] = 0;
                $this->setCloakConfig($ck);
                $this->ssh('pkill -f ck-server', 'ss');
            }
            $st = $this->getStlsConfig();
            if (!empty($st['Enabled'])) {
                $st['Enabled'] = 0;
                $this->setStlsConfig($st);
                $this->ssh('pkill -f simple-tls', 'ss');
            }
            $hash             = $this->getHashBot();
            $c['plugin']      = 'v2ray-plugin';
            $c['plugin_opts'] = 'server;loglevel=none';
            $l['server']      = 'up';
            $l['server_port'] = $ssl ? 443 : 80;
            $l['plugin']      = 'v2ray-plugin';
            $l['plugin_opts'] = ($ssl ? 'tls;' : '') . "fast-open;path=/v2ray$hash;host=$domain";
        }
        file_put_contents('/config/ssserver.json', json_encode($c, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        file_put_contents('/config/sslocal.json', json_encode($l, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        $this->ssh('ssserver -v -d -c /config.json', 'ss');
        $this->ssh('sslocal -v -d -c /config.json', 'proxy');
        $this->menu('ss');
    }

    public function getStlsConfig()
    {
        $f = '/config/stlsserver.json';
        return file_exists($f) ? (json_decode(file_get_contents($f), true) ?: []) : [];
    }

    public function setStlsConfig(array $c)
    {
        file_put_contents(
            '/config/stlsserver.json',
            json_encode($c, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)
        );
    }

    // simple-tls работает поверх plain ssserver (как cloak), поэтому при включении
    // нужно выключить v2ray (там ssserver слушает с плагином, не plain). С cloak
    // simple-tls сосуществует — оба форвардят в 127.0.0.1:8388, просто на
    // разных внешних портах. В ss://-линке приоритет фиксированный: cloak >
    // simple-tls > v2ray > plain (см. buildSSLink).
    public function simpleTls()
    {
        $c = $this->getStlsConfig();
        if (!empty($c['Enabled'])) {
            $c['Enabled'] = 0;
            $this->setStlsConfig($c);
            $this->ssh('pkill -f simple-tls', 'ss');
        } else {
            // Раньше при активном v2ray-plugin вызывался v2ray() с return —
            // получался UX-баг: пользователь жмёт «simple-tls: OFF→ON»,
            // а на деле просто выключается v2ray, simple-tls не запускается.
            // Теперь снимаем плагин inline и идём дальше.
            $this->disableV2rayPluginIfOn();
            $domain = $this->getPacConf()['domain'] ?: $this->ip;
            $c['Enabled']    = 1;
            $c['ServerName'] = $c['ServerName'] ?? $domain;
            $this->setStlsConfig($c);
            $this->ssh('pkill -f simple-tls', 'ss');
            $port = (int) (getenv('STLSPORT') ?: 3443);
            $ssport = (int) (getenv('SSPORT') ?: 8388);
            $cert = $this->ssh('[ -s /certs/cert_public ] && [ -s /certs/cert_private ] && echo cert || echo self', 'ss');
            $cert = trim($cert) === 'cert' ? '/certs/cert_public:/certs/cert_private' : '/certs/self_public:/certs/self_private';
            [$cp, $kp] = explode(':', $cert);
            $this->ssh("nohup setsid simple-tls -s -b :$port -d 127.0.0.1:$ssport -cert $cp -key $kp </dev/null >>/logs/simple-tls.log 2>&1 &", 'ss');
        }
        $this->menu('ss');
    }

    public function changeStlsPort()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter simple-tls port",
            $this->input['message_id'],
            reply: 'enter simple-tls port',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'chStlsPort',
            'args'           => [],
        ];
    }

    public function chStlsPort($port)
    {
        $port = (int) $port;
        if ($port < 1 || $port > 65535) {
            $this->menu('ss');
            return;
        }
        $this->setEnvVar('STLSPORT', (string) $port);
        $pac = $this->getPacConf();
        $pac['restart'] = 1;
        $this->setPacConf($pac);
        $this->menu('ss');
    }

    public function changeStlsSNI()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter simple-tls SNI (server name in cert, e.g. {$this->getDomain()})",
            $this->input['message_id'],
            reply: 'enter simple-tls SNI',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'chStlsSNI',
            'args'           => [],
        ];
    }

    public function chStlsSNI($name)
    {
        $name = trim($name);
        if (!preg_match('~^[A-Za-z0-9.-]+$~', $name)) {
            $this->menu('ss');
            return;
        }
        $c = $this->getStlsConfig();
        $c['ServerName'] = $name;
        $this->setStlsConfig($c);
        $this->menu('ss');
    }

    public function getCloakConfig()
    {
        $f = '/config/ckserver.json';
        $c = file_exists($f) ? (json_decode(file_get_contents($f), true) ?: []) : [];
        return $c;
    }

    // Сборка ss://-ссылки с учётом активного плагина. Приоритет:
    //   cloak > simple-tls > v2ray-plugin > чистый shadowsocks.
    // cloak и simple-tls могут сосуществовать (оба слушают на отдельных
    // внешних портах и форвардят в plain ssserver:8388), но в линке
    // отдаём только cloak, как более защищённый.
    //
    // $cloakUid — если задан, идёт в plugin-opts вместо $ck['UID']. Нужно
    // для per-user QR из cloak users menu (Phase 2 multi-user).
    public function buildSSLink($hash = '', $cloakUid = null)
    {
        $ss     = $this->getSSConfig();
        $domain = $this->getDomain();
        $ck     = $this->getCloakConfig();
        $st     = $this->getStlsConfig();
        $b64    = preg_replace('~==~', '', 'ss://' . base64_encode("{$ss['method']}:{$ss['password']}"));

        if (!empty($ck['Enabled'])) {
            $ckPort = (int) (getenv('CKPORT') ?: 8443);
            $ckSrv  = $ck['ServerName'] ?? ($ck['RedirAddr'] ?? $domain);
            $effUid = $cloakUid !== null && $cloakUid !== '' ? $cloakUid : ($ck['UID'] ?? '');
            $opts   = "ck-client;UID=" . $effUid
                    . ";PublicKey=" . ($ck['PublicKey'] ?? '')
                    . ";ServerName=$ckSrv"
                    . ";ProxyMethod=shadowsocks"
                    . ";EncryptionMethod=" . ($ck['EncryptionMethod'] ?? 'aes-256-gcm')
                    . ";NumConn=" . ($ck['NumConn'] ?? 4)
                    . ";BrowserSig=" . ($ck['BrowserSig'] ?? 'chrome');
            return $b64 . "@$domain:$ckPort/?plugin=" . urlencode($opts);
        }

        if (!empty($st['Enabled'])) {
            $stPort  = (int) (getenv('STLSPORT') ?: 3443);
            $stSrv   = $st['ServerName'] ?? $domain;
            // Если используется self-signed cert — клиенту нужен no-verify,
            // иначе TLS-handshake провалится. LE-бандл валидируется штатно.
            $ssl     = $this->nginxGetTypeCert();
            $opts    = "simple-tls;n=$stSrv" . ($ssl === 'letsencrypt' ? '' : ';no-verify');
            return $b64 . "@$domain:$stPort/?plugin=" . urlencode($opts);
        }

        if (!empty($ss['plugin'])) {
            $ssl  = $this->nginxGetTypeCert();
            $port = $ssl ? 443 : 80;
            $opts = "v2ray-plugin;path=/v2ray$hash;host=$domain" . ($ssl ? ';tls' : '');
            return $b64 . "@$domain:$port/?plugin=" . urlencode($opts);
        }

        $ports = $this->getPorts();
        return $b64 . "@$domain:{$ports['ss']['port']}/";
    }

    public function setCloakConfig(array $c)
    {
        file_put_contents(
            '/config/ckserver.json',
            json_encode($c, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)
        );
    }

    // Лениво создаём ключи и UID через ck-server -key / -uid в ss-контейнере.
    // Cloak печатает их в человекочитаемом формате с ANSI-цветами и
    // выравниванием по ширине поля (%65s/%47s/%s после "Your X is:"),
    // поэтому надёжнее искать сами base64-строки фиксированной длины:
    // curve25519 ключ = 32 байта = 44 символа base64 с одним '=' в конце,
    // UID = 16 байт = 22 символа + '==' (24 всего). Создаём один раз и
    // храним, чтобы клиентские ссылки переживали recreate.
    public function ensureCloakIdentity()
    {
        $c = $this->getCloakConfig();
        if (empty($c['PrivateKey']) || empty($c['PublicKey']) || empty($c['UID'])) {
            $key = $this->ssh('ck-server -key 2>&1', 'ss') ?: '';
            $uid = $this->ssh('ck-server -uid 2>&1', 'ss') ?: '';
            if (preg_match_all('~[A-Za-z0-9+/]{43}=~', $key, $m) && count($m[0]) >= 2) {
                $c['PublicKey']  = $m[0][0];
                $c['PrivateKey'] = $m[0][1];
            }
            if (preg_match('~[A-Za-z0-9+/]{22}==~', $uid, $m)) {
                $c['UID'] = $m[0];
            }
            $this->setCloakConfig($c);
        }
        return $c;
    }

    // ck-server не понимает поле Enabled (плюс пустые AdminUID/DatabasePath
    // ломают bind), поэтому передаём ему очищенную копию через /tmp.
    // Тот же приём, что и в start_ss.sh. Извлечено в один метод, потому что
    // вызывается из cloak/cloakDomain/cloakMethod/regen/addUser/delUser.
    private function ckServerRestartCmd(): string
    {
        return 'pkill -f ck-server; '
            . 'jq "del(.Enabled) '
            . '| if (.AdminUID // \"\") == \"\" then del(.AdminUID) else . end '
            . '| if (.DatabasePath // \"\") == \"\" then del(.DatabasePath) else . end" '
            . '/config/ckserver.json > /tmp/ckserver.json '
            . '&& nohup setsid ck-server -c /tmp/ckserver.json </dev/null >>/logs/ck-server.log 2>&1 &';
    }

    private function restartCloakIfRunning(): void
    {
        $c = $this->getCloakConfig();
        if (!empty($c['Enabled'])) {
            $this->ssh($this->ckServerRestartCmd(), 'ss');
        }
    }

    // Phase 2 — multi-user storage для cloak. Параллельно ckserver.json
    // (где BypassUID — список UID-ов, который читает сам ck-server) держим
    // side-store /config/ckusers.json с метой: имя, UID, время создания.
    // На первом чтении бутстрапим из текущего ckserver.json: основной UID
    // → "default", всё, что лежало в BypassUID отдельно — "user2", "user3"…
    // BypassUID всегда пересчитывается из ckusers.json через syncCloakBypassUIDs().
    public function getCloakUsers(): array
    {
        $f = '/config/ckusers.json';
        $list = file_exists($f) ? (json_decode(file_get_contents($f), true) ?: []) : [];
        if (!empty($list)) {
            return array_values($list);
        }
        // bootstrap from current ckserver.json
        $c = $this->getCloakConfig();
        $defaultUid = $c['UID'] ?? '';
        if ($defaultUid !== '') {
            $list[] = ['name' => 'default', 'uid' => $defaultUid, 'created' => time()];
        }
        $idx = 2;
        foreach (($c['BypassUID'] ?? []) as $u) {
            if ($u === '' || $u === $defaultUid) {
                continue;
            }
            $list[] = ['name' => 'user' . $idx, 'uid' => $u, 'created' => time()];
            $idx++;
        }
        if (!empty($list)) {
            $this->setCloakUsers($list);
        }
        return $list;
    }

    public function setCloakUsers(array $list): void
    {
        file_put_contents(
            '/config/ckusers.json',
            json_encode(array_values($list), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)
        );
    }

    // sha1-prefix как route id: UID содержит '/' и '+' и не лезет в callback
    // напрямую без urlencode, что ломается на парсинге Telegram (пробел —
    // разделитель аргументов). 12 hex-символов это 48 бит — коллизии
    // практически невозможны при количестве пользователей в десятки.
    public function findCloakUserByHash(string $hash): ?array
    {
        foreach ($this->getCloakUsers() as $u) {
            if (substr(sha1($u['uid']), 0, 12) === $hash) {
                return $u;
            }
        }
        return null;
    }

    // BypassUID — то, что читает сам ck-server. Держим его в синхронизации
    // с ckusers.json: после любого add/delete пересчитываем заново.
    private function syncCloakBypassUIDs(): void
    {
        $c = $this->getCloakConfig();
        $uids = array_values(array_unique(array_filter(
            array_map(fn($u) => $u['uid'] ?? '', $this->getCloakUsers())
        )));
        $c['BypassUID'] = $uids;
        $this->setCloakConfig($c);
    }

    // Toggle cloak on/off. Конфиг ckserver.json хранится в общей папке
    // /config (разделяется между php и ss контейнерами); поле Enabled
    // не понимается самим ck-server, мы используем его как флаг для
    // start_ss.sh и для UI бота.
    public function cloak()
    {
        $c = $this->ensureCloakIdentity();
        $domain = $this->getPacConf()['domain'] ?: $this->ip;
        $port   = (int) (getenv('CKPORT') ?: 8443);
        $ssport = (int) (getenv('SSPORT') ?: 8388);

        if (!empty($c['Enabled'])) {
            $c['Enabled'] = 0;
            $this->setCloakConfig($c);
            $this->ssh('pkill -f ck-server', 'ss');
        } else {
            // v2ray-plugin несовместим с cloak (ssserver слушал бы с плагином,
            // не plain). Раньше тут был return после v2ray()-toggle, что давало
            // UX-баг: "включаю cloak" → выключился v2ray, cloak не включился.
            // Теперь честно отключаем плагин inline и идём дальше.
            $this->disableV2rayPluginIfOn();
            // Гарантируем, что в ckusers.json есть default запись для текущего
            // UID — getCloakUsers() сам бутстрапит, дальше syncCloakBypassUIDs()
            // переписывает BypassUID из side-store.
            $this->getCloakUsers();
            $c = $this->getCloakConfig();
            $c['Enabled']    = 1;
            $c['BindAddr']   = [":$port"];
            $c['ProxyBook']  = ['shadowsocks' => ['tcp', "127.0.0.1:$ssport"]];
            $c['RedirAddr']  = $c['RedirAddr'] ?: 'www.bing.com';
            $c['ServerName'] = $c['ServerName'] ?: $domain;
            $this->setCloakConfig($c);
            $this->syncCloakBypassUIDs();
            $this->ssh($this->ckServerRestartCmd(), 'ss');
        }
        $this->menu('ss');
    }

    // Снимает плагин v2ray-plugin с ssserver/sslocal без перерисовки меню.
    // Раньше cloak()/simpleTls() при активном v2ray вызывали v2ray() и делали
    // return — это рендерило меню от лица v2ray и обрывало текущий toggle,
    // т.е. кнопка "включить cloak" фактически выключала v2ray. Теперь это
    // выделено и вызывается inline перед собственным enable.
    private function disableV2rayPluginIfOn(): void
    {
        $c = $this->getSSConfig();
        if (empty($c['plugin'])) {
            return;
        }
        $this->ssh('pkill sslocal', 'proxy');
        $this->ssh('pkill ssserver', 'ss');
        $l = $this->getSSLocalConfig();
        unset($c['plugin'], $c['plugin_opts'], $l['plugin'], $l['plugin_opts']);
        $ssport = (int) (getenv('SSPORT') ?: 8388);
        $l['server']      = 'ss';
        $l['server_port'] = $ssport;
        $c['server_port'] = $ssport;
        file_put_contents('/config/ssserver.json', json_encode($c, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        file_put_contents('/config/sslocal.json',  json_encode($l, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        $this->ssh('ssserver -v -d -c /config.json', 'ss');
        $this->ssh('sslocal -v -d -c /config.json', 'proxy');
    }

    public function changeCloakPort()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter cloak port",
            $this->input['message_id'],
            reply: 'enter cloak port',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'chCloakPort',
            'args'           => [],
        ];
    }

    public function chCloakPort($port)
    {
        $port = (int) $port;
        if ($port < 1 || $port > 65535) {
            $this->menu('ss');
            return;
        }
        // Главный compose уже разворачивает ${CKPORT:-8443}:${CKPORT:-8443}/tcp
        // на сервисе ss, так что одного setEnvVar достаточно — после `make r`
        // докер подхватит новое значение. Флаг restart в pac заставит бот
        // напомнить пользователю про пересоздание контейнера.
        $this->setEnvVar('CKPORT', (string) $port);
        $c = $this->getCloakConfig();
        if (!empty($c)) {
            $c['BindAddr'] = [":$port"];
            $this->setCloakConfig($c);
        }
        $pac = $this->getPacConf();
        $pac['restart'] = 1;
        $this->setPacConf($pac);
        $this->menu('ss');
    }

    public function changeCloakDomain()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter masquerade domain (e.g. www.bing.com)",
            $this->input['message_id'],
            reply: 'enter masquerade domain',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'chCloakDomain',
            'args'           => [],
        ];
    }

    public function chCloakDomain($domain)
    {
        $domain = trim($domain);
        if (!preg_match('~^[A-Za-z0-9.-]+$~', $domain)) {
            $this->menu('ss');
            return;
        }
        $c = $this->ensureCloakIdentity();
        $c['RedirAddr']  = $domain;
        $c['ServerName'] = $domain;
        $this->setCloakConfig($c);
        // Перезапускаем ck-server с новым RedirAddr/ServerName.
        $this->restartCloakIfRunning();
        $this->menu('ss');
    }

    // Регенерация ключей cloak (PrivateKey/PublicKey/UID). После выполнения
    // все ранее розданные клиентские ссылки/QR становятся невалидными —
    // пользователю нужно заново раздать новый ss:// или скан QR. ck-server
    // глушится перед очисткой, чтобы не держал старые ключи в памяти.
    // Cloak принимает только фиксированный набор EncryptionMethod;
    // совпадение с SS method (например chacha20-ietf-poly1305 у SS vs
    // chacha20-poly1305 у Cloak) безопасно — это два независимых слоя
    // шифрования с разными ключами.
    public function cycleCloakMethod()
    {
        $methods = ['aes-256-gcm', 'aes-128-gcm', 'chacha20-poly1305', 'plain'];
        $c       = $this->getCloakConfig();
        $cur     = $c['EncryptionMethod'] ?? 'aes-256-gcm';
        $i       = array_search($cur, $methods, true);
        $c['EncryptionMethod'] = $methods[($i === false ? 0 : $i + 1) % count($methods)];
        $this->setCloakConfig($c);
        $this->restartCloakIfRunning();
        $this->menu('ss');
    }

    public function regenCloakKeys()
    {
        $c     = $this->getCloakConfig();
        $wasOn = !empty($c['Enabled']);

        $this->ssh('pkill -f ck-server', 'ss');

        // Сбрасываем идентификационные поля. ensureCloakIdentity() их
        // восстановит через ck-server -key / -uid.
        unset($c['PrivateKey'], $c['PublicKey'], $c['UID'], $c['BypassUID']);
        $this->setCloakConfig($c);

        // Старые UID-ы из ckusers.json (Phase 2 multi-user) теперь не подходят
        // к новой паре PrivateKey/PublicKey — все ранее розданные клиентские
        // ссылки и так умерли вместе с server-keys, поэтому стираем
        // side-store, чтобы getCloakUsers() забутстрапился под новый
        // default-UID. Без этого в списке остались бы «мёртвые» имена.
        @unlink('/config/ckusers.json');

        $c = $this->ensureCloakIdentity();

        if ($wasOn) {
            $domain = $this->getPacConf()['domain'] ?: $this->ip;
            $port   = (int) (getenv('CKPORT') ?: 8443);
            $ssport = (int) (getenv('SSPORT') ?: 8388);

            $c['Enabled']    = 1;
            $c['BindAddr']   = [":$port"];
            $c['ProxyBook']  = ['shadowsocks' => ['tcp', "127.0.0.1:$ssport"]];
            $c['RedirAddr']  = $c['RedirAddr'] ?: 'www.bing.com';
            $c['ServerName'] = $c['ServerName'] ?: $domain;
            $this->setCloakConfig($c);
            // bootstrap default user в ckusers.json и пересинхронизируем
            // BypassUID — иначе ck-server стартует с пустым allow-list.
            $this->getCloakUsers();
            $this->syncCloakBypassUIDs();
            $this->ssh($this->ckServerRestartCmd(), 'ss');
        }

        $this->menu('ss');
    }

    // ── cloak users (Phase 2) ────────────────────────────────────────

    // Открывает prompt-режим для имени нового пользователя; ответ ловится
    // sessions[]['callback'] => 'addCkUserSubmit' и передаётся в submit-метод.
    public function addCloakUser()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter cloak user name",
            $this->input['message_id'],
            reply: 'enter cloak user name',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'addCkUserSubmit',
            'args'           => [],
        ];
    }

    // Регистрирует нового пользователя cloak. Имя нормализуется (тот же
    // санитайзер, что у ovpn — буквы/цифры/_-.), UID берём через
    // ck-server -uid (16 байт base64). Дальше переписываем BypassUID и
    // рестартуем ck-server, если он крутится.
    public function addCkUserSubmit($name)
    {
        $name = preg_replace('~[^a-zA-Z0-9_.\- ]~', '', (string) $name);
        $name = trim($name);
        if ($name === '') {
            $this->send($this->input['chat'], 'wrong name');
            return $this->menuCkUsers();
        }
        $list = $this->getCloakUsers();
        foreach ($list as $u) {
            if (($u['name'] ?? '') === $name) {
                $this->send($this->input['chat'], "user $name already exists");
                return $this->menuCkUsers();
            }
        }
        $uidOut = $this->ssh('ck-server -uid 2>&1', 'ss') ?: '';
        if (!preg_match('~[A-Za-z0-9+/]{22}==~', $uidOut, $m)) {
            $this->send($this->input['chat'], 'failed to generate UID');
            return $this->menuCkUsers();
        }
        $list[] = ['name' => $name, 'uid' => $m[0], 'created' => time()];
        $this->setCloakUsers($list);
        $this->syncCloakBypassUIDs();
        $this->restartCloakIfRunning();
        $this->menuCkUsers();
    }

    // Удаляет пользователя по sha1-prefix UID. Default user (тот, что лежит
    // в $ck['UID']) защищён: он используется как admin/identity-маркер при
    // регенерации, и часть кода (ensureCloakIdentity) на него полагается.
    public function delCloakUser($hash)
    {
        $u = $this->findCloakUserByHash($hash);
        if (!$u) {
            return $this->menuCkUsers();
        }
        $c = $this->getCloakConfig();
        if (($u['uid'] ?? '') === ($c['UID'] ?? '')) {
            $this->send($this->input['chat'], 'cannot delete default user (use regen keys instead)');
            return $this->menuCkUsers();
        }
        $list = array_values(array_filter(
            $this->getCloakUsers(),
            fn($x) => ($x['uid'] ?? '') !== ($u['uid'] ?? '')
        ));
        $this->setCloakUsers($list);
        $this->syncCloakBypassUIDs();
        $this->restartCloakIfRunning();
        $this->menuCkUsers();
    }

    // Per-user QR. ss://-ссылка та же, что в qrSS, но в plugin-opts UID=
    // подменяется на UID этого юзера. Файл именуем по name (с санитайзером,
    // чтобы exec/qrencode не получили опасных символов в пути).
    public function qrCloakUser($hash)
    {
        $u = $this->findCloakUserByHash($hash);
        if (!$u) {
            return $this->menuCkUsers();
        }
        $link    = $this->buildSSLink($this->getHashBot(), $u['uid']);
        $safe    = preg_replace('~[^a-zA-Z0-9_.\-]~', '_', $u['name']);
        $qr_file = __DIR__ . "/qr/cloak_$safe.png";
        exec("qrencode -t png -o $qr_file '$link'");
        $this->sendPhoto(
            $this->input['chat'],
            curl_file_create($qr_file),
            "<code>$link</code>\n\n<b>" . htmlspecialchars($u['name'], ENT_QUOTES) . "</b>"
        );
        @unlink($qr_file);
        if ($this->getPacConf()['blinkmenu']) {
            $this->delete($this->input['chat'], $this->input['message_id']);
            $this->input['message_id'] = $this->send($this->input['chat'], '.')['result']['message_id'];
            $this->ckUserMenu($hash);
        }
    }

    // Список всех cloak-пользователей. Default помечен ★. Если cloak
    // отключён — всё равно показываем список (можно подготовить юзеров
    // заранее, BypassUID применится при следующем enable).
    public function menuCkUsers()
    {
        $users      = $this->getCloakUsers();
        $c          = $this->getCloakConfig();
        $defaultUid = $c['UID'] ?? '';
        $cloakOn    = !empty($c['Enabled']);

        $text   = [];
        $text[] = 'Menu -> ShadowSocks -> ' . $this->i18n('cloak users');
        $text[] = 'cloak: ' . $this->i18n($cloakOn ? 'on' : 'off');
        $text[] = 'users: ' . count($users);

        $data   = [];
        $data[] = [[
            'text'          => $this->i18n('add user'),
            'callback_data' => '/addCloakUser',
        ]];
        foreach ($users as $u) {
            $hash   = substr(sha1($u['uid'] ?? ''), 0, 12);
            $marker = (($u['uid'] ?? '') === $defaultUid) ? '★ ' : '';
            $data[] = [[
                'text'          => $marker . ($u['name'] ?? '?'),
                'callback_data' => "/ckUser $hash",
            ]];
        }
        $data[] = [[
            'text'          => $this->i18n('back'),
            'callback_data' => '/menu ss',
        ]];

        if (!empty($this->input['callback_id'])) {
            $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $text), $data);
        } else {
            $this->send($this->input['chat'], implode("\n", $text), $this->input['message_id'], $data);
        }
    }

    // Per-user submenu — мета (UID, дата) и actions (QR / delete).
    public function ckUserMenu($hash)
    {
        $u = $this->findCloakUserByHash($hash);
        if (!$u) {
            return $this->menuCkUsers();
        }
        $c         = $this->getCloakConfig();
        $isDefault = (($u['uid'] ?? '') === ($c['UID'] ?? ''));
        $created   = !empty($u['created']) ? date('Y-m-d', (int) $u['created']) : '?';

        $text   = [];
        $text[] = 'Menu -> ShadowSocks -> ' . $this->i18n('cloak users')
            . ' -> <code>' . htmlspecialchars($u['name'] ?? '?', ENT_QUOTES) . '</code>';
        $text[] = ($isDefault ? '★ default' : '');
        $text[] = "UID: <span class='tg-spoiler'>" . htmlspecialchars($u['uid'] ?? '', ENT_QUOTES) . "</span>";
        $text[] = "created: $created";

        $data   = [];
        $data[] = [[
            'text'          => $this->i18n('show QR'),
            'callback_data' => "/qrCloakUser $hash",
        ]];
        if (!$isDefault) {
            $data[] = [[
                'text'          => $this->i18n('delete'),
                'callback_data' => "/delCloakUser $hash",
            ]];
        }
        $data[] = [[
            'text'          => $this->i18n('back'),
            'callback_data' => '/ckUsers',
        ]];

        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", array_filter($text)), $data);
    }


    public function rename(int $client, $page)
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter the title:",
            $this->input['message_id'],
            reply: 'enter the title:',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'renameClient',
            'args'           => [$client, $page],
        ];
    }

    public function timer(int $client, $page)
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter time like https://www.php.net/manual/ru/function.strtotime.php:",
            $this->input['message_id'],
            reply: 'enter time like https://www.php.net/manual/ru/function.strtotime.php:',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'timerClient',
            'args'           => [$client, $page],
        ];
    }

    public function importList($type)
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} send the export file:",
            $this->input['message_id'],
            reply: 'send the export file:',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'importListFile',
            'args'           => [$type],
        ];
    }

    public function importListFile($message = '', $type)
    {
        $r = $this->request('getFile', ['file_id' => $this->input['file_id']]);
        $f = file_get_contents($this->file . $r['result']['file_path']);
        if (!empty($f)) {
            foreach (explode("\n", $f) as $v) {
                if (!empty($s = trim($v))) {
                    $t = explode(';', $s);
                    if ($type == 'rulessetlist') {
                        if (preg_match('~^.+:.+:https?://.+~', $t[0])) {
                            $list[$t[0]] = (bool) $t[1];
                        }
                    } else {
                        $list[$t[0]] = (bool) $t[1];
                    }
                }
            }
            $p = $this->getPacConf();
            $p[$type] = $list;
            $this->setPacConf($p);
        }
        $this->backXtlsList($type);
    }

    public function timerClient(string $time, int $client)
    {
        $clients = $this->readClients();
        if ($clients[$client]['# off']) {
            $this->switchClient($client);
            $clients = $this->readClients();
        }
        $server = $this->readConfig();
        switch (true) {
            case preg_match('~^0$~', $time):
                unset($clients[$client]['interface']['## time']);
                foreach ($server['peers'] as $k => $v) {
                    if ($v['AllowedIPs'] == $clients[$client]['interface']['Address']) {
                        unset($server['peers'][$k]['## time']);
                    }
                }
                break;
            default:
                $date = date('Y-m-d H:i:s', strtotime($time));
                $clients[$client]['interface']['## time'] = $date;
                foreach ($server['peers'] as $k => $v) {
                    if ($v['AllowedIPs'] == $clients[$client]['interface']['Address']) {
                        $server['peers'][$k]['## time'] = $date;
                    }
                }
                break;
        }
        $this->saveClients($clients);
        $this->restartWG($this->createConfig($server));
        $this->menu('client', implode('_', $_SESSION['reply'][$this->input['reply']]['args']));
    }

    public function cron()
    {
        $period = 10;
        while (true) {
            $this->shutdownClient();
            $this->shutdownClientXr();
            $this->checkVersion();
            $this->checkBackup();
            $this->checkLogs();
            $this->checkResetXrayStats();
            $this->checkCert();
            $this->autoAnalyzeLogs();
            $this->xrayStatsUser();
            $this->trackOnline();
            sleep($period);
        }
    }

    public function xrayStatsUser()
    {
        if (empty($this->time_xray_stats) || time() - $this->time_xray_stats > 60) {
            $this->time_xray_stats = time();
            try {
                $x  = $this->getXray();
                $td = json_decode($this->ssh('xray api stats --server=127.0.0.1:8080 -name "inbound>>>vless_tls>>>traffic>>>downlink" 2>&1', 'xr'), true)['stat']['value'] ?: 0;
                $tu = json_decode($this->ssh('xray api stats --server=127.0.0.1:8080 -name "inbound>>>vless_tls>>>traffic>>>uplink" 2>&1', 'xr'), true)['stat']['value'] ?: 0;
                $p  = $this->getXrayStats();
                $p['session'] = [
                    'download' => $td,
                    'upload'   => $tu,
                ];
                if (!empty($users = $x['inbounds'][0]['settings']['clients'])) {
                    $tmp = [];
                    foreach ($users as $k => $v) {
                        $d = json_decode($this->ssh('xray api stats --server=127.0.0.1:8080 -name "user>>>' . $v['email'] . '>>>traffic>>>downlink" 2>&1', 'xr'), true)['stat']['value'] ?: 0;
                        $u = json_decode($this->ssh('xray api stats --server=127.0.0.1:8080 -name "user>>>' . $v['email'] . '>>>traffic>>>uplink" 2>&1', 'xr'), true)['stat']['value'] ?: 0;
                        $tmp[$k] = [
                            'session' => [
                                'download' => $d,
                                'upload'   => $u,
                            ],
                            'global' => [
                                'download' => $p['users'][$k]['global']['download'],
                                'upload'   => $p['users'][$k]['global']['upload'],
                            ]
                        ];
                    }
                    $p['users'] = $tmp;
                }
                $this->setXrayStats($p);
            } catch (\Throwable $th) {
            }
        }
    }

    public function autoAnalyzeLogs()
    {
        try {
            $pac = $this->getPacConf();
            if (!empty($pac['autoscan'])) {
                require __DIR__ . '/config.php';
                if (!empty($c['admin']) && (empty($this->time3) || ((time() - $this->time3) > $pac['autoscan_timeout']))) {
                    $this->time3 = time();
                    $r = $this->analysisIp(return: 1);
                    if (!empty($r)) {
                        foreach ($r as $k => $v) {
                            foreach ($v as $i) {
                                $t[$i['title']][$k] = 1;
                            }
                        }
                        foreach ($t as $k => $v) {
                            $text .= "\n" . count($v) . " $k";
                        }
                        if (!empty($pac['autodeny'])) {
                            $this->denyIp(array_keys($r));
                            $ban = count(array_keys($r));
                            foreach (array_keys($r) as $v) {
                                $ips[] = [[
                                    'text'          => $v,
                                    'callback_data' => "/searchLogs $v",
                                ]];
                            }
                        }
                        if ($pac['silence'] == 0 || $pac['silence'] == 1) {
                            foreach ($c['admin'] as $k => $v) {
                                $this->send($v, "suspicious ips found: $text" . ($ban ? "\nbanned:$ban" : ''), button: $ips ?: [[
                                    [
                                        'text'          => $this->i18n('analyze'),
                                        'callback_data' => '/analysisIp',
                                    ],
                                ]], disable_notification: $pac['silence'] ? true : false);
                            }
                        }
                    }
                }
            }
        } catch (Exception $e) {
            file_put_contents('/logs/php_error', $e->getMessage());
        }
    }

    public function checkBackup()
    {
        $c = $this->getPacConf();
        if (!empty($c['backup'])) {
            $now = time();
            [$start, $period] = explode('/', $c['backup']);
            $start  = strtotime(trim($start));
            $period = strtotime(trim($period), 0);

            if (
                !empty($start)
                && !empty($period)
                && $now >= $start
            ) {
                // Вычисляем, сколько полных периодов прошло с момента start
                $elapsed = $now - $start;
                $periodsElapsed = floor($elapsed / $period);

                // Время последнего планового бэкапа
                $lastScheduledBackup = $start + ($periodsElapsed * $period);

                // Проверяем, делали ли уже бэкап в этом периоде
                $lastBackupTime = $c['last_backup_time'] ?? 0;

                // Если последний бэкап был сделан до начала текущего периода - делаем бэкап
                if ($lastBackupTime < $lastScheduledBackup) {
                    $c['last_backup_time'] = $now;
                    $this->setPacConf($c);
                    $this->pinBackup();
                }
            }
        }
    }

    public function checkResetXrayStats()
    {
        $pac = $this->getPacConf();
        if (!empty($pac['reset_monthly'])) {
            $now    = time();
            $start  = strtotime('first day of previous month midnight');
            $period = strtotime('1 month', 0);

            if (
                !empty($start)
                && !empty($period)
                && $now >= $start
            ) {
                // Вычисляем, сколько полных периодов прошло с момента start
                $elapsed = $now - $start;
                $periodsElapsed = floor($elapsed / $period);

                // Время последнего планового сброса статистики
                $lastScheduledReset = $start + ($periodsElapsed * $period);

                // Проверяем, делали ли уже сброс в этом периоде
                $lastResetTime = $pac['last_reset_xray_time'] ?? 0;

                // Если последний сброс был сделан до начала текущего периода - делаем сброс
                if ($lastResetTime < $lastScheduledReset) {
                    $pac['last_reset_xray_time'] = $now;
                    $this->setPacConf($pac);
                    $this->resetXrStats(1);
                    require __DIR__ . '/config.php';
                    foreach ($c['admin'] as $admin) {
                        $this->send($admin, "vless: reset stats");
                    }
                }
            }
        }
    }

    public function checkLogs()
    {
        $c = $this->getPacConf();
        if (!empty($c['autocleanlogs'])) {
            $now = time();
            [$start, $period] = explode('/', $c['autocleanlogs']);
            $start  = strtotime(trim($start));
            $period = strtotime(trim($period), 0);

            if (
                !empty($start)
                && !empty($period)
                && $now >= $start
            ) {
                // Вычисляем, сколько полных периодов прошло с момента start
                $elapsed = $now - $start;
                $periodsElapsed = floor($elapsed / $period);

                // Время последней плановой очистки логов
                $lastScheduledClean = $start + ($periodsElapsed * $period);

                // Проверяем, делали ли уже очистку в этом периоде
                $lastCleanTime = $c['last_clean_logs_time'] ?? 0;

                // Если последняя очистка была сделана до начала текущего периода - делаем очистку
                if ($lastCleanTime < $lastScheduledClean) {
                    $c['last_clean_logs_time'] = $now;
                    $this->setPacConf($c);
                    $this->cleanLog();
                }
            }
        }
    }

    public function cleanQueue(): void
    {
        $r = $this->request('deleteWebhook', []);
        $r = $this->request('getUpdates', ['offset' => -1]);
    }

    public function pinAdmin($pin, $unpin = false)
    {
        require __DIR__ . '/config.php';
        if ($unpin) {
            return $this->unpin($c['admin'][0], $pin);
        } else {
            return $this->pin($c['admin'][0], $pin);
        }
    }

    public function pinBackup($file = false)
    {
        require __DIR__ . '/config.php';
        $conf = $this->getPacConf();
        $bot  = preg_replace('~[\W]~iu', '_', $this->request('getMyName', [])['result']['name']);
        $json = $this->export();
        if (!empty($file)) {
            file_put_contents($file, $json);
        }
        if (!empty($conf['pinbackup'])) {
            $this->pinAdmin($conf['pinbackup'], 1);
        }
        $conf['pinbackup'] = $this->upload("{$bot}_export_" . date('d_m_Y_H_i') . '.json', $json, $c['admin'][0])['result']['message_id'];
        $this->setPacConf($conf);
        $this->pinAdmin($conf['pinbackup']);
    }

    public function checkVersion()
    {
        try {
            require __DIR__ . '/config.php';
            if (!empty($c['admin']) && (empty($this->time) || ((time() - $this->time) > 3600))) {
                $this->time = time();
                $current    = file_get_contents('/version');
                $b          = exec('git -C / rev-parse --abbrev-ref HEAD');
                $last       = file_get_contents("https://raw.githubusercontent.com/mercurykd/vpnbot/$b/version");
                if (!empty($last) && $last != $this->last && $last != $current) {
                    $this->last = $last;
                    $diff       = array_slice(explode("\n", $last), 0, count(explode("\n", $last)) - count(explode("\n", $current)));
                    $diff       = array_slice($diff, 0, 10);
                    if (!empty($diff)) {
                        exec('git -C / fetch');
                        foreach ($c['admin'] as $k => $v) {
                            $this->send($v, implode("\n", $diff), 0, [
                                [
                                    [
                                        'text'    => 'changelog',
                                        'web_app' => ['url' => "https://raw.githubusercontent.com/mercurykd/vpnbot/$b/version"],
                                    ],
                                    [
                                        'text'          => $this->i18n('update bot'),
                                        'callback_data' => "/applyupdatebot",
                                    ],
                                ]
                            ]);
                        }
                        if ($this->getPacConf()['autoupdate']) {
                            $this->input['chat'] = $this->input['from'] = $c['admin'][0];
                            $this->applyupdatebot();
                        }
                    }
                }
            }
        } catch (Exception $e) {
        }
    }

    public function checkCert()
    {
        try {
            require __DIR__ . '/config.php';
            if (!empty($c['admin']) && date('H') == 12 && (empty($this->time2) || ((time() - $this->time2) > 4600))) {
                $this->time2 = time();
                $cert = $this->expireCert();
                if (!empty($cert) && $cert - 60 * 60 * 24 * 14 < time()) {
                    foreach ($c['admin'] as $k => $v) {
                        $this->send($v, "certificate expire: " . date('Y-m-d H:i:s', $cert));
                    }
                }
            }
        } catch (Exception $e) {
        }
    }

    public function getTime(int $seconds)
    {
        $seconds = ($seconds - time()) > 0 ? $seconds - time() : 0;
        $items   = [
            'Y' => [
                'diff' => 1970,
                'sign' => 'y',
            ],
            'm' => [
                'diff' => 1,
                'sign' => 'mon',
            ],
            'd' => [
                'diff' => 1,
                'sign' => 'd',
            ],
            'H' => [
                'diff' => 0,
                'sign' => 'h',
            ],
            'i' => [
                'diff' => 0,
                'sign' => 'min',
            ],
            's' => [
                'diff' => 0,
                'sign' => 's',
            ],
        ];
        $text = '';
        foreach ($items as $k => $v) {
            if (($t = gmdate($k, $seconds) - $v['diff']) > 0) {
                $text .= " $t{$v['sign']}";
                if (!empty($i)) {
                    break;
                }
                $i++;
            }
        }
        return trim($text) ?: '♾';
    }

    public function shutdownClient()
    {
        try {
            for ($i=0; $i < 2; $i++) {
                $this->wg = $i;
                $clients  = $this->readClients();
                if ($clients) {
                    foreach ($clients as $k => $v) {
                        if (!empty($v['interface']['## time'])) {
                            if (strtotime($v['interface']['## time']) < time()) {
                                $this->switchClient($k);
                            }
                        }
                    }
                }
            }
        } catch (Exception $e) {
        }
    }

    public function shutdownClientXr()
    {
        try {
            $c = $this->getXray();
            foreach ($c['inbounds'][0]['settings']['clients'] as $k => $v) {
                if (!empty($v['time']) && ($v['time'] < time())) {
                    $this->switchXr($k, 1);
                }
            }
        } catch (Exception $e) {
        }
    }

    public function renameClient(string $name, int $client)
    {
        $clients = $this->readClients();
        $clients[$client]['interface']['## name'] = $name;
        $this->saveClients($clients);
        $server = $this->readConfig();
        foreach ($server['peers'] as $k => $v) {
            if ($v['AllowedIPs'] == $clients[$client]['interface']['Address']) {
                $server['peers'][$k]['## name'] = $name;
            }
        }
        $this->restartWG($this->createConfig($server));
        $this->menu('client', implode('_', $_SESSION['reply'][$this->input['reply']]['args']));
    }

    public function readClients(): array
    {
        return json_decode(file_get_contents($this->getInstanceWG(1) ? $this->clients1 : $this->clients), true) ?: [];
    }

    public function export()
    {
        $this->wg = 0;
        $wg = [
            'server'  => $this->readConfig(),
            'clients' => json_decode(file_get_contents($this->clients), true) ?: [],
        ];
        $this->wg = 1;
        $wg1 = [
            'server'  => $this->readConfig(),
            'clients' => json_decode(file_get_contents($this->clients1), true) ?: [],
        ];
        $conf = [
            'wg'  => $wg,
            'wg1' => $wg1,
            'ad'  => yaml_parse_file($this->adguard),
            'pac' => $this->getPacConf(),
            'hwid' => file_exists($this->hwid) ? (json_decode(file_get_contents($this->hwid), true) ?: []) : [],
            'ssl' => file_exists('/certs/cert_private') && preg_match('~BEGIN PRIVATE KEY~', file_get_contents('/certs/cert_private')) ? [
                'private' => file_get_contents('/certs/cert_private'),
                'public'  => file_get_contents('/certs/cert_public'),
            ] : false,
            'dnstt' => file_exists('/config/dnstt/server.key') ? [
                'private' => file_get_contents('/config/dnstt/server.key'),
                'public'  => file_get_contents('/config/dnstt/server.pub'),
            ] : false,
            'mtproto'       => file_get_contents('/config/mtprotosecret'),
            'mtprotodomain' => file_get_contents('/config/mtprotodomain'),
            'mtprotoadtag'  => file_exists('/config/mtprotoadtag') ? file_get_contents('/config/mtprotoadtag') : '',
            'xray'          => $this->getXray(),
            'hy'            => yaml_parse_file('/config/hysteria.yaml'),
            'oc'            => file_get_contents('/config/ocserv.conf'),
            'ocu'           => file_get_contents('/config/ocserv.passwd'),
            'tt'            => file_exists('/config/trusttunnel/credentials.toml') ? file_get_contents('/config/trusttunnel/credentials.toml') : '',
            'ss'            => $this->getSSConfig(),
            'sl'            => $this->getSSLocalConfig(),
            'cloak'         => file_exists('/config/ckserver.json') ? (json_decode(file_get_contents('/config/ckserver.json'), true) ?: null) : null,
            'ckusers'       => file_exists('/config/ckusers.json') ? (json_decode(file_get_contents('/config/ckusers.json'), true) ?: null) : null,
            'ovpn'          => $this->exportOvpnPki(),
            'xraystats'     => $this->getXrayStats(),
        ];
        return json_encode($conf, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }

    public function backupHasTelemt(array $pac): bool
    {
        foreach ($pac as $key => $value) {
            if (str_starts_with((string) $key, 'telemt_')) {
                return true;
            }
        }
        return false;
    }

    public function import()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} send the export file:",
            $this->input['message_id'],
            reply: 'send the export file:',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'importFile',
            'args'           => [],
        ];
    }

    public function importFile($file = false)
    {
        if (!empty($file)) {
            $json = json_decode(file_get_contents($file), true);
        } else {
            $r    = $this->request('getFile', ['file_id' => $this->input['file_id']]);
            $json = json_decode(file_get_contents($this->file . $r['result']['file_path']), true);
        }
        if (empty($json) || !is_array($json)) {
            $this->answer($this->input['callback_id'], 'error', true);
        } else {
            // certs
            if (!empty($json['ssl'])) {
                $out[] = 'update certificates';
                $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
                file_put_contents('/certs/cert_private', $json['ssl']['private']);
                file_put_contents('/certs/cert_public', $json['ssl']['public']);
            }
            // pac
            if (!empty($json['pac'])) {
                $out[] = 'update pac';
                $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
                if ($this->getPacConf()['amnezia'] != $json['pac']['amnezia']) {
                    $switch_amnezia = 1;
                }
                if ($this->getPacConf()['wg1_amnezia'] != $json['pac']['wg1_amnezia']) {
                    $switch_wg1amnezia = 1;
                }
                $this->setPacConf($json['pac']);
                $out[] = 'update naiveproxy';
                $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
                $this->restartNaive();
                $this->pacUpdate('1');
                if ($this->backupHasTelemt($json['pac'])) {
                    $out[] = 'update telemt';
                    $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
                    $this->restartTelemt();
                }
            }
            // wg
            if (!empty($json['wg'])) {
                $out[] = 'update wireguard';
                $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
                $this->wg = 0;
                $this->saveClients($json['wg']['clients']);
                $this->restartWG($this->createConfig($json['wg']['server']), $switch_amnezia);
                $this->iptablesWG();
            }
            // wg1
            if (!empty($json['wg1'])) {
                $out[] = 'update wireguard 1';
                $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
                $this->wg = 1;
                $this->saveClients($json['wg1']['clients']);
                $this->restartWG($this->createConfig($json['wg1']['server']), $switch_wg1amnezia);
                $this->iptablesWG();
            }
            // ad
            if (!empty($json['ad'])) {
                $out[] = 'update adguard';
                $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
                $this->stopAd();
                yaml_emit_file($this->adguard, $json['ad']);
                $this->startAd();
            }
            // ss
            if (!empty($json['ss'])) {
                $out[] = 'update shadowsocks server';
                $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
                $this->ssh('pkill ssserver', 'ss');
                file_put_contents('/config/ssserver.json', json_encode($json['ss'], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
                $this->ssh('ssserver -v -d -c /config.json', 'ss');
            }
            // sl
            if (!empty($json['sl'])) {
                $out[] = 'update shadowsocks proxy';
                $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
                $this->ssh('pkill sslocal', 'proxy');
                file_put_contents('/config/sslocal.json', json_encode($json['sl'], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
                $this->ssh('sslocal -v -d -c /config.json', 'proxy');
            }
            // mtproto
            if (!empty($json['mtproto'])) {
                $out[] = 'update mtproto';
                $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
                file_put_contents('/config/mtprotosecret', $json['mtproto']);
                file_put_contents('/config/mtprotodomain', $json['mtprotodomain'] ?: '');
                file_put_contents('/config/mtprotoadtag', trim($json['mtprotoadtag'] ?? ''));
                $this->restartTG();
            }
            // hwid
            if (array_key_exists('hwid', $json)) {
                $out[] = 'update hwid devices';
                $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
                $data = is_array($json['hwid']) ? $json['hwid'] : [];
                file_put_contents($this->hwid, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
            }
            // xray
            if (!empty($json['xray'])) {
                $out[] = 'update xray';
                $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
                $this->restartXray($json['xray']);
                $this->adguardXrayClients();
                $this->setUpstreamDomain($json['pac']['transport'] != 'Reality' ? 't' : ($json['pac']['reality']['domain'] ?: $json['xray']['inbounds'][0]['streamSettings']['realitySettings']['serverNames'][0]));
            }
            // xraystats
            if (!empty($json['xraystats'])) {
                $out[] = 'update xray stats';
                $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
                $this->setXrayStats($json['xraystats']);
            }
            // ocserv
            if (!empty($json['oc'])) {
                $out[] = 'update ocserv';
                $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
                file_put_contents('/config/ocserv.passwd', $json['ocu']);
                $this->restartOcserv($json['oc']);
            }
            // hysteria
            if (!empty($json['hy'])) {
                $out[] = 'update hysteria';
                $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
                yaml_emit_file('/config/hysteria.yaml', $json['hy']);
                $this->restartHysteria();
            }
            // trusttunnel
            if (!empty($json['tt'])) {
                $out[] = 'update trusttunnel';
                $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
                @mkdir('/config/trusttunnel', 0755, true);
                file_put_contents('/config/trusttunnel/credentials.toml', $json['tt']);
                $this->restartTt();
            }
            // cloak
            if (!empty($json['cloak'])) {
                $out[] = 'update cloak';
                $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
                $this->ssh('pkill -f ck-server', 'ss');
                file_put_contents(
                    '/config/ckserver.json',
                    json_encode($json['cloak'], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)
                );
                // Восстанавливаем side-store с именами; если в бэкапе нет
                // (старый формат) — getCloakUsers() забутстрапит из BypassUID.
                if (!empty($json['ckusers']) && is_array($json['ckusers'])) {
                    $this->setCloakUsers($json['ckusers']);
                } else {
                    @unlink('/config/ckusers.json');
                }
                if (!empty($json['cloak']['Enabled'])) {
                    $this->ssh($this->ckServerRestartCmd(), 'ss');
                }
            }
            // openvpn (PKI + server.conf + ccd, восстановленные из inline-base64)
            if (!empty($json['ovpn']) && is_array($json['ovpn'])) {
                $out[] = 'update openvpn';
                $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
                $this->importOvpnPki($json['ovpn']);
                $this->restartOvpn();
            }
            if (!empty($json['pac']['domain'])) {
                $this->setUpstreamDomainOcserv($json['pac']['domain']);
                $this->setUpstreamDomainNaive($json['pac']['domain']);
            }
            // dnstt
            if (!empty($json['dnstt'])) {
                $out[] = 'update dnstt certificates';
                $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
                file_put_contents('/config/dnstt/server.key', $json['dnstt']['private']);
                file_put_contents('/config/dnstt/server.pub', $json['dnstt']['public']);
            }
            // nginx
            $out[] = 'reset nginx';
            $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));

            $this->cloakNginx();

            $out[] = "end import";
            $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
            $this->language = $this->getPacConf()['language'] ?: 'en';
            $this->limit    = $this->getPacConf()['limitpage'] ?: 5;
            if (empty($file)) {
                sleep(3);
                $this->menu();
            }
        }
    }

    public function dw($u, $t)
    {
        $pac                    = $this->getPacConf();
        $c                      = $this->getXray()['inbounds'][0]['settings']['clients'][$u];
        $_GET['s']              = $c['id'];
        $_GET['t']              = $t;
        $_SERVER['SERVER_NAME'] = $this->getDomain($pac['transport'] != 'Reality');
        $conf                   = $this->subscription(1);
        $this->sendFile($this->input['from'], new CURLStringFile($conf, $c['email'] . ($t == 'cl' ? '_mihomo.yaml' :($t == 'si' ? '_singbox.json' : '_v2ray.json'))));
    }

    public function downloadPeer($client)
    {
        $cl     = $client;
        $client = $this->readClients()[$client];
        $name   = $this->getName($client['interface']);
        $code   = $this->createConfig($client);
        $this->upload(preg_replace(['~\s+~', '~\(|\)~'], ['_', ''], $name) . ".conf", $code);
        if ($this->getPacConf()['blinkmenu']) {
            $this->delete($this->input['chat'], $this->input['message_id']);
            $this->input['message_id'] = $this->send($this->input['chat'], '.')['result']['message_id'];
            $this->menu('client', "{$cl}_0");
        }
    }

    public function switchClient($client)
    {
        $clients = $this->readClients();
        if ($clients[$client]['# off']) {
            unset($clients[$client]['# off']);
        } else {
            $clients[$client]['# off'] = 1;
        }
        unset($clients[$client]['interface']['## time']);
        $this->saveClients($clients);

        $server = $this->readConfig();
        if (array_key_exists('# PublicKey', $server['peers'][$client])) {
            foreach ($server['peers'][$client] as $k => $v) {
                $new[trim(preg_replace('~#~', '', $k, 1))] = $v;
            }
        } else {
            foreach ($server['peers'][$client] as $k => $v) {
                $new["# $k"] = $v;
            }
        }
        unset($new['## time']);
        unset($new['# ## time']);
        $server['peers'][$client] = $new;
        $this->restartWG($this->createConfig($server));
    }

    public function resetAmnezia($page = 0) {
        $this->switchAmnezia($page, 1);
    }

    public function reduceAmnezia($page = 0) {
        $this->switchAmnezia($page, false, 1);
    }

    public function applyAmneziaTemplate($template, $page = 0)
    {
        $allowed = ['standard_2', 'aggressive_2', 'mobile_2', 'classic_1'];
        if (!in_array($template, $allowed, true)) {
            return $this->menu('wg', $page);
        }
        $c = $this->getPacConf();
        $prefix = $this->getInstanceWG(1);
        $c[$prefix . 'amnezia']      = 1;
        $c[$prefix . 'amnezia_tpl']  = $template;
        $c[$prefix . 'amnezia_keys'] = $this->generateAmneziaKeys($template);
        // Сбросить ротационный таймер: ручная смена шаблона = свежая генерация
        // I1-I5, нет смысла дёргать ротацию повторно через несколько часов.
        if ((int) ($c[$prefix . 'amnezia_rotation_period'] ?? 0) > 0) {
            $c[$prefix . 'amnezia_last_rotation'] = time();
        }
        $this->setPacConf($c);
        $this->switchAmnezia($page, false, false, 1);
    }

    public function amneziaTemplates($page = 0)
    {
        $prefix  = $this->getInstanceWG(1);
        $current = $this->getPacConf()[$prefix . 'amnezia_tpl'] ?? '';
        $labels  = [
            'standard_2'   => 'Standard 2.0',
            'aggressive_2' => 'Aggressive 2.0',
            'mobile_2'     => 'Mobile 2.0',
            'classic_1'    => 'Classic 1.x',
        ];
        $descs = [
            'standard_2'   => 'балансир: умеренные junk-пакеты и I1–I5',
            'aggressive_2' => 'против GFW-класса DPI; +10–15% трафика',
            'mobile_2'     => 'мелкие junk, экономит батарею и трафик',
            'classic_1'    => 'без 2.0-полей, совместимо со старыми клиентами',
        ];
        $text = ['Menu -> Wireguard -> amnezia templates', ''];
        foreach ($labels as $k => $label) {
            $mark = ($k === $current) ? '• ' : '';
            $text[] = "$mark<b>$label</b> — " . $descs[$k];
        }
        $data = [];
        foreach ($labels as $k => $label) {
            $data[] = [[
                'text'          => (($k === $current) ? '• ' : '') . $label,
                'callback_data' => "/amneziaTemplate $k $page",
            ]];
        }
        $data[] = [[
            'text'          => $this->i18n('back'),
            'callback_data' => "/menu wg $page",
        ]];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            implode("\n", $text),
            $data,
        );
    }

    // Validates a CPS string for AmneziaWG 2.0 I1-I5 fields.
    // Accepts only the tokens supported by amneziawg-go: <b 0xHEX>, <r N>, <rc N>, <rd N>, <t>.
    // Critical rule (from amnezia article comments): hex inside <b 0x..> must have an
    // EVEN number of hex chars — otherwise it's not a whole byte sequence and the peer
    // silently rejects the signature packet.
    //
    // Future-work (предложения для upstream amneziawg-go — пока НЕ существуют):
    //   <ra N>  — N случайных букв a-zA-Z (для User-Agent, hostname-частей)
    //   <rh N>  — N символов hostname-charset a-zA-Z0-9- (DNS-labels, SNI)
    //   <ru N>  — N байт UTF-8 (теоретически для SNI с IDN-доменами,
    //             хотя на практике IDN на wire — это уже Punycode-ASCII).
    // Сейчас обходимся литералами через <b 0xHEX> (см. HTTP/1.1 пресет:
    // "Host: cloudflare.com" целиком захардкожен). Если эти токены появятся
    // upstream — нужно (1) добавить альтернативы в regex ниже, (2) добавить
    // строки в cheatsheet setAmneziaI1, (3) при желании — pres-helpers
    // типа cpsHTTPGet($host_random_len, ...).
    public function validateCPSLine($s)
    {
        $s = trim($s);
        if ($s === '') {
            return 'empty';
        }
        if (!preg_match('~^(?:<b 0x[0-9a-fA-F]+>|<r \d+>|<rc \d+>|<rd \d+>|<t>)+$~', $s)) {
            return 'bad syntax — allowed tokens: &lt;b 0xHEX&gt;, &lt;r N&gt;, &lt;rc N&gt;, &lt;rd N&gt;, &lt;t&gt; (no spaces between tokens)';
        }
        if (preg_match_all('~<b 0x([0-9a-fA-F]+)>~', $s, $m)) {
            foreach ($m[1] as $hex) {
                if (strlen($hex) % 2 !== 0) {
                    return "hex in &lt;b 0x$hex&gt; has odd length — must be even (whole bytes)";
                }
            }
        }
        return '';
    }

    // CPS-builders с согласованными полями длины. Возвращают строку CPS, у которой
    // ВСЕ внутренние length-поля корректно соответствуют реальному размеру пакета.
    // Это глубже обманывает DPI: первый pass-парсер не отбрасывает пакет как
    // "битый" из-за рассогласования length-fields. target = желаемый итоговый
    // размер пакета I1 в байтах (≥100).

    // TLS 1.2/1.3 ClientHello (RFC 5246 / 8446). Структура wire-формата идентична,
    // отличаются только расширения (которые в нашем junk-пакете отсутствуют).
    // Layout: record_hdr(5) + handshake_hdr(4) + legacy_version(2) + random(32) + tail.
    // Min target = 43 (всё структурное без payload); рекомендуется ≥100 (амнезия 2.0).
    public function cpsTLS(int $target): string
    {
        if ($target < 43) {
            throw new InvalidArgumentException("cpsTLS: target=$target < 43 minimum");
        }
        $rec_len = $target - 5;
        $hs_len  = $target - 9;
        $hex = sprintf('160301%04x01%06x0303', $rec_len, $hs_len);
        $pad = $target - 43;
        return "<b 0x$hex><r 32><r $pad>";
    }

    // DTLS 1.2 ClientHello (RFC 6347). Отличается от TLS дополнительными
    // полями в record/handshake-заголовках (epoch+seq, message_seq+frag_off+frag_len).
    // Layout: record_hdr(13) + handshake_hdr(12) + inner_version(2) + random(32) + tail.
    // Min target = 59.
    public function cpsDTLS(int $target): string
    {
        if ($target < 59) {
            throw new InvalidArgumentException("cpsDTLS: target=$target < 59 minimum");
        }
        $rec_len  = $target - 13;
        $hs_len   = $target - 25;
        $hex = sprintf(
            '16fefd0000000000000000%04x01%06x0000000000%06xfefd',
            $rec_len, $hs_len, $hs_len,
        );
        $pad = $target - 59;
        return "<b 0x$hex><r 32><r $pad>";
    }

    // STUN Binding Request (RFC 5389). msg_length указывает количество байт
    // ПОСЛЕ 20-байтного STUN-заголовка (т.е. в attribute-секции).
    // Layout: type(2) + length(2) + magic(4) + tx_id(12) + attrs(target-20).
    // Min target = 20 (attrs=0); STUN attrs не обязаны быть кратны 4, но
    // отдельные атрибуты — да; для junk-mimicry это не проверяется.
    public function cpsSTUN(int $target): string
    {
        if ($target < 20) {
            throw new InvalidArgumentException("cpsSTUN: target=$target < 20 minimum");
        }
        $attrs = $target - 20;
        $hex   = sprintf('0001%04x2112a442', $attrs);
        return "<b 0x$hex><r 12><r $attrs>";
    }

    // HTTP/2 connection preface (RFC 7540 §3.5) + SETTINGS frame (тип 0x04).
    // RFC 7540 §6.5: "A SETTINGS frame ... A SETTINGS frame whose length is not
    // a multiple of 6 octets MUST be treated as a connection error". Поэтому
    // target должен удовлетворять (target - 33) % 6 == 0, т.е. target ∈ {33,39,45,...,123,129,...}.
    // Layout: preface(24) + frame_hdr(9) + payload(target-33).
    public function cpsHTTP2(int $target): string
    {
        if ($target < 33) {
            throw new InvalidArgumentException("cpsHTTP2: target=$target < 33 minimum");
        }
        if (($target - 33) % 6 !== 0) {
            throw new InvalidArgumentException(
                "cpsHTTP2: target=$target — frame body " . ($target - 33) . " not multiple of 6 (RFC 7540 §6.5)"
            );
        }
        $body = $target - 33;
        $hex  = '505249202a20485454502f322e300d0a0d0a534d0d0a0d0a'
              . sprintf('%06x040000000000', $body);
        return "<b 0x$hex><r $body>";
    }

    // Стандартный DNS-ответ на A-запрос (RFC 1035), пригодный для I1-junk.
    // tx_id рандомизируется per-session через <r 2>; всё остальное — литералы:
    // header (flags=0x8180 response+RA, qd=1 an=1) + question (name+A+IN) +
    // answer (compressed name pointer 0xc00c + A + IN + TTL + rdlen + IPv4).
    public function cpsDNSResponseA(string $domain, string $ipv4, int $target): string
    {
        $name_hex = '';
        foreach (explode('.', $domain) as $part) {
            if (strlen($part) > 63) {
                throw new InvalidArgumentException("cpsDNSResponseA: label '$part' >63 bytes (RFC 1035 §2.3.4)");
            }
            $name_hex .= sprintf('%02x', strlen($part)) . bin2hex($part);
        }
        $name_hex .= '00';
        $ip_hex = '';
        foreach (explode('.', $ipv4) as $oct) {
            $n = (int) $oct;
            if ($n < 0 || $n > 255) {
                throw new InvalidArgumentException("cpsDNSResponseA: octet $oct out of range");
            }
            $ip_hex .= sprintf('%02x', $n);
        }
        $literal  = '81800001000100000000';
        $literal .= $name_hex . '00010001';
        $literal .= 'c00c00010001000001230004' . $ip_hex;
        $pad = $target - 2 - strlen($literal) / 2;
        if ($pad < 0) {
            throw new InvalidArgumentException("cpsDNSResponseA: target=$target too small for '$domain'");
        }
        return "<r 2><b 0x$literal><r $pad>";
    }

    public function setAmneziaI1($page = 0)
    {
        $c   = $this->getPacConf();
        $cur = $c[$this->getInstanceWG(1) . 'amnezia_keys']['I1'] ?? '—';

        // Tap-to-copy CPS presets. Стартовые байты имитируют реальный протокол, остаток —
        // рандом-добивка до рекомендуемых ≥100 байт (habr.com/ru/companies/amnezia/articles/1014636).
        // Hex внутри <b 0x..> всегда чётной длины (целые байты). Никаких пробелов между токенами.
        // Источники структуры заголовков:
        //   QUIC — RFC 9000, docs.amnezia.org
        //   DNS  — RFC 1035; mDNS — RFC 6762
        //   TLS  — RFC 5246 (1.2) / RFC 8446 (1.3); DTLS — RFC 6347
        //   HTTP — RFC 7230 (1.1) / RFC 7540 (2)
        //   STUN — RFC 5389 (magic cookie 0x2112A442)
        //   NTP  — RFC 5905 (mode 3 client, first byte 0x23 = LI=0,VN=4,Mode=3)
        $presets = [
            'QUIC (UDP/443)' => [
                'Initial v1 (long header, RFC 9000)'
                    => '<b 0xc700000001><r 8><t><r 100>',
                'Initial v1 (вариант из доки Amnezia)'
                    => '<b 0xd100000001><r 8><t><r 100>',
            ],
            'DNS / mDNS (UDP/53)' => [
                'RU: Yandex DNS-ответ (yabs.yandex.ru)'
                    => '<b 0x8580000100010000000004796162730679616e6465780272750000010001c00c000100010001c00c000100010000026d000457fa27d1><r 50>',
                'RU: Yandex DNS-ответ (widget.tickets.kinopoisk + Afisha)'
                    => '<b 0x084481800001000300000000077469636b65747306776964676574096b696e6f706f69736b0272750000010001c00c0005000100000039001806776964676574077469636b6574730679616e646578c025c0390005000100000039002b1765787465726e616c2d7469636b6574732d776964676574066166697368610679616e646578036e657400c05d000100010000001c000457fafe25>',
                'Global: Cloudflare A-ответ (cloudflare.com → 104.16.132.229)'
                    => $this->cpsDNSResponseA('cloudflare.com', '104.16.132.229', 120),
                'Global: Google A-ответ (google.com → 142.250.80.46)'
                    => $this->cpsDNSResponseA('google.com', '142.250.80.46', 120),
                'Global: A-запрос www.google.com (recursion desired)'
                    => '<r 2><b 0x012000010000000000000377777706676f6f676c6503636f6d0000010001><r 80>',
                'Global: A-запрос cloudflare.com (recursion desired)'
                    => '<r 2><b 0x012000010000000000000a636c6f7564666c61726503636f6d0000010001><r 80>',
                'Global: mDNS-запрос _services._dns-sd._udp.local'
                    => '<b 0x000000000001000000000000095f7365727669636573075f646e732d7364045f756470056c6f63616c00000c0001><r 80>',
            ],
            'TLS / DTLS' => [
                'TLS 1.2/1.3 ClientHello (consistent length fields)'
                    => $this->cpsTLS(120),
                'DTLS 1.2 ClientHello (consistent length fields, RFC 6347)'
                    => $this->cpsDTLS(120),
            ],
            'HTTP' => [
                'HTTP/2 preface + SETTINGS frame (consistent frame_len)'
                    => $this->cpsHTTP2(123),
                'HTTP/1.1 GET / с Host: cloudflare.com'
                    => '<b 0x474554202f20485454502f312e310d0a486f73743a20636c6f7564666c6172652e636f6d0d0a4163636570743a202a2f2a0d0a0d0a><r 70>',
            ],
            'WebRTC / NTP (UDP)' => [
                'STUN Binding Request (consistent msg_length, RFC 5389)'
                    => $this->cpsSTUN(112),
                'NTPv4 client request (mode 3, RFC 5905)'
                    => '<b 0x23000000000000000000000000000000><r 100>',
            ],
            'Прочее' => [
                'Лёгкий профиль (минимальный валидный 2.0)'
                    => '<b 0xc000000001><r 100>',
            ],
        ];
        $lines = [
            "@{$this->input['username']} введите строку I1 (CPS) или 0 — отключить цепочку 2.0.",
            '',
            'Текущее: <code>' . htmlspecialchars($cur) . '</code>',
            '',
            'Правила: hex в &lt;b 0x..&gt; — чётное число символов (целые байты); итоговый размер пакета ≥100 байт. Без пробелов между токенами.',
            '',
            'Токены CPS:',
            '<code>&lt;b 0xHEX&gt;</code> — литерал-байты, для заголовков протоколов',
            '<code>&lt;r N&gt;</code>     — N случайных байт, для CID/padding/IP/random fields',
            '<code>&lt;rc N&gt;</code>    — N случайных printable-ASCII (буквы+цифры+пунктуация)',
            '<code>&lt;rd N&gt;</code>    — N случайных ASCII-цифр (0-9), для числовых ID',
            '<code>&lt;t&gt;</code>       — 4-байтный UNIX-timestamp',
            '',
            'I1 пишется одинаково в server и client (требование протокола: обе стороны должны консьюмить тот же junk-паттерн). Для разнообразия fingerprint\'а во времени включите авто-ротацию: rotate: every Nd.',
            '',
            'Готовые примеры (нажмите на строку — скопируется):',
        ];
        foreach ($presets as $section => $items) {
            $lines[] = '';
            $lines[] = "<b>— $section —</b>";
            foreach ($items as $label => $val) {
                $lines[] = "• $label";
                $lines[] = '<code>' . htmlspecialchars($val) . '</code>';
            }
        }

        $r = $this->send(
            $this->input['chat'],
            implode("\n", $lines),
            $this->input['message_id'],
            reply: 'введите I1 или 0',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'setAmneziaI1Value',
            'args'           => [$page],
        ];
    }

    public function setAmneziaI1Value($text, $page = 0)
    {
        $text   = trim($text);
        $c      = $this->getPacConf();
        $prefix = $this->getInstanceWG(1);
        $k      = $prefix . 'amnezia_keys';

        if ($text === '0' || $text === '') {
            if (!empty($c[$k])) {
                unset($c[$k]['I1']);
                $this->setPacConf($c);
                $this->switchAmnezia($page, false, false, 1);
                return;
            }
            $this->menu('wg', $page);
            return;
        }

        $err = $this->validateCPSLine($text);
        if ($err) {
            $this->update($this->input['chat'], $this->input['message_id'], "I1: $err");
            sleep(3);
            $this->menu('wg', $page);
            return;
        }

        if (empty($c[$k])) {
            $c[$k] = $this->generateAmneziaKeys($c[$prefix . 'amnezia_tpl'] ?? 'standard_2');
        }
        $c[$k]['I1']       = $text;
        $c[$prefix . 'amnezia'] = 1;
        $this->setPacConf($c);
        $this->switchAmnezia($page, false, false, 1);
    }

    public function switchAmnezia($page = 0, $reset = false, $reduce = false, $apply = false, $silent = false)
    {
        $c = $this->getPacConf();
        switch (true) {
            case !empty($reset):
                $amnezia = 1;
                unset($c[$this->getInstanceWG(1) . 'amnezia_keys']);
                unset($c[$this->getInstanceWG(1) . 'presharedkey']);
                break;
            case !empty($reduce):
                $amnezia = 1;
                unset($c[$this->getInstanceWG(1) . 'amnezia_keys']['S3']);
                unset($c[$this->getInstanceWG(1) . 'amnezia_keys']['S4']);
                unset($c[$this->getInstanceWG(1) . 'amnezia_keys']['I1']);
                unset($c[$this->getInstanceWG(1) . 'amnezia_keys']['I2']);
                unset($c[$this->getInstanceWG(1) . 'amnezia_keys']['I3']);
                unset($c[$this->getInstanceWG(1) . 'amnezia_keys']['I4']);
                unset($c[$this->getInstanceWG(1) . 'amnezia_keys']['I5']);
                break;
            case !empty($apply):
                // Caller (applyAmneziaTemplate) has already set keys + amnezia=1.
                $amnezia = 1;
                break;

            default:
                $amnezia = $c[$this->getInstanceWG(1) . 'amnezia'] = $c[$this->getInstanceWG(1) . 'amnezia'] ? 0 : 1;
                break;
        }
        $this->setPacConf($c);

        $pk = $this->presharedKey();
        $ak = $this->amneziaKeys();
        $clients = $this->readClients();
        foreach ($clients as $k => $v) {
            unset($clients[$k]['peers'][0]['PresharedKey']);
            unset($clients[$k]['interface']['Jc']);
            unset($clients[$k]['interface']['Jmin']);
            unset($clients[$k]['interface']['Jmax']);
            unset($clients[$k]['interface']['S1']);
            unset($clients[$k]['interface']['S2']);
            unset($clients[$k]['interface']['S3']);
            unset($clients[$k]['interface']['S4']);
            unset($clients[$k]['interface']['H1']);
            unset($clients[$k]['interface']['H2']);
            unset($clients[$k]['interface']['H3']);
            unset($clients[$k]['interface']['H4']);
            unset($clients[$k]['interface']['I1']);
            unset($clients[$k]['interface']['I2']);
            unset($clients[$k]['interface']['I3']);
            unset($clients[$k]['interface']['I4']);
            unset($clients[$k]['interface']['I5']);
            if (!empty($amnezia)) {
                $clients[$k]['peers'][0]['PresharedKey'] = $pk;
                foreach ($ak as $j => $i) {
                    $clients[$k]['interface'][$j] = $i;
                }
            }
        }
        $this->saveClients($clients);

        $wg = $this->readConfig();
        unset($wg['interface']['Jc']);
        unset($wg['interface']['Jmin']);
        unset($wg['interface']['Jmax']);
        unset($wg['interface']['S1']);
        unset($wg['interface']['S2']);
        unset($wg['interface']['S3']);
        unset($wg['interface']['S4']);
        unset($wg['interface']['H1']);
        unset($wg['interface']['H2']);
        unset($wg['interface']['H3']);
        unset($wg['interface']['H4']);
        unset($wg['interface']['I1']);
        unset($wg['interface']['I2']);
        unset($wg['interface']['I3']);
        unset($wg['interface']['I4']);
        unset($wg['interface']['I5']);
        if (!empty($amnezia)) {
            foreach ($ak as $j => $i) {
                $wg['interface'][$j] = $i;
            }
        }

        foreach ($wg['peers'] as $k => $v) {
            if (!empty($amnezia)) {
                $wg['peers'][$k]['PresharedKey'] = $pk;
            } else {
                unset($wg['peers'][$k]['PresharedKey']);
            }
        }
        $this->restartWG($this->createConfig($wg), !$reset && !$reduce && !$apply);
        if (!$silent) {
            $this->menu('wg', $page);
        }
    }

    // Ротация только "junk"-полей I1-I5 и S3-S4 (генерация заново по текущему
    // шаблону). S1/S2/H1-H4/Jc/Jmin/Jmax и PSK сохраняются — они влияют на
    // совместимость handshake между сервером и клиентами. После ротации
    // клиентам нужно перекачать конфиги.
    public function rotateAmneziaJunk($silent = false, $page = 0)
    {
        $c = $this->getPacConf();
        $prefix = $this->getInstanceWG(1);
        if (empty($c[$prefix . 'amnezia'])) {
            if (!$silent) {
                $this->menu('wg', $page);
            }
            return;
        }
        $tpl = $c[$prefix . 'amnezia_tpl'] ?? 'standard_2';
        // classic_1 — это 1.x-режим без I1-I5/S3-S4. Ротировать нечего, но
        // обновим last_rotation чтобы maybeRotate не дёргался каждый менеджмент.
        if ($tpl === 'classic_1') {
            $c[$prefix . 'amnezia_last_rotation'] = time();
            $this->setPacConf($c);
            if (!$silent) {
                $this->menu('wg', $page);
            }
            return;
        }
        // Defensive: гарантировать наличие полного набора ключей перед частичной
        // ротацией. Закрывает race-окно между resetAmnezia и завершением
        // switchAmnezia (когда amnezia_keys могут быть пусты, но amnezia=1).
        if (empty($c[$prefix . 'amnezia_keys'])) {
            $this->amneziaKeys();
            $c = $this->getPacConf();
        }
        $new = $this->generateAmneziaKeys($tpl);
        foreach (['I1', 'I2', 'I3', 'I4', 'I5', 'S3', 'S4'] as $k) {
            if (isset($new[$k])) {
                $c[$prefix . 'amnezia_keys'][$k] = $new[$k];
            } else {
                unset($c[$prefix . 'amnezia_keys'][$k]);
            }
        }
        $c[$prefix . 'amnezia_last_rotation'] = time();
        $this->setPacConf($c);
        $this->switchAmnezia($page, false, false, 1, $silent);
    }

    // Ленивая проверка таймера ротации. Вызывается из statusWg при открытии
    // wg-меню. Если ротация настроена и срок истёк — silent-перегенерация.
    public function maybeRotateAmnezia()
    {
        $c = $this->getPacConf();
        $prefix = $this->getInstanceWG(1);
        if (empty($c[$prefix . 'amnezia'])) {
            return;
        }
        $period_days = (int) ($c[$prefix . 'amnezia_rotation_period'] ?? 0);
        if ($period_days <= 0) {
            return;
        }
        $last = (int) ($c[$prefix . 'amnezia_last_rotation'] ?? 0);
        if (time() < $last + $period_days * 86400) {
            return;
        }
        $this->rotateAmneziaJunk(true);
    }

    public function setAmneziaRotation($page = 0)
    {
        $c = $this->getPacConf();
        $prefix = $this->getInstanceWG(1);
        $cur = (int) ($c[$prefix . 'amnezia_rotation_period'] ?? 0);
        $last = (int) ($c[$prefix . 'amnezia_last_rotation'] ?? 0);
        $last_str = $last ? date('Y-m-d H:i', $last) : '—';
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} введите период авто-ротации I1-I5/S3-S4 в днях (0 — выкл).\n\n"
            . "Текущий период: <code>" . ($cur ?: 'выкл') . "</code>\n"
            . "Последняя ротация: <code>$last_str</code>\n\n"
            . "После ротации клиентам нужно перекачать конфиги (S1/S2/H1-H4/PSK сохраняются, рукопожатие совместимо, но junk-паттерн обновится).",
            $this->input['message_id'],
            reply: 'введите N или 0',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'setAmneziaRotationValue',
            'args'           => [$page],
        ];
    }

    public function setAmneziaRotationValue($text, $page = 0)
    {
        $text = trim($text);
        if (!preg_match('~^\d+$~', $text)) {
            $this->update($this->input['chat'], $this->input['message_id'], 'rotation: введите целое число дней или 0');
            sleep(3);
            $this->menu('wg', $page);
            return;
        }
        $days = min((int) $text, 365);
        $c = $this->getPacConf();
        $prefix = $this->getInstanceWG(1);
        $c[$prefix . 'amnezia_rotation_period'] = $days;
        if ($days > 0 && empty($c[$prefix . 'amnezia_last_rotation'])) {
            $c[$prefix . 'amnezia_last_rotation'] = time();
        }
        $this->setPacConf($c);
        $this->menu('wg', $page);
    }

    public function switchTorrent($page = 0, $restart = false)
    {
        $c = $this->getPacConf();
        $c[$this->getInstanceWG(1) . 'blocktorrent'] = $c[$this->getInstanceWG(1) . 'blocktorrent'] ? 0 : 1;
        $this->setPacConf($c);
        $this->iptablesWG();
        $this->answer($this->input['callback_id'], 'доступ к торрентам ' . ($c[$this->getInstanceWG(1) . 'blocktorrent'] ? 'заблокирован' : 'разблокирован'), true);
        $this->menu('wg', $page);
    }

    public function switchEndpoint($page = 0)
    {
        $c = $this->getPacConf();
        $c[$this->getInstanceWG(1) . 'endpoint'] = $c[$this->getInstanceWG(1) . 'endpoint'] ? 0 : 1;
        $this->setPacConf($c);
        $this->menu('wg', $page);
    }

    public function iptablesWG()
    {
        $c = $this->getPacConf();
        $this->ssh('iptables -F', $this->getInstanceWG());
        if ($c['exchange']) {
            $this->ssh('bash /block_exchange.sh', $this->getInstanceWG());
        }
        if ($c['blocktorrent']) {
            $this->ssh('bash /block_torrent.sh', $this->getInstanceWG());
        }
    }
    public function switchExchange($page)
    {
        $c = $this->getPacConf();
        $c[$this->getInstanceWG(1) . 'exchange'] = $c[$this->getInstanceWG(1) . 'exchange'] ? 0 : 1;
        $this->setPacConf($c);
        $this->iptablesWG();
        $this->answer($this->input['callback_id'], 'обмен между пользователями ' . ($c[$this->getInstanceWG(1) . 'exchange'] ? 'заблокирован' : 'разблокирован'), true);
        $this->menu('wg', $page);
    }

    public function blinkmenuswitch()
    {
        $c = $this->getPacConf();
        $c['blinkmenu'] = $c['blinkmenu'] ? 0 : 1;
        $this->setPacConf($c);
        $this->menu('config');
    }

    public function sendQr($name, $code, $title = false)
    {
        $qr      = preg_replace(['~\s+~', '~\(~', '~\)~'], ['_'], $name);
        $qr_file = __DIR__ . "/qr/$qr.png";
        exec("qrencode -t png -o $qr_file '$code'");
        $r = $this->sendPhoto(
            $this->input['chat'],
            curl_file_create($qr_file),
            $title ?: $name
        );
        unlink($qr_file);
    }

    public function qrPeer($client)
    {
        $cl      = $client;
        $client  = $this->readClients()[$client];
        $name    = $this->getName($client['interface']);
        if ($this->getWGType() == 'awg') {
            $this->sendQr($name, preg_replace('/^vpn:\/\//', '', $this->getAmneziaShortLink($client)), "$name for AmneziaVPN");
            $this->sendQr($name, $this->createConfig($client), "$name for AmneziaWG");
        } else {
            $this->sendQr($name, $this->createConfig($client), "$name for Wireguard");
        }
        if ($this->getPacConf()['blinkmenu']) {
            $this->delete($this->input['chat'], $this->input['message_id']);
            $this->input['message_id'] = $this->send($this->input['chat'], '.')['result']['message_id'];
            $this->menu('client', "{$cl}_0");
        }
    }

    public function qrSS()
    {
        $ss_link = $this->buildSSLink($this->getHashBot());
        $qr_file = __DIR__ . "/qr/shadowsocks.png";
        exec("qrencode -t png -o $qr_file '$ss_link'");
        $r = $this->sendPhoto(
            $this->input['chat'],
            curl_file_create($qr_file),
            "<code>$ss_link</code>"
        );
        unlink($qr_file);
        if ($this->getPacConf()['blinkmenu']) {
            $this->delete($this->input['chat'], $this->input['message_id']);
            $this->input['message_id'] = $this->send($this->input['chat'], '.')['result']['message_id'];
            $this->menu('ss');
        }
    }

    public function qrXray($i, $s = false)
    {
        $link    = $this->linkXray($i, $s);
        $qr_file = __DIR__ . "/qr/xray.png";
        exec("qrencode -t png -o $qr_file '$link'");
        $r = $this->sendPhoto(
            $this->input['chat'],
            curl_file_create($qr_file),
            "<code>$link</code>"
        );
        unlink($qr_file);
        if ($this->getPacConf()['blinkmenu']) {
            $this->delete($this->input['chat'], $this->input['message_id']);
            $this->input['message_id'] = $this->send($this->input['chat'], '.')['result']['message_id'];
            $this->xray();
        }
    }

    public function qrMtproto()
    {
        $link    = $this->linkMtproto();
        $qr_file = __DIR__ . "/qr/mtproto.png";
        exec("qrencode -t png -o $qr_file '$link'");
        $r = $this->sendPhoto(
            $this->input['chat'],
            curl_file_create($qr_file),
            "<code>$link</code>"
        );
        unlink($qr_file);
        if ($this->getPacConf()['blinkmenu']) {
            $this->delete($this->input['chat'], $this->input['message_id']);
            $this->input['message_id'] = $this->send($this->input['chat'], '.')['result']['message_id'];
            $this->mtproto();
        }
    }

    public function upload($name, $code, $chat = false)
    {
        $path = "/logs/$name";
        file_put_contents($path, $code);
        $r = $this->sendFile(
            $chat ?: $this->input['chat'],
            curl_file_create($path),
        );
        unlink($path);
        return $r;
    }

    public function proxy()
    {
        $proxy = trim($this->ssh("getent hosts proxy | awk '{ print $1 }'"));
        $this->createPeer("$proxy/32", 'proxy');
    }

    public function addSubnets($page = 0)
    {
        $this->createPeer(implode(',', $this->getPacConf()['subnets']), 'list');
    }

    public function change_server_ip($ip)
    {
        $conf = $this->readConfig();
        $conf['interface']['Address'] = $ip;
        $this->restartWG($this->createConfig($conf));
    }

    public function reply()
    {
        if (!empty($_SESSION['reply'][$this->input['reply']])) {
            $this->delete($this->input['chat'], $this->input['reply']);
            $this->delete($this->input['chat'], $this->input['message_id']);
            $callback = $_SESSION['reply'][$this->input['reply']]['callback'];
            $this->input['message_id'] = $this->input['callback_id'] = $_SESSION['reply'][$this->input['reply']]['start_message'];
            $this->{$callback}($this->input['message'], ...$_SESSION['reply'][$this->input['reply']]['args']);
            $this->answer($_SESSION['reply'][$this->input['reply']]['start_message']);
            unset($_SESSION['reply'][$this->input['reply']]);
        }
    }

    public function addNipdomain()
    {
        $this->addDomain(str_replace('.', '-', $this->ip) . '.nip.io');
    }

    public function addDomain($domain, $nomenu = false)
    {
        $domain = trim($domain);
        if (!empty($domain)) {
            $conf = $this->getPacConf();
            $conf['domain'] = idn_to_ascii($domain);
            $this->setPacConf($conf);
            $this->chocdomain($domain);
            $this->setUpstreamDomainOcserv($domain);
            $this->setUpstreamDomainNaive($domain);
            $this->cloakNginx();
        }
        if (empty($nomenu)) {
            sleep(3);
            $this->menu('config');
        }
    }

    public function sslip()
    {
        require __DIR__ . '/config.php';
        $p  = $this->getPacConf();
        $ip = getenv('IP');
        $r  = $this->send($c['admin'][0], "start $ip");

        $this->input['chat']        = $c['admin'][0];
        $this->input['message_id']  = $r['result']['message_id'];
        $this->input['callback_id'] = false;
        if (empty($p)) {
            $this->addDomain(str_replace('.', '-', $this->ip) . '.nip.io', 1);
            $this->setSSL('letsencrypt');
        }
        $this->menu();
    }

    public function comment($text, $tag)
    {
        $text = explode("\n", $text);
        foreach ($text as $k => $v) {
            if (preg_match("~##$tag~", $v)) {
                $text[$k] = "#-$tag";
                continue;
            }
            $text[$k] = "#$v";
        }
        return implode("\n", $text);
    }

    public function uncomment($text, $tag)
    {
        $text = explode("\n", $text);
        foreach ($text as $k => $v) {
            if (preg_match("~#-$tag~", $v)) {
                $text[$k] = "##$tag";
                continue;
            }
            $text[$k] = preg_replace('~#~', '', $v, 1);
        }
        return implode("\n", $text);
    }

    public function deleteSSL($notmenu = false)
    {
        unlink('/certs/cert_private');
        unlink('/certs/cert_public');
        $conf = $this->getPacConf();
        unset($conf['letsencrypt']);
        $this->setPacConf($conf);
        $this->adguardSync();
        $this->cloakNginx();
        if (!$notmenu) {
            $this->menu('config');
        }
    }

    public function updateUnitInitConfig()
    {
        $unit = $this->controlUnit('config');
        file_put_contents('/config/unit.json', $unit);
    }

    public function setSSL($name)
    {
        $conf = $this->getPacConf();
        switch ($name) {
            case 'letsencrypt':
                $out[] = 'Install certificate:';
                $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
                $adguardClient = $conf['adguardkey'] ? "-d {$conf['adguardkey']}.{$conf['domain']}" : '';
                $oc = $this->getHashSubdomain('oc');
                $np = $this->getHashSubdomain('np');
                exec("certbot certonly --force-renew --preferred-chain 'ISRG Root X1' -n --agree-tos --email mail@{$conf['domain']} -d {$conf['domain']}" . ($oc ? " -d $oc.{$conf['domain']}" : '') . ($np ? " -d $np.{$conf['domain']}" : '') . " $adguardClient --webroot -w /certs/ --logs-dir /logs --max-log-backups 0 2>&1", $out, $code);
                if ($code > 0) {
                    $this->send($this->input['chat'], "ERROR\n" . implode("\n", $out));
                    break;
                }
                $out[] = 'Generate bundle';
                $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
                $bundle = file_get_contents("/etc/letsencrypt/live/{$conf['domain']}/privkey.pem") . file_get_contents("/etc/letsencrypt/live/{$conf['domain']}/fullchain.pem");
                $conf['letsencrypt'] = 'letsencrypt';
                break;
            case 'self':
                $r      = $this->request('getFile', ['file_id' => $this->input['file_id']]);
                $bundle = file_get_contents($this->file . $r['result']['file_path']);
                $conf['letsencrypt'] = 'self';
                break;
        }
        if (preg_match('~[^\s]+BEGIN PRIVATE KEY.+?END PRIVATE KEY[^\s]+~s', $bundle, $m)) {
            $this->setPacConf($conf);
            file_put_contents('/certs/cert_private', $m[0]);
            file_put_contents('/certs/cert_public', preg_replace('~[^\s]+BEGIN PRIVATE KEY.+?END PRIVATE KEY[^\s]+~s', '', $bundle));
            $this->adguardSync();
            $this->cloakNginx();
            $this->restartTt();
        } else {
            $this->update($this->input['chat'], $this->input['message_id'], "wrong format key");
        }
        sleep(3);
        $this->menu('config');
    }

    public function controlUnit($url, $method = 'GET', $json = false, $bundle = false)
    {
        $ch = curl_init();
        $opt = [
            CURLOPT_CUSTOMREQUEST    => $method,
            CURLOPT_URL              => "http://localhost/$url",
            CURLOPT_RETURNTRANSFER   => 1,
            CURLOPT_UNIX_SOCKET_PATH => '/var/run/control.unit.sock',
            CURLOPT_TIMEOUT          => 10,
        ];
        if ($json) {
            $opt[CURLOPT_POSTFIELDS] = $json;
        }
        if ($bundle) {
            $opt[CURLOPT_POSTFIELDS] = ['file' => new CURLStringFile($bundle, 'bundle.pem', 'text/plain')];
        }
        curl_setopt_array($ch, $opt);
        $r = curl_exec($ch);
        curl_close($ch);
        return $r ?: 'lost connect to unit';
    }

    public function delDomain()
    {
        $this->deleteSSL(1);
        $conf = $this->getPacConf();
        unset($conf['domain']);
        $this->setPacConf($conf);
        $this->setUpstreamDomainOcserv('');
        $this->chocdomain('');
        $this->adguardSync();
        $this->cloakNginx();
        $this->menu('config');
    }

    public function addips()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} list subnets separated by commas",
            $this->input['message_id'],
            reply: 'list subnets separated by commas',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message' => $this->input['message_id'],
            'callback'      => 'createPeer',
            'args'          => ['subnet'],
        ];
    }

    public function getPacConf()
    {
        return json_decode(file_get_contents($this->pac), true);
    }

    public function setPacConf(array $conf)
    {
        return file_put_contents($this->pac, json_encode($conf, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
    }

    public function domain()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter domain",
            $this->input['message_id'],
            reply: 'enter domain',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message' => $this->input['message_id'],
            'callback'      => 'addDomain',
            'args'          => [],
        ];
    }

    public function selfssl()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} send file with your certificate chain and private key <code>cat key.pem ca.pem cert.pem</code>",
            $this->input['message_id'],
            reply: 'send file with your certificate chain and private key',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message' => $this->input['message_id'],
            'callback'      => 'selfsslInstall',
            'args'          => [],
        ];
    }

    public function adguardSync()
    {
        $pac = $this->getPacConf();
        $pac['adpswd'] = $pac['adpswd'] ?: substr(hash('md5', time()), 0, 10);
        $this->setPacConf($pac);
        $ssl = $this->nginxGetTypeCert();
        $c   = yaml_parse_file($this->adguard);
        $this->stopAd();
        $c['users'][0]['password'] = password_hash($pac['adpswd'], PASSWORD_DEFAULT);
        if (!empty($ssl) && !empty($pac['domain']) && empty($c['tls']['enabled'])) {
            $c['tls']['enabled']     = true;
            $c['tls']['server_name'] = $pac['domain'];
        }
        yaml_emit_file($this->adguard, $c);
        $this->startAd();
    }

    public function adguardpsswd()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter password",
            $this->input['message_id'],
            reply: 'enter password',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message' => $this->input['message_id'],
            'callback'      => 'chpsswd',
            'args'          => [],
        ];
    }

    public function setAdguardKey()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter key",
            $this->input['message_id'],
            reply: 'enter key',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message' => $this->input['message_id'],
            'callback'      => 'setAdKey',
            'args'          => [],
        ];
    }

    public function timerXr($k)
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter time like https://www.php.net/manual/ru/function.strtotime.php:",
            $this->input['message_id'],
            reply: 'enter time like https://www.php.net/manual/ru/function.strtotime.php:',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message' => $this->input['message_id'],
            'callback'      => 'setTimerXr',
            'args'          => [$k],
        ];
    }

    public function setAdKey($key)
    {
        $c = $this->getPacConf();
        $c['adguardkey'] = $key;
        $this->setPacConf($c);
        $this->menu('adguard');
    }

    public function enterAdmin()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter id",
            $this->input['message_id'],
            reply: 'enter id',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message' => $this->input['message_id'],
            'callback'      => 'addAdmin',
            'args'          => [],
        ];
    }

    public function addSubdomain()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter subdomain",
            $this->input['message_id'],
            reply: 'enter subdomain',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message' => $this->input['message_id'],
            'callback'      => 'setSubdomain',
            'args'          => [],
        ];
    }

    public function setIpLimit()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter seconds and count ip",
            $this->input['message_id'],
            reply: 'enter seconds:count_ip',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message' => $this->input['message_id'],
            'callback'      => 'switchIpLimit',
            'args'          => [],
        ];
    }

    public function changePort($container)
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} number port",
            $this->input['message_id'],
            reply: 'number port',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message' => $this->input['message_id'],
            'callback'      => 'setPort',
            'args'          => [$container],
        ];
    }

    public function addLinkDomain()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter domain for link",
            $this->input['message_id'],
            reply: 'enter domain for link',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message' => $this->input['message_id'],
            'callback'      => 'setLinkDomain',
            'args'          => [],
        ];
    }

    public function setLinkDomain($text)
    {
        $c = $this->getPacConf();
        if (empty($text)) {
            unset($c['linkdomain']);
        } else {
            $c['linkdomain'] = trim($text);
        }
        $this->setPacConf($c);
        $this->xray();
    }

    public function setSubdomain($text)
    {
        $c = $this->getPacConf();
        if (empty($text)) {
            unset($c['subdomain']);
        } else {
            $c['subdomain'] = array_filter(explode(',', $text), fn($e) => !empty(trim($e)));
        }
        $this->setPacConf($c);
        $this->menu('config');
    }

    public function enterPage()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter limit on page",
            $this->input['message_id'],
            reply: 'enter limit on page',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message' => $this->input['message_id'],
            'callback'      => 'setPage',
            'args'          => [],
        ];
    }

    public function setPage($text) {
        $c = $this->getPacConf();
        $c['limitpage'] = (int) $text;
        $this->setPacConf($c);
        $this->menu('config');
    }

    public function addAdmin($id)
    {
        $file = __DIR__ . '/config.php';
        require $file;
        $c['admin'][] = $id;
        file_put_contents($file, "<?php\n\n\$c = " . var_export($c, true) . ";\n");
        $this->menu('config');
    }

    public function delAdmin($id)
    {
        $file = __DIR__ . '/config.php';
        require $file;
        unset($c['admin'][array_search($id, $c['admin'])]);
        file_put_contents($file, "<?php\n\n\$c = " . var_export($c, true) . ";\n");
        $this->menu('config');
    }

    public function chpsswd($pass)
    {
        $out[] = 'Restart Adguard Home';
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
        $out[] = $this->stopAd();
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
        $c = yaml_parse_file($this->adguard);
        $c['users'][0]['password'] = password_hash($pass, PASSWORD_DEFAULT);
        yaml_emit_file($this->adguard, $c);
        $p = $this->getPacConf();
        $p['adpswd'] = $pass;
        $this->setPacConf($p);
        $out[] = $this->startAd();
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
        sleep(3);
        $this->menu('adguard');
    }

    public function adguardreset()
    {
        $out[] = 'Restart Adguard Home';
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
        exec('git -C / checkout config/AdGuardHome.yaml');
        $this->adguardSync();
        $this->cloakNginx();
        sleep(3);
        $this->menu('adguard');
    }

    public function guidv4($data = null) {
        // Generate 16 bytes (128 bits) of random data or use the data passed into the function.
        $data = $data ?? random_bytes(16);
        assert(strlen($data) == 16);

        // Set version to 0100
        $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
        // Set bits 6-7 to 10
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80);

        // Output the 36 character UUID.
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

    public function adguardXrayClients()
    {
        $xr = $this->getXray();
        $ad = yaml_parse_file($this->adguard);
        foreach ($xr['inbounds'][0]['settings']['clients'] as $k => $v) {
            $tmp[] = [
                'safe_search' => [
                    'enabled'    => true,
                    'bing'       => true,
                    'duckduckgo' => true,
                    'google'     => true,
                    'pixabay'    => true,
                    'yandex'     => true,
                    'youtube'    => true,
                ],
                'blocked_services' => [
                    'schedule' => ['time_zone' => date_default_timezone_get()],
                    'ids'      => [],
                ],
                'name'                        => $v['email'],
                'ids'                         => [$v['id']],
                'tags'                        => [],
                'upstreams'                   => [],
                'uid'                         => $v['id'],
                'upstreams_cache_size'        => 0,
                'upstreams_cache_enabled'     => false,
                'use_global_settings'         => true,
                'filtering_enabled'           => false,
                'parental_enabled'            => false,
                'safebrowsing_enabled'        => false,
                'use_global_blocked_services' => true,
                'ignore_querylog'             => false,
                'ignore_statistics'           => false,
            ];
        }
        $ad['clients']['persistent'] = $tmp;
        yaml_emit_file($this->adguard, $ad);
        $this->stopAd();
        $this->startAd();
    }

    public function checkdns()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter dns address
Plain DNS:
<code>example.org 94.140.14.14</code>
DNS-over-TLS:
<code>example.org tls://dns.adguard.com</code>
DNS-over-TLS with IP:
<code>example.org tls://dns.adguard.com 94.140.14.14</code>
DNS-over-HTTPS with HTTP/2:
<code>example.org https://dns.adguard.com/dns-query</code>
DNS-over-HTTPS forcing HTTP/3 only:
<code>example.org h3://dns.google/dns-query</code>
DNS-over-HTTPS with IP:
<code>example.org https://dns.adguard.com/dns-query 94.140.14.14</code>",
            $this->input['message_id'],
            reply: 'enter command',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message' => $this->input['message_id'],
            'callback'      => 'dnscheck',
            'args'          => [],
        ];
    }

    public function dnscheck($dns)
    {
        exec("JSON=1 dnslookup $dns", $out, $code);
        if ($code) {
            $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out), mode: false);
        } else {
            $this->send($this->input['chat'], "JSON=1 dnslookup $dns\n" . implode("\n", $out), mode: false);
        }
        sleep(3);
        $this->menu('adguard');
    }

    public function addupstream()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter address upstream",
            $this->input['message_id'],
            reply: 'enter address upstream',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message' => $this->input['message_id'],
            'callback'      => 'upstream',
            'args'          => [],
        ];
    }

    public function upstream($url)
    {
        $out[] = 'Restart Adguard Home';
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
        $out[] = $this->stopAd();
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
        $c = yaml_parse_file($this->adguard);
        $c['dns']['upstream_dns'][] = $url;
        yaml_emit_file($this->adguard, $c);
        $out[] = $this->startAd();
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
        sleep(3);
        $this->menu('adguard');
    }

    public function delupstream($k)
    {
        $out[] = 'Restart Adguard Home';
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
        $this->stopAd();
        $c = yaml_parse_file($this->adguard);
        unset($c['dns']['upstream_dns'][$k]);
        $c['dns']['upstream_dns'] = array_values($c['dns']['upstream_dns']);
        yaml_emit_file($this->adguard, $c);
        $this->startAd();
        $this->menu('adguard');
    }

    public function startAd()
    {
        return $this->ssh('/opt/adguardhome/AdGuardHome --no-check-update --pidfile /opt/adguardhome/pid -c /config/AdGuardHome.yaml -h 0.0.0.0 -w /opt/adguardhome/work', 'ad', false);
    }

    public function stopAd()
    {
        return $this->ssh('kill -15 $(cat /opt/adguardhome/pid)', 'ad');
    }

    public function selfsslInstall()
    {
        $this->setSSL('self');
    }

    public function include($type)
    {
        switch ($type) {
            case 'rulessetlist':
                $r = $this->send(
                    $this->input['chat'],
                    "@{$this->input['username']} outbound[:behavior]:time:URL",
                    $this->input['message_id'],
                    reply: 'outbound[:behavior]:time:URL',
                );
                break;

            default:
                $r = $this->send(
                    $this->input['chat'],
                    "@{$this->input['username']} list separated by commas",
                    $this->input['message_id'],
                    reply: 'list separated by commas',
                );
                break;
        }
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message' => $this->input['message_id'],
            'callback'      => 'addInclude',
            'args'          => [$type],
        ];
    }

    public function addInclude(string $domains, $type)
    {
        if ($type == 'rulessetlist' && !preg_match('~^.+:.+:https?://.+~', $domains)) {
            $this->send($this->input['from'], 'wrong pattern, enter [direct|block|proxy|custom outbound]:time:URL');
            return;
        }
        $domains = explode(',', $domains);
        $domains = array_filter($domains, fn($x) => !empty(trim($x)));
        if (!empty($domains)) {
            $conf = $this->getPacConf();
            foreach ($domains as $k => $v) {
                if (in_array($type, ['white', 'deny'])) {
                    $conf[$type][] = $v;
                } else {
                    $conf[$type][in_array($type, ['rulessetlist', 'packagelist', 'processlist']) ? trim($v) : idn_to_ascii(trim($v))] = true;
                }
            }
            ksort($conf[$type]);
            $this->setPacConf($conf);
            $page = (int) floor(array_search($v, array_keys($conf[$type])) / $this->limit);
        }
        $page = $page ?: -2;
        $this->backXtlsList($type, $page);
    }

    public function backXtlsList($type, $page = 0)
    {
        switch ($type) {
            case 'includelist':
                $this->pacUpdate($_SESSION['proxylistentry']);
                if (!empty($_SESSION['proxylistentry'])) {
                    $this->xtlsproxy($page);
                }
                break;
            case 'blocklist':
                $this->xrayUpdateRules();
                $this->xtlsblock($page);
                break;
            case 'warplist':
                $this->xrayUpdateRules();
                $this->xtlswarp($page);
                break;
            case 'processlist':
                $this->xtlsprocess($page);
                break;
            case 'packagelist':
                $this->xtlsapp($page);
                break;
            case 'subnetlist':
                $this->xtlssubnet($page);
                break;
            case 'rulessetlist':
                $this->xtlsrulesset($page);
                break;
            case 'tunprocess':
                $this->tunprocess($page);
                break;
            case 'tunpackage':
                $this->tunpackage($page);
                break;
            case 'white':
            case 'deny':
                $this->syncDeny();
                $this->denyList($page, $type == 'white' ? 1 : 0);
                break;
        }
    }

    public function xrayUpdateRules()
    {
        $c  = $this->getPacConf();
        $xr = $this->getXray();
        $xr['outbounds'] = [
            [
                "protocol" => "freedom",
                "tag"      => "direct",
            ],
            [
                "protocol" => "blackhole",
                "tag"      => "block",
            ],
            [
                "protocol" => "socks",
                "tag"      => "warp",
                "settings" => [
                    'servers' => [
                        [
                            "address" => "10.10.0.13",
                            "port"    => 1080,
                        ],
                    ],
                ],
            ],
        ];
        if (!empty($c['blocklist']) && !empty(array_filter($c['blocklist']))) {
            $domains = array_keys(array_filter($c['blocklist'], function ($v, $k){
                    if (!empty($v)) {
                        if (!preg_match('~^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$~', $k)) {
                            return true;
                        }
                    }
                    return false;
                }, ARRAY_FILTER_USE_BOTH));
            if (!empty($domains)) {
                $rules[] = [
                    "type"        => "field",
                    "outboundTag" => "block",
                    "domain"      => array_keys(array_filter($c['blocklist'], function ($v, $k){
                        if (!empty($v)) {
                            if (!preg_match('~^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$~', $k)) {
                                return true;
                            }
                        }
                        return false;
                    }, ARRAY_FILTER_USE_BOTH)),
                ];
            }
        }
        if (!empty($c['blocklist']) && !empty(array_filter($c['blocklist']))) {
            $ips = array_keys(array_filter($c['blocklist'], function ($v, $k){
                    if (!empty($v)) {
                        if (preg_match('~^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$~', $k)) {
                            return true;
                        }
                    }
                    return false;
                }, ARRAY_FILTER_USE_BOTH));
            if (!empty($ips)) {
                $rules[] = [
                    "type"        => "field",
                    "outboundTag" => "block",
                    "ip"          => array_keys(array_filter($c['blocklist'], function ($v, $k){
                        if (!empty($v)) {
                            if (preg_match('~^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$~', $k)) {
                                return true;
                            }
                        }
                        return false;
                    }, ARRAY_FILTER_USE_BOTH)),
                ];
            }
        }
        if (!empty($c['warplist']) && !empty(array_filter($c['warplist']))) {
            $domains = array_keys(array_filter($c['warplist'], function ($v, $k){
                    if (!empty($v)) {
                        if (!preg_match('~^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$~', $k)) {
                            return true;
                        }
                    }
                    return false;
                }, ARRAY_FILTER_USE_BOTH));
            if (!empty($domains)) {
                $rules[] = [
                    "type"        => "field",
                    "outboundTag" => "warp",
                    "domain"      => array_keys(array_filter($c['warplist'], function ($v, $k){
                        if (!empty($v)) {
                            if (!preg_match('~^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$~', $k)) {
                                return true;
                            }
                        }
                        return false;
                    }, ARRAY_FILTER_USE_BOTH)),
                ];
            }
        }
        if (!empty($c['warplist']) && !empty(array_filter($c['warplist']))) {
            $ips = array_keys(array_filter($c['warplist'], function ($v, $k){
                    if (!empty($v)) {
                        if (preg_match('~^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$~', $k)) {
                            return true;
                        }
                    }
                    return false;
                }, ARRAY_FILTER_USE_BOTH));
            if (!empty($ips)) {
                $rules[] = [
                    "type"        => "field",
                    "outboundTag" => "warp",
                    "ip"          => array_keys(array_filter($c['warplist'], function ($v, $k){
                        if (!empty($v)) {
                            if (preg_match('~^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$~', $k)) {
                                return true;
                            }
                        }
                        return false;
                    }, ARRAY_FILTER_USE_BOTH)),
                ];
            }
        }
        $xr['routing']['rules'] = $rules ?: [];
        $this->restartXray($xr);
    }

    public function reverse(int $count)
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} list domains separated by commas",
            $this->input['message_id'],
            reply: 'list domains separated by commas',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message' => $this->input['message_id'],
            'callback'      => 'addReverse',
            'args'          => [$count],
        ];
    }

    public function addReverse(string $domains, int $count)
    {
        $domains = explode(',', $domains);
        $domains = array_filter($domains, fn($x) => !empty(trim($x)));
        if (!empty($domains)) {
            $conf = $this->getPacConf();
            foreach ($domains as $k => $v) {
                $conf['reverselist'][idn_to_ascii(trim($v))] = true;
            }
            ksort($conf['reverselist']);
            $this->setPacConf($conf);
            $page = (int) floor(array_search($v, array_keys($conf['reverselist'])) / $count);
        }
        $page = $page ?: -2;
        $this->menu('reverselist', $page);
    }

    public function subzones(int $count)
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} list subdomains separated by commas",
            $this->input['message_id'],
            reply: 'list subdomains separated by commas',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message' => $this->input['message_id'],
            'callback'      => 'addSubzones',
            'args'          => [$count],
        ];
    }

    public function addSubzones(string $domains, int $count)
    {
        $domains = explode(',', $domains);
        $domains = array_filter($domains, fn($x) => !empty(trim($x)));
        if (!empty($domains)) {
            $conf = $this->getPacConf();
            foreach ($domains as $k => $v) {
                $conf['subzoneslist'][idn_to_ascii(trim($v))] = true;
            }
            ksort($conf['subzoneslist']);
            $this->setPacConf($conf);
            $page = (int) floor(array_search($v, array_keys($conf['subzoneslist'])) / $count);
        }
        $page = $page ?: -2;
        $this->menu('subzoneslist', $page);
    }

    public function exclude(int $count)
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter regular expression",
            $this->input['message_id'],
            reply: 'enter regular expression',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message' => $this->input['message_id'],
            'callback'      => 'addExclude',
            'args'          => [$count],
        ];
    }

    public function addExclude(string $reg, int $count)
    {
        $reg = trim($reg);
        if (!empty($reg)) {
            $conf = $this->getPacConf();
            $conf['excludelist'][$reg] = true;
            ksort($conf['excludelist']);
            $this->setPacConf($conf);
            $page = (int) floor(array_search($reg, array_keys($conf['excludelist'])) / $count);
        }
        $page = $page ?: -2;
        $this->menu('excludelist', $page);
    }

    public function addPeer()
    {
        $this->createPeer(name: 'all');
    }

    public function config()
    {
        $conf = $this->createConfig($this->readConfig());
        $data = [
            [
                [
                    'text'          => $this->i18n('back'),
                    'callback_data' => "/menu",
                ],
            ],
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            "Server config:\n\n<code>$conf</code>",
            $data,
        );
    }

    public function deletePeer($client, $page, $menu = true)
    {
        $conf = $this->readConfig();
        $this->deleteClient($client);
        unset($conf['peers'][$client]);
        $this->restartWG($this->createConfig($conf));
        if ($menu) {
            $this->menu('wg', $page);
        }
    }

    public function dnsPeer($client, $page)
    {
        $clients = $this->readClients();
        $clients[$client]['interface']['DNS'] = '10.10.0.5';
        $this->saveClients($clients);
        $this->menu('client', "{$client}_$page");
    }

    public function deletednsPeer($client, $page)
    {
        $clients = $this->readClients();
        unset($clients[$client]['interface']['DNS']);
        $this->saveClients($clients);
        $this->menu('client', "{$client}_$page");
    }

    public function pad($text, $length, $symbol = ' ')
    {
        for ($i = 0; $i < $length; $i++) {
            $text .= $symbol;
        }
        return $text;
    }

    public function getTitleWG()
    {
        $c = $this->getPacConf();
        return $this->i18n($c[$this->getInstanceWG(1) . 'amnezia'] ? 'amnezia' : 'wg_title') . ' ' . $c['wg_instance'];
    }

    public function statusWg(int $page = 0)
    {
        // Lazy auto-rotation: silently regenerates I1-I5/S3-S4 if the configured
        // period has elapsed. Must run BEFORE loading pacconf so subsequent reads
        // see the freshly rotated keys.
        $this->maybeRotateAmnezia();
        $c       = $this->getPacConf();
        $conf    = $this->readConfig();
        $status  = $this->readStatus();
        if (empty($status)) {
            return [
                'text' => "Menu -> " . $this->getTitleWG() . "\n\nerror status",
                'data' => [[
                    [
                        'text'          => $this->i18n('back'),
                        'callback_data' => "/menu",
                    ],
                ]],
            ];
        }
        $clients = $this->getClients($page);
        $bt      = $c[$this->getInstanceWG(1) . 'blocktorrent'] ?? false;
        $ex      = $c[$this->getInstanceWG(1) . 'exchange'] ?? false;
        $dns     = $c[$this->getInstanceWG(1) . 'dns'] ?? false;
        $mtu     = $c[$this->getInstanceWG(1) . 'mtu'] ?? $this->mtu;
        $am      = $c[$this->getInstanceWG(1) . 'amnezia'] ?? false;
        $end     = $c[$this->getInstanceWG(1) . 'endpoint'] ?? false;

        if (!empty($am)) {
            $ak     = $this->amneziaKeys();
            $text[] = '<code>' . implode("\n", array_map(fn($k, $v) => htmlspecialchars($k) . ': ' . htmlspecialchars($v), array_keys($ak), $ak)) . "</code>\n";
        }
        $data   = [
            [
                [
                    'text'          => $this->i18n(!$bt ? 'on' : 'off') . " {$this->i18n('torrent')} ",
                    'callback_data' => "/switchTorrent $page",
                ],
                [
                    'text'          => $this->i18n(!$ex ? 'on' : 'off') . " {$this->i18n('exchange')} ",
                    'callback_data' => "/switchExchange $page",
                ],
                [
                    'text'          =>  $this->i18n('listSubnet'),
                    'callback_data' => "/subnet $page",
                ],
            ],
            [
                [
                    'text'          =>  $this->i18n('defaultDNS') . ': ' . ($dns ?: $this->dns),
                    'callback_data' => "/defaultDNS $page",
                ],
                [
                    'text'          =>  $this->i18n('defaultMTU') . ': ' . $mtu,
                    'callback_data' => "/defaultMTU $page",
                ],
            ],
            [
                [
                    'text'          => $this->i18n('endpoint') . ': ' . ($end ? $this->ip : $this->getDomain()),
                    'callback_data' => "/switchEndpoint $page",
                ],
            ],
            [
                [
                    'text'          =>  $this->i18n('add peer'),
                    'callback_data' => "/menu addpeer $page",
                ],
            ],
        ];
        if (!empty($am)) {
            $rot_period = (int) ($c[$this->getInstanceWG(1) . 'amnezia_rotation_period'] ?? 0);
            $rot_label  = $rot_period > 0 ? "rotate: every {$rot_period}d" : "rotate: off";
            array_unshift($data, [
                [
                    'text'          => "templates",
                    'callback_data' => "/amneziaTemplates $page",
                ],
                [
                    'text'          => "set I1",
                    'callback_data' => "/setAmneziaI1 $page",
                ],
            ]);
            array_unshift($data, [
                [
                    'text'          => "rotate now",
                    'callback_data' => "/rotateAmnezia $page",
                ],
                [
                    'text'          => $rot_label,
                    'callback_data' => "/setAmneziaRotation $page",
                ],
            ]);
            array_unshift($data, [
                [
                    'text'          => "reset obf-keys",
                    'callback_data' => "/resetAmnezia $page",
                ],
                [
                    'text'          => "reduce to 1",
                    'callback_data' => "/reduceAmnezia $page",
                ],
            ]);
        }
        array_unshift($data, [
            [
                'text'          => $this->i18n($am ? 'on' : 'off') . " amnezia",
                'callback_data' => "/switchAmnezia $page",
            ],
        ]);
        if ($clients) {
            $data = array_merge($data, $clients);
        }
        if (!empty($conf['peers'])) {
            $all     = (int) ceil(count($conf['peers']) / $this->limit);
            $page    = min($page, $all - 1);
            $page    = $page == -2 ? $all - 1 : $page;
            $conf['peers'] = array_slice($conf['peers'], $page * $this->limit, $this->limit, true);
            // A peer is also "online" if its linked vless email is active right now.
            // Map peer address (AllowedIPs) -> vless email via the canonical
            // interface.Address <-> AllowedIPs link, then check the live online set.
            $onlineEmails = $this->onlineClients();
            $privEmail    = [];
            foreach (($this->getXray()['inbounds'][0]['settings']['clients'] ?? []) as $vl) {
                if (!empty($vl['awg']) && !empty($vl['email'])) {
                    $privEmail[$vl['awg']] = $vl['email'];
                }
            }
            $addrEmail = [];
            foreach ($this->readClients() as $cl) {
                $addr = $cl['interface']['Address'] ?? null;
                $priv = $cl['interface']['PrivateKey'] ?? null;
                if ($addr !== null && $priv !== null && isset($privEmail[$priv])) {
                    $addrEmail[$addr] = $privEmail[$priv];
                }
            }
            foreach ($conf['peers'] as $k => $v) {
                if (!empty($v['# PublicKey'])) {
                    $conf['peers'][$k]['online'] = 'off';
                } else {
                    $conf['peers'][$k]['status'] = $status ? $this->getStatusPeer($v['PublicKey'], $status['peers']) : 'error';
                    $conf['peers'][$k]['online'] = preg_match('~^(\d+ seconds|[12] minute)~', $conf['peers'][$k]['status']['latest handshake']) ? 'online' : '';
                }
            }
            foreach ($conf['peers'] as $k => $v) {
                if (empty($v['# PublicKey'])) {
                    preg_match_all('~([0-9.]+\.?)\s(\w+)~', $v['status']['transfer'], $m);
                    $tr = $m[0] ? ceil($m[1][1]) . '↓' . substr($m[2][1], 0, 1) . '/' . ceil($m[1][0]) . '↑' . substr($m[2][0], 0, 1) : '';
                } else {
                    $tr = '';
                }
                $vlessEmail = $addrEmail[$v['AllowedIPs'] ?? ''] ?? null;
                $vlessOn    = $vlessEmail !== null && isset($onlineEmails[$vlessEmail]);
                $circle     = $v['online'] == 'off'
                    ? '🚷'
                    : (($v['online'] === 'online' || $vlessOn) ? '🟢' : '🔴');
                $t = [
                    'name'    => $this->getName($v),
                    'time'    => $this->getTime(strtotime($v['## time'])),
                    'status'  => $circle,
                    'traffic' => $tr,
                ];
                $pad = [
                    'name'    => max(mb_strlen($t['name']), $pad['name'] ?? 0),
                    'time'    => max($t['time'] == '♾' ? 4 : mb_strlen($t['time']), $pad['time'] ?? 0),
                    'status'  => max(mb_strlen($t['status']), $pad['status'] ?? 0),
                    'traffic' => max(mb_strlen($t['traffic']), $pad['traffic'] ?? 0),
                ];
                $peers[] = $t;
            }
            foreach ($peers as $k => $v) {
                $text[] = implode('', [
                    $this->pad($v['name'], $pad['name'] - mb_strlen($v['name'])),
                    $this->pad(" {$v['time']}", $pad['time'] - mb_strlen($v['time'])),
                    $this->pad($v['status'], $pad['status'] - mb_strlen($v['status'])),
                    $this->pad(" {$v['traffic']}", $pad['traffic'] - mb_strlen($v['traffic'])),
                ]);
            }
        }
        $text = "Menu -> " . $this->getTitleWG() . "\n\n<code>" . implode(PHP_EOL, $text ?: []) . '</code>';
        $data[] = [
            [
                'text'          =>  '🔄 ' . $this->i18n('refresh'),
                'callback_data' => "/menu wg $page",
            ],
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/menu",
            ]
        ];
        return [
            'text' => $text,
            'data' => $data,
        ];
    }

    public function defaultDNS($page = 0)
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter dns separated by commas",
            $this->input['message_id'],
            reply: 'enter dns separated by commas',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'setDNS',
            'args'           => [$page],
        ];
    }

    public function defaultMTU($page = 0)
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter MTU",
            $this->input['message_id'],
            reply: 'enter MTU',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'setMTU',
            'args'           => [$page],
        ];
    }

    public function changeMTU($client, $page = 0)
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter MTU",
            $this->input['message_id'],
            reply: 'enter MTU',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'changeClientMTU',
            'args'           => [$client, $page],
        ];
    }

    public function setDNS($text, $page = 0)
    {
        $c = $this->getPacConf();
        if ($text) {
            $c[$this->getInstanceWG(1) . 'dns'] = $text;
        } else {
            unset($c[$this->getInstanceWG(1) . 'dns']);
        }
        $this->setPacConf($c);
        $this->menu('wg', $page);
    }

    public function setMTU($text, $page = 0)
    {
        $c = $this->getPacConf();
        if ($text) {
            $c[$this->getInstanceWG(1) . 'mtu'] = $text;
        } else {
            unset($c[$this->getInstanceWG(1) . 'mtu']);
        }
        $this->setPacConf($c);
        $this->menu('wg', $page);
    }

    public function changeClientMTU($text, $client, $page = 0)
    {
        $clients = $this->readClients();
        if (!empty((int) $text)) {
            $clients[$client]['interface']['MTU'] = $text;
        } else {
            unset($clients[$client]['interface']['MTU']);
        }
        $this->saveClients($clients);
        $this->menu('client', "{$client}_$page");
    }

    public function subnetAdd($wgpage, $page, $openconnect)
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter subnet separated by commas",
            $this->input['message_id'],
            reply: 'enter subnet separated by commas',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'subnetSave',
            'args'           => [$wgpage, $page, $openconnect],
        ];
    }

    public function subnetSave($text, $wgpage, $page, $openconnect)
    {
        $c = $this->getPacConf();
        $subnets = explode(',', $text);
        if ($subnets) {
            $c['subnets'] = array_merge($c['subnets'] ?: [], array_filter(array_map(fn ($e) => trim($e), $subnets)));
            $this->setPacConf($c);
            $page = floor(count($c['subnets']) / $this->limit);
        }
        if (!empty($openconnect)) {
            $this->ocservRoute();
        }
        $this->subnet($wgpage, $page, $openconnect);
    }

    public function subnetDelete($wgpage, $k, $page = 0, $openconnect = 0)
    {
        $c = $this->getPacConf();
        unset($c['subnets'][$k]);
        $this->setPacConf($c);
        if (!empty($openconnect)) {
            $this->ocservRoute();
        }
        $this->subnet($wgpage, $page, $openconnect);
    }

    public function ocservRoute()
    {
        $p = $this->getPacConf();
        $c = file_get_contents('/config/ocserv.conf');
        $t = preg_replace('~^route[^\n]+~sm', '', $c);
        if (!empty($p['subnets'])) {
            foreach ($p['subnets'] as $v) {
                if (preg_match('~^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}~', $v)) {
                    $t .= "route = $v";
                    $flag = true;
                }
            }
            if (empty($flag)) {
                $t .= 'route = default';
            }
        } else {
            $t .= 'route = default';
        }
        $this->restartOcserv($t);
    }

    public function calc()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter like '10.0.0.0/24, -10.0.0.5/32'",
            $this->input['message_id'],
            reply: 'enter like \'10.0.0.0/24, -10.0.0.5/32\'',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'calcSubnet',
            'args'           => [],
        ];
    }

    public function calcSubnet($text)
    {
        $text = explode(',', $text);
        $text = array_map(fn ($e) => trim($e), $text);
        if (!empty($text)) {
            foreach ($text as $k => $v) {
                if (preg_match('~^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}~', $v)) {
                    $include[] = $v;
                }
                if (preg_match('~^-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})~', $v, $m)) {
                    $exclude[] = $m[1];
                }
            }
        }
        if (!empty($include)) {
            foreach ($include as $k => $v) {
                $t = explode('/', $v);
                $include[$k] = [ip2long($t[0]), ip2long($t[0]) + (1 << (32 - $t[1])) - 1];
            }
            if (!empty($exclude)) {
                foreach ($exclude as $k => $v) {
                    $t = explode('/', $v);
                    $exclude[$k] = [ip2long($t[0]), ip2long($t[0]) + (1 << (32 - $t[1])) - 1];
                }
            }
            $c = new Calc();
            $r = $c->prepare($include, $exclude ?: []);
            if (!empty($r)) {
                $t = [];
                foreach ($r as $k => $v) {
                    $t = array_merge($t, $c->toCIDR($v[0], $v[1]));
                }
                $this->send($this->input['chat'], '<pre>' . implode(', ', $t) . '</pre>');
            }
        }
    }

    public function subnet($wgpage = 0, $page = 0, $openconnect = 0)
    {
        $count  = $this->limit;
        $text   = 'Menu -> ' . ($openconnect ? 'Openconnect' : 'Wireguard') . ' -> ' . $this->i18n('listSubnet') . "\n";
        $data[] = [
            [
                'text'          => $this->i18n('calc'),
                'callback_data' => "/calc",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('add'),
                'callback_data' => "/subnetAdd {$wgpage}_{$page}_$openconnect",
            ],
        ];
        $subnets = $this->getPacConf()['subnets'];
        if (!empty($subnets)) {
            $all     = (int) ceil(count($subnets) / $count);
            $page    = min($page, $all - 1);
            $page    = $page == -2 ? $all - 1 : $page;
            $subnets = $page != -1 ? array_slice($subnets, $page * $count, $count, true) : $subnets;
            foreach ($subnets as $k => $v) {
                $data[] = [
                    [
                        'text'          => $this->i18n('delete') . " $v",
                        'callback_data' => "/subnetDelete {$wgpage}_{$k}_{$page}_$openconnect",
                    ],
                ];
            }
            if ($page != -1 && $all > 1) {
                $data[] = [
                    [
                        'text'          => '<<',
                        'callback_data' => "/subnet {$wgpage}_" . ($page - 1 >= 0 ? $page - 1 : $all - 1) . ($openconnect ? '_1' : ''),
                    ],
                    [
                        'text'          => $page + 1,
                        'callback_data' => "/subnet {$wgpage}_$page" . ($openconnect ? '_1' : ''),
                    ],
                    [
                        'text'          => '>>',
                        'callback_data' => "/subnet {$wgpage}_" . ($page < $all - 1 ? $page + 1 : 0) . ($openconnect ? '_1' : ''),
                    ],
                ];
            }
        }
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => $openconnect ? '/menu oc' : "/menu wg $wgpage",
            ],
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            $text,
            $data ?: false,
        );
    }

    public function changeAllowedIps($k, $page = 0)
    {
        $clients = $this->readClients();
        $name    = $this->getName($clients[$k]['interface']);
        $text    = "Menu -> Wireguard -> $name -> Change AllowedIPs\n\n";
        $data[]  = [
            [
                'text'          =>  $this->i18n('all traffic'),
                'callback_data' => "/changeIps all_{$k}_$page",
            ]
        ];
        $data[] = [
            [
                'text'          =>  $this->i18n('subnet'),
                'callback_data' => "/changeIps subnet_{$k}_$page",
            ]
        ];
        if ($this->getPacConf()['subnets']) {
            $data[] = [
                [
                    'text'          =>  $this->i18n('listSubnet'),
                    'callback_data' => "/changeIps list_{$k}_$page",
                ]
            ];
        }
        $data[] = [
            [
                'text'          =>  $this->i18n('proxy ip'),
                'callback_data' => "/changeIps proxy_{$k}_$page",
            ]
        ];
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/menu client {$k}_$page",
            ]
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            $text,
            $data ?: false,
        );
    }

    public function changeIps($type, $k, $page = 0)
    {
        switch ($type) {
            case 'all':
                $this->setIps('0.0.0.0/0', $k, $page);
                break;
            case 'subnet':
                $r = $this->send(
                    $this->input['chat'],
                    "@{$this->input['username']} list subnets separated by commas",
                    $this->input['message_id'],
                    reply: 'list subnets separated by commas',
                );
                $_SESSION['reply'][$r['result']['message_id']] = [
                    'start_message' => $this->input['message_id'],
                    'callback'      => 'setIps',
                    'args'          => [$k, $page],
                ];
                break;
            case 'list':
                $this->setIps(implode(',', $this->getPacConf()['subnets']), $k, $page);
                break;
            case 'proxy':
                $this->setIps(trim($this->ssh("getent hosts proxy | awk '{ print $1 }'")) . '/32', $k, $page);
                break;
        }
    }

    public function setIps($ips, $k, $page = 0)
    {
        $clients = $this->readClients();
        $clients[$k]['peers'][0]['AllowedIPs'] = $ips;
        $this->saveClients($clients);
        $this->menu('client', "{$k}_$page");
    }

    public function getAmneziaShortLink($client)
    {
        $pac           = $this->getPacConf();
        $domain        = $pac[$this->getInstanceWG(1) . 'endpoint'] ? $this->ip : $this->getDomain();
        $dnsRaw        = $client['interface']['DNS'] ?: $pac[$this->getInstanceWG(1) . 'dns'] ?: $this->dns;
        $dns           = array_map('trim', explode(',', $dnsRaw));
        $ports         = $this->getPorts();
        $wgPort        = (int) $ports[$this->getInstanceWG()]['port'];
        $amneziaKeys   = $this->amneziaKeys();
        $protoVer      = array_key_exists('I1', $amneziaKeys) ? "2" : "1";
        $containerName = $protoVer === "2" ? "amnezia-awg2" : "amnezia-awg";
        $c             = [
            "containers" => [
                [
                    "awg" => [
                        "isThirdPartyConfig" => true,
                        "last_config" => json_encode(array_merge(array_map('strval', $amneziaKeys), [
                            "protocol_version" => $protoVer,
                            "client_ip"        => $client['interface']['Address'],
                            "client_priv_key"  => $client['interface']['PrivateKey'],
                            "client_pub_key"   => "0",
                            "config"           => $this->createConfig($client),
                            "hostName"         => $domain,
                            "port"             => $wgPort,
                            "psk_key"          => $client['peers'][0]['PresharedKey'],
                            "server_pub_key"   => $client['peers'][0]['PublicKey'],
                            "allowed_ips"      => array_map('trim', explode(',', $client['peers'][0]['AllowedIPs'])),
                            "persistent_keep_alive" => "25"
                        ])),
                        "port" => $wgPort,
                        "transport_proto" => "udp",
                        "protocol_version" => $protoVer
                    ],
                    "container" => $containerName
                ]
            ],
            "defaultContainer"  => $containerName,
            "description"       => $client['interface']['## name'],
            "dns1"              => $dns[0] ?? '',
            "dns2"              => $dns[1] ?? '',
            "hostName"          => $domain,
            "isThirdPartyConfig" => true
        ];
        $json = json_encode($c);
        $proc = proc_open('python amnezia.py', [0 => ['pipe', 'r'], 1 => ['pipe', 'w']], $pipes);
        fwrite($pipes[0], $json);
        fclose($pipes[0]);
        $result = trim(stream_get_contents($pipes[1]));
        fclose($pipes[1]);
        proc_close($proc);
        return $result;
    }

    public function setAsVlessTransport($k, $page)
    {
        $c = $this->getPacConf();
        $key = $this->getInstanceWG() . ':' . $k;
        if ($key == $c['awg_for_vless']) {
            unset($c['awg_for_vless']);
        } else {
            $c['awg_for_vless'] = $this->getInstanceWG(1) . ':' . $k;
        }
        $this->setPacConf($c);
        $this->menu('wg', $page);
    }

    public function getAwgVless()
    {
        $c = $this->getPacConf();
        if (empty($c['awg_for_vless'])) {
            return false;
        }
        $container = explode(':', $c['awg_for_vless'])[0] ?? '';
        $client    = explode(':', $c['awg_for_vless'])[1] ?? false;

        $clients = $this->readClients();
        if ($client === false || empty($clients[$client])) {
            return false;
        }
        return [
            "amnezia-wg-option" => $c["{$container}amnezia_keys"],
            "pre-shared-key"    => $c["{$container}presharedkey"],
            "server"            => explode(':', $clients[$client]['peers'][0]['Endpoint'])[0],
            "port"              => explode(':', $clients[$client]['peers'][0]['Endpoint'])[1],
            "ip"                => explode('/', $clients[$client]['interface']['Address'])[0],
            "private-key"       => $clients[$client]['interface']['PrivateKey'],
            "public-key"        => $clients[$client]['peers'][0]['PublicKey'],
            "mtu"               => $c["{$container}mtu"] ?? $this->mtu,
        ];

    }

    public function getClient($client, $page)
    {
        $clients = $this->readClients();
        if ($clients) {
            $name = $this->getName($clients[$client]['interface']);
            $conf = htmlspecialchars($this->createConfig($clients[$client]));
            if ($this->getWGType() == 'awg') {
                $sl = $this->getAmneziaShortLink($clients[$client]);
            }
            return [
                'text' => "<pre>$conf</pre>\n\n<code>$sl</code>\n\n<b>$name</b> ({$this->getTitleWG()})",
                'data' => [
                    [
                        [
                            'text'          =>  $this->i18n('rename'),
                            'callback_data' => "/rename {$client}_$page",
                        ],
                        [
                            'text'          =>  $this->i18n('timer'),
                            'callback_data' => "/timer {$client}_$page",
                        ],
                    ],
                    [
                        [
                            'text'          => $this->i18n('show QR'),
                            'callback_data' => "/qr $client",
                        ],
                        [
                            'text'          => $this->i18n('download config'),
                            'callback_data' => "/download $client",
                        ],
                    ],
                    [
                        [
                            'text'          => $this->i18n($clients[$client]['# off'] ? 'off' : 'on'),
                            'callback_data' => "/switchClient {$client}_$page",
                        ],
                        [
                            'text'          => $this->i18n($clients[$client]['interface']['DNS'] ? 'delete internal dns' : 'set internal dns'),
                            'callback_data' => "/" . ($clients[$client]['interface']['DNS'] ? 'delete' : '') . "dns {$client}_$page",
                        ],
                    ],
                    [
                        [
                            'text'          => $this->i18n('AllowedIPs'),
                            'callback_data' => "/changeAllowedIps {$client}_$page",
                        ],
                    ],
                    [
                        [
                            'text'          => $this->i18n('MTU') . " " . ($clients[$client]['interface']['MTU'] ?: $this->getPacConf()[$this->getInstanceWG(1) . 'mtu'] ?: $this->mtu),
                            'callback_data' => "/changeMTU {$client}_$page",
                        ],
                    ],
                    [
                        [
                            'text'          => $this->i18n('delete'),
                            'callback_data' => "/delete {$client}_$page",
                        ],
                        [
                            'text'          => $this->i18n('back'),
                            'callback_data' => "/menu wg $page",
                        ],
                    ],
                ],
            ];
        }
        return [
            'text' => "no clients",
            'data' => false
        ];
    }

    public function setVlessLink($cl, $wg, $page_wg = 0)
    {
        $c = $this->getXray();
        $w = $this->readClients();
        $privatekey = $w[$wg]['interface']['PrivateKey'];
        foreach ($c['inbounds'][0]['settings']['clients'] as $i => $j) {
            if ($i == $cl) {
                $c['inbounds'][0]['settings']['clients'][$i]['awg'] = $privatekey;
            } elseif (!empty($j['awg']) && $j['awg'] == $privatekey) {
                unset($c['inbounds'][0]['settings']['clients'][$i]['awg']);
            }
        }
        $this->restartXray($c, 1);
        $this->menu('wg', $page_wg);
    }

    public function unsetVlessLink($wg, $page_wg = 0)
    {
        $c = $this->getXray();
        $w = $this->readClients();
        $privatekey = $w[$wg]['interface']['PrivateKey'];
        foreach ($c['inbounds'][0]['settings']['clients'] as $i => $j) {
            if (!empty($j['awg']) && $j['awg'] == $privatekey) {
                unset($c['inbounds'][0]['settings']['clients'][$i]['awg']);
            }
        }
        $this->restartXray($c, 1);
        $this->menu('wg', $page_wg);
    }

    public function choiceVless($i, $page_wg = 0, $page_vl = 0)
    {
        $c = $this->getXray();

        $text[] = "Menu -> " . $this->i18n('link awg');

        $data[] = [
            [
                'text'          => $this->i18n('delete'),
                'callback_data' => "/unsetVlessLink {$i}_$page_wg",
            ],
        ];

        $clients = array_filter($c['inbounds'][0]['settings']['clients'], fn($e) => empty($e['off']));
        uasort($clients, fn($a, $b) => ($a['time'] ?: PHP_INT_MAX) <=> ($b['time'] ?: PHP_INT_MAX));

        $all     = (int) ceil(count($clients) / $this->limit);
        $page_vl = min($page_vl, $all - 1);
        $page_vl = $page_vl == -2 ? $all - 1 : $page_vl;
        $clients = $page_vl != -1 ? array_slice($clients, $page_vl * $this->limit, $this->limit, true) : $clients;
        foreach ($clients as $k => $v) {
            $data[]   = [
                [
                    'text'          => "{$v['email']}",
                    'callback_data' => "/setVlessLink {$k}_{$i}_$page_wg",
                ],
            ];
        }
        if ($page_vl != -1 && $all > 1) {
            $data[] = [
                [
                    'text'          => '<<',
                    'callback_data' => "/choiceVless {$i}_{$page_wg}_" . ($page_vl - 1 >= 0 ? $page_vl - 1 : $all - 1),
                ],
                [
                    'text'          => $page_vl + 1,
                    'callback_data' => "/choiceVless {$i}_{$page_wg}_$page_vl",
                ],
                [
                    'text'          => '>>',
                    'callback_data' => "/choiceVless {$i}_{$page_wg}_" . ($page_vl < $all - 1 ? $page_vl + 1 : 0),
                ],
            ];
        }

        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/menu wg $page_wg",
            ],
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            implode("\n", $text ?? ['...']),
            $data ?: false,
        );
    }

    public function getClients(int $page, int $count = 5)
    {
        $count   = $this->limit;
        $clients = $this->readClients();
        if (!empty($clients)) {
            $all     = (int) ceil(count($clients) / $count);
            $page    = min($page, $all - 1);
            $page    = $page == -2 ? $all - 1 : $page;
            $clients = $page != -1 ? array_slice($clients, $page * $count, $count, true) : $clients;
            $c = $this->getXray();
            foreach ($clients as $k => $v) {
                $vless = false;
                foreach ($c['inbounds'][0]['settings']['clients'] as $vl) {
                    if (!empty($vl['awg']) && $vl['awg'] == $v['interface']['PrivateKey']) {
                        $vless = $vl['email'];
                        break;
                    }
                }
                $data[] = [
                    [
                        'text'          => $this->getName($v['interface']),
                        'callback_data' => "/menu client {$k}_$page",
                    ],
                    [
                        'text'          => $this->i18n('vless') . ': ' . $this->i18n($vless != false ? 'on' : 'off') . ($vless != false ? " $vless" : ''),
                        'callback_data' => "/choiceVless {$k}_{$page}_0",
                    ],
                ];
            }
            if ($page != -1 && $all > 1) {
                $data[] = [
                    [
                        'text'          => '<<',
                        'callback_data' => "/menu wg " . ($page - 1 >= 0 ? $page - 1 : $all - 1),
                    ],
                    [
                        'text'          => $page + 1,
                        'callback_data' => "/menu wg $page",
                    ],
                    [
                        'text'          => '>>',
                        'callback_data' => "/menu wg " . ($page < $all - 1 ? $page + 1 : 0),
                    ]
                ];
            }
        }
        return $data;
    }

    public function sizeFormat($bytes)
    {
        if (floor($bytes / 1024 ** 2) > 0) {
            $r = round($bytes / 1024 ** 2, 2) . 'MB';
        } elseif (floor($bytes / 1024) > 0) {
            $r = round($bytes / 1024, 2) . 'KB';
        } else {
            $r = $bytes . 'B';
        }
        return $r;
    }

    public function addCommunityFilter()
    {
        $pac = $this->getPacConf();
        $l   = array_filter(array_map(fn($e) => trim($e), explode("\n", file_get_contents('https://community.antifilter.download/list/domains.lst'))));
        if (!empty($l)) {
            foreach ($l as $k => $v) {
                $pac['includelist'][$v] = true;
            }
        }
        $this->setPacConf($pac);
        $this->pacUpdate();
    }

    public function addLegizFilter()
    {
        $pac = $this->getPacConf();
        $l   = array_filter(array_map(fn($e) => trim($e), explode("\n", file_get_contents('https://github.com/legiz-ru/sb-rule-sets/raw/main/ru-bundle.lst'))));
        if (!empty($l)) {
            foreach ($l as $k => $v) {
                $pac['includelist'][$v] = true;
            }
        }
        $this->setPacConf($pac);
        $this->pacUpdate();
    }

    public function pacMenu($page = 0)
    {
        unset($_SESSION['proxylistentry']);
        $rmpac  = stat(__DIR__ . '/zapretlists/rmpac');
        $rpac   = stat(__DIR__ . '/zapretlists/rpac');
        $mpac   = stat(__DIR__ . '/zapretlists/mpac');
        $pac    = stat(__DIR__ . '/zapretlists/pac');
        $conf   = $this->getPacConf();
        $ip     = $this->getDomain();
        $hash   = $this->getHashBot();
        $scheme = empty($this->nginxGetTypeCert()) ? 'http' : 'https';
        $text   = <<<text
                Menu -> pac
                text;
        if ($pac) {
            $pac['time']  = date('d.m.Y H:i:s', $pac['mtime']);
            $pac['sz']    = $this->sizeFormat($pac['size']);
            $text .= <<<text


                    <b>PAC ({$pac['time']} / {$pac['sz']}):</b>
                    <code>$scheme://$ip/pac$hash?a=127.0.0.1&p=1080</code>
                    text;
            $urls[0][] = [
                'text'    => "PAC",
                'web_app' => ['url'  => "https://$ip/pac$hash&a=127.0.0.1&p=1080"],
            ];
        }
        if ($mpac) {
            $mpac['time']  = date('d.m.Y H:i:s', $mpac['mtime']);
            $mpac['sz']    = $this->sizeFormat($mpac['size']);
            $text .= <<<text


                    <b>Shadowsocks-android PAC ({$mpac['time']} / {$mpac['sz']}):</b>
                    <code>$scheme://$ip/pac$hash&t=mpac</code>
                    text;
            $urls[0][] = [
                'text'    => "PAC ShadowSocks(Android)",
                'web_app' => ['url'  => "https://$ip/pac$hash&t=mpac"],
            ];
        }
        if ($rpac) {
            $rpac['time']  = date('d.m.Y H:i:s', $rpac['mtime']);
            $rpac['sz']    = $this->sizeFormat($rpac['size']);
            $text .= <<<text


                    <b>Reverse PAC ({$rpac['time']} / {$rpac['sz']}):</b>
                    <code>$scheme://$ip/pac$hash&t=rpac&a=127.0.0.1&p=1080</code>
                    text;
            $urls[0][] = [
                'text' => "Reverse PAC",
                'url'  => "$scheme://$ip/pac$hash&t=rpac",
            ];
            $urls[1][] = [
                'text' => "Reverse PAC Wireguard proxy",
                'url'  => "$scheme://$ip/pac$hash&t=rpac&a=10.10.0.3",
            ];
        }
        if ($rmpac) {
            $rmpac['time']  = date('d.m.Y H:i:s', $rmpac['mtime']);
            $rmpac['sz']    = $this->sizeFormat($rmpac['size']);
            $text .= <<<text


                    <b>Reverse shadowsocks-android PAC ({$rmpac['time']} / {$rmpac['sz']}):</b>
                    <code>$scheme://$ip/pac$hash&t=rmpac</code>
                    text;
            $urls[2][] = [
                'text' => "Reverse PAC SS(Android)",
                'url'  => "$scheme://$ip/pac$hash&t=rmpac",
            ];
        }
        if ($urls) {
            $data = $urls;
        }
        $data[] = [
            [
                'text'          => $this->i18n('add') . ' community antifilter',
                'callback_data' => "/addCommunityFilter",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('add') . ' ru-bundle',
                'callback_data' => "/addLegizFilter",
            ],
        ];
        $data   = array_merge($data, $this->listPac('includelist', $page, 'pacMenu')[0]);
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/menu",
            ],
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            $text,
            $data ?: false,
        );
    }

    public function deleteYes($type)
    {
        $c = $this->getPacConf();
        unset($c[$type]);
        $this->setPacConf($c);
        switch ($type) {
            case 'includelist':
                $this->pacUpdate();
                break;
            case 'blocklist':
                $this->xtlsblock();
                break;
            case 'warplist':
                $this->xtlswarp();
                break;
            case 'packagelist':
                $this->xtlsapp();
                break;
            case 'processlist':
                $this->xtlsprocess();
                break;
            case 'rulessetlist':
                $this->xtlsrulesset();
                break;
        }
    }

    public function deleteAll($type)
    {
        switch ($type) {
            case 'includelist':
                $dir = 'PAC';
                break;
            case 'warplist':
                $dir = 'WARP';
                break;
            case 'blocklist':
                $dir = 'BLOCK';
                break;
            case 'packagelist':
                $dir = 'PACKAGE';
                break;
            case 'processlist':
                $dir = 'PROCESS';
                break;
            case 'subnetlist':
                $dir = 'SUBNET';
                break;
            case 'rulessetlist':
                $dir = 'rulesset';
                break;
        }
        $text   = <<<text
                Menu -> $dir -> delete all
                text;
        $data[] = [
            [
                'text'          => $this->i18n('yes'),
                'callback_data' => "/deleteYes $type",
            ],
        ];
        switch ($type) {
            case 'includelist':
                $data[] = [
                    [
                        'text'          => $this->i18n('back'),
                        'callback_data' => "/pacMenu 0",
                    ],
                ];
                break;
            case 'warplist':
                $data[] = [
                    [
                        'text'          => $this->i18n('back'),
                        'callback_data' => "/xtlswarp",
                    ],
                ];
                break;
            case 'blocklist':
                $data[] = [
                    [
                        'text'          => $this->i18n('back'),
                        'callback_data' => "/xtlsblock",
                    ],
                ];
                break;
            case 'packagelist':
                $data[] = [
                    [
                        'text'          => $this->i18n('back'),
                        'callback_data' => "/xtlsapp",
                    ],
                ];
                break;
            case 'processlist':
                $data[] = [
                    [
                        'text'          => $this->i18n('back'),
                        'callback_data' => "/xtlsprocess",
                    ],
                ];
                break;
            case 'subnetlist':
                $data[] = [
                    [
                        'text'          => $this->i18n('back'),
                        'callback_data' => "/xtlssubnet",
                    ],
                ];
                break;
            case 'rulessetlist':
                $data[] = [
                    [
                        'text'          => $this->i18n('back'),
                        'callback_data' => "/xtlsrulesset",
                    ],
                ];
                break;
        }
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            $text,
            $data ?: false,
        );
    }

    public function exportList($type)
    {
        $domains = $this->getPacConf()[$type];
        if (!empty($domains)) {
            foreach ($domains as $k => $v) {
                $text .= "$k;$v\n";
            }
            $this->sendFile(
                $this->input['chat'],
                new CURLStringFile($text, "$type.csv", 'application/csv'),
                to: $this->input['message_id'],
            );
        }
    }

    public function tunpackagemode()
    {
        $c = $this->getPacConf();
        $c['tunpackagemode'] = $c['tunpackagemode'] ? 0 : 1;
        $this->setPacConf($c);
        $this->tun();
    }

    public function tunprocessmode()
    {
        $c = $this->getPacConf();
        $c['tunprocessmode'] = $c['tunprocessmode'] ? 0 : 1;
        $this->setPacConf($c);
        $this->tun();
    }

    public function tunpackage($page = 0)
    {
        $text[] = "Menu -> " . $this->i18n('xray') . ' -> ' . $this->i18n('routes') . ' -> ' . $this->i18n('package');

        [$data] = $this->listPac('tunpackage', $page, 'tunpackage');
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/tun",
            ],
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            implode("\n", $text ?: ['...']),
            $data ?: false,
        );
    }

    public function tunprocess($page = 0)
    {
        $text[] = "Menu -> " . $this->i18n('xray') . ' -> ' . $this->i18n('routes') . ' -> ' . $this->i18n('process');

        [$data] = $this->listPac('tunprocess', $page, 'tunprocess');
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/tun",
            ],
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            implode("\n", $text ?: ['...']),
            $data ?: false,
        );
    }

    public function xtlsblock($page = 0)
    {
        $text[] = "Menu -> " . $this->i18n('xray') . ' -> ' . $this->i18n('routes') . ' -> block list';

        [$data] = $this->listPac('blocklist', $page, 'xtlsblock');
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/routes",
            ],
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            implode("\n", $text ?: ['...']),
            $data ?: false,
        );
    }

    public function xtlswarp($page = 0)
    {
        $text[] = "Menu -> " . $this->i18n('xray') . ' -> ' . $this->i18n('routes') . ' -> warp list';

        [$data] = $this->listPac('warplist', $page, 'xtlswarp');
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/routes",
            ],
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            implode("\n", $text ?: ['...']),
            $data ?: false,
        );
    }

    public function xtlsproxy($page = 0)
    {
        $_SESSION['proxylistentry'] = 1;
        $p = $this->getPacConf();
        $text[] = "Menu -> " . $this->i18n('xray') . ' -> ' . $this->i18n('routes') . ' -> proxy list';
        [$data] = $this->listPac('includelist', $page, 'xtlsproxy');
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/routes",
            ],
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            implode("\n", $text ?: ['...']),
            $data ?: false,
        );
    }

    public function appOutbound()
    {
        $p = $this->getPacConf();
        $p['app_outbound'] = !$p['app_outbound'];
        $p = $this->setPacConf($p);
        $this->xtlsapp();
    }

    public function domainsOutbound()
    {
        $p = $this->getPacConf();
        $p['domains_outbound'] = !$p['domains_outbound'];
        $p = $this->setPacConf($p);
        $this->xtlsproxy();
    }

    public function finalOutbound()
    {
        $p = $this->getPacConf();
        $p['final_outbound'] = !$p['final_outbound'];
        $p = $this->setPacConf($p);
        $this->routes();
    }

    public function processOutbound()
    {
        $p = $this->getPacConf();
        $p['process_outbound'] = !$p['process_outbound'];
        $p = $this->setPacConf($p);
        $this->xtlsprocess();
    }

    public function xtlsapp($page = 0)
    {
        $text[] = "Menu -> " . $this->i18n('xray') . ' -> ' . $this->i18n('routes') . ' -> package list';

        [$data] = $this->listPac('packagelist', $page, 'xtlsapp');
        $p      = $this->getPacConf();
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/routes",
            ],
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            implode("\n", $text ?: ['...']),
            $data ?: false,
        );
    }

    public function xtlsprocess($page = 0)
    {
        $text[] = "Menu -> " . $this->i18n('xray') . ' -> ' . $this->i18n('routes') . ' -> process list';

        [$data] = $this->listPac('processlist', $page, 'xtlsprocess');
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/routes",
            ],
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            implode("\n", $text ?: ['...']),
            $data ?: false,
        );
    }

    public function xtlssubnet($page = 0)
    {
        $text[] = "Menu -> " . $this->i18n('xray') . ' -> ' . $this->i18n('routes') . ' -> subnet';

        [$data] = $this->listPac('subnetlist', $page, 'xtlssubnet');
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/routes",
            ],
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            implode("\n", $text ?: ['...']),
            $data ?: false,
        );
    }

    public function xtlsrulesset($page = 0)
    {
        $text[] = "Menu -> " . $this->i18n('xray') . ' -> ' . $this->i18n('routes') . ' -> rulesset list';

        [$data, $tmp] = $this->listPac('rulessetlist', $page, 'xtlsrulesset', 1);
        $text = array_merge($text, $tmp ?: []);
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/routes",
            ],
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            implode("\n", $text ?: ['...']),
            $data ?: false,
        );
    }

    public function listPac($type, $page, $menu, $basename = false)
    {
        $data[] = [
            [
                'text'          => $this->i18n('add'),
                'callback_data' => "/include $type",
            ],
        ];
        $domains = $this->getPacConf()[$type];
        if (!empty($domains)) {
            $all     = (int) ceil(count($domains) / $this->limit);
            $page    = min($page, $all - 1);
            $page    = $page < 0 ? $all - 1 : $page;
            $domains = array_slice($domains, $page * $this->limit, $this->limit, true);
            $i = 0;
            foreach ($domains as $k => $v) {
                if ($type == 'rulessetlist') {
                    $text[] = "<blockquote><code>$k</code></blockquote>";
                }
                $data[] = [
                    [
                        'text'          => $this->i18n($v ? 'on' : 'off') . ' ' . ($basename ? basename($k) . ' ' : '') . (in_array($type, ['rulessetlist', 'packagelist', 'processlist', 'subnetlist']) ? $k : idn_to_utf8($k)),
                        'callback_data' => "/change$type " . ($i + $page * $this->limit) . " $page",
                    ],
                    [
                        'text'          => 'delete',
                        'callback_data' => "/delete$type " . ($i + $page * $this->limit) . " $page",
                    ],
                ];
                $i++;
            }
            if ($all > 1) {
                $data[] = [
                    [
                        'text'          => '<<',
                        'callback_data' => "/$menu " . ($page - 1 >= 0 ? $page - 1 : $all - 1),
                    ],
                    [
                        'text'          => $page + 1,
                        'callback_data' => "/$menu $page",
                    ],
                    [
                        'text'          => '>>',
                        'callback_data' => "/$menu " . ($page < $all - 1 ? $page + 1 : 0),
                    ],
                ];
            }
            $data[] = [
                [
                    'text'          => $this->i18n('delete all'),
                    'callback_data' => "/deleteAll $type",
                ],
                [
                    'text'          => $this->i18n('export'),
                    'callback_data' => "/exportList $type",
                ],
                [
                    'text'          => $this->i18n('import'),
                    'callback_data' => "/importList $type",
                ],
            ];
        } else {
            $data[] = [
                [
                    'text'          => $this->i18n('import'),
                    'callback_data' => "/importList $type",
                ],
            ];
        }
        return [$data, $text];
    }

    public function listPacChange($type, $action, $key, $page = 0)
    {
        $conf = $this->getPacConf();
        $i = 0;
        foreach ($conf[$type] as $k => $v) {
            if ($key == $i) {
                switch ($action) {
                    case 'change':
                        $conf[$type][$k] = !$v;
                        break;
                    case 'delete':
                        unset($conf[$type][$k]);
                        break;
                }
                break;
            }
            $i++;
        }
        $this->setPacConf($conf);
        $this->backXtlsList($type, $page);
    }

    public function pacZapret()
    {
        $conf = $this->getPacConf();
        $conf['zapret'] = !$conf['zapret'];
        $this->setPacConf($conf);
        $this->menu('pac');
    }

    public function pacUpdate($import = '')
    {
        exec("php updatepac.php start {$this->input['chat']} {$this->input['message_id']} {$this->input['callback_id']} $import > /dev/null &");
    }

    public function getSSConfig()
    {
        return json_decode(file_get_contents('/config/ssserver.json'), true);
    }

    public function getSSLocalConfig()
    {
        return json_decode(file_get_contents('/config/sslocal.json'), true);
    }

    public function menuSS()
    {
        $hash    = $this->getHashBot();
        $domain  = $this->getDomain();
        $ss      = $this->getSSConfig();
        $p       = $this->getPorts();
        $v2ray   = !empty($ss['plugin']) ? 'ON' : 'OFF';

        $ck       = $this->getCloakConfig();
        $cloakOn  = !empty($ck['Enabled']);
        $ckPort   = (int) (getenv('CKPORT') ?: 8443);
        $ckSrv    = $ck['ServerName'] ?? ($ck['RedirAddr'] ?? 'www.bing.com');

        $st       = $this->getStlsConfig();
        $stlsOn   = !empty($st['Enabled']);
        $stPort   = (int) (getenv('STLSPORT') ?: 3443);
        $stSrv    = $st['ServerName'] ?? $domain;

        // Порт для display: тот же приоритет, что в buildSSLink
        // (cloak > simple-tls > v2ray > plain).
        if ($cloakOn) {
            $port = $ckPort;
        } elseif ($stlsOn) {
            $port = $stPort;
        } elseif (!empty($ss['plugin'])) {
            $port = 443;
        } else {
            $port = $p['ss']['port'];
        }
        $options = !empty($ss['plugin']) ? "tls;fast-open;path=/v2ray$hash;host=$domain" : "path=/v2ray$hash;host=$domain";

        $text = "Menu -> ShadowSocks";
        $data[] = [
            [
                'text'          => $this->i18n('change password'),
                'callback_data' => "/sspswd",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('generate password'),
                'callback_data' => "/ssGenPswd",
            ],
        ];
        $ss_link = $this->buildSSLink($hash);
        $text .= "\n\n<code>$ss_link</code>\n";
        $text .= "\n\npassword: <span class='tg-spoiler'>{$ss['password']}</span>";
        $text .= "\n\nserver: <code>$domain:$port</code>";
        $text .= "\n\nmethod: <code>{$ss['method']}</code>";
        $text .= "\n\nnameserver: <code>10.10.0.5</code>";
        if ($ss['plugin']) {
            $text .= "\n\nplugin: <code>v2ray-plugin</code>";
            $text .= "\n\nv2ray options: <code>$options</code>";
        }
        if ($cloakOn) {
            $text .= "\n\nplugin: <code>cloak (ck-client)</code>";
            $text .= "\n\ncloak masq: <code>$ckSrv</code>";
            $text .= "\n\ncloak UID: <span class='tg-spoiler'>" . ($ck['UID'] ?? '') . "</span>";
            $text .= "\n\ncloak pubkey: <span class='tg-spoiler'>" . ($ck['PublicKey'] ?? '') . "</span>";
            $text .= "\n\ncloak method: <code>" . ($ck['EncryptionMethod'] ?? 'aes-256-gcm') . "</code>";
        }
        if ($stlsOn) {
            $text .= "\n\nplugin: <code>simple-tls</code>";
            $text .= "\n\nstls SNI: <code>$stSrv</code>";
            $text .= "\n\nstls port: <code>$stPort</code>";
        }
        $data[] = [
            [
                'text'          => "v2ray: $v2ray",
                'callback_data' => "/v2ray",
            ],
        ];
        $data[] = [
            [
                'text'          => 'cloak: ' . ($cloakOn ? 'ON' : 'OFF'),
                'callback_data' => "/cloak",
            ],
        ];
        if ($cloakOn) {
            $data[] = [
                [
                    'text'          => $this->i18n('cloak port:') . " $ckPort",
                    'callback_data' => "/cloakPort",
                ],
                [
                    'text'          => $this->i18n('cloak masq:') . " $ckSrv",
                    'callback_data' => "/cloakDomain",
                ],
            ];
            $data[] = [
                [
                    'text'          => $this->i18n('cloak method:') . ' ' . ($ck['EncryptionMethod'] ?? 'aes-256-gcm'),
                    'callback_data' => "/cloakMethod",
                ],
            ];
            $data[] = [
                [
                    'text'          => $this->i18n('regen cloak keys'),
                    'callback_data' => "/cloakRegen",
                ],
            ];
            $ckUserCount = count($this->getCloakUsers());
            $data[] = [
                [
                    'text'          => $this->i18n('cloak users') . " ($ckUserCount)",
                    'callback_data' => "/ckUsers",
                ],
            ];
        }
        $data[] = [
            [
                'text'          => 'simple-tls: ' . ($stlsOn ? 'ON' : 'OFF'),
                'callback_data' => "/simpleTls",
            ],
        ];
        if ($stlsOn) {
            $data[] = [
                [
                    'text'          => $this->i18n('stls port:') . " $stPort",
                    'callback_data' => "/stlsPort",
                ],
                [
                    'text'          => $this->i18n('stls SNI:') . " $stSrv",
                    'callback_data' => "/stlsSNI",
                ],
            ];
        }
        $data[] = [
            [
                'text'          => $this->i18n('show QR'),
                'callback_data' => "/qrSS",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/menu",
            ],
        ];
        return [
            'text' => $text,
            'data' => $data,
        ];
    }

    public function i18n(string $menu): string
    {
        return $this->i18n[$menu][$this->language] ?: $menu;
    }

    public function changeWG($i)
    {
        $c = $this->getPacConf();
        $c['wg_instance'] = $i;
        $this->setPacConf($c);
        $this->menu('wg', 0);
    }

    public function alignColumns(array $columns): string
    {
        // Находим максимальную длину для каждого столбца
        $columnLengths = [];
        foreach ($columns as $column) {
            $maxLength = 0;
            foreach ($column as $cell) {
                $len = mb_strlen($cell, 'UTF-8');
                $maxLength = max($maxLength, $len);
            }
            $columnLengths[] = $maxLength;
        }

        // Получаем количество строк из первого столбца
        $rowCount = count($columns[0]);
        $columnCount = count($columns);

        // Формируем строки с выравниванием
        $result = [];
        for ($row = 0; $row < $rowCount; $row++) {
            $line = '';
            for ($col = 0; $col < $columnCount; $col++) {
                $cell = $columns[$col][$row];
                $padding = str_repeat(' ', $columnLengths[$col] - mb_strlen($cell, 'UTF-8'));
                $line .= $cell . $padding;

                // Добавляем разделитель между столбцами, кроме последнего
                if ($col < $columnCount - 1) {
                    $line .= '  '; // Два пробела между столбцами
                }
            }
            $result[] = $line;
        }

        return implode("\n", $result);
    }

    public function dnsttDomain()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter domain",
            $this->input['message_id'],
            reply: 'enter domain',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message' => $this->input['message_id'],
            'callback'      => 'setdnsttDomain',
            'args'          => [],
        ];
    }

    public function dnsttPassword()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter password",
            $this->input['message_id'],
            reply: 'enter password',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message' => $this->input['message_id'],
            'callback'      => 'setdnsttPassword',
            'args'          => [],
        ];
    }

    public function setdnsttPassword($text)
    {
        $c = $this->getPacConf();
        if ($text) {
            $c['dnsttPassword'] = $text;
        } else {
            unset($c['dnsttPassword']);
        }
        $this->setPacConf($c);
        $this->dnsttStart();
        $this->dnstt();
    }

    public function setdnsttDomain($text)
    {
        $c = $this->getPacConf();
        if ($text) {
            $c['dnsttDomain'] = $text;
        } else {
            unset($c['dnsttDomain']);
        }
        $this->setPacConf($c);
        $this->dnsttStart();
        $this->dnstt();
    }

    public function telemt($update = false)
    {
        [$conf, $changed] = $this->normalizeTelemtUsers($this->getPacConf());
        if ($changed) {
            $this->setPacConf($conf);
            $this->restartTelemt();
        }
        $ports  = $this->getPorts()['telemt'];
        $domain = $conf['telemt_domain'] ?? 'www.google.com';
        $users  = $conf['telemt_users'] ?? [];
        $masking = $this->telemtBool($conf, 'telemt_mask_hardening', $this->telemtMaskDefault('telemt_mask_hardening'))
            || $this->telemtBool($conf, 'telemt_mask_aggressive', $this->telemtMaskDefault('telemt_mask_aggressive'))
            || $this->telemtBool($conf, 'telemt_mask_blur', $this->telemtMaskDefault('telemt_mask_blur'))
            || $this->telemtBool($conf, 'telemt_mask_timing', $this->telemtMaskDefault('telemt_mask_timing'));
        $diagnostics = $this->telemtBool($conf, 'telemt_beobachten', false);
        $st     = $this->ssh('pgrep -x telemt', 'telemt') ? 'on' : 'off';

        $text[] = "Menu -> TeleMT (MTProto)\n";
        $text[] = "status: $st";
        $text[] = "port: " . ($ports['enable'] ? $ports['port'] : $this->i18n('port unavailable'));
        $text[] = "fake-TLS domain: <code>" . htmlspecialchars($domain, ENT_QUOTES) . "</code>";
        $text[] = "fast mode: " . $this->i18n('on');
        $text[] = "masking: " . $this->telemtState($masking);
        $text[] = "diagnostics: " . $this->telemtState($diagnostics);
        $text[] = "users: " . count($users);
        if (!$ports['enable']) {
            $text[] = "\n⚠ " . $this->i18n('telemt set port hint');
        }

        $data[] = [['text' => $this->i18n('telemt users'), 'callback_data' => "/telemtUsers"]];
        $data[] = [['text' => $this->i18n('telemt settings'), 'callback_data' => "/telemtSettings"]];
        $data[] = [['text' => $this->i18n('telemt masking'), 'callback_data' => "/telemtMasking"]];
        $data[] = [['text' => $this->i18n('telemt diagnostics'), 'callback_data' => "/telemtDiagnostics"]];
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => "/menu"]];

        if ($update) {
            $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $text), $data);
        } else {
            $this->send($this->input['chat'], implode("\n", $text), $this->input['message_id'], $data);
        }
    }

    public function telemtUsers()
    {
        $conf = $this->getPacConf();
        $users = is_array($conf['telemt_users'] ?? null) ? $conf['telemt_users'] : [];
        $enabled = is_array($conf['telemt_user_enabled'] ?? null) ? $conf['telemt_user_enabled'] : [];

        $text[] = "Menu -> TeleMT -> " . $this->i18n('telemt users') . "\n";
        $text[] = "users: " . count($users);
        if ($users) {
            $text[] = '';
            foreach ($users as $name => $secret) {
                $safeName = htmlspecialchars((string) $name, ENT_QUOTES);
                $state = array_key_exists($name, $enabled) && empty($enabled[$name]) ? 'off' : 'on';
                $text[] = "👤 <b>$safeName</b> " . $this->i18n($state);
                $text[] = htmlspecialchars($this->linkTelemt($name), ENT_QUOTES);
            }
        }

        foreach ($users as $name => $secret) {
            $link = $this->linkTelemt($name);
            $state = array_key_exists($name, $enabled) && empty($enabled[$name]) ? 'off' : 'on';
            $data[] = [
                ['text' => "🔗 $name", 'url' => $link],
                ['text' => $this->i18n($state), 'callback_data' => "/telemtToggleUser $name"],
                ['text' => '📷', 'callback_data' => "/telemtQr $name"],
                ['text' => '🔄', 'callback_data' => "/telemtRegen $name"],
                ['text' => '❌', 'callback_data' => "/telemtDelUser $name"],
            ];
        }
        $data[] = [['text' => $this->i18n('telemt add user'), 'callback_data' => "/telemtAddUser"]];
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => "/telemt"]];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $text), $data);
    }

    public function telemtSettings()
    {
        $conf = $this->getPacConf();
        $domain = $conf['telemt_domain'] ?? 'www.google.com';
        $ports = $this->getPorts()['telemt'];

        $text[] = "Menu -> TeleMT -> " . $this->i18n('telemt settings') . "\n";
        $text[] = "port: " . ($ports['enable'] ? $ports['port'] : $this->i18n('port unavailable'));
        $text[] = "fake-TLS domain: <code>" . htmlspecialchars($domain, ENT_QUOTES) . "</code>";
        $text[] = "fast mode: " . $this->i18n('on');

        $data[] = [['text' => $this->i18n('changeFakeDomain'), 'callback_data' => "/telemtDomain"]];
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => "/telemt"]];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $text), $data);
    }

    public function telemtMasking()
    {
        $conf = $this->getPacConf();
        $items = [
            'telemt_mask_hardening' => 'shape hardening',
            'telemt_mask_aggressive' => 'aggressive hardening',
            'telemt_mask_blur' => 'above-cap blur',
            'telemt_mask_timing' => 'timing normalization',
        ];

        $text[] = "Menu -> TeleMT -> " . $this->i18n('telemt masking') . "\n";
        foreach ($items as $key => $title) {
            $state = $this->telemtBool($conf, $key, $this->telemtMaskDefault($key));
            $text[] = "$title: " . $this->telemtState($state);
            $data[] = [[
                'text' => "$title: " . $this->telemtState($state),
                'callback_data' => "/telemtToggle $key masking",
            ]];
        }
        // Эти 4 опции усиливают только anti-probe cover-path и не влияют на
        // трафик реальных клиентов; реализм клиентского хендшейка (session
        // tickets / полный ServerHello / ALPN-echo) включён всегда.
        $text[] = "\nℹ " . $this->i18n('telemt masking note');
        $text[] = $this->i18n('telemt realism');
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => "/telemt"]];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $text), $data);
    }

    public function telemtDiagnostics()
    {
        $conf = $this->getPacConf();
        $enabled = $this->telemtBool($conf, 'telemt_beobachten', false);
        $minutes = $this->telemtInt($conf, 'telemt_beobachten_minutes', 10, 1, 1440);

        $st      = $this->ssh('pgrep -x telemt', 'telemt') ? 'on' : 'off';
        $bfile   = '/config/telemt/data/beobachten.txt';
        $btxt    = is_file($bfile) ? trim((string) file_get_contents($bfile)) : '';
        $bcount  = $btxt === '' ? 0 : count(preg_split('~\R~', $btxt));

        $text[] = "Menu -> TeleMT -> " . $this->i18n('telemt diagnostics') . "\n";
        $text[] = "service: $st";
        $text[] = "beobachten: " . $this->telemtState($enabled);
        $text[] = "retention: $minutes min";
        $text[] = "JA3/JA4 observed: " . ($enabled ? "$bcount line(s)" : 'off');
        $text[] = "loopback API (127.0.0.1): " . $this->telemtState($enabled);
        if ($enabled) {
            $text[] = "\n📊 " . $this->i18n('telemt report') . " — health · traffic · users · masking · security";
        }

        $data[] = [[
            'text' => 'beobachten: ' . $this->telemtState($enabled),
            'callback_data' => "/telemtToggle telemt_beobachten diagnostics",
        ]];
        $data[] = [[
            'text' => "retention: $minutes min",
            'callback_data' => "/telemtCycleBeobachtenMinutes",
        ]];
        if ($enabled) {
            $data[] = [['text' => $this->i18n('telemt report'), 'callback_data' => "/telemtReport"]];
        }
        $data[] = [['text' => $this->i18n('telemt observe'), 'callback_data' => "/telemtShowBeobachten"]];
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => "/telemt"]];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $text), $data);
    }

    public function telemtToggle($key, $return)
    {
        $allowed = [
            'telemt_beobachten' => true,
            'telemt_mask_hardening' => true,
            'telemt_mask_aggressive' => true,
            'telemt_mask_blur' => true,
            'telemt_mask_timing' => true,
        ];
        if (empty($allowed[$key])) {
            return $this->telemt(true);
        }
        $conf = $this->getPacConf();
        $new = $this->telemtBool($conf, $key, $this->telemtMaskDefault($key)) ? 0 : 1;
        $conf[$key] = $new;
        if ($new && in_array($key, ['telemt_mask_aggressive', 'telemt_mask_blur'], true)) {
            $conf['telemt_mask_hardening'] = 1;
        }
        if (!$new && $key === 'telemt_mask_hardening') {
            $conf['telemt_mask_aggressive'] = 0;
            $conf['telemt_mask_blur'] = 0;
        }
        $this->setPacConf($conf);
        $this->restartTelemt();
        return $return === 'diagnostics' ? $this->telemtDiagnostics() : $this->telemtMasking();
    }

    public function telemtCycleBeobachtenMinutes()
    {
        $conf = $this->getPacConf();
        $values = [5, 10, 30, 60, 180, 360, 720, 1440];
        $current = $this->telemtInt($conf, 'telemt_beobachten_minutes', 10, 1, 1440);
        $i = array_search($current, $values, true);
        $conf['telemt_beobachten_minutes'] = $values[$i === false || $i === count($values) - 1 ? 0 : $i + 1];
        $this->setPacConf($conf);
        $this->restartTelemt();
        $this->telemtDiagnostics();
    }

    public function telemtToggleUser($name)
    {
        $conf = $this->getPacConf();
        if (empty($conf['telemt_users'][$name])) {
            return $this->telemtUsers();
        }
        if (!is_array($conf['telemt_user_enabled'] ?? null)) {
            $conf['telemt_user_enabled'] = [];
        }
        $cur = array_key_exists($name, $conf['telemt_user_enabled']) ? !empty($conf['telemt_user_enabled'][$name]) : true;
        $conf['telemt_user_enabled'][$name] = $cur ? 0 : 1;
        $this->setPacConf($conf);
        $this->restartTelemt();
        $this->telemtUsers();
    }

    public function telemtShowBeobachten()
    {
        if (!$this->telemtBool($this->getPacConf(), 'telemt_beobachten', false)) {
            $this->answer($this->input['callback_id'], 'beobachten off', true);
            return $this->telemtDiagnostics();
        }
        // beobachten ведёт журнал JA3/JA4 в файл (telemtToml: beobachten_file).
        // /telemt/data в контейнере telemt = /config/telemt/data в php-контейнере.
        $file = '/config/telemt/data/beobachten.txt';
        $out  = is_file($file) ? trim((string) file_get_contents($file)) : '';
        if ($out === '') {
            $out = 'no beobachten data yet';
        } else {
            // хвост, чтобы уложиться в лимит сообщения Telegram
            $out = ltrim(substr($out, -3500));
        }
        $this->send($this->input['chat'], "<pre>" . htmlspecialchars($out, ENT_QUOTES) . "</pre>", $this->input['message_id']);
    }

    // Один ssh-заход в контейнер telemt: дёргаем перечисленные /v1/* эндпоинты
    // управляющего API на 127.0.0.1:9091. API слушает только loopback внутри
    // контейнера и наружу не публикуется; включён лишь при beobachten = on.
    // Возвращаем path => распакованный envelope.data (или null при ошибке).
    public function telemtApiFetch(array $paths): array
    {
        $cmd = '';
        foreach ($paths as $p) {
            $url  = 'http://127.0.0.1:9091' . $p;
            $cmd .= "printf '@@@%s@@@\\n' " . escapeshellarg($p) . "; "
                  . "wget -qO- -T 3 " . escapeshellarg($url) . " 2>/dev/null; "
                  . "printf '\\n'; ";
        }
        $raw    = (string) $this->ssh($cmd, 'telemt');
        $result = array_fill_keys($paths, null);
        // Режем вывод по маркерам @@@/v1/...@@@ и декодируем тело каждого.
        $parts = preg_split('~@@@(/v1/[^@]+)@@@\n~', $raw, -1, PREG_SPLIT_DELIM_CAPTURE);
        for ($i = 1; $i + 1 < count($parts); $i += 2) {
            $body = trim($parts[$i + 1]);
            if ($body === '') {
                continue;
            }
            $j = json_decode($body, true);
            if (is_array($j) && !empty($j['ok']) && array_key_exists('data', $j)) {
                $result[$parts[$i]] = $j['data'];
            }
        }
        return $result;
    }

    public function telemtReport()
    {
        $conf = $this->getPacConf();
        if (!$this->telemtBool($conf, 'telemt_beobachten', false)) {
            $this->answer($this->input['callback_id'], 'beobachten off', true);
            return $this->telemtDiagnostics();
        }
        $api = $this->telemtApiFetch([
            '/v1/health', '/v1/health/ready', '/v1/system/info',
            '/v1/stats/summary', '/v1/stats/users', '/v1/security/posture',
        ]);
        $h     = $api['/v1/health'] ?? [];
        $ready = $api['/v1/health/ready'] ?? [];
        $info  = $api['/v1/system/info'] ?? [];
        $sum   = $api['/v1/stats/summary'] ?? [];
        $users = $api['/v1/stats/users'] ?? null;
        $sec   = $api['/v1/security/posture'] ?? [];

        $uptime = function ($s) {
            $s = (int) $s;
            $d = intdiv($s, 86400);
            $s %= 86400;
            return ($d ? "{$d}d " : '') . sprintf('%02d:%02d', intdiv($s, 3600), intdiv($s % 3600, 60));
        };
        $yn = fn($v) => !empty($v) ? '✓' : '✗';

        $L   = ["TeleMT diagnostics"];

        // ── Состояние ──
        $L[] = "\n▌ Health / build";
        if ($h || $ready || $info) {
            $L[] = "live: " . (($h['status'] ?? '') === 'ok' ? '✓ ok' : '✗ ' . ($h['status'] ?? 'n/a'));
            if ($ready) {
                $rl = !empty($ready['ready']) ? '✓ ready' : '✗ ' . ($ready['status'] ?? 'not_ready');
                if (!empty($ready['reason'])) {
                    $rl .= " ({$ready['reason']})";
                }
                $L[] = "ready: $rl";
                $L[] = "upstreams: " . ($ready['healthy_upstreams'] ?? '?') . "/" . ($ready['total_upstreams'] ?? '?') . " healthy";
            }
            if ($info) {
                $L[] = "version: " . ($info['version'] ?? '?') . " (" . ($info['target_arch'] ?? '?') . "/" . ($info['target_os'] ?? '?') . ")";
                $L[] = "uptime: " . $uptime($info['uptime_seconds'] ?? 0);
                $hash = (string) ($info['config_hash'] ?? '');
                $L[] = "config: " . ($hash !== '' ? substr($hash, 0, 12) : '?') . ", reloads: " . ($info['config_reload_count'] ?? 0);
            }
        } else {
            $L[] = "API unreachable — beobachten just enabled? retry in a few seconds";
        }

        // ── Трафик ──
        if ($sum) {
            $L[] = "\n▌ Traffic (since start)";
            $L[] = "connections: " . ($sum['connections_total'] ?? 0) . " (bad " . ($sum['connections_bad_total'] ?? 0) . ")";
            $L[] = "handshake timeouts: " . ($sum['handshake_timeouts_total'] ?? 0);
            foreach (['connections_bad_by_class' => 'bad', 'handshake_failures_by_class' => 'hs-fail'] as $k => $lbl) {
                if (!empty($sum[$k]) && is_array($sum[$k])) {
                    $cl = [];
                    foreach (array_slice($sum[$k], 0, 6) as $c) {
                        $cl[] = ($c['class'] ?? '?') . '=' . ($c['total'] ?? 0);
                    }
                    if ($cl) {
                        $L[] = "$lbl: " . implode(', ', $cl);
                    }
                }
            }
        }

        // ── Пользователи ──
        $L[] = "\n▌ Users";
        if (is_array($users)) {
            $names = [];
            foreach ($users as $u) {
                $names[] = is_array($u) ? (string) ($u['username'] ?? $u['name'] ?? '?') : (string) $u;
            }
            $L[] = "active views: " . count($users)
                . (isset($sum['configured_users']) ? " (configured " . $sum['configured_users'] . ")" : '');
            if ($names) {
                $L[] = implode(', ', array_slice($names, 0, 20)) . (count($names) > 20 ? ' …' : '');
            }
        } else {
            $L[] = "n/a";
        }

        // ── Маскировка / fingerprint ──
        $L[] = "\n▌ Masking / fingerprint (JA3/JA4)";
        $L[] = "fake-TLS domain: " . ($conf['telemt_domain'] ?? 'www.google.com');
        $maskRow = [];
        foreach (['telemt_mask_hardening' => 'harden', 'telemt_mask_aggressive' => 'aggr', 'telemt_mask_blur' => 'blur', 'telemt_mask_timing' => 'timing'] as $k => $lbl) {
            $maskRow[] = "$lbl " . ($this->telemtBool($conf, $k, $this->telemtMaskDefault($k)) ? 'on' : 'off');
        }
        $L[] = "shaping: " . implode(', ', $maskRow);
        $bfile = '/config/telemt/data/beobachten.txt';
        $btxt  = is_file($bfile) ? trim((string) file_get_contents($bfile)) : '';
        if ($btxt === '') {
            $L[] = "beobachten: no observations yet";
        } else {
            $blines = preg_split('~\R~', $btxt);
            $L[] = "beobachten: " . count($blines) . " line(s), retention "
                . $this->telemtInt($conf, 'telemt_beobachten_minutes', 10, 1, 1440) . "m — last:";
            foreach (array_slice($blines, -8) as $bl) {
                $L[] = "  " . $bl;
            }
        }

        // ── Безопасность ──
        if ($sec) {
            $L[] = "\n▌ Security posture";
            $L[] = "api: loopback 127.0.0.1 (not published, nft-dropped on host)";
            $L[] = "read_only: " . $yn($sec['api_read_only'] ?? false)
                . "  whitelist: " . ($sec['api_whitelist_entries'] ?? 0) . " cidr"
                . "  auth_header: " . $yn($sec['api_auth_header_enabled'] ?? false);
            $L[] = "log_level: " . ($sec['log_level'] ?? '?')
                . "  telemetry: core " . $yn($sec['telemetry_core_enabled'] ?? false)
                . ", user " . $yn($sec['telemetry_user_enabled'] ?? false);
        }

        $msg = implode("\n", $L);
        if (mb_strlen($msg) > 3900) {
            $msg = mb_substr($msg, 0, 3900) . "\n…";
        }
        $this->send($this->input['chat'], "<pre>" . htmlspecialchars($msg, ENT_QUOTES) . "</pre>", $this->input['message_id']);
    }

    public function telemtQr($name)
    {
        $conf = $this->getPacConf();
        if (empty($conf['telemt_users'][$name])) {
            $this->telemtUsers();
            return;
        }
        $link    = $this->linkTelemt($name);
        $qr_file = __DIR__ . "/qr/telemt.png";
        exec("qrencode -t png -o $qr_file " . escapeshellarg($link));
        $this->sendPhoto(
            $this->input['chat'],
            curl_file_create($qr_file),
            '<b>' . htmlspecialchars((string) $name, ENT_QUOTES) . "</b>\n" . htmlspecialchars($link, ENT_QUOTES)
        );
        @unlink($qr_file);
        if ($this->getPacConf()['blinkmenu']) {
            $this->delete($this->input['chat'], $this->input['message_id']);
            $this->input['message_id'] = $this->send($this->input['chat'], '.')['result']['message_id'];
            $this->telemt();
        }
    }

    public function telemtAddUser()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter user name",
            $this->input['message_id'],
            reply: 'enter user name',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message' => $this->input['message_id'],
            'callback'      => 'telemtUserAdd',
            'args'          => [],
        ];
    }

    public function telemtUserAdd($name)
    {
        $name = preg_replace('~[^A-Za-z0-9_]~', '', trim($name));
        if ($name === '') {
            $this->telemtUsers();
            return;
        }
        $conf = $this->getPacConf();
        $conf['telemt_users'][$name] = $this->telemtSecret();
        $this->setPacConf($conf);
        $this->restartTelemt();
        $this->telemtUsers();
    }

    public function telemtDelUser($name)
    {
        $conf = $this->getPacConf();
        unset($conf['telemt_users'][$name]);
        unset($conf['telemt_user_enabled'][$name]);
        $this->setPacConf($conf);
        $this->restartTelemt();
        $this->telemtUsers();
    }

    public function telemtRegen($name)
    {
        $conf = $this->getPacConf();
        if (isset($conf['telemt_users'][$name])) {
            $conf['telemt_users'][$name] = $this->telemtSecret();
            $this->setPacConf($conf);
            $this->restartTelemt();
        }
        $this->telemtUsers();
    }

    public function telemtDomain()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter fake-TLS domain (or 0 for default)",
            $this->input['message_id'],
            reply: 'enter domain',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message' => $this->input['message_id'],
            'callback'      => 'setTelemtDomain',
            'args'          => [],
        ];
    }

    public function setTelemtDomain($domain)
    {
        $domain = trim($domain);
        $conf   = $this->getPacConf();
        if ($domain === '' || $domain === '0') {
            $conf['telemt_domain'] = 'www.google.com';
        } elseif (preg_match('~^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$~i', $domain)) {
            $conf['telemt_domain'] = strtolower($domain);
        } else {
            $this->update($this->input['chat'], $this->input['message_id'], 'wrong domain');
            sleep(2);
            $this->telemtSettings();
            return;
        }
        $this->setPacConf($conf);
        $this->restartTelemt();
        $this->telemtSettings();
    }

    public function dnsttStart()
    {
        $c = $this->getPacConf();
        $this->ssh('pkill dnstt', 'dnstt');
        if (!empty($c['dnsttDomain']) && !empty($c['dnsttPassword'])) {
            $this->ssh("adduser -D -s /bin/sh vpnbot", 'dnstt');
            $this->ssh("echo 'vpnbot:{$c['dnsttPassword']}' | chpasswd", 'dnstt');
            if (!file_exists('/config/dnstt/server.key')) {
                $this->ssh("dnstt-server -gen-key -privkey-file /dnstt/server.key -pubkey-file /dnstt/server.pub", 'dnstt');
            }
            $this->ssh("dnstt-server -udp :53 -privkey-file /dnstt/server.key {$c['dnsttDomain']} 127.0.0.1:22", 'dnstt' , false, '/logs/dnstt');
        }
    }

    public function dnsttDownload()
    {
        $this->sendFile($this->input['from'], curl_file_create('/config/dnstt/server.pub'));
    }

    public function dnstt($update = false)
    {
        $c      = $this->getPacConf();
        $pubkey = file_get_contents('/config/dnstt/server.pub');
        $text[] = "dnstt";
        if (!empty($c['dnsttDomain']) && !empty($c['dnsttPassword'])) {
            $text[] = "<pre>set the NS record for {$c['dnsttDomain']}: tns.{$c['domain']}\nset A record for tns.{$c['domain']}: {$this->ip}</pre>";
            $text[] = "account: <code>vpnbot:{$c['dnsttPassword']}</code>";
            $text[] = "server name: <code>{$c['dnsttDomain']}</code>";
            $text[] = "public key: <code>$pubkey</code>";
            $data[] = [
                [
                    'text'          => $this->i18n('download pubkey'),
                    'callback_data' => "/dnsttDownload",
                ],
            ];
        } else {
            $text[] = "set subdomain and password";
        }

        $data[] = [
            [
                'text'          => $this->i18n('set subdomain'),
                'callback_data' => "/dnsttDomain",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('set password'),
                'callback_data' => "/dnsttPassword",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/menu",
            ],
        ];
        if ($update) {
            $this->update(
                $this->input['chat'],
                $this->input['message_id'],
                implode("\n", $text),
                $data ?: false,
            );
        } else {
            $this->send(
                $this->input['chat'],
                implode("\n", $text),
                $this->input['message_id'],
                $data ?: false,
            );
        }
    }

    public function getPorts()
    {
        $f = '/docker/compose';
        $c = is_file($f) ? (yaml_parse_file($f) ?: []) : [];
        $r = [];
        foreach ($this->ports as $k => $v) {
            $r[$k] = [
                'port'   => !empty($c['services'][$k]['ports']) ? explode(':', $c['services'][$k]['ports'][0])[0] : explode('/', $v)[0],
                'enable' => !empty($c['services'][$k]['ports']),
            ];
        }
        return $r;
    }

    public function menu($type = false, $arg = false, $return = false)
    {
        $conf   = $this->getPacConf();
        $domain = $conf['domain'] ?: $this->ip;
        $hash   = $this->getHashBot();
        if ($type == false) {
            $update = exec('git -C / rev-list --count HEAD..@{u}');
            $branch = exec('git -C / rev-parse --abbrev-ref HEAD');
            $backup = array_filter(explode('/', $conf['backup'] ?? ''));
            if (!empty($backup)) {
                if (!empty(strtotime($backup[0])) && !empty(strtotime($backup[1]))) {
                    $backup = "{$backup[0]} start / {$backup[1]} period";
                } else {
                    $backup = "{$conf['backup']} - wrong format";
                }
            }
            $cron   = $this->dontshowcron ? '' : $this->i18n($this->ssh('pgrep -f cron.php', 'service') ? 'on' : 'off') . ' cron';
            $f      = '/docker/compose';
            $c      = is_file($f) ? (yaml_parse_file($f)['services'] ?? []) : [];
            // BUILD_COMMIT пишется post-receive скриптом в .env перед make r,
            // чтобы в меню был идентификатор сборки даже когда VER
            // (git describe --tags) пустой из-за отсутствия тегов в репе.
            $commit = getenv('BUILD_COMMIT');
            $main[] = 'v' . getenv('VER') . " $branch"
                . ($commit ? " @$commit" : '')
                . ($update ? ' (have updates)' : '');

            if (!empty($conf['domain'])) {
                $main[] = '';
                $oc     = $this->getHashSubdomain('oc');
                $np     = $this->getHashSubdomain('np');
                if (!empty($conf['domain'])) {
                    $ssl_expiry = $this->expireCert();
                    $certs      = $this->domainsCert() ?: [];

                    $main[] = "<blockquote>";
                    $main[] = "Domains:";
                    $main[] = $conf['domain'] . (in_array($conf['domain'], $certs) ? ' (ssl: ' . date('Y-m-d H:i:s', $ssl_expiry) . ')' : '');
                    if (!empty($np)) {
                        $main[] = 'naive ' . "$np.{$conf['domain']}" . (in_array("$np.{$conf['domain']}", $certs) ? ' (ssl: ' . date('Y-m-d H:i:s', $ssl_expiry) . ')' : '');
                    }
                    if (!empty($oc)) {
                        $main[] = 'openconnect ' . "$oc.{$conf['domain']}" . (in_array("$oc.{$conf['domain']}", $certs) ? ' (ssl: ' . date('Y-m-d H:i:s', $ssl_expiry) . ')' : '');
                    }
                    if (!empty($conf['adguardkey'])) {
                        $main[] = "{$conf['adguardkey']}.{$conf['domain']}" . (in_array("{$conf['adguardkey']}.{$conf['domain']}", $certs) ? ' (ssl: ' . date('Y-m-d H:i:s', $ssl_expiry) . ')' : '') . ' adguard DOT';
                    }
                    $main[] = "</blockquote>";
                } else {
                    $main[] = $this->i18n('domain explain');
                }
            }


            $ports  = $this->getPorts();
            $main[] = '';

            $main[] = '<code>';
            $main[] = $this->alignColumns([
                [
                    $this->i18n($this->ssh(!empty($this->getPacConf()['amnezia']) ? 'awg' : 'wg', 'wg') ? 'on' : 'off') . ' ' . $this->i18n(!empty($this->getPacConf()['amnezia']) ? 'amnezia' : 'wg_title'),
                    $this->i18n($this->ssh(!empty($this->getPacConf()['wg1_amnezia']) ? 'awg' : 'wg', 'wg1') ? 'on' : 'off') . ' ' . $this->i18n(!empty($this->getPacConf()['wg1_amnezia']) ? 'amnezia' : 'wg_title'),
                    $this->i18n($this->ssh('pgrep xray', 'xr') ? 'on' : 'off') . ' ' . $this->i18n('xray'),
                    $this->i18n($this->ssh('pgrep caddy', 'np') ? 'on' : 'off') . ' ' . $this->i18n('naive'),
                    $this->i18n($this->ssh('pgrep ocserv', 'oc') ? 'on' : 'off') . ' ' . $this->i18n('ocserv'),
                    $this->i18n($this->ssh('pgrep hysteria', 'hy') ? 'on' : 'off') . ' ' . $this->i18n('hysteria'),
                    $this->i18n($this->ssh('pgrep -f trusttunnel_endpoint', 'tt') ? 'on' : 'off') . ' ' . $this->i18n('TrustTunnel'),
                    $this->i18n($this->ssh('pgrep openvpn', 'ovpn') ? 'on' : 'off') . ' ' . $this->i18n('OpenVPN'),
                    $this->i18n($this->ssh('pgrep mtproto-proxy', 'tg') ? 'on' : 'off') . ' ' . $this->i18n('mtproto'),
                    $this->i18n(exec("JSON=1 timeout 2 dnslookup google.com ad") ? 'on' : 'off') . ' ' . $this->i18n('ad_title'),
                    $this->i18n($this->ssh('pgrep ssserver', 'ss') ? 'on' : 'off') . ' ' . $this->i18n('sh_title'),
                    $this->i18n($this->ssh('pgrep dnstt', 'dnstt') ? 'on' : 'off') . ' ' . $this->i18n('dnstt'),
                    $this->i18n($this->ssh('pgrep -x telemt', 'telemt') ? 'on' : 'off') . ' ' . $this->i18n('telemt'),
                    $this->i18n($this->warpStatus()) . ' ' . $this->i18n('warp'),
                ],
                [
                    $this->i18n($ports['wg']['enable'] ? 'on' : 'off') . ($ports['wg']['enable'] ? ' ' . $ports['wg']['port'] : ' port unavailable'),
                    $this->i18n($ports['wg1']['enable'] ? 'on' : 'off') . ($ports['wg1']['enable'] ? ' ' . $ports['wg1']['port'] : ' port unavailable'),
                    $this->i18n('on') . ' 443',
                    $this->i18n('on') . ' 443',
                    $this->i18n('on') . ' 443',
                    $this->i18n($ports['hy']['enable'] ? 'on' : 'off') . ($ports['hy']['enable'] ? ' ' . $ports['hy']['port'] : ' port unavailable'),
                    $this->i18n($this->ssh('pgrep -f trusttunnel_endpoint', 'tt') ? 'on' : 'off') . ' ' . (isset($c['tt']['ports'][0]) ? explode(':', $c['tt']['ports'][0])[0] : getenv('TTPORT')),
                    $this->i18n($this->ssh('pgrep openvpn', 'ovpn') ? 'on' : 'off') . ' ' . (isset($c['ovpn']['ports'][0]) ? explode(':', $c['ovpn']['ports'][0])[0] : getenv('OVPNPORT')),
                    $this->i18n($ports['tg']['enable'] ? 'on' : 'off') . ($ports['tg']['enable'] ? ' ' . $ports['tg']['port'] : ' port unavailable'),
                    $this->i18n($ports['ad']['enable'] ? 'on' : 'off') . ($ports['ad']['enable'] ? ' ' . $ports['ad']['port'] : ' port unavailable'),
                    $this->i18n($ports['ss']['enable'] ? 'on' : 'off') . ($ports['ss']['enable'] ? ' ' . $ports['ss']['port'] : ' port unavailable'),
                    $this->i18n($ports['dnstt']['enable'] ? 'on' : 'off') . ($ports['dnstt']['enable'] ? ' ' . $ports['dnstt']['port'] : ' port unavailable'),
                    $this->i18n($ports['telemt']['enable'] ? 'on' : 'off') . ($ports['telemt']['enable'] ? ' ' . $ports['telemt']['port'] : ' port unavailable'),
                    '',
                ],
            ]);
            $main[] = '';
            $main[] = $this->alignColumns([
                [
                    $this->i18n($backup ? 'on' : 'off') . ' autobackup',
                    $this->i18n(!empty($conf['autoupdate']) ? 'on' : 'off') . ' autoupdate',
                    $this->i18n(!empty($conf['autoscan']) ? 'on' : 'off') . ' autoscan',
                ],
                [
                    $this->i18n(!empty($conf['autodeny']) ? 'on' : 'off') . ' autoblock' . (!empty($conf['deny']) ? ': ' . count($conf['deny']) : ''),
                    $this->i18n(!empty($conf['reset_monthly']) ? 'on' : 'off') . ' autoreset',
                    $cron,
                ],
            ]);
            $main[] = '</code>';

        }
        $menu   = [
            'main' => [
                'text' => implode("\n", $main ?: []),
                'data' => array_merge(
                    [
                        [
                            [
                                'text'          => $this->i18n(!empty($this->getPacConf()['amnezia']) ? 'amnezia' : 'wg_title'),
                                'callback_data' => "/changeWG 0",
                            ],
                            [
                                'text'          => $this->i18n(!empty($this->getPacConf()['wg1_amnezia']) ? 'amnezia' : 'wg_title'),
                                'callback_data' => "/changeWG 1",
                            ],
                        ],
                        [
                            [
                                'text'          => $this->i18n('xray'),
                                'callback_data' => "/xray",
                            ],
                            [
                                'text'          => $this->i18n('naive'),
                                'callback_data' => "/menu naive",
                            ],
                        ],
                        [
                            [
                                'text'          => $this->i18n('ocserv'),
                                'callback_data' => "/menu oc",
                            ],
                            [
                                'text'          => $this->i18n('mtproto'),
                                'callback_data' => "/mtproto",
                            ],
                        ],
                        [
                            [
                                'text'          => $this->i18n('telemt'),
                                'callback_data' => "/telemt",
                            ],
                            [
                                'text'          => $this->i18n('TrustTunnel'),
                                'callback_data' => "/menu tt",
                            ],
                        ],
                        [
                            [
                                'text'          => $this->i18n('ad_title'),
                                'callback_data' => "/menu adguard",
                            ],
                            [
                                'text'          => $this->i18n('Hysteria'),
                                'callback_data' => "/menu hy",
                            ],
                        ],
                        [
                            [
                                'text'          => $this->i18n('sh_title'),
                                'callback_data' => "/menu ss",
                            ],
                            [
                                'text'          => $this->i18n('pac'),
                                'callback_data' => "/pacMenu 0",
                            ],
                        ],
                    ],
                    [
                        [
                            [
                                'text'          => $this->i18n('DNSTT'),
                                'callback_data' => "/dnstt",
                            ],
                            [
                                'text'          => $this->i18n('warp'),
                                'callback_data' => "/warp",
                            ],
                        ],
                    ],
                    [
                        [
                            [
                                'text'          => $this->i18n('config'),
                                'callback_data' => "/menu config",
                            ],
                            [
                                'text'          => $this->i18n('OpenVPN'),
                                'callback_data' => "/menu ovpn",
                            ],
                        ],
                        [
                            [
                                'text' => $this->i18n('chat'),
                                'url'  => base64_decode('aHR0cHM6Ly90Lm1lLys0RzMtUTRkX3ZGRXhPRGN5'),
                            ],
                            [
                                'text' => $this->i18n('donate'),
                                'web_app' => [
                                    'url'  => "https://$domain/webapp$hash/donate.html",
                                ]
                            ],
                        ],
                    ],
                )
            ],
            'wg'           => $type == 'wg'      ? $this->statusWg($arg)                   : false,
            'client'       => $type == 'client'  ? $this->getClient(...explode('_', $arg)) : false,
            'addpeer'      => $type == 'addpeer' ? $this->addWg(...explode('_', $arg))     : false,
            'pac'          => $type == 'pac'     ? $this->pacMenu((int) $arg)              : false,
            'adguard'      => $type == 'adguard' ? $this->adguardMenu()                    : false,
            'config'       => $type == 'config'  ? $this->configMenu()                     : false,
            'ss'           => $type == 'ss'      ? $this->menuSS()                         : false,
            'lang'         => $type == 'lang'    ? $this->menuLang()                       : false,
            'oc'           => $type == 'oc'      ? $this->ocMenu()                         : false,
            'naive'        => $type == 'naive'   ? $this->naiveMenu()                      : false,
            'hy'           => $type == 'hy'      ? $this->hysteriaMenu()                   : false,
            'tt'           => $type == 'tt'      ? $this->ttMenu()                         : false,
            'ovpn'         => $type == 'ovpn'    ? $this->ovpnMenu()                       : false,
            'mirror'       => $type == 'mirror'  ? $this->mirrorMenu()                     : false,
            'update'       => $type == 'update'  ? $this->updatebot()                      : false,
        ];

        $text = $menu[$type ?: 'main' ]['text'];
        $data = $menu[$type ?: 'main' ]['data'];

        if (empty($type) && $update) {
            $b = exec('git -C / rev-parse --abbrev-ref HEAD');
            array_unshift($data, [
                [
                    'text'    => 'changelog',
                    'web_app' => ['url' => "https://raw.githubusercontent.com/mercurykd/vpnbot/$b/version"],
                ],
                [
                    'text'          => $this->i18n('update bot'),
                    'callback_data' => "/applyupdatebot",
                ],
            ]);
        }

        if ($return) {
            return [$text, $data];
        }

        if (!empty($this->input['callback_id'])) {
            $this->update(
                $this->input['chat'],
                $this->input['message_id'],
                $text,
                $data ?: false,
            );
        } else {
            $this->send(
                $this->input['chat'],
                $text,
                $this->input['message_id'],
                $data ?: false,
            );
        }
    }

    public function switchScanIp()
    {
        $c = $this->getPacConf();
        $c['autoscan'] = $c['autoscan'] ? 0 : 1;
        $this->setPacConf($c);
        $this->ipMenu();
    }

    public function switchBanIp()
    {
        $c = $this->getPacConf();
        $c['autodeny'] = $c['autodeny'] ? 0 : 1;
        $this->setPacConf($c);
        $this->ipMenu();
    }

    public function switchMonthlyStats()
    {
        $c = $this->getPacConf();
        $c['reset_monthly'] = $c['reset_monthly'] ? 0 : 1;
        $this->setPacConf($c);
        $this->xray();
    }

    // uTLS fingerprints offered in the menu. All are valid Xray uTLS ids; for
    // sing-box / clash configs the Xray-only ids (randomizednoalpn, unsafe) are
    // normalized away in subscription() because those cores don't accept them.
    public function fingerprints()
    {
        return ['chrome', 'firefox', 'safari', 'ios', 'android', 'edge', '360', 'qq', 'random', 'randomized', 'randomizednoalpn', 'unsafe'];
    }

    public function changeFingerprint($fingerprint = false)
    {
        $allowed = $this->fingerprints();
        $c       = $this->getPacConf();
        if ($fingerprint && in_array($fingerprint, $allowed, true)) {
            $c['fingerprint'] = $fingerprint;
        } else {
            // bare call (no/invalid arg): cycle to the next fingerprint in the list
            $current          = ($c['fingerprint'] ?? '') ?: 'chrome';
            $i                = array_search($current, $allowed, true);
            $c['fingerprint'] = $allowed[($i === false ? 0 : $i + 1) % count($allowed)];
        }
        $this->setPacConf($c);
        $this->fingerprintMenu();
    }

    public function fingerprintMenu()
    {
        $current = $this->getPacConf()['fingerprint'] ?: 'chrome';
        $text[]  = "Menu -> " . $this->i18n('xray') . ' -> ' . $this->i18n('fingerprint');
        $text[]  = $this->i18n('fingerprint') . ': <code>' . $current . '</code>';

        $data = [];
        $row  = [];
        foreach ($this->fingerprints() as $fp) {
            $row[] = [
                'text'          => ucfirst($fp) . ' ' . ($current === $fp ? $this->i18n('on') : $this->i18n('off')),
                'callback_data' => "/changeFingerprint $fp",
            ];
            if (count($row) === 2) {
                $data[] = $row;
                $row    = [];
            }
        }
        if ($row) {
            $data[] = $row;
        }
        $data[] = [[
            'text'          => $this->i18n('back'),
            'callback_data' => '/xray',
        ]];

        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            implode("\n", $text),
            $data,
        );
    }

    public function switchIpLimit($limit)
    {
        $limit = explode(':', $limit);
        $c = $this->getPacConf();
        if ((int) $limit[0] <= 0) {
            unset($c['ip_limit']);
            unset($c['ip_count']);
        } else {
            $c['ip_limit'] = (int) $limit[0];
            $c['ip_count'] = (int) $limit[1] ?: 1;
        }
        $this->setPacConf($c);
        $this->xray();
    }

    public function hwidLimit()
    {
        $pac     = $this->getPacConf();
        $enabled = !empty($pac['hwid_limit_enabled']);
        $count   = max(1, (int) ($pac['hwid_device_count'] ?: 1));

        $text[] = 'Settings -> ' . $this->i18n('hwid limit');
        $text[] = $this->i18n('hwid notice');
        $text[] = $this->i18n('hwid limit') . ': ' . ($enabled ? $count : $this->i18n('off'));

        $data[] = [
            [
                'text'          => $this->i18n($enabled ? 'on' : 'off'),
                'callback_data' => '/toggleHwidLimit',
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('set hwid devices count') . ': ' . $count,
                'callback_data' => '/setHwidDevices',
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => '/xray',
            ],
        ];

        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            implode("\n", $text ?: ['...']),
            $data ?: false,
        );
    }

    public function toggleHwidLimit($context = null)
    {
        $pac = $this->getPacConf();
        $pac['hwid_limit_enabled'] = $pac['hwid_limit_enabled'] ? 0 : 1;
        if (!empty($pac['hwid_limit_enabled']) && empty($pac['hwid_device_count'])) {
            $pac['hwid_device_count'] = 1;
        }
        $this->setPacConf($pac);
        $this->answer($this->input['callback_id'], $this->i18n('hwid notice'), true);
        if ($context === 'xray') {
            $this->xray();
        } else {
            $this->hwidLimit();
        }
    }

    public function setHwidDevices($context = null)
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter hwid devices count",
            $this->input['message_id'],
            reply: 'enter hwid devices count',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message' => $this->input['message_id'],
            'callback'      => 'saveHwidDevices',
            'args'          => [$context],
        ];
    }

    public function saveHwidDevices($count, $context = null)
    {
        $count = (int) $count;
        if ($count <= 0) {
            $count = 1;
        }
        $pac = $this->getPacConf();
        $pac['hwid_device_count'] = $count;
        $this->setPacConf($pac);
        $this->send($this->input['chat'], $this->i18n('hwid notice'), $this->input['message_id']);
        if ($context === 'xray') {
            $this->xray();
        } else {
            $this->hwidLimit();
        }
    }

    public function getHwidStorage()
    {
        if (!file_exists($this->hwid)) {
            return [];
        }
        $data = json_decode(file_get_contents($this->hwid), true);
        return is_array($data) ? $data : [];
    }

    public function setHwidStorage(array $storage)
    {
        file_put_contents($this->hwid, json_encode($storage, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
    }

    public function getHwidDevicesByUser($uid)
    {
        $storage = $this->getHwidStorage();
        return $storage[$uid] ?? [];
    }

    public function setHwidDevice($uid, $hwid, array $info)
    {
        $storage = $this->getHwidStorage();
        $storage[$uid][$hwid] = $info;
        $this->setHwidStorage($storage);
    }

    public function deleteHwidDevice($uid, $hwid)
    {
        $storage = $this->getHwidStorage();
        if (isset($storage[$uid][$hwid])) {
            unset($storage[$uid][$hwid]);
            if (empty($storage[$uid])) {
                unset($storage[$uid]);
            }
            $this->setHwidStorage($storage);
        }
    }

    public function deleteHwidUser($uid)
    {
        $storage = $this->getHwidStorage();
        if (isset($storage[$uid])) {
            unset($storage[$uid]);
            $this->setHwidStorage($storage);
        }
    }

    protected function getHwidTokenScope($index)
    {
        return ($this->input['chat'] ?? 'global') . ':' . $index;
    }

    protected function rememberHwidToken($scope, $hwid)
    {
        if (!isset($_SESSION['hwidTokens'])) {
            $_SESSION['hwidTokens'] = [];
        }
        if (!isset($_SESSION['hwidTokens'][$scope])) {
            $_SESSION['hwidTokens'][$scope] = [];
        }
        do {
            try {
                $token = bin2hex(random_bytes(5));
            } catch (\Throwable $e) {
                $token = substr(hash('sha256', $hwid . microtime(true)), 0, 10);
            }
        } while (isset($_SESSION['hwidTokens'][$scope][$token]));

        $_SESSION['hwidTokens'][$scope][$token] = $hwid;

        return $token;
    }

    protected function resolveHwidToken($scope, $token)
    {
        if (isset($_SESSION['hwidTokens'][$scope][$token])) {
            $hwid = $_SESSION['hwidTokens'][$scope][$token];
            unset($_SESSION['hwidTokens'][$scope][$token]);
            return $hwid;
        }

        $decoded = base64_decode($token, true);

        return $decoded !== false ? $decoded : '';
    }

    public function processHwidRequest(array $client)
    {
        $pac = $this->getPacConf();
        if (empty($pac['hwid_limit_enabled']) || !empty($client['hwid_disabled'])) {
            return true;
        }

        $limit = (int) ($client['hwid_limit'] ?: ($pac['hwid_device_count'] ?: 0));
        if ($limit <= 0) {
            return true;
        }

        $devices   = $this->getHwidDevicesByUser($client['id']);
        $hwid      = trim($_SERVER['HTTP_X_HWID'] ?? '');
        $isBrowser = $this->isBrowserRequest();

        if ($hwid === '') {
            if ($isBrowser) {
                return true;
            }

            $message = 'HWID device limit exceeded';
            header('announce: base64:' . base64_encode($message));
            header('X-HWID-Status: ' . $message);
            header('HTTP/1.1 429 Too Many Requests', true, 429);

            return false;
        }

        $isNew = !isset($devices[$hwid]);

        if ($isNew && count($devices) >= $limit) {
            $message = 'HWID device limit exceeded';
            header('announce: base64:' . base64_encode($message));
            header('X-HWID-Status: ' . $message);
            header('HTTP/1.1 429 Too Many Requests', true, 429);
            return false;
        }

        $this->setHwidDevice($client['id'], $hwid, [
            'time'         => time(),
            'user_agent'   => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'device_os'    => $_SERVER['HTTP_X_DEVICE_OS'] ?? '',
            'os_version'   => $_SERVER['HTTP_X_VER_OS'] ?? '',
            'device_model' => $_SERVER['HTTP_X_DEVICE_MODEL'] ?? '',
        ]);

        return true;
    }

    protected function isBrowserRequest()
    {
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $accept    = $_SERVER['HTTP_ACCEPT'] ?? '';

        if ($userAgent === '' && $accept === '') {
            return false;
        }

        $browserPatterns = [
            'Mozilla/',
            'Chrome/',
            'Safari/',
            'Firefox/',
            'Edge/',
            'Edg/',
            'MSIE ',
            'Trident/',
            'Opera/',
            'OPR/',
        ];

        foreach ($browserPatterns as $pattern) {
            if (stripos($userAgent, $pattern) !== false) {
                return true;
            }
        }

        if (stripos($accept, 'text/html') !== false) {
            return true;
        }

        return false;
    }

    public function switchSilence()
    {
        $c = $this->getPacConf();
        $c['silence'] = (($c['silence'] ?: 0) + 1) % 3;
        $this->setPacConf($c);
        $this->ipMenu();
    }

    public function ipMenu()
    {
        $text   = 'Settings -> IP & Logs';
        $pac    = $this->getPacConf();
        $d      = count($pac['deny'] ?: []);
        $w      = count($pac['white'] ?: []);
        $data[] = [
            [
                'text'          => $this->i18n('autoscan') . ': ' . ($pac['autoscan'] ? $this->getTime(strtotime(($pac['autoscan_timeout'] ?: 3600) . ' seconds')) : $this->i18n('off')),
                'callback_data' => '/autoScanTimeout',
            ],
        ];
        if (!empty($pac['autoscan'])) {
            $data[] = [
                [
                    'text'          => $this->i18n('autoblock') . ': ' . $this->i18n($pac['autodeny'] ? 'on' : 'off'),
                    'callback_data' => '/switchBanIp',
                ],
                [
                    'text'          => $this->i18n('notify') . ': ' . ((function ($pac) {
                        switch ($pac['silence']) {
                            case 0:
                                return '🔊';
                            case 1:
                                return '🔈';
                            case 2:
                                return '🔇';
                        }
                    })($pac)),
                    'callback_data' => '/switchSilence',
                ],
            ];
        }
        $data[] = [
            [
                'text'          => $this->i18n('ignorelist') . ": $w",
                'callback_data' => '/denyList 0 1',
            ],
            [
                'text'          => $this->i18n('blocklist') . ": $d",
                'callback_data' => '/denyList 0 0',
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('analyze'),
                'callback_data' => '/analysisIp',
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/menu config",
            ],
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            $text,
            $data ?: false,
        );
    }

    public function ipInRange($ip, $range) {
        [$range, $netmask] = explode('/', $range, 2);
        $rangeDecimal      = ip2long($range);
        $ipDecimal         = ip2long($ip);
        $wildcardDecimal   = pow(2, 32 - $netmask) - 1;
        $netmaskDecimal    = ~$wildcardDecimal;
        return ($ipDecimal & $netmaskDecimal) == ($rangeDecimal & $netmaskDecimal);
    }

    public function suspicious($regexp, $file, $ranges, $title, $reverse = false)
    {
        if ($r = fopen($file, 'r')) {
            while (feof($r) === false) {
                $l = fgets($r);
                if (preg_match('~(\d+\.\d+\.\d+\.\d+)~', $l, $m)) {
                    if ($reverse xor preg_match($regexp, $l)) {
                        if (is_array($ranges)) {
                            $flag = true;
                            foreach ($ranges as $range) {
                                if ($this->ipInRange($m[1], $range)) {
                                    $flag = false;
                                    break;
                                }
                            }
                            if ($flag) {
                                $ret[$m[1]][] = [
                                    'title' => $title,
                                    'log'   => $l,
                                ];
                            }
                        } else {
                            if ($this->ipInRange($m[1], $ranges)) {
                                $ret[$m[1]][] = [
                                    'title' => $title,
                                    'log'   => $l,
                                ];
                            }
                        }
                    }
                }
            }
            fclose($r);
        }
        return $ret ?: [];
    }

    // Host CPU usage in percent, sampled over a short interval. /proc/stat is the
    // host kernel's view inside the container, so this reflects the whole machine.
    public function cpuUsage()
    {
        $sample = function () {
            $line = (@file('/proc/stat') ?: [''])[0];
            $p    = array_map('intval', array_slice(preg_split('~\s+~', trim($line)), 1));
            $idle = ($p[3] ?? 0) + ($p[4] ?? 0); // idle + iowait
            return [$idle, array_sum($p)];
        };
        [$idle1, $total1] = $sample();
        usleep(200000); // 200ms window
        [$idle2, $total2] = $sample();
        $dt = $total2 - $total1;
        $di = $idle2 - $idle1;
        return $dt > 0 ? (int) round((1 - $di / $dt) * 100) : 0;
    }

    public function cpuCores()
    {
        return max(1, preg_match_all('~^cpu\d+~m', @file_get_contents('/proc/stat') ?: ''));
    }

    // [usedBytes, totalBytes] from /proc/meminfo (host RAM as seen in the container).
    public function memInfo()
    {
        $m   = @file_get_contents('/proc/meminfo') ?: '';
        $get = fn($k) => preg_match('~^' . $k . ':\s+(\d+)\s*kB~m', $m, $x) ? (int) $x[1] * 1024 : 0;
        $total = $get('MemTotal');
        $avail = $get('MemAvailable') ?: ($get('MemFree') + $get('Buffers') + $get('Cached'));
        return [max(0, $total - $avail), $total];
    }

    public function serverStatus()
    {
        $up    = (int) (float) (@file('/proc/uptime') ?: [0])[0];
        $load  = sys_getloadavg() ?: [0, 0, 0];
        [$memUsed, $memTotal] = $this->memInfo();
        $dt    = @disk_total_space('/') ?: 0;
        $df    = @disk_free_space('/') ?: 0;
        $du    = max(0, $dt - $df);
        $pct   = fn($u, $t) => $t > 0 ? round($u / $t * 100) : 0;

        $text   = [];
        $text[] = "Menu -> " . $this->i18n('server status');
        $text[] = '';
        $text[] = '<code>';
        $text[] = 'uptime:  ' . $this->getTime(time() + $up);
        $text[] = 'cpu:     ' . $this->cpuUsage() . '% (' . $this->cpuCores() . ' cores)';
        $text[] = 'load:    ' . implode(' / ', array_map(fn($l) => round($l, 2), array_slice($load, 0, 3)));
        $text[] = 'memory:  ' . $this->fmtBytes($memUsed) . ' / ' . $this->fmtBytes($memTotal) . ' (' . $pct($memUsed, $memTotal) . '%)';
        $text[] = 'disk:    ' . $this->fmtBytes($du) . ' / ' . $this->fmtBytes($dt) . ' (' . $pct($du, $dt) . '%)';
        $text[] = '</code>';

        $data   = [];
        $data[] = [[
            'text'          => '🔄 ' . $this->i18n('refresh'),
            'callback_data' => '/status',
        ]];
        $data[] = [[
            'text'          => $this->i18n('back'),
            'callback_data' => '/menu config',
        ]];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            implode("\n", $text),
            $data,
        );
    }

    // Clients with a vless connection in the last $window seconds, grouped by email
    // with their distinct source IPs. Parsed from the tail of the xray access log;
    // log timestamps and time() share the container TZ (see app/timezone.php).
    // Vless clients active in the last $window seconds, grouped by email -> distinct
    // source IPs (+ 'last' = newest timestamp). Pure data, no Telegram I/O.
    //
    // Robust against timezone and log-format quirks:
    //  - filemtime() is a TZ-independent epoch gate: if the access log wasn't written
    //    within the window, nobody is online.
    //  - the per-client window compares each entry to the log's OWN newest timestamp
    //    (log-clock vs log-clock), so it doesn't depend on PHP/xray TZ alignment.
    //  - the match is lenient (any line prefix), mirroring frequencyAnalyze(), and if
    //    timestamps can't be parsed at all it falls back to the last lines of the tail.
    public function getOnlineState(): array
    {
        return json_decode(@file_get_contents('/config/online.json'), true) ?: [];
    }

    public function setOnlineState($s)
    {
        // atomic write: cron and the webhook (separate containers, shared volume) both
        // touch this file, so write to a unique temp and rename to avoid torn reads.
        // uniqid() guards against the two containers sharing a PID number.
        $tmp = '/config/online.json.' . getmypid() . '.' . uniqid();
        if (file_put_contents($tmp, json_encode($s)) !== false) {
            rename($tmp, '/config/online.json');
        } else {
            @unlink($tmp);
        }
    }

    // Continuously tracked last-seen per vless email. Incrementally tails the xray
    // access log from a saved byte offset and stamps every newly-seen email with the
    // wall clock at read time (like frequencyAnalyze) — no log-timestamp parsing, so
    // it is immune to TZ/format quirks. Called every cron tick AND on each online
    // read, so a single missed connection no longer makes a client flicker out: they
    // stay listed until the window elapses without any new connection.
    public function trackOnline(): array
    {
        $path = '/logs/xray';
        if (!is_file($path)) {
            return [];
        }
        $state = $this->getOnlineState();
        $seen  = $state['seen'] ?? [];
        clearstatcache(true, $path);
        $size   = filesize($path);
        $offset = $state['offset'] ?? null;
        // first run or a rotated/truncated log: start at EOF so we don't import old
        // history as "online" (a connection from an hour ago must not count as live).
        if ($offset === null || $offset > $size) {
            $offset = $size;
        }
        if ($size > $offset && ($r = fopen($path, 'r'))) {
            fseek($r, $offset);
            $now = time();
            while (($l = fgets($r)) !== false) {
                if (preg_match('~\sfrom\s(\d{1,3}(?:\.\d{1,3}){3})\D.*?email:\s*(\S+)~', $l, $m)) {
                    $seen[$m[2]]['ts']         = $now;
                    $seen[$m[2]]['ips'][$m[1]] = $now;
                }
            }
            $offset = ftell($r);
            fclose($r);
        }
        // prune entries/IPs not seen in the last 10 min to keep the file small
        $cutoff = time() - 600;
        foreach ($seen as $email => $info) {
            foreach (($info['ips'] ?? []) as $ip => $ts) {
                if ($ts < $cutoff) {
                    unset($seen[$email]['ips'][$ip]);
                }
            }
            if (($info['ts'] ?? 0) < $cutoff) {
                unset($seen[$email]);
            }
        }
        $this->setOnlineState(['offset' => $offset, 'seen' => $seen]);
        return $seen;
    }

    // Vless clients seen within the last $window seconds, grouped by email -> IPs.
    // Cross-checked against the live xray roster: a client that was disabled (off
    // flag) or deleted is dropped immediately instead of lingering for the whole
    // access-log window. Disabling cuts the connection (xray restart) so no new log
    // lines arrive, but its email would otherwise stay "online" until $window passed
    // — the roster check makes /onlines reflect reality on the very next refresh.
    public function onlineClients(int $window = 60): array
    {
        $seen = $this->trackOnline();
        $now  = time();
        // set of emails that currently exist AND are enabled in xray
        $enabled = [];
        foreach (($this->getXray()['inbounds'][0]['settings']['clients'] ?? []) as $cl) {
            if (empty($cl['off']) && !empty($cl['email'])) {
                $enabled[$cl['email']] = true;
            }
        }
        $clients = [];
        foreach ($seen as $email => $info) {
            if (!isset($enabled[$email])) {
                continue;
            }
            if (($info['ts'] ?? 0) < $now - $window) {
                continue;
            }
            $ips = [];
            foreach (($info['ips'] ?? []) as $ip => $ts) {
                if ($ts >= $now - $window) {
                    $ips[$ip] = $ts;
                }
            }
            $clients[$email] = ['ips' => $ips, 'last' => $info['ts']];
        }
        return $clients;
    }

    // Persistent IP -> geo (country / org-ISP / city) cache, shared like online.json.
    // ipinfo.io is rate-limited, so we cache for 7 days and keep the file bounded.
    public function getGeoCache(): array
    {
        return json_decode(@file_get_contents('/config/geoip.json'), true) ?: [];
    }

    public function setGeoCache(array $cache)
    {
        // keep the newest 500 entries so the file can't grow without bound
        if (count($cache) > 500) {
            uasort($cache, fn($a, $b) => ($b['ts'] ?? 0) <=> ($a['ts'] ?? 0));
            $cache = array_slice($cache, 0, 500, true);
        }
        // atomic write (cron + webhook share the volume), same pattern as online.json
        $tmp = '/config/geoip.json.' . getmypid() . '.' . uniqid();
        if (file_put_contents($tmp, json_encode($cache)) !== false) {
            rename($tmp, '/config/geoip.json');
        } else {
            @unlink($tmp);
        }
    }

    // Look up an IP's country/ISP, serving from $cache when fresh and filling misses
    // from ipinfo.io. $cache is updated in place; the caller persists it once.
    public function geoLookup(string $ip, array &$cache): array
    {
        if (isset($cache[$ip]) && ($cache[$ip]['ts'] ?? 0) > time() - 604800) {
            return $cache[$ip];
        }
        $info = @json_decode(@file_get_contents(
            "https://ipinfo.io/$ip/json",
            context: stream_context_create(['http' => ['timeout' => 2]])
        ), true) ?: [];
        // A network/rate-limit failure yields []; don't cache that or a transient blip
        // would suppress this IP's geo for the whole 7-day TTL. A reachable ipinfo always
        // echoes at least "ip" (even for bogons), so a non-empty reply means success.
        if (!$info) {
            return ['country' => '', 'org' => '', 'city' => '', 'ts' => 0];
        }
        // ipinfo's "org" is like "AS13335 Cloudflare, Inc." — drop the AS prefix for display
        $org = trim(preg_replace('~^AS\d+\s*~', '', $info['org'] ?? ''));
        $cache[$ip] = [
            'country' => $info['country'] ?? '',
            'org'     => $org,
            'city'    => $info['city'] ?? '',
            'ts'      => time(),
        ];
        return $cache[$ip];
    }

    // 2-letter ISO country code -> regional-indicator flag emoji ('' if invalid).
    public function countryFlag(string $cc): string
    {
        // note: the php container has no ctype extension, so match with a regex
        if (!preg_match('~^[A-Za-z]{2}$~', $cc)) {
            return '';
        }
        $cc = strtoupper($cc);
        return mb_chr(0x1F1E6 + ord($cc[0]) - 65, 'UTF-8')
             . mb_chr(0x1F1E6 + ord($cc[1]) - 65, 'UTF-8');
    }

    public function onlinesView()
    {
        $clients = $this->onlineClients();
        $n       = count($clients);
        $text[]  = "Menu -> " . $this->i18n('online') . ($n ? "   ($n online)" : '');
        $text[]  = '';
        if (empty($clients)) {
            $text[] = $this->i18n('no one online');
        } else {
            uasort($clients, fn($a, $b) => $b['last'] <=> $a['last']);

            // map vless email -> cumulative traffic (global + current session)
            $xray  = $this->getXray();
            $stats = $this->getXrayStats();
            $byEmail = [];
            foreach (($xray['inbounds'][0]['settings']['clients'] ?? []) as $k => $cl) {
                $byEmail[$cl['email']] = [
                    'down' => ($stats['users'][$k]['global']['download'] ?? 0) + ($stats['users'][$k]['session']['download'] ?? 0),
                    'up'   => ($stats['users'][$k]['global']['upload'] ?? 0) + ($stats['users'][$k]['session']['upload'] ?? 0),
                ];
            }

            $geo    = $this->getGeoCache();
            $before = $geo;
            $now    = time();
            $text[] = '<code>';
            foreach ($clients as $email => $info) {
                $ips    = array_keys($info['ips']);
                $ago    = max(0, $now - ($info['last'] ?? $now));
                // email is free-form user input and the message is parse_mode=HTML, so
                // an unescaped & or < would 400 the whole view — escape it.
                $text[] = '🟢 ' . htmlspecialchars($email, ENT_QUOTES) . ' (' . count($ips) . ')';

                $line = '   ';
                if ($tr = $byEmail[$email] ?? null) {
                    $line .= '↓' . $this->fmtBytes($tr['down']) . '  ↑' . $this->fmtBytes($tr['up']) . '  · ';
                }
                $text[] = $line . $ago . 's ' . $this->i18n('ago');

                foreach ($ips as $ip) {
                    $g    = $this->geoLookup($ip, $geo);
                    $flag = $this->countryFlag($g['country'] ?? '');
                    // the flag already conveys the country, so only print the country code
                    // as text when we couldn't render a flag; always append the ISP/org.
                    $meta = array_filter([$flag ? '' : ($g['country'] ?? ''), $g['org'] ?? '']);
                    $text[] = '   ' . trim(($flag ? "$flag " : '') . $ip
                        . ($meta ? ' — ' . htmlspecialchars(implode(' · ', $meta), ENT_QUOTES) : ''));
                }
            }
            $text[] = '</code>';
            if ($geo !== $before) {
                $this->setGeoCache($geo);
            }
        }

        $data   = [];
        $data[] = [[
            'text'          => '🔄 ' . $this->i18n('refresh'),
            'callback_data' => '/onlines',
        ]];
        $data[] = [[
            'text'          => $this->i18n('back'),
            'callback_data' => '/xray',
        ]];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            implode("\n", $text),
            $data,
        );
    }

    public function analysisIp(int $page = 0, $return = false)
    {
        $pac = $this->getPacConf();
        $xr  = [];
        foreach (array_merge($pac['white'] ?: [], $pac['deny'] ?: [], ['10.10.0.0/23']) as $v) {
            if (preg_match('~^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:(/\d{1,2}))?$~', $v, $m)) {
                if (!in_array($m[1] . ($m[2] ?: '/32'), $xr)) {
                    $xr[] = $m[1] . ($m[2] ?: '/32');
                }
            }
        }
        if ($r = fopen('/logs/nginx_tlgrm_access', 'r')) {
            while (feof($r) === false) {
                $l = fgets($r);
                if (preg_match('~(\d+\.\d+\.\d+\.\d+)~', $l, $m)) {
                    if (!in_array("{$m[1]}/32", $xr)) {
                        $xr[] = "{$m[1]}/32";
                    }
                }
            }
            fclose($r);
        }
        if ($r = fopen('/logs/nginx_doh_access', 'r')) {
            while (feof($r) === false) {
                $l = fgets($r);
                if (preg_match('~(\d+\.\d+\.\d+\.\d+)~', $l, $m)) {
                    if (!in_array("{$m[1]}/32", $xr)) {
                        $xr[] = "{$m[1]}/32";
                    }
                }
            }
            fclose($r);
        }
        if ($r = fopen('/logs/xray', 'r')) {
            while (feof($r) === false) {
                $l = fgets($r);
                if (preg_match('~(\d+\.\d+\.\d+\.\d+)(?=.+accepted)~', $l, $m)) {
                    if (!in_array("{$m[1]}/32", $xr)) {
                        $xr[] = "{$m[1]}/32";
                    }
                }
            }
            fclose($r);
        }

        $t = [
            $this->suspicious($this->reg, '/logs/nginx_default_access', $xr, 'possibly a scanner', true),
            $this->suspicious($this->reg, '/logs/nginx_domain_access', $xr, 'possibly a scanner', true),
        ];

        $ip = [];
        foreach ($t as $r) {
            foreach ($r as $k => $v) {
                $ip[$k] = $v;
            }
        }

        $r = $this->suspicious('~\d+\.\d+\.\d+\.\d+.+200\s\d+\s0$~', '/logs/upstream_access', $xr, 'possibly a Reality Degenerate');
        if (!empty($r)) {
            foreach ($r as $k => $v) {
                if (count($v) > 30) {
                    $ip[$k] = $v;
                }
            }
        }

        if (!empty($return)) {
            return $ip;
        }
        if (!empty($ip)) {
            foreach ($ip as $k => $v) {
                $data[] = [
                    [
                        'text'          => $k,
                        'callback_data' => "/searchLogs $k analysisIp $page 0",
                    ]
                ];
            }
            $all  = (int) ceil(count($data) / $this->limit);
            $page = min($page, $all - 1);
            $page = $page < 0 ? $all - 1 : $page;
            $data = array_slice($data ?: [], $page * $this->limit, $this->limit);
            if ($all > 1) {
                $data[] = [
                    [
                        'text'          => '<<',
                        'callback_data' => "/analysisIp " . ($page - 1 >= 0 ? $page - 1 : $all - 1),
                    ],
                    [
                        'text'          => $page + 1,
                        'callback_data' => "/analysisIp $page",
                    ],
                    [
                        'text'          => '>>',
                        'callback_data' => "/analysisIp " . ($page < $all - 1 ? $page + 1 : 0),
                    ],
                ];
            }
        }
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/ipMenu",
            ],
        ];
        $this->update($this->input['from'], $this->input['message_id'], count($ip) ?: 'empty', $data);
    }

    public function searchLogs($search, $fun = false, $page = 0, $white = 0)
    {
        if (preg_match('~^\d+\.\d+\.\d+\.\d+$~', $search)) {
            $info = file_get_contents("https://ipinfo.io/$search/json", context: stream_context_create(['http' => ['timeout' => 2]]));
            $text = "$search\n<pre>$info</pre>";
            $data[] = [
                [
                    'text'          => $this->i18n('block'),
                    'callback_data' => "/denyIp $search" . ($fun ? " $fun $page $white" : ''),
                ],
                [
                    'text'          => $this->i18n('ignore'),
                    'callback_data' => "/whiteIp $search" . ($fun ? " $fun $page $white" : ''),
                ],
            ];
            $data[] = [
                [
                    'text'          => $this->i18n('all logs'),
                    'callback_data' => "/searchIp $search",
                ],
                [
                    'text'          => $this->i18n('suspicious log'),
                    'callback_data' => "/searchSuspiciousIp $search",
                ],
            ];
            $data[] = [
                [
                    'text'          => $this->i18n("clean logs $search"),
                    'callback_data' => "/cleanLogs $search",
                ],
            ];
            if (!empty($fun)) {
                $data[] = [
                    [
                        'text'          => $this->i18n('back'),
                        'callback_data' => "/$fun $page" . ($white ? " $white" : ''),
                    ],
                ];
                $this->update($this->input['from'], $this->input['message_id'], $text, button: $data);
            } else {
                if (empty($this->input['callback_id'])) {
                    $this->delete($this->input['from'], $this->input['message_id']);
                }
                $this->send($this->input['from'], $text, button: $data);
            }
        }
    }

    public function searchIp($ip)
    {
        foreach ($this->logs as $v) {
            if ($r = fopen("/logs/$v", 'r')) {
                while (feof($r) === false) {
                    $l = fgets($r);
                    if (preg_match('~' . preg_quote($ip) . '~', $l)) {
                        $res[$v][] = $l;
                    }
                }
                fclose($r);
            }
        }
        if (!empty($res)) {
            foreach ($res as $k => $v) {
                $head= "$k:\n";
                $t = array_chunk($v, 10);
                foreach ($t as $j) {
                    $text = "$head<pre>";
                    foreach ($j as $i) {
                        $text .= htmlspecialchars($i, ENT_HTML5, 'UTF-8');
                    }
                    $text .= '</pre>';
                    $this->send($this->input['from'], $text, $this->input['message_id']);
                }
            }
        } else {
            $this->answer($this->input['callback_id'], 'empty');
        }
    }

    public function searchSuspiciousIp($ip)
    {
        $t = [
            $this->suspicious('~\d+\.\d+\.\d+\.\d+.+200\s\d+\s0$~', '/logs/upstream_access', "$ip/32", 'possibly a Reality Degenerate'),
            $this->suspicious($this->reg, '/logs/nginx_default_access', "$ip/32", 'possibly a scanner', true),
            $this->suspicious($this->reg, '/logs/nginx_domain_access', "$ip/32", 'possibly a scanner', true),
        ];
        foreach ($t as $r) {
            if (!empty($r)) {
                foreach ($r as $v) {
                    foreach ($v as $k) {
                        $logs[$k['title']][] = $k['log'];
                    }
                }
            }
        }
        if (!empty($logs)) {
            foreach ($logs as $k => $v) {
                $head= "$k:\n";
                $t = array_chunk($v, 10);
                foreach ($t as $j) {
                    $text = "$head<pre>";
                    foreach ($j as $i) {
                        $text .= htmlspecialchars($i, ENT_HTML5, 'UTF-8');
                    }
                    $text .= '</pre>';
                    $this->send($this->input['from'], $text, $this->input['message_id']);
                }
            }
        } else {
            $this->answer($this->input['callback_id'], 'empty');
        }
    }

    public function importIps($type)
    {
        switch ($type) {
            case 'telegram':
                $r = file_get_contents('https://core.telegram.org/resources/cidr.txt');
                if (!empty($r)) {
                    $domains = explode("\n", $r);
                }
                break;
            case 'gcore':
                $r = json_decode(file_get_contents('https://api.gcore.com/cdn/public-ip-list'), true);
                if (!empty($r['addresses'])) {
                    $domains = $r['addresses'];
                }
                break;
            case 'cloudflare':
                $r = json_decode(file_get_contents('https://api.cloudflare.com/client/v4/ips'), true);
                if (!empty($r['result']['ipv4_cidrs'])) {
                    $domains = $r['result']['ipv4_cidrs'];
                }
                break;
        }
        if (!empty($domains = array_filter($domains ?: [], fn($e) => preg_match('~^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}~', $e)))) {
            $this->addInclude(implode(',', $domains), 'white');
        }
    }

    public function denyList($page = 0, $white = 0)
    {
        $text    = 'Menu -> IP -> ' . ($white ? 'ignore' : 'block') . 'list';
        $domains = $this->getPacConf()[$white ? 'white' : 'deny'] ?: [];
        $all     = (int) ceil(count($domains) / $this->limit);
        $page    = min($page, $all - 1);
        $page    = $page < 0 ? $all - 1 : $page;

        if (!empty($white)) {
            $data[] = [
                [
                    'text'          => $this->i18n('telegram IPs'),
                    'callback_data' => "/importIps telegram",
                ],
            ];
            $data[] = [
                [
                    'text'          => $this->i18n('gcore IPs'),
                    'callback_data' => "/importIps gcore",
                ],
            ];
            $data[] = [
                [
                    'text'          => $this->i18n('cloudflare IPs'),
                    'callback_data' => "/importIps cloudflare",
                ],
            ];
        }
        $data[] = [
            [
                'text'          => $this->i18n('add'),
                'callback_data' => "/include " . ($white ? 'white' : 'deny'),
            ],
        ];
        if (!empty($domains)) {
            foreach (array_slice($domains, $page * $this->limit, $this->limit) as $v) {
                $data[] = [
                    [
                        'text'          => $v,
                        'callback_data' => "/searchLogs $v denyList $page $white",
                    ],
                    [
                        'text'          => $this->i18n('delete'),
                        'callback_data' => "/allowIp $v $page" . ($white ? " 1" : ''),
                    ],
                ];
            }
            if ($all > 1) {
                $data[] = [
                    [
                        'text'          => '<<',
                        'callback_data' => "/denyList " . ($page - 1 >= 0 ? $page - 1 : $all - 1) . ($white ? " 1" : ' 0'),
                    ],
                    [
                        'text'          => $page + 1,
                        'callback_data' => "/denyList $page" . ($white ? " 1" : ' 0'),
                    ],
                    [
                        'text'          => '>>',
                        'callback_data' => "/denyList " . ($page < $all - 1 ? $page + 1 : 0) . ($white ? " 1" : ' 0'),
                    ],
                ];
            }
            $data[] = [
                [
                    'text'          => $this->i18n('delete all'),
                    'callback_data' => "/cleanDeny" . ($white ? " 1" : ''),
                ],
            ];
        }

        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/ipMenu",
            ],
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            $text,
            $data ?: false,
        );
    }

    public function cleanDeny($white = 0)
    {
        $pac = $this->getPacConf();
        unset($pac[$white ? 'white' : 'deny']);
        $this->setPacConf($pac);
        $this->syncDeny();
        $this->ipMenu();
    }

    public function denyIp($ip, $fun = false, $page = 0, $white = 0)
    {
        $pac = $this->getPacConf();
        if (is_array($ip)) {
            foreach ($ip as $v) {
                $pac['deny'][] = $v;
                if (($t = array_search($v, $pac['white'] ?: [])) !== false) {
                    unset($pac['white'][$t]);
                }
            }
        } else {
            $pac['deny'][] = $ip;
            if (($t = array_search($ip, $pac['white'] ?: [])) !== false) {
                unset($pac['white'][$t]);
            }
        }
        $this->setPacConf($pac);
        if (empty($fun)) {
            $this->delete($this->input['from'], $this->input['message_id']);
        }
        $this->syncDeny();
        if (!empty($fun)) {
            $this->{$fun}($page, $white);
        }
    }

    public function whiteIp($ip, $fun = false, $page = 0, $white = 0)
    {
        $pac = $this->getPacConf();
        if (is_array($ip)) {
            foreach ($ip as $v) {
                $pac['white'][] = $v;
                if (($t = array_search($v, $pac['deny'] ?: [])) !== false) {
                    unset($pac['deny'][$t]);
                }
            }
        } else {
            $pac['white'][] = $ip;
            if (($t = array_search($ip, $pac['deny'] ?: [])) !== false) {
                unset($pac['deny'][$t]);
            }
        }
        $this->setPacConf($pac);
        if (empty($fun)) {
            $this->delete($this->input['from'], $this->input['message_id']);
        }
        $this->syncDeny();
        if (!empty($fun)) {
            $this->{$fun}($page, $white);
        }
    }

    public function allowIp($ip, $page, $white = 0)
    {
        $pac = $this->getPacConf();
        unset($pac[$white ? 'white' : 'deny'][array_search($ip, $pac[$white ? 'white' : 'deny'])]);
        $this->setPacConf($pac);
        $this->syncDeny();
        $this->denyList($page, $white);
    }

    public function cleanLogs($ip, $nodelete = false)
    {
        foreach ($this->logs as $v) {
            exec("sed -i '/$ip/d' /logs/$v");
        }
        if (empty($nodelete)) {
            $this->delete($this->input['from'], $this->input['message_id']);
        }
    }

    public function syncDeny()
    {
        $pac = $this->getPacConf();
        if ($r = fopen('/logs/nginx_tlgrm_access', 'r')) {
            while (feof($r) === false) {
                $l = fgets($r);
                if (preg_match('~(\d+\.\d+\.\d+\.\d+)~', $l, $m)) {
                    $xr[$m[1]] = true;
                }
            }
            fclose($r);
        }
        $text = '';
        if (!empty($xr)) {
            foreach (array_keys($xr) as $v) {
                $text .= "allow $v;\n";
            }
        }
        if (!empty($pac['white'])) {
            $pac['white'] = array_unique($pac['white']);
            sort($pac['white']);
            foreach ($pac['white'] as $v) {
                $text .= "allow $v;\n";
            }
        }
        if (!empty($pac['deny'])) {
            $pac['deny'] = array_unique($pac['deny']);
            sort($pac['deny']);
            foreach ($pac['deny'] as $k => $v) {
                if (!in_array($v, $pac['white'] ?: []) && !in_array($v, array_keys($xr ?: []))) {
                    $text .= "deny $v;\n";
                } else {
                    unset($pac['deny'][$k]);
                }
            }
        }
        $this->setPacConf($pac);
        file_put_contents('/config/deny', $text ?: '');
        $this->ssh('nginx -s reload', 'up');
    }

    public function linkXray($i, $s = false)
    {
        $c      = $this->getXray();
        $pac    = $this->getPacConf();
        $domain = $this->getDomain($pac['transport'] != 'Reality');
        $scheme = empty($this->nginxGetTypeCert()) ? 'http' : 'https';
        $hash   = $this->getHashBot();
        $fp     = $pac['fingerprint'] ?: 'chrome';
        $si     = "$scheme://{$domain}/pac$hash/" . base64_encode(serialize([
            'h' => $hash,
            't' => 'si',
            's' => $c['inbounds'][0]['settings']['clients'][$i]['id'],
        ]));
        $v2     = "$scheme://{$domain}/pac$hash/" . base64_encode(serialize([
            'h' => $hash,
            't' => 's',
            's' => $c['inbounds'][0]['settings']['clients'][$i]['id'],
        ]));

        switch ($s) {
            case 1:
                return "v2rayng://install-config?url=$v2#{$c['inbounds'][0]['settings']['clients'][$i]['id']}";
            case 2:
                return "sing-box://import-remote-profile/?url={$si}#{$c['inbounds'][0]['settings']['clients'][$i]['email']}";

            default:
                switch ($pac['transport']) {
                    case 'Reality':
                        $link = "vless://{$c['inbounds'][0]['settings']['clients'][$i]['id']}@$domain:443"
                                    . "?security=reality"
                                    . "&sni={$c['inbounds'][0]['streamSettings']['realitySettings']['serverNames'][0]}"
                                    . "&fp=$fp&pbk={$pac['xray']}"
                                    . "&sid={$c['inbounds'][0]['streamSettings']['realitySettings']['shortIds'][0]}"
                                    . "&type=tcp"
                                    . "&flow=xtls-rprx-vision"
                                    . "#{$c['inbounds'][0]['settings']['clients'][$i]['email']}";
                        break;
                    case 'xhttp':
                        $link = "vless://{$c['inbounds'][0]['settings']['clients'][$i]['id']}@$domain:443"
                                    . "?security=tls"
                                    . "&type=xhttp"
                                    . "&headerType="
                                    . "&path=%2Fws$hash"
                                    . "&host=$domain"
                                    . "&flow="
                                    . "&mode=packet-up"
                                    . "&extra=%7B%22xmux%22%3A%7B%22cMaxReuseTimes%22%3A0%2C%22maxConcurrency%22%3A%2216-32%22%2C%22maxConnections%22%3A0%2C%22hKeepAlivePeriod%22%3A0%2C%22hMaxRequestTimes%22%3A%22600-900%22%2C%22hMaxReusableSecs%22%3A%221800-3000%22%7D%2C%22headers%22%3A%7B%7D%2C%22noGRPCHeader%22%3Afalse%2C%22xPaddingBytes%22%3A%22100-1000%22%2C%22scMaxEachPostBytes%22%3A1000000%2C%22scMinPostsIntervalMs%22%3A30%2C%22scStreamUpServerSecs%22%3A%2220-80%22%7D"
                                    . "&sni=$domain"
                                    . "&fp=$fp"
                                    . "&alpn=h2"
                                    . "#{$c['inbounds'][0]['settings']['clients'][$i]['email']}";
                        break;
                    case 'trojan-grpc':
                        $trojanPwd = rawurlencode($c['inbounds'][0]['settings']['clients'][$i]['password']);
                        $link = "trojan://$trojanPwd@$domain:443"
                                    . "?type=grpc"
                                    . "&serviceName=grpc$hash"
                                    . "&security=tls"
                                    . "&sni=$domain"
                                    . "&fp=$fp"
                                    . "#{$c['inbounds'][0]['settings']['clients'][$i]['email']}";
                        break;

                    default:
                        $link =  "vless://{$c['inbounds'][0]['settings']['clients'][$i]['id']}@$domain:443"
                                    . "?flow="
                                    . "&path=%2Fws$hash"
                                    . "&security=tls"
                                    . "&sni=$domain"
                                    . "&fp=$fp"
                                    . "&type=ws"
                                    . "#{$c['inbounds'][0]['settings']['clients'][$i]['email']}";
                        break;
                }
                return $link;

        }
    }

    public function dockerApi($url, $method = 'GET', $data = [])
    {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST    => $method,
            CURLOPT_POSTFIELDS       => !empty($data) ? json_encode($data) : null,
            CURLOPT_URL              => "http://localhost$url",
            CURLOPT_RETURNTRANSFER   => true,
            CURLOPT_UNIX_SOCKET_PATH => '/var/run/docker.sock'
        ]);
        $r = json_decode(curl_exec($ch), true);
        curl_close($ch);
        return $r;
    }

    public function cleanDocker()
    {
        $r = $this->dockerApi('/images/json');
        foreach ($r as $v) {
            if (!empty($v['RepoTags'])) {
                foreach ($v['RepoTags'] as $j) {
                    if (preg_match('~^mercurykd/vpnbot~', $j)) {
                        $i[] = $v['Id'];
                        break;
                    }
                }
            }
        }
        $r = $this->dockerApi('/containers/json?all=1');
        foreach ($r as $v) {
            if (preg_match('~^mercurykd/vpnbot~', $v['Image'])) {
                $c[] = $v['ImageID'];
            }
        }
        if (!empty($d = array_diff($i, $c))) {
            foreach ($d as $v) {
                $this->dockerApi("/images/$v", 'DELETE');
            }
        }
        $this->dockerApi('/images/prune', 'POST', ['dangling' => true]);
        $this->dockerApi('/build/prune', 'POST');
    }

    public function naiveMenu()
    {
        $pac    = $this->getPacConf();
        $domain = $this->getDomain();
        $text[] = "Menu -> NaiveProxy";
        $np     = $this->getHashSubdomain('np');
        $text[] = "<code>https://{$pac['naive']['user']}:{$pac['naive']['pass']}@$np.$domain</code>";
        $data[] = [
            [
                'text'          => $this->i18n('change subdomain'),
                'callback_data' => "/changeNaiveSubdomain",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('change login'),
                'callback_data' => "/changeNaiveUser",
            ],
            [
                'text'          => $this->i18n('change password'),
                'callback_data' => "/changeNaivePass",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/menu",
            ],
        ];
        return [
            'text' => implode("\n", $text),
            'data' => $data,
        ];
    }

    public function hysteriaMenu()
    {
        $pac    = $this->getPacConf();
        $ports  = $this->getPorts();
        $port   = $ports['hy']['enable'] ? $ports['hy']['port'] : null;
        $domain = $this->getDomain();
        $hy     = yaml_parse_file('/config/hysteria.yaml');
        $sni    = parse_url($hy['masquerade']['proxy']['url'] ?? '', PHP_URL_HOST) ?: $domain;
        $pass   = $pac['hysteria_pass'] ?? '';
        $obfsOn = !empty($pac['hysteria_obfs']);
        $obfs   = $pac['hysteria_obfs'] ?? '';
        $insec  = !empty($pac['hysteria_insecure']);
        $bwUp   = $pac['hysteria_bw_up']   ?? '';
        $bwDown = $pac['hysteria_bw_down'] ?? '';
        $cc     = ($bwUp && $bwDown) ? "brutal ($bwUp / $bwDown)" : 'bbr';
        $link   = $this->linkHysteria();

        $text[] = "Menu -> Hysteria";
        $text[] = "server: " . ($port ? "<code>$domain:$port</code>" : 'port unavailable');
        $text[] = "passwd: <code>$pass</code>";
        $text[] = "masq (decoy): <code>$sni</code>";
        $text[] = "obfs: " . ($obfsOn ? "salamander <code>$obfs</code>" : $this->i18n('off'));
        $text[] = "cc: <code>$cc</code>";
        $text[] = "insecure: " . $this->i18n($insec ? 'on' : 'off');
        if ($link) {
            $text[] = "\n<code>$link</code>";
        }
        $data[] = [
            [
                'text'          => $this->i18n('change password'),
                'callback_data' => "/changeHysteriaPass",
            ],
            [
                'text'          => $this->i18n('generate password'),
                'callback_data' => "/genHyPass",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('masquerade') . ": $sni",
                'callback_data' => "/hyMasqMenu",
            ],
        ];
        $obfsRow = [[
            'text'          => 'obfs: ' . $this->i18n($obfsOn ? 'on' : 'off'),
            'callback_data' => "/toggleHyObfs",
        ]];
        if ($obfsOn) {
            $obfsRow[] = [
                'text'          => $this->i18n('generate password'),
                'callback_data' => "/genHyObfs",
            ];
        }
        $data[] = $obfsRow;
        $data[] = [
            [
                'text'          => "cc: $cc",
                'callback_data' => "/changeHyBw",
            ],
            [
                'text'          => 'insecure: ' . $this->i18n($insec ? 'on' : 'off'),
                'callback_data' => "/toggleHyInsecure",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/menu",
            ],
        ];
        return [
            'text' => implode("\n", $text),
            'data' => $data,
        ];
    }

    public function mirrorMenu()
    {
        $ip     = $this->getPacConf()['domain'] ?: $this->ip;
        $text[] = "Menu -> Mirror";
        $text[] = <<<PNG
                    <pre>client -> intermediate VPS -> vpnbot
                                         ^           |
                                         |  install  |
                                         |  mirror   |
                                          -----------
                    </pre>
                    PNG;
        $data[] = [
            [
                'text'          => $this->i18n('download'),
                'callback_data' => "/getMirror",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/menu",
            ],
        ];
        return [
            'text' => implode("\n", $text),
            'data' => $data,
        ];
    }

    public function getMirror()
    {
        $s = file_get_contents('/mirror/start_socat.sh');
        $p = $this->getPorts();
        $t = str_replace([
            '~ip~',
            '~tg~',
            '~ss~',
            '~wg1~',
            '~wg2~',
        ], [
            getenv('IP'),
            $p['tg']['port'],
            $p['ss']['port'],
            $p['wg']['port'],
            $p['wg1']['port'],
        ], $s);
        $this->sendFile($this->input['from'], new CURLStringFile($t, 'socat.sh', 'application/x-sh'));
    }

    public function ocMenu()
    {
        $pac    = $this->getPacConf();
        $domain = $this->getDomain();
        $ocserv = file_get_contents('/config/ocserv.conf');
        preg_match('~^camouflage_secret[^\n]+?"([^"]+)*"~sm', $ocserv, $m);
        $cs = $m[1];
        preg_match('~^dns = ([^\n]+)~sm', $ocserv, $m);
        $dns = $m[1];
        preg_match('~^expose-iroutes = (true)~sm', $ocserv, $m);
        $expose = $m[1];
        $pass   = htmlspecialchars($pac['ocserv']);
        $text[] = "Menu -> OpenConnect";
        if (!empty($cs)) {
            $oc = $this->getHashSubdomain('oc');
            $text[] = "<code>https://$oc.$domain/?$cs</code>";
        }
        $text[] = "password: <span class='tg-spoiler'>$pass</span>";
        $data[] = [
            [
                'text'          => $this->i18n('change subdomain'),
                'callback_data' => "/changeOcDomain",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('change secret'),
                'callback_data' => "/changeCamouflage",
            ],
            [
                'text'          => $this->i18n('change password'),
                'callback_data' => "/changeOcPass",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('dns') . ": $dns",
                'callback_data' => "/changeOcDns",
            ],
        ];
        $data[] = [
            [
                'text'          =>  $this->i18n('listSubnet'),
                'callback_data' => "/subnet 0_0_1",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('expose-iroutes') . ' ' . $this->i18n($expose ? 'on' : 'off'),
                'callback_data' => "/changeOcExpose",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('add peer'),
                'callback_data' => "/addOcUser",
            ],
        ];
        $clients = $this->getClientsOc();
        foreach ($clients as $k => $v) {
            $data[] = [
                [
                    'text'          => $this->i18n('delete') . " $v",
                    'callback_data' => "/deloc $k",
                ],
            ];
        }
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/menu",
            ],
        ];
        return [
            'text' => implode("\n", $text),
            'data' => $data,
        ];
    }

    public function changeOcExpose()
    {
        $c = file_get_contents('/config/ocserv.conf');
        preg_match('~^expose-iroutes = ([^\n]+)~sm', $c, $m);
        $t = preg_replace('~^expose-iroutes[^\n]+~sm', "expose-iroutes = " . ($m[1] == 'true' ? 'false' : 'true'), $c);
        $this->restartOcserv($t);
        $this->menu('oc');
    }

    public function deloc($i)
    {
        $clients = $this->getClientsOc();
        foreach ($clients as $k => $v) {
            if ($i == $k) {
                $this->ssh("ocpasswd -c /etc/ocserv/ocserv.passwd -d $v", 'oc');
                break;
            }
        }
        $this->menu('oc');
    }

    public function delxr($i)
    {
        $r  = $this->getXray();
        $st = $this->getXrayStats();
        foreach ($r['inbounds'][0]['settings']['clients'] as $k => $v) {
            if ($i == $k) {
                $this->deleteHwidUser($r['inbounds'][0]['settings']['clients'][$k]['id']);
                unset($r['inbounds'][0]['settings']['clients'][$k]);
                unset($st['users'][$k]);
                $this->setXrayStats($st);
                $this->restartXray($r);
                $this->adguardXrayClients();
                break;
            }
        }
        $this->xray();
    }

    public function getClientsOc()
    {
        $users = array_filter(explode("\n", file_get_contents('/config/ocserv.passwd')), fn ($e) => !empty($e));
        return array_map(fn($e) => explode(':', $e)[0], $users);
    }

    public function addocus($user)
    {
        $pac = $this->getPacConf();
        $this->ssh("echo '{$pac['ocserv']}' | ocpasswd -c /etc/ocserv/ocserv.passwd $user", 'oc');
        $this->menu('oc');
    }

    public function addxrus($users)
    {
        $c     = $this->getXray();
        $p     = $this->getPacConf();
        $users = array_map(fn ($e) => trim($e), explode(',', $users));
        $users = array_map(fn ($e) => explode(':', $e), $users);
        foreach ($c['inbounds'][0]['settings']['clients'] as $k => $v) {
            $uuids[]  = $v['id'];
            $emails[] = $v['email'];
        }
        foreach ($users as $user) {
            $uuid = $user[1] ?: trim($this->ssh('xray uuid', 'xr'));
            if (in_array($uuid, $uuids ?: []) || in_array($user[0], $emails ?: [])) {
                $this->send($this->input['chat'], "user {$user[0]} already exists");
                return $this->xray();
            }
            $c['inbounds'][0]['settings']['clients'][] = match($p['transport']) {
                'Reality'     => ['id' => $uuid, 'flow' => 'xtls-rprx-vision', 'email' => $user[0]],
                'trojan-grpc' => ['id' => $uuid, 'password' => bin2hex(random_bytes(16)), 'email' => $user[0]],
                default       => ['id' => $uuid, 'email' => $user[0]],
            };
        }
        $this->restartXray($c);
        $this->adguardXrayClients();
        if (count($users) == 1) {
            $this->userXr(count($c['inbounds'][0]['settings']['clients']) - 1);
        } else {
            $this->xray();
        }
    }

    public function setTimerXr($time, $i)
    {
        $c = $this->getXray();
        if (empty($time)) {
            unset($c['inbounds'][0]['settings']['clients'][$i]['time']);
        } else {
            $time = strtotime($time);
            if ($time === false) {
                $this->send($this->input['chat'], 'wrong format');
                return;
            }
            $c['inbounds'][0]['settings']['clients'][$i]['time'] = $time;
        }
        $this->restartXray($c, 1);
        if (!empty($c['inbounds'][0]['settings']['clients'][$i]['off'])) {
            $this->switchXr($i, 0, 1);
        } else {
            $this->userXr($i);
        }
    }

    public function switchXr($i, $nm = 0, $time = false)
    {
        $c = $this->getXray();
        if (empty($time)) {
            unset($c['inbounds'][0]['settings']['clients'][$i]['time']);
        }
        if (empty($c['inbounds'][0]['settings']['clients'][$i]['off'])) {
            $c['inbounds'][0]['settings']['clients'][$i]['off'] = $c['inbounds'][0]['settings']['clients'][$i]['id'];
            $c['inbounds'][0]['settings']['clients'][$i]['id']  = trim($this->ssh('xray uuid', 'xr'));
            if (isset($c['inbounds'][0]['settings']['clients'][$i]['password'])) {
                $c['inbounds'][0]['settings']['clients'][$i]['off_pwd']  = $c['inbounds'][0]['settings']['clients'][$i]['password'];
                $c['inbounds'][0]['settings']['clients'][$i]['password'] = trim($this->ssh('xray uuid', 'xr'));
            }
        } else {
            $c['inbounds'][0]['settings']['clients'][$i]['id'] = $c['inbounds'][0]['settings']['clients'][$i]['off'];
            if (isset($c['inbounds'][0]['settings']['clients'][$i]['password'])) {
                $c['inbounds'][0]['settings']['clients'][$i]['password'] = $c['inbounds'][0]['settings']['clients'][$i]['off_pwd']
                    ?: $c['inbounds'][0]['settings']['clients'][$i]['off'];
                unset($c['inbounds'][0]['settings']['clients'][$i]['off_pwd']);
            }
            unset($c['inbounds'][0]['settings']['clients'][$i]['off']);
        }
        $this->restartXray($c);
        if (empty($nm)) {
            $this->userXr($i);
        }
    }

    public function changeXrPwd($i)
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter password (or leave empty to auto-generate)",
            $this->input['message_id'],
            reply: 'enter xr password',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'setXrPwd',
            'args'           => [$i],
        ];
    }

    public function setXrPwd($pwd, $i)
    {
        $c        = $this->getXray();
        $password = trim($pwd) ?: bin2hex(random_bytes(16));
        $c['inbounds'][0]['settings']['clients'][$i]['password'] = $password;
        $this->restartXray($c);
        $this->userXr($i);
    }

    // Generate a fresh Reality keypair (matched private/public) + shortId.
    // Same commands/parsing as the initial setup in changeTransport(); the pair
    // comes from a single `xray x25519` call so private and public always match.
    public function genRealityKeys(): array
    {
        $shortId = trim($this->ssh('openssl rand -hex 8', 'xr'));
        $keys    = $this->ssh('xray x25519', 'xr');
        preg_match('~^PrivateKey:\s([^\s]+)~m', $keys, $m);
        $private = trim($m[1] ?? '');
        preg_match('~^Password(?:\s*\(PublicKey\))?:\s([^\s]+)~m', $keys, $m);
        $public  = trim($m[1] ?? '');
        return ['private' => $private, 'public' => $public, 'shortId' => $shortId];
    }

    // Rotate the shared Reality parameters: pbk (keypair) + sid (shortId).
    // Updates pac.json (pbk/privateKey/shortId) and xray.json in lock-step so the
    // server private key matches the public key embedded in every client link.
    // Invalidates all existing links — every client must re-import.
    public function regenRealityXr()
    {
        $x = $this->getXray();
        $p = $this->getPacConf();
        if (empty($x['inbounds'][0]['streamSettings']['realitySettings'])) {
            return $this->answer($this->input['callback_id'], 'reality only', true);
        }
        $k = $this->genRealityKeys();
        if (empty($k['private']) || empty($k['public']) || empty($k['shortId'])) {
            return $this->answer($this->input['callback_id'], 'keygen failed', true);
        }
        $p['xray']                  = $k['public'];
        $p['reality']['privateKey'] = $k['private'];
        $p['reality']['shortId']    = $k['shortId'];
        $x['inbounds'][0]['streamSettings']['realitySettings']['privateKey'] = $k['private'];
        $x['inbounds'][0]['streamSettings']['realitySettings']['shortIds']   = [$k['shortId']];
        $this->setPacConf($p);
        $this->restartXray($x);
        $this->xray();
    }

    // Rotate a single client's UUID (clientID). For an enabled client this is the
    // live credential; for a disabled one the real id lives in 'off' (the active
    // 'id' is a throwaway), so rotate 'off' too. Invalidates only this client.
    public function regenIdXr($i)
    {
        $x = $this->getXray();
        if (!isset($x['inbounds'][0]['settings']['clients'][$i])) {
            return $this->xray();
        }
        if (!empty($x['inbounds'][0]['settings']['clients'][$i]['off'])) {
            $x['inbounds'][0]['settings']['clients'][$i]['off'] = $this->guidv4();
        }
        $x['inbounds'][0]['settings']['clients'][$i]['id'] = $this->guidv4();
        $this->restartXray($x);
        $this->userXr($i);
    }

    // Full rotation: shared Reality pbk+sid (if Reality) AND every client's UUID.
    // One restart, all configs written consistently. Invalidates every link.
    public function regenAllXr()
    {
        $x = $this->getXray();
        $p = $this->getPacConf();
        if (!empty($x['inbounds'][0]['streamSettings']['realitySettings'])) {
            $k = $this->genRealityKeys();
            if (empty($k['private']) || empty($k['public']) || empty($k['shortId'])) {
                return $this->answer($this->input['callback_id'], 'keygen failed', true);
            }
            $p['xray']                  = $k['public'];
            $p['reality']['privateKey'] = $k['private'];
            $p['reality']['shortId']    = $k['shortId'];
            $x['inbounds'][0]['streamSettings']['realitySettings']['privateKey'] = $k['private'];
            $x['inbounds'][0]['streamSettings']['realitySettings']['shortIds']   = [$k['shortId']];
        }
        foreach ($x['inbounds'][0]['settings']['clients'] as $key => $v) {
            if (!empty($v['off'])) {
                $x['inbounds'][0]['settings']['clients'][$key]['off'] = $this->guidv4();
            }
            $x['inbounds'][0]['settings']['clients'][$key]['id'] = $this->guidv4();
        }
        $this->setPacConf($p);
        $this->restartXray($x);
        $this->xray();
    }

    public function renXrUs($name, $i)
    {
        $c = $this->getXray();
        $c['inbounds'][0]['settings']['clients'][$i]['email'] = $name;
        $this->restartXray($c);
        $this->adguardXrayClients();
        $this->userXr($i);
    }

    public function getXrayStats()
    {
        return json_decode(file_get_contents('/config/xray.stats'), true) ?: [];
    }

    public function setXrayStats($x)
    {
        file_put_contents('/config/xray.stats', json_encode($x));
    }

    public function resetXrUser($i)
    {
        $c = $this->getXrayStats();
        unset($c['users'][$i]);
        $this->restartXray($this->getXray());
        $this->userXr($i);
    }

    public function resetXrStats($nomenu = false)
    {
        $this->restartXray($this->getXray());
        $this->setXrayStats([]);
        if (empty($nomenu)) {
            $this->xray();
        }
    }

    public function listXr($i)
    {
        $c = $this->getPacConf();
        $c['xtlslist'] = $i;
        $this->setPacConf($c);
        $this->xray();
    }

    public function templateAdd($type)
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} send the template file:",
            $this->input['message_id'],
            reply: 'send the template file:',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'addTemplate',
            'args'           => [$type],
        ];
    }

    public function autoScanTimeout()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} send time like 1 hour or 1 day etc",
            $this->input['message_id'],
            reply: 'send time like 1 hour or 1 day etc',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'setAutoScanTimeout',
            'args'           => [],
        ];
    }

    public function setAutoScanTimeout($time)
    {
        $pac = $this->getPacConf();
        if (empty($time)) {
            unset($pac['autoscan_timeout']);
            unset($pac['autoscan']);
        } elseif ($t = strtotime($time, 0)) {
            $pac['autoscan_timeout'] = $t;
            $pac['autoscan'] = 1;
        } else {
            $this->send($this->input['from'], "$time - wrong format", $this->input['message_id']);
        }
        $this->setPacConf($pac);
        $this->ipMenu();
    }

    public function templateCopy($type)
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} send the template name",
            $this->input['message_id'],
            reply: 'send the template name',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'copyTemplate',
            'args'           => [$type],
        ];
    }

    public function addTemplate($n, $type)
    {
        if (empty($this->input['caption'])) {
            $this->send($this->input['chat'], 'empty name');
            return;
        }
        $r    = $this->request('getFile', ['file_id' => $this->input['file_id']]);
        $json = json_decode(file_get_contents($this->file . $r['result']['file_path']), true);
        if ($json === false) {
            $this->send($this->input['chat'], 'wrong format');
            return;
        }
        $pac = $this->getPacConf();
        $pac["{$type}templates"][$this->input['caption']] = $json;
        $this->setPacConf($pac);
        $this->templates($type);
    }

    public function saveTemplate($name, $type, $json)
    {
        if (json_decode($json, true) === false) {
            return [
                'status'  => false,
                'message' => 'wrong format',
            ];
        }
        $pac = $this->getPacConf();
        switch ($name) {
            case 'origin':
                file_put_contents("/config/$type.json", json_encode(json_decode($json, true), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
                break;

            default:
                $pac["{$type}templates"][$name] = json_decode($json, true);
                break;
        }
        $this->setPacConf($pac);
        return [
            'status' => true,
        ];
    }

    public function delTemplate($type, $name)
    {
        $pac = $this->getPacConf();
        unset($pac["{$type}templates"][base64_decode($name)]);
        $this->setPacConf($pac);
        $this->templates($type);
    }

    public function copyTemplate($name, $type)
    {
        $pac  = $this->getPacConf();
        $pac["{$type}templates"][$name] = json_decode(file_get_contents("/config/$type.json"), true);
        $this->setPacConf($pac);
        $this->templates($type);
    }

    public function downloadOrigin($type)
    {
        $f = new \CURLFile("/config/$type.json", 'application/json', 'origin.json');
        $this->sendFile($this->input['chat'], $f);
    }

    public function downloadTemplate($type, $name)
    {
        $pac = $this->getPacConf();
        $f = new \CURLStringFile(json_encode($pac["{$type}templates"][base64_decode($name)], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), base64_decode($name) . '.json', 'application/json');
        $this->sendFile($this->input['chat'], $f);
    }

    public function defaultTemplate($type, $name)
    {
        $pac = $this->getPacConf();
        if (!empty($name)) {
            $pac["default{$type}template"] = $name;
        } else {
            unset($pac["default{$type}template"]);
        }
        $this->setPacConf($pac);
        $this->templates($type);
    }

    public function templates($type)
    {
        $pac    = $this->getPacConf();
        $domain = $this->getDomain();
        $hash   = $this->getHashBot();
        $text[] = "Menu -> " . $this->i18n('xray') . " -> " . $this->i18n($type) . " templates";
        $text[] = <<<TEXT
            <code>~outbound~</code>
            <code>~pac~</code>
            <code>~package~</code>
            <code>~process~</code>
            <code>~subnet~</code>
            <code>~block~</code>
            <code>~warp~</code>
            <code>~dns~</code>
            <code>~dnspath~</code>
            <code>~uid~</code>
            <code>~domain~</code>
            <code>~directdomain~</code>
            <code>~cdndomain~</code>
            <code>~short_id~</code>
            <code>~email~</code>
            <code>~public_key~</code>
            <code>~server_name~</code>
            <code>~ip~</code>
            TEXT;
        $templates = $pac["{$type}templates"];

        $data[] = [
            [
                'text'          => $this->i18n('add'),
                'callback_data' => "/templateAdd $type",
            ],
        ];
        $data[] = [
            [
                'text'          => "origin",
                'web_app' => ['url' => "https://$domain/pac$hash?t=te&ty=$type"],
            ],
            [
                'text'          => $this->i18n('download'),
                'callback_data' => "/downloadOrigin $type",
            ],
            [
                'text'          => $this->i18n('copy'),
                'callback_data' => "/templateCopy $type",
            ],
            [
                'text'          => $this->i18n($pac["default{$type}template"] && !empty($pac["{$type}templates"][base64_decode($pac["default{$type}template"])]) ? 'off' : 'on'),
                'callback_data' => "/defaultTemplate $type",
            ],
        ];
        foreach ($templates as $k => $v) {
            $data[] = [
                [
                    'text'          => $k,
                    'web_app' => ['url' => "https://$domain/pac$hash?t=te&ty=$type&te=" . urlencode($k)],
                ],
                [
                    'text'          => $this->i18n('download'),
                    'callback_data' => "/downloadTemplate $type " . base64_encode($k),
                ],
                [
                    'text'          => $this->i18n('delete'),
                    'callback_data' => "/delTemplate $type " . base64_encode($k),
                ],
                [
                    'text'          => $this->i18n($pac["default{$type}template"] == base64_encode($k) ? 'on' : 'off'),
                    'callback_data' => "/defaultTemplate $type " . base64_encode($k),
                ],
            ];
        }

        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/xray",
            ],
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            implode("\n", $text ?: ['...']),
            $data ?: false,
        );
    }

    public function mainOutbound()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} send name",
            $this->input['message_id'],
            reply: 'send name',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'setMainOutbound',
            'args'           => [],
        ];
    }

    public function setMainOutbound($text)
    {
        $pac = $this->getPacConf();
        if (!empty($text)) {
            $pac['outbound'] = $text;
        } else {
            unset($pac['outbound']);
        }
        $this->setPacConf($pac);
        $this->xray();
    }

    public function getBytes($bytes)
    {
        $t = [
            'B',
            'KB',
            'MB',
            'GB',
            'TB',
        ];
        foreach ($t as $k => $v) {
            if ($k == 0) {
                continue;
            }
            if ($bytes / (1024 ** $k) < 1) {
                return round($bytes / (1024 ** ($k - 1)), 2) . " {$t[$k - 1]}";
            }
        }
    }

    public function xray($page = 0)
    {
        $c      = $this->getXray();
        $p      = $this->getPacConf();
        $text[] = "Menu -> " . $this->i18n('xray');
        if (!empty($c['inbounds'][0]['streamSettings']['realitySettings']['serverNames'][0])) {
            $text[] = "fake domain: <code>{$c['inbounds'][0]['streamSettings']['realitySettings']['serverNames'][0]}</code>";
        }
        $text[] = 'transport: ' . ($p['transport'] ?: 'Websocket');
        $text[] = 'fingerprint: ' . ($p['fingerprint'] ?: 'chrome');
        $st = $this->getXrayStats();
        $td = $this->getBytes($st['global']['download'] + $st['session']['download']);
        $tu = $this->getBytes($st['global']['upload'] + $st['session']['upload']);
        $text[] = "↓$td  ↑$tu";
        $data[] = [
            [
                'text'          => $this->i18n('reset stats'),
                'callback_data' => '/resetXrStats',
            ],
            [
                'text'          => $this->i18n('reset monthly') . ": " . $this->i18n(!empty($this->getPacConf()['reset_monthly']) ? 'on' : 'off'),
                'callback_data' => '/switchMonthlyStats',
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('main outbound name: ') . ($p['outbound'] ?? 'proxy'),
                'callback_data' => '/mainOutbound',
            ],
        ];
        $data[] = [
            [
                'text'          => $p['linkdomain'] ?? $this->i18n('cdn'),
                'callback_data' => '/addLinkDomain',
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('RLTY') . ' ' . ($p['transport'] == 'Reality' ? $this->i18n('on') : $this->i18n('off')),
                'callback_data' => "/changeTransport Reality",
            ],
            [
                'text'          => $this->i18n('WS') . ' ' . ($p['transport'] == 'Websocket' ? $this->i18n('on') : $this->i18n('off')),
                'callback_data' => "/changeTransport Websocket",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('XHTTP') . ' ' . ($p['transport'] == 'xhttp' ? $this->i18n('on') : $this->i18n('off')),
                'callback_data' => "/changeTransport xhttp",
            ],
            [
                'text'          => 'Trojan-gRPC ' . ($p['transport'] == 'trojan-grpc' ? $this->i18n('on') : $this->i18n('off')),
                'callback_data' => "/changeTransport trojan-grpc",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('fingerprint') . ': ' . ucfirst($p['fingerprint'] ?: 'chrome'),
                'callback_data' => "/fingerprintMenu",
            ],
        ];

        $ip_count      = $p['ip_count'] ?: 1;
        $hwidEnabled   = !empty($p['hwid_limit_enabled']);
        $defaultHwids  = max(1, (int) ($p['hwid_device_count'] ?: 1));
        $data[] = [
            [
                'text'          => $this->i18n('ip limit') . ' ' . (!empty($p['ip_limit']) ? ": {$p['ip_limit']} sec & $ip_count" : $this->i18n('off')),
                'callback_data' => "/setIpLimit",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('hwid limit') . ': ' . $this->i18n($hwidEnabled ? 'on' : 'off') . " ({$defaultHwids})",
                'callback_data' => '/toggleHwidLimit xray',
            ],
            [
                'text'          => $this->i18n('set hwid devices count'),
                'callback_data' => '/setHwidDevices xray',
            ],
        ];
        if ($p['transport'] == 'Reality') {
            $data[] = [
                [
                    'text'          => $this->i18n('changeFakeDomain'),
                    'callback_data' => "/changeFakeDomain",
                ],
                [
                    'text'          => $this->i18n('selfFakeDomain'),
                    'callback_data' => "/selfFakeDomain",
                ],
            ];
            $data[] = [
                [
                    'text'          => '🔄 ' . $this->i18n('rotate all'),
                    'callback_data' => "/regenAllXr",
                ],
                [
                    'text'          => '🔑 pbk+sid',
                    'callback_data' => "/regenRealityXr",
                ],
            ];
        }
        $data[] = [
            [
                'text'          => $this->i18n('v2ray templates'),
                'callback_data' => "/templates v2ray",
            ],
            [
                'text'          => $this->i18n('sing-box templates'),
                'callback_data' => "/templates sing",
            ],
            [
                'text'          => $this->i18n('mihomo templates'),
                'callback_data' => "/templates clash",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('routes'),
                'callback_data' => "/routes",
            ],
            [
                'text'          => $this->i18n('tun lists'),
                'callback_data' => "/tun",
            ],
        ];
        $on = $off = 0;
        foreach ($c['inbounds'][0]['settings']['clients'] as $k => $v) {
            if (!empty($v['off'])) {
                $off++;
            } else {
                $on++;
            }
        }
        $type    = !empty($this->getPacConf()['xtlslist']);
        $clients = array_filter($c['inbounds'][0]['settings']['clients'], fn($e) => !$type ? empty($e['off']) : !empty($e['off']));
        uasort($clients, fn($a, $b) => ($a['time'] ?: PHP_INT_MAX) <=> ($b['time'] ?: PHP_INT_MAX));

        $wg  = json_decode(file_get_contents($this->clients), true) ?: [];
        $wg1 = json_decode(file_get_contents($this->clients1), true) ?: [];

        foreach ($wg as $k => $v) {
            $wg_clients[$v['interface']['PrivateKey']] = [
                'container' => '1',
                'name'      => $v['interface']['## name'],
            ];
        }
        foreach ($wg1 as $k => $v) {
            $wg_clients[$v['interface']['PrivateKey']] = [
                'container' => '2',
                'name'      => $v['interface']['## name'],
            ];
        }

        $all     = (int) ceil(count($clients) / $this->limit);
        $page    = min($page, $all - 1);
        $page    = $page == -2 ? $all - 1 : $page;
        $clients = $page != -1 ? array_slice($clients, $page * $this->limit, $this->limit, true) : $clients;
        foreach ($clients as $k => $v) {
            $download = $this->getBytes($st['users'][$k]['global']['download'] + $st['users'][$k]['session']['download']);
            $upload   = $this->getBytes($st['users'][$k]['global']['upload'] + $st['users'][$k]['session']['upload']);
            $time     = !empty($v['time']) ? $this->getTime($v['time']) : '';
            $data[]   = [
                [
                    'text'          => "{$v['email']}" . ($time ? ": $time" : '') . " (↓$download  ↑$upload)" . (!empty($v['awg']) ? " {$wg_clients[$v['awg']]['container']}-{$wg_clients[$v['awg']]['name']}" : ''),
                    'callback_data' => "/userXr $k",
                ],
            ];
        }
        if ($page != -1 && $all > 1) {
            $data[] = [
                [
                    'text'          => '<<',
                    'callback_data' => "/xray " . ($page - 1 >= 0 ? $page - 1 : $all - 1),
                ],
                [
                    'text'          => $page + 1,
                    'callback_data' => "/xray $page",
                ],
                [
                    'text'          => '>>',
                    'callback_data' => "/xray " . ($page < $all - 1 ? $page + 1 : 0),
                ],
            ];
        }
        $data[] = [
            [
                'text'          => $this->i18n('add'),
                'callback_data' => "/addXrUser",
            ],
            [
                'text'          => $this->i18n('on') . " $on " . (!$type ? "✅" : ''),
                'callback_data' => "/listXr 0",
            ],
            [
                'text'          => $this->i18n('off') . " $off " . ($type ? "✅" : ''),
                'callback_data' => "/listXr 1",
            ],
        ];
        $onlineCount = count($this->onlineClients());
        $data[] = [
            [
                'text'          => '👥 ' . $this->i18n('online') . ($onlineCount ? " ($onlineCount)" : ''),
                'callback_data' => "/onlines",
            ],
        ];

        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/menu",
            ],
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            implode("\n", $text ?: ['...']),
            $data ?: false,
        );
    }

    public function routes()
    {
        $text[] = "Menu -> " . $this->i18n('xray') . ' -> routes';

        $data = [
            [[
                'text'          => $this->i18n('block'),
                'callback_data' => "/xtlsblock",
            ]],
            [[
                'text'          => $this->i18n('warp'),
                'callback_data' => "/xtlswarp",
            ]],
            [[
                'text'          => 'domains',
                'callback_data' => "/xtlsproxy",
            ]],
            [[
                'text'          => "subnet",
                'callback_data' => "/xtlssubnet",
            ]],
            [[
                'text'          => 'process',
                'callback_data' => "/xtlsprocess",
            ]],
            [[
                'text'          => 'package',
                'callback_data' => "/xtlsapp",
            ]],
            [[
                'text'          => $this->i18n('rulesset'),
                'callback_data' => "/xtlsrulesset",
            ]],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/xray",
            ],
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            implode("\n", $text ?: ['...']),
            $data ?: false,
        );
    }

    public function tun()
    {
        $text[] = "Menu -> " . $this->i18n('xray') . ' -> ' . $this->i18n('tun lists');

        $c = $this->getPacConf();

        $data = [
            [
                [
                    'text'          => $this->i18n('package'),
                    'callback_data' => "/tunpackage",
                ],
                [
                    'text'          => 'mode: ' . $this->i18n(!empty($c['tunpackagemode']) ? 'exclude' : 'include'),
                    'callback_data' => "/tunpackagemode",
                ],
            ],
            [
                [
                    'text'          => $this->i18n('process'),
                    'callback_data' => "/tunprocess",
                ],
                [
                    'text'          => 'mode: ' . $this->i18n(!empty($c['tunprocessmode']) ? 'exclude' : 'include'),
                    'callback_data' => "/tunprocessmode",
                ],
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/xray",
            ],
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            implode("\n", $text ?: ['...']),
            $data ?: false,
        );
    }

    public function warpPlus()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter key",
            $this->input['message_id'],
            reply: 'enter key',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'addWarpPlus',
            'args'           => [],
        ];
    }

    public function addWarpPlus($key)
    {
        $c    = $this->getPacConf();
        $chat = $this->input['chat'];
        $log  = '';

        $step = function($label, $cmd, $container) use ($chat, &$log) {
            $log .= "$label...";
            $this->sendDraft($chat, 1, $log);
            $out = trim($this->ssh($cmd, $container));
            $log .= $out ? "\n$out\n" : " ok\n";
            $this->sendDraft($chat, 1, $log);
            return empty($out); // true = success (no output = exit 0)
        };

        if (!$step('stopping warp', 'wg-quick down /etc/warp/wgcf-profile.conf 2>/dev/null || true', 'wp')) {
            $this->send($chat, $log);
            return;
        }

        // Удаляем старые профиль и аккаунт
        if (!$step('removing old profile', 'rm -f /etc/warp/wgcf-profile.conf /etc/warp/wgcf-account.toml', 'wp')) {
            $this->send($chat, $log);
            return;
        }

        // Регистрируем новый аккаунт
        if (!$step('[warp] Registering WARP account...', 'cd /etc/warp && wgcf register --accept-tos', 'wp')) {
            $this->send($chat, $log);
            return;
        }

        if (!empty($key)) {
            $key = trim($key);
            // WARP keys are alphanumeric + dashes only; reject anything else so the
            // value can't break out of the sed/shell command below (it is interpolated raw).
            if (!preg_match('~^[A-Za-z0-9-]+$~', $key)) {
                $this->send($chat, $log . "invalid license key format\n");
                return;
            }
            $c['warp'] = $key;
            // Заменяем ключ в wgcf-account.toml
            if (!$step('setting license key', "sed -i 's/^license_key.*/license_key = \"$key\"/' /etc/warp/wgcf-account.toml", 'wp')) {
                $this->send($chat, $log);
                return;
            }
            // Обновляем аккаунт с ключом
            if (!$step('applying license key', 'cd /etc/warp && wgcf update', 'wp')) {
                $this->send($chat, $log);
                return;
            }
        } else {
            unset($c['warp']);
        }
        $this->setPacConf($c);

        if (!$step('generating profile', 'cd /etc/warp && wgcf generate', 'wp')) {
            $this->send($chat, $log);
            return;
        }
        $this->ssh("sed -i '/^Address.*:/d' /etc/warp/wgcf-profile.conf", 'wp');
        $this->ssh("sed -i '/^AllowedIPs.*::/d' /etc/warp/wgcf-profile.conf", 'wp');

        $started = $step('starting warp', 'out=$(wg-quick up /etc/warp/wgcf-profile.conf 2>&1 | grep -v "skip sysctl"); ec=${PIPESTATUS[0]}; [ "$ec" -ne 0 ] && printf "%s" "$out"; exit $ec', 'wp');

        if (!$started) {
            $this->send($chat, $log);
            return;
        }

        sleep(1);
        // sendMessageDraft closes only when sendMessage is called — send a dummy and delete it
        $r = $this->send($chat, '.');
        if (!empty($r['result']['message_id'])) {
            $this->delete($chat, $r['result']['message_id']);
        }

        $this->warp();
    }

    public function warpStatus()
    {
        $st = $this->ssh('curl -m 1 -x socks5://wp:1080 https://cloudflare.com/cdn-cgi/trace', 'xr');
        preg_match('~warp=(\w+)~', $st, $m);
        return trim($m[1]) ?: 'off';
    }

    public function analyzeXray()
    {
        while (true) {
            if (!empty($this->getPacConf()['ip_limit'])) {
                $this->pool = [];
                $log = '/logs/xray';
                $r   = fopen($log, 'r');
                fseek($r, 0, SEEK_END);
                while (true) {
                    $pac = $this->getPacConf();
                    if (empty($pac['ip_limit'])) {
                        break;
                    }
                    $currentPosition = ftell($r);
                    clearstatcache();
                    $fileSize = filesize($log);
                    if ($fileSize > $currentPosition) {
                        fseek($r, $currentPosition); // сброс флага feof
                        while (!feof($r)) {
                            $line = fgets($r);
                            if ($line !== false) {
                                $this->frequencyAnalyze($line, $pac);
                            }
                        }
                    }
                    sleep(1);
                }
                fclose($r);
            }
            sleep(10);
        }
    }

    public function frequencyAnalyze($line, $pac)
    {
        if (!empty($this->pool)) {
            foreach ($this->pool as $i => $j) {
                if (!empty($j['ips'])) {
                    foreach ($j['ips'] as $k => $v) {
                        if ($v + $pac['ip_limit'] < time()) {
                            unset($this->pool[$i]['ips'][$k]);
                        }
                    }
                }
            }
        }
        if (empty(preg_match('~(?<date>.+)\sfrom\s(?<ip>\d+\.\d+\.\d+\.\d+)(?=.+email:\s(?<email>.+))~', $line, $m))) {
            return;
        }
        if (!empty($m['ip']) && !empty($m['email'])) {
            $ip = ip2long($m['ip']);
            if (!empty($this->pool[$m['email']]['ip']) && $this->pool[$m['email']]['ip'] != $ip) {
                $this->pool[$m['email']]['ips'][$ip] = time();
            }
            if (!empty($this->pool[$m['email']]['ips']) && count($this->pool[$m['email']]['ips']) > ($pac['ip_count'] ?: 1)) {
                $xr = $this->getXray();
                foreach ($xr['inbounds'][0]['settings']['clients'] as $k => $v) {
                    if (empty($v['off']) && $v['email'] == $m['email']) {
                        require __DIR__ . '/config.php';
                        foreach ($c['admin'] as $admin) {
                            $this->send($admin, "vless: {$m['email']} limit ip " . count($this->pool[$m['email']]['ips']) . ' > ' . ($pac['ip_count'] ?: 1), button: [[
                                [
                                    'text'          => $this->i18n($c['off'] ? 'off' : 'on'),
                                    'callback_data' => "/switchXr $k",
                                ],
                            ]]);
                        }
                        unset($this->pool[$m['email']]);
                        break;
                    }
                }
            }
            $this->pool[$m['email']]['ip'] = $ip;
        }
    }

    public function offWarp()
    {
        $p    = $this->getPacConf();
        if (!empty($this->selfupdate)) {
            if (!empty($p['warpoff'])) {
                $this->ssh('warp-cli --accept-tos registration delete 2>&1', 'wp');
                $this->ssh('pkill warp-svc', 'wp');
            }
        } elseif (!empty($p['warpoff'])) {
            $this->ssh('warp-svc > /dev/null 2>&1 &', 'wp');
            sleep(3);
            if (empty($this->ssh('[ -f "/var/lib/cloudflare-warp/conf.json" ] && echo 1', 'wp'))) {
                $this->send($this->input['chat'], 'Registration: ' . $this->ssh('warp-cli --accept-tos registration new 2>&1', 'wp'));
                if (!empty($p['warp'])) {
                    $this->send($this->input['chat'], 'License: ' . $this->ssh("warp-cli --accept-tos registration license {$p['warp']} 2>&1", 'wp'));
                }
            }
            $this->send($this->input['chat'], 'Proxy mode: ' . $this->ssh('warp-cli --accept-tos mode proxy 2>&1', 'wp'));
            $this->send($this->input['chat'], 'Connect: ' . $this->ssh('warp-cli --accept-tos connect 2>&1', 'wp'));
            unset($p['warpoff']);
        } else {
            $this->send($this->input['chat'], 'Registration delete: ' . $this->ssh('warp-cli --accept-tos registration delete 2>&1', 'wp'));
            $this->ssh('pkill warp-svc', 'wp');
            $p['warpoff'] = 1;
        }
        $this->setPacConf($p);
        if (empty($this->selfupdate)) {
            $this->warp();
        }
    }

    public function warp()
    {
        $p      = $this->getPacConf();
        $c      = file_get_contents('/etc/warp/wgcf-profile.conf');
        $a      = file_get_contents('/etc/warp/wgcf-account.toml');
        $text[] = "Menu -> " . $this->i18n('warp');
        $text[] = "status: <pre>" . $this->ssh('wgcf trace', 'wp') . '</pre>';
        $text[] = "key: <code>{$p['warp']}</code>";
        $text[] = "<pre>$a</pre>";
        $text[] = "<pre>$c</pre>";
        $data[] = [
            [
                'text'          => $this->i18n('set key'),
                'callback_data' => "/warpPlus",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/menu",
            ],
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            implode("\n", $text ?: ['...']),
            $data ?: false,
        );
    }

    public function choiceTemplate($arg)
    {
        $arg = explode('_', $arg);
        $c   = $this->getXray();
        if (!empty($arg[2])) {
            $c['inbounds'][0]['settings']['clients'][$arg[1]]["{$arg[0]}template"] = $arg[2];
        } else {
            unset($c['inbounds'][0]['settings']['clients'][$arg[1]]["{$arg[0]}template"]);
        }
        file_put_contents('/config/xray.json', json_encode($c, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        $this->userXr($arg[1]);
    }

    public function templateUser($type, $i)
    {
        $c         = $this->getXray();
        $pac       = $this->getPacConf();
        $text[]    = "Menu -> " . $this->i18n('xray') . " -> {$c['inbounds'][0]['settings']['clients'][$i]['email']}\n";
        $templates = $pac["{$type}templates"];
        $data[]    = [
            [
                'text'          => 'default',
                'callback_data' => "/choiceTemplate {$type}_$i",
            ],
        ];
        $data[] = [
            [
                'text'          => 'origin',
                'callback_data' => "/choiceTemplate {$type}_{$i}_" . base64_encode('origin'),
            ],
        ];
        foreach ($templates as $k => $v) {
            $data[] = [
                [
                    'text'          => $k,
                    'callback_data' => "/choiceTemplate {$type}_{$i}_" . base64_encode($k),
                ],
            ];
        }
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/userXr $i",
            ],
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            implode("\n", $text ?: ['...']),
            $data ?: false,
        );
    }

    public function userXr($i)
    {
        $xray   = $this->getXray();
        $c      = $xray['inbounds'][0]['settings']['clients'][$i];
        $pac    = $this->getPacConf();
        $domain = $this->getDomain($pac['transport'] != 'Reality');
        $scheme = empty($this->nginxGetTypeCert()) ? 'http' : 'https';
        $hash   = $this->getHashBot();

        $devices      = $this->getHwidDevicesByUser($c['id']);
        $hwidEnabled  = !empty($pac['hwid_limit_enabled']) && empty($c['hwid_disabled']);
        $defaultHwid  = max(1, (int) ($pac['hwid_device_count'] ?: 1));
        $hwidLimit    = $c['hwid_limit'] ? (int) $c['hwid_limit'] : $defaultHwid;

        $text[] = "Menu -> " . $this->i18n('xray') . " -> {$c['email']}\n";
        if (file_exists(__DIR__ . '/subscription.php')) {
            $text[] = "<a href='$scheme://{$domain}/pac$hash/sub?id={$c['id']}'>subscription</a>";
        }
        $text[] = "<pre><code>{$this->linkXray($i)}</code></pre>\n";

        $text[] = "<a href='$scheme://{$domain}/pac$hash?t=s&r=v&s={$c['id']}#{$c['email']}'>import://v2rayng</a>";
        $text[] = "<a href='$scheme://{$domain}/pac$hash?t=si&r=si&s={$c['id']}#{$c['email']}'>import://sing-box</a>";
        $text[] = "<a href='$scheme://{$domain}/pac$hash?t=s&r=st&s={$c['id']}#{$c['email']}'>import://streisand</a>";
        $text[] = "<a href='$scheme://{$domain}/pac$hash?t=si&r=h&s={$c['id']}#{$c['email']}'>import://hiddify</a>";
        $text[] = "<a href='$scheme://{$domain}/pac$hash?t=si&r=k&s={$c['id']}#{$c['email']}'>import://karing</a>";
        $text[] = "<a href='$scheme://{$domain}/pac$hash?t=cl&r=c&s={$c['id']}#{$c['email']}'>import://mihomo</a>";
        $text[] = "<a href='$scheme://{$domain}/pac$hash?t=cl&r=rh&s={$c['id']}#{$c['email']}'>import://rabbit-hole</a>";

        $si = "$scheme://{$domain}/pac$hash/" . base64_encode(serialize([
            'h' => $hash,
            't' => 'si',
            's' => $c['id'],
        ]));
        $xr = "$scheme://{$domain}/pac$hash/" . base64_encode(serialize([
            'h' => $hash,
            't' => 's',
            's' => $c['id'],
        ]));
        $cl = "$scheme://{$domain}/pac$hash/" . base64_encode(serialize([
            'h' => $hash,
            't' => 'cl',
            's' => $c['id'],
        ]));

        $text[] = "\nxray config: <pre><code>$xr</code></pre>";
        $text[] = "sing-box config: <pre><code>$si</code></pre>";
        $text[] = "mihomo config: <pre><code>$cl</code></pre>";

        $text[]   = "sing-box windows: <a href='$scheme://{$domain}/pac$hash?t=si&r=w&s={$c['id']}'>windows service</a>";
        $st       = $this->getXrayStats();
        $download = $this->getBytes($st['users'][$i]['global']['download'] + $st['users'][$i]['session']['download']);
        $upload   = $this->getBytes($st['users'][$i]['global']['upload'] + $st['users'][$i]['session']['upload']);
        $data[]   = [
            [
                'text'          => $this->i18n('reset stats') . ": ↓$download  ↑$upload",
                'callback_data' => "/resetXrUser $i",
            ],
        ];
        $data[] = [
            [
                'text'    => $this->i18n('v2ray'),
                'web_app' => ['url' => "https://{$domain}/pac$hash?t=s&s={$c['id']}"]
            ],
            [
                'text'    => $this->i18n('singbox'),
                'web_app' => ['url' => "https://{$domain}/pac$hash?t=si&s={$c['id']}"]
            ],
            [
                'text'    => $this->i18n('mihomo'),
                'web_app' => ['url' => "https://{$domain}/pac$hash?t=cl&s={$c['id']}"]
            ],
        ];
        $data[] = [
            [
                'text'    => $this->i18n('v2ray ⬇️'),
                'callback_data' => "/dw {$i} s",
            ],
            [
                'text'    => $this->i18n('singbox ⬇️'),
                'callback_data' => "/dw {$i} si",
            ],
            [
                'text'    => $this->i18n('mihomo ⬇️'),
                'callback_data' => "/dw {$i} cl",
            ],
        ];
        $data[] = [
            [
                'text'          => $c['time'] ? "timer: " . $this->getTime($c['time']) : $this->i18n('timer'),
                'callback_data' => "/timerXr $i",
            ],
            [
                'text'          => $this->i18n($c['off'] ? 'off' : 'on'),
                'callback_data' => "/switchXr $i",
            ],
        ];
        // clientID (UUID) is the credential for vless transports; for trojan-grpc
        // auth is by password, so the clientID button is pointless there — hide it.
        if ($pac['transport'] != 'trojan-grpc') {
            $data[] = [
                [
                    'text'          => '🆔 ' . $this->i18n('new clientID'),
                    'callback_data' => "/regenIdXr $i",
                ],
            ];
        }
        $singtemplate  = $c['singtemplate'] ? base64_decode($c['singtemplate']) : 'default(' . ($pac['defaultsingtemplate'] && !empty($pac['singtemplates'][base64_decode($pac['defaultsingtemplate'])]) ? base64_decode($pac['defaultsingtemplate']) : 'origin') . ')';
        $v2raytemplate = $c['v2raytemplate'] ? base64_decode($c['v2raytemplate']) : 'default(' . ($pac['defaultv2raytemplate'] && !empty($pac['v2raytemplates'][base64_decode($pac['defaultv2raytemplate'])]) ? base64_decode($pac['defaultv2raytemplate']) : 'origin') . ')';
        $clashtemplate = $c['clashtemplate'] ? base64_decode($c['clashtemplate']) : 'default(' . ($pac['defaultclashtemplate'] && !empty($pac['clashtemplates'][base64_decode($pac['defaultclashtemplate'])]) ? base64_decode($pac['defaultclashtemplate']) : 'origin') . ')';
        $data[]        = [
            [
                'text'          => $this->i18n('v2ray') . ": $v2raytemplate",
                'callback_data' => "/templateUser v2ray $i",
            ],
            [
                'text'          => $this->i18n('singbox') . ": $singtemplate",
                'callback_data' => "/templateUser sing $i",
            ],
            [
                'text'          => $this->i18n('mihomo') . ": $clashtemplate",
                'callback_data' => "/templateUser clash $i",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('qr short'),
                'callback_data' => "/qrXray $i",
            ],
            [
                'text'          => $this->i18n('qr v2ray'),
                'callback_data' => "/qrXray {$i}_1",
            ],
            [
                'text'          => $this->i18n('qr singbox'),
                'callback_data' => "/qrXray {$i}_2",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('hwid limit') . ': ' . ($hwidEnabled ? $hwidLimit : $this->i18n('off')) . ' (' . count($devices) . ')',
                'callback_data' => "/hwidUser $i",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('rename'),
                'callback_data' => "/renameXrUser $i",
            ],
            [
                'text'          => $this->i18n('delete'),
                'callback_data' => "/delxr $i",
            ],
        ];
        if ($pac['transport'] == 'trojan-grpc') {
            $text[] = "\npassword: <span class='tg-spoiler'>{$c['password']}</span>";
            $data[] = [
                [
                    'text'          => $this->i18n('change password'),
                    'callback_data' => "/changeXrPwd $i",
                ],
                [
                    'text'          => $this->i18n('generate password'),
                    'callback_data' => "/genXrPwd $i",
                ],
            ];
        }
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/xray",
            ],
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            implode("\n", $text ?: ['...']),
            $data ?: false,
        );
    }

    public function hwidUser($i, $page = 0)
    {
        $xray   = $this->getXray();
        $client = $xray['inbounds'][0]['settings']['clients'][$i];
        $pac    = $this->getPacConf();

        $devices = $this->getHwidDevicesByUser($client['id']);
        $scope   = $this->getHwidTokenScope($i);
        if (!isset($_SESSION['hwidTokens'])) {
            $_SESSION['hwidTokens'] = [];
        }
        $_SESSION['hwidTokens'][$scope] = [];
        uasort($devices, fn($a, $b) => ($b['time'] ?? 0) <=> ($a['time'] ?? 0));
        $hwids        = array_keys($devices);
        $perPage      = max(1, $this->limit ?: 5);
        $total        = count($hwids);
        $pages        = max(1, (int) ceil($total / $perPage));
        $page         = min(max((int) $page, 0), $pages - 1);
        $hwidsPage    = array_slice($hwids, $page * $perPage, $perPage);
        $defaultHwid  = max(1, (int) ($pac['hwid_device_count'] ?: 1));

        $text[] = "Menu -> " . $this->i18n('xray') . " -> {$client['email']} -> " . $this->i18n('hwid devices');
        $text[] = $this->i18n('hwid notice');
        if (empty($pac['hwid_limit_enabled'])) {
            $status = $this->i18n('off');
        } elseif (!empty($client['hwid_disabled'])) {
            $status = $this->i18n('off');
        } elseif (!empty($client['hwid_limit'])) {
            $status = (int) $client['hwid_limit'];
        } else {
            $status = "default($defaultHwid)";
        }
        $text[] = $this->i18n('hwid limit') . ': ' . $status;
        $text[] = $this->i18n('hwid devices') . ': ' . $total;

        $data[] = [
            [
                'text'          => $this->i18n(!empty($client['hwid_disabled']) ? 'off' : 'on'),
                'callback_data' => "/hwidUserToggle $i",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('set hwid devices count'),
                'callback_data' => "/setHwidUserLimit $i",
            ],
        ];
        if (!empty($client['hwid_limit'])) {
            $data[] = [
                [
                    'text'          => $this->i18n('use default hwid limit'),
                    'callback_data' => "/hwidUserDefault $i",
                ],
            ];
        }

        if ($total == 0) {
            $text[] = $this->i18n('no devices');
        }

        foreach ($hwidsPage as $index => $hwid) {
            $info    = $devices[$hwid];
            $number  = $page * $perPage + $index + 1;
            $details = array_filter([
                $info['device_os'] ?? '',
                $info['os_version'] ?? '',
                $info['device_model'] ?? '',
            ], fn($v) => $v !== '');
            $line = $number . '. <code>' . htmlspecialchars($hwid, ENT_HTML5, 'UTF-8') . '</code>';
            if (!empty($details)) {
                $line .= ' - ' . htmlspecialchars(implode(' ', $details), ENT_HTML5, 'UTF-8');
            }
            if (!empty($info['time'])) {
                $line .= ' (' . date('d.m.Y H:i', $info['time']) . ')';
            }
            $text[] = $line;
            if (!empty($info['user_agent'])) {
                $text[] = 'UA: ' . htmlspecialchars($info['user_agent'], ENT_HTML5, 'UTF-8');
            }
            $token = $this->rememberHwidToken($scope, $hwid);
            $data[] = [
                [
                    'text'          => '🗑 ' . $number,
                    'callback_data' => "/hwidUserDel {$i}_{$page} $token",
                ],
            ];
        }

        if ($pages > 1) {
            $data[] = [
                [
                    'text'          => '<<',
                    'callback_data' => "/hwidUser {$i}_" . ($page - 1 >= 0 ? $page - 1 : $pages - 1),
                ],
                [
                    'text'          => ($page + 1) . '/' . $pages,
                    'callback_data' => "/hwidUser {$i}_$page",
                ],
                [
                    'text'          => '>>',
                    'callback_data' => "/hwidUser {$i}_" . (($page + 1) % $pages),
                ],
            ];
        }

        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/userXr $i",
            ],
        ];

        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            implode("\n", $text ?: ['...']),
            $data ?: false,
        );
    }

    public function hwidUserToggle($i)
    {
        $xray = $this->getXray();
        if (!empty($xray['inbounds'][0]['settings']['clients'][$i]['hwid_disabled'])) {
            unset($xray['inbounds'][0]['settings']['clients'][$i]['hwid_disabled']);
        } else {
            $xray['inbounds'][0]['settings']['clients'][$i]['hwid_disabled'] = 1;
        }
        file_put_contents('/config/xray.json', json_encode($xray, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        $this->answer($this->input['callback_id'], $this->i18n('hwid notice'), true);
        $this->hwidUser($i);
    }

    public function hwidUserDefault($i)
    {
        $xray = $this->getXray();
        unset($xray['inbounds'][0]['settings']['clients'][$i]['hwid_limit']);
        file_put_contents('/config/xray.json', json_encode($xray, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        $this->hwidUser($i);
    }

    public function setHwidUserLimit($i)
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter hwid devices count",
            $this->input['message_id'],
            reply: 'enter hwid devices count',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message' => $this->input['message_id'],
            'callback'      => 'saveHwidUserLimit',
            'args'          => [$i],
        ];
    }

    public function saveHwidUserLimit($count, $i)
    {
        $xray = $this->getXray();
        $count = (int) $count;
        if ($count > 0) {
            $xray['inbounds'][0]['settings']['clients'][$i]['hwid_limit'] = $count;
        } else {
            unset($xray['inbounds'][0]['settings']['clients'][$i]['hwid_limit']);
        }
        file_put_contents('/config/xray.json', json_encode($xray, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        $this->send($this->input['chat'], $this->i18n('hwid notice'), $this->input['message_id']);
        $this->hwidUser($i);
    }

    public function hwidUserDel($i, $page, $hwid)
    {
        $xray = $this->getXray();
        $uid    = $xray['inbounds'][0]['settings']['clients'][$i]['id'];
        $scope  = $this->getHwidTokenScope($i);
        $decoded = $this->resolveHwidToken($scope, $hwid);
        if ($decoded !== '') {
            $this->deleteHwidDevice($uid, $decoded);
        }
        $this->hwidUser($i, $page);
    }

    public function getDomain($cdn = false)
    {
        $c = $this->getPacConf();
        if ($cdn && $c['linkdomain']) {
            return $c['linkdomain'];
        }
        return $c['domain'] ?: $this->ip;
    }

    public function sub()
    {
        $xr     = $this->getXray();
        $pac    = $this->getPacConf();
        $st     = $this->getXrayStats();
        $domain = $_GET['cdn'] ?: ($_SERVER['SERVER_NAME'] ?: $this->getDomain($pac['transport'] != 'Reality'));
        $scheme = empty($this->nginxGetTypeCert()) ? 'http' : 'https';
        $hash   = $this->getHashBot();
        $flag   = true;
        $client = null;
        foreach ($xr['inbounds'][0]['settings']['clients'] as $k => $v) {
            if ($v['id'] == $_GET['id']) {
                if (empty($v['off'])) {
                    $flag = false;
                }
                $uid    = $v['id'];
                $email  = $v['email'];
                $expire = $v['time'];
                $client = $v;
                break;
            }
        }
        if (!$flag && !$this->processHwidRequest($client)) {
            exit;
        }
        $suburl   = "<a href='$scheme://{$domain}/pac$hash/sub?id={$uid}'>subscription</a>";
        $download = $this->getBytes($st['users'][$k]['global']['download'] + $st['users'][$k]['session']['download']);
        $upload   = $this->getBytes($st['users'][$k]['global']['upload'] + $st['users'][$k]['session']['upload']);
        $singbox  = "$scheme://{$domain}/pac$hash/" . base64_encode(serialize([
            'h' => $hash,
            't' => 'si',
            's' => $uid,
        ]));
        $xray = "$scheme://{$domain}/pac$hash/" . base64_encode(serialize([
            'h' => $hash,
            't' => 's',
            's' => $uid,
        ]));
        $clash = "$scheme://{$domain}/pac$hash/" . base64_encode(serialize([
            'h' => $hash,
            't' => 'cl',
            's' => $uid,
        ]));
        $vless   = $this->linkXray($k);
        $windows = "$scheme://{$domain}/pac$hash?t=si&r=w&s=$uid";
        $_GET['s'] = $uid;
        foreach ([
          'xray'    => 's',
          'singbox' => 'si',
          'clash'   => 'cl'
        ] as $k     => $v) {
            $_GET['t'] = $v;
            $configs[$k] = $this->subscription(1);
        }
        require __DIR__ . '/subscription.php';
    }

    public function subscription($return = false)
    {
        switch ($_GET['t']) {
            case 's':
                $type = 'v2ray';
                break;
            case 'si':
                $type = 'sing';
                break;
            case 'cl':
                $type = 'clash';
                break;
        }
        $pac    = $this->getPacConf();
        $domain = $_GET['cdn'] ?: ($_SERVER['SERVER_NAME'] ?: $this->getDomain($pac['transport'] != 'Reality'));
        $xr     = $this->getXray();
        $scheme = empty($this->nginxGetTypeCert()) ? 'http' : 'https';
        $hash   = $this->getHashBot();

        $flag = true;
        $client = null;
        foreach ($xr['inbounds'][0]['settings']['clients'] as $k => $v) {
            if ($v['id'] == $_GET['s']) {
                if (empty($v['off'])) {
                    $flag = false;
                }
                $template = base64_decode($v["{$type}template"]);
                $uid      = $v['id'];
                $email    = $v['email'];
                $client   = $v;
                break;
            }
        }
        if ($flag) {
            header('500', true, 500);
            exit;
        }

        if (!$return && !$this->processHwidRequest($client)) {
            exit;
        }

        if (!empty($_GET['r'])) {
            $si = "$scheme://{$domain}/pac$hash/" . base64_encode(serialize([
                'h' => $hash,
                't' => 'si',
                's' => $uid,
            ]));
            $v2 = "$scheme://{$domain}/pac$hash/" . base64_encode(serialize([
                'h' => $hash,
                't' => 's',
                's' => $uid,
            ]));
            $cl = "$scheme://{$domain}/pac$hash/" . base64_encode(serialize([
                'h' => $hash,
                't' => 'cl',
                's' => $uid,
            ]));
            switch ($_GET['r']) {
                case 'si':
                    header("Location: sing-box://import-remote-profile/?url=$si");
                    exit;
                case 'st':
                    header("Location: streisand://import/$v2");
                    exit;
                case 'v':
                    header("Location: v2rayng://install-config?url=$v2");
                    exit;
                case 'k':
                    header("Location: karing://install-config?url=$si");
                    exit;
                case 'h':
                    header("Location: hiddify://install-config/?url=$si");
                    exit;
                case 'c':
                    header("Location: clash://install-config/?url=$cl&overwrite=no&name=$email");
                    exit;
                case 'rh':
                    header("Location: rabbithole://add/$cl");
                    exit;
                case 'w':
                    $link = htmlspecialchars($si, ENT_XML1, 'UTF-8');
                    $n    = "singbox_$uid.zip";
                    copy('/singbox/singbox.zip', $n);
                    $zip = new ZipArchive();
                    $zip->open($n, ZipArchive::CREATE);
                    $zip->addFromString('winsw3.xml', preg_replace('#~url~#', $link, file_get_contents('/singbox/winsw3.xml')));
                    $zip->close();
                    header('Content-Disposition: attachment; filename="singbox.zip"');
                    echo file_get_contents($n);
                    unlink($n);
                    exit;
            }
        }
        switch (true) {
            case !empty($template) && $template == 'origin':
            case empty($template) && empty($pac["default{$type}template"]):
            case empty($template) && empty($pac["{$type}templates"][base64_decode($pac["default{$type}template"])]):
            case !empty($template) && empty($pac["{$type}templates"][$template]):
                $c = json_decode(file_get_contents("/config/{$type}.json"), true);
                break;
            case !empty($template):
                $c = $pac["{$type}templates"][$template];
                break;

            default:
                $c = $pac["{$type}templates"][base64_decode($pac["default{$type}template"])];
                break;
        }

        $outbound = $pac['outbound'] ?: 'proxy';
        $c = json_decode($this->replaceTags(json_encode($c), [
            '~outbound~' => $outbound,
        ]), true);
        foreach ($c['outbounds'] as $k => $v) {
            if ($v['tag'] == $outbound) {
                $index = $k;
                break;
            }
        }
        if (!isset($index)) {
            foreach ($c['proxies'] as $k => $v) {
                if ($v['name'] == $outbound) {
                    $index = $k;
                    break;
                }
            }
        }

        $fingerprint = $pac['fingerprint'] ?: 'chrome';
        // randomizednoalpn and unsafe are Xray-only uTLS ids: sing-box errors on an
        // unknown fingerprint and mihomo silently drops uTLS, so map them to a
        // supported value for the sing-box (si) and clash (cl) configs.
        if (in_array($_GET['t'], ['si', 'cl'], true)) {
            $fingerprint = ['randomizednoalpn' => 'randomized', 'unsafe' => 'chrome'][$fingerprint] ?? $fingerprint;
        }

        switch ($_GET['t']) {
            case 's':
                $c['outbounds'][$index]['settings']['vnext'][0]['address']  = '~domain~';
                $c['outbounds'][$index]['settings']['vnext'][0]['users'][0] = [
                    'id'         => '~uid~',
                    'encryption' => 'none',
                ];
                switch ($pac['transport']) {
                    case 'Reality':
                        $c['outbounds'][$index]['settings']['vnext'][0]['users'][0]["flow"] = "xtls-rprx-vision";
                        $c['outbounds'][$index]['streamSettings']                           = [
                            "network"         => "tcp",
                            "security"        => "reality",
                            "realitySettings" => [
                                "serverName"  => '~server_name~',
                                "fingerprint" => $fingerprint,
                                "publicKey"   => '~public_key~',
                                "shortId"     => '~short_id~',
                            ]
                        ];
                        $c['outbounds'][$index]['mux'] = [
                            "enabled"     => false,
                            "concurrency" => -1
                        ];
                        break;
                    case 'xhttp':
                        $c['outbounds'][$index]['streamSettings'] = [
                            "network"  => "xhttp",
                            "security" => "tls",

                            "xhttpSettings" => [
                                "host" => "~domain~",
                                "mode" => "packet-up",
                                "path" => "/ws$hash",

                                "extra" => [
                                    "scMaxEachPostBytes"    => 1000000,
                                    "scMinPostsIntervalMs"  => 30,
                                    "scStreamUpServerSecs"  => "20-80",
                                    "xmux" => [
                                        "cMaxReuseTimes"    => 0,
                                        "hKeepAlivePeriod"  => 0,
                                        "hMaxRequestTimes"  => "600-900",
                                        "hMaxReusableSecs"  => "1800-3000",
                                        "maxConcurrency"    => "16-32",
                                        "maxConnections"    => 0,
                                    ],
                                    "xPaddingBytes" => "100-1000",
                                    "noGRPCHeader"  => false
                                ]
                            ],

                            "tlsSettings" => [
                                "allowInsecure" => false,
                                "alpn"          => ["h2", "http/1.1"],
                                "fingerprint"   => $fingerprint,
                                "serverName"    => "~domain~",
                                "show"          => false
                            ]
                        ];
                        unset($c['outbounds'][$index]['mux']);
                        break;
                    case 'trojan-grpc':
                        $c['outbounds'][$index] = [
                            'tag'      => $outbound,
                            'protocol' => 'trojan',
                            'settings' => [
                                'servers' => [
                                    [
                                        'address'  => '~domain~',
                                        'port'     => 443,
                                        'password' => '~uid~',
                                    ]
                                ]
                            ],
                            'streamSettings' => [
                                'network'      => 'grpc',
                                'security'     => 'tls',
                                'grpcSettings' => [
                                    'serviceName' => "grpc$hash",
                                ],
                                'tlsSettings'  => [
                                    'allowInsecure' => false,
                                    'alpn'          => ['h2'],
                                    'fingerprint'   => $fingerprint,
                                    'serverName'    => '~domain~',
                                    'show'          => false
                                ]
                            ]
                        ];
                        break;

                    default:
                        $c['outbounds'][$index]['streamSettings'] = [
                            "network"    => "ws",
                            "security"   => "tls",
                            "wsSettings" => [
                                "path" => "/ws$hash?ed=2560"
                            ],
                            "tlsSettings" => [
                                "allowInsecure" => false,
                                "serverName"    => '~domain~',
                                "fingerprint"   => $fingerprint
                            ]
                        ];
                        unset($c['outbounds'][$index]['mux']);
                        break;
                }

                break;
            case 'si':
                $c['outbounds'][$index]['uuid'] = '~uid~';
                switch ($pac['transport']) {
                    case 'Reality':
                        unset($c['outbounds'][$index]["transport"]);
                        $c['outbounds'][$index]['flow']                         = 'xtls-rprx-vision';
                        $c['outbounds'][$index]['tls']['reality']['public_key'] = '~public_key~';
                        $c['outbounds'][$index]['tls']['server_name']           = '~server_name~';
                        $c['outbounds'][$index]['tls']['reality']['short_id']   = '~short_id~';
                        break;
                    case 'xhttp':
                        unset($c['outbounds'][$index]['flow']);
                        unset($c['outbounds'][$index]['tls']['reality']);

                        $c['outbounds'][$index]["transport"] = [
                            "type" => "xhttp",
                            "host" => "~domain~",
                            "mode" => "packet-up",
                            "path" => "/ws$hash",
                            "xmux" => [
                                "max_concurrency"   => "16-32",
                                "max_connections"   => "0-1",
                                "c_max_reuse_times" => "0-1",
                                "h_max_request_times" => "600-900",
                                "h_max_reusable_secs" => "1800-3000",
                                "h_keep_alive_period" => 60
                            ]
                        ];

                        $c['outbounds'][$index]['tls'] = [
                            "enabled"     => true,
                            "insecure"    => false,
                            "server_name" => "~domain~",
                            "alpn"        => ["h2"]
                        ];
                        break;
                    case 'trojan-grpc':
                        $c['outbounds'][$index]['type']     = 'trojan';
                        $c['outbounds'][$index]['password'] = '~uid~';
                        unset($c['outbounds'][$index]['uuid']);
                        unset($c['outbounds'][$index]['flow']);
                        unset($c['outbounds'][$index]['packet_encoding']);
                        unset($c['outbounds'][$index]['tls']['reality']);

                        $c['outbounds'][$index]['transport'] = [
                            'type'         => 'grpc',
                            'service_name' => "grpc$hash",
                        ];
                        $c['outbounds'][$index]['tls'] = [
                            'enabled'     => true,
                            'insecure'    => false,
                            'server_name' => '~domain~',
                            'alpn'        => ['h2'],
                            'utls'        => [
                                'enabled'     => true,
                                'fingerprint' => $fingerprint,
                            ],
                        ];
                        break;

                    default:
                        unset($c['outbounds'][$index]['tls']['reality']);
                        unset($c['outbounds'][$index]['flow']);
                        $c['outbounds'][$index]["transport"] = [
                            "type" => "ws",
                            "path" => "/ws$hash"
                        ];
                        $c['outbounds'][$index]['tls']['server_name'] = '~domain~';
                        break;
                }
                break;
            case 'cl':
                $c['proxies'][$index]['server'] = '~domain~';
                $c['proxies'][$index]['uuid']   = '~uid~';
                switch (true) {
                    case $pac['transport'] == 'Reality':
                        unset($c['proxies'][$index]["ws-opts"]);
                        unset($c['proxies'][$index]["skip-cert-verify"]);
                        $c['proxies'][$index]["network"]      = "tcp";
                        $c['proxies'][$index]['flow']         = 'xtls-rprx-vision';
                        $c['proxies'][$index]['servername']  = '~server_name~';
                        $c['proxies'][$index]['reality-opts'] = [
                            'public-key' => '~public_key~',
                            'short-id'   => '~short_id~',
                        ];
                        break;
                    case $pac['transport'] == 'xhttp':
                        unset($c['proxies'][$index]['ws-opts']);
                        unset($c['proxies'][$index]['flow']);
                        unset($c['proxies'][$index]['reality-opts']);

                        $c['proxies'][$index]['network']            = 'xhttp';
                        $c['proxies'][$index]['client-fingerprint'] = $fingerprint;
                        $c['proxies'][$index]['tls']                = true;
                        $c['proxies'][$index]['alpn']               = ['h2'];
                        $c['proxies'][$index]['servername']         = '~domain~';
                        $c['proxies'][$index]['skip-cert-verify']   = false;

                        $c['proxies'][$index]['xhttp-opts'] = [
                            'host'                   => '~domain~',
                            'path'                   => "/ws$hash",
                            'mode'                   => 'packet-up',
                            'no-grpc-header'         => false,
                            'x-padding-bytes'        => '100-1000',
                            'sc-max-each-post-bytes' => 1000000,
                            'reuse-settings'         => [
                                'max-connections'   => '0',
                                'max-concurrency'   => '8-16',
                                'c-max-reuse-times' => '0',
                                'h-max-request-times' => '100-200',
                                'h-max-reusable-secs' => '1800-3000',
                            ],
                        ];
                        break;
                    case 'trojan-grpc':
                        unset($c['proxies'][$index]['ws-opts']);
                        unset($c['proxies'][$index]['flow']);
                        unset($c['proxies'][$index]['reality-opts']);
                        unset($c['proxies'][$index]['xhttp-opts']);
                        unset($c['proxies'][$index]['uuid']);

                        $c['proxies'][$index]['type']             = 'trojan';
                        $c['proxies'][$index]['password']         = '~uid~';
                        $c['proxies'][$index]['network']          = 'grpc';
                        $c['proxies'][$index]['tls']              = true;
                        $c['proxies'][$index]['alpn']             = ['h2'];
                        $c['proxies'][$index]['skip-cert-verify'] = false;
                        $c['proxies'][$index]['servername']       = '~domain~';
                        $c['proxies'][$index]['grpc-opts']        = [
                            'grpc-service-name' => "grpc$hash",
                        ];
                        break;

                    default:
                        unset($c['proxies'][$index]['flow']);
                        unset($c['proxies'][$index]['reality-opts']);
                        $c['proxies'][$index]["network"]          = "ws";
                        $c['proxies'][$index]["ws-opts"]['path']  = "/ws$hash";
                        $c['proxies'][$index]["skip-cert-verify"] = false;
                        $c['proxies'][$index]['servername']       = '~domain~';
                        break;
                }


                    if (!empty($client['awg']) && !empty($awg = $this->getAwgClient($client['awg']))) {
                        $c['proxies'][$index + 1] = [
                            "name"        => 'awg',
                            "type"        => 'wireguard',
                            "server"      => $awg['server'],
                            "port"        => $awg['port'],
                            "ip"          => $awg['ip'],
                            "private-key" => $awg['private-key'],
                            "public-key"  => $awg['public-key'],
                            "allowed-ips" => [
                                "0.0.0.0/0",
                            ],
                            "mtu"                  => $awg['mtu'],
                            "persistent-keepalive" => 20,
                            "udp"                  => true,
                        ];
                        if (!empty($awg['pre-shared-key'])) {
                            $c['proxies'][$index + 1]['pre-shared-key'] = $awg['pre-shared-key'];
                        }
                        if (!empty($awg['amnezia-wg-option'])) {
                            $c['proxies'][$index + 1]['amnezia-wg-option'] = $awg['amnezia-wg-option'];
                        }
                        $c['proxy-groups'][0]['proxies'][] = 'awg';
                    }

                $tunpackage = array_filter($pac['tunpackage'] ?? []);
                $tunprocess = array_filter($pac['tunprocess'] ?? []);
                if (!empty($tunpackage) || !empty($tunprocess)) {
                    if (!empty($tunpackage)) {
                        if (!empty($pac['tunpackagemode'])) {
                            $c['tun']['exclude-package'] = array_keys($tunpackage);
                        } else {
                            $c['tun']['include-package'] = array_keys($tunpackage);
                        }
                    }
                    if (!empty($tunprocess)) {
                        if (!empty($pac['tunprocessmode'])) {
                            $c['tun']['exclude-process'] = array_keys($tunprocess);
                        } else {
                            $c['tun']['include-process'] = array_keys($tunprocess);
                        }
                    }
                }
                break;
        }
        // Cloudflare WARP profile of this server, exposed as template tags so a
        // (per-user) template can embed a wireguard-WARP proxy with the dynamic
        // server secrets. Empty array when warp isn't set up — the tags then
        // resolve to empty strings / defaults.
        $warp = $this->getWarpProfile() ?: [];
        $c = json_decode($this->replaceTags(json_encode($c), [
            '"~pac~"'        => json_encode(array_keys(array_filter($pac['includelist'] ?: []))),
            '"~block~"'      => json_encode(array_keys(array_filter($pac['blocklist'] ?: []))),
            '"~warp~"'       => json_encode(array_keys(array_filter($pac['warplist'] ?: []))),
            '"~process~"'    => json_encode(array_keys(array_filter($pac['processlist'] ?: []))),
            '"~package~"'    => json_encode(array_keys(array_filter($pac['packagelist'] ?: []))),
            '"~subnet~"'     => json_encode(array_keys(array_filter($pac['subnetlist'] ?: []))),
            '"~warp_port~"'      => (int) ($warp['port'] ?? 2408),
            '"~warp_mtu~"'       => (int) ($warp['mtu'] ?? 1280),
            '~warp_server~'      => $warp['server'] ?? '',
            '~warp_ip~'          => $warp['ip'] ?? '',
            '~warp_private_key~' => $warp['private-key'] ?? '',
            '~warp_public_key~'  => $warp['public-key'] ?? '',
            '~dns~'          => "https://$domain/dns-query$hash/$uid",
            '~dnspath~'      => "/dns-query$hash/$uid",
            '~uid~'          => ($pac['transport'] == 'trojan-grpc' ? ($client['password'] ?? $uid) : $uid),
            '~domain~'       => $domain,
            '~directdomain~' => $pac['domain'],
            '~cdndomain~'    => $pac['linkdomain'],
            '~short_id~'     => $xr['inbounds'][0]['streamSettings']['realitySettings']['shortIds'][0],
            '~email~'        => $email,
            '~public_key~'   => $pac['xray'],
            '~server_name~'  => $xr['inbounds'][0]['streamSettings']['realitySettings']['serverNames'][0],
            '~fingerprint~'  => $fingerprint,
            '~ip~'           => $this->ip,
            '~outbound~'     => $outbound,
        ]), true);

        switch ($_GET['t']) {
            case 's':
                if (!empty($c['routing']['rules'])) {
                    $ips = $domains = [];
                    foreach ($c['routing']['rules'] as $k => $v) {
                        if (array_key_exists('domain', $v) && !empty($v['domain'])) {
                            foreach ($v['domain'] as $j) {
                                if (!preg_match('~^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$~', $j)) {
                                    $domains[$v['outboundTag']][] = $j;
                                } else {
                                    $ips[$v['outboundTag']][] = $j;
                                }
                            }
                        }
                        if (array_key_exists('ip', $v) && !empty($v['ip'])) {
                            foreach ($v['domain'] as $j) {
                                if (!preg_match('~^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$~', $j)) {
                                    $domains[$v['outboundTag']][] = $j;
                                } else {
                                    $ips[$v['outboundTag']][] = $j;
                                }
                            }
                        }
                    }
                    $c['routing']['rules'] = [];

                    if (!empty($domains)) {
                        foreach ($domains as $k => $v) {
                            $c['routing']['rules'][] = [
                                "type"        => "field",
                                "outboundTag" => $k,
                                "domain"      => $v
                            ];
                        }
                    }
                    if (!empty($ips)) {
                        foreach ($ips as $k => $v) {
                            $c['routing']['rules'][] = [
                                "type"        => "field",
                                "outboundTag" => $k,
                                "ip"          => $v
                            ];
                        }
                    }
                }
                break;
            case 'si':
                $c['route'] = $this->addRuleSet($c['route']);
                $c['route'] = $this->createRuleSet($c['route'], $uid, $domain);
                if (!empty($c['route']['rules'])) {
                    foreach ($c['route']['rules'] as $k => $v) {
                        if (count($v) == 1 && array_key_exists('outbound', $v)) {
                            unset($c['route']['rules'][$k]);
                        }
                    }
                    $c['route']['rules'] = array_values($c['route']['rules']);
                }
                if (empty($c['route'])) {
                    unset($c['route']);
                }
                break;
            case 'cl':
                $c = $this->addClashRuleSet($c);
                if (!empty($c['rules'])) {
                    $c = $this->clashRules($c, $uid, $domain);
                    if (count($c['rules']) == 1) {
                        unset($c['rules']);
                    }
                }
                break;
        }
        if (!empty($return)) {
            if ($_GET['t'] == 'cl') {
                return yaml_emit($c);
            }
            return json_encode($c);
        }

        if ($_GET['t'] == 'cl') {
            header('Content-type: text/yaml');
            echo yaml_emit($c);
            return;
        }

        header('Content-type: application/json');
        echo json_encode($c);
    }

    public function getAwgClient($pk)
    {
        $c   = $this->getPacConf();
        $wg  = json_decode(file_get_contents($this->clients), true) ?: [];
        $wg1 = json_decode(file_get_contents($this->clients1), true) ?: [];
        foreach ($wg as $k => $v) {
            if ($v['interface']['PrivateKey'] == $pk) {
                $container = '';
                $cl = $v;
                break;
            }
        }
        foreach ($wg1 as $k => $v) {
            if ($v['interface']['PrivateKey'] == $pk) {
                $container = 'wg1_';
                $cl = $v;
                break;
            }
        }

        if (empty($cl)) {
            return false;
        }

        return [
            "amnezia-wg-option" => $c["{$container}amnezia_keys"],
            "pre-shared-key"    => $c["{$container}presharedkey"],
            "server"            => explode(':', $cl['peers'][0]['Endpoint'])[0],
            "port"              => explode(':', $cl['peers'][0]['Endpoint'])[1],
            "ip"                => explode('/', $cl['interface']['Address'])[0],
            "private-key"       => $cl['interface']['PrivateKey'],
            "public-key"        => $cl['peers'][0]['PublicKey'],
            "mtu"               => $c["{$container}mtu"] ?? $this->mtu,
        ];
    }

    public function addClashRuleSet($c)
    {
        $p = $this->getPacConf();
        if (!empty($p['rulessetlist']) && $c['add-rule-providers']) {
            foreach ($p['rulessetlist'] as $k => $v) {
                if (!empty($v)) {
                    [$type, $behavior, $time, $url] = explode(':', $k, 4);
                    if (preg_match('~\.(mrs|yaml|yml)$~', $url, $m)) {
                        $c['rule-providers'][$url] = [
                            'type'     => 'http',
                            'url'      => $url,
                            'interval' => (int) $time,
                            'behavior' => $behavior,
                            'format'   => $m[1],
                        ];
                        switch ($type) {
                            case 'reject':
                            case 'REJECT':
                                array_unshift($c['rules'], [
                                    'RULE-SET', $url, strtoupper($type)
                                ]);
                                break;

                            default:
                                array_splice($c['rules'], count($c['rules']) - 1, 0, [[
                                    'RULE-SET', $url, strtoupper($type)
                                ]]);
                                break;
                        }
                    }
                }
            }
        }
        unset($c['add-rule-providers']);
        if (empty($c['rule-providers'])) {
            unset($c['rule-providers']);
        }
        return $c;
    }

    public function clashRules($c, $uid, $domain)
    {
        $scheme = empty($this->nginxGetTypeCert()) ? 'http' : 'https';
        $hash   = $this->getHashBot();
        foreach ($c['rules'] as $v) {
            if (array_key_exists('list', $v)) {
                if ($v['type'] == 'RULE-SET') {
                    if (!empty($_GET['r']) && $v['name'] == $_GET['r']) {
                        header("Content-Disposition: attachment; filename={$v['name']}.yaml");
                        header('Content-Type: text/yaml');
                        switch ($v['name']) {
                            case 'process':
                            case 'package':
                                echo yaml_emit(['payload' => array_map(fn($e) => "PROCESS-NAME,$e", $v['list'])]);
                                break;

                            default:
                                echo yaml_emit(['payload' => array_map(function($e) {
                                    if (preg_match('~^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$~', $e, $m)) {
                                        return "IP-CIDR,$e" . (empty($m[1]) ? '/32' : '');
                                    } else {
                                        return "DOMAIN-SUFFIX,$e";
                                    }
                                }, $v['list'])]);
                                break;

                        }
                        exit;
                    }
                    $c['rule-providers'][$v['name']] = [
                        'type'     => 'http',
                        'url'      => "$scheme://{$domain}/pac$hash/" . base64_encode(serialize([
                            'h' => $hash,
                            't' => 'cl',
                            's' => $uid,
                            'r' => $v['name'],
                        ])),
                        'interval' => $v['interval'],
                        'behavior' => $v['behavior'],
                        'format'   => 'yaml',
                    ];
                    $tmp[] = "{$v['type']}, {$v['name']}, {$v['action']}";
                } else {
                    if (!empty($v['list'])) {
                        foreach ($v['list'] as $j) {
                            $tmp[] = "{$v['type']}, $j, {$v['action']}";
                        }
                    }
                }
            } else {
                $tmp[] = implode(', ', $v);
            }
        }
        $c['rules'] = $tmp;
        return $c;
    }

    /**
     * Parse the server's Cloudflare WARP wgcf profile (/etc/warp/wgcf-profile.conf,
     * IPv6 already stripped by start_wp.sh) into the fields a mihomo wireguard
     * proxy needs. Returns false when the profile is missing/unreadable so callers
     * can fall back gracefully.
     */
    public function getWarpProfile()
    {
        // Cache per request: this runs on every config download (all types), and
        // when the profile is absent the ssh fallback below would otherwise fire
        // each time. null = not loaded yet; false/array = resolved result.
        if ($this->warpprofile !== null) {
            return $this->warpprofile;
        }
        $conf = @file_get_contents('/etc/warp/wgcf-profile.conf');
        if (empty($conf)) {
            // /etc/warp is mounted into this container, but fall back to the wp
            // container over ssh just in case the volume isn't present.
            $conf = $this->ssh('cat /etc/warp/wgcf-profile.conf 2>/dev/null', 'wp');
        }
        if (empty($conf) || !str_contains($conf, '[Peer]')) {
            return $this->warpprofile = false;
        }
        $val = function ($key) use ($conf) {
            return preg_match('~^\s*' . $key . '\s*=\s*(.+?)\s*$~mi', $conf, $m) ? trim($m[1]) : null;
        };
        $endpoint   = $val('Endpoint');
        $privateKey = $val('PrivateKey');
        $publicKey  = $val('PublicKey');
        $address    = $val('Address');
        if (empty($endpoint) || empty($privateKey) || empty($publicKey) || empty($address)) {
            return $this->warpprofile = false;
        }
        // endpoint is host:port, but tolerate an IPv6 literal like [2606:..]:2408
        if (preg_match('~^\[(.+)\]:(\d+)$~', $endpoint, $em)) {
            $server = $em[1];
            $port   = (int) $em[2];
        } else {
            $pos    = strrpos($endpoint, ':');
            $server = substr($endpoint, 0, $pos);
            $port   = (int) substr($endpoint, $pos + 1);
        }
        return $this->warpprofile = [
            'server'      => $server,
            'port'        => $port,
            'ip'          => explode('/', $address)[0],
            'private-key' => $privateKey,
            'public-key'  => $publicKey,
            'mtu'         => (int) ($val('MTU') ?: 1280),
        ];
    }

    public function replaceTags($subject, $tags)
    {
        return str_replace(array_keys($tags), array_values($tags), $subject);
    }

    public function addRuleSet($route)
    {
        if (!empty($route['rules'])) {
            foreach ($route['rules'] as $k => $v) {
                if (!empty($v['addruleset'])) {
                    $t[$v['outbound'] ?: 'block'] = $k;
                }
            }
            $p = $this->getPacConf();
            if (!empty($p['rulessetlist'])) {
                foreach ($p['rulessetlist'] as $k => $v) {
                    if (!empty($v)) {
                        [$type, $time, $url] = explode(':', $k, 3);
                        if (preg_match('~\.srs$~', $url) && !empty($route['rules'][$t[$type]])) {
                            $route['rule_set'][] = [
                                "tag"             => $k,
                                "type"            => "remote",
                                "format"          => "binary",
                                "url"             => $url,
                                "download_detour" => "direct",
                                "update_interval" => $time
                            ];
                            $route['rules'][$t[$type]]['rule_set'][] = $k;
                        }
                    }
                }
            }
            foreach ($route['rules'] as $k => $v) {
                unset($route['rules'][$k]['addruleset']);
            }
        }
        return $route;
    }

    public function cleanEmptyKeys(array $arr)
    {
        foreach ($arr as $k => $v) {
            if (empty($v)) {
                unset($arr[$k]);
            } elseif (is_array($v)) {
                $arr[$k] = $this->cleanEmptyKeys($v);
                if (empty($arr[$k])) {
                    unset($arr[$k]);
                }
            }
        }
        return $arr;
    }

    public function createSrs(string $name, array $rules)
    {
        $rules = $this->cleanEmptyKeys($rules);
        header("Content-Disposition: attachment; filename=$name.srs");
        header('Content-Type: application/binary');
        $f = "/tmp/$name" . time() . rand(1, 100);
        foreach ($rules as $k => $v) {
            if (array_key_exists('domain_suffix', $v)) {
                foreach ($v['domain_suffix'] as $j) {
                    if (!preg_match('~^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$~', $j, $m)) {
                        $domains[] = $j;
                    } else {
                        $ips[] = $j . (empty($m[1]) ? '/32' : '');
                    }
                }
                unset($rules[$k]['domain_suffix']);
                if (!empty($domains)) {
                    $rules[$k]['domain_suffix'] = $domains;
                }
                if (!empty($ips)) {
                    $rules[$k]['ip_cidr'] = $ips;
                }
            }
        }
        file_put_contents($f, json_encode([
            'version' => 1,
            'rules'   => $rules ?: [],
        ]));
        exec("sing-box rule-set compile $f");
        echo file_get_contents("$f.srs");
        unlink($f);
        unlink("$f.srs");
        exit;
    }

    public function createRuleSet($route, $uid, $domain)
    {
        $scheme = empty($this->nginxGetTypeCert()) ? 'http' : 'https';
        $hash   = $this->getHashBot();

        foreach ($route['rules'] as $k => $v) {
            if (!empty($v['createruleset'])) {
                foreach ($v['createruleset'] as $r) {
                    if (!empty($_GET['r']) && $r['name'] == $_GET['r']) {
                        $this->createSrs($r['name'], $r['rules']);
                    }
                    $ruleset[] = [
                        "tag"             => $r['name'],
                        "url"             => "$scheme://{$domain}/pac$hash/" . base64_encode(serialize([
                            'h' => $hash,
                            't' => 'si',
                            's' => $uid,
                            'r' => $r['name'],
                        ])),
                        "update_interval" => $r['interval'],
                        "type"            => "remote",
                        "format"          => "binary",
                        "download_detour" => "direct",
                    ];
                    $route['rules'][$k]['rule_set'][] = $r['name'];
                }
                unset($route['rules'][$k]['createruleset']);
                if (empty($route['rules'][$k]['rule_set'])) {
                    unset($route['rules'][$k]);
                }
            }
        }
        if (!empty($route['rules'])) {
            $route['rules']    = array_values($route['rules']);
        }
        $route['rule_set'] = array_merge($route['rule_set'] ?: [], $ruleset ?: []);
        if (empty($route['rule_set'])) {
            unset($route['rule_set']);
        }
        return $route;
    }

    public function getXray()
    {
        return json_decode(file_get_contents('/config/xray.json'), true);
    }

    public function setUpstreamDomain($domain)
    {
        $nginx = file_get_contents('/config/upstream.conf');
        $t = preg_replace('~#domain.+#domain~s', "#domain\n$domain reality;\n#domain", $nginx);
        file_put_contents('/config/upstream.conf', $t);
        $this->ssh("nginx -s reload 2>&1", 'up');
    }

    public function setUpstreamDomainOcserv($domain)
    {
        $sub   = $this->getHashSubdomain('oc');
        $nginx = file_get_contents('/config/upstream.conf');
        $t     = preg_replace('~#ocserv.+#ocserv~s', $domain ? "#ocserv\n" . ($sub ? '' : '#' ) . "$sub.$domain ocserv;\n#ocserv" : "#ocserv\n#$sub.\$domain ocserv;\n#ocserv", $nginx);
        file_put_contents('/config/upstream.conf', $t);
        $this->ssh("nginx -s reload 2>&1", 'up');
    }

    public function setUpstreamDomainNaive($domain)
    {
        $sub   = $this->getHashSubdomain('np');
        $nginx = file_get_contents('/config/upstream.conf');
        $t = preg_replace('~#naive.+#naive~s', $domain ? "#naive\n" . ($sub ? '' : '#' ) . "$sub.$domain naive;\n#naive" : "#naive\n#$sub.\$domain naive;\n#naive", $nginx);
        file_put_contents('/config/upstream.conf', $t);
        $this->ssh("nginx -s reload 2>&1", 'up');
    }

    public function getHashBot($notset = false)
    {
        $p = $this->getPacConf();
        if (!empty($p['hashbot'])) {
            return $p['hashbot'];
        }
        $p['hashbot'] = substr(hash('sha256', $this->key), 0, 8);
        if (empty($notset)) {
            $this->setPacConf($p);
        }
        return $p['hashbot'];
    }

    public function cloakNginx()
    {
        $conf     = $this->getPacConf();
        $template = file_get_contents('/config/nginx_default.conf');
        // $template = preg_replace('~server_name ip~', "server_name {$this->ip}", $template);
        $template = preg_replace('~server_name domain~', "server_name " . ($conf['domain'] ? " *.{$conf['domain']} {$conf['domain']}" : '_'), $template);
        if ($conf['domain'] && $conf['letsencrypt']) {
            $template = preg_replace('/#~([^\n]+)?/', "#~{$conf['letsencrypt']}", $template);
            preg_match_all('~#-domain.+?#-domain~s', $template, $m);
            foreach ($m[0] as $v) {
                $template = preg_replace('~#-domain.+?#-domain~s', $this->uncomment($v, 'domain'), $template, 1);
            }
        }
        $h = $this->getHashBot();
        $s = empty($conf['adgbrowser']) ? '' : '#';
        $r = <<<CONF
        location /adguard/ {
                access_log /logs/nginx_adguard_access;
                if (\$cookie_c != "$h") {
                    $s rewrite .* /webapp redirect;
                }
                proxy_pass http://ad/;
                proxy_redirect / /adguard/;
                proxy_cookie_path / /adguard/;
            }
            location
        CONF;
        $template = preg_replace('~(location /adguard.+?})\s*location~s', $r, $template);
        $template = preg_replace('~(/webapp|/pac|/adguard|/ws|/grpc|/v2ray|location /dns-query)~', '${1}' . $h, $template);
        file_put_contents('/config/nginx.conf', $template);
        $x = $this->getXray();
        if (!empty($x['inbounds'][0]['streamSettings']['wsSettings']['path'])) {
            $x['inbounds'][0]['streamSettings']['wsSettings']['path'] = "/ws$h";
            $this->restartXray($x);
        }
        if (!empty($x['inbounds'][0]['streamSettings']['xhttpSettings']['path'])) {
            $x['inbounds'][0]['streamSettings']['xhttpSettings']['path'] = "/ws$h";
            $this->restartXray($x);
        }
        if (!empty($x['inbounds'][0]['streamSettings']['grpcSettings']['serviceName'])) {
            $x['inbounds'][0]['streamSettings']['grpcSettings']['serviceName'] = "grpc$h";
            $this->restartXray($x);
        }

        return $this->ssh('nginx -s reload', 'ng');
    }

    public function getHashSubdomain($subdomain)
    {
        $p = $this->getPacConf();
        if (isset($p["{$subdomain}_domain"])) {
            return $p["{$subdomain}_domain"];
        }
        $p["{$subdomain}_domain"] = substr(hash('sha256', "$subdomain{$this->key}"), 0, 8);
        $this->setPacConf($p);
        return $p["{$subdomain}_domain"];
    }

    public function addWg($page)
    {
        $text = "Menu -> {$this->getTitleWG()} -> Add peer\n\n";
        $data[] = [
            [
                'text'          =>  $this->i18n('all traffic'),
                'callback_data' => "/add",
            ]
        ];
        $data[] = [
            [
                'text'          =>  $this->i18n('subnet'),
                'callback_data' => "/add_ips",
            ]
        ];
        if ($this->getPacConf()['subnets']) {
            $data[] = [
                [
                    'text'          =>  $this->i18n('listSubnet'),
                    'callback_data' => "/addSubnets $page",
                ]
            ];
        }
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/menu wg $page",
            ]
        ];
        return [
            'text' => $text,
            'data' => $data,
        ];
    }

    public function adguardBasicAuth()
    {
        return base64_encode('admin:' . $this->getPacConf()['adpswd']);
    }

    public function adguardChBr()
    {
        $c = $this->getPacConf();
        $c['adgbrowser'] = $c['adgbrowser'] ? 0 : 1;
        $this->setPacConf($c);
        $this->cloakNginx();
        $this->answer($this->input['callback_id'], $this->i18n($c['adgbrowser'] ? 'browser_notify_on' : 'browser_notify_off'), true);
        $this->menu('adguard');
    }

    public function adguardMenu()
    {
        $conf   = $this->getPacConf();
        $ip     = $this->ip;
        $domain = $this->getDomain();
        $hash   = $this->getHashBot();
        $scheme = empty($ssl = $this->nginxGetTypeCert()) ? 'http' : 'https';
        $text   = "$scheme://$domain/adguard$hash\nLogin: admin\nPass: <span class='tg-spoiler'>{$conf['adpswd']}</span>\n\n";
        if ($ssl) {
            $text .= "DNS over HTTPS:\n<code>$ip</code>\n<code>$scheme://$domain/dns-query$hash" . (!empty($conf['adguardkey']) ? "/{$conf['adguardkey']}" : '') . "</code>\n\n";
            $text .= "DNS over TLS:\n<code>tls://" . (!empty($conf['adguardkey'] )? "{$conf['adguardkey']}." : '') . "$domain</code>";
        }
        $status = $this->i18n(exec("JSON=1 timeout 2 dnslookup google.com ad") ? 'on' : 'off');
        $safesearch = yaml_parse_file($this->adguard)['filtering']['safe_search']['enabled'];
        $text .= "\n\nstatus: $status\t\tsafesearch: " . $this->i18n($safesearch ? 'on' : 'off');
        $allowedClients = yaml_parse_file($this->adguard)['dns']['allowed_clients'];
        $text .= $allowedClients ? "\n\nallowed clients: \n - " . implode("\n - ", $allowedClients) : '';

        $data = [
            [
                [
                    'text'          => 'web panel',
                    'web_app' => [
                        "url" => "https://$domain/adguard$hash"
                    ],
                ],
                [
                    'text'          => $this->i18n('third party browser') . ': ' . $this->i18n(!empty($conf['adgbrowser']) ? 'on' : 'off'),
                    'callback_data' => '/adguardChBr'
                ],
            ],
            [
                [
                    'text'          => $this->i18n('change password'),
                    'callback_data' => "/adguardpsswd",
                ],
                [
                    'text'          => 'ClientID' . ($conf['adguardkey'] ? ": {$conf['adguardkey']}" : ''),
                    'callback_data' => "/setAdguardKey",
                ],
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('fill allowed clients'),
                'callback_data' => "/adgFillAllowedClients 0",
            ],
            [
                'text'          => $this->i18n('delete allowed clients'),
                'callback_data' => "/adgFillAllowedClients 1",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('check DNS'),
                'callback_data' => "/checkdns",
            ],
            [
                'text'          => $this->i18n('reset settings'),
                'callback_data' => "/adguardreset",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('add upstream'),
                'callback_data' => "/addupstream",
            ],
        ];
        $upstreams = yaml_parse_file($this->adguard)['dns']['upstream_dns'];
        if (!empty($upstreams)) {
            foreach ($upstreams as $k => $v) {
                $data[] = [
                    [
                        'text'          => $v,
                        'callback_data' => "/menu adguard",
                    ],
                    [
                        'text'          => $this->i18n('delete'),
                        'callback_data' => "/delupstream $k",
                    ],
                ];
            }
        }
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/menu",
            ],
        ];
        return [
            'text' => $text,
            'data' => $data,
        ];
    }

    public function adgFillAllowedClients($delete = false)
    {
        $pac = $this->getPacConf();
        $out[] = 'Restart Adguard Home';
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n", $out));
        $this->stopAd();
        $c = yaml_parse_file($this->adguard);
        if (!empty($delete)) {
            unset($c['dns']['allowed_clients']);
        } else {
            $c['dns']['allowed_clients'] = [];
            $c['dns']['allowed_clients'][] = '10.10.0.0/24';
            if (!empty($pac['adguardkey'])) {
                $c['dns']['allowed_clients'][] = $pac['adguardkey'];
            }
            $c['dns']['allowed_clients'][] = getenv('WGADDRESS');
            $c['dns']['allowed_clients'][] = getenv('WG1ADDRESS');
            $c['dns']['allowed_clients'][] = '10.0.2.0/24'; // openconnect
            if (!empty($xr = $this->getXray())) {
                foreach ($xr['inbounds'][0]['settings']['clients'] as $v) {
                    $c['dns']['allowed_clients'][] = $v['id'];
                }
            }
        }
        yaml_emit_file($this->adguard, $c);
        $this->startAd();
        $this->menu('adguard');
    }

    public function menuLang()
    {
        $data = [];
        $lang = [];
        foreach ($this->i18n as $k => $v) {
            $lang = array_merge($lang, array_keys($v));
        }
        $lang = array_unique($lang);
        foreach ($lang as $v) {
            if ($v != $this->language) {
                $data[] = [
                    [
                        'text'          => $v,
                        'callback_data' => "/lang $v",
                    ],
                ];
            }
        }
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/menu config",
            ],
        ];
        return [
            'text' => 'Language',
            'data' => $data,
        ];
    }

    public function expireCert()
    {
        $c = openssl_x509_read(file_get_contents("/certs/cert_public"));
        return openssl_x509_parse($c)["validTo_time_t"] ?: false;
    }

    public function domainsCert()
    {
        $domains = openssl_x509_parse(openssl_x509_read(file_get_contents("/certs/cert_public")))['extensions']["subjectAltName"];
        if (empty($domains)) {
            return false;
        }
        return array_map(fn($e) => trim($e), explode(',', str_replace('DNS:', '', $domains)));
    }

    public function updatebot()
    {
        $b = exec('git -C / rev-parse --abbrev-ref HEAD');
        $track  = trim(file_get_contents('/update/branch'));
        $data = [
            [
                [
                    'text'          => "$b => $track",
                    'callback_data' => "/branches",
                ],
                [
                    'text'    => $this->i18n('changelog'),
                    'web_app' => ['url' => "https://raw.githubusercontent.com/mercurykd/vpnbot/$b/version"],
                ],
            ],
            [
                [
                    'text'          => $this->i18n('update bot'),
                    'callback_data' => "/applyupdatebot",
                ],
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/menu config",
            ],
        ];
        exec("git -C / branch -vv", $mm);
        return [
            'text' => '<pre><code class="language-shell">' . htmlentities(implode("\n", $mm)) . '</code></pre>',
            'data' => $data,
        ];
    }

    public function applyupdatebot()
    {
        $this->pinBackup($this->update);
        $r = $this->sendDraft($this->input['from'], 1, 'update...');
        file_put_contents('/update/reload_message', "{$this->input['from']}:{$r['result']['message_id']}");
        file_put_contents('/update/key', $this->key);
        file_put_contents('/update/curl', json_encode([
            'chat_id'    => $this->input['chat'],
            'message_id' => $r['result']['message_id'],
            'text'       => '~t~'
        ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        file_put_contents('/update/pipe', '1');
        $this->delete($this->input['from'], $this->input['message_id']);
    }

    public function restart()
    {
        $r = $this->sendDraft($this->input['from'], 1, 'restart...');
        file_put_contents('/update/reload_message', "{$this->input['from']}:{$r['result']['message_id']}");
        file_put_contents('/update/key', $this->key);
        file_put_contents('/update/curl', json_encode([
            'chat_id'    => $this->input['chat'],
            'message_id' => $r['result']['message_id'],
            'text'       => '~t~'
        ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        file_put_contents('/update/pipe', '2');
        $this->delete($this->input['from'], $this->input['message_id']);
    }

    public function configMenu()
    {
        $conf = $this->getPacConf();
        $oc   = $this->getHashSubdomain('oc');
        $np   = $this->getHashSubdomain('np');
        if (!empty($conf['domain'])) {
            $ssl_expiry = $this->expireCert();
            $certs      = $this->domainsCert() ?: [];

            $text[] = "<blockquote>";
            $text[] = "Domains:";
            $text[] = $conf['domain'] . (in_array($conf['domain'], $certs) ? ' (ssl: ' . date('Y-m-d H:i:s', $ssl_expiry) . ')' : '');
            $text[] = 'naive ' . "$np.{$conf['domain']}" . (in_array("$np.{$conf['domain']}", $certs) ? ' (ssl: ' . date('Y-m-d H:i:s', $ssl_expiry) . ')' : '');
            $text[] = 'openconnect ' . "$oc.{$conf['domain']}" . (in_array("$oc.{$conf['domain']}", $certs) ? ' (ssl: ' . date('Y-m-d H:i:s', $ssl_expiry) . ')' : '');
            if (!empty($conf['adguardkey'])) {
                $text[] = "{$conf['adguardkey']}.{$conf['domain']}" . (in_array("{$conf['adguardkey']}.{$conf['domain']}", $certs) ? ' (ssl: ' . date('Y-m-d H:i:s', $ssl_expiry) . ')' : '') . ' adguard DOT';
            }
            $text[] = "</blockquote>";
        } else {
            $text[] = $this->i18n('domain explain');
        }

        $data = [
            [
                [
                    'text'          => $conf['domain'] ? "{$this->i18n('delete')} {$conf['domain']}" : $this->i18n('install domain'),
                    'callback_data' => $conf['domain'] ? '/deldomain' : '/domain',
                ],
                [
                    'text'          => $this->i18n('nip.io'),
                    'callback_data' => '/addNipdomain',
                ],
            ],
        ];
        if ($conf['domain']) {
            if ($cert = $this->nginxGetTypeCert()) {
                switch ($cert) {
                    case 'letsencrypt':
                        $data[] = [
                            [
                                'text'          => $this->i18n('renew SSL'),
                                'callback_data' => "/setSSL letsencrypt",
                            ],
                            [
                                'text'          => $this->i18n('delete SSL'),
                                'callback_data' => "/deletessl",
                            ],
                        ];
                        break;
                    case 'self':
                        $data[] = [
                            [
                                'text'          => $this->i18n('delete SSL'),
                                'callback_data' => "/deletessl",
                            ],
                        ];
                        break;
                }
            } else {
                $data[] = [
                    [
                        'text'          => $this->i18n('Letsencrypt SSL'),
                        'callback_data' => "/setSSL letsencrypt",
                    ],
                    [
                        'text'          => $this->i18n('Self SSL'),
                        'callback_data' => "/selfssl",
                    ],
                ];
            }
        }
        $data[] = [
            [
                'text'          => $this->i18n('Ports'),
                'callback_data' => "/ports",
            ],
            [
                'text'          => $this->i18n('logs'),
                'callback_data' => "/logs",
            ],
            [
                'text'          => $this->i18n('IP ban'),
                'callback_data' => "/ipMenu",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('server status'),
                'callback_data' => "/status",
            ],
        ];

        $data[] = [
            [
                'text'          => $this->i18n('lang'),
                'callback_data' => "/menu lang",
            ],
            [
                'text'          => "{$this->i18n('page')}: " . ($conf['limitpage'] ?: 5),
                'callback_data' => "/enterPage",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('export'),
                'callback_data' => "/export",
            ],
            [
                'text'          => $this->i18n('import'),
                'callback_data' => "/import",
            ],
        ];
        $backup = array_filter(explode('/', $conf['backup']));
        if (!empty($backup)) {
            if (!empty(strtotime($backup[0])) && !empty(strtotime($backup[1]))) {
                $backup = "{$backup[0]} start / {$backup[1]} period";
            } else {
                $backup = $this->i18n('off') . " {$conf['backup']} - wrong format";
            }
        }
        $data[] = [
            [
                'text'          => $this->i18n('backup') . ': ' . ($backup ?: $this->i18n('off')),
                'callback_data' => "/backup",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('autoupdate') . ': ' .  $this->i18n($conf['autoupdate'] ? 'on' : 'off'),
                'callback_data' => "/autoupdate",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('branches'),
                'callback_data' => "/menu update",
            ],
            [
                'text'          => $this->i18n('restart'),
                'callback_data' => "/restart",
            ],
        ];
        $data[] = [
            [
                'text'          => "{$this->i18n('add')} {$this->i18n('admin')}",
                'callback_data' => "/addadmin",
            ],
        ];
        $file = __DIR__ . '/config.php';
        opcache_invalidate($file);
        require $file;
        foreach ($c['admin'] as $k => $v) {
            $data[] = [
                [
                    'text'          => $this->i18n('delete') . " $v",
                    'callback_data' => "/deladmin $v",
                ],
            ];
        }
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/menu",
            ],
        ];
        return [
            'text' => implode("\n", $text),
            'data' => $data,
        ];
    }

    public function ports()
    {
        $text[] = 'Settings -> Ports';
        $f      = '/docker/compose';
        $c      = is_file($f) ? (yaml_parse_file($f)['services'] ?? []) : [];
        $pac = $this->getPacConf();
        $p   = $this->getPorts();

        $ssCfg  = $this->getSSConfig();
        $ckCfg  = $this->getCloakConfig();
        $stCfg  = $this->getStlsConfig();
        if (!empty($ckCfg['Enabled'])) {
            $ssPort = (int) (getenv('CKPORT') ?: 8443);
        } elseif (!empty($stCfg['Enabled'])) {
            $ssPort = (int) (getenv('STLSPORT') ?: 3443);
        } elseif (!empty($ssCfg['plugin'])) {
            $ssPort = $this->nginxGetTypeCert() ? 443 : 80;
        } else {
            $ssPort = (int) $p['ss']['port'];
        }

        $data   = [
            [[
                'text'          => $this->i18n($p['wg']['enable'] ? 'on' : 'off') . ($p['wg']['enable'] ? ' ' . $p['wg']['port'] : ' port unavailable') . ' Wireguard',
                'callback_data' => "/changePort wg",
            ]],
            [[
                'text'          => $this->i18n($p['wg1']['enable'] ? 'on' : 'off') . ($p['wg1']['enable'] ? ' ' . $p['wg1']['port'] : ' port unavailable') . ' Wireguard',
                'callback_data' => "/changePort wg1",
            ]],
            [[
                'text'          => $this->i18n($p['tg']['enable'] ? 'on' : 'off') . ($p['tg']['enable'] ? ' ' . $p['tg']['port'] : ' port unavailable') . ' MTProto ',
                'callback_data' => "/changePort tg",
            ]],
            [[
                'text'          => $this->i18n($p['telemt']['enable'] ? 'on' : 'off') . ($p['telemt']['enable'] ? ' ' . $p['telemt']['port'] : ' port unavailable') . ' TeleMT',
                'callback_data' => "/changePort telemt",
            ]],
            [[
                'text'          => $this->i18n(!empty($c['ad']) ? 'on' : 'off') . ' 853 AdguardHome DoT',
                'callback_data' => "/hidePort ad",
            ]],
            [[
                'text'          => $this->i18n($p['ss']['enable'] ? 'on' : 'off') . " $ssPort Shadowsocks",
                'callback_data' => "/changePort ss",
            ]],
            [[
                'text'          => $this->i18n(!empty($c['dnstt']) ? 'on' : 'off') . ' 53 dnstt',
                'callback_data' => "/hidePort dnstt",
            ]],
            [[
                'text'          => $this->i18n($p['hy']['enable'] ? 'on' : 'off') . ($p['hy']['enable'] ? ' ' . $p['hy']['port'] : ' port unavailable') . ' hysteria',
                'callback_data' => "/changePort hy",
            ]],
            [[
                'text'          => $this->i18n('on') . ' ' . (isset($c['tt']['ports'][0]) ? explode(':', $c['tt']['ports'][0])[0] : getenv('TTPORT')) . ' TrustTunnel',
                'callback_data' => "/changePort tt",
            ]],
            [[
                'text'          => $this->i18n($this->ssh('pgrep openvpn', 'ovpn') ? 'on' : 'off') . ' ' . (isset($c['ovpn']['ports'][0]) ? explode(':', $c['ovpn']['ports'][0])[0] : getenv('OVPNPORT')) . ' OpenVPN',
                'callback_data' => "/changePort ovpn",
            ]],
        ];
        if (!empty($pac['restart'])) {
            $data[] = [
                [
                    'text'          => $this->i18n('restart'),
                    'callback_data' => "/restart",
                ],
            ];
        }
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/menu config",
            ],
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            implode("\n", $text ?: ['...']),
            $data ?: false,
        );
    }

    // Сервисы, у которых в текущем тексте override-compose стоит
    // `ports: !override`. PHP yaml_emit не умеет кастомные YAML-теги, поэтому
    // фиксируем их ДО парсинга и восстанавливаем ПОСЛЕ emit
    // (см. emitComposeWithOverrides). Любой yaml_parse→yaml_emit roundtrip без
    // этого молча теряет тег, и docker-compose сольёт ports основного файла и
    // override — контейнер получит и старый, и новый порт.
    private function detectComposeOverrides(string $content): array
    {
        $overrides = [];
        if (preg_match_all('/(\w+):\s*\n\s+ports:\s*!override/m', $content, $matches)) {
            foreach ($matches[1] as $service) {
                $overrides[$service] = true;
            }
        }
        return $overrides;
    }

    // Сериализует compose-структуру обратно в YAML и возвращает `ports: !override`
    // тем сервисам, что перечислены в $overrides (см. detectComposeOverrides).
    private function emitComposeWithOverrides(array $c, array $overrides): string
    {
        $yaml = yaml_emit($c);
        foreach ($overrides as $service => $val) {
            // Заменяем "ports:" на "ports: !override" для конкретного сервиса
            $yaml = preg_replace(
                '/(' . preg_quote($service, '/') . ':\s*\n\s+)ports:/m',
                '${1}ports: !override',
                $yaml
            );
        }
        return $yaml;
    }

    public function hidePort($container)
    {
        $ports = [
            'ad'    => '853:853',
            'dnstt' => '53:53/udp',
        ];
        $f = '/docker/compose';
        $content = is_file($f) ? file_get_contents($f) : '';

        // Находим все сервисы с !override для ports (фиксируем до парсинга)
        $overrides = $this->detectComposeOverrides($content);

        // Парсим YAML
        $c = $content ? yaml_parse($content) : [];

        // Изменяем структуру
        if (!empty($c['services'][$container])) {
            unset($c['services'][$container]);
        } else {
            $c['services'][$container]['ports'][] = $ports[$container];
        }

        // Записываем обратно (с восстановлением !override)
        if (empty($c['services'])) {
            file_put_contents($f, '');
        } else {
            file_put_contents($f, $this->emitComposeWithOverrides($c, $overrides));
        }

        $pac = $this->getPacConf();
        $pac['restart'] = 1;
        $this->setPacConf($pac);
        $this->ports();
    }

    public function setPort($port, $container)
    {
        $port  = (int) $port;
        $ovpnProto = str_starts_with($this->getOvpnProto(), 'tcp') ? 'tcp' : 'udp';
        $ports = [
            'hy'   => ['443/udp'],
            'tt'   => ['8443/tcp', '8443/udp'],
            'ovpn' => ["1194/$ovpnProto"],
        ];
        foreach ($this->ports as $service => $target) {
            $ports[$service] = [$target];
        }
        // Port value that means "remove from override" for each service.
        // hy uses 443 (its in-container port); tt/ovpn have no port mapping in
        // main compose, so 0/empty disables external exposure.
        $disable = [
            'hy'   => 443,
            'tg'   => 443,
            'tt'   => 0,
            'ovpn' => 0,
        ];
        $reserved = [80, 443];
        // Сервисы, у которых ports заданы в основном compose — для них
        // override.yml ДОЛЖЕН использовать !override, иначе docker-compose
        // объединит массивы и контейнер получит и старый, и новый порт.
        $forceOverride = ['tt' => true];

        $f = '/docker/compose';
        $content = is_file($f) ? file_get_contents($f) : '';

        // Находим все сервисы с !override для ports (фиксируем до парсинга)
        $overrides = $this->detectComposeOverrides($content);

        // Парсим YAML
        $c = $content ? yaml_parse($content) : [];

        // Изменяем структуру
        if (!empty($port) && is_numeric($port) && !in_array($port, $reserved, true) && $port != ($disable[$container] ?? 0) && !empty($ports[$container])) {
            $c['services'][$container]['ports'] = array_map(
                fn($p) => "$port:$p",
                $ports[$container]
            );
            if (!empty($forceOverride[$container])) {
                $overrides[$container] = true;
            }
        } else {
            unset($c['services'][$container]);
        }

        // Записываем обратно (с восстановлением !override)
        if (empty($c['services'])) {
            file_put_contents($f, '');
        } else {
            file_put_contents($f, $this->emitComposeWithOverrides($c, $overrides));
        }

        // TT идёт через nginx в upstream-контейнере: client → host:PORT
        // → DNAT (Docker iptables ИЛИ ручной nftables) → upstream:PORT
        // → proxy_pass trusttunnel (tt:8443). Меняем listen-порт в
        // upstream.conf и перезагружаем nginx, чтобы новый порт начал
        // приниматься без полного recreate. Заодно синхронизируем
        // TTPORT в .env, чтобы fallback-значение для бота совпадало.
        if ($container === 'tt') {
            $listen = ($port > 0 && $port != ($disable['tt'] ?? 0)) ? $port : (int)(getenv('TTPORT') ?: 2443);
            $this->setUpstreamPortTt($listen);
            $this->setEnvVar('TTPORT', (string) $listen);
        }

        // Same architecture as TT: client → host:PORT → DNAT → upstream:PORT
        // → proxy_pass openvpn (ovpn:1194/udp). Sync upstream listen + .env
        // fallback. UDP-only, no TCP.
        if ($container === 'ovpn') {
            $listen = ($port > 0 && $port != ($disable['ovpn'] ?? 0)) ? $port : (int)(getenv('OVPNPORT') ?: 1194);
            $this->setUpstreamPortOvpn($listen);
            $this->setEnvVar('OVPNPORT', (string) $listen);
        }
        if ($container === 'tg') {
            $listen = ($port > 0 && $port != ($disable['tg'] ?? 0)) ? $port : (int)(getenv('TGPORT') ?: 4443);
            $this->setEnvVar('TGPORT', (string) $listen);
        }

        $pac = $this->getPacConf();
        $pac['restart'] = 1;
        $this->setPacConf($pac);
        $this->ports();
    }

    public function setUpstreamPortTt($port)
    {
        $port  = (int) $port ?: 2443;
        $f     = '/config/upstream.conf';
        if (!file_exists($f)) {
            return;
        }
        $nginx = file_get_contents($f);
        $block = "#tt-port\n    server {\n        listen      $port reuseport;\n        proxy_pass  trusttunnel;\n    }\n    server {\n        listen      $port udp reuseport;\n        proxy_pass  trusttunnel;\n    }\n    #tt-port";
        // Маркер должен быть на собственной строке (с необязательным
        // отступом), чтобы не совпасть с упоминанием "#tt-port" внутри
        // комментариев выше по файлу.
        $re = '~^[ \t]*#tt-port[ \t]*\R.+?^[ \t]*#tt-port[ \t]*$~sm';
        if (!preg_match($re, $nginx)) {
            return; // markers were stripped by manual edit; bail out
        }
        $nginx = preg_replace($re, $block, $nginx);
        file_put_contents($f, $nginx);
        $this->ssh('nginx -s reload 2>&1', 'up');
    }

    public function setUpstreamPortOvpn($port, $proto = null)
    {
        $port  = (int) $port ?: 1194;
        $proto = $proto ?: $this->getOvpnProto();
        $f     = '/config/upstream.conf';
        if (!file_exists($f)) {
            return;
        }
        $nginx  = file_get_contents($f);
        $listen = str_starts_with($proto, 'tcp')
            ? "listen      $port reuseport;"
            : "listen      $port udp reuseport;";
        $block = "#ovpn-port\n    server {\n        $listen\n        proxy_pass  openvpn;\n    }\n    #ovpn-port";
        $re = '~^[ \t]*#ovpn-port[ \t]*\R.+?^[ \t]*#ovpn-port[ \t]*$~sm';
        if (!preg_match($re, $nginx)) {
            return;
        }
        $nginx = preg_replace($re, $block, $nginx);
        file_put_contents($f, $nginx);
        $this->ssh('nginx -s reload 2>&1', 'up');
    }

    public function setEnvVar($key, $value)
    {
        // Контейнер php монтирует корневой .env как /mirror/.env.
        $f = '/mirror/.env';
        if (!file_exists($f) || !preg_match('~^[A-Z_][A-Z0-9_]*$~', $key)) {
            return;
        }
        $content = file_get_contents($f);
        $line    = "$key=$value";
        if (preg_match('~^' . preg_quote($key, '~') . '=.*$~m', $content)) {
            $content = preg_replace('~^' . preg_quote($key, '~') . '=.*$~m', $line, $content);
        } else {
            $content = rtrim($content, "\n") . "\n$line\n";
        }
        file_put_contents($f, $content);
    }

    public function branches()
    {
        exec('git -C / branch -r', $m);
        array_shift($m);
        foreach ($m as $k => $v) {
            $data[] = [
                [
                    'text'          => $v,
                    'callback_data' => "/changeBranch $k",
                ]
            ];
        }
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/menu update",
            ]
        ];
        $this->update($this->input['from'], $this->input['message_id'], 'branches', $data);
    }

    public function changeBranch($i)
    {
        exec('git -C / branch -r', $m);
        array_shift($m);
        foreach ($m as $k => $v) {
            if ($i == $k) {
                file_put_contents('/update/branch', trim(str_replace('origin/', '', $v)));
            }
        }
        $this->menu('update');
    }

    public function logs()
    {
        $p = $this->getPacConf();
        foreach (scandir('/logs/') as $k => $v) {
            if (!preg_match('~^\.~', $v)) {
                $size   = filesize("/logs/$v");
                $data[] = [
                    [
                        'text'          => "$size $v",
                        'callback_data' => "/getLog $k",
                    ],
                    [
                        'text'          => $this->i18n('clean'),
                        'callback_data' => "/clearLog $k",
                    ],
                ];
            }
        }
        $data[] = [
            [
                'text'          => $this->i18n('clean all'),
                'callback_data' => "/cleanLog",
            ],
        ];
        $autocleanlogs = array_filter(explode('/', $p['autocleanlogs']));
        if (!empty($autocleanlogs)) {
            if (!empty(strtotime($autocleanlogs[0])) && !empty(strtotime($autocleanlogs[1]))) {
                $autocleanlogs = "{$autocleanlogs[0]} start / {$autocleanlogs[1]} period";
            } else {
                $autocleanlogs = $this->i18n('off') . " {$p['autocleanlogs']} - wrong format";
            }
        }
        $data[] = [
            [
                'text'          => $this->i18n('autoclean'). ': ' . ($autocleanlogs ?: $this->i18n('off')),
                'callback_data' => "/autoCleanLogs",
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => "/menu config",
            ],
        ];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            implode("\n", ['...']),
            $data ?: false,
        );
    }

    public function getLog($i)
    {
        foreach (scandir('/logs/') as $k => $v) {
            if (!preg_match('~^\.~', $v)) {
                $logs[$k] = $v;
            }
        }
        $this->sendFile(
            $this->input['chat'],
            curl_file_create("/logs/{$logs[$i]}"),
        );
    }

    public function clearLog($i)
    {
        foreach (scandir('/logs/') as $k => $v) {
            if ($i == $k) {
                file_put_contents("/logs/$v", '');
                break;
            }
        }
        $this->logs();
    }

    public function cleanLog()
    {
        foreach (scandir('/logs/') as $k => $v) {
            file_put_contents("/logs/$v", '');
        }
        $this->logs();
    }

    public function delLog($i)
    {
        foreach (scandir('/logs/') as $k => $v) {
            if ($i == $k) {
                unlink("/logs/$v");
                break;
            }
        }
        $this->logs();
    }

    public function selfUpdate()
    {
        $ip                         = getenv('IP');
        $rm                         = explode(':', trim(file_get_contents('/update/reload_message')));
        $m                          = file_get_contents('/update/message');
        $this->input['chat']        = $rm[0];
        $this->input['message_id']  = $rm[1] ?? false;
        $this->input['callback_id'] = $rm[1] ?? false;
        if (file_exists($this->update)) {
            $this->selfupdate = true;
            if (!empty($m)) {
                $this->send($this->input['chat'], "<pre>$m</pre>", $rm[1]);
            }
            $r = $this->send($this->input['chat'], "import settings");
            $this->input['message_id']  = $r['result']['message_id'];
            $this->input['callback_id'] = $r['result']['message_id'];
            $this->importFile($this->update);
            unlink($this->update);
        }
        file_put_contents('/update/message', '');
        file_put_contents('/update/reload_message', '');
        $pac = $this->getPacConf();
        unset($pac['restart']);
        $this->setPacConf($pac);
    }

    public function backup()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter like: start / period",
            $this->input['message_id'],
            reply: 'enter like: now / 12 hours',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'setBackup',
            'args'           => [],
        ];
    }

    public function autoCleanLogs()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter like: start / period",
            $this->input['message_id'],
            reply: 'enter like: now / 12 hours',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'setAutoCleanLogs',
            'args'           => [],
        ];
    }

    public function changeFakeDomain()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter domain",
            $this->input['message_id'],
            reply: 'enter domain',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'setFakeDomain',
            'args'           => [],
        ];
    }

    public function changeTGDomain()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter domain",
            $this->input['message_id'],
            reply: 'enter domain',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'setTelegramDomain',
            'args'           => [],
        ];
    }

    public function changeTGAdtag()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter adtag or 0 for disable",
            $this->input['message_id'],
            reply: 'enter adtag or 0 for disable',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'setTelegramAdtag',
            'args'           => [],
        ];
    }

    public function setFakeDomain($domain, $self = false)
    {
        $c = $this->getXray();
        $p = $this->getPacConf();
        $c['inbounds'][0]['streamSettings']['realitySettings']['serverNames'][0] = $domain;
        $c['inbounds'][0]['streamSettings']['realitySettings']['dest'] = $self ? "10.10.1.2:443" : "$domain:443";
        $p['reality']['domain'] = $domain;
        $p['reality']['destination'] = $self ? "10.10.1.2:443" : "$domain:443";
        $this->setPacConf($p);
        $this->restartXray($c);
        $this->setUpstreamDomain($domain);
        $this->xray();
    }

    public function selfFakeDomain()
    {
        $c = $this->getPacConf();
        if (!empty($c['domain'])) {
            $this->setFakeDomain($c['domain'], 1);
        } else{
            $this->answer($this->input['callback_id'], 'empty domain', true);
        }
    }

    public function changeTransport($transport)
    {
        $p = $this->getPacConf();
        $x = $this->getXray();
        $h = $this->getHashBot();

        $p['reality']['domain']      = $p['reality']['domain'] ?: 'yandex.ru';
        $p['reality']['destination'] = $p['reality']['destination'] ?: $p['reality']['domain'] . ':443';
        $p['transport'] = $transport;

        $p['reality']['domain']      = $x['inbounds'][0]['streamSettings']['realitySettings']['serverNames'][0] ?? $p['reality']['domain'];
        $p['reality']['destination'] = $x['inbounds'][0]['streamSettings']['realitySettings']['dest'] ?? $p['reality']['destination'];
        $p['reality']['shortId']     = $x['inbounds'][0]['streamSettings']['realitySettings']['shortIds'][0] ?? $p['reality']['shortId'];

        if (empty($p['xray'])) {
            $shortId = trim($this->ssh('openssl rand -hex 8', 'xr'));
            $keys    = $this->ssh('xray x25519', 'xr');
            preg_match('~^PrivateKey:\s([^\s]+)~m', $keys, $m);
            $private = trim($m[1]);
            preg_match('~^Password(?:\s*\(PublicKey\))?:\s([^\s]+)~m', $keys, $m);
            $public = trim($m[1]);
            $p['xray'] = $public;
            $p['reality']['shortId']    = $shortId;
            $p['reality']['privateKey'] = $private;
        }


        $x['inbounds'][0]['protocol'] = 'vless';

        switch ($transport) {
            case 'xhttp':
                foreach ($x['inbounds'][0]['settings']['clients'] as $k => $v) {
                    unset($x['inbounds'][0]['settings']['clients'][$k]['flow']);
                }
                $x['inbounds'][0]['streamSettings'] = [
                    "network"       => "xhttp",
                    "xhttpSettings" => [
                        "mode"  => "auto",
                        "path"  => "/ws$h",
                        "extra" => [
                            "noSSEHeader"          => true,
                            "xPaddingBytes"        => "100-1000",
                            "scMaxBufferedPosts"   => 30,
                            "scMaxEachPostBytes"   => 1000000,
                            "scStreamUpServerSecs" => "20-80"
                        ]
                    ]
                ];
                break;

            case 'trojan-grpc':
                $x['inbounds'][0]['protocol'] = 'trojan';
                foreach ($x['inbounds'][0]['settings']['clients'] as $k => $v) {
                    unset($x['inbounds'][0]['settings']['clients'][$k]['flow']);
                    $x['inbounds'][0]['settings']['clients'][$k]['password'] = $v['password'] ?? bin2hex(random_bytes(16));
                }
                $x['inbounds'][0]['streamSettings'] = [
                    "network"      => "grpc",
                    "grpcSettings" => [
                        "serviceName" => "grpc$h",
                    ]
                ];
                break;

            case 'Reality':
                foreach ($x['inbounds'][0]['settings']['clients'] as $k => $v) {
                    $x['inbounds'][0]['settings']['clients'][$k]['flow'] = 'xtls-rprx-vision';
                }
                $x['inbounds'][0]['streamSettings'] = [
                    "network"         => "tcp",
                    "realitySettings" => [
                        "dest"         => $p['reality']['destination'] ?: $x['inbounds'][0]['streamSettings']['realitySettings']['dest'],
                        "maxClientVer" => "",
                        "maxTimeDiff"  => 0,
                        "minClientVer" => "",
                        "privateKey"   => $p['reality']['privateKey'],
                        "serverNames"  => [
                            $p['reality']['domain'] ?: $x['inbounds'][0]['streamSettings']['realitySettings']['serverNames'][0]
                        ],
                        "shortIds" => [$p['reality']['shortId']] ?: $x['inbounds'][0]['streamSettings']['realitySettings']['shortIds'][0],
                        "show"     => false,
                        "xver"     => 0
                    ],
                    "tcpSettings" => [
                        "acceptProxyProtocol" => true
                    ],
                    "sockopt" => [
                        "acceptProxyProtocol" => true
                    ],
                    "security" => "reality"
                ];
                break;

            default:
                $x['inbounds'][0]['streamSettings'] = [
                    "network"    => "ws",
                    "wsSettings" => [
                        "path" => "/ws$h"
                    ]
                ];
                foreach ($x['inbounds'][0]['settings']['clients'] as $k => $v) {
                    unset($x['inbounds'][0]['settings']['clients'][$k]['flow']);
                }
                break;
        }

        $this->setUpstreamDomain($transport == 'Reality'
            ? ($p['reality']['domain'] ?: $x['inbounds'][0]['streamSettings']['realitySettings']['serverNames'][0])
            : 't'
        );
        $this->setPacConf($p);
        $this->restartXray($x);
        $this->xray();
    }

    public function setBackup($text)
    {
        $text = trim($text);
        $c    = $this->getPacConf();
        if (empty($text)) {
            $c['backup'] = '';
        } else {
            [$start, $period] = explode('/', $text);
            if (!empty(strtotime($start)) && !empty(strtotime($period))) {
                $c['backup'] = implode(' / ', [date('Y-m-d H:i', strtotime($start)), trim($period)]);
            } else {
                $this->send($this->input['from'], $this->input['message'] . ' - wrong format');
            }
        }
        if ($c['pinbackup']) {
            $this->pinAdmin($c['pinbackup'], 1);
            $c['pinbackup'] = '';
        }
        $this->setPacConf($c);
        $this->menu('config');
    }

    public function setAutoCleanLogs($text)
    {
        $text = trim($text);
        $c    = $this->getPacConf();
        if (empty($text)) {
            $c['autocleanlogs'] = '';
        } else {
            [$start, $period] = explode('/', $text);
            if (!empty(strtotime($start)) && !empty(strtotime($period))) {
                $c['autocleanlogs'] = implode(' / ', [date('Y-m-d H:i', strtotime($start)), trim($period)]);
            } else {
                $this->send($this->input['from'], $this->input['message'] . ' - wrong format');
            }
        }
        $this->setPacConf($c);
        $this->logs();
    }

    public function debug()
    {
        $file = __DIR__ . '/config.php';
        require $file;
        $c['debug'] = !$c['debug'];
        file_put_contents($file, "<?php\n\n\$c = " . var_export($c, true) . ";\n");
        $this->menu('config');
    }

    public function getStatusPeer(string $publickey, array $peers)
    {
        foreach ($peers as $k => $v) {
            if ($v['peer'] == $publickey) {
                return $v;
            }
        }
    }

    public function getInstanceWG($k = false)
    {
        if (!empty($k)) {
            return ($this->wg ?? $this->getPacConf()['wg_instance']) ? 'wg1_' : '';
        }
        return ($this->wg ?? $this->getPacConf()['wg_instance']) ? 'wg1' : 'wg';
    }

    public function readConfig()
    {
        $r = $this->ssh('cat /etc/wireguard/wg0.conf', $this->getInstanceWG());
        $r = explode(PHP_EOL, $r);
        $r = array_filter($r);
        $i = 0;
        foreach ($r as $k => $v) {
            if (preg_match('~\[(.+)\]~', $v, $m)) {
                $i++;
                if ($m[1] == 'Interface') {
                    $data[$i]['type'] = 'interface';
                } else {
                    $data[$i]['type'] = 'peer';
                }
            } else {
                $t = explode('=', $v, 2);
                $data[$i][trim($t[0])] = trim($t[1]);
            }
        }
        foreach ($data as $v) {
            $type = $v['type'];
            unset($v['type']);
            if ($type == 'interface') {
                $d['interface'] = $v;
            } else {
                $d['peers'][] = $v;
            }
        }
        return $d;
    }

    public function nginxGetTypeCert()
    {
        $conf = $this->ssh('cat /etc/nginx/nginx.conf', 'ng');
        preg_match("/#~([^\s]+)/", $conf, $m);
        return $m[1] ?? '';
    }

    public function readStatus()
    {
        $r = $this->ssh($this->getWGType(), $this->getInstanceWG());
        $r = explode(PHP_EOL, $r);
        $r = array_filter($r);
        $i = 0;
        foreach ($r as $k => $v) {
            if (preg_match('~^(interface|peer):~', $v, $m)) {
                $i++;
                if ($m[1] == 'interface') {
                    $data[$i]['type'] = 'interface';
                } else {
                    $data[$i]['type'] = 'peer';
                }
            }
            $t = explode(':', $v, 2);
            $data[$i][trim($t[0])] = trim($t[1]);
        }
        foreach ($data as $v) {
            $type = $v['type'];
            unset($v['type']);
            if ($type == 'interface') {
                $d['interface'] = $v;
            } else {
                $d['peers'][] = $v;
            }
        }
        return $d;
    }

    public function getName(array $a): string
    {
        $name = '';
        foreach ($a as $k => $v) {
            if (preg_match('~^#.*name$~', $k)) {
                $name = $v;
            }
        }
        $name = $name ?: $a['AllowedIPs'] ?: $a['Address'];
        return $name;
    }

    public function createConfig($data)
    {
        $pac = $this->getPacConf();
        $conf[] = "[Interface]";
        if (empty($data['interface']['ListenPort'])) {
            if (empty($data['interface']['DNS'])) {
                $data['interface']['DNS'] = $pac[$this->getInstanceWG(1) . 'dns'] ?: $this->dns;
            }
            if (empty($data['interface']['MTU'])) {
                $data['interface']['MTU'] = $pac[$this->getInstanceWG(1) . 'mtu'] ?: $this->mtu;
            }
        }
        foreach ($data['interface'] as $k => $v) {
            $conf[] = "$k = $v";
        }
        $ports = $this->getPorts();
        if (!empty($data['peers'])) {
            foreach ($data['peers'] as $peer) {
                $conf[] = '';
                $conf[] = $peer['# PublicKey'] ? '# [Peer]' : '[Peer]';
                if (!empty($peer['Endpoint'])) {
                    $peer['Endpoint'] = ($pac[$this->getInstanceWG(1) . 'endpoint'] ? $this->ip : $this->getDomain()) . ":" . $ports[$this->getInstanceWG()]['port'];
                }
                foreach ($peer as $k => $v) {
                    $conf[] = "$k = $v";
                }
            }
        }
        return implode(PHP_EOL, $conf);
    }

    public function presharedKey()
    {
        $c = $this->getPacConf();
        if (empty($c[$this->getInstanceWG(1) . 'presharedkey'])) {
            $c[$this->getInstanceWG(1) . 'presharedkey'] = trim($this->ssh("{$this->getWGType()} genpsk", $this->getInstanceWG()));
            $this->setPacConf($c);
        }
        return $c[$this->getInstanceWG(1) . 'presharedkey'];
    }

    // ВАЖНО — симметрия server↔client.
    // Возвращаемый набор Jc/Jmin/Jmax/S1-S4/H1-H4/I1-I5 пишется ОДИНАКОВО
    // в [Interface] на сервере и в [Interface] каждого клиента (см. switchAmnezia).
    // Это требование протокола amneziawg-go: CPS-паттерн (I1-I5) описывает
    // junk-байты, которые сторона ВСТАВЛЯЕТ в свой исходящий handshake И
    // КОНСЬЮМИТ из входящего. Если у сервера и клиента CPS-строки разные,
    // принимающая сторона неверно вычитывает байты потока и handshake падает.
    // Поэтому раздельных server-I1 / client-I1 не существует на уровне config.
    //
    // Diversity fingerprint'а во времени обеспечивается ротацией I1-I5/S3-S4
    // (rotateAmneziaJunk + maybeRotateAmnezia, см. выше) — оба пира берут
    // новый паттерн одновременно из общего config-файла после повторного
    // импорта клиентских конфигов.
    public function amneziaKeys()
    {
        $c = $this->getPacConf();
        $k = $this->getInstanceWG(1) . 'amnezia_keys';
        if (empty($c[$k])) {
            $c[$k] = $this->generateAmneziaKeys($c[$this->getInstanceWG(1) . 'amnezia_tpl'] ?? 'standard_2');
            $this->setPacConf($c);
        }
        return $c[$k];
    }

    // Templates for AmneziaWG key generation. Ranges follow official docs
    // (docs.amnezia.org/documentation/amnezia-wg): Jc 0–10, Jmin/Jmax 64–1024,
    // S1/S2/S3 0–64, S4 0–32. Constraints: S1+56 ≠ S2 and S1 ≠ S2.
    // I1 presence ⇒ 2.0; I1 absent ⇒ 1.x. CPS tags supported by amneziawg-go:
    // <b HEX>, <r N>, <rc N>, <rd N>, <t>. (<c> removed upstream — not used.)
    // H1–H4 format:
    //   1.x: distinct non-zero 32-bit integers.
    //   2.0: non-overlapping "MIN-MAX" ranges across uint32 space (server picks
    //        a random value per session, raising DPI cost).
    public function generateAmneziaKeys($template = 'standard_2')
    {
        $rngS = function ($min, $max) {
            $s1 = random_int($min, $max);
            do {
                $s2 = random_int($min, $max);
            } while ($s1 + 56 === $s2 || $s1 === $s2);
            return [$s1, $s2];
        };

        // 2.0 H1-H4: non-overlapping ranges in AWG 2.0 "MIN-MAX" format.
        // 4 strict quarters inside signed int32 space to support all platforms.
        $rngH2 = function () {
            $segments = [
                [0x01000000, 0x1FFFFFFF],
                [0x20000000, 0x3FFFFFFF],
                [0x40000000, 0x5FFFFFFF],
                [0x60000000, 0x7FFFFFFF],
            ];
            shuffle($segments);
            $h = [];
            foreach ($segments as [$seg_min, $seg_max]) {
                // Unique range width per header increases entropy.
                $range_width = random_int(5_000_000, 50_000_000);
                $start = random_int($seg_min, $seg_max - $range_width);
                $h[] = $start . '-' . ($start + $range_width);
            }
            return ['H1' => $h[0], 'H2' => $h[1], 'H3' => $h[2], 'H4' => $h[3]];
        };

        // 1.x H1-H4: distinct non-zero 32-bit integers.
        $rngH1 = function () {
            $h = [];
            while (count($h) < 4) {
                $v = random_int(1, 4_294_967_295);
                if (!in_array($v, $h, true)) {
                    $h[] = $v;
                }
            }
            return ['H1' => $h[0], 'H2' => $h[1], 'H3' => $h[2], 'H4' => $h[3]];
        };

        switch ($template) {
            // 2.0 templates: каждое из I1–I5 даёт пакет ≥100 байт
            // (рекомендуемый минимум, habr.com/ru/companies/amnezia/articles/1014636/).
            case 'aggressive_2':
                [$s1, $s2] = $rngS(40, 64);
                return $rngH2() + [
                    'Jc' => 10, 'Jmin' => 256, 'Jmax' => 1024,
                    'S1' => $s1, 'S2' => $s2,
                    'S3' => random_int(32, 64), 'S4' => random_int(16, 32),
                    'I1' => '<b 0xc000000001><r ' . random_int(150, 250) . '>',
                    'I2' => '<t><r ' . random_int(100, 200) . '>',
                    'I3' => '<r ' . random_int(100, 200) . '>',
                    'I4' => '<rd ' . random_int(16, 24) . '><r ' . random_int(100, 150) . '>',
                    'I5' => '<rc ' . random_int(100, 150) . '>',
                ];

            case 'mobile_2':
                // Для mobile приоритет маскировки выше экономии батареи/трафика.
                [$s1, $s2] = $rngS(15, 32);
                return $rngH2() + [
                    'Jc' => random_int(2, 4), 'Jmin' => 64, 'Jmax' => 256,
                    'S1' => $s1, 'S2' => $s2,
                    'S3' => random_int(0, 32), 'S4' => random_int(0, 16),
                    'I1' => '<b 0xc000000001><r ' . random_int(100, 150) . '>',
                    'I2' => '<t><r ' . random_int(100, 130) . '>',
                    'I3' => '<r ' . random_int(100, 130) . '>',
                    'I4' => '<rd ' . random_int(6, 12) . '><r ' . random_int(100, 130) . '>',
                    'I5' => '<rc ' . random_int(100, 130) . '>',
                ];

            case 'classic_1':
                [$s1, $s2] = $rngS(15, 64);
                return $rngH1() + [
                    'Jc' => random_int(3, 10), 'Jmin' => 64, 'Jmax' => 1000,
                    'S1' => $s1, 'S2' => $s2,
                ];

            case 'standard_2':
            default:
                [$s1, $s2] = $rngS(15, 64);
                return $rngH2() + [
                    'Jc' => random_int(3, 10), 'Jmin' => 64, 'Jmax' => 1024,
                    'S1' => $s1, 'S2' => $s2,
                    'S3' => random_int(0, 64), 'S4' => random_int(0, 32),
                    'I1' => '<b 0xc000000001><r ' . random_int(120, 200) . '>',
                    'I2' => '<t><r ' . random_int(100, 150) . '>',
                    'I3' => '<r ' . random_int(100, 150) . '>',
                    'I4' => '<rd ' . random_int(8, 16) . '><r ' . random_int(100, 150) . '>',
                    'I5' => '<rc ' . random_int(100, 150) . '>',
                ];
        }
    }

    public function createPeer($ips_user = false, $name = false)
    {
        $conf      = $this->readConfig();
        $ipnet     = explode('/', $conf['interface']['Address']);
        $server_ip = ip2long($ipnet[0]);
        $ips       = [$server_ip];
        $bitmask   = $ipnet[1];
        if (!empty($conf['peers'])) {
            foreach ($conf['peers'] as $k => $v) {
                $ips[] = ip2long(explode('/', $v['AllowedIPs'] ?: $v['# AllowedIPs'])[0]);
            }
        }
        $ip_count = (1 << (32 - $bitmask)) - count($ips) - 1;
        for ($i = 1; $i < $ip_count; $i++) {
            $ip = $i + $server_ip;
            if (!in_array($ip, $ips)) {
                $client_ip = long2ip($ip);
                break;
            }
        }
        $public_server_key = trim($this->ssh("echo {$conf['interface']['PrivateKey']} | {$this->getWGType()} pubkey", $this->getInstanceWG()));
        $private_peer_key  = trim($this->ssh("{$this->getWGType()} genkey", $this->getInstanceWG()));
        $public_peer_key   = trim($this->ssh("echo $private_peer_key | {$this->getWGType()} pubkey", $this->getInstanceWG()));

        $name = ($name ? "$name" : '') . time();

        $conf['peers'][] = array_merge([
                '## name'    => $name,
                'PublicKey'  => $public_peer_key,
                'AllowedIPs' => "$client_ip/32",
            ],
            $this->getPacConf()[$this->getInstanceWG(1) . 'amnezia'] ? ['PresharedKey' => $this->presharedKey()] : []
        );
        $client_conf = [
            'interface' => array_merge(
                [
                    '## name'    => $name,
                    'PrivateKey' => $private_peer_key,
                    'Address'    => "$client_ip/32",
                ],
                $this->getPacConf()[$this->getInstanceWG(1) . 'amnezia'] ? $this->amneziaKeys() : []
            ),
            'peers' => [
                    array_merge(
                        [
                            'PublicKey'           => $public_server_key,
                            'AllowedIPs'          => $ips_user ?: "0.0.0.0/0",
                            'PersistentKeepalive' => 20,
                        ],
                        $this->getPacConf()[$this->getInstanceWG(1) . 'amnezia'] ? ['PresharedKey' => $this->presharedKey()] : []
                    ),
                ],
        ];
        $k = $this->saveClient($client_conf);
        $this->restartWG($this->createConfig($conf));
        $this->menu('client', "{$k}_-2");
    }

    public function deleteClient(int $client)
    {
        $clients = $this->readClients();
        unset($clients[$client]);
        $this->saveClients(array_values($clients));
    }

    public function saveClient(array $client)
    {
        $r = array_merge($this->readClients(), [$client]);
        $this->saveClients($r);
        return count($r) - 1;
    }

    public function syncPortClients()
    {
        for ($i=0; $i < 2; $i++) {
            $this->wg = $i;
            $this->saveClients($this->readClients());
        }
        unset($this->wg);
    }

    public function saveClients(array $clients)
    {
        $c      = $this->getPacConf();
        $ports  = $this->getPorts();
        $domain = ($c['domain'] ?: $this->ip) . ":" . $ports[$this->getInstanceWG()]['port'];
        foreach ($clients as $k => $v) {
            $clients[$k]['peers'][0]['Endpoint'] = $domain;
        }
        file_put_contents($this->getInstanceWG(1) ? $this->clients1 : $this->clients, json_encode($clients, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
    }

    public function getWGType($revert = 0)
    {
        $wg = $this->getPacConf()[$this->getInstanceWG(1) . 'amnezia'];
        return ($revert ? !$wg : $wg) ? 'awg' : 'wg';
    }

    public function restartWG($conf_str, $switch = false)
    {
        $this->ssh("echo '$conf_str' > /etc/wireguard/wg0.conf", $this->getInstanceWG());
        $this->ssh("{$this->getWGType((int) $switch)}-quick down wg0", $this->getInstanceWG());
        $this->ssh("{$this->getWGType()}-quick up wg0", $this->getInstanceWG());
        return true;
    }

    public function autoupdate()
    {
        $p = $this->getPacConf();
        $p['autoupdate'] = !$p['autoupdate'];
        $this->setPacConf($p);
        $this->menu('config');
    }

    public function disconnect(...$args)
    {
        $this->send($this->input['chat'], "disconnect: \n" . var_export($args, true) . "\n", $this->input['message_id']);
    }

    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
    {
        try {
            $c = ssh2_connect($service, 22);
            if (empty($c)) {
                throw new Exception("no connection to $service: \n$cmd\n" . var_export($c, true));
            }
            $a = ssh2_auth_pubkey_file($c, 'root', '/ssh/key.pub', '/ssh/key');
            if (empty($a)) {
                throw new Exception("auth fail: \n$cmd\n" . var_export($a, true));
            }

            // Оборачиваем команду для выполнения в фоновом режиме
            if (!$wait) {
                // nohup запускает процесс независимо от SSH-сессии
                // & переносит процесс в фон
                // </dev/null >/dev/null 2>&1 перенаправляет все потоки ввода-вывода
                $cmd = "nohup sh -c \"$cmd 2>&1 | tee -a $log >&3\" 3>/proc/1/fd/1 </dev/null &";
            }


            $s = ssh2_exec($c, $cmd);
            if (empty($s)) {
                throw new Exception("exec fail: \n$cmd\n" . var_export($s, true));
            }

            $data = "";
            if ($wait) {
                // Только для синхронных команд читаем вывод
                stream_set_blocking($s, true);
                while ($buf = fread($s, 4096)) {
                    $data .= $buf;
                }
            } else {
                // Для фоновых команд просто даем время запуститься
                stream_set_blocking($s, false);
                usleep(100000); // 100ms для запуска процесса
            }

            fclose($s);
            ssh2_disconnect($c);
        } catch (Exception | Error $e) {
            if (!empty($GLOBALS['debug'])) {
                $this->send($this->input['chat'], $e->getMessage(), $this->input['message_id']);
            }
        }
        return $data;
    }

    public function request($method, $data, $json_header = 0)
    {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $this->api . $method,
            CURLOPT_CUSTOMREQUEST  => 'POST',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => $json_header ? [
                'Content-Type: application/json'
            ] : [],
            CURLOPT_POSTFIELDS     => $data,
        ]);
        $res = curl_exec($ch);
        $r   = json_decode($res, true);
        if (!empty($res['description']) || is_null($res)) {
            file_put_contents('/logs/requests_error', var_export([
                'r' => [
                    'method' => $method,
                    'data'   => $data,
                ],
                'a' => $res,
            ], true) . "\n", FILE_APPEND);
        }
        return $r;
    }

    public function polling()
    {
        $offset = -1;
        while (true) {
            $r = $this->request('getUpdates', [
                'offset'  => $offset,
                'limit'   => 3,
                'timeout' => 5,
            ]);
            if (!empty($r['description'])) {
                error_log('getUpdates error: ' . $r['description']);
                sleep(3);
                continue;
            }
            file_put_contents('/start', 1);
            if (!empty($r['result'])) {
                foreach ($r['result'] as $v) {
                    try {
                        $this->input($v);
                    } catch (Throwable $e) {
                        error_log($e);
                    } finally {
                        session_write_close();
                    }
                    $offset = max($offset, $v['update_id']);
                }
                $offset++;
            } else {
                sleep(1);
            }
        }
    }

    public function setcommands()
    {
        $data = [
            'commands' => [
                [
                    'command'     => 'menu',
                    'description' => '...',
                ],
                [
                    'command'     => 'id',
                    'description' => 'your id telegram',
                ],
            ]
        ];
        $this->request('setMyCommands', json_encode($data), 1);
    }

    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false)
    {
        if (is_null($text)) {
            $text = '';
        }
        if ($button) {
            $extra = ['inline_keyboard' => $button];
        }
        if (false !== $reply) {
            $extra = [
                'force_reply'             => true,
                'input_field_placeholder' => $reply,
                'selective'               => true,
            ];
        }
        $length = 3096;
        if (mb_strlen($text, 'utf-8') > $length) {
            $tails = $this->splitText($text, $length);
            foreach ($tails as $k => $v) {
                $data = [
                    'chat_id'                  => $chat,
                    'text'                     => "$v\n",
                    'parse_mode'               => $mode,
                    // 'disable_web_page_preview' => true,
                    'disable_notification'     => $disable_notification,
                    'reply_to_message_id'      => 0 == $k && $to > 0 ? $to : false,
                ];
                if ($k == array_key_last($tails)) {
                    if ($extra) {
                        $data['reply_markup'] = json_encode($extra);
                    }
                }
                $r = $this->request('sendMessage', $data);
            }
        } else {
            $data = [
                'chat_id'                  => $chat,
                'text'                     => $text,
                'parse_mode'               => $mode,
                // 'disable_web_page_preview' => true,
                'disable_notification'     => $disable_notification,
                'reply_to_message_id'      => $to,
            ];
            if (!empty($extra)) {
                $data['reply_markup'] = json_encode($extra);
            }
            $r = $this->request('sendMessage', $data);
        }
        return $r;
    }

    public function splitText($text, $size = 4096)
    {
        $tails = preg_split('~\n~', $text);
        if (!empty($tails)) {
            foreach ($tails as $v) {
                $lines[] = [
                    'length' => mb_strlen($v, 'utf-8'),
                    'text'   => $v,
                ];
            }
            $i = 0;
            foreach ($lines as $v) {
                $i += $v['length'];
                $output[ceil($i / $size)] .= $v['text'] . "\n";
            }
            return array_values($output);
        } else {
            return [$text];
        }
    }

    public function sendDraft($chat, $draft_id, $text = '', $mode = 'HTML')
    {
        $data = [
            'chat_id'    => $chat,
            'draft_id'   => $draft_id,
            'text'       => $text,
            'parse_mode' => $mode,
        ];
        return $this->request('sendMessageDraft', json_encode($data), 1);
    }

    public function image($chat, $id_url_cFile, $caption = false, $to = false)
    {
        return $this->request('sendPhoto', [
            'chat_id'             => $chat,
            'photo'               => $id_url_cFile,
            'caption'             => $caption,
            'reply_to_message_id' => $to,
        ]);
    }

    public function sendPhoto($chat, $id_url_cFile, $caption = false, $to = false)
    {
        return $this->request('sendPhoto', [
            'chat_id'             => $chat,
            'photo'               => $id_url_cFile,
            'caption'             => $caption,
            'reply_to_message_id' => $to,
            'parse_mode'          => 'html',
        ]);
    }

    public function sendFile($chat, $id_url_cFile, $caption = false, $to = false)
    {
        return $this->request('sendDocument', [
            'chat_id'             => $chat,
            'document'            => $id_url_cFile,
            'caption'             => $caption,
            'reply_to_message_id' => $to,
            'parse_mode'          => 'html',
        ]);
    }

    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML')
    {
        if ($button) {
            $extra = ['inline_keyboard' => $button];
        }
        if ($reply !== false) {
            $extra = [
                'force_reply'             => true,
                'input_field_placeholder' => $reply
            ];
        }
        $data = [
            'chat_id'                  => $chat,
            'message_id'               => $message_id,
            'text'                     => $text,
            'parse_mode'               => $mode,
            'disable_web_page_preview' => true,
        ];
        if (!empty($extra)) {
            $data['reply_markup'] = json_encode($extra);
        }
        return $this->request('editMessageText', $data);
    }

    public function answer($callback_id, $textNotify = false, $notify = false)
    {
        return $this->request('answerCallbackQuery', [
            'callback_query_id' => $callback_id,
            'show_alert'        => $notify,
            'text'              => $textNotify,
        ]);
    }

    public function delete($chat, $message_id)
    {
        $data = [
            'chat_id'    => $chat,
            'message_id' => $message_id,
        ];
        return $this->request('deleteMessage', $data);
    }

    public function pin($chat, $message_id, $notnotify = true)
    {
        $data = [
            'chat_id'    => $chat,
            'message_id' => $message_id,
            'disable_notification' => $notnotify,
        ];
        return $this->request('pinChatMessage', $data);
    }

    public function unpin($chat, $message_id)
    {
        $data = [
            'chat_id'    => $chat,
            'message_id' => $message_id,
        ];
        return $this->request('unpinChatMessage', $data);
    }

    // ─── TrustTunnel ──────────────────────────────────────────────────────────
    public function getClientsTt()
    {
        $f = '/config/trusttunnel/credentials.toml';
        if (!file_exists($f)) {
            return [];
        }
        $data = file_get_contents($f);
        preg_match_all('~\[\[client\]\].*?username\s*=\s*"([^"]+)".*?password\s*=\s*"([^"]+)"~s', $data, $m, PREG_SET_ORDER);
        $users = [];
        foreach ($m as $row) {
            $users[$row[1]] = $row[2];
        }
        return $users;
    }

    public function writeTtCredentials($users)
    {
        $out = "# TrustTunnel credentials. Generated by bot — do not edit manually.\n";
        foreach ($users as $u => $p) {
            $u = addcslashes($u, '"\\');
            $p = addcslashes($p, '"\\');
            $out .= "\n[[client]]\nusername = \"$u\"\npassword = \"$p\"\n";
        }
        file_put_contents('/config/trusttunnel/credentials.toml', $out);
    }

    public function writeTtHosts($domain)
    {
        $domain = $domain ?: 'vpn.example.com';
        $out    = "[[main_hosts]]\nhostname = \"$domain\"\n"
                . "cert_chain_path = \"/certs/cert_public\"\nprivate_key_path = \"/certs/cert_private\"\n";
        file_put_contents('/config/trusttunnel/hosts.toml', $out);
    }

    public function restartTt()
    {
        $pac    = $this->getPacConf();
        $domain = $this->getDomain() ?: $pac['domain'] ?? '';
        $users  = $this->getClientsTt();

        $this->writeTtHosts($domain);
        $this->writeTtCredentials($users);
        if (!file_exists('/config/trusttunnel/vpn.toml') || !file_exists('/config/trusttunnel/rules.toml')) {
            return; // templates missing — init.sh ещё не развернул
        }

        // Linux truncates /proc/<pid>/comm to 15 chars, so the binary name
        // "trusttunnel_endpoint" only matches via -f (full cmdline).
        $this->ssh('pkill -9 -f trusttunnel_endpoint; while pgrep -f trusttunnel_endpoint >/dev/null; do sleep 0.2; done', 'tt');
        $hasCert = file_exists('/certs/cert_public') && file_exists('/certs/cert_private');
        if (!empty($users) && !empty($domain) && $hasCert) {
            $this->ssh(
                'cd /trusttunnel_endpoint && trusttunnel_endpoint vpn.toml hosts.toml',
                'tt',
                false,
                '/logs/trusttunnel.log'
            );
        }
    }

    public function addTtUser()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter username",
            $this->input['message_id'],
            reply: 'enter username',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'addttus',
            'args'           => [],
        ];
    }

    public function addttus($user)
    {
        $user = preg_replace('~[^a-zA-Z0-9_.\-]~', '', $user);
        if (empty($user)) {
            $this->send($this->input['chat'], 'wrong username');
            return $this->menu('tt');
        }
        $users = $this->getClientsTt();
        if (isset($users[$user])) {
            $this->send($this->input['chat'], "user $user already exists");
            return $this->menu('tt');
        }
        $users[$user] = base64_encode(random_bytes(18));
        $this->writeTtCredentials($users);
        $this->restartTt();
        $this->menu('tt');
    }

    public function delttus($user)
    {
        $users = $this->getClientsTt();
        unset($users[$user]);
        $this->writeTtCredentials($users);
        $this->restartTt();
        $this->menu('tt');
    }

    public function changeTtPass($user)
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter password for $user",
            $this->input['message_id'],
            reply: 'enter password',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'chttpass',
            'args'           => [$user],
        ];
    }

    public function chttpass($pass, $user)
    {
        $users = $this->getClientsTt();
        if (!isset($users[$user]) || empty($pass)) {
            return $this->menu('tt');
        }
        $users[$user] = $pass;
        $this->writeTtCredentials($users);
        $this->restartTt();
        $this->menu('tt');
    }

    public function genTtPass($user)
    {
        $users = $this->getClientsTt();
        if (!isset($users[$user])) {
            return $this->menu('tt');
        }
        $users[$user] = base64_encode(random_bytes(18));
        $this->writeTtCredentials($users);
        $this->restartTt();
        $this->menu('tt');
    }

    public function getTtConfig($user)
    {
        $users  = $this->getClientsTt();
        if (!isset($users[$user])) {
            return $this->menu('tt');
        }
        $pac    = $this->getPacConf();
        $domain = $this->getDomain() ?: $pac['domain'] ?? '';
        $port   = $this->getTtPort();
        $pass   = addcslashes($users[$user], '"\\');
        $u      = addcslashes($user, '"\\');
        $toml   = "# TrustTunnel client config. Import via: trusttunnel client run <this-file>\n"
                . "# Or replace [endpoint] section of an existing trusttunnel_client.toml.\n"
                . "\n[endpoint]\n"
                . "hostname = \"$domain\"\n"
                . "addresses = [\"$domain:$port\"]\n"
                . "username = \"$u\"\n"
                . "password = \"$pass\"\n";
        $this->sendFile(
            $this->input['from'],
            new CURLStringFile($toml, "trusttunnel-$user.toml", 'application/toml')
        );
    }

    public function getTtPort()
    {
        $f = '/docker/compose';
        if (is_file($f)) {
            $c = yaml_parse_file($f)['services'] ?? [];
            if (isset($c['tt']['ports'][0])) {
                return (int) explode(':', $c['tt']['ports'][0])[0];
            }
        }
        return (int) (getenv('TTPORT') ?: 2443);
    }

    public function ttMenu()
    {
        $pac    = $this->getPacConf();
        $domain = $this->getDomain() ?: $pac['domain'] ?? '';
        $port   = $this->getTtPort();
        $users  = $this->getClientsTt();
        $text[] = "Menu -> TrustTunnel";
        $text[] = "server: " . ($domain ? "<code>$domain:$port</code>" : 'domain unavailable');
        $text[] = 'clients: ' . count($users);
        foreach ($users as $u => $p) {
            $text[] = htmlspecialchars($u, ENT_QUOTES) . ': <code>' . htmlspecialchars($p, ENT_QUOTES) . '</code>';
        }
        if (!file_exists('/certs/cert_public')) {
            $text[] = "⚠ cert missing (/certs/cert_public)";
        }
        $data[] = [
            [
                'text'          => $this->i18n('change port') . ": $port",
                'callback_data' => '/changePort tt',
            ],
        ];
        $data[] = [
            [
                'text'          => $this->i18n('add peer'),
                'callback_data' => '/addTtUser',
            ],
        ];
        foreach ($users as $u => $_) {
            $data[] = [
                [
                    'text'          => $this->i18n('download') . " $u",
                    'callback_data' => "/getTtConfig $u",
                ],
                [
                    'text'          => $this->i18n('change password'),
                    'callback_data' => "/changeTtPass $u",
                ],
            ];
            $data[] = [
                [
                    'text'          => $this->i18n('generate password'),
                    'callback_data' => "/genTtPass $u",
                ],
                [
                    'text'          => $this->i18n('delete'),
                    'callback_data' => "/delttus $u",
                ],
            ];
        }
        $data[] = [
            [
                'text'          => $this->i18n('back'),
                'callback_data' => '/menu',
            ],
        ];
        return [
            'text' => implode("\n", $text),
            'data' => $data,
        ];
    }

    // ─── OpenVPN ──────────────────────────────────────────────────────────
    // Architecture mirrors TrustTunnel:
    //   client → host:OVPNPORT/udp → (manual nft DNAT or docker port) →
    //   upstream nginx (#ovpn-port stream block) → ovpn:1194/udp.
    // PKI lives on a bind mount at /config/openvpn (visible inside the bot's
    // php container), so we manipulate certs/files directly and invoke easyrsa
    // inside the ovpn container only when issuing/revoking keys.

    public function ovpnPaths()
    {
        return [
            'pki'    => '/config/openvpn/pki',
            'issued' => '/config/openvpn/pki/issued',
            'priv'   => '/config/openvpn/pki/private',
            'ta'     => '/config/openvpn/pki/ta.key',
            'ca'     => '/config/openvpn/pki/ca.crt',
            'srv'    => '/config/openvpn/server.conf',
            'ccd'    => '/config/openvpn/ccd',
            'status' => '/config/openvpn/openvpn-status.log',
            'log'    => '/logs/openvpn.log',
            'conn'   => '/logs/openvpn-connections.log',
        ];
    }

    // Снэпшот /config/openvpn — PKI (ca/server/issued/private/ta), serial,
    // index.txt, crl.pem, server.conf, ccd/. Каждый файл хранится как base64
    // в общем JSON-бэкапе; при восстановлении ключи получают chmod 600.
    // Runtime-файлы (openvpn-status.log) исключаем — они генерятся демоном.
    public function exportOvpnPki()
    {
        $root = '/config/openvpn';
        if (!is_dir($root)) {
            return null;
        }
        $skipBasenames = ['openvpn-status.log'];
        $files         = [];
        $rii = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS)
        );
        foreach ($rii as $f) {
            if (!$f->isFile() || $f->isLink()) {
                continue;
            }
            if (in_array($f->getFilename(), $skipBasenames, true)) {
                continue;
            }
            $rel = ltrim(substr($f->getPathname(), strlen($root)), '/');
            $files[$rel] = base64_encode(file_get_contents($f->getPathname()));
        }
        return $files ?: null;
    }

    public function importOvpnPki(array $files)
    {
        $root = '/config/openvpn';
        @mkdir($root, 0755, true);
        foreach ($files as $rel => $b64) {
            // Защита от path traversal: запрещаем .. и абсолютные пути,
            // нормализуем разделители.
            $rel = str_replace('\\', '/', $rel);
            if ($rel === '' || $rel[0] === '/' || strpos($rel, '..') !== false) {
                continue;
            }
            $path = "$root/$rel";
            @mkdir(dirname($path), 0755, true);
            file_put_contents($path, base64_decode($b64));
        }
        // OpenVPN отказывается стартовать с приватниками доступными группе/всем.
        foreach (glob("$root/pki/private/*.key") ?: [] as $k) {
            chmod($k, 0600);
        }
        if (file_exists("$root/pki/ta.key")) {
            chmod("$root/pki/ta.key", 0600);
        }
    }

    public function getOvpnPort()
    {
        $f = '/docker/compose';
        if (is_file($f)) {
            $c = yaml_parse_file($f)['services'] ?? [];
            if (isset($c['ovpn']['ports'][0])) {
                return (int) explode(':', $c['ovpn']['ports'][0])[0];
            }
        }
        return (int) (getenv('OVPNPORT') ?: 1194);
    }

    // Proto читается из server.conf (source of truth после первого запуска),
    // с fallback на OVPNPROTO env для ранней стадии до создания конфига.
    // Возвращает 'udp4' или 'tcp4' — формат OpenVPN CE.
    public function getOvpnProto()
    {
        $p = $this->ovpnPaths();
        if (file_exists($p['srv'])) {
            $cfg = file_get_contents($p['srv']);
            if (preg_match('~^\s*proto\s+(\S+)~m', $cfg, $m)) {
                $v = $m[1];
                if ($v === 'udp4' || $v === 'tcp4') {
                    return $v;
                }
            }
        }
        $env = strtolower((string) getenv('OVPNPROTO'));
        return ($env === 'tcp4') ? 'tcp4' : 'udp4';
    }

    public function getOvpnUsers()
    {
        $p = $this->ovpnPaths();
        if (!is_dir($p['issued'])) {
            return [];
        }
        $users = [];
        foreach (scandir($p['issued']) ?: [] as $f) {
            if (!preg_match('~^([a-zA-Z0-9_.\-]+)\.crt$~', $f, $m)) {
                continue;
            }
            if ($m[1] === 'server') {
                continue;
            }
            $users[] = $m[1];
        }
        sort($users);
        return $users;
    }

    public function isOvpnUserDisabled($user)
    {
        $p = $this->ovpnPaths();
        $f = $p['ccd'] . '/' . $user;
        return file_exists($f) && stripos(file_get_contents($f), 'disable') !== false;
    }

    public function getOvpnStatus()
    {
        // status-version 2 is CSV with HEADER rows. Parse CLIENT_LIST entries:
        // CLIENT_LIST,CN,Real Address,Virtual Addr,Virtual IPv6,Bytes Received,
        // Bytes Sent,Connected Since,Connected Since (s),Username,Client ID,...
        $p = $this->ovpnPaths();
        if (!file_exists($p['status'])) {
            return [];
        }
        $rows = explode("\n", file_get_contents($p['status']));
        $out  = [];
        foreach ($rows as $row) {
            $cols = str_getcsv($row);
            if (($cols[0] ?? '') !== 'CLIENT_LIST') {
                continue;
            }
            $cn = $cols[1] ?? '';
            if ($cn === '' || $cn === 'UNDEF') {
                continue;
            }
            $out[$cn] = [
                'real'    => $cols[2] ?? '',
                'virtual' => $cols[3] ?? '',
                'rx'      => (int) ($cols[5] ?? 0),
                'tx'      => (int) ($cols[6] ?? 0),
                'since'   => $cols[7] ?? '',
                'cid'     => $cols[10] ?? '',
            ];
        }
        return $out;
    }

    public function fmtBytes($n)
    {
        $n = (int) $n;
        if ($n < 1024) return "{$n} B";
        $units = ['KB', 'MB', 'GB', 'TB'];
        $i = -1;
        do { $n /= 1024; $i++; } while ($n >= 1024 && $i < count($units) - 1);
        return sprintf('%.1f %s', $n, $units[$i]);
    }

    // openvpn-status.log's Real Address is "IP:port" for IPv4 или "[v6]:port"
    // для IPv6. Для UI достаточно хоста без порта — кратко и читаемо.
    public function ovpnRealIp($real)
    {
        $real = trim((string) $real);
        if ($real === '') {
            return '';
        }
        // IPv6: [::1]:1234 → ::1
        if (preg_match('~^\[([^\]]+)\]:\d+$~', $real, $m)) {
            return $m[1];
        }
        // IPv4: 1.2.3.4:1234 → 1.2.3.4  (bare IP без порта тоже проходит)
        if (preg_match('~^([0-9a-fA-F:.]+):\d+$~', $real, $m)) {
            return $m[1];
        }
        return $real;
    }

    // Явная "обновить": перечитываем openvpn-status.log + перерендерим меню.
    // Телеграм эдитит сообщение только при diff; чтобы клик не выглядел
    // немым — отвечаем коротким toast'ом. callbackCheck не отправит второй
    // answer, т.к. $this->callback уже будет выставлен answer()'ом.
    public function refreshOvpn()
    {
        if (!empty($this->input['callback_id'])) {
            $this->answer($this->input['callback_id'], '🔄 ' . $this->i18n('refreshed'));
        }
        $this->menu('ovpn');
    }

    // Список файлов, без которых openvpn не стартует. Используется и для
    // гейта в restartOvpn, и для диагностики в ovpnMenu.
    public function ovpnPkiMissing()
    {
        $p       = $this->ovpnPaths();
        $missing = [];
        $require = [
            'ca'               => $p['ca'],
            'server cert'      => $p['issued'] . '/server.crt',
            'server key'       => $p['priv'] . '/server.key',
            'crl'              => $p['pki'] . '/crl.pem',
            'tls-crypt (ta)'   => $p['ta'],
            'server.conf'      => $p['srv'],
        ];
        foreach ($require as $name => $path) {
            if (!file_exists($path)) {
                $missing[] = $name;
            }
        }
        return $missing;
    }

    public function restartOvpn()
    {
        // Без всех PKI-файлов openvpn немедленно падает с «Cannot pre-load
        // keyfile» и бот показывает on→off. Лучше ничего не запускать, чтобы
        // статус честно оставался off и пользователь увидел причину в меню.
        if ($this->ovpnPkiMissing()) {
            $this->ssh('pkill -9 openvpn 2>/dev/null || true', 'ovpn');
            return;
        }
        // Гарантированная остановка: pkill -9 + ждём полного отсутствия
        // процесса. Ранее, при быстрых двух toggleProto подряд, успевало
        // подняться два демона (один TCP, один UDP на одном порту — не
        // конфликтуют). Дополнительно убираем stale unix-socket.
        $this->ssh(
            'pkill -9 openvpn 2>/dev/null; ' .
            'for i in 1 2 3 4 5 6 7 8 9 10; do pgrep openvpn >/dev/null || break; sleep 0.2; done; ' .
            'rm -f /var/run/openvpn-mgmt.sock',
            'ovpn'
        );
        $this->ssh('openvpn --config /etc/openvpn/server.conf', 'ovpn', false, '/dev/null');
    }

    public function addOvpnUser()
    {
        $r = $this->send(
            $this->input['chat'],
            "@{$this->input['username']} enter username",
            $this->input['message_id'],
            reply: 'enter username',
        );
        $_SESSION['reply'][$r['result']['message_id']] = [
            'start_message'  => $this->input['message_id'],
            'start_callback' => $this->input['callback_id'],
            'callback'       => 'addovus',
            'args'           => [],
        ];
    }

    public function addovus($user)
    {
        $user = preg_replace('~[^a-zA-Z0-9_.\-]~', '', (string) $user);
        if (empty($user) || $user === 'server') {
            $this->send($this->input['chat'], 'wrong username');
            return $this->menu('ovpn');
        }
        if (in_array($user, $this->getOvpnUsers(), true)) {
            $this->send($this->input['chat'], "user $user already exists");
            return $this->menu('ovpn');
        }
        // Без ca.crt easyrsa build-client-full молча пишет в stderr и
        // пользователь ничего не увидит. Блокируем заранее, пока PKI не
        // доинициализирован.
        $p = $this->ovpnPaths();
        if (!file_exists($p['ca']) || !file_exists($p['pki'] . '/private/ca.key')) {
            $this->send($this->input['chat'], 'PKI not ready — restart ovpn container first');
            return $this->menu('ovpn');
        }
        $u = escapeshellarg($user);
        // Та же болезнь, что у server-cert: если прошлый build-client-full
        // упал после создания reqs/$user.req, повтор даст "file already
        // exists". Чистим stale артефакты перед новой попыткой (для этого
        // имени, не для всего PKI).
        $this->ssh(
            "rm -f /etc/openvpn/pki/reqs/$u.req /etc/openvpn/pki/private/$u.key /etc/openvpn/pki/issued/$u.crt && " .
            "EASYRSA_PKI=/etc/openvpn/pki EASYRSA_BATCH=1 /usr/share/easy-rsa/easyrsa build-client-full $u nopass " .
            ">>/logs/openvpn.log 2>&1",
            'ovpn'
        );
        if (!in_array($user, $this->getOvpnUsers(), true)) {
            $this->send($this->input['chat'], "failed to issue cert for $user (check /logs/openvpn.log)");
        }
        $this->menu('ovpn');
    }

    public function delOvpnUser($user)
    {
        $user = preg_replace('~[^a-zA-Z0-9_.\-]~', '', (string) $user);
        if (empty($user) || $user === 'server') {
            return $this->menu('ovpn');
        }
        $u = escapeshellarg($user);
        $this->ssh(
            "EASYRSA_PKI=/etc/openvpn/pki EASYRSA_BATCH=1 /usr/share/easy-rsa/easyrsa revoke $u && " .
            "EASYRSA_PKI=/etc/openvpn/pki EASYRSA_BATCH=1 /usr/share/easy-rsa/easyrsa gen-crl",
            'ovpn'
        );
        $p = $this->ovpnPaths();
        @unlink($p['ccd'] . '/' . $user);
        // crl.pem is re-read on every TLS handshake → new connections from
        // this CN get rejected. Kick the live session, if any.
        $this->ovpnMgmt(["kill $user", 'exit']);
        $this->menu('ovpn');
    }

    public function getOvpnConfig($user)
    {
        $user = preg_replace('~[^a-zA-Z0-9_.\-]~', '', (string) $user);
        if (empty($user) || !in_array($user, $this->getOvpnUsers(), true)) {
            return $this->menu('ovpn');
        }
        $p     = $this->ovpnPaths();
        $crt   = file_exists("{$p['issued']}/$user.crt") ? file_get_contents("{$p['issued']}/$user.crt") : '';
        $key   = file_exists("{$p['priv']}/$user.key")   ? file_get_contents("{$p['priv']}/$user.key")   : '';
        $ca    = file_exists($p['ca'])                    ? file_get_contents($p['ca'])                    : '';
        $ta    = file_exists($p['ta'])                    ? file_get_contents($p['ta'])                    : '';
        // Любой пустой компонент = битый .ovpn, клиент не подключится и будет
        // ругаться на "VERIFY ERROR" без внятной подсказки. Лучше сказать явно.
        if (empty($crt) || empty($key) || empty($ca) || empty($ta)) {
            $this->send($this->input['chat'], "PKI for $user is incomplete — restart ovpn container");
            return $this->menu('ovpn');
        }
        // strip easyrsa's pre-cert plaintext metadata; keep only the PEM block
        if (preg_match('~-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----~s', $crt, $m)) {
            $crt = $m[0];
        }
        $domain = $this->getDomain() ?: ($this->getPacConf()['domain'] ?? '');
        $host   = $domain ?: getenv('IP');
        $port   = $this->getOvpnPort();
        $proto  = $this->getOvpnProto();
        $ovpn   = "client\ndev tun\nproto $proto\nremote $host $port\nresolv-retry infinite\nnobind\npersist-key\npersist-tun\nremote-cert-tls server\ncipher AES-256-GCM\nauth SHA256\ndata-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305\ntls-version-min 1.2\nverb 3\n";
        $ovpn  .= "<ca>\n$ca</ca>\n";
        $ovpn  .= "<cert>\n$crt\n</cert>\n";
        $ovpn  .= "<key>\n$key</key>\n";
        $ovpn  .= "<tls-crypt>\n$ta</tls-crypt>\n";
        $this->sendFile(
            $this->input['from'],
            new CURLStringFile($ovpn, "$user.ovpn", 'application/x-openvpn-profile')
        );
    }

    // Send a list of newline-terminated commands to openvpn's management
    // interface and return raw response. Quiet on connection failures because
    // openvpn might be restarting. Socket: unix (см. server.conf) — это
    // убирает "management on TCP WITHOUT passwords" warning из лога.
    public function ovpnMgmt(array $cmds)
    {
        $script = implode('\n', array_map(fn($c) => str_replace("'", "'\\''", $c), $cmds));
        return $this->ssh(
            "printf '" . $script . "\\n' | nc -U -w 2 /var/run/openvpn-mgmt.sock 2>/dev/null",
            'ovpn'
        );
    }

    public function kickOvpn($user)
    {
        $user = preg_replace('~[^a-zA-Z0-9_.\-]~', '', (string) $user);
        if (empty($user)) {
            return $this->menu('ovpn');
        }
        $this->ovpnMgmt(["kill $user", 'exit']);
        // Re-open client submenu so the user sees the online marker flip off.
        if (in_array($user, $this->getOvpnUsers(), true)) {
            return $this->ovpnClientMenu($user);
        }
        $this->menu('ovpn');
    }

    public function disableOvpnUser($user)
    {
        $user = preg_replace('~[^a-zA-Z0-9_.\-]~', '', (string) $user);
        if (empty($user) || !in_array($user, $this->getOvpnUsers(), true)) {
            return $this->menu('ovpn');
        }
        $p = $this->ovpnPaths();
        @mkdir($p['ccd'], 0755, true);
        file_put_contents($p['ccd'] . '/' . $user, "disable\n");
        $this->ovpnMgmt(["kill $user", 'exit']);
        $this->ovpnClientMenu($user);
    }

    public function enableOvpnUser($user)
    {
        $user = preg_replace('~[^a-zA-Z0-9_.\-]~', '', (string) $user);
        if (empty($user) || !in_array($user, $this->getOvpnUsers(), true)) {
            return $this->menu('ovpn');
        }
        $p = $this->ovpnPaths();
        @unlink($p['ccd'] . '/' . $user);
        $this->ovpnClientMenu($user);
    }

    public function isOvpnIsolated()
    {
        // "Isolated" means clients CANNOT reach each other → server.conf has
        // NO `client-to-client` directive between markers. Default is isolated.
        // Use `.*?` (not `.+?`) so the empty initial block generated by
        // start_ovpn.sh — two adjacent marker lines with nothing between —
        // still matches; otherwise the toggle silently no-ops.
        $p = $this->ovpnPaths();
        if (!file_exists($p['srv'])) {
            return true;
        }
        $cfg = file_get_contents($p['srv']);
        if (!preg_match('~^[ \t]*#ovpn-isolation[ \t]*\R(.*?)^[ \t]*#ovpn-isolation[ \t]*$~sm', $cfg, $m)) {
            return true;
        }
        return !preg_match('~^\s*client-to-client\s*$~m', $m[1]);
    }

    public function toggleOvpnProto()
    {
        $p = $this->ovpnPaths();
        if (!file_exists($p['srv'])) {
            return $this->menu('ovpn');
        }
        $cur = $this->getOvpnProto();
        $new = ($cur === 'tcp4') ? 'udp4' : 'tcp4';
        $cfg = file_get_contents($p['srv']);
        // Строка `proto XXX` генерируется start_ovpn.sh при первом запуске;
        // дальше бот переписывает только её, остальной конфиг не трогаем.
        if (!preg_match('~^\s*proto\s+\S+~m', $cfg)) {
            return $this->menu('ovpn');
        }
        $cfg = preg_replace('~^\s*proto\s+\S+~m', "proto $new", $cfg, 1);
        // explicit-exit-notify ignored for --proto tcp → удаляем для TCP и
        // возвращаем для UDP. Иначе лог openvpn засорён "NOTICE: ... ignored".
        if ($new === 'tcp4') {
            $cfg = preg_replace('~^\s*explicit-exit-notify\s+\S+\s*\R?~m', '', $cfg);
        } elseif (!preg_match('~^\s*explicit-exit-notify\s+~m', $cfg)) {
            $cfg = rtrim($cfg, "\n") . "\nexplicit-exit-notify 1\n";
        }
        file_put_contents($p['srv'], $cfg);
        $this->setEnvVar('OVPNPROTO', $new);
        // Перестраиваем #ovpn-port блок upstream.conf с правильным listen —
        // tcp без ключевого слова udp, udp — с ним. Также синхронизируем
        // docker-compose override (ports: ["PORT:1194/proto"]), если задано
        // прямое пробрасывание, иначе клиенты получат не тот транспорт.
        $port = $this->getOvpnPort();
        $this->setUpstreamPortOvpn($port, $new);
        $this->syncOvpnOverridePort();
        $this->restartOvpn();
        $this->menu('ovpn');
    }

    // Если docker-compose override содержит ports для ovpn — обновляем proto
    // суффикс под текущий getOvpnProto(). Вызывается после смены proto.
    public function syncOvpnOverridePort()
    {
        $f = '/docker/compose';
        if (!is_file($f)) {
            return;
        }
        $content = file_get_contents($f);
        // Фиксируем !override-сервисы до парсинга: yaml_emit ниже их теряет,
        // и без восстановления docker-compose сольёт ports (например tt
        // получит и старый TTPORT, и текущий override-порт).
        $overrides = $this->detectComposeOverrides($content);
        $c = $content ? yaml_parse($content) : [];
        if (!isset($c['services']['ovpn']['ports'][0])) {
            return;
        }
        $proto = str_starts_with($this->getOvpnProto(), 'tcp') ? 'tcp' : 'udp';
        $host  = (int) explode(':', $c['services']['ovpn']['ports'][0])[0];
        $c['services']['ovpn']['ports'] = ["$host:1194/$proto"];
        file_put_contents($f, $this->emitComposeWithOverrides($c, $overrides));
    }

    public function toggleOvpnIsolation()
    {
        $p = $this->ovpnPaths();
        if (!file_exists($p['srv'])) {
            return $this->menu('ovpn');
        }
        $cfg     = file_get_contents($p['srv']);
        $isolated = $this->isOvpnIsolated();
        // If currently isolated, ENABLE inter-client by adding the directive.
        $body    = $isolated ? "client-to-client\n" : "";
        $block   = "#ovpn-isolation\n$body#ovpn-isolation";
        // `.*?` so the empty starter block (two adjacent marker lines) matches.
        $re      = '~^[ \t]*#ovpn-isolation[ \t]*\R.*?^[ \t]*#ovpn-isolation[ \t]*$~sm';
        if (!preg_match($re, $cfg)) {
            return $this->menu('ovpn');
        }
        $cfg = preg_replace($re, $block, $cfg);
        file_put_contents($p['srv'], $cfg);
        $this->restartOvpn();
        $this->menu('ovpn');
    }

    public function showOvpnLog()
    {
        $p = $this->ovpnPaths();
        $tail = '';
        if (file_exists($p['log'])) {
            $lines = explode("\n", file_get_contents($p['log']));
            $tail  = implode("\n", array_slice($lines, -40));
        }
        $text  = "Menu -> OpenVPN -> " . $this->i18n('log tail') . "\n";
        $text .= "<pre>" . htmlspecialchars($tail ?: '(empty)', ENT_QUOTES) . "</pre>";
        $data  = [[
            ['text' => $this->i18n('back'), 'callback_data' => '/menu ovpn'],
        ]];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            $text,
            $data,
        );
    }

    // Журнал UP/DOWN-событий, который пишет /etc/openvpn/connect.sh через
    // client-connect/client-disconnect hook (см. start_ovpn.sh).
    // Содержит CN + реальный IP клиента — без шума из основного openvpn.log.
    public function showOvpnConnLog()
    {
        $p = $this->ovpnPaths();
        $tail = '';
        if (file_exists($p['conn'])) {
            $lines = explode("\n", file_get_contents($p['conn']));
            $tail  = implode("\n", array_slice($lines, -40));
        }
        $text  = "Menu -> OpenVPN -> " . $this->i18n('connections') . "\n";
        $text .= "<pre>" . htmlspecialchars($tail ?: '(empty)', ENT_QUOTES) . "</pre>";
        $data  = [[
            ['text' => $this->i18n('back'), 'callback_data' => '/menu ovpn'],
        ]];
        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            $text,
            $data,
        );
    }

    public function ovpnMenu()
    {
        $port    = $this->getOvpnPort();
        $domain  = $this->getDomain() ?: ($this->getPacConf()['domain'] ?? '');
        $host    = $domain ?: getenv('IP');
        $users   = $this->getOvpnUsers();
        $online  = $this->getOvpnStatus();
        $running = (bool) $this->ssh('pgrep openvpn', 'ovpn');
        $isolated = $this->isOvpnIsolated();
        $p       = $this->ovpnPaths();

        $proto  = $this->getOvpnProto();
        $pshort = str_starts_with($proto, 'tcp') ? 'tcp' : 'udp';

        $text   = [];
        $text[] = "Menu -> " . $this->i18n('OpenVPN');
        $text[] = "server: <code>$host:$port/$pshort</code>";
        $text[] = $this->i18n($running ? 'on' : 'off') . " openvpn";
        $text[] = 'proto: ' . $pshort;
        // Inline hint clarifies what the adjacent toggle actually does — без
        // этого пользователь видит "трафик между клиентами: off" и не
        // понимает, в какую сторону флаг работает.
        $interHint = $isolated
            ? $this->i18n('inter-client off hint')
            : $this->i18n('inter-client on hint');
        $text[] = $this->i18n('inter-client') . ': '
            . $this->i18n($isolated ? 'off' : 'on')
            . ' <i>(' . $interHint . ')</i>';
        $text[] = "clients: " . count($users) . " (" . count($online) . " " . $this->i18n('online') . ")";
        $pkiMissing = $this->ovpnPkiMissing();
        if ($pkiMissing) {
            $text[] = '⚠ PKI incomplete, missing: ' . implode(', ', $pkiMissing);
            $text[] = '   → <code>docker compose restart ovpn</code> чтобы доинициализировать';
        }
        if (!empty($online)) {
            $text[] = '';
            foreach ($online as $cn => $s) {
                // Real address из openvpn-status.log приходит в виде IP:port
                // (или [v6]:port); порт в UI только шумит, режем до хоста.
                $real = $this->ovpnRealIp($s['real'] ?? '');
                $text[] = '🟢 <code>' . htmlspecialchars($cn, ENT_QUOTES) . '</code> '
                    . $s['virtual']
                    . ($real !== '' ? ' · <code>' . htmlspecialchars($real, ENT_QUOTES) . '</code>' : '')
                    . ' ↓' . $this->fmtBytes($s['rx']) . ' ↑' . $this->fmtBytes($s['tx']);
            }
        }

        $data   = [];
        $data[] = [
            [
                'text'          => $this->i18n('change port') . ": $port",
                'callback_data' => '/changePort ovpn',
            ],
            [
                'text'          => 'proto: ' . $pshort,
                'callback_data' => '/toggleOvpnProto',
            ],
        ];
        $data[] = [[
            'text'          => $this->i18n('inter-client') . ': ' . $this->i18n($isolated ? 'off' : 'on'),
            'callback_data' => '/toggleOvpnIsolation',
        ]];
        $data[] = [[
            'text'          => $this->i18n('add peer'),
            'callback_data' => '/addOvpnUser',
        ]];
        $data[] = [
            [
                'text'          => $this->i18n('log tail'),
                'callback_data' => '/showOvpnLog',
            ],
            [
                'text'          => $this->i18n('connections'),
                'callback_data' => '/showOvpnConnLog',
            ],
        ];
        // Обновление статистики (онлайн/байты/real IP) для ВСЕХ клиентов —
        // просто перерендер меню. Статус-файл openvpn-status.log пишется
        // самим демоном каждые 5с, так что чтение заново даёт свежие цифры.
        $data[] = [[
            'text'          => '🔄 ' . $this->i18n('refresh'),
            'callback_data' => '/refreshOvpn',
        ]];
        // One button per client: [marker] [name] → opens per-client submenu.
        // Marker logic: 🚫 disabled (ccd/<cn> contains `disable`), 🟢 online
        // (CLIENT_LIST row with this CN in openvpn-status.log), ⚪ offline.
        // If everyone is ⚪, most likely nobody has connected yet — not a bug.
        foreach ($users as $u) {
            $isDis  = $this->isOvpnUserDisabled($u);
            $isOn   = isset($online[$u]);
            $marker = $isDis ? '🚫' : ($isOn ? '🟢' : '⚪');
            $data[] = [[
                'text'          => "$marker $u",
                'callback_data' => "/ovpnClientMenu $u",
            ]];
        }
        $data[] = [[
            'text'          => $this->i18n('back'),
            'callback_data' => '/menu',
        ]];
        return [
            'text' => implode("\n", $text),
            'data' => $data,
        ];
    }

    // Per-client submenu: shows explicit status (disabled / online+bytes /
    // offline) so the state is visible without decoding the emoji marker,
    // and exposes all client-scoped actions on one screen.
    public function ovpnClientMenu($user)
    {
        $user = preg_replace('~[^a-zA-Z0-9_.\-]~', '', (string) $user);
        if (empty($user) || !in_array($user, $this->getOvpnUsers(), true)) {
            return $this->menu('ovpn');
        }

        $isDis  = $this->isOvpnUserDisabled($user);
        $online = $this->getOvpnStatus();
        $s      = $online[$user] ?? null;

        if ($isDis) {
            $status = '🚫 ' . $this->i18n('disabled');
        } elseif ($s) {
            $real = $this->ovpnRealIp($s['real'] ?? '');
            $status = '🟢 ' . $this->i18n('online')
                . ' · ' . htmlspecialchars($s['virtual'], ENT_QUOTES)
                . ($real !== '' ? ' · ' . htmlspecialchars($real, ENT_QUOTES) : '')
                . ' · ↓' . $this->fmtBytes($s['rx'])
                . ' ↑' . $this->fmtBytes($s['tx']);
        } else {
            $status = '⚪ ' . $this->i18n('offline');
        }

        $text   = [];
        $text[] = 'Menu -> ' . $this->i18n('OpenVPN') . ' -> <code>'
            . htmlspecialchars($user, ENT_QUOTES) . '</code>';
        $text[] = $this->i18n('status') . ': ' . $status;

        $data   = [];
        $data[] = [[
            'text'          => $this->i18n('download') . ' .ovpn',
            'callback_data' => "/getOvpnConfig $user",
        ]];
        $data[] = [
            $isDis
                ? ['text' => $this->i18n('enable'),  'callback_data' => "/enableOvpnUser $user"]
                : ['text' => $this->i18n('disable'), 'callback_data' => "/disableOvpnUser $user"],
        ];
        $data[] = [[
            'text'          => $this->i18n('kick'),
            'callback_data' => "/kickOvpn $user",
        ]];
        $data[] = [[
            'text'          => $this->i18n('delete'),
            'callback_data' => "/delOvpnUser $user",
        ]];
        $data[] = [[
            'text'          => $this->i18n('back'),
            'callback_data' => '/menu ovpn',
        ]];

        $this->update(
            $this->input['chat'],
            $this->input['message_id'],
            implode("\n", $text),
            $data,
        );
    }
}
