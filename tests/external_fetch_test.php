<?php
require_once __DIR__ . '/../app/bot.php';
if (getenv('VPNBOT_EXT_FETCH_WORKER')) {
    class ExtFetchBot extends Bot {
        public function __construct() {}
        public function getPacConf() { return ['extsub_user_agent' => getenv('VPNBOT_TEST_FETCH_UA') ?: '']; }
        public function safeExtUrlIps(string $url): array {
            // This fixture bypasses only public DNS/IP selection; real TLS and
            // the production cURL transfer/error handling remain under test.
            return parse_url($url, PHP_URL_HOST) === 'audit.example.test' ? ['127.0.0.1'] : [];
        }
    }
    $_SERVER += ['HTTP_COOKIE' => 'session=subscriber-fixture', 'HTTP_AUTHORIZATION' => 'Bearer subscriber-fixture',
        'HTTP_REFERER' => 'https://subscriber.example.test/private-fixture', 'HTTP_X_HWID' => 'device-fixture',
        'HTTP_X_DEVICE_MODEL' => 'model-fixture', 'HTTP_USER_AGENT' => 'ClientAgent/1.0'];
    echo json_encode((new ExtFetchBot())->doFetchExtSub(getenv('VPNBOT_EXT_FETCH_WORKER')));
    exit;
}
$root=sys_get_temp_dir().'/vpnbot-ext-fetch-'.bin2hex(random_bytes(6));mkdir($root,0700);
$failures=[];
try {
    $key=openssl_pkey_new(['private_key_bits'=>2048]);
    $csr=openssl_csr_new(['commonName'=>'audit.example.test'],$key);
    $cert=openssl_csr_sign($csr,null,$key,1);openssl_x509_export($cert,$public);openssl_pkey_export($key,$private);
    file_put_contents("$root/cert.pem",$public);file_put_contents("$root/key.pem",$private);chmod("$root/key.pem",0600);
    $context=stream_context_create(['ssl'=>['local_cert'=>"$root/cert.pem",'local_pk'=>"$root/key.pem",'verify_peer'=>false]]);
    $node='vless://11111111-2222-4333-8444-555555555555@vpn.example:443?security=tls#test';
    foreach(['complete','complete-custom-ua','complete-env-proxy','complete-redirect','empty','html','truncated','oversize','redirect-private','http-error'] as $scenario) {
        $server=stream_socket_server('tls://127.0.0.1:0',$errno,$error,STREAM_SERVER_BIND|STREAM_SERVER_LISTEN,$context);
        $address=stream_socket_get_name($server,false);$port=substr(strrchr($address,':'),1);
        $redirect = $scenario === 'complete-redirect';
        $next = $redirect ? stream_socket_server('tls://127.0.0.1:0', $errno, $error, STREAM_SERVER_BIND|STREAM_SERVER_LISTEN, $context) : null;
        $nextPort = $redirect ? parse_url('tcp://' . stream_socket_get_name($next, false), PHP_URL_PORT) : null;
        $pid=pcntl_fork();
        if($pid===0){
            foreach ($redirect ? [$server, $next] : [$server] as $hop => $listener) {
                $connection = @stream_socket_accept($listener, 10);
                if (!$connection) exit(1);
                stream_set_timeout($connection, 3);
                $request = trim((string) fgets($connection));
                $headers = [];
                while (($line = fgets($connection)) !== false && trim($line) !== '') {
                    [$name, $value] = explode(':', $line, 2);
                    $headers[strtolower($name)] = trim($value);
                }
                $expected = $scenario === 'complete-custom-ua' ? 'Happ/4.8.3' : Bot::EXT_SUB_USER_AGENT;
                if (($headers['user-agent'] ?? '') !== $expected ||
                    array_intersect(['cookie','referer','x-hwid','x-device-model','x-real-ip','x-forwarded-for'], array_keys($headers))) exit(2);
                if ($redirect && $hop === 0) {
                    if (!str_contains($request, '/source?fixture=1 ') || ($headers['authorization'] ?? '') !== 'Basic ' . base64_encode('fixture:provider')) exit(3);
                    fwrite($connection, "HTTP/1.1 302 Found\r\nLocation: https://audit.example.test:$nextPort/destination\r\nSet-Cookie: dummy=fixture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    fclose($connection);
                    continue;
                }
                if (isset($headers['authorization']) || ($redirect && !str_contains($request, ' /destination '))) exit(4);
                break;
            }
            $body=$scenario==='oversize' ? str_repeat('x',3<<20) : $node;
            if ($scenario === 'empty') $body = '';
            if ($scenario === 'html') $body = '<html>Provider maintenance</html>';
            $length=strlen($body)+($scenario==='truncated' ? 1000 : 0);
            $code=$scenario==='redirect-private' ? '302 Found' : ($scenario==='http-error' ? '503 Unavailable' : '200 OK');
            $extra=$scenario==='redirect-private' ? "Location: https://127.0.0.1/private\r\n" : '';
            @fwrite($connection,"HTTP/1.1 $code\r\nContent-Length: $length\r\n$extra"."Connection: close\r\n\r\n".$body);
            fclose($connection);fclose($server);exit(0);
        }
        fclose($server);
        if ($next) fclose($next);
        $env=array_merge(getenv(),['VPNBOT_EXT_FETCH_WORKER'=>$redirect ? "https://fixture:provider@audit.example.test:$port/source?fixture=1" : "https://audit.example.test:$port/",'HTTPS_PROXY'=>'','https_proxy'=>'','ALL_PROXY'=>'','all_proxy'=>'']);
        $env['VPNBOT_TEST_FETCH_UA'] = $scenario === 'complete-custom-ua' ? 'Happ/4.8.3' : '';
        if ($scenario === 'complete-env-proxy') $env['HTTPS_PROXY'] = $env['https_proxy'] = 'http://127.0.0.1:1';
        $process=proc_open([PHP_BINARY,'-d',"curl.cainfo=$root/cert.pem",__FILE__],[1=>['pipe','w'],2=>['pipe','w']],$pipes,null,$env);
        $out=stream_get_contents($pipes[1]);$error=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);$code=proc_close($process);pcntl_waitpid($pid,$status);
        $result=json_decode($out,true);
        $ok=pcntl_wifexited($status) && pcntl_wexitstatus($status) === 0 && $code===0 && $error==='' && (str_starts_with($scenario,'complete') ? $result===[$node] : ($scenario==='empty' ? $result===[] : is_string($result)));
        if(!$ok)$failures[]=$scenario;
    }
} finally {foreach(glob("$root/*") as $file)unlink($file);rmdir($root);}
foreach($failures as $name)echo "FAIL: external HTTPS $name\n";
if($failures)exit(1);
echo "external_fetch_test OK\n";
