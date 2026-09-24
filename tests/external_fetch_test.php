<?php
require_once __DIR__ . '/../app/bot.php';
if (getenv('VPNBOT_EXT_FETCH_WORKER')) {
    class ExtFetchBot extends Bot {
        public function __construct() {}
        public function safeExtUrlIps(string $url): array {
            // This fixture bypasses only public DNS/IP selection; real TLS and
            // the production cURL transfer/error handling remain under test.
            return parse_url($url, PHP_URL_HOST) === 'audit.example.test' ? ['127.0.0.1'] : [];
        }
    }
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
    foreach(['complete','complete-env-proxy','empty','html','truncated','oversize','redirect-private','http-error'] as $scenario) {
        $server=stream_socket_server('tls://127.0.0.1:0',$errno,$error,STREAM_SERVER_BIND|STREAM_SERVER_LISTEN,$context);
        $address=stream_socket_get_name($server,false);$port=substr(strrchr($address,':'),1);
        $pid=pcntl_fork();
        if($pid===0){
            $connection=@stream_socket_accept($server,10);
            if(!$connection)exit(1);
            stream_set_timeout($connection,3);
            while(($line=fgets($connection))!==false && trim($line)!==''){}
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
        $env=array_merge(getenv(),['VPNBOT_EXT_FETCH_WORKER'=>"https://audit.example.test:$port/",'HTTPS_PROXY'=>'','https_proxy'=>'','ALL_PROXY'=>'','all_proxy'=>'']);
        if ($scenario === 'complete-env-proxy') $env['HTTPS_PROXY'] = $env['https_proxy'] = 'http://127.0.0.1:1';
        $process=proc_open([PHP_BINARY,'-d',"curl.cainfo=$root/cert.pem",__FILE__],[1=>['pipe','w'],2=>['pipe','w']],$pipes,null,$env);
        $out=stream_get_contents($pipes[1]);$error=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);$code=proc_close($process);pcntl_waitpid($pid,$status);
        $result=json_decode($out,true);
        $ok=$code===0 && $error==='' && (str_starts_with($scenario,'complete') ? $result===[$node] : ($scenario==='empty' ? $result===[] : is_string($result)));
        if(!$ok)$failures[]=$scenario;
    }
} finally {foreach(glob("$root/*") as $file)unlink($file);rmdir($root);}
foreach($failures as $name)echo "FAIL: external HTTPS $name\n";
if($failures)exit(1);
echo "external_fetch_test OK\n";
