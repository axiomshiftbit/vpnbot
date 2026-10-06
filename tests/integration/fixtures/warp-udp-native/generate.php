<?php
require '/app/bot.php';
$bot = (new ReflectionClass(Bot::class))->newInstanceWithoutConstructor();
$config = ['log'=>['loglevel'=>'warning'], 'inbounds'=>[
    ['tag'=>'wg-in','listen'=>'127.0.0.1','port'=>18081,'protocol'=>'socks','settings'=>['auth'=>'noauth','udp'=>true,'ip'=>'127.0.0.1']],
    ['tag'=>'vless-fixture','port'=>24444,'protocol'=>'vless','settings'=>['decryption'=>'none','clients'=>[['id'=>$argv[1]]]],'streamSettings'=>['network'=>'tcp']]],
    'outbounds'=>[['tag'=>'warp','protocol'=>'socks','settings'=>['servers'=>[['address'=>'10.10.0.13','port'=>1080]]]],['tag'=>'direct','protocol'=>'freedom']],
    'routing'=>['rules'=>[]]];
$bot->ensureWgGuard($config);$bot->ensureFreedomCompat($config);
echo json_encode($config,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES);
