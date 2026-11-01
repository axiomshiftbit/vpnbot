<?php
ob_start();require __DIR__.'/managed_node_choice_dispatch_test.php';ob_end_clean();
class NodeTlsDispatchFixture extends NodeChoiceDispatchFixture {
    public array $reply=['tls'=>'TLSv1.3','alpn'=>'h2','record'=>120,'name'=>'node.example.test','own'=>true,'transport'=>'reality'];
    protected function managedNodeRpc(string $id,array $request):array{
        if($request!==['action'=>'tls_probe'])throw new RuntimeException('Unexpected RPC');
        $this->events[]='tls_probe';return $this->reply;
    }
}
$checks=0;
foreach(['ru','en'] as $language)foreach(['reality','domains'] as $group){
    foreach(['h2','http/1.1','','invalid'] as $alpn){
        $bot=new NodeTlsDispatchFixture();$bot->language=$language;$bot->reply['alpn']=$alpn;$bot->showSetting($group);
        $before=$bot->pacState;$bot->click('/nodeSettings aabbccdd '.$group);$screen=end($bot->screens);
        $callbacks=array_column(array_merge(...$screen[1]),'callback_data');$callback='/nodeTls aabbccdd '.$group;
        if(!in_array($callback,$callbacks,true))throw new RuntimeException('Missing probe button');
        $bot->click($callback);$screen=end($bot->screens);
        if(end($screen[1])[0]['callback_data']!=='/nodeSettings aabbccdd '.$group)throw new RuntimeException('Wrong TLS return');
        if($screen[1][0][0]['callback_data']!==$callback)throw new RuntimeException('Retry lost origin');
        $green=$language==='ru'?'✅ Согласован ALPN h2.':'✅ ALPN h2 negotiated.';
        if(str_contains($screen[0],$green)!==($alpn==='h2'))throw new RuntimeException('False h2 confirmation');
        if($alpn==='invalid' && str_contains($screen[0],'✅'))throw new RuntimeException('Malformed reply reported success');
        if($bot->events!==['tls_probe'] || $bot->pacState!==$before)throw new RuntimeException('Probe modified configuration');
        $checks++;
    }
    $bot=new NodeTlsDispatchFixture();$bot->language=$language;$bot->pacState['managed_nodes']['aabbccdd']['job']=['active'=>true];
    $bot->click('/nodeTls aabbccdd '.$group);
    if($bot->events || str_contains(end($bot->screens)[0],'✅'))throw new RuntimeException('Busy node probed or reported success');
}
echo "PASS $checks TLS probe buttons, truthful result and menu return\n";
