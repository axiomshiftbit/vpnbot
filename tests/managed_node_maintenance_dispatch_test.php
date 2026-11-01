<?php
ob_start(); require __DIR__.'/managed_node_choice_dispatch_test.php'; ob_end_clean();

$checks=0; $id='aabbccdd';
foreach (['ru','en'] as $language) {
    $b=new NodeChoiceDispatchFixture(); $b->language=$language;
    $b->click("/nodeMaintenance $id");
    $maintenance=array_column(array_merge(...end($b->screens)[1]),'callback_data');
    $b->click("/nodeCert $id");
    $certificate=array_column(array_merge(...end($b->screens)[1]),'callback_data');
    foreach (array_merge($maintenance,$certificate) as $callback) {
        if (!str_starts_with($callback,"/nodeRun $id ")) continue;
        $b=new NodeChoiceDispatchFixture(); $b->language=$language;
        $options=&$b->pacState['managed_nodes'][$id]['status']['options'];
        $options['transport']='reality';
        $options['xray']['encryption']=['auth'=>'mlkem768'];
        $options['xray']['reality']['mldsa']=true;
        $options['wireguard']['enabled']=$options['amnezia']['enabled']=true;
        $b->click($callback);
        $buttons=array_column(array_merge(...end($b->screens)[1]),'callback_data');
        if ($b->events) throw new RuntimeException('Maintenance action executed before confirmation');
        if (!in_array($callback.' yes',$buttons,true)) throw new RuntimeException('Maintenance confirmation missing: '.$callback);
        if (!in_array("/nodeMaintenance $id",$buttons,true)) throw new RuntimeException('Maintenance return missing: '.$callback);
        if (mb_strlen(end($b->screens)[0])<50) throw new RuntimeException('Maintenance explanation missing');
        $checks++;
    }
    $b=new NodeChoiceDispatchFixture(); $b->language=$language;
    $b->click("/nodeBackup $id");
    $buttons=array_column(array_merge(...end($b->screens)[1]),'callback_data');
    if (!in_array("/nodeBackup $id yes",$buttons,true) || $b->events) throw new RuntimeException('Backup confirmation missing or premature snapshot');
    $checks++;
}
echo "PASS $checks maintenance and certificate confirmation buttons\n";
