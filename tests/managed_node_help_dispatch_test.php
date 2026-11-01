<?php
ob_start();require __DIR__.'/managed_node_choice_dispatch_test.php';ob_end_clean();
$checks=0;
foreach(['ru','en'] as $language){
    foreach(ManagedNodeFields::GROUPS as $group=>$label){
        $bot=new NodeChoiceDispatchFixture();$bot->language=$language;$bot->showSetting($group);$before=$bot->pacState;
        $bot->click('/nodeSettings aabbccdd '.$group);
        $screen=end($bot->screens);$rows=$screen[1];
        $help='/menuhelp nodeconfig 0 aabbccdd_'.$group;
        if(($rows[count($rows)-2][0]['callback_data']??'')!==$help)throw new RuntimeException('Help is not last before Back: '.$group);
        $bot->click($help);$toc=end($bot->screens);
        $back='/nodeSettings aabbccdd '.$group;
        if(end($toc[1])[0]['callback_data']!==$back)throw new RuntimeException('Wrong help return: '.$group);
        $count=count($toc[1])-1;
        if($count<2)throw new RuntimeException('Missing named sections: '.$group);
        for($page=1;$page<=$count;$page++){
            $button=$toc[1][$page-1][0];
            if(!preg_match('~^'.$page.'\. .+~u',$button['text']))throw new RuntimeException('Unnamed section');
            $bot->click($button['callback_data']);$screen=end($bot->screens);
            if(mb_strlen($screen[0])>4096 || !str_contains($screen[0],'<b>'))throw new RuntimeException('Invalid Telegram help page');
            foreach($screen[1] as $row)foreach($row as $item)if(strlen($item['callback_data'])>64)throw new RuntimeException('Callback too long');
            if(end($screen[1])[0]['callback_data']!==$back)throw new RuntimeException('Wrong page return');
            $bot->click('/menuhelp nodeconfig 0 aabbccdd_'.$group);
            $checks++;
        }
        $bot->click($back);
        if(!str_contains(end($bot->screens)[0],$label[$language]))throw new RuntimeException('Returned to another settings group');
        if($bot->events || $bot->pacState!==$before)throw new RuntimeException('Help modified settings or invoked RPC');
    }
    foreach(['aabbccdd_invalid','ffffffff_reality','aabbccdd_reality_extra','../reality'] as $context){
        $bot=new NodeChoiceDispatchFixture();$bot->language=$language;
        if($bot->menuHelpContent('nodeconfig',$context)!==[])throw new RuntimeException('Invalid help context accepted');
    }
    $bot=new NodeChoiceDispatchFixture();$bot->language=$language;
    $peer=['id'=>'11111111-1111-4111-8111-111111111111','name'=>'panel','enabled'=>true,'channel'=>'vless'];
    $bot->pacState['managed_nodes']['aabbccdd']['status']['peers']=[$peer];
    $key=Bot::exitEntryKey($peer['id']);$before=$bot->pacState;
    foreach(['aabbccdd'=>'/nodePeers aabbccdd','aabbccdd_'.$key=>'/nodePeer aabbccdd '.$key] as $context=>$back){
        $bot->click($back);$screen=end($bot->screens);
        $help='/menuhelp nodepeers 0 '.$context;
        if($screen[1][count($screen[1])-2][0]['callback_data']!==$help)throw new RuntimeException('Missing peer help');
        $bot->click($help);$toc=end($bot->screens);
        foreach(array_slice($toc[1],0,-1) as $row){
            $bot->click($row[0]['callback_data']);$screen=end($bot->screens);
            if(end($screen[1])[0]['callback_data']!==$back || mb_strlen($screen[0])>4096)throw new RuntimeException('Invalid peer help page or return');
            $checks++;
        }
    }
    if($bot->events || $bot->pacState!==$before)throw new RuntimeException('Peer help changed settings');
    if($bot->menuHelpContent('nodepeers','aabbccdd_0000000000')!==[])throw new RuntimeException('Unknown peer accepted');
}
echo "PASS $checks named node help pages, read-only navigation and invalid contexts\n";
