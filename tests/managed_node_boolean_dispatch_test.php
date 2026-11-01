<?php
ob_start(); require __DIR__.'/managed_node_choice_dispatch_test.php'; ob_end_clean();

$checks=0; $id='aabbccdd';
foreach (['ru','en'] as $language) {
    foreach (ManagedNodeFields::all() as $path=>$field) {
        if ($field[3]!=='bool') continue;
        foreach ([false,true] as $initial) {
            $b=new NodeChoiceDispatchFixture(); $b->language=$language;
            $node=&$b->pacState['managed_nodes'][$id];
            $node['status']['options']=ManagedNodeFields::change($node['status']['options'],$path,$initial);
            $original=$node['status']['options'];
            $b->click("/nodeField $id $path");
            if (ManagedNodeFields::get($node['draft']??[],$path)!==!$initial) throw new RuntimeException('Boolean callback did not toggle '.$path);
            if ($node['status']['options']!==$original || $b->events) throw new RuntimeException('Boolean callback changed the running node '.$path);
            $b->click("/nodeField $id $path");
            if (ManagedNodeFields::get($node['draft'],$path)!==$initial) throw new RuntimeException('Boolean callback did not toggle back '.$path);
            $before=$b->pacState;
            $node['job']=['operation'=>'configure'];
            $b->click("/nodeField $id $path");
            if ($node['draft']!==$before['managed_nodes'][$id]['draft']) throw new RuntimeException('Busy node accepted a boolean change '.$path);
            $checks++;
        }
    }
}
echo "PASS $checks boolean button transitions, running-state isolation and busy-node refusals\n";
