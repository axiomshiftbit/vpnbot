<?php
require __DIR__.'/managed_nodes_test.php';
$b=new ManagedFixtureBot();
$b->pacState['managed_nodes']['aabbccdd']['job']['operation']='rotate';
$b->pacState['managed_nodes']['aabbccdd']['job']['subject']='controller';
$b->managedNodePoll('aabbccdd');
$r=$b->pacState['managed_nodes']['aabbccdd']['last_operation']??[];
$check(($r['ok']??false) && ($r['subject']??'')==='controller','confirmed rotation records target and success');
$b->managedNodeMenu('aabbccdd');
$check(str_contains(end($b->screens)[0],'ключ клиента основного бота'),'node card explains completed rotation');
echo "PASS node operation feedback\n";
