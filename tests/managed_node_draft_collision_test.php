<?php
require __DIR__.'/managed_nodes_test.php';
$b=new ManagedFixtureBot(); $b->pacState['managed_nodes']['aabbccdd']['job']=null;
$b->managedNodeChoice('aabbccdd','transport','xhttp');
$draft=$b->pacState['managed_nodes']['aabbccdd']['draft'];
try { $b->managedNodeSubmit('aabbccdd','restart',null); } catch (RuntimeException $e) {}
$check(($b->pacState['managed_nodes']['aabbccdd']['draft']??null)===$draft,'maintenance cannot erase an unsaved settings draft');
$check(!in_array('submit',$b->events,true),'pending draft prevents unrelated remote mutation');
$b->managedNodeSubmit('aabbccdd','configure',$draft);
$check(($b->pacState['managed_nodes']['aabbccdd']['job']['draft']['draft']??null)===$draft,'in-flight configuration preserves submitted draft');
$b->remoteJob=['state'=>'failed']; $b->remoteStatus['pending']=null;
$b->managedNodePoll('aabbccdd');
$check(($b->pacState['managed_nodes']['aabbccdd']['draft']??null)===$draft,'rejected configuration restores editable draft');
$b=new ManagedFixtureBot();
$b->pacState['managed_nodes']['aabbccdd']['job']['draft']=['draft'=>$draft,'draft_generation'=>str_repeat('a',32)];
$b->probePass=false; $b->managedNodePoll('aabbccdd');
$b->remoteStatus['pending']=null; $b->remoteStatus['generation']=str_repeat('a',32); $b->managedNodePoll('aabbccdd');
$check(($b->pacState['managed_nodes']['aabbccdd']['draft']??null)===$draft,'traffic rollback restores editable draft');
$b=new ManagedFixtureBot();
try { $b->managedNodeChoice('aabbccdd','transport','xhttp'); } catch (RuntimeException $e) {}
$check(!isset($b->pacState['managed_nodes']['aabbccdd']['draft']),'settings cannot race an in-flight remote operation');
echo "PASS node draft collision guard\n";
