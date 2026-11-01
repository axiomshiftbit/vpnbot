<?php
ob_start();require __DIR__.'/managed_node_choice_dispatch_test.php';ob_end_clean();
$count=0;
foreach(['ru','en'] as $lang)foreach(['dpi','finalmask'] as $group)foreach(['fragment','noise'] as $kind){
 $base=new NodeChoiceDispatchFixture();$base->language=$lang;
 $presets=$kind==='fragment'?$base->fragmentPresets():$base->noisePresets();
 foreach($presets as $key=>$preset){
  $b=new NodeChoiceDispatchFixture();$b->language=$lang;$id='aabbccdd';
  $b->click("/nodeSettings $id $group");
  $buttons=array_column(array_merge(...end($b->screens)[1]),'callback_data');
  if(!in_array("/nodePreset $id {$group}_{$kind}",$buttons,true))throw new RuntimeException('Missing template entry');
  $b->click("/nodePreset $id {$group}_{$kind}");
  $buttons=array_column(array_merge(...end($b->screens)[1]),'callback_data');
  $cb="/nodePreset $id {$group}_{$kind} $key";
  if(!in_array($cb,$buttons,true))throw new RuntimeException('Missing full-bot template');
  $b->click($cb);$draft=$b->pacState['managed_nodes'][$id]['draft']['xray'][$group][$kind]??[];
  $expected=$kind==='fragment'?['enabled'=>true,'packets'=>$preset['packets'],'length'=>$preset['length'],'delay'=>$preset['interval'],'maxSplit'=>$preset['maxSplit']]:['enabled'=>true,'reset'=>'5-10','list'=>$preset['list']];
  if($draft!==$expected)throw new RuntimeException('Template did not prepare expected draft: '.$group.' '.$key);
  if(end($b->screens)[1][array_key_last(end($b->screens)[1])][0]['callback_data']!=="/nodeSettings $id")throw new RuntimeException('Wrong return after preset');
  if($b->events)throw new RuntimeException('Preset mutated remote before Apply');
  $count++;
 }
}
echo "PASS $count DPI and finalmask template button workflows\n";
