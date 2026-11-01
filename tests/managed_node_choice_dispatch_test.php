<?php
ob_start();require __DIR__.'/managed_nodes_test.php';ob_end_clean();
class NodeChoiceDispatchFixture extends ManagedFixtureBot {
    public function __construct(){parent::__construct();$this->admin=true;$this->input+=['callback'=>'','message'=>''];$this->pacState['managed_nodes']['aabbccdd']['job']=null;$this->pacState['managed_nodes']['aabbccdd']['status']['pending']=null;}
    public function getWgMsg(){return null;}
    public function click(string $callback):void{$this->input['callback']=$callback;$this->action();}
}
$checks=0;
foreach(['ru','en'] as $lang){
 foreach(ManagedNodeFields::all() as $path=>$field){
  if($field[3]!=='choice')continue;
  foreach($field[4] as $value){
   $b=new NodeChoiceDispatchFixture();$b->language=$lang;$id='aabbccdd';
   $b->click('/nodeField '.$id.' '.$path);$screen=end($b->screens);$callbacks=array_column(array_merge(...$screen[1]),'callback_data');
   $callback="/nodeChoice $id $path $value";
   if(!in_array($callback,$callbacks,true))throw new RuntimeException('Missing choice button: '.$path);
   $b->click($callback);$draft=$b->pacState['managed_nodes'][$id]['draft']??[];
   if((string)ManagedNodeFields::get($draft,$path)!==(string)$value)throw new RuntimeException('Choice dispatch does not set draft: '.$path.' '.$value);
   if($b->events)throw new RuntimeException('Choice applied to remote before Apply');
   $b->click('/nodeDiscard '.$id);
   if(isset($b->pacState['managed_nodes'][$id]['draft']))throw new RuntimeException('Discard did not remove draft');
   $checks++;
  }
 }
}
echo "PASS $checks actual node choice dispatches and draft cancellation\n";
