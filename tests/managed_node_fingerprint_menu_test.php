<?php
// Same fingerprint marks as the main bot's fingerprintRejected(); RU and EN.
ob_start();require __DIR__.'/managed_nodes_test.php';ob_end_clean();
class NodeFingerprintFixture extends ManagedFixtureBot {
    public function __construct(){parent::__construct();$this->admin=true;$this->input+=['callback'=>'','message'=>''];$this->pacState['managed_nodes']['aabbccdd']['job']=null;}
    public function getWgMsg(){return null;}
    public function click(string $callback):void{$this->input['callback']=$callback;$this->action();}
}
$cases=[
 ['ws','origin',false,[]],
 ['grpc','origin',false,['android','360']],
 ['xhttp','fork',false,['android','360']],
 ['reality','origin',false,['ios','edge','qq','random','android','360']],
 ['reality','origin2',false,['ios','edge','qq','random','android','360']],
 ['reality','origin3',false,['android','360']],
 ['reality','fork',false,['android','360']],
 ['reality','fork',true,['ios','edge','qq','random','android','360']],
];
$checks=0;
foreach(['ru','en'] as $lang) foreach($cases as [$transport,$core,$mlkem,$rejected]) {
 $b=new NodeFingerprintFixture();$b->language=$lang;$id='aabbccdd';
 $o=$b->pacState['managed_nodes'][$id]['status']['options'];
 $o['transport']=$transport;$o['core']=$core;$o['xray']['reality']['requireMlkem']=$mlkem;
 $b->pacState['managed_nodes'][$id]['status']['options']=$o;
 $b->click("/nodeField $id xray.fingerprint");
 $rows=array_merge(...end($b->screens)[1]);
 $marked=[];
 foreach($rows as $row) if(str_ends_with($row['text'],' ⚠')) $marked[]=explode(' ',$row['callback_data'])[3];
 sort($marked);$want=$rejected;sort($want);
 if($marked!==$want)throw new RuntimeException("Wrong marks for $transport/$core: ".implode(',',$marked));
 foreach($rows as $row) if(strlen($row['callback_data'])>64)throw new RuntimeException('Callback too long');
 $checks++;
 $o['xray']['fingerprint']=$rejected[0]??'chrome';
 $b->pacState['managed_nodes'][$id]['status']['options']=$o;
 $b->click("/nodeSettings $id basic");
 $warned=str_contains((string)end($b->screens)[0],'⚠');
 if($warned!==($rejected!==[]))throw new RuntimeException("Wrong warning for $transport/$core");
 $checks++;
}
// Node removal confirmation: a real line break, never a literal backslash-n.
foreach(['ru','en'] as $lang){
 $b=new NodeFingerprintFixture();$b->language=$lang;
 $b->click('/exitDel aabbccdd');
 $screen=(string)end($b->screens)[0];
 if(str_contains($screen,'\\n')||!str_contains($screen,"\n"))throw new RuntimeException('Literal line break in node removal');
 $checks++;
}
echo "PASS $checks node fingerprint marks match the main bot and node validator\n";
