<?php
require_once __DIR__.'/../app/bot.php';
$keys=['RandomTrailers'=>'on','H1'=>'1-100','H2'=>'101-200','H3'=>'201-300','H4'=>'301-400','RekeyTimeout'=>'5-10'];
if(Bot::awgRandomTrailersSafe($keys))throw new RuntimeException('broad headers considered safe');
if(Bot::amneziaKeysUsable($keys,true,true)['RandomTrailers']!=='on')throw new RuntimeException('client export changed before live server');
class TrailersFixture extends Bot {
    public array $state=[];public int $applied=0;public array $notices=[];
    public function __construct(){$this->language='ru';$this->input=['callback_id'=>'test'];}
    public function getInstanceWG($k=false){return $k?'':'wg0';}
    public function getPacConf(){return $this->state;}
    public function setPacConf(array $conf){$this->state=$conf;return true;}
    public function awgSupports31():?bool{return true;}
    public function menu($type=false,$arg=false,$return=false){}
    public function answer($id,$textNotify=false,$notify=false){$this->notices[]=$textNotify;}
    public function awgApplyGuarded(int $page,callable $mutate,bool $silent=false):bool{$mutate();$this->applied++;return true;}
}
$bot=new TrailersFixture();$bot->state=['amnezia_keys'=>$keys];$bot->toggleRandomTrailers();
if($bot->applied!==1 || $bot->state['amnezia_keys']['RandomTrailers']!=='off')throw new RuntimeException('cannot explicitly disable legacy unsafe mode');
$bot->toggleRandomTrailers();
if($bot->applied!==1 || !$bot->notices || $bot->state['amnezia_keys']['RandomTrailers']!=='off')throw new RuntimeException('unsafe mode enabled');
foreach(['H1','H2','H3'] as $key)$keys[$key]=explode('-',$keys[$key])[0];
if(!Bot::awgRandomTrailersSafe($keys))throw new RuntimeException('fixed headers rejected');
foreach(['H1','H2','H3'] as $key)$keys[$key].='-'.$keys[$key];
if(!Bot::awgRandomTrailersSafe($keys))throw new RuntimeException('fixed ranges rejected');
$keys['RandomTrailers']='off';$bot->state=['amnezia_keys'=>$keys];$bot->toggleRandomTrailers();
if($bot->applied!==2 || $bot->state['amnezia_keys']['RandomTrailers']!=='on')throw new RuntimeException('fixed headers cannot enable trailers');
echo "PASS broad header toggle safety, explicit legacy disable and consistent client exports\n";

class TrailersMutationFixture extends TrailersFixture {
    public function awgSupports3(): ?bool { return true; }
    public function genHeaderProtectionKey(): string { return base64_encode(str_repeat('a', 32)); }
    public function switchAmnezia($page=0,$reset=false,$reduce=false,$apply=false,$silent=false) { $this->applied++; }
}
$checks=0;
foreach (array_keys(Bot::AMNEZIA_TEMPLATE_LABELS) as $template) {
    $b=new TrailersMutationFixture();
    $b->state=['amnezia'=>1,'amnezia_tpl'=>'standard_3','amnezia_keys'=>$keys];
    $b->state['amnezia_keys']['RandomTrailers']='on';
    $b->applyAmneziaTemplate($template);
    if (($b->state['amnezia_keys']['RandomTrailers']??'off')==='on') throw new RuntimeException('template retained RandomTrailers with regenerated headers');
    $checks++;
}
foreach ([1,2,3] as $version) {
    $b=new TrailersMutationFixture();
    $fixed=$b->generateAmneziaKeys('standard_3');
    foreach (['H1','H2','H3'] as $name) $fixed[$name]=explode('-', (string)$fixed[$name])[0];
    $fixed['RandomTrailers']='on';
    $b->state=['amnezia'=>1,'amnezia_tpl'=>'standard_3','amnezia_keys'=>$fixed];
    $b->setAmneziaProto($version);
    $next=$b->state['amnezia_keys'];
    if ($version<3 && isset($next['RandomTrailers'])) throw new RuntimeException('downgrade retained 3.1 option');
    if ($version===3 && (!Bot::awgRandomTrailersSafe($next) || $next['RandomTrailers']!=='on')) throw new RuntimeException('version switch changed fixed-header policy');
    $checks++;
}
$b=new TrailersMutationFixture();
$b->state=['amnezia'=>1,'amnezia_tpl'=>'standard_3','amnezia_keys'=>$fixed];
$b->rotateAmneziaJunk(true);
if (!Bot::awgRandomTrailersSafe($b->state['amnezia_keys']) || $b->state['amnezia_keys']['RandomTrailers']!=='on') throw new RuntimeException('rotation changed fixed-header policy');
$b->resetAwg3();
if (isset($b->state['amnezia_keys']['RandomTrailers'])) throw new RuntimeException('reset retained 3.1 option');
echo 'PASS '.($checks+2)." template/version/rotation/reset trailer transitions\n";
