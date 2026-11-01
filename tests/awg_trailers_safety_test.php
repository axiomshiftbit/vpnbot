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
