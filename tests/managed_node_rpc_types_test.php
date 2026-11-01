<?php
require_once __DIR__.'/../app/bot.php';

class NodeRpcTypesFixture extends Bot {
    public string $body = '';
    public function __construct() {}
    protected function managedNodeTransport(string $id, string $action, $value = null): array {
        $this->body = json_encode($value, JSON_THROW_ON_ERROR);
        return [];
    }
    public function submitFixture(string $operation, array $value): object {
        $this->managedNodeRpc('aabbccdd', ['action'=>'submit', 'request'=>['operation'=>$operation, 'value'=>$value]]);
        return json_decode($this->body, false, 64, JSON_THROW_ON_ERROR)->request->value;
    }
}
$b = new NodeRpcTypesFixture();
$options = ['transport'=>'reality', 'core'=>'origin', 'family'=>4, 'connect_family'=>4,
    'domain'=>'', 'mask'=>'www.example.test', 'domain_aliases'=>[], 'amnezia'=>['parameters'=>[]]];
$check = static function (bool $ok, string $name): void {if (!$ok) throw new RuntimeException('FAIL '.$name);};
$wire = $b->submitFixture('configure', $options);
$check($wire->amnezia->parameters instanceof stdClass, 'empty AWG options remain a JSON object');
$check($wire->domain_aliases === [], 'empty domain list remains a list');
$wire = $b->submitFixture('restore', ['options'=>$options, 'tls'=>[], 'peers'=>[]]);
$check($wire->options->amnezia->parameters instanceof stdClass, 'restored empty AWG options remain an object');
$check($wire->tls instanceof stdClass && $wire->peers === [], 'empty TLS map and peer list keep their types');
$options['amnezia']['parameters'] = ['Jc'=>3];
$wire = $b->submitFixture('configure', $options);
$check($wire->amnezia->parameters->Jc === 3, 'nonempty AWG parameters preserved');
$options['amnezia']['parameters'] = [3];
$wire = $b->submitFixture('configure', $options);
$check($wire->amnezia->parameters === [3], 'invalid nonempty lists remain invalid for the remote validator');
$check($options['amnezia']['parameters'] === [3], 'caller data unchanged');
echo "PASS node RPC JSON object/list contracts\n";
