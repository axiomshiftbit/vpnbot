<?php

// Simulate a user saved by versions predating the shared VLESS subscriptions.
function managedProtocolFixtureUser(ManagedProtocol $store, string $name): string
{
    $id = 'a' . bin2hex(random_bytes(7)) . 'b';
    $store->change(static function (&$state) use ($store, $id, $name) {
        $user = ['name' => trim($name), 'password' => ManagedProtocol::secret(), 'token' => bin2hex(random_bytes(32)),
            'enabled' => true, 'expires' => null, 'quota' => null, 'reset' => bin2hex(random_bytes(8))];
        if ($store->protocol === 'tuic') $user['uuid'] = '00000000-0000-4000-8000-' . bin2hex(random_bytes(6));
        if ($store->protocol === 'shadowtls') $user['ss_key'] = base64_encode(random_bytes(16));
        $state['users'][$id] = $user;
    });
    return $id;
}
