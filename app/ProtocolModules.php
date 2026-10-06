<?php

require_once __DIR__ . '/ManagedProtocol.php';

/** Optional containers are independent from their saved VPN credentials. */
final class ProtocolModules
{
    public const DEFAULTS = ['oc' => true, 'ovpn' => true, 'tt' => true, 'hy' => true, 'ss' => true, 'dnstt' => true, 'telemt' => true, 'ipsec' => true,
        'ikev2' => true, 'l2tp' => true, 'anytls' => false, 'mieru' => false, 'tuic' => false, 'shadowtls' => false, 'masque' => false];
    public const LABELS = ['oc' => 'OpenConnect', 'ovpn' => 'OpenVPN', 'tt' => 'TrustTunnel', 'hy' => 'Hysteria', 'ss' => 'Shadowsocks', 'dnstt' => 'DNSTT', 'telemt' => 'TeleMT', 'ipsec' => 'IPsec',
        'ikev2' => 'IKEv2', 'l2tp' => 'L2TP/IPsec', 'anytls' => 'AnyTLS', 'mieru' => 'Mieru', 'tuic' => 'TUIC v5', 'shadowtls' => 'ShadowTLS v3 + SS', 'masque' => 'MASQUE'];

    public function __construct(public readonly string $path = '/config/protocol-services.json') {}

    public function read(): array
    {
        if (!file_exists($this->path)) return self::DEFAULTS;
        $settings = ManagedProtocol::readJson($this->path);
        // The removed module may remain in settings from an older installation.
        unset($settings['snolc']);
        if (array_diff_key($settings, self::DEFAULTS)) throw new RuntimeException('Неизвестный модуль протокола');
        foreach ($settings as $value) if (!is_bool($value)) throw new RuntimeException('Повреждены настройки модулей');
        return array_replace(self::DEFAULTS, $settings);
    }

    public function enabled(string $key): bool
    {
        if ($key === 'snolc') return false;
        if (!isset(self::DEFAULTS[$key])) return true;
        $s = $this->read();
        if ($key === 'ipsec') return $s['ipsec'] && ($s['ikev2'] || $s['l2tp']);
        return $s[$key] && (!in_array($key, ['ikev2', 'l2tp'], true) || $s['ipsec']);
    }

    public function set(string $key, bool $enabled): void
    {
        $this->setMany([$key => $enabled]);
    }

    public function setMany(array $values): void
    {
        if (array_diff_key($values, self::DEFAULTS)) throw new InvalidArgumentException('Неизвестный модуль');
        foreach ($values as $value) if (!is_bool($value)) throw new InvalidArgumentException('Неверное состояние модуля');
        $this->update(static fn($settings) => array_replace($settings, $values));
    }

    public function toggle(string $key): void
    {
        if (!isset(self::DEFAULTS[$key])) throw new InvalidArgumentException('Неизвестный модуль');
        $this->update(static fn($settings) => array_replace($settings, [$key => !$settings[$key]]));
    }

    private function update(callable $change): void
    {
        $old = umask(0077);
        $lock = @fopen($this->path . '.lock', 'c');
        umask($old);
        if (!$lock) throw new RuntimeException('Не удалось открыть блокировку модулей');
        try {
            if (!flock($lock, LOCK_EX)) throw new RuntimeException('Модули заняты');
            $settings = $change($this->read());
            ManagedProtocol::writeJson($this->path, $settings);
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }
}
