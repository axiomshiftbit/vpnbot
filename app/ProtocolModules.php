<?php

require_once __DIR__ . '/Lang.php';
require_once __DIR__ . '/ManagedProtocol.php';

/** Optional containers are independent from their saved VPN credentials. */
final class ProtocolModules
{
    public const DEFAULTS = ['oc' => true, 'ovpn' => true, 'tt' => true, 'hy' => true, 'ss' => true, 'dnstt' => true, 'telemt' => true, 'ipsec' => true,
        'ikev2' => true, 'l2tp' => true, 'anytls' => false, 'mieru' => false, 'tuic' => false, 'shadowtls' => false, 'snolc' => false, 'masque' => false];
    public const LABELS = ['oc' => 'OpenConnect', 'ovpn' => 'OpenVPN', 'tt' => 'TrustTunnel', 'hy' => 'Hysteria', 'ss' => 'Shadowsocks', 'dnstt' => 'DNSTT', 'telemt' => 'TeleMT', 'ipsec' => 'IPsec',
        'ikev2' => 'IKEv2', 'l2tp' => 'L2TP/IPsec', 'anytls' => 'AnyTLS', 'mieru' => 'Mieru', 'tuic' => 'TUIC v5', 'shadowtls' => 'ShadowTLS v3 + SS', 'snolc' => 'snolc · SSH + Noise', 'masque' => 'MASQUE'];

    public function __construct(public readonly string $path = '/config/protocol-services.json') {}

    public function read(): array
    {
        if (!file_exists($this->path)) return self::DEFAULTS;
        $settings = ManagedProtocol::readJson($this->path);
        if (array_diff_key($settings, self::DEFAULTS)) throw new RuntimeException(Lang::t('Неизвестный модуль протокола', 'Unknown protocol module'));
        foreach ($settings as $value) if (!is_bool($value)) throw new RuntimeException(Lang::t('Повреждены настройки модулей', 'The module settings are damaged'));
        return array_replace(self::DEFAULTS, $settings);
    }

    public function enabled(string $key): bool
    {
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
        if (array_diff_key($values, self::DEFAULTS)) throw new InvalidArgumentException(Lang::t('Неизвестный модуль', 'Unknown module'));
        foreach ($values as $value) if (!is_bool($value)) throw new InvalidArgumentException(Lang::t('Неверное состояние модуля', 'Invalid module state'));
        $this->update(static fn($settings) => array_replace($settings, $values));
    }

    public function toggle(string $key): void
    {
        if (!isset(self::DEFAULTS[$key])) throw new InvalidArgumentException(Lang::t('Неизвестный модуль', 'Unknown module'));
        $this->update(static fn($settings) => array_replace($settings, [$key => !$settings[$key]]));
    }

    private function update(callable $change): void
    {
        $old = umask(0077);
        $lock = @fopen($this->path . '.lock', 'c');
        umask($old);
        if (!$lock) throw new RuntimeException(Lang::t('Не удалось открыть блокировку модулей', 'Could not open the module lock'));
        try {
            if (!flock($lock, LOCK_EX)) throw new RuntimeException(Lang::t('Модули заняты', 'Modules are busy'));
            $settings = $change($this->read());
            ManagedProtocol::writeJson($this->path, $settings);
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }
}
