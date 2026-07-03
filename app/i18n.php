<?php

$i = [
    'warp'             => [
        'en' => 'Warp',
        'ru' => 'Warp',
    ],
    'wg_title'             => [
        'en' => 'Wireguard',
        'ru' => 'Wireguard',
    ],
    'amnezia'             => [
        'en' => 'Amnezia',
        'ru' => 'Amnezia',
    ],
    'sh_title'             => [
        'en' => 'Shadowsocks',
        'ru' => 'Shadowsocks',
    ],
    'ad_title'             => [
        'en' => 'AdGuard',
        'ru' => 'AdGuard',
    ],
    'config'               => [
        'en' => 'Settings',
        'ru' => 'настройки',
    ],
    'pac'                  => [
        'en' => 'PAC',
        'ru' => 'PAC',
    ],
    'chat'                 => [
        'en' => 'chat',
        'ru' => 'чат поддержки',
    ],
    'back'                 => [
        'en' => 'back',
        'ru' => 'назад',
    ],
    'relay'                => [
        'en' => 'relay',
        'ru' => 'relay',
    ],
    'relay hint'           => [
        'en' => 'Relay subscriptions swap only the server address+port to the relay; SNI/serverName/host and DNS stay real (TLS terminates on origin via DNAT).',
        'ru' => 'Relay-подписки подменяют только адрес+порт сервера на relay; SNI/serverName/host и DNS остаются реальными (TLS терминируется на origin через DNAT).',
    ],
    'add relay'            => [
        'en' => 'add relay',
        'ru' => 'добавить relay',
    ],
    'traffic limit'        => [
        'en' => 'traffic limit',
        'ru' => 'лимит трафика',
    ],
    'enter traffic limit'  => [
        'en' => 'enter traffic limit in GB (0 or empty = unlimited)',
        'ru' => 'введите лимит трафика в ГБ (0 или пусто = безлимит)',
    ],
    'dpi masking'          => [
        'en' => '🛡 DPI masking',
        'ru' => '🛡 маскировка DPI',
    ],
    'dpi hint'             => [
        'en' => 'Anti-DPI tweaks. All default OFF — enable one at a time and turn it back off if it breaks connectivity. Fragment/noise affect only the xray (v2rayNG) config.',
        'ru' => 'Настройки против DPI. Всё по умолчанию ВЫКЛ — включай по одной и выключай, если ломается связь. Fragment/noise влияют только на xray (v2rayNG) конфиг.',
    ],
    'fragment'             => [
        'en' => 'TLS fragment',
        'ru' => 'TLS-фрагментация',
    ],
    'noise'                => [
        'en' => 'UDP noise',
        'ru' => 'UDP-шум',
    ],
    'sniffing'             => [
        'en' => 'Sniffing',
        'ru' => 'Сниффинг',
    ],
    'mldsa'                => [
        'en' => 'Reality ML-DSA-65',
        'ru' => 'Reality ML-DSA-65',
    ],
    'mldsa hint'           => [
        'en' => 'ℹ️ Post-quantum Reality auth (extra cert signature). Backward compatible: only xray clients carrying the verify key check it; sing-box/mihomo and older clients keep working without it. Rotate Reality keys after enabling to re-issue links.',
        'ru' => 'ℹ️ Пост-квантовая аутентификация Reality (доп. подпись сертификата). Обратно совместима: проверяют только xray-клиенты с verify-ключом; sing-box/mihomo и старые клиенты продолжают работать без него. После включения ротани ключи Reality, чтобы переиздать ссылки.',
    ],
    'reality params'       => [
        'en' => 'Reality params',
        'ru' => 'параметры Reality',
    ],
    'enter value'          => [
        'en' => 'enter value (0/default/off = default)',
        'ru' => 'введите значение (0/default/off = по умолчанию)',
    ],
    'autogen'              => [
        'en' => 'autogen',
        'ru' => 'авто',
    ],
    'default'              => [
        'en' => 'default',
        'ru' => 'по умолчанию',
    ],
    'relay subscriptions'  => [
        'en' => 'relay subscriptions',
        'ru' => 'relay-подписки',
    ],
    'external links'       => [
        'en' => 'external links',
        'ru' => 'внешние ссылки',
    ],
    'external hint'        => [
        'en' => 'Add third-party share links and remote subscription URLs from other servers — they are merged into this client\'s base64 (v2rayNG) subscription.',
        'ru' => 'Добавьте сторонние share-ссылки и URL удалённых подписок с других серверов — они подмешиваются в base64-подписку (v2rayNG) этого клиента.',
    ],
    'add external link'    => [
        'en' => 'add external link',
        'ru' => 'добавить внешнюю ссылку',
    ],
    'add external subscription' => [
        'en' => 'add external subscription',
        'ru' => 'добавить внешнюю подписку',
    ],
    'enter external link'  => [
        'en' => 'enter a share link (vless://, vmess://, trojan://, ss:// …)',
        'ru' => 'отправьте share-ссылку (vless://, vmess://, trojan://, ss:// …)',
    ],
    'enter external subscription' => [
        'en' => 'enter a remote subscription URL (https only)',
        'ru' => 'отправьте URL удалённой подписки (только https)',
    ],
    'enter remark'         => [
        'en' => 'enter a display name (empty to keep the original)',
        'ru' => 'введите отображаемое имя (пусто — оставить как есть)',
    ],
    'ext status pending'   => [
        'en' => 'not fetched yet',
        'ru' => 'ещё не загружено',
    ],
    'ext status nodes'     => [
        'en' => 'nodes',
        'ru' => 'узлов',
    ],
    'rotate subscription'  => [
        'en' => 'rotate sub link',
        'ru' => 'сменить ссылку подписки',
    ],
    'subtoken strict'      => [
        'en' => 'strict sub token',
        'ru' => 'строгий токен подписки',
    ],
    'relay aggregate'      => [
        'en' => 'relays in one sub',
        'ru' => 'relay одной подпиской',
    ],
    'relay health'         => [
        'en' => 'health',
        'ru' => 'статус',
    ],
    'relay delete'         => [
        'en' => '🗑 delete relay',
        'ru' => '🗑 удалить relay',
    ],
    'relay address'        => [
        'en' => 'relay address',
        'ru' => 'адрес relay',
    ],
    'relay port map'       => [
        'en' => 'port map (src:dst)',
        'ru' => 'маппинг портов (src:dst)',
    ],
    'enter relay name'     => [
        'en' => 'enter relay name (letters, digits, - . _)',
        'ru' => 'введите имя relay (буквы, цифры, - . _)',
    ],
    'enter relay address'  => [
        'en' => 'enter relay address (domain or IP)',
        'ru' => 'введите адрес relay (домен или IP)',
    ],
    'enter relay port map' => [
        'en' => 'enter port map src:dst,src:dst (e.g. 443:8443), empty to clear',
        'ru' => 'введите маппинг портов src:dst,src:dst (напр. 443:8443), пусто — очистить',
    ],
    'relay awg address'    => [
        'en' => 'WG/AWG relay address',
        'ru' => 'адрес relay для WG/AWG',
    ],
    'relay awg port map'   => [
        'en' => 'WG/AWG port map (src:dst)',
        'ru' => 'маппинг портов WG/AWG (src:dst)',
    ],
    'enter relay awg address' => [
        'en' => 'enter WG/AWG relay address (domain or IP), empty to clear',
        'ru' => 'введите адрес relay для WG/AWG (домен или IP), пусто — очистить',
    ],
    'enter relay awg port map' => [
        'en' => 'enter WG/AWG port map src:dst,src:dst (e.g. 51820:443), empty to clear',
        'ru' => 'введите маппинг портов WG/AWG src:dst,src:dst (напр. 51820:443), пусто — очистить',
    ],
    'import'               => [
        'en' => 'restore',
        'ru' => 'восстановить',
    ],
    'export'               => [
        'en' => 'backup',
        'ru' => 'сохранить',
    ],
    'delete'               => [
        'en' => 'delete',
        'ru' => 'удалить',
    ],
    'add'                  => [
        'en' => 'add',
        'ru' => 'добавить',
    ],
    'donate'               => [
        'en' => 'donate',
        'ru' => 'донат',
    ],
    'admin'                => [
        'en' => 'admin',
        'ru' => 'админа',
    ],
    'menu'                 => [
        'en' => 'Menu',
        'ru' => 'Меню',
    ],
    'update status'        => [
        'en' => 'update status',
        'ru' => 'обновить статус',
    ],
    'add peer'             => [
        'en' => 'add peer',
        'ru' => 'добавить клиента',
    ],
    'all traffic'          => [
        'en' => 'all traffic',
        'ru' => 'весь трафик',
    ],
    'subnet'               => [
        'en' => 'subnet',
        'ru' => 'подсеть',
    ],
    'proxy ip'             => [
        'en' => 'proxy ip',
        'ru' => 'айпи прокси',
    ],
    'rename'               => [
        'en' => 'rename',
        'ru' => 'переименовать',
    ],
    'show QR'              => [
        'en' => 'show QR',
        'ru' => 'показать QR',
    ],
    'download config'      => [
        'en' => 'download config',
        'ru' => 'скачать настройки',
    ],
    'install domain'       => [
        'en' => 'install domain',
        'ru' => 'установить домен',
    ],
    'renew SSL'            => [
        'en' => 'renew SSL',
        'ru' => 'обновить SSL',
    ],
    'delete SSL'           => [
        'en' => 'delete SSL',
        'ru' => 'удалить SSL',
    ],
    'Letsencrypt SSL'      => [
        'en' => 'Letsencrypt SSL',
        'ru' => 'Letsencrypt SSL',
    ],
    'Self SSL'             => [
        'en' => 'Self SSL',
        'ru' => 'Собственный SSL',
    ],
    'change password'      => [
        'en' => 'change password',
        'ru' => 'изменить пароль',
    ],
    'generate password'    => [
        'en' => 'generate password',
        'ru' => 'сгенерировать пароль',
    ],
    'obfs password'        => [
        'en' => 'obfs password',
        'ru' => 'пароль obfs',
    ],
    'not found'            => [
        'en' => 'not found',
        'ru' => 'не найден',
    ],
    'port hopping fw hint' => [
        'en' => 'Port hopping needs a firewall rule that redirects the whole UDP range to the real Hysteria port. The bot will show the nft snippet — apply it yourself (manual nft / not auto-managed).',
        'ru' => 'Для port hopping нужно правило firewall, реднатящее весь UDP-диапазон на реальный порт Hysteria. Бот покажет nft-сниппет — примени его сам (ручной nft, бот его не трогает).',
    ],
    'port hopping bad'     => [
        'en' => 'invalid port range',
        'ru' => 'неверный диапазон портов',
    ],
    'cloak port:'          => [
        'en' => 'cloak port:',
        'ru' => 'cloak порт:',
    ],
    'cloak masq:'          => [
        'en' => 'cloak masq:',
        'ru' => 'cloak маска:',
    ],
    'regen cloak keys'     => [
        'en' => 'regen cloak keys',
        'ru' => 'новые ключи cloak',
    ],
    'cloak method:'        => [
        'en' => 'cloak method:',
        'ru' => 'cloak метод:',
    ],
    'cloak users'          => [
        'en' => 'cloak users',
        'ru' => 'пользователи cloak',
    ],
    'add user'             => [
        'en' => 'add user',
        'ru' => 'добавить пользователя',
    ],
    'stls port:'           => [
        'en' => 'stls port:',
        'ru' => 'stls порт:',
    ],
    'stls SNI:'            => [
        'en' => 'stls SNI:',
        'ru' => 'stls SNI:',
    ],
    'change sni'           => [
        'en' => 'change sni',
        'ru' => 'изменить sni',
    ],
    'masquerade'           => [
        'en' => 'masquerade',
        'ru' => 'маскировка',
    ],
    'masquerade host'      => [
        'en' => 'decoy site',
        'ru' => 'decoy-сайт',
    ],
    'masquerade hint'      => [
        'en' => 'Pick a real third-party site to reverse-proxy probes to. Pointing at your own IP/domain is weak camouflage.',
        'ru' => 'Выберите реальный сторонний сайт — на него будут проксироваться зонды. Указывать на свой IP/домен — слабая маскировка.',
    ],
    'reset settings'       => [
        'en' => 'reset settings',
        'ru' => 'сбросить настройки',
    ],
    'add upstream'         => [
        'en' => 'add upstream',
        'ru' => 'добавить DNS',
    ],
    'check DNS'            => [
        'en' => 'check DNS',
        'ru' => 'проверить DNS',
    ],
    'update'               => [
        'en' => 'update',
        'ru' => 'обновить',
    ],
    'self list'            => [
        'en' => 'self list',
        'ru' => 'собственный список',
    ],
    'reverse list'         => [
        'en' => 'reverse list',
        'ru' => 'обратный список',
    ],
    'subzones'             => [
        'en' => 'subzones',
        'ru' => 'поддомены',
    ],
    'check url'            => [
        'en' => 'check url',
        'ru' => 'проверить домен',
    ],
    'blacklist exclude'    => [
        'en' => 'blacklist exclude',
        'ru' => 'исключения из списка ркн',
    ],
    'lang'                 => [
        'en' => 'language',
        'ru' => 'язык интерфейса',
    ],
    'adguard web'          => [
        'en' => 'web interface',
        'ru' => 'вебморда адгварда',
    ],
    'domain explain'       => [
        'en' => 'Some clients require a valid certificate when connecting, such as windows 11 DoH or ShadowSocks Android (PAC url), this requires a domain',
        'ru' => 'Некоторым клиентам требуется валидный сертификат при подключении, например Windows 11 DoH или ShadowSocks Android (URL-адрес PAC), для этого требуется домен',
    ],
    'self list explain'    => [
        'en' => ' - domains that will work through a proxy, all others directly',
        'ru' => ' - домены, которые будут работать через прокси, все остальные напрямую',
    ],
    'reverse list explain' => [
        'en' => ' - domains that will work directly, all others through a proxy',
        'ru' => ' - домены которые будут работать напрямую, все остальные через прокси',
    ],
    'timer'                => [
        'en' => 'set timer',
        'ru' => 'установить время действия',
    ],
    'reset nginx'          => [
        'en' => 'reset nginx',
        'ru' => 'сбросить nginx',
    ],
    'set internal dns'     => [
        'en' => 'set internal dns',
        'ru' => 'установить внутренний dns',
    ],
    'delete internal dns'  => [
        'en' => 'delete internal dns',
        'ru' => 'удалить внутренний dns',
    ],
    'hwid limit' => [
        'en' => 'HWID limit',
        'ru' => 'HWID лимит',
    ],
    'hwid devices' => [
        'en' => 'HWID devices',
        'ru' => 'Устройства HWID',
    ],
    'set hwid devices count' => [
        'en' => 'set HWID devices count',
        'ru' => 'установить количество HWID устройств',
    ],
    'use default hwid limit' => [
        'en' => 'use default limit',
        'ru' => 'использовать лимит по умолчанию',
    ],
    'no devices' => [
        'en' => 'no devices',
        'ru' => 'нет устройств',
    ],
    'hwid notice' => [
        'en' => 'HWID limit works only when subscription is refreshed or added',
        'ru' => 'HWID лимит срабатывает только в момент обновления и добавления подписки',
    ],
    'on'  => [
        'en' => '🟢',
        'ru' => '🟢',
    ],
    'off'  => [
        'en' => '🔴',
        'ru' => '🔴',
    ],
    'torrent'  => [
        'en' => 'torrents',
        'ru' => 'торренты',
    ],
    'blinkmenuon'  => [
        'en' => 'blinkmenu on',
        'ru' => 'прыгающее меню вкл',
    ],
    'blinkmenuoff'  => [
        'en' => 'blinkmenu off',
        'ru' => 'прыгающее меню выкл',
    ],
    'listSubnet'  => [
        'en' => 'listSubnet',
        'ru' => 'список подсетей',
    ],
    'AllowedIPs'  => [
        'en' => 'AllowedIPs',
        'ru' => 'AllowedIPs',
    ],
    'calc'  => [
        'en' => 'calc CIDR',
        'ru' => 'calc CIDR',
    ],
    'mtproto'  => [
        'en' => 'MTProto',
        'ru' => 'MTProto',
    ],
    'telemt'  => [
        'en' => 'TeleMT',
        'ru' => 'TeleMT',
    ],
    'telemt add user'  => [
        'en' => '➕ add user',
        'ru' => '➕ добавить юзера',
    ],
    'telemt users'  => [
        'en' => 'users',
        'ru' => 'пользователи',
    ],
    'telemt settings'  => [
        'en' => 'settings',
        'ru' => 'настройки',
    ],
    'telemt mode'  => [
        'en' => 'mode',
        'ru' => 'режим',
    ],
    'telemt mode classic'  => [
        'en' => 'classic',
        'ru' => 'classic',
    ],
    'telemt mode secure'  => [
        'en' => 'secure (dd)',
        'ru' => 'secure (dd)',
    ],
    'telemt mode tls'  => [
        'en' => 'tls (ee)',
        'ru' => 'tls (ee)',
    ],
    'telemt mode note'  => [
        'en' => 'Only one mode is active. tls (ee) = Fake-TLS + SNI fronting (recommended); secure = dd-secret; classic = plain.',
        'ru' => 'Активен только один режим. tls (ee) = Fake-TLS + SNI fronting (рекомендуется); secure = dd-секрет; classic = обычный.',
    ],
    'telemt sni'  => [
        'en' => 'unknown SNI',
        'ru' => 'неизвестный SNI',
    ],
    'telemt sni reject_handshake'  => [
        'en' => 'reject_handshake (nginx-like)',
        'ru' => 'reject_handshake (как nginx)',
    ],
    'telemt sni mask'  => [
        'en' => 'mask (front any SNI)',
        'ru' => 'mask (фронт любого SNI)',
    ],
    'telemt sni drop'  => [
        'en' => 'drop (silent close)',
        'ru' => 'drop (молча закрыть)',
    ],
    'telemt sni note'  => [
        'en' => 'Action for a ClientHello whose SNI differs from the Fake-TLS domain. reject_handshake = look like a stock web server (default). mask = transparently front any SNI to the mask host — use to debug a link/domain mismatch ("Unknown TLS SNI"). drop = silently close.',
        'ru' => 'Что делать с ClientHello, чей SNI не совпадает с Fake-TLS доменом. reject_handshake = вести себя как обычный веб-сервер (дефолт). mask = прозрачно фронтить любой SNI на mask-host — полезно при рассинхроне ссылки и домена ("Unknown TLS SNI"). drop = молча закрыть.',
    ],
    'telemt relays'  => [
        'en' => 'relays',
        'ru' => 'релеи',
    ],
    'telemt direct'  => [
        'en' => 'direct',
        'ru' => 'напрямую',
    ],
    'telemt masking'  => [
        'en' => 'masking',
        'ru' => 'маскировка',
    ],
    'telemt masking note'  => [
        'en' => 'These harden the anti-probe cover path only — real client traffic is unaffected, so enabling them is safe.',
        'ru' => 'Усиливают только cover-path против active-probing — трафика реальных клиентов не касаются, включать безопасно.',
    ],
    'telemt realism'  => [
        'en' => 'Client-path TLS emulation: on. Session tickets use telemt default (0) unless overridden.',
        'ru' => 'TLS-эмуляция на клиентском пути: включена. Session tickets используют дефолт telemt (0), если не переопределены.',
    ],
    'telemt diagnostics'  => [
        'en' => 'diagnostics',
        'ru' => 'диагностика',
    ],
    'telemt observe'  => [
        'en' => '📄 beobachten log',
        'ru' => '📄 журнал beobachten',
    ],
    'telemt report'  => [
        'en' => '📊 diagnostics report',
        'ru' => '📊 отчёт диагностики',
    ],
    'port unavailable'  => [
        'en' => 'port unavailable',
        'ru' => 'порт не задан',
    ],
    'telemt set port hint'  => [
        'en' => 'set a port in Settings -> Ports to expose the proxy',
        'ru' => 'задайте порт в "настройки -> Ports", чтобы открыть прокси',
    ],
    'generateSecret'  => [
        'en' => 'generateSecret',
        'ru' => 'сгенерировать ключ',
    ],
    'setSecret'  => [
        'en' => 'setSecret',
        'ru' => 'установить свой ключ',
    ],
    'setAdTag'  => [
        'en' => 'set adtag',
        'ru' => 'установить adtag',
    ],
    'defaultDNS'  => [
        'en' => 'defaultDNS',
        'ru' => 'дефолтный днс',
    ],
    'defaultMTU'  => [
        'en' => 'defaultMTU',
        'ru' => 'дефолтный MTU',
    ],
    'debug'  => [
        'en' => 'debug mode',
        'ru' => 'режим отладки',
    ],
    'backup'  => [
        'en' => 'auto backup',
        'ru' => 'автобэкап',
    ],
    'logs'  => [
        'en' => 'logs',
        'ru' => 'логи',
    ],
    'server status'  => [
        'en' => '📊 server status',
        'ru' => '📊 статус сервера',
    ],
    'no one online'  => [
        'en' => 'no one online',
        'ru' => 'никого онлайн',
    ],
    'ago'  => [
        'en' => 'ago',
        'ru' => 'назад',
    ],
    'rotate all'  => [
        'en' => 'rotate all',
        'ru' => 'ротация всего',
    ],
    'new clientID'  => [
        'en' => 'new clientID',
        'ru' => 'новый clientID',
    ],
    'clear'  => [
        'en' => 'clear',
        'ru' => 'очистить',
    ],
    'xray'  => [
        'en' => 'Vless',
        'ru' => 'Vless',
    ],
    'clash'  => [
        'en' => 'mihomo',
        'ru' => 'mihomo',
    ],
    'geodb'  => [
        'en' => 'GeoIp/GeoSite',
        'ru' => 'GeoIp/GeoSite',
    ],
    'changeFakeDomain'  => [
        'en' => 'changeFakeDomain',
        'ru' => 'фейковый домен',
    ],
    'fingerprint'  => [
        'en' => 'fingerprint',
        'ru' => 'отпечаток',
    ],
    'selfFakeDomain'  => [
        'en' => 'steal from yourself',
        'ru' => 'steal from yourself',
    ],
    'page'  => [
        'en' => 'pagination',
        'ru' => 'пагинация',
    ],
    'exchange'  => [
        'en' => 'client isolation',
        'ru' => 'изоляция клиентов',
    ],
    'ocserv'  => [
        'en' => 'OpenConnect',
        'ru' => 'OpenConnect',
    ],
    'naive'  => [
        'en' => 'NaiveProxy',
        'ru' => 'NaiveProxy',
    ],
    'change login'  => [
        'en' => 'change login',
        'ru' => 'изменить логин',
    ],
    'change secret'  => [
        'en' => 'change secret',
        'ru' => 'секретное слово',
    ],
    'dns'  => [
        'en' => 'dns',
        'ru' => 'днс',
    ],
    'mirror'  => [
        'en' => 'mirror',
        'ru' => 'зеркало',
    ],
    'download'  => [
        'en' => 'download',
        'ru' => 'скачать',
    ],
    'update bot'  => [
        'en' => 'update bot',
        'ru' => 'обновить бота',
    ],
    'third party browser'  => [
        'en' => 'third party browser',
        'ru' => 'сторонний браузер',
    ],
    'browser_notify_on'  => [
        'en' => 'the web panel can be opened in any browser',
        'ru' => 'веб панель может быть открыта в любом браузере',
    ],
    'browser_notify_off'  => [
        'en' => 'web panel is only available from telegram',
        'ru' => 'веб панель доступна только из телеграмма',
    ],
    'no updates'  => [
        'en' => 'no updates',
        'ru' => 'нет обновлений',
    ],
    'have updates'  => [
        'en' => '🟢 have updates',
        'ru' => '🟢 есть обновления',
    ],
    'fake html'  => [
        'en' => 'fake html',
        'ru' => 'фейк заглушка',
    ],
    'expose-iroutes'  => [
        'en' => 'expose-iroutes',
        'ru' => 'изоляция клиентов',
    ],
    'fill allowed clients'  => [
        'en' => 'fill allowed clients',
        'ru' => 'заполнить белый список клиентов',
    ],
    'delete allowed clients'  => [
        'en' => 'delete allowed clients',
        'ru' => 'очистить белый список клиентов',
    ],
    'success'  => [
        'en' => 'success',
        'ru' => 'сохранено',
    ],
    'error'  => [
        'en' => 'error',
        'ru' => 'ошибка',
    ],
    'save'  => [
        'en' => 'save',
        'ru' => 'сохранить',
    ],
    'copy'  => [
        'en' => 'copy',
        'ru' => 'копировать',
    ],
    'restart'  => [
        'en' => 'restart',
        'ru' => 'перезагрузка',
    ],
    'OpenVPN'  => [
        'en' => 'OpenVPN',
        'ru' => 'OpenVPN',
    ],
    'inter-client'  => [
        'en' => 'inter-client routing',
        'ru' => 'трафик между клиентами',
    ],
    'inter-client on hint'  => [
        'en' => 'on: clients see each other',
        'ru' => 'вкл: клиенты видят друг друга',
    ],
    'inter-client off hint'  => [
        'en' => 'off: clients isolated',
        'ru' => 'выкл: клиенты изолированы',
    ],
    'refresh'  => [
        'en' => 'refresh',
        'ru' => 'обновить',
    ],
    'refreshed'  => [
        'en' => 'refreshed',
        'ru' => 'обновлено',
    ],
    'real ip'  => [
        'en' => 'real IP',
        'ru' => 'реальный IP',
    ],
    'online'  => [
        'en' => 'online',
        'ru' => 'онлайн',
    ],
    'offline'  => [
        'en' => 'offline',
        'ru' => 'оффлайн',
    ],
    'traffic'  => [
        'en' => 'traffic',
        'ru' => 'трафик',
    ],
    'kick'  => [
        'en' => 'kick',
        'ru' => 'отключить',
    ],
    'disable'  => [
        'en' => 'disable',
        'ru' => 'заблокировать',
    ],
    'enable'  => [
        'en' => 'enable',
        'ru' => 'разблокировать',
    ],
    'log tail'  => [
        'en' => 'log tail',
        'ru' => 'журнал',
    ],
    'connections'  => [
        'en' => 'connections',
        'ru' => 'подключения',
    ],
    'status'  => [
        'en' => 'status',
        'ru' => 'статус',
    ],
    'disabled'  => [
        'en' => 'disabled',
        'ru' => 'заблокирован',
    ],
    'settings'  => [
        'en' => 'settings',
        'ru' => 'настройки',
    ],
    'expires'  => [
        'en' => 'expires',
        'ru' => 'истекает',
    ],
    'expired'  => [
        'en' => 'expired',
        'ru' => 'истёк',
    ],
    'created'  => [
        'en' => 'created',
        'ru' => 'создан',
    ],
    'last seen'  => [
        'en' => 'last seen',
        'ru' => 'был в сети',
    ],
    'never'  => [
        'en' => 'never',
        'ru' => 'никогда',
    ],
    'since'  => [
        'en' => 'since',
        'ru' => 'подключён с',
    ],
    'history'  => [
        'en' => 'history',
        'ru' => 'история',
    ],
    'confirm delete ovpn'  => [
        'en' => 'delete client? this revokes the certificate irreversibly',
        'ru' => 'удалить клиента? сертификат будет безвозвратно отозван',
    ],
    'delete forever'  => [
        'en' => 'delete forever',
        'ru' => 'удалить навсегда',
    ],
    'cancel'  => [
        'en' => 'cancel',
        'ru' => 'отмена',
    ],
    'credentials'  => [
        'en' => 'credentials',
        'ru' => 'реквизиты',
    ],
    'profile'  => [
        'en' => 'profile',
        'ru' => 'профиль',
    ],
    'confirm delete user'  => [
        'en' => 'delete user permanently?',
        'ru' => 'удалить пользователя безвозвратно?',
    ],
    'no native l2tp'  => [
        'en' => 'no native L2TP client, use IKEv2 instead',
        'ru' => 'нет нативного L2TP-клиента, используйте IKEv2',
    ],
];

if (file_exists(__DIR__ . '/i18n.override.php')) {
    include __DIR__ . '/i18n.override.php';
}
