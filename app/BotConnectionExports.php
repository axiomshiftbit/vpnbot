<?php

trait BotConnectionExports
{
    public function connectionFormats(string $protocol): array
    {
        if ($protocol === 'masque') return ['native' => $this->t('MASQUE · полный JSON Xray 26.9.30+', 'MASQUE · full JSON for Xray 26.9.30+')];
        if ($protocol === 'snolc') return ['native' => 'snolc SSH + Noise · ZIP'];
        $formats = ['cl' => 'Mihomo · YAML', 'clj' => 'Mihomo · JSON'];
        if ($protocol !== 'mieru') $formats['si'] = 'sing-box · JSON';
        if ($protocol === 'vless') {
            $formats['s'] = 'Xray · JSON';
            if ($this->subscriptionCompatibilityError($this->getXray(), $this->getPacConf(), 'si') !== ''
                || ($this->getPacConf()['transport'] ?? '') === 'xhttp') unset($formats['si']);
        }
        if ($protocol !== 'shadowtls') $formats['uri'] = $this->t('Ссылка · TXT', 'Link · TXT');
        if ($protocol !== 'vless') $formats['sr'] = $this->t('Shadowrocket · параметры TXT', 'Shadowrocket · TXT parameters');
        return $formats;
    }

    /** Keep just the connection and its required detours (ShadowTLS, Xray DPI). */
    public static function connectionNodes(array $config, string $type, int $index = 0, string $name = ''): array
    {
        $key = $type === 'cl' ? 'proxies' : 'outbounds'; $tag = $type === 'cl' ? 'name' : 'tag';
        if (!isset($config[$key][$index][$tag])) throw new RuntimeException(Lang::t('Не найдено подключение в шаблоне.', 'No connection found in the template.'));
        $pending = [$config[$key][$index][$tag]]; $nodes = [];
        while ($pending) {
            $next = array_shift($pending);
            if ($type === 'cl' && $next === 'DIRECT' && $nodes) continue;
            if (isset($nodes[$next])) throw new RuntimeException(Lang::t('В шаблоне обнаружена циклическая цепочка подключений.', 'The template has a cyclic chain of connections.'));
            $matches = array_values(array_filter($config[$key], static fn($node) => ($node[$tag] ?? '') === $next));
            if (count($matches) !== 1) throw new RuntimeException(Lang::t('Подключение зависит от отсутствующей или неоднозначной группы/прокси. Используйте полный профиль.', 'The connection depends on a missing or ambiguous group/proxy. Use the full profile.'));
            $node = $matches[0];
            if (in_array($node['type'] ?? '', ['selector', 'urltest'], true)) throw new RuntimeException(Lang::t('Подключение зависит от группы. Используйте полный профиль.', 'The connection depends on a group. Use the full profile.'));
            // A fragment must not refer to a DNS server defined only in the full template.
            if ($type === 'si') unset($node['domain_resolver']);
            $nodes[$next] = $node;
            $dependency = $node['detour'] ?? $node['dialer-proxy'] ?? $node['streamSettings']['sockopt']['dialerProxy'] ?? null;
            if (is_string($dependency) && $dependency !== '') $pending[] = $dependency;
        }
        if ($name !== '') {
            $names = []; $n = 0;
            foreach ($nodes as $old => $_) $names[$old] = $name . ($n++ === 0 ? '' : ' · ' . $old);
            foreach ($nodes as &$node) {
                $node[$tag] = $names[$node[$tag]];
                foreach (['detour', 'dialer-proxy'] as $field) if (isset($node[$field], $names[$node[$field]])) $node[$field] = $names[$node[$field]];
                if (isset($node['streamSettings']['sockopt']['dialerProxy'], $names[$node['streamSettings']['sockopt']['dialerProxy']])) {
                    $node['streamSettings']['sockopt']['dialerProxy'] = $names[$node['streamSettings']['sockopt']['dialerProxy']];
                }
            }
            unset($node);
        }
        return [$key => array_values($nodes)];
    }

    public function connectionExport(string $source, string $protocol, string $format): array|string
    {
        $found = $this->xrayProtocolClient($source);
        if ($found === null) throw new RuntimeException($this->t('Пользователь удалён.', 'User deleted.'));
        [$index, $client] = $found;
        if (!isset((['vless' => 'VLESS'] + ManagedProtocol::NAMES)[$protocol])) throw new InvalidArgumentException($this->t('Неизвестный протокол.', 'Unknown protocol.'));
        if (!isset($this->connectionFormats($protocol)[$format])) throw new InvalidArgumentException($this->t('Формат не поддерживается с текущими настройками. Выберите другой файл.', 'The format is not supported with the current settings. Choose another file.'));
        if (!empty($client['off']) || ((int) ($client['time'] ?? 0) > 0 && $client['time'] <= time())
            || ((int) ($client['traffic'] ?? 0) > 0 && $this->xrUserTraffic($this->getXrayStats(), $index)
                + array_sum($this->xrayProtocolUsage($client)) >= (int) $client['traffic'])) {
            throw new RuntimeException($this->t('Доступ отключён, истёк или исчерпан.', 'Access is disabled, expired or used up.'));
        }
        $type = $format === 'clj' ? 'cl' : $format;
        if ($format === 'sr') return self::shadowrocketSettings($protocol, $this->connectionExport($source, $protocol, 'cl')['proxies'][0]);
        if ($protocol === 'vless') {
            if (!$this->protocolModuleEnabled('xray')) throw new RuntimeException($this->t('Сервис VLESS выключен.', 'The VLESS service is off.'));
            if ($format === 'uri') {
                $link = $this->linkXray($index);
                if ($link === '') throw new RuntimeException($this->t('Ссылка недоступна с текущими настройками VLESS.', 'The link is not available with the current VLESS settings.'));
                return $link;
            }
            $before = $_GET; $token = $this->subToken;
            try {
                $_GET = ['s' => $this->sidOf($client), 't' => $type]; $this->subToken = [];
                $body = $this->subscription('connection');
                if ($body === '') throw new RuntimeException($this->t('Не удалось сформировать подключение. Проверьте совместимость клиента и шаблон.', 'Could not build the connection. Check client compatibility and the template.'));
                $config = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
            } finally { $_GET = $before; $this->subToken = $token; }
            return self::connectionNodes($config, $type, name: $client['email'] . ' · ' . (($this->getPacConf()['transport'] ?? '') === 'trojan-grpc' ? 'Trojan' : 'VLESS'));
        }
        $this->syncXrayProtocolUsers();
        $store = $this->protocolStore($protocol); $state = $store->read();
        if (!$this->protocolModuleEnabled($protocol) || !$state['enabled']) throw new RuntimeException($this->t('Сначала включите сервис этого протокола.', 'Enable this protocol\'s service first.'));
        if (!$this->protocolPortApplied($protocol, $state)) throw new RuntimeException($this->t('Внешний порт ещё не применён. Проверьте Settings → Ports.', 'The external port is not applied yet. Check Settings → Ports.'));
        foreach ($state['users'] as $id => $user) {
            if (($user['xray_source'] ?? '') !== $source || !hash_equals($user['xray_credential'], ManagedProtocol::xrayCredential($client))) continue;
            if ($protocol === 'masque') return $store->profile($id, 'native', $state);
            if ($protocol === 'snolc') return $store->profileDocument($id, 'native', $state)['body'];
            if ($format === 'uri') return $store->connectionUri($id, $state);
            $profile = $store->profile($id, $type === 'cl' ? 'mihomo' : 'singbox', $state);
            return self::connectionNodes($profile, $type, name: $client['email'] . ' · ' . ManagedProtocol::NAMES[$protocol]);
        }
        throw new RuntimeException($this->t('Подключение ещё не создано. Повторите после синхронизации сервиса.', 'The connection has not been created yet. Retry after the service syncs.'));
    }

    // Shadowrocket is closed source: export actual connection values for its
    // editor, not a fabricated URI dialect or a replacement routing profile.
    public static function shadowrocketSettings(string $protocol, array $node): string
    {
        $fields = [Lang::t('Тип', 'Type') => $protocol === 'shadowtls' ? 'Shadowsocks + ShadowTLS v3' : ManagedProtocol::NAMES[$protocol],
            Lang::t('Имя', 'Name') => $node['name'], Lang::t('Адрес', 'Address') => $node['server'], Lang::t('Порт', 'Port') => $node['port']];
        $map = ['password' => Lang::t('Пароль', 'Password'), 'uuid' => 'UUID (TUIC v5)', 'username' => Lang::t('Имя пользователя', 'Username'),
            'sni' => 'TLS SNI', 'alpn' => 'ALPN', 'client-fingerprint' => 'TLS fingerprint',
            'congestion-controller' => Lang::t('Контроль перегрузки', 'Congestion control'), 'udp-relay-mode' => Lang::t('Режим UDP', 'UDP mode'),
            'reduce-rtt' => '0-RTT', 'heartbeat-interval' => Lang::t('Heartbeat, мс', 'Heartbeat, ms'), 'udp' => 'UDP',
            'udp-over-stream' => 'UDP over stream', 'udp-over-stream-version' => Lang::t('Версия UDP over stream', 'UDP over stream version'),
            'cipher' => Lang::t('Шифр Shadowsocks', 'Shadowsocks cipher'), 'udp-over-tcp' => 'UDP over TCP', 'udp-over-tcp-version' => Lang::t('Версия UoT', 'UoT version'),
            'transport' => Lang::t('Транспорт', 'Transport'), 'multiplexing' => Lang::t('Мультиплексирование Mieru', 'Mieru multiplexing'),
            'handshake-mode' => Lang::t('Рукопожатие Mieru', 'Mieru handshake'), 'traffic-pattern' => Lang::t('Профиль трафика Mieru', 'Mieru traffic pattern')];
        foreach ($map as $key => $label) if (array_key_exists($key, $node)) $fields[$label] = $node[$key];
        if ($protocol === 'shadowtls') {
            foreach (['version' => Lang::t('Версия ShadowTLS', 'ShadowTLS version'), 'host' => 'TLS SNI', 'password' => Lang::t('Пароль ShadowTLS', 'ShadowTLS password'),
                'fingerprint' => 'TLS fingerprint', 'alpn' => 'ALPN'] as $key => $label) {
                if (isset($node['plugin-opts'][$key])) $fields[$label] = $node['plugin-opts'][$key];
            }
        }
        if ($protocol !== 'mieru') $fields[Lang::t('Проверка TLS-сертификата', 'TLS certificate verification')] = Lang::t('включена', 'on');
        $lines = [Lang::t('Shadowrocket · параметры для ручного ввода', 'Shadowrocket · parameters for manual entry'),
            Lang::t('Это памятка, не импортируемый конфиг. Главная → + → выберите тип и перенесите значения. DNS и правила приложения сохраняются.', 'This is a cheat sheet, not an importable config. Home → + → choose the type and transfer the values. The app\'s DNS and rules stay.'), ''];
        foreach ($fields as $label => $value) $lines[] = $label . ': ' . (is_bool($value) ? ($value ? Lang::t('вкл.', 'on') : Lang::t('выкл.', 'off'))
            : (is_array($value) ? json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) : $value));
        $lines[] = '';
        $lines[] = Lang::t('Обновите Shadowrocket. Поддержка дополнительных параметров зависит от версии; настройки Mihomo/sing-box не всегда имеют аналог в этом приложении.', 'Update Shadowrocket. Support for additional parameters depends on the version; Mihomo/sing-box settings do not always have an equivalent in this app.');
        if ($protocol === 'anytls') $lines[] = Lang::t('AnyTLS поддерживается с 2.2.65. Можно импортировать базовую ссылку anytls:// из предыдущего меню и затем сверить TLS SNI и ALPN.', 'AnyTLS is supported since 2.2.65. You can import the basic anytls:// link from the previous menu and then check TLS SNI and ALPN.');
        if ($protocol === 'mieru') $lines[] = Lang::t('Для Mieru используйте 2.2.90 или новее: в этих версиях добавлены UDP, импорт и профиль трафика. При отказе импорта mierus:// перенесите значения вручную.', 'For Mieru use 2.2.90 or newer: these versions added UDP, import and the traffic pattern. If importing mierus:// fails, transfer the values by hand.');
        if ($protocol === 'tuic') $lines[] = Lang::t('Выберите TUIC v5 с UUID и паролем. При отказе импорта tuic:// перенесите значения вручную.', 'Choose TUIC v5 with UUID and password. If importing tuic:// fails, transfer the values by hand.');
        if ($protocol === 'shadowtls') $lines[] = Lang::t('Пароль Shadowsocks содержит два ключа через двоеточие; скопируйте целиком. В настройках обфускации выберите ShadowTLS v3 и задайте его отдельный пароль и TLS SNI. UDP требует UoT v2; обычный UDP этой связки не работает. При включённом sing-mux совместимость с Shadowrocket не подтверждена.', 'The Shadowsocks password contains two keys separated by a colon; copy it whole. In the obfuscation settings choose ShadowTLS v3 and set its separate password and TLS SNI. UDP needs UoT v2; plain UDP does not work for this pair. With sing-mux on, Shadowrocket compatibility is not confirmed.');
        return implode("\n", $lines);
    }

    public function connectionExports(string $source, string $protocol = '', string $format = ''): void
    {
        if (!$this->admin) return;
        $found = $this->xrayProtocolClient($source);
        if ($found === null) { $this->protocolError($this->t('Пользователь удалён.', 'User deleted.'), '/xray'); return; }
        [$index, $client] = $found;
        $prefix = "/xc $source";
        $labels = ['vless' => ($this->getPacConf()['transport'] ?? '') === 'trojan-grpc' ? 'Trojan (Xray)' : 'VLESS'] + ManagedProtocol::NAMES;
        $back = $protocol === '' ? "/userXr $index" : $prefix;
        try {
            if ($protocol !== '' && !isset($labels[$protocol])) throw new InvalidArgumentException($this->t('Неизвестный протокол.', 'Unknown protocol.'));
            if ($format === 'ios') {
                $text = $this->connectionExport($source, $protocol, 'sr');
                $body = '<pre>' . self::esc($text) . '</pre>';
                if ($this->messageTextLength($body) > 3900) $body = $this->t('Параметры Shadowrocket слишком длинные для сообщения. Скачайте памятку TXT.', 'The Shadowrocket parameters are too long for a message. Download the TXT cheat sheet.');
                $this->update($this->input['chat'], $this->input['message_id'], $body, [
                    [['text' => $this->t('⬇️ Параметры Shadowrocket · TXT', '⬇️ Shadowrocket parameters · TXT'), 'callback_data' => "$prefix $protocol sr"]],
                    [['text' => $this->t('⬇️ Узел Clash/Mihomo · YAML', '⬇️ Clash/Mihomo node · YAML'), 'callback_data' => "$prefix $protocol cl"]],
                    [['text' => $this->i18n('back'), 'callback_data' => "$prefix $protocol"]],
                ]);
                return;
            }
            if ($format !== '') {
                $value = $this->connectionExport($source, $protocol, $format);
                $extension = in_array($format, ['uri', 'sr'], true) ? 'txt' : ($format === 'cl' ? 'yaml' : 'json');
                if ($protocol === 'snolc') $extension = 'zip';
                $body = is_string($value) ? $value : ($format === 'cl' ? yaml_emit($value, YAML_UTF8_ENCODING)
                    : json_encode($value, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR));
                $filename = self::safeFileName($client['email'], 'client') . "-$protocol-$format.$extension";
                $mime = $extension === 'yaml' ? 'application/yaml' : ($extension === 'json' ? 'application/json' : 'text/plain');
                if ($protocol === 'snolc') $mime = 'application/zip';
                $this->protocolOutput = true;
                try { $this->sendFile($this->input['chat'], new CURLStringFile($body, $filename, $mime)); }
                finally { $this->protocolOutput = false; }
                return;
            }
            $text = [$this->t('Отдельные подключения · ', 'Separate connections · ') . self::esc($client['email']),
                $this->t('JSON/YAML содержит только подключение в proxies/outbounds, без DNS, маршрутов, rule-set, TUN и локальных портов. Добавьте эти записи в свою конфигурацию и выберите прокси в её группе или правилах.', 'The JSON/YAML contains only the connection in proxies/outbounds, without DNS, routes, rule-set, TUN or local ports. Add these entries to your configuration and select the proxy in its group or rules.'),
                $this->t('Это файлы для ручного импорта, не подписка. Сохраните файл до следующего нажатия: временные сообщения удаляются.', 'These are files for manual import, not a subscription. Save the file before the next tap: temporary messages are deleted.')];
            if ($protocol === 'snolc') $text = ['snolc SSH + Noise · ' . self::esc($client['email']),
                $this->t('Архив для нативного клиента Linux x86_64 с glibc и Python 3.11+. Внутри профиль, проверенные версии модулей и инструкция запуска. SOCKS5 передаёт TCP и UDP. Сохраните архив до следующего нажатия.', 'An archive for the native Linux x86_64 client with glibc and Python 3.11+. Inside are the profile, tested module versions and launch instructions. SOCKS5 carries TCP and UDP. Save the archive before the next tap.'),
                $this->t('В Mihomo, sing-box и текущий импорт snolcNG этот архив не добавляется.', 'This archive is not added to Mihomo, sing-box or the current snolcNG import.')];
            if ($protocol === 'masque') $text = ['MASQUE · ' . self::esc($client['email']),
                $this->t('Полный профиль для Xray 26.9.30 или новее. Запуск: xray run -config profile.json. Локальный SOCKS5: 127.0.0.1:1080, TCP и UDP. Проверка TLS включена.', 'A full profile for Xray 26.9.30 or newer. Run: xray run -config profile.json. Local SOCKS5: 127.0.0.1:1080, TCP and UDP. TLS verification is on.'),
                $this->t('HTTP/3 использует UDP, HTTP/2 — TCP. Выбор транспорта и UDP-маскировка находятся в настройках MASQUE. После изменений скачайте профиль заново.', 'HTTP/3 uses UDP, HTTP/2 uses TCP. The transport choice and UDP masking are in the MASQUE settings. After changes download the profile again.')];
            $buttons = [];
            if ($protocol === '') {
                foreach ($labels as $key => $label) $buttons[] = [['text' => $label, 'callback_data' => "$prefix $key"]];
            } else {
                $text[] = '<b>' . self::esc($labels[$protocol]) . '</b>';
                $formats = $this->connectionFormats($protocol);
                if (isset($formats['uri'])) {
                    $link = $this->connectionExport($source, $protocol, 'uri');
                    $text[] = $protocol === 'vless'
                        ? $this->t('Ссылка переносит параметры VLESS/Trojan и транспорта. Отдельные настройки DPI и мультиплексирования используйте из JSON/YAML.', 'The link carries the VLESS/Trojan and transport parameters. Take separate DPI and multiplexing settings from the JSON/YAML.')
                        : $this->t('Ссылка переносит базовые параметры подключения. Поддержка URI зависит от клиента; дополнительные настройки, включая fingerprint, импортируйте из JSON/YAML.', 'The link carries the basic connection parameters. URI support depends on the client; import additional settings, including fingerprint, from the JSON/YAML.');
                    $display = '<pre>' . self::esc($link) . '</pre>';
                    $text[] = $this->messageTextLength(implode("\n\n", $text) . "\n\n" . $display) <= 3900
                        ? $display : $this->t('Ссылка слишком длинная для сообщения. Скачайте её целиком кнопкой «Ссылка · TXT».', 'The link is too long for a message. Download it whole with the Link · TXT button.');
                } elseif ($protocol === 'shadowtls') {
                    $text[] = $this->t('ShadowTLS + Shadowsocks: переносимой короткой ссылки для этой связки нет. JSON sing-box содержит обе связанные записи; скопируйте обе. Для Shadowrocket есть отдельная памятка.', 'ShadowTLS + Shadowsocks: there is no portable short link for this pair. The sing-box JSON contains both linked entries; copy both. Shadowrocket has a separate cheat sheet.');
                }
                if ($protocol === 'mieru') $text[] = $this->t('Mieru поддерживается Mihomo и нативным Mieru; обычный sing-box его не поддерживает.', 'Mieru is supported by Mihomo and native Mieru; ordinary sing-box does not support it.');
                if ($protocol === 'vless' && !isset($formats['si'])) $text[] = $this->t('Текущий VLESS несовместим с обычным sing-box. Используйте Xray или Mihomo.', 'The current VLESS is incompatible with ordinary sing-box. Use Xray or Mihomo.');
                foreach ($formats as $key => $label) {
                    $buttons[] = [['text' => $key === 'sr' ? 'Shadowrocket · iOS' : '⬇️ ' . $label,
                        'callback_data' => "$prefix $protocol " . ($key === 'sr' ? 'ios' : $key)]];
                }
            }
            $buttons[] = [['text' => $this->i18n('back'), 'callback_data' => $back]];
            $this->update($this->input['chat'], $this->input['message_id'], implode("\n\n", $text), $buttons);
        } catch (RuntimeException | InvalidArgumentException | JsonException $e) {
            $this->protocolError($e->getMessage(), $back, $protocol === '' ? '' : "$prefix $protocol");
        }
    }
}
