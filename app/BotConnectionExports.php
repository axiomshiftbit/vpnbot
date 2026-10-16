<?php

trait BotConnectionExports
{
    public function connectionFormats(string $protocol): array
    {
        if ($protocol === 'masque') return ['native' => 'MASQUE · полный JSON Xray 26.9.30+'];
        if ($protocol === 'snolc') return ['native' => 'snolc SSH + Noise · ZIP'];
        $formats = ['cl' => 'Mihomo · YAML', 'clj' => 'Mihomo · JSON'];
        if ($protocol !== 'mieru') $formats['si'] = 'sing-box · JSON';
        if ($protocol === 'vless') {
            $formats['s'] = 'Xray · JSON';
            if ($this->subscriptionCompatibilityError($this->getXray(), $this->getPacConf(), 'si') !== ''
                || ($this->getPacConf()['transport'] ?? '') === 'xhttp') unset($formats['si']);
        }
        if ($protocol !== 'shadowtls') $formats['uri'] = 'Ссылка · TXT';
        if ($protocol !== 'vless') $formats['sr'] = 'Shadowrocket · параметры TXT';
        return $formats;
    }

    /** Keep just the connection and its required detours (ShadowTLS, Xray DPI). */
    public static function connectionNodes(array $config, string $type, int $index = 0, string $name = ''): array
    {
        $key = $type === 'cl' ? 'proxies' : 'outbounds'; $tag = $type === 'cl' ? 'name' : 'tag';
        if (!isset($config[$key][$index][$tag])) throw new RuntimeException('Не найдено подключение в шаблоне.');
        $pending = [$config[$key][$index][$tag]]; $nodes = [];
        while ($pending) {
            $next = array_shift($pending);
            if ($type === 'cl' && $next === 'DIRECT' && $nodes) continue;
            if (isset($nodes[$next])) throw new RuntimeException('В шаблоне обнаружена циклическая цепочка подключений.');
            $matches = array_values(array_filter($config[$key], static fn($node) => ($node[$tag] ?? '') === $next));
            if (count($matches) !== 1) throw new RuntimeException('Подключение зависит от отсутствующей или неоднозначной группы/прокси. Используйте полный профиль.');
            $node = $matches[0];
            if (in_array($node['type'] ?? '', ['selector', 'urltest'], true)) throw new RuntimeException('Подключение зависит от группы. Используйте полный профиль.');
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
        if ($found === null) throw new RuntimeException('Пользователь удалён.');
        [$index, $client] = $found;
        if (!isset((['vless' => 'VLESS'] + ManagedProtocol::NAMES)[$protocol])) throw new InvalidArgumentException('Неизвестный протокол.');
        if (!isset($this->connectionFormats($protocol)[$format])) throw new InvalidArgumentException('Формат не поддерживается с текущими настройками. Выберите другой файл.');
        if (!empty($client['off']) || ((int) ($client['time'] ?? 0) > 0 && $client['time'] <= time())
            || ((int) ($client['traffic'] ?? 0) > 0 && $this->xrUserTraffic($this->getXrayStats(), $index)
                + array_sum($this->xrayProtocolUsage($client)) >= (int) $client['traffic'])) {
            throw new RuntimeException('Доступ отключён, истёк или исчерпан.');
        }
        $type = $format === 'clj' ? 'cl' : $format;
        if ($format === 'sr') return self::shadowrocketSettings($protocol, $this->connectionExport($source, $protocol, 'cl')['proxies'][0]);
        if ($protocol === 'vless') {
            if (!$this->protocolModuleEnabled('xray')) throw new RuntimeException('Сервис VLESS выключен.');
            if ($format === 'uri') {
                $link = $this->linkXray($index);
                if ($link === '') throw new RuntimeException('Ссылка недоступна с текущими настройками VLESS.');
                return $link;
            }
            $before = $_GET; $token = $this->subToken;
            try {
                $_GET = ['s' => $this->sidOf($client), 't' => $type]; $this->subToken = [];
                $body = $this->subscription('connection');
                if ($body === '') throw new RuntimeException('Не удалось сформировать подключение. Проверьте совместимость клиента и шаблон.');
                $config = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
            } finally { $_GET = $before; $this->subToken = $token; }
            return self::connectionNodes($config, $type, name: $client['email'] . ' · ' . (($this->getPacConf()['transport'] ?? '') === 'trojan-grpc' ? 'Trojan' : 'VLESS'));
        }
        $this->syncXrayProtocolUsers();
        $store = $this->protocolStore($protocol); $state = $store->read();
        if (!$this->protocolModuleEnabled($protocol) || !$state['enabled']) throw new RuntimeException('Сначала включите сервис этого протокола.');
        if (!$this->protocolPortApplied($protocol, $state)) throw new RuntimeException('Внешний порт ещё не применён. Проверьте Settings → Ports.');
        foreach ($state['users'] as $id => $user) {
            if (($user['xray_source'] ?? '') !== $source || !hash_equals($user['xray_credential'], ManagedProtocol::xrayCredential($client))) continue;
            if ($protocol === 'masque') return $store->profile($id, 'native', $state);
            if ($protocol === 'snolc') return $store->profileDocument($id, 'native', $state)['body'];
            if ($format === 'uri') return $store->connectionUri($id, $state);
            $profile = $store->profile($id, $type === 'cl' ? 'mihomo' : 'singbox', $state);
            return self::connectionNodes($profile, $type, name: $client['email'] . ' · ' . ManagedProtocol::NAMES[$protocol]);
        }
        throw new RuntimeException('Подключение ещё не создано. Повторите после синхронизации сервиса.');
    }

    // Shadowrocket is closed source: export actual connection values for its
    // editor, not a fabricated URI dialect or a replacement routing profile.
    public static function shadowrocketSettings(string $protocol, array $node): string
    {
        $fields = ['Тип' => $protocol === 'shadowtls' ? 'Shadowsocks + ShadowTLS v3' : ManagedProtocol::NAMES[$protocol],
            'Имя' => $node['name'], 'Адрес' => $node['server'], 'Порт' => $node['port']];
        $map = ['password' => 'Пароль', 'uuid' => 'UUID (TUIC v5)', 'username' => 'Имя пользователя',
            'sni' => 'TLS SNI', 'alpn' => 'ALPN', 'client-fingerprint' => 'TLS fingerprint',
            'congestion-controller' => 'Контроль перегрузки', 'udp-relay-mode' => 'Режим UDP',
            'reduce-rtt' => '0-RTT', 'heartbeat-interval' => 'Heartbeat, мс', 'udp' => 'UDP',
            'udp-over-stream' => 'UDP over stream', 'udp-over-stream-version' => 'Версия UDP over stream',
            'cipher' => 'Шифр Shadowsocks', 'udp-over-tcp' => 'UDP over TCP', 'udp-over-tcp-version' => 'Версия UoT',
            'transport' => 'Транспорт', 'multiplexing' => 'Мультиплексирование Mieru',
            'handshake-mode' => 'Рукопожатие Mieru', 'traffic-pattern' => 'Профиль трафика Mieru'];
        foreach ($map as $key => $label) if (array_key_exists($key, $node)) $fields[$label] = $node[$key];
        if ($protocol === 'shadowtls') {
            foreach (['version' => 'Версия ShadowTLS', 'host' => 'TLS SNI', 'password' => 'Пароль ShadowTLS',
                'fingerprint' => 'TLS fingerprint', 'alpn' => 'ALPN'] as $key => $label) {
                if (isset($node['plugin-opts'][$key])) $fields[$label] = $node['plugin-opts'][$key];
            }
        }
        if ($protocol !== 'mieru') $fields['Проверка TLS-сертификата'] = 'включена';
        $lines = ['Shadowrocket · параметры для ручного ввода',
            'Это памятка, не импортируемый конфиг. Главная → + → выберите тип и перенесите значения. DNS и правила приложения сохраняются.', ''];
        foreach ($fields as $label => $value) $lines[] = $label . ': ' . (is_bool($value) ? ($value ? 'вкл.' : 'выкл.')
            : (is_array($value) ? json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) : $value));
        $lines[] = '';
        $lines[] = 'Обновите Shadowrocket. Поддержка дополнительных параметров зависит от версии; настройки Mihomo/sing-box не всегда имеют аналог в этом приложении.';
        if ($protocol === 'anytls') $lines[] = 'AnyTLS поддерживается с 2.2.65. Можно импортировать базовую ссылку anytls:// из предыдущего меню и затем сверить TLS SNI и ALPN.';
        if ($protocol === 'mieru') $lines[] = 'Для Mieru используйте 2.2.90 или новее: в этих версиях добавлены UDP, импорт и профиль трафика. При отказе импорта mierus:// перенесите значения вручную.';
        if ($protocol === 'tuic') $lines[] = 'Выберите TUIC v5 с UUID и паролем. При отказе импорта tuic:// перенесите значения вручную.';
        if ($protocol === 'shadowtls') $lines[] = 'Пароль Shadowsocks содержит два ключа через двоеточие; скопируйте целиком. В настройках обфускации выберите ShadowTLS v3 и задайте его отдельный пароль и TLS SNI. UDP требует UoT v2; обычный UDP этой связки не работает. При включённом sing-mux совместимость с Shadowrocket не подтверждена.';
        return implode("\n", $lines);
    }

    public function connectionExports(string $source, string $protocol = '', string $format = ''): void
    {
        if (!$this->admin) return;
        $found = $this->xrayProtocolClient($source);
        if ($found === null) { $this->protocolError('Пользователь удалён.', '/xray'); return; }
        [$index, $client] = $found;
        $prefix = "/xc $source";
        $labels = ['vless' => ($this->getPacConf()['transport'] ?? '') === 'trojan-grpc' ? 'Trojan (Xray)' : 'VLESS'] + ManagedProtocol::NAMES;
        $back = $protocol === '' ? "/userXr $index" : $prefix;
        try {
            if ($protocol !== '' && !isset($labels[$protocol])) throw new InvalidArgumentException('Неизвестный протокол.');
            if ($format === 'ios') {
                $text = $this->connectionExport($source, $protocol, 'sr');
                $body = '<pre>' . self::esc($text) . '</pre>';
                if ($this->messageTextLength($body) > 3900) $body = 'Параметры Shadowrocket слишком длинные для сообщения. Скачайте памятку TXT.';
                $this->update($this->input['chat'], $this->input['message_id'], $body, [
                    [['text' => '⬇️ Параметры Shadowrocket · TXT', 'callback_data' => "$prefix $protocol sr"]],
                    [['text' => '⬇️ Узел Clash/Mihomo · YAML', 'callback_data' => "$prefix $protocol cl"]],
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
            $text = ['Отдельные подключения · ' . self::esc($client['email']),
                'JSON/YAML содержит только подключение в proxies/outbounds, без DNS, маршрутов, rule-set, TUN и локальных портов. Добавьте эти записи в свою конфигурацию и выберите прокси в её группе или правилах.',
                'Это файлы для ручного импорта, не подписка. Сохраните файл до следующего нажатия: временные сообщения удаляются.'];
            if ($protocol === 'snolc') $text = ['snolc SSH + Noise · ' . self::esc($client['email']),
                'Архив для нативного клиента Linux x86_64 с glibc и Python 3.11+. Внутри профиль, проверенные версии модулей и инструкция запуска. SOCKS5 передаёт TCP и UDP. Сохраните архив до следующего нажатия.',
                'В Mihomo, sing-box и текущий импорт snolcNG этот архив не добавляется.'];
            if ($protocol === 'masque') $text = ['MASQUE · ' . self::esc($client['email']),
                'Полный профиль для Xray 26.9.30 или новее. Запуск: xray run -config profile.json. Локальный SOCKS5: 127.0.0.1:1080, TCP и UDP. Проверка TLS включена.',
                'HTTP/3 использует UDP, HTTP/2 — TCP. Выбор транспорта и UDP-маскировка находятся в настройках MASQUE. После изменений скачайте профиль заново.'];
            $buttons = [];
            if ($protocol === '') {
                foreach ($labels as $key => $label) $buttons[] = [['text' => $label, 'callback_data' => "$prefix $key"]];
            } else {
                $text[] = '<b>' . self::esc($labels[$protocol]) . '</b>';
                $formats = $this->connectionFormats($protocol);
                if (isset($formats['uri'])) {
                    $link = $this->connectionExport($source, $protocol, 'uri');
                    $text[] = $protocol === 'vless'
                        ? 'Ссылка переносит параметры VLESS/Trojan и транспорта. Отдельные настройки DPI и мультиплексирования используйте из JSON/YAML.'
                        : 'Ссылка переносит базовые параметры подключения. Поддержка URI зависит от клиента; дополнительные настройки, включая fingerprint, импортируйте из JSON/YAML.';
                    $display = '<pre>' . self::esc($link) . '</pre>';
                    $text[] = $this->messageTextLength(implode("\n\n", $text) . "\n\n" . $display) <= 3900
                        ? $display : 'Ссылка слишком длинная для сообщения. Скачайте её целиком кнопкой «Ссылка · TXT».';
                } elseif ($protocol === 'shadowtls') {
                    $text[] = 'ShadowTLS + Shadowsocks: переносимой короткой ссылки для этой связки нет. JSON sing-box содержит обе связанные записи; скопируйте обе. Для Shadowrocket есть отдельная памятка.';
                }
                if ($protocol === 'mieru') $text[] = 'Mieru поддерживается Mihomo и нативным Mieru; обычный sing-box его не поддерживает.';
                if ($protocol === 'vless' && !isset($formats['si'])) $text[] = 'Текущий VLESS несовместим с обычным sing-box. Используйте Xray или Mihomo.';
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
