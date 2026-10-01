<?php

trait BotMenuHelp
{
    public function menuHelpButton(string $topic, string $context = ''): array
    {
        return [['text' => $this->i18n('menu help'),
            'callback_data' => '/menuhelp ' . $topic . ' 0' . ($context === '' ? '' : ' ' . $context)]];
    }

    public function menuHelp(string $topic, int $page = 0, string $context = ''): void
    {
        $help = $this->menuHelpContent($topic, $context);
        if (!$help) return;
        [$title, $back, $pages] = $help;
        $titles = array_keys($pages);
        $count = count($pages);
        $page = max(0, min($page, $count));
        if ($count === 1) $page = 1;
        $callback = fn(int $n) => '/menuhelp ' . $topic . ' ' . $n . ($context === '' ? '' : ' ' . $context);
        $text = self::esc($title) . ' → ' . $this->i18n('menu help') . "\n\n";
        $data = [];
        if ($page === 0) {
            $text .= $this->i18n('menu help choose');
            foreach ($titles as $index => $name) $data[] = [['text' => ($index + 1) . '. ' . $name, 'callback_data' => $callback($index + 1)]];
        } else {
            $name = $titles[$page - 1];
            $text .= '<b>' . self::esc($name) . "</b>\n\n" . $pages[$name];
            if ($count > 1) {
                $nav = [];
                if ($page > 1) $nav[] = ['text' => '←', 'callback_data' => $callback($page - 1)];
                $nav[] = ['text' => "$page/$count", 'callback_data' => $callback($page)];
                if ($page < $count) $nav[] = ['text' => '→', 'callback_data' => $callback($page + 1)];
                $data[] = $nav;
                $data[] = [['text' => $this->i18n('menu help topics'), 'callback_data' => $callback(0)]];
            }
        }
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => $back]];
        $this->update($this->input['chat'], $this->input['message_id'], $text, $data);
    }

    // Только справочные тексты и фиксированные маршруты возврата. Просмотр не
    // обращается к ядрам, не сохраняет настройки и не запускает перезагрузки.
    public function menuHelpContent(string $topic, string $context = ''): array
    {
        $ru = $this->language === 'ru';
        $t = static fn(string $ruText, string $enText) => $ru ? $ruText : $enText;
        switch ($topic) {
            case 'telemt_limits':
                if (!preg_match('~^([a-f0-9]{12})\.(\d{1,6})\.(direct|[a-f0-9]{12})$~D', $context, $m)) return [];
                return ['TeleMT → ' . $this->i18n('telemt limits'), "/tuc {$m[1]} {$m[2]} {$m[3]} limits", [
                    $t('Квота: объём и сброс', 'Quota and reset') => $t(
                        "Квота относится к одному имени пользователя и суммирует передачу и приём в MTProxy и WEB. Ядро считает переданные данные прокси, а не весь трафик сетевой карты и не только полезные файлы Telegram.\n\nВведите <code>10</code> для 10 GiB или <code>0,5</code> для половины GiB. <code>0</code> отключает квоту. Новый доступ без ограничений. Первое включение квоты и повторное включение после безлимита начинают расход с нуля. Изменение уже действующей квоты сохраняет расход. Например, израсходовано 7 GiB: повышение с 10 до 20 оставляет 13 GiB; снижение до 5 запрещает дальнейший трафик.\n\nКвота действует до ручного сброса, автоматического месячного обновления нет. «Сбросить расход» после подтверждения начинает новый период, не меняя размер квоты, IP-лимит и ссылки. Расход сохраняется при смене секрета, отключении пользователя и штатном перезапуске. Изменения переподключают всех пользователей TeleMT.",
                        "A quota belongs to one username and combines uploaded and downloaded proxy data over MTProxy and WEB. It is not the entire network interface traffic or only Telegram file sizes.\n\nEnter <code>10</code> for 10 GiB, <code>0.5</code> for half a GiB, or <code>0</code> for unlimited. New users have no limits. Enabling a quota starts usage from zero; changing an active quota preserves usage. With 7 GiB used, increasing 10 to 20 leaves 13 GiB; lowering it to 5 blocks further traffic.\n\nThere is no automatic monthly renewal. Confirmed reset starts a new accounting period and preserves limits and links. Usage survives secret rotation, user disable and graceful restart. Changes reconnect all TeleMT users."),
                    $t('Limit IP: адреса и устройства', 'Limit IP: addresses and devices') => $t(
                        "Считаются одновременно активные исходные IP одного пользователя: режим ядра <code>active_window</code>. Несколько соединений с одного IP занимают одно место. После закрытия последнего соединения с этого IP место освобождается. MTProxy и WEB используют общий лимит. <code>0</code> выключает его.\n\nНапример, при лимите <code>2</code> домашняя сеть и мобильная сеть могут работать одновременно; третьему адресу придётся подождать. Это не счётчик устройств: за одним NAT могут быть несколько телефонов; один телефон может использовать IPv4, IPv6 и менять мобильный адрес. Для начала разумнее 2–3, чем 1.\n\nУ WEB адрес фиксируется при создании сессии: смена сети в уже открытой сессии не обязательно займёт новое место. За MTProxy-relay ядро может видеть IP самого relay. Поэтому Limit IP не гарантирует запрет передачи ссылки другому человеку и не заменяет личные доступы. WEB-relay в боте не реализован.",
                        "The core counts concurrent source IPs per user in <code>active_window</code> mode. Connections from the same IP share one slot; the last connection closing frees it. MTProxy and WEB share the limit. <code>0</code> disables it.\n\nWith <code>2</code>, home and mobile networks can connect together; a third address must wait. NAT can hide many devices behind one IP; one phone can use both IPv4 and IPv6 or change mobile addresses. Start with 2–3 rather than 1.\n\nWEB records the address when a session is created; moving an existing session may not occupy another slot. MTProxy relays may expose only the relay IP. This is not a reliable device or anti-sharing limit. WEB relay is not implemented."),
                    $t('Сохранение и диагностика', 'Persistence and diagnostics') => $t(
                        "Расход сохраняется при штатной остановке TeleMT и в резервной копии бота. Дополнительно примерно раз в секунду записываются изменившиеся счётчики. При аварийном выключении или SIGKILL возможна потеря расхода после последней успешной записи; это не биллинговая система с гарантией каждого байта.\n\nВ меню показаны текущие данные ядра либо явно отмеченная последняя сохранённая запись. «Обновить» перечитывает значения. Если файл расхода пропал или повреждён, бот не запускает пользователей с квотой с нулевым счётчиком автоматически. Восстановите резервную копию. Не удаляйте <code>config/telemt/data</code> при обновлении.\n\nНужен обновлённый образ TeleMT. Control API доступен только внутри контейнера на loopback и остаётся только для чтения. При отказе применения проверьте контейнер и свободное место; интерфейс покажет ошибку.",
                        "Graceful shutdown and bot backups preserve usage. Changed counters are also checkpointed roughly every second. A crash or SIGKILL can lose traffic after the last successful checkpoint; this is not byte-perfect billing.\n\nThe menu shows live data or an explicitly labelled saved checkpoint. Refresh reloads it. Missing or corrupt state does not silently restart quota users with zero usage: restore a backup. Keep <code>config/telemt/data</code> across updates.\n\nAn updated TeleMT image is required. The Control API stays read-only on container loopback. Check container availability and free disk space if applying changes fails."),
                ]];
            case 'telemt':
            case 'telemt_carrier':
            case 'telemt_path':
                return ['TeleMT → WEB', match ($topic) { 'telemt_carrier' => '/telemtWebMode', 'telemt_path' => '/telemtWebPath', default => '/telemtWeb' }, [
                    $t('Как выбрать транспорт', 'Choosing a transport') => $t(
                        "<b>Авто · только HTTPS</b> — сначала <code>https-lanes</code>, затем <code>https</code>. Подходит для совместимых Android, Desktop и iOS.\n\n"
                        . "<b>Авто · HTTPS + WebSocket</b> — полный набор: <code>websocket-lanes → websocket → https-lanes → https</code>. Это не режим «только WebSocket»: HTTPS остаётся запасным вариантом. Ваш прежний «полный (WebSocket)» — именно этот режим.\n\n"
                        . "<b>Без подбора · HTTPS</b> — один общий транспорт <code>https</code>, в том числе для iOS.\n\n"
                        . "<b>Без подбора · HTTPS Lanes</b> — только <code>https-lanes</code>, без запасного HTTPS. Для iOS не подходит.\n\n"
                        . "В меню ✅ отмечен действующий выбор. Настройка общая для всех WEB-пользователей. Ссылки после смены транспорта остаются прежними; активный TeleMT перезапускается, соединения переподключаются.",
                        "<b>Auto · HTTPS only</b>: <code>https-lanes → https</code>. Supports compatible Android, Desktop and iOS clients.\n\n"
                        . "<b>Auto · HTTPS + WebSocket</b>: <code>websocket-lanes → websocket → https-lanes → https</code>. HTTPS remains the fallback; this is the former full (WebSocket) mode.\n\n"
                        . "<b>Fixed · HTTPS</b>: one <code>https</code> transport, including iOS.\n\n"
                        . "<b>Fixed · HTTPS Lanes</b>: only <code>https-lanes</code>, with no fallback; incompatible with iOS.\n\n"
                        . "✅ marks the current choice. The setting applies to all WEB users. Links stay valid. Changing the active mode restarts TeleMT and reconnects sessions."),
                    $t('Подбор и совместимость клиентов', 'Negotiation and client compatibility') => $t(
                        "<b>Carrier</b> — способ передачи MTProto внутри HTTPS/WSS. <code>https</code> использует общий обмен HTTPS; варианты <code>-lanes</code> разделяют логические потоки. WebSocket использует постоянное двустороннее соединение, также поверх TLS.\n\n"
                        . "Подбор происходит при создании сессии: совместимый клиент сообщает свои возможности, а TeleMT выбирает из разрешённых вариантов. После начала передачи транспорт этой сессии уже не переключается; для повторного подбора нужна новая сессия. Обучение может менять предпочтение между рабочими вариантами.\n\n"
                        . "Клиент без метаданных подбора сразу получает фиксированный запасной <code>https</code>. Поэтому в обоих режимах «Авто» совместимый iOS работает через HTTPS, даже если Android использует WebSocket. Для iOS с явными метаданными TeleMT тоже ограничивает выбор HTTPS.\n\n"
                        . "Наличие кнопки не добавляет поддержку WEB самому Telegram. Если приложение не понимает <code>tg://webproxy</code>, используйте обычную MTProxy-ссылку. Автоподбор требует TeleMT 3.5.4+.",
                        "A <b>carrier</b> carries MTProto inside HTTPS/WSS. Lane variants separate logical streams; WebSocket maintains a bidirectional TLS connection.\n\n"
                        . "Negotiation happens when a session starts, using explicit client capabilities. Once real data commits a carrier, that session does not switch transports. Learning may adjust preferences between working candidates.\n\n"
                        . "Clients without negotiation metadata use the fixed HTTPS fallback in either Auto mode. Native iOS with explicit metadata is also restricted to HTTPS. Android can use WebSocket at the same time.\n\n"
                        . "Telegram itself must support WEB. Otherwise use a regular MTProxy link. Negotiation requires TeleMT 3.5.4+."),
                    $t('Свой поддомен, HTTPS и маскировка', 'Your subdomain, HTTPS and cover site') => $t(
                        "1. Скопируйте <b>host</b> из меню WEB. Запись DNS этого имени должна указывать на ваш сервер; бот не создаёт запись у DNS-провайдера.\n"
                        . "2. Включите WEB и выполните <b>Настройки → SSL → renew SSL</b>, чтобы сертификат включал этот поддомен.\n"
                        . "3. Откройте <code>https://ваш-поддомен/</code> в браузере: сертификат должен быть действительным, без предупреждений. Без секрета показывается сайт прикрытия.\n\n"
                        . "WEB использует настоящий HTTPS на порту 443. Чужой домен сюда подставлять нельзя: нужен действительный сертификат для вашего имени. Поле <b>fake-TLS domain</b> в настройках TeleMT относится к обычному MTProxy, а не к WEB.\n\n"
                        . "На сервере страницу прикрытия можно заменить в <code>config/telemt/decoy/index.html</code> внутри каталога VPNBot. Используйте обычную статическую страницу с локальными ресурсами; TeleMT загрузит её после перезапуска. Уже существующий файл бот не заменяет.\n\n"
                        . "HTTPS и сайт прикрытия помогают при проверочных запросах, но не скрывают IP сервера и обычно SNI. Гарантии обхода любого DPI нет.",
                        "1. Copy <b>host</b> from WEB settings and point its DNS record to your server. The bot does not register DNS records.\n"
                        . "2. Enable WEB, then use <b>Settings → SSL → renew SSL</b> to include that host in the certificate.\n"
                        . "3. Open its HTTPS address in a browser and verify the certificate. Requests without a valid secret receive the cover site.\n\n"
                        . "WEB uses real HTTPS on port 443. Use your own hostname with a valid certificate. TeleMT's fake-TLS domain belongs to native MTProxy, not WEB.\n\n"
                        . "Replace <code>config/telemt/decoy/index.html</code> in the VPNBot installation with a normal static page and local assets; restart TeleMT to load it. Existing files are preserved. HTTPS does not hide the server IP or usually SNI, and cannot guarantee DPI evasion."),
                    $t('Ссылки и формат секрета', 'Links and secret format') => $this->i18n('telemt web note') . "\n\n" . $t(
                        "Откройте <b>TeleMT → Пользователи → имя пользователя</b>: в карточке находятся обе ссылки, кнопки MTProxy и WEB, а также их QR-коды. Выбранный relay меняет только MTProxy; WEB подключается напрямую к своему HTTPS-поддомену.\n\n"
                        . "<code>dd</code> и <code>plain</code> — форматы секрета; <code>ee</code>/Fake-TLS для WEB не используется. После смены формата выдайте новые ссылки. Возврат к прежнему формату может снова включить соответствующие старые ссылки; для окончательного отзыва смените секрет пользователя. В WEB включаются первые 32 профиля.",
                        "Open <b>TeleMT → Users → user name</b> for both links, MTProxy and WEB buttons and their QR codes. The selected relay affects only MTProxy; WEB connects directly to its HTTPS hostname.\n\n"
                        . "WEB supports dd and plain secrets, not ee/Fake-TLS. Issue new links after changing the format. Restoring a previous format may reactivate matching old links; rotate the user's secret for permanent revocation. WEB includes the first 32 profiles."),
                    $t('Секретный путь path', 'Secret base path') => $this->i18n('telemt web path note') . "\n\n" . $t(
                        "<b>Сгенерировать новый путь</b> создаёт 16 случайных шестнадцатеричных символов, например <code>/a17b24c39d40e56f/</code>. Бот сам записывает base_path и обновляет ссылки 🌐. При включённом WEB TeleMT перезапускается. Повторная генерация сразу заменяет путь новым.\n\n"
                        . "<b>Использовать корень /</b> убирает префикс. Возврат к прежнему пути или к <code>/</code> может снова сделать действительными соответствующие старые ссылки. Для окончательного отзыва доступа смените секрет пользователя.\n\n"
                        . "Не нужно вручную менять nginx, DNS или сертификат: домен и порт 443 остаются прежними. До проверки поддержки пути в вашем Telegram используйте <code>/</code>.",
                        "<b>Generate a new path</b> creates 16 random hexadecimal characters, saves base_path and updates 🌐 links. Active WEB is restarted. Repeating generation replaces the path directly.\n\n"
                        . "<b>Use root /</b> removes the prefix. Restoring an old path or root may reactivate matching old links. Rotate the user's secret for permanent revocation. No nginx, DNS or certificate changes are needed; the hostname and port stay the same. Use root until client path support is verified."),
                    $t('Диагностика WEB', 'WEB diagnostics') => $this->i18n('telemt web diag note') . "\n\n" . $t(
                        "Диагностика помогает выяснить причину сбоя, но не улучшает маскировку. Для отчёта включите <b>TeleMT → Диагностика → beobachten</b>. Путь и диагностика бриджа требуют TeleMT 3.5.8+.",
                        "Diagnostics explain failures; they do not improve cover. Enable <b>TeleMT → Diagnostics → beobachten</b> for the report. Base paths and bridge diagnostics require TeleMT 3.5.8+."),
                ]];
            case 'telemt_mask':
                return ['TeleMT', '/telemtMasking', [$t('Маскировка MTProxy', 'MTProxy cover') => $this->i18n('telemt masking note') . "\n\n" . $this->i18n('telemt realism') . "\n\n" . $t('Эти настройки относятся к ответам обычного MTProxy на проверочные подключения. WEB использует отдельный поддомен, настоящий HTTPS и свой сайт прикрытия.', 'These settings affect native MTProxy probe responses. WEB uses a separate hostname, real HTTPS and its own cover site.')]];
            case 'dpi':
                return ['Vless → DPI', '/dpiMenu', [
                    $t('Клиентская маскировка', 'Client-side masking') => $this->i18n('dpi hint'),
                    $t('TLS-фрагментация', 'TLS fragmentation') => $this->dpiFieldHint('fragment') . "\n\n" . $this->dpiFieldHint('fragment_maxSplit'),
                    $t('UDP-шум и примеры', 'UDP noise and examples') => $this->dpiFieldHint('noise') . "\n\n" . $this->noiseExamplesHint(),
                ]];
            case 'smux':
                return ['Vless → SMUX', '/smuxMenu', [
                    $t('Назначение и подписки', 'Purpose and subscriptions') => $this->i18n('smux hint') . "\n\n" . $this->i18n('smux link warn') . "\n\n" . $this->i18n('smux sing compatibility'),
                    'half-close' => $this->i18n('smux halfclose hint'),
                    'TCP Brutal' => $this->i18n('smux brutal hint') . "\n\n" . $this->i18n('smux brutal warn'),
                ]];
            case 'finalmask':
                return ['Vless → finalmask', '/finalmaskMenu', [
                    $t('Серверная маскировка', 'Server-side masking') => $this->i18n('finalmask hint') . "\n\n" . $this->i18n('finalmask fragment hint'),
                    $t('UDP-шум, exp и примеры', 'UDP noise, exp and examples') => $this->i18n('finalmask noise hint') . "\n\n" . $this->finalmaskNoiseHint(),
                ]];
            case 'dpi_frag':
            case 'finalmask_frag':
                return ['Vless → ' . $t('Шаблоны фрагментации', 'Fragment presets'), $topic === 'dpi_frag' ? '/dpiFragPresets' : '/finalmaskFragPresets', [$t('Значения шаблонов', 'Preset values') => $this->fragmentPresetsHint()]];
            case 'dpi_noise':
            case 'finalmask_noise':
                return ['Vless → ' . $t('Шаблоны UDP-шума', 'UDP noise presets'), $topic === 'dpi_noise' ? '/dpiNoisePresets' : '/finalmaskNoisePresets', [
                    $t('Формат пакетов и примеры', 'Packet format and examples') => $topic === 'dpi_noise' ? $this->noiseExamplesHint() : $this->finalmaskNoiseHint(),
                    $t('Значения шаблонов', 'Preset values') => $this->noisePresetsHint(),
                ]];
            case 'encryption':
                return ['Vless → Encryption', '/vlessEncryption', [$t('Шифрование и совместимость', 'Encryption and compatibility') => $this->i18n('vless encryption hint') . "\n\n" . $this->i18n('vless encryption singbox')]];
            case 'awg':
                if (!preg_match('~^[01]_-?\d{1,8}$~D', $context)) return [];
                return ['WireGuard → AWG 3', '/awg3 ' . str_replace('_', ' ', $context), [
                    $t('Поля и обновление клиентов', 'Fields and client updates') => $t(
                        'Все поля, кроме HeaderProtectionKey, задаются числом или диапазоном <code>LO-HI</code>; <code>0</code> возвращает значение по умолчанию. После изменения клиенты должны заново скачать конфиги. Header protection требует S1–S4 ≥ ' . self::AWG_HPK_MIN_S . '.',
                        'Fields other than HeaderProtectionKey accept a number or <code>LO-HI</code> range; <code>0</code> restores defaults. Clients must download updated profiles after changes. Header protection requires S1–S4 ≥ ' . self::AWG_HPK_MIN_S . '.'),
                    'RandomTrailers / DisableCookies' => $t(
                        '<b>RandomTrailers</b> добавляет случайный хвост к пакетам; клиент должен использовать то же значение. <b>DisableCookies</b> отключает cookie-reply и штатную защиту WireGuard от потока поддельных запросов подключения. Эти параметры требуют AWG 3.1 на обеих сторонах.',
                        '<b>RandomTrailers</b> adds random packet trailers and requires the same client setting. <b>DisableCookies</b> disables cookie replies and WireGuard flood protection. Both require AWG 3.1 on both ends.'),
                    'mihomo awg3' => $t(
                        'Включает блок AWG 3.0 в подписке Mihomo: <code>amnezia-wg-option</code> и <code>version: 3</code>. Нужен совместимый клиент. Старый клиент может игнорировать эти поля и не подключиться к серверу AWG 3.0.',
                        'Includes <code>amnezia-wg-option</code> and <code>version: 3</code> in Mihomo subscriptions. Older clients may ignore these fields and fail to connect to AWG 3.0.'),
                ]];
            case 'naive_relay':
                if ($context !== '' && !preg_match('~^[\w.-]{1,32}$~D', $context)) return [];
                return ['NaiveProxy → Relay', $context === '' ? '/npRelay' : '/npRelaySub ' . $context, [$t('Адрес, SNI и сертификат', 'Address, SNI and certificate') => $this->i18n('naive relay hint')]];
        }
        if (str_starts_with($topic, 'ps_')) {
            $protocol = substr($topic, 3);
            if (!isset(ManagedProtocol::NAMES[$protocol]) || !preg_match('~^([a-f0-9]{16})\.(direct|[a-f0-9]{16})$~D', $context, $m)) return [];
            $pages = $this->protocolHelpPages($protocol);
            if (!in_array($protocol, ['snolc', 'masque'], true)) {
                $pages['Форматы подписок'] = 'Ссылки в этом меню относятся к отдельному доступу. Общая подписка в меню VLESS сохраняет DNS и маршрутизацию выбранного шаблона, включая TUN. Provider подключает только список прокси к существующему Mihomo / XKeen.'
                    . ($protocol === 'mieru'
                        ? "\n\nНативный Mieru: скачайте JSON и выполните <code>mieru apply config</code>. CLI не обновляет HTTP-подписки автоматически. Для автообновления используйте Mihomo."
                        : "\n\nsing-box JSON отдельного доступа создаёт локальный SOCKS/HTTP на <code>127.0.0.1:1080</code>. Это отличается от полной общей подписки пользователя VLESS.");
            }
            return [ManagedProtocol::NAMES[$protocol] . ' → Подписки', "/ps $protocol {$m[1]} {$m[2]}", $pages];
        }
        if (str_starts_with($topic, 'p_')) {
            $protocol = substr($topic, 2);
            if (!isset(ManagedProtocol::NAMES[$protocol])) return [];
            if ($context === '') $back = '/protocol ' . $protocol;
            elseif (preg_match('~^page_(\d{1,6})$~D', $context, $m)) $back = "/protocol $protocol page {$m[1]}";
            elseif (preg_match('~^[a-f0-9]{16}$~D', $context)) $back = "/protocol $protocol user $context";
            else return [];
            return [ManagedProtocol::NAMES[$protocol], $back, $this->protocolHelpPages($protocol)];
        }
        return [];
    }

    private function protocolHelpPages(string $protocol): array
    {
        // Эти меню протоколов используют русские тексты, как и их карточки.
        $about = match ($protocol) {
            'snolc' => 'Экспериментальный snolc: SSH + Noise на отдельном TCP-порту. UDP приложений передаётся внутри SSH. TLS-сертификат и SNI не требуются. Нативный клиент — Linux x86_64. Импорт SSH-режима в snolcNG пока не поддерживается.',
            'mieru' => 'Mieru использует отдельный порт без TLS. Транспорт TCP/UDP относится к соединению с сервером; оба передают TCP и UDP приложений. В общих подписках бот добавляет Mieru только в Mihomo.',
            'shadowtls' => 'SNI — домен сайта прикрытия с действительным TLS 1.3. Сертификат этого сайта на VPS не устанавливается. Внутренний SS2022 закрыт от внешних подключений. UDP доступен через UoT v2 внутри TCP, если включён соответствующий переключатель.',
            'tuic' => 'TUIC v5 использует UDP-порт. Блокировка UDP прерывает и TCP, и UDP приложений. Проверка TLS включена; нужен действительный сертификат на SNI. После добавления имени обновите SSL в настройках.',
            'masque' => 'MASQUE CONNECT-IP: HTTP/3 по UDP и HTTP/2 по TCP на одном отдельном порту. Клиент — Xray 26.9.30+. Нужен действительный сертификат SNI. Клиенты изолированы; доступ к внутренним адресам запрещён. UDP-маскировка действует только на HTTP/3; HTTP/2 её не использует.',
            default => 'AnyTLS требует действительный сертификат на SNI. При выборе собственного сайта поддомен создаётся в настройках бота, но DNS-запись необходимо направить на сервер самостоятельно. После добавления имени обновите SSL в настройках.',
        };
        $export = match ($protocol) {
            'masque' => 'Скачайте JSON и запустите Xray 26.9.30+: <code>xray run -config profile.json</code>. Локальный SOCKS5: <code>127.0.0.1:1080</code>. После изменения настроек скачайте профиль заново: CLI не обновляет его автоматически.',
            'snolc' => 'Архив содержит профиль, установщик клиента Linux x86_64 и инструкцию. SSH и Noise проверяют ключи сервера; личный ключ управляет доступом. После изменения параметров скачайте архив заново; CLI не обновляет его автоматически.',
            default => '«Полный профиль» — готовый конфиг клиента. «Запись прокси» — блок для раздела <code>proxies</code> существующего Mihomo/XKeen; порты, DNS и правила остаются вашими. Файлы и QR временные: сохраните их до следующего нажатия в меню.',
        };
        return [
            'Протокол и подключение' => $about,
            'Доступы, лимиты и WARP' => 'Новые доступы связаны с пользователями VLESS: срок, выключатель и лимит общие. Профиль находится в карточке пользователя → Отдельные подключения. MASQUE и snolc не включаются в общие подписки старых клиентов.'
                . "\n\nAnyTLS, TUIC и ShadowTLS включаются в полную подписку Mihomo / sing-box; Mieru — только в Mihomo."
                . "\n\nСрок проверяется каждую секунду, расход — каждые 5 секунд. Отзыв завершает соединения этого протокола. Изменение настроек сервера тоже перезапускает его соединения."
                . ($protocol === 'mieru' ? "\n\nСброс общего расхода не сбрасывает историю периодической квоты ядра Mieru." : '')
                . ($protocol === 'snolc' ? '' : "\n\nВыход через WARP передаёт только TCP приложений. UDP отклоняется; при отказе WARP прямой обход не включается."),
            'Профили и подписки' => $export . "\n\nСсылки содержат личный токен доступа: не публикуйте их. «Сменить секрет» отзывает старые ссылки и пароль. Отключение, срок и квота закрывают выдачу профиля и VPN-доступ.",
        ];
    }
}
