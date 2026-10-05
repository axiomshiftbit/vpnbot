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
            case 'tt':
                $back = preg_match('~^[a-zA-Z0-9_.\-]{1,40}$~D', $context) ? '/ttClientMenu ' . $context : '/menu tt';
                return ['TrustTunnel', $back, [
                    $t('Подключение и управление доступом', 'Connection and access') => $t(
                        "Откройте пользователя: ссылка и QR подходят для приложения TrustTunnel, файл TOML — для настройки CLI-клиента через setup_wizard. Оба варианта содержат пароль; передавайте их только владельцу доступа. После смены пароля выдайте новый профиль. Удаление после подтверждения отзывает доступ. Смена реквизитов и перезапуск переподключают остальных пользователей.\n\nСервер принимает HTTP/2 по TCP и HTTP/3 по UDP на указанном внешнем порту. Штатный экспорт использует HTTP/2. HTTP/3 можно выбрать в поддерживающем его клиенте; UDP-порт должен быть доступен. Нужны домен и действующий сертификат. При собственном сертификате используйте выданный ботом профиль с сертификатом, сохраняя проверку TLS.",
                        "Open a user: the link and QR import into the TrustTunnel app; the TOML file configures the CLI client through setup_wizard. Both contain credentials. After changing a password, issue a new profile. Confirmed deletion revokes access. Credential changes and restarts reconnect other users too.\n\nThe endpoint accepts HTTP/2 over TCP and HTTP/3 over UDP on the external port. Standard exports use HTTP/2. Select HTTP/3 in a compatible client with UDP reachable. A hostname and valid certificate are required. For a private certificate, use the exported profile containing it and keep TLS verification enabled."),
                    $t('Сессии, трафик и IP', 'Sessions, traffic and IP') => $t(
                        "🟢 — у пользователя есть активная сессия, ⚪ — сессий нет. 🔑 означает, что данные метрик недоступны; это не доказательство отключения пользователя. «Обновить» заново читает состояние, не перезапуская VPN. В списке показываются 20 пользователей на странице.\n\nВ карточке ↑ — байты, отправленные клиентом через сервер; ↓ — полученные клиентом. Это счётчики ядра с его последнего запуска. Перезапуск, смена реквизитов, выключение контейнера и восстановление с перезапуском обнуляют их. Это не месячная квота и не постоянный учёт для оплаты; резервная копия не сохраняет эти оперативные значения.\n\nСессии не равны числу устройств. Ядро возвращает один IP соединения, а не полный список устройств. За NGINX или relay это может быть адрес промежуточного сервера. Не используйте его как достоверный внешний IP клиента.",
                        "🟢 means an active session, ⚪ no active sessions. 🔑 means metrics are unavailable, not proof that the user is disconnected. Refresh reads status without restarting the VPN. Lists show 20 users per page.\n\n↑ counts bytes uploaded by the client; ↓ counts bytes downloaded. Counters cover the current core process lifetime and reset on restart, credential changes, container shutdown or a restore that restarts the core. They are not a monthly quota or persistent billing records; backups do not preserve these runtime counters.\n\nSessions are not a device count. The core returns one connection IP, not a complete device list. Behind NGINX or a relay it may be the intermediary address, not the client's public IP."),
                    $t('Если статистика недоступна', 'Unavailable statistics') => $t(
                        "Нужен TrustTunnel 1.1.0+ с per_client_metrics. При штатном запуске бот дополняет старый vpn.toml без ручной настройки метрик: адрес 127.0.0.1:1987, per_client_metrics = true. Данные считываются через SSH внутри контейнера; открывать порт снаружи не требуется.\n\nЕсли настройки metrics уже указаны вручную, бот сохраняет их. Для карточек нужен именно локальный адрес 127.0.0.1:1987 и включённый per_client_metrics. После ручной правки перезапустите TrustTunnel и обновите карточку. Недоступный API, старая версия, выключенный модуль или неправильный ответ показываются как «Статистика недоступна», а не как нулевой расход. Метрики содержат имена и IP: не публикуйте этот listener в Интернет.",
                        "Requires TrustTunnel 1.1.0+ with per_client_metrics. Normal startup adds loopback metrics to an older vpn.toml without a manual metrics policy: 127.0.0.1:1987 and per_client_metrics = true. The bot reads them via SSH inside the container; no public port is needed.\n\nExisting manual metrics settings are preserved. Cards require that loopback address and per_client_metrics enabled. Restart TrustTunnel after manual edits, then refresh. API failures, older versions, disabled modules and invalid responses display unavailable rather than zero traffic. Metrics contain usernames and IPs: never expose this listener publicly."),
                ]];
            case 'telemt_main':
                return ['TeleMT', '/telemt', [
                    $t('Статус и два способа подключения', 'Status and connection types') => $t(
                        "TeleMT предоставляет прокси для Telegram. Обычный MTProxy подключается к отдельному TCP-порту; WEB использует ваш HTTPS-поддомен на порту 443. Один пользователь может пользоваться обоими способами с общими квотой и Limit IP. Это не VPN для остальных приложений.\n\n<b>status</b> показывает наличие процесса ядра, а не успешность подключения до Telegram. <b>version</b> — версия образа TeleMT. <b>port</b> — внешний порт MTProxy, задаётся в «Настройки → Порты». WEB включается отдельно в своём меню. Общий выключатель модуля TeleMT находится в меню протоколов; он отключает оба способа подключения.\n\n<b>fast mode</b> в этой сборке включён постоянно: ядро использует прямое подключение к DC Telegram. Переключателя Middle-End в боте нет. Состояния masking и diagnostics означают включённые настройки, а не результат проверки обхода блокировок.",
                        "TeleMT is a Telegram proxy. Native MTProxy uses a separate TCP port; WEB uses your HTTPS hostname on port 443. Both share each user's quota and Limit IP. This is not a VPN for other applications.\n\n<b>status</b> reports the core process, not end-to-end Telegram connectivity. <b>version</b> is the TeleMT image version. <b>port</b> is the external MTProxy port, configured in Settings → Ports. Enable WEB in its own menu. The protocol module switch disables both connection types.\n\n<b>fast mode</b> is always enabled in this setup with direct Telegram DC connections; the bot has no Middle-End switch. Masking and diagnostics states describe settings, not successful block evasion."),
                    $t('Пользователи, ссылки и отзыв доступа', 'Users, links and access revocation') => $t(
                        "В «Пользователи» откройте имя: карточка содержит ссылки и QR для MTProxy и WEB, выключатель доступа, смену секрета, удаление и лимиты. Новые пользователи не имеют квоты или ограничения IP. Справка по ограничениям доступна в карточке → «Квота / Limit IP».\n\nВыключение пользователя закрывает оба способа подключения и сохраняет секрет, лимиты и расход. Повторное включение возвращает доступ по прежним ссылкам, если квота не исчерпана. «Сменить секрет» после подтверждения отзывает старые MTProxy- и WEB-ссылки и QR; выдайте новые. Расход при этом не сбрасывается. Удаление после подтверждения убирает пользователя. Эти действия применяются через перезапуск TeleMT: переподключатся и остальные пользователи.\n\nСсылки и QR содержат данные доступа. Выбранный relay меняет только адрес обычного MTProxy; WEB остаётся прямым. В WEB включаются первые 32 профиля, поэтому при большем числе пользователей проверяйте доступность WEB в карточке.",
                        "Open a user card for MTProxy and WEB links, QR codes, enable/disable, secret rotation, deletion and limits. New users have no quota or IP limit. Detailed limit help is available inside the card.\n\nDisabling a user revokes both connection types while retaining their secret, limits and usage. Re-enabling restores existing links unless the quota is exhausted. Confirmed secret rotation revokes old links and QR codes without resetting usage; distribute the new links. Confirmed deletion removes the user. These changes restart TeleMT and reconnect other users too.\n\nLinks and QR codes contain credentials. A selected relay changes only native MTProxy; WEB remains direct. WEB includes the first 32 profiles, so check individual cards when there are more users."),
                ]];
            case 'telemt_mode':
                return ['TeleMT → ' . $this->i18n('telemt mode'), '/telemtMode', [
                    $t('Classic, Secure и Fake-TLS', 'Classic, Secure and Fake-TLS') => $t(
                        "Режим определяет формат обычного MTProxy, а не WEB. В боте активен один режим.\n\n<b>Classic</b> — базовый MTProto-прокси без TLS-маскировки. Секрет в ссылке без префикса.\n\n<b>Secure</b> — MTProto со случайным дополнением пакетов, секрет с префиксом <code>dd</code>. Название не означает, что сообщения в остальных режимах передаются открытым текстом.\n\n<b>Fake-TLS</b> — значение по умолчанию. Имитирует TLS-подключение к домену прикрытия, секрет с префиксом <code>ee</code> и доменом. Это не обычный HTTPS-сайт и не WEB-прокси.\n\nПосле смены режима ядро перезапускается; заново выдайте MTProxy-ссылки и QR из карточек. Сами пользовательские секреты, квоты и расход сохраняются. Формат секрета WEB (<code>dd/plain</code>) выбирается отдельно в WEB и от этого режима не меняется.",
                        "This selects native MTProxy mode, independently of WEB. One native mode is enabled at a time.\n\n<b>Classic</b>: basic MTProto proxy without TLS cover; no secret prefix.\n\n<b>Secure</b>: randomized packet padding with a <code>dd</code> secret. The name does not mean other modes transmit messages in plaintext.\n\n<b>Fake-TLS</b> is the default: it imitates a TLS connection to the cover hostname, using an <code>ee</code> secret containing the domain. This is not ordinary HTTPS or WEB proxying.\n\nChanging mode restarts the core. Distribute updated MTProxy links and QR codes. User secrets, quotas and usage are preserved. WEB's <code>dd/plain</code> format is configured separately and remains unchanged."),
                ]];
            case 'telemt_sni':
                return ['TeleMT → SNI', '/telemtSni', [
                    $t('Действие при чужом SNI', 'Unknown SNI action') => $t(
                        "SNI — имя сайта, которое клиент передаёт в начале TLS-подключения. Настройка определяет реакцию обычного MTProxy на ClientHello с именем, отличающимся от fake-TLS domain.\n\n<b>reject_handshake</b> — значение по умолчанию: отказ в TLS-рукопожатии, подобный веб-серверу без такого сайта.\n\n<b>mask</b> — передать проверочное подключение на сайт прикрытия, даже если SNI другой. Это меняет поведение при проверках и несовпадении домена; не гарантирует работоспособность любой старой ссылки.\n\n<b>drop</b> — закрыть соединение без TLS-ответа. Такой ответ тоже может быть отличим от обычного веб-сервера.\n\nОставьте reject_handshake, если нет конкретной причины менять. При ошибке Unknown TLS SNI сначала сверяйте домен в текущей MTProxy-ссылке с настройками бота. Изменение перезапускает TeleMT; ссылки не меняются. К сертификату HTTPS-поддомена WEB этот параметр не относится.",
                        "SNI is the hostname sent at the start of a TLS connection. This controls native MTProxy's response to ClientHello with a hostname different from the fake-TLS domain.\n\n<b>reject_handshake</b> is the default: a TLS handshake rejection, like a web server without that hostname.\n\n<b>mask</b> forwards the probe to the cover site despite the different SNI. It changes probe and mismatch handling; it does not guarantee all old links will work.\n\n<b>drop</b> closes without a TLS response, which may itself be distinguishable from a normal web server.\n\nKeep reject_handshake unless there is a specific reason to change it. For Unknown TLS SNI errors, first compare the current link's domain with bot settings. Changing this restarts TeleMT without changing links. It does not control WEB's HTTPS certificate."),
                ]];
            case 'telemt_settings':
                return ['TeleMT → ' . $this->i18n('telemt settings'), '/telemtSettings', [
                    $t('Домен прикрытия и порт', 'Cover hostname and port') => $t(
                        "<b>fake-TLS domain</b> — имя HTTPS-сайта, который TeleMT использует для TLS-маскировки обычного MTProxy. По умолчанию <code>www.google.com</code>; ввод <code>0</code> возвращает это значение. Вводите только домен, без https://, порта и пути. Сайт должен быть доступен с сервера по HTTPS. Бот проверяет формат имени, но это не гарантирует совместимость выбранного сайта.\n\nПосле изменения домена TeleMT перезапускается. Для режима Fake-TLS скачайте новые MTProxy-ссылки и QR: в них включён домен. Секрет пользователя, квота и расход сохраняются. WEB использует собственный поддомен и настоящий сертификат; этот домен прикрытия его не заменяет.\n\n<b>port</b> — внешний TCP-порт MTProxy. Меняется в «Настройки → Порты → TeleMT»; после смены выдайте новые ссылки и проверьте доступность порта извне. WEB использует HTTPS-порт 443 отдельно. <b>fast mode</b> отображается для информации и постоянно включён.",
                        "<b>fake-TLS domain</b> is the HTTPS cover hostname used by native MTProxy. Default: <code>www.google.com</code>; enter <code>0</code> to restore it. Enter only a domain, without scheme, port or path. The site must be reachable over HTTPS from the server. Syntax validation does not guarantee site compatibility.\n\nChanging it restarts TeleMT. In Fake-TLS mode, distribute fresh MTProxy links and QR codes because they embed the hostname. Secrets, quotas and usage remain intact. WEB requires its own hostname and a real certificate, independently of this cover domain.\n\n<b>port</b> is the external native MTProxy TCP port. Change it in Settings → Ports → TeleMT, distribute updated links and verify external reachability. WEB uses HTTPS port 443 separately. <b>fast mode</b> is informational and always enabled."),
                ]];
            case 'telemt_relays':
                return ['TeleMT → ' . $this->i18n('telemt relays'), '/telemtRelays', [
                    $t('Адрес, порт и карта портов', 'Address, port and port map') => $t(
                        "Relay — промежуточный сервер, на который указывает MTProxy-ссылка. Запись в боте только подставляет адрес и порт в ссылку; пересылку TCP с relay до основного TeleMT нужно настроить отдельно. Создание записи не устанавливает ПО и не открывает порты на другом сервере.\n\n<b>Имя</b> — метка записи. <b>Адрес</b> — IP или домен relay; <code>0</code> очищает адрес и убирает запись из выбора подключения.\n\n<b>Порт</b> — внешний порт relay (1–65535). Явно заданный порт имеет приоритет. Если он пуст, используется <b>карта портов</b>: например, <code>8443:443</code> заменит внешний порт TeleMT 8443 на порт relay 443. Без подходящей пары остаётся исходный порт TeleMT. Ввод <code>0</code> очищает порт или карту. Для одного TeleMT обычно достаточно явного порта.\n\nВыберите relay в списке пользователей и выдайте MTProxy-ссылки из карточек. Пользовательский секрет и домен Fake-TLS сохраняются. WEB через этот relay не идёт: его ссылка остаётся прямой. Если relay не сохраняет исходный IP, Limit IP видит адрес relay, а не отдельные устройства.",
                        "A relay is an intermediary named in the MTProxy link. The bot entry only substitutes its address and port; configure TCP forwarding to the main TeleMT server separately. Adding an entry does not install software or open ports on another server.\n\n<b>Name</b> is a label. <b>Address</b> is the relay IP or hostname; <code>0</code> clears it and removes the entry from connection choices.\n\nAn explicit <b>port</b> (1–65535) takes priority. Otherwise the <b>port map</b> is used: <code>8443:443</code> maps native TeleMT port 8443 to relay port 443. Without a matching entry, the original TeleMT port is retained. Enter <code>0</code> to clear the port or map. An explicit port usually suffices.\n\nSelect the relay in the users list and distribute the resulting MTProxy links. Secrets and Fake-TLS domains are retained. WEB stays direct. If the relay does not preserve the source IP, Limit IP sees the relay address instead of individual devices."),
                ]];
            case 'telemt_diagnostics':
                return ['TeleMT → ' . $this->i18n('telemt diagnostics'), '/telemtDiagnostics', [
                    $t('beobachten, retention и JA3/JA4', 'beobachten, retention and JA3/JA4') => $t(
                        "<b>beobachten</b> — наблюдение за TLS-отпечатками входящих подключений; по умолчанию выключено. JA3/JA4 описывают особенности TLS-рукопожатия и помогают сравнивать клиенты и проверочные подключения. Они не являются точным идентификатором устройства и не раскрывают содержимое сообщений Telegram. В наблюдениях могут быть сетевые адреса: учитывайте это при передаче журнала.\n\n<b>retention</b> — окно хранения групп отпечатков в памяти ядра. По умолчанию 10 минут; кнопка перебирает 5, 10, 30, 60, 180, 360, 720, 1440 минут. Это не срок доступа пользователя, период квоты или гарантия удаления строк из файла. Включение beobachten и смена окна перезапускают TeleMT.\n\nКнопка наблюдений показывает конец файла <code>config/telemt/data/beobachten.txt</code>. Если файл пуст, это может означать, что подходящих подключений ещё не было. Само включение диагностики не ускоряет прокси и не улучшает маскировку.",
                        "<b>beobachten</b> observes incoming TLS fingerprints; disabled by default. JA3/JA4 describe handshake characteristics and help compare clients and probes. They are not unique device identities and do not reveal Telegram message contents. Observations may contain network addresses, so consider this before sharing them.\n\n<b>retention</b> is the core's in-memory fingerprint bucket window. Default: 10 minutes. The button cycles 5, 10, 30, 60, 180, 360, 720 and 1440 minutes. This is not a user expiry, quota period or a guarantee of file log deletion. Toggling beobachten or changing retention restarts TeleMT.\n\nThe observations button shows the tail of <code>config/telemt/data/beobachten.txt</code>. An empty file may simply mean no relevant connections have arrived. Diagnostics do not improve speed or cover."),
                    $t('Отчёт и диагностика WEB', 'Report and WEB diagnostics') => $t(
                        "При включённом beobachten доступен отчёт: состояние ядра, трафик, пользователи, маскировка, защитные счётчики и WEB. Для данных используется Control API только для чтения на loopback внутри контейнера; наружу открывать его не требуется. API также нужен для квот и Limit IP, даже при выключенном beobachten.\n\n<b>WEB → Диагностика</b> — отдельная настройка: включает события работы браузерного бриджа, полезные при обрывах и выборе транспорта. В боте записываются события жизненного цикла, а захват заголовков, тела и фреймов выключен. Для просмотра отчёта включите также beobachten. После сбора информации диагностику можно выключить.\n\nОтсутствие событий WEB не доказывает отсутствие клиентов: конкретная сборка Telegram может не отправлять эти сведения. При ошибке сначала проверьте текущую версию ядра, DNS и сертификат WEB, затем статус и отчёт.",
                        "With beobachten enabled, the report shows core health, traffic, users, cover, security counters and WEB. It uses a read-only Control API on container loopback; no public API port is needed. Quotas and Limit IP also need this API, even with beobachten disabled.\n\n<b>WEB → Diagnostics</b> separately enables browser bridge events useful for disconnects and transport selection. The bot enables lifecycle events but disables header, body and frame capture. Enable beobachten as well to view the report. Diagnostics can be disabled after investigation.\n\nMissing WEB events do not prove there are no clients: a Telegram build may not emit them. Check the core version, WEB DNS and certificate, then status and the report."),
                ]];
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
            case 'telemt_method':
            case 'telemt_conveyor':
                $setting = substr($topic, strlen('telemt_'));
                return ['TeleMT → WEB', '/telemtWebHttp ' . $setting, [
                    $this->i18n('telemt web ' . $setting) => $this->i18n('telemt web ' . $setting . ' help'),
                ]];
            case 'telemt':
            case 'telemt_carrier':
            case 'telemt_path':
                return ['TeleMT → WEB', match ($topic) { 'telemt_carrier' => '/telemtWebMode', 'telemt_path' => '/telemtWebPath', default => '/telemtWeb' }, [
                    $t('Как выбрать транспорт', 'Choosing a transport') => $t(
                        "<b>Авто · только HTTPS</b> — сначала <code>https-lanes</code>, затем <code>https</code>. Подходит для совместимых Android, Desktop и iOS.\n\n"
                        . "<b>Авто · HTTPS + WebSocket</b> — полный набор: <code>websocket-lanes → websocket → https-lanes → https</code>. Это не режим «только WebSocket»: HTTPS остаётся запасным вариантом. Ваш прежний «полный (WebSocket)» — именно этот режим.\n\n"
                        . "<b>Без подбора · HTTPS</b> — один общий транспорт <code>https</code>, в том числе для iOS-клиентов с поддержкой WEB.\n\n"
                        . "<b>Без подбора · HTTPS Lanes</b> — только <code>https-lanes</code>, без запасного HTTPS. Для iOS не подходит.\n\n"
                        . "В меню ✅ отмечен действующий выбор. Настройка общая для всех WEB-пользователей. Ссылки после смены транспорта остаются прежними; активный TeleMT перезапускается, соединения переподключаются.",
                        "<b>Auto · HTTPS only</b>: <code>https-lanes → https</code>. Supports compatible Android, Desktop and iOS clients.\n\n"
                        . "<b>Auto · HTTPS + WebSocket</b>: <code>websocket-lanes → websocket → https-lanes → https</code>. HTTPS remains the fallback; this is the former full (WebSocket) mode.\n\n"
                        . "<b>Fixed · HTTPS</b>: one <code>https</code> transport, including iOS clients with WEB support.\n\n"
                        . "<b>Fixed · HTTPS Lanes</b>: only <code>https-lanes</code>, with no fallback; incompatible with iOS.\n\n"
                        . "✅ marks the current choice. The setting applies to all WEB users. Links stay valid. Changing the active mode restarts TeleMT and reconnects sessions."),
                    $t('Подбор и совместимость клиентов', 'Negotiation and client compatibility') => $t(
                        "<b>Carrier</b> — способ передачи MTProto внутри HTTPS/WSS. <code>https</code> использует общий обмен HTTPS; варианты <code>-lanes</code> разделяют логические потоки. WebSocket использует постоянное двустороннее соединение, также поверх TLS.\n\n"
                        . "Подбор происходит при создании сессии: совместимый клиент сообщает свои возможности, а TeleMT выбирает из разрешённых вариантов. После начала передачи транспорт этой сессии уже не переключается; для повторного подбора нужна новая сессия. Обучение может менять предпочтение между рабочими вариантами.\n\n"
                        . "Клиент без метаданных подбора сразу получает фиксированный запасной <code>https</code>. Поэтому в обоих режимах «Авто» совместимый iOS работает через HTTPS, даже если Android использует WebSocket. Для iOS с явными метаданными TeleMT тоже ограничивает выбор HTTPS.\n\n"
                        . "Наличие кнопки не добавляет поддержку WEB самому Telegram. Если приложение не понимает <code>tg://webproxy</code>, используйте обычную MTProxy-ссылку. Автоподбор требует TeleMT 3.5.4+.",
                        "A <b>carrier</b> carries MTProto inside HTTPS/WSS. Lane variants separate logical streams; WebSocket maintains a bidirectional TLS connection.\n\n"
                        . "Negotiation happens when a session starts, using explicit client capabilities. Once real data commits a carrier, that session does not switch transports. Learning may adjust preferences between working candidates.\n\n"
                        . "Clients without negotiation metadata use the fixed HTTPS fallback in either Auto mode. WEB-capable iOS clients with explicit metadata are also restricted to HTTPS. Android can use WebSocket at the same time.\n\n"
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
                    $this->i18n('telemt web method') => $this->i18n('telemt web method help'),
                    $this->i18n('telemt web conveyor') => $this->i18n('telemt web conveyor help'),
                    $t('Telegram для iOS: статус WEB', 'Telegram for iOS: WEB status') => $t(
                        "Проверено 04.10.2026. В репозитории Telegram Desktop описан <a href=\"https://github.com/telegramdesktop/tproxy-server/blob/master/IOS.md\">экспериментальный WEB-клиент для iOS</a> на основе отдельной сборки Telegram. Это подтверждает техническую реализацию, но не выпуск функции в обычном приложении из App Store.\n\nВ <a href=\"https://github.com/TelegramMessenger/Telegram-iOS/blob/6ad963e5b62d354da79040f388ae2b9132fb17b8/submodules/TelegramCore/Sources/SyncCore/SyncCore_ProxySettings.swift\">публичном коде официального iOS-клиента</a> перечислены SOCKS5 и MTProxy; WEB там не обнаружен. Публичный код может отставать от магазинной версии. Подтвердить поддержку WEB в App Store по доступным первичным источникам пока не удалось.\n\nЕсли ваша сборка не распознаёт <code>tg://webproxy</code>, используйте MTProxy-ссылку из карточки пользователя. Если поддержка WEB в конкретной сборке подтверждена, начните с «Без подбора · HTTPS» или «Авто · только HTTPS», POST и пути <code>/</code>. Настройки сервера не добавляют отсутствующую функцию в приложение. Физический iPhone в серверных испытаниях не использовался.",
                        "Checked on 2026-10-04. Telegram Desktop's repository describes an <a href=\"https://github.com/telegramdesktop/tproxy-server/blob/master/IOS.md\">experimental iOS WEB client</a> based on a separate Telegram build. This confirms a technical implementation, not an App Store release.\n\nThe <a href=\"https://github.com/TelegramMessenger/Telegram-iOS/blob/6ad963e5b62d354da79040f388ae2b9132fb17b8/submodules/TelegramCore/Sources/SyncCore/SyncCore_ProxySettings.swift\">public official iOS source</a> lists SOCKS5 and MTProxy, with no WEB type found. Public source can lag store releases. Available primary sources do not yet confirm WEB support in the App Store app.\n\nIf your build does not recognize <code>tg://webproxy</code>, use the user card's MTProxy link. With a confirmed WEB-capable iOS build, start with Fixed HTTPS or Auto HTTPS only, POST and root path <code>/</code>. Server settings cannot add a missing app feature. No physical iPhone was used in server tests."),
                    $t('Диагностика WEB', 'WEB diagnostics') => $this->i18n('telemt web diag note') . "\n\n" . $t(
                        "Диагностика помогает выяснить причину сбоя, но не улучшает маскировку. Для отчёта включите <b>TeleMT → Диагностика → beobachten</b>. Путь и диагностика бриджа требуют TeleMT 3.5.8+.",
                        "Diagnostics explain failures; they do not improve cover. Enable <b>TeleMT → Diagnostics → beobachten</b> for the report. Base paths and bridge diagnostics require TeleMT 3.5.8+."),
                ]];
            case 'telemt_mask':
                return ['TeleMT', '/telemtMasking', [
                    $t('Назначение и значения по умолчанию', 'Purpose and defaults') => $t(
                        "Эти четыре переключателя меняют обработку проверочных подключений на пути к сайту прикрытия обычного MTProxy. Они не фрагментируют трафик авторизованных клиентов и не настраивают WEB: у него отдельный HTTPS-поддомен и своя страница прикрытия. TLS-эмуляция MTProxy уже включена.\n\nПо умолчанию включён только <b>shape hardening</b>; aggressive hardening, above-cap blur и timing normalization выключены. Начните с этого набора. Дополнительные опции изменяют размеры или время проверочного обмена и могут увеличить его трафик или задержку. Гарантии обхода любого DPI нет.\n\nКаждое изменение перезапускает TeleMT и переподключает всех пользователей, включая WEB. Ссылки, секреты и расход сохраняются. Включение aggressive или blur автоматически включает shape hardening; выключение shape hardening отключает оба зависимых параметра. Timing normalization независим.",
                        "These four switches affect native MTProxy probe handling on the cover-site path. They do not fragment authenticated client traffic or configure WEB, which has a separate HTTPS hostname and cover page. MTProxy TLS emulation is already enabled.\n\nOnly <b>shape hardening</b> is enabled by default. Start there; aggressive hardening, above-cap blur and timing normalization are optional and may add probe traffic or delay. No setting guarantees DPI evasion.\n\nChanges restart TeleMT and reconnect all users, including WEB, while preserving links, secrets and usage. Enabling aggressive or blur also enables shape hardening; disabling shape hardening disables both dependent options. Timing normalization is independent."),
                    'shape hardening' => $t(
                        "Дополняет проверочный поток, пересылаемый на сайт прикрытия, до заданных размерных ступеней при штатном завершении. Близкие по длине запросы становятся менее различимыми по размеру. В боте нижняя ступень 512 байт, верхняя 4096 байт.\n\nВключён по умолчанию. В обычном режиме дополнение консервативное: не применяется ко всем вариантам тайм-аута. Цена — небольшой дополнительный исходящий трафик для проверочных запросов. Это не увеличение размера каждого пакета Telegram.",
                        "Pads the forwarded probe stream to size buckets on clean shutdown, making nearby probe sizes less distinguishable. The bot uses a 512-byte floor and a 4096-byte cap.\n\nEnabled by default. Normal mode applies padding conservatively, not to every timeout path. It adds some cover-path egress traffic, not padding to every Telegram packet."),
                    'aggressive hardening' => $t(
                        "Расширяет shape hardening на некоторые незавершённые и истёкшие по тайм-ауту проверочные подключения, если сайт прикрытия ещё не вернул данные. Вместе с above-cap blur добавляет минимум один байт вместо возможного нуля.\n\nПо умолчанию выключен. Делает обработку активных проверок менее консервативной; включайте для сравнения при конкретной проблеме, а не ради обещанного ускорения. Требует shape hardening: бот включит его автоматически.",
                        "Extends shaping to some non-EOF or timed-out probe paths when the cover backend has returned no data. With above-cap blur, it always adds at least one byte.\n\nDisabled by default. This is less conservative probe handling, not a speed feature. Enable to investigate a specific issue. Requires shape hardening, which the bot enables automatically."),
                    'above-cap blur' => $t(
                        "Добавляет случайный хвост к большим проверочным потокам, которые уже превышают верхнюю ступень shape hardening — 4096 байт. В боте хвост до 512 байт: 0–512 обычно, 1–512 при aggressive hardening. Так точная длина крупных проверок становится менее предсказуемой.\n\nПо умолчанию выключен. Увеличивает трафик пути прикрытия в указанных пределах. Требует shape hardening: бот включит его автоматически. Данные авторизованных MTProxy-пользователей этим хвостом не дополняются.",
                        "Adds a random tail to probe streams already above the 4096-byte shaping cap. The bot allows 0–512 extra bytes, or 1–512 with aggressive hardening, making exact oversized probe lengths less predictable.\n\nDisabled by default. Adds bounded cover-path traffic and requires shape hardening, enabled automatically. It does not append this tail to authenticated MTProxy user data."),
                    'timing normalization' => $t(
                        "Сглаживает различия во времени обработки проверочных подключений. Бот задаёт случайную целевую длительность 180–320 мс: быстрый ответ задерживается до выбранной границы. Уже медленное соединение не обрывается на 320 мс.\n\nПо умолчанию выключен. Может затруднить сравнение проверок по времени, но добавляет задержку на пути прикрытия. Не требует shape hardening. Это не регулировка пинга обычных клиентов Telegram.",
                        "Smooths probe timing differences. The bot selects a target duration of 180–320 ms and delays fast outcomes to that target. Already slow connections are not cut off at 320 ms.\n\nDisabled by default. It may make timing comparisons harder at the cost of cover-path delay. Independent of shape hardening; not a latency control for normal Telegram clients."),
                ]];
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
