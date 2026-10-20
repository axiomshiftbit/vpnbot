<?php

$i = [
    'menu help' => [
        'ru' => '📖 Справка',
        'en' => '📖 Help',
    ],
    'menu help topics' => [
        'ru' => '📑 Все темы',
        'en' => '📑 All topics',
    ],
    'menu help choose' => [
        'ru' => 'Выберите тему. Открытие справки не меняет настройки.',
        'en' => 'Choose a topic. Opening help does not change settings.',
    ],
    'preset tap applies' => [
        'ru' => 'Нажатие применяет шаблон. Значения и примеры — в справке.',
        'en' => 'Tap to apply a preset. Values and examples are in Help.',
    ],
    'naive relay short' => [
        'ru' => 'Имя relay должно вести на relay-сервер и входить в TLS-сертификат origin.',
        'en' => 'The relay hostname must point to the relay and be covered by the origin TLS certificate.',
    ],
    'vless encryption refresh' => [
        'ru' => 'После изменения шифрования или ротации ключей все клиенты должны обновить профили.',
        'en' => 'All clients must refresh profiles after changing encryption or rotating keys.',
    ],
    'finalmask udp only' => [
        'ru' => 'UDP-шум действует только на внешний UDP-транспорт. Для VLESS/REALITY по TCP он не работает; MASQUE настраивается отдельно.',
        'en' => 'UDP noise affects only the outer UDP transport. It does not affect VLESS/REALITY over TCP; configure MASQUE separately.',
    ],
    'telemt web transport' => [
        'ru' => 'Транспорт WEB',
        'en' => 'WEB transport',
    ],
    'telemt web path' => [
        'ru' => 'Путь WEB · path',
        'en' => 'WEB path',
    ],
    'telemt web method' => [
        'ru' => 'HTTP-метод',
        'en' => 'HTTP method',
    ],
    'telemt web conveyor' => [
        'ru' => 'Конвейер WEB',
        'en' => 'WEB conveyor',
    ],
    'telemt web conveyor on' => [
        'ru' => 'Включён',
        'en' => 'Enabled',
    ],
    'telemt web conveyor off' => [
        'ru' => 'Выключен',
        'en' => 'Disabled',
    ],
    'telemt web unavailable' => [
        'ru' => 'недоступно',
        'en' => 'unavailable',
    ],
    'telemt web http need version' => [
        'ru' => 'Эта настройка требует TeleMT %s+. Обновите образ и контейнер TeleMT.',
        'en' => 'This setting requires TeleMT %s+. Update the TeleMT image and container.',
    ],
    'telemt web method note' => [
        'ru' => 'POST — стандартный вариант. PUT может улучшить повторное использование HTTP-соединений в Linux WebKitGTK. Настройка действует на передачу и приём через HTTPS и HTTPS-lanes, включая повторы запросов. WebSocket использует прежний GET Upgrade. Ссылки сохраняются; при включённом WEB изменение переподключает всех пользователей TeleMT.',
        'en' => 'POST is the default. PUT may improve HTTP connection reuse in Linux WebKitGTK. Applies to HTTPS and HTTPS-lanes upload, download and retries. WebSocket keeps GET Upgrade. Links stay valid; changing this with WEB enabled reconnects all TeleMT users.',
    ],
    'telemt web conveyor note' => [
        'ru' => 'По умолчанию включён. Совместимый WEB-клиент может отправлять до четырёх HTTP-запросов параллельно; ядро сохраняет порядок данных и распознаёт повторы. Старые клиенты продолжают последовательную передачу. WebSocket не меняется. При проблемах совместимости конвейер можно выключить. Ссылки сохраняются; при включённом WEB изменение переподключает всех пользователей TeleMT.',
        'en' => 'Enabled by default. Compatible WEB clients can send up to four HTTP requests concurrently; the core preserves data order and detects retries. Older clients remain sequential. WebSocket is unchanged. Disable it to troubleshoot compatibility. Links stay valid; changing this with WEB enabled reconnects all TeleMT users.',
    ],
    'telemt web method help' => [
        'ru' => "<b>Что меняется</b>\nСпособ отправки HTTP-запросов между WEB-клиентом и TeleMT: POST или PUT. Он применяется к передаче, приёму и повторным запросам в HTTPS и HTTPS-lanes. Это не смена протокола Telegram, домена или шифрования. Создание сессии и WebSocket-подключения сохраняют прежние методы.\n\n<b>Что выбрать</b>\n<b>POST</b> — значение по умолчанию. Оставьте его, если подключение работает нормально. <b>PUT</b> может помочь Linux-клиентам на WebKitGTK повторно использовать HTTP-соединения и уменьшить затраты на создание новых. На других клиентах улучшение может быть незаметно. Если после выбора PUT соединение ухудшилось, верните POST; промежуточный прокси может ограничивать разрешённые методы. Гарантии ускорения или обхода блокировок нет.\n\n<b>Применение</b>\nНужен образ TeleMT 3.5.12+. Настройка общая для всех WEB-пользователей, включая HTTPS-варианты в Auto. При включённом WEB бот перезапускает всё ядро TeleMT: MTProxy и WEB переподключатся. Ссылки, секреты, квоты и сохранённый расход остаются прежними. При выключенном WEB выбор сохраняется до его включения.",
        'en' => "<b>What changes</b>\nThe HTTP request method between the WEB client and TeleMT: POST or PUT. It applies to HTTPS and HTTPS-lanes upload, download and retries. It does not change Telegram's protocol, hostname or encryption. Session creation and WebSocket connections keep their existing methods.\n\n<b>Which to choose</b>\n<b>POST</b> is the default; keep it when connections work normally. <b>PUT</b> may help Linux clients using WebKitGTK reuse HTTP connections and reduce connection setup overhead. Other clients may see no improvement. Switch back to POST if PUT causes problems; intermediary proxies may restrict HTTP methods. Neither faster transfers nor bypassing blocks is guaranteed.\n\n<b>Applying the change</b>\nRequires TeleMT 3.5.12+. Applies to all WEB users, including HTTPS candidates in Auto mode. With WEB enabled, the bot restarts the entire TeleMT core, reconnecting MTProxy and WEB users. Links, secrets, quotas and saved usage stay unchanged. With WEB disabled, the choice is saved for the next enable.",
    ],
    'telemt web conveyor help' => [
        'ru' => "<b>Что даёт конвейер</b>\nПри последовательной отправке клиент ждёт подтверждения предыдущего HTTP-запроса. Конвейер позволяет совместимому WEB-клиенту держать до четырёх запросов в работе одновременно. Это уменьшает ожидание на соединениях с большой задержкой и может ускорить передачу. Ядро сохраняет порядок данных и распознаёт повторные запросы, чтобы не передавать их полезные данные дважды. Результат зависит от клиента и сети; фиксированного прироста скорости нет.\n\n<b>Что выбрать</b>\nПо умолчанию <b>включён</b>. Поддержка согласуется с клиентом; старые клиенты продолжают последовательную отправку. Параметр действует на HTTPS и HTTPS-lanes, в том числе при Auto, и не меняет WebSocket. Если после обновления появились обрывы или зависания, временно выключите конвейер и сравните поведение на том же транспорте и HTTP-методе. Выключение ограничивает параллельную отправку, а не отключает WEB-прокси.\n\n<b>Применение</b>\nНужен образ TeleMT 3.5.13+. Настройка общая для всех WEB-пользователей. При включённом WEB изменение перезапускает всё ядро TeleMT и переподключает MTProxy и WEB. Ссылки, секреты, квоты и сохранённый расход остаются прежними. При выключенном WEB выбор сохраняется до его включения.",
        'en' => "<b>What the conveyor does</b>\nSequential upload waits for the previous HTTP request to be acknowledged. The conveyor lets compatible WEB clients keep up to four requests in flight. This reduces waiting on high latency connections and may improve throughput. The core preserves data order and recognizes retries so their payload is not delivered twice. Results depend on the client and network; no fixed speed gain is guaranteed.\n\n<b>Which to choose</b>\n<b>Enabled</b> by default. Support is negotiated with the client; older clients keep sequential uploads. Applies to HTTPS and HTTPS-lanes, including Auto candidates, and does not change WebSocket. If an upgrade causes disconnects or stalls, temporarily disable the conveyor and compare using the same transport and HTTP method. Disabling it limits parallel uploads; it does not disable WEB proxying.\n\n<b>Applying the change</b>\nRequires TeleMT 3.5.13+. Applies to all WEB users. With WEB enabled, changing it restarts the entire TeleMT core and reconnects MTProxy and WEB. Links, secrets, quotas and saved usage stay unchanged. With WEB disabled, the choice is saved for the next enable.",
    ],
    'telemt users cards' => [
        'ru' => 'Выберите пользователя: в карточке находятся ссылки MTProxy и WEB, QR и управление доступом.',
        'en' => 'Select a user for MTProxy and WEB links, QR codes and access settings.',
    ],
    'telemt user enable' => [
        'ru' => 'Включить доступ',
        'en' => 'Enable access',
    ],
    'telemt user disable' => [
        'ru' => 'Отключить доступ',
        'en' => 'Disable access',
    ],
    'telemt user disabled' => [
        'ru' => 'Доступ выключен: ссылки сохранены, но подключение запрещено до включения.',
        'en' => 'Access is disabled. Links are preserved but connections are blocked until enabled.',
    ],
    'telemt limits' => ['ru' => '📊 Квота / Limit IP', 'en' => '📊 Quota / Limit IP'],
    'telemt activity none' => ['ru' => '⚪ Данных о подключениях ещё нет: ядро остановлено или не успело ответить.', 'en' => '⚪ No connection data yet: the core is stopped or has not answered.'],
    'telemt activity stale' => ['ru' => 'нет свежих данных от ядра', 'en' => 'no fresh data from the core'],
    'telemt activity traffic' => ['ru' => 'Трафик (приём и передача)', 'en' => 'Traffic (both directions)'],
    'telemt activity since' => ['ru' => 'с', 'en' => 'since'],
    'telemt activity log note' => ['ru' => 'Адреса, с которых подключался пользователь: первое и последнее появление и число подключений. Опрос раз в 20 с, записи хранятся 30 дней.', 'en' => 'Source addresses of this user: first and last sighting and the number of connections. Polled every 20 s, kept for 30 days.'],
    'telemt limits quota' => ['ru' => 'Квота трафика', 'en' => 'Traffic quota'],
    'telemt limits ips' => ['ru' => 'Лимит одновременных IP', 'en' => 'Concurrent IP limit'],
    'telemt limits used' => ['ru' => 'Израсходовано', 'en' => 'Used'],
    'telemt limits active' => ['ru' => 'активных IP', 'en' => 'active IPs'],
    'telemt limits since' => ['ru' => 'Начало учёта', 'en' => 'Accounting since'],
    'telemt limits reset' => ['ru' => 'Сбросить расход', 'en' => 'Reset usage'],
    'telemt limits saved' => ['ru' => '✅ Применено.', 'en' => '✅ Applied.'],
    'telemt limits snapshot' => ['ru' => 'последняя сохранённая запись; текущий расход недоступен', 'en' => 'last saved checkpoint; live usage unavailable'],
    'telemt limits exhausted' => ['ru' => '⛔ Квота исчерпана. Для подключения увеличьте квоту или сбросьте расход.', 'en' => '⛔ Quota exhausted. Increase the quota or reset usage to reconnect.'],
    'telemt limits input quota' => [
        'ru' => 'Введите квоту в GiB: например 10, 100 или 0,5. 1 GiB = 1024³ байт. Допустимо 0–1000000, до 6 знаков после точки/запятой. 0 — безлимит. После включения из безлимита расход начинается с нуля; изменение действующей квоты сохраняет расход.',
        'en' => 'Enter a quota in GiB, e.g. 10, 100 or 0.5. 1 GiB = 1024³ bytes. Range: 0–1000000, up to 6 decimal places. 0 means unlimited. Enabling a quota starts fresh; changing an active quota preserves usage.',
    ],
    'telemt limits input ips' => [
        'ru' => 'Введите целое число 0–1000. 0 — без ограничения IP. Например 2 или 3 для нескольких сетей. Это число одновременных адресов, а не устройств; IPv4 и IPv6 считаются отдельно.',
        'en' => 'Enter an integer from 0 to 1000. 0 disables the IP limit. Try 2 or 3 for multiple networks. This counts concurrent addresses, not devices; IPv4 and IPv6 are separate.',
    ],
    'telemt limits apply note' => [
        'ru' => 'Квота и IP общие для MTProxy + WEB этого пользователя. Применение и сброс переподключают всех пользователей TeleMT.',
        'en' => 'Quota and IP limits are shared by this user’s MTProxy + WEB. Applying changes or resetting usage reconnects all TeleMT users.',
    ],
    'telemt limits reset confirm' => [
        'ru' => 'Начать учёт трафика этого пользователя с нуля? Размер квоты и Limit IP сохранятся. Все соединения TeleMT будут переподключены.',
        'en' => 'Start this user’s traffic accounting from zero? Quota size and Limit IP stay unchanged. All TeleMT connections will reconnect.',
    ],
    'telemt limits invalid' => ['ru' => 'Некорректные настройки лимитов TeleMT.', 'en' => 'Invalid TeleMT limits.'],
    'telemt limits stale' => ['ru' => 'Доступ изменился. Откройте карточку пользователя заново.', 'en' => 'Access has changed. Reopen the user card.'],
    'telemt limits service off' => ['ru' => 'Сначала включите контейнер TeleMT.', 'en' => 'Enable the TeleMT container first.'],
    'telemt limits need image' => ['ru' => 'Для лимитов обновите образ и контейнер TeleMT. Служба сохранения расхода недоступна.', 'en' => 'Update the TeleMT image and container first. The quota persistence helper is unavailable.'],
    'telemt limits stop error' => ['ru' => 'TeleMT не подтвердил штатную остановку и сохранение расхода. Проверьте контейнер и свободное место.', 'en' => 'TeleMT did not confirm graceful shutdown and quota persistence. Check the container and free disk space.'],
    'telemt limits state error' => ['ru' => 'Не удалось безопасно применить или прочитать расход TeleMT. Проверьте контейнер, место на диске и файл data/telemt.limit.json. При утрате файла восстановите резервную копию; расход автоматически не обнуляется.', 'en' => 'Could not safely apply or read TeleMT usage. Check the container, disk space and data/telemt.limit.json. Restore a backup if the file was lost; usage is never silently reset.'],
    'telemt user restart note' => [
        'ru' => 'Изменение доступа перезапускает TeleMT: активные соединения переподключатся.',
        'en' => 'Access changes restart TeleMT; active connections will reconnect.',
    ],
    'telemt user regen' => [
        'ru' => '🔄 Сменить секрет',
        'en' => '🔄 Rotate secret',
    ],
    'telemt user delete' => [
        'ru' => '🗑 Удалить пользователя',
        'en' => '🗑 Delete user',
    ],
    'telemt user confirm regen' => [
        'ru' => 'Будет создан новый секрет. Прежние ссылки MTProxy и WEB этого пользователя перестанут работать. После смены выдайте обе новые ссылки.',
        'en' => 'A new secret will invalidate this user’s MTProxy and WEB links. Issue both new links after rotation.',
    ],
    'telemt user confirm delete' => [
        'ru' => 'Пользователь и его секрет будут удалены. Подключение по его ссылкам MTProxy и WEB станет недоступно.',
        'en' => 'The user and secret will be deleted. Their MTProxy and WEB links will no longer connect.',
    ],
    'telemt web direct only' => [
        'ru' => 'WEB подключается напрямую к своему HTTPS-поддомену; выбранный relay относится только к MTProxy.',
        'en' => 'WEB uses its HTTPS hostname directly; the selected relay applies only to MTProxy.',
    ],
    'telemt qr failed' => [
        'ru' => 'Не удалось создать QR. Используйте ссылку из карточки пользователя.',
        'en' => 'Could not create a QR code. Use the link in the user card.',
    ],
    'telemt web path generate' => [
        'ru' => '🎲 Сгенерировать новый путь',
        'en' => '🎲 Generate a new path',
    ],
    'telemt web path reset' => [
        'ru' => 'Использовать корень /',
        'en' => 'Use root /',
    ],
    'telemt web decoy' => [
        'ru' => 'Сайт-приманка',
        'en' => 'Decoy site',
    ],
    'telemt web decoy builtin' => [
        'ru' => 'встроенная страница',
        'en' => 'built-in page',
    ],
    'telemt web decoy ask' => [
        'ru' => 'Указать адрес',
        'en' => 'Set address',
    ],
    'telemt web decoy setup' => [
        'ru' => 'Запрос к WEB-хосту без секрета получает встроенную страницу. Вместо неё TeleMT может передавать такие запросы на ваш сайт во внутренней сети: <code>http://адрес[:порт]</code>, без пути. Сайт на самом сервере доступен по адресу шлюза <code>10.10.0.1</code>. С TeleMT 3.5.14 вместо IP можно указать имя хоста: оно разрешается при запуске TeleMT и закрепляется до следующего перезапуска.' . "\n\n" . '⚠ Всё, что отвечает по этому адресу, станет доступно из интернета под именем WEB-хоста. Служебные адреса сборки (<code>10.10.x.x</code>, кроме шлюза), loopback и публичные адреса не принимаются. Пока имя хоста не разрешается, TeleMT не запускается целиком — для независимости от DNS указывайте IP. Активный TeleMT перезапускается; ссылки остаются прежними.',
        'en' => 'A request to the WEB host without a secret gets the built-in page. Instead, TeleMT can pass such requests to your site on the internal network: <code>http://address[:port]</code>, no path. A site on the server itself is reachable at the gateway <code>10.10.0.1</code>. Since TeleMT 3.5.14 a host name may replace the IP: it is resolved when TeleMT starts and pinned until the next restart.' . "\n\n" . '⚠ Whatever answers at this address becomes reachable from the internet under the WEB host name. Service addresses of this stack (<code>10.10.x.x</code> except the gateway), loopback and public addresses are refused. While the host name does not resolve, TeleMT does not start at all — use an IP to stay independent of DNS. Active TeleMT restarts; links stay the same.',
    ],
    'telemt web decoy changed' => [
        'ru' => 'Сайт-приманка изменён.',
        'en' => 'Decoy site changed.',
    ],
    'telemt web decoy bad url' => [
        'ru' => 'Нужен адрес вида http://адрес[:порт] без пути, логина и параметров.',
        'en' => 'Expected http://address[:port] without a path, credentials or query.',
    ],
    'telemt web decoy own port' => [
        'ru' => 'Порт 8080 занят WEB-листенером самого TeleMT: такой адрес он отвергает как петлю.',
        'en' => 'Port 8080 belongs to the WEB listener of TeleMT itself: it rejects such an address as a loop.',
    ],
    'telemt web decoy not private' => [
        'ru' => 'Адрес не принят: нужен приватный адрес вне сети сборки (10.10.x.x, кроме шлюза 10.10.0.1), не loopback и не link-local.',
        'en' => 'Address refused: a private address outside the stack network (10.10.x.x except the gateway 10.10.0.1) is required, not loopback or link-local.',
    ],
    'telemt web decoy need version' => [
        'ru' => 'Имя хоста поддерживает TeleMT 3.5.14 и новее. Обновите образ или укажите IP.',
        'en' => 'Host names need TeleMT 3.5.14 or newer. Update the image or use an IP.',
    ],
    'telemt web decoy unchecked' => [
        'ru' => 'Не удалось проверить адрес: контейнер TeleMT недоступен. Настройка не изменена.',
        'en' => 'The address could not be checked: the TeleMT container is unreachable. Nothing was changed.',
    ],
    'telemt web decoy unresolved' => [
        'ru' => 'Имя хоста не разрешается в контейнере TeleMT. Настройка не изменена.',
        'en' => 'The host name does not resolve inside the TeleMT container. Nothing was changed.',
    ],
    'telemt web decoy no answer' => [
        'ru' => 'Адрес не отвечает по HTTP из контейнера TeleMT. Настройка не изменена.',
        'en' => 'The address does not answer HTTP from the TeleMT container. Nothing was changed.',
    ],
    'telemt web decoy redirect' => [
        'ru' => 'Сайт перенаправляет на сам WEB-хост — получилась бы петля. Настройка не изменена.',
        'en' => 'The site redirects to the WEB host itself, which would loop. Nothing was changed.',
    ],
    'telemt web decoy reverted' => [
        'ru' => 'TeleMT не запустился с этим адресом. Возвращена встроенная страница.',
        'en' => 'TeleMT did not start with this address. The built-in page is back.',
    ],
    'telemt web path setup' => [
        'ru' => 'Генерация сама сохраняет случайный путь, применяет его к активному WEB и обновляет ссылки 🌐. Активный TeleMT перезапускается. Раздайте новые ссылки; клиент должен поддерживать WEB с путём. Возврат к / может снова включить прежние корневые ссылки.',
        'en' => 'Generation saves a random path, applies it to active WEB and updates 🌐 links. Active TeleMT restarts. Issue new links; clients must support WEB paths. Returning to / may reactivate previous root links.',
    ],
    'telemt web mode auto-https' => [
        'ru' => 'Авто · только HTTPS',
        'en' => 'Auto · HTTPS only',
    ],
    'telemt web mode auto-full' => [
        'ru' => 'Авто · HTTPS + WebSocket',
        'en' => 'Auto · HTTPS + WebSocket',
    ],
    'telemt web mode https' => [
        'ru' => 'Без подбора · HTTPS',
        'en' => 'Fixed · HTTPS',
    ],
    'telemt web mode https-lanes' => [
        'ru' => 'Без подбора · HTTPS Lanes',
        'en' => 'Fixed · HTTPS Lanes',
    ],
    'telemt web select mode' => [
        'ru' => '✅ — выбранный режим. Для Android + iOS: любой «Авто» или «Без подбора · HTTPS». Нужна версия Telegram с поддержкой WEB. Выбор другого режима перезапускает активный TeleMT; ссылки сохраняются.',
        'en' => '✅ marks the selected mode. For Android + iOS use either Auto mode or Fixed HTTPS. Telegram must support WEB. Changing mode restarts active TeleMT; links stay valid.',
    ],
    'telemt web lanes ios' => [
        'ru' => 'Для iOS-клиента с поддержкой WEB выберите «Авто» или «Без подбора · HTTPS»: фиксированный HTTPS Lanes не подходит. Наличие WEB в App Store пока не подтверждено; подробности в справке.',
        'en' => 'For an iOS client with WEB support, select Auto or Fixed HTTPS instead of Fixed HTTPS Lanes. App Store support is not yet confirmed; see Help.',
    ],
    'backup create failed' => [
        'ru' => '❌ Не удалось создать или отправить резервную копию. Предыдущая копия сохранена. Повторите попытку.',
        'en' => '❌ Could not create or send the backup. The previous backup is preserved. Try again.',
    ],
    'backup restore interrupted' => [
        'ru' => 'Восстановление прервано.',
        'en' => 'Restore interrupted.',
    ],
    'backup restore completed' => [
        'ru' => '✅ Восстановление завершено.',
        'en' => '✅ Restore completed.',
    ],
    'backup restore incomplete' => [
        'ru' => '❌ Восстановление выполнено не полностью. Проверьте ошибки выше. Файл бэкапа сохранён в чате.',
        'en' => '❌ Restore incomplete. Check the errors above. The backup file remains in the chat.',
    ],
    'backup protocol failed' => [
        'ru' => 'Не удалось применить настройки или запустить сервис.',
        'en' => 'Could not apply the settings or start the service.',
    ],
    'backup stage file' => [
        'ru' => 'Не удалось загрузить или прочитать JSON-файл бэкапа.',
        'en' => 'Could not download or read the backup JSON file.',
    ],
    'backup stage telemt' => [
        'ru' => 'Ошибка проверки квот TeleMT в бэкапе.',
        'en' => 'The TeleMT quota snapshot is invalid.',
    ],
    'backup stage trusttunnel' => [
        'ru' => 'Неверный формат настроек TrustTunnel.',
        'en' => 'Invalid TrustTunnel backup format.',
    ],
    'backup stage hysteria' => [
        'ru' => 'Ошибка проверки пользователей Hysteria в бэкапе.',
        'en' => 'The Hysteria user snapshot is invalid.',
    ],
    'backup stage protocols' => [
        'ru' => 'Не удалось восстановить дополнительные протоколы или подготовить их сайт. Причина записана в журнал ошибок PHP.',
        'en' => 'Could not restore managed protocols or prepare their cover site. See the PHP error log.',
    ],
    'backup stage certificates' => [
        'ru' => 'Не удалось записать сертификаты.',
        'en' => 'Could not write the certificates.',
    ],
    'backup stage settings' => [
        'ru' => 'Не удалось сохранить настройки бота.',
        'en' => 'Could not save the bot settings.',
    ],
    'backup stage apply' => [
        'ru' => 'Не все настройки применены. Файл бэкапа сохранён в чате; место ошибки записано в журнал PHP. Повторите восстановление после устранения причины.',
        'en' => 'Some settings were not applied. The backup remains in the chat; the error location is in the PHP log. Retry after fixing the cause.',
    ],
    'update backup failed' => [
        'ru' => 'Не удалось сохранить резервную копию. Обновление отменено; текущие настройки сохранены.',
        'en' => 'Could not save the backup. Update cancelled; current settings are preserved.',
    ],
    'update restore failed' => [
        'ru' => 'Восстановление после обновления не завершено. Резервная копия сохранена в /update/json. Автонастройка домена остановлена.',
        'en' => 'Update recovery did not complete. The backup remains in /update/json. Automatic domain setup has stopped.',
    ],
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
    'ss via warp'          => [
        'en' => 'ss via warp',
        'ru' => 'ss через warp',
    ],
    'ss via warp hint'     => [
        'en' => 'Only TCP of ssserver goes through the WARP SOCKS5: the UDP relay of the core ignores the chain, so QUIC and plain-UDP DNS keep leaving from the server address. If WARP dies, TCP does not fall back to direct — it just stops.',
        'ru' => 'Через SOCKS5 WARP идёт только TCP ssserver: UDP-релей ядра цепочку не знает, поэтому QUIC и DNS по UDP по-прежнему уходят с адреса сервера. Если WARP отвалится, TCP НЕ откатится на direct — он просто перестанет ходить.',
    ],
    'ss warp acl failed'   => [
        'en' => 'The SOCKS access rule was not installed — the wp container is not answering, or its firewall rejected the rule (the chain appears only at the very end of the wp startup). Not switching ss to WARP: without the rule the TCP of every ss client would stop silently. Try again in a minute.',
        'ru' => 'Правило доступа к SOCKS не встало: контейнер wp не отвечает либо его firewall отказал (цепочка появляется только в самом конце старта wp). ss на WARP не переключаю: без правила TCP у всех клиентов ss встал бы молча. Попробуйте через минуту.',
    ],
    'warp is off for ss'   => [
        'en' => 'WARP is not answering — not switching ss to it: without a working proxy the TCP of every ss client stops.',
        'ru' => 'WARP не отвечает — не переключаю ss на него: без рабочего прокси TCP у всех клиентов ss встанет.',
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
    'hy tune' => ['ru' => 'Тонкие настройки', 'en' => 'Fine tuning'],
    'hy tune obfs' => ['ru' => 'salamander превращает пакеты в шум; gecko (экспериментальная, ядро 2.9.2+) дополнительно дробит рукопожатие QUIC. Gecko понимает только официальный клиент Hysteria 2.9.2+; после смены типа всем клиентам нужна новая ссылка.', 'en' => 'salamander scrambles packets; gecko (experimental, core 2.9.2+) also fragments the QUIC handshake. Only the official Hysteria 2.9.2+ client supports gecko; every client needs a new link after switching.'],
    'hy tune cc' => ['ru' => 'Контроллер перегрузки, когда Brutal не задан: bbr, bbr-conservative (мягче к соседям по каналу), bbr-aggressive (напористее на потерях), reno. Настройка серверная, клиентам ничего менять не нужно.', 'en' => 'Congestion controller used without Brutal: bbr, bbr-conservative, bbr-aggressive or reno. Server-side only; clients need no change.'],
    'hy tune loss' => ['ru' => 'Компенсация потерь Brutal', 'en' => 'Brutal loss compensation'],
    'hy tune loss note' => ['ru' => 'При потерях Brutal шлёт быстрее заданной полосы. Выключение иногда делает скорость ровнее. Действует только при заданной полосе (cc: brutal).', 'en' => 'On packet loss Brutal sends faster than the set bandwidth. Turning it off can smooth the speed. Only applies with a bandwidth set.'],
    'hy tune ignorebw' => ['ru' => 'Игнорировать полосу клиента', 'en' => 'Ignore client bandwidth'],
    'hy tune ignorebw note' => ['ru' => 'Сервер не верит полосе, которую заявил клиент, и использует свой контроллер: пользователь не может выпросить себе Brutal в ущерб остальным.', 'en' => 'The server disregards bandwidth hints from clients and uses its own controller, so a user cannot claim Brutal at the expense of others.'],
    'hy tune sniff note' => ['ru' => 'Сервер достаёт домен из HTTP, TLS и QUIC и резолвит его сам через AdGuard: фильтры AdGuard действуют, даже когда клиент прислал готовый IP.', 'en' => 'The server extracts the domain from HTTP, TLS and QUIC and resolves it through AdGuard itself, so AdGuard filtering applies even when the client sent a bare IP.'],
    'hysteria relay hint'  => [
        'en' => 'The link swaps only address+port to the relay (Hysteria address, port and port map from the relay card in the xray menu); password/SNI/obfs stay from origin. The relay must DNAT the hysteria UDP port (and the hopping range, if set) to origin. An explicit relay port overrides the port map and collapses the hopping range in the link to that single port.',
        'ru' => 'Ссылка подменяет только адрес+порт на relay (адрес, порт и маппинг Hysteria — из карточки relay в xray-меню); пароль/SNI/obfs остаются от origin. Relay должен DNAT-ить UDP-порт hysteria (и диапазон hopping, если задан) на origin. Явный порт relay перебивает маппинг и схлопывает диапазон hopping в ссылке в этот единственный порт.',
    ],
    'hysteria relay no link' => [
        'en' => 'no link: set the hysteria password and open the port (or enable port hopping)',
        'ru' => 'ссылки нет: задайте пароль hysteria и откройте порт (или включите port hopping)',
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
    'xray core'            => [
        'en' => 'core',
        'ru' => 'ядро',
    ],
    'xray versions' => [
        'en' => 'Core / version',
        'ru' => 'Ядро / версия',
    ],
    'xray versions hint' => [
        'en' => 'Choose an installed version. Switching restarts Xray and interrupts current connections. The config is checked before stopping the core. Refresh client subscriptions afterwards: REALITY compatibility and SMUX depend on the selected core.',
        'ru' => 'Выберите установленную версию. Переключение перезапускает Xray и прерывает текущие соединения. Конфиг проверяется до остановки ядра. После смены обновите подписки клиентов: совместимость REALITY и SMUX зависит от выбранного ядра.',
    ],
    'xray running' => [
        'en' => 'Running',
        'ru' => 'Работает',
    ],
    'xray version switched' => [
        'en' => 'Xray core switched. Refresh client subscriptions.',
        'ru' => 'Ядро Xray переключено. Обновите подписки клиентов.',
    ],
    'xray version missing' => [
        'en' => 'The selected version is missing from the xr image. Update the image or choose an installed version.',
        'ru' => 'Выбранной версии нет в образе xr. Обновите образ или выберите установленную версию.',
    ],
    'xray version incompatible' => [
        'en' => 'The selected core rejected the config. The previous core is preserved. Check transport and encryption compatibility.',
        'ru' => 'Выбранное ядро не приняло конфиг. Прежнее ядро сохранено. Проверьте совместимость транспорта и шифрования.',
    ],
    'xray start failed' => [
        'en' => 'The selected core did not start. The previous core and config were restored.',
        'ru' => 'Выбранное ядро не запустилось. Прежнее ядро и конфигурация восстановлены.',
    ],
    'xray rollback failed' => [
        'en' => 'Switching failed; recovery could not be confirmed. Check Xray status and logs before retrying.',
        'ru' => 'Переключение не удалось, восстановление не подтверждено. Проверьте состояние и журнал Xray перед повторной попыткой.',
    ],
    'xray switch busy' => [
        'en' => 'Xray settings are being changed. Try again shortly.',
        'ru' => 'Настройки Xray сейчас изменяются. Повторите немного позже.',
    ],
    'smux hint'            => [
        'en' => 'SMUX multiplexes every stream into ONE carrier connection: no TLS handshake per request, one long session instead of hundreds of short ones, less load on the server. Needs the fork core (Jolymmiles/Xray-core) — upstream XTLS only knows its own mux.cool. A broken carrier drops every stream inside it, so keep it off if the link is unstable.',
        'ru' => 'SMUX сводит все потоки в ОДНО несущее соединение: не платим хендшейком за каждый запрос, вместо сотен коротких сессий одна долгая, серверу дешевле. Нужно форк-ядро (Jolymmiles/Xray-core) — апстримный XTLS знает только свой mux.cool. Обрыв несущего коннекта роняет все потоки внутри, так что на нестабильном канале лучше выключить.',
    ],
    'smux enabled' => [
        'en' => 'SMUX enabled. Refresh client profiles.',
        'ru' => 'SMUX включён. Обновите клиентские профили.',
    ],
    'smux disabled' => [
        'en' => 'SMUX disabled. Refresh client profiles.',
        'ru' => 'SMUX выключен. Обновите клиентские профили.',
    ],
    'xdrive intro' => [
        'en' => 'XDRIVE connects through a cloud storage folder: the server opens no port and clients only need to reach the storage. Clients: Xray only. The profile contains the storage credentials — hand it to trusted people only.',
        'ru' => 'XDRIVE — подключение через папку облачного хранилища: сервер не открывает порт, а клиенту нужен доступ только к хранилищу. Клиент — только Xray. В профиле лежит доступ к хранилищу: выдавайте его только своим.',
    ],
    'xdrive inactive' => [
        'en' => 'XDRIVE is enabled but not running: the selected Xray core does not support it, the main inbound is not VLESS, or the keys are missing. See help.',
        'ru' => 'XDRIVE включён, но не работает: выбранное ядро Xray его не поддерживает, основной вход не VLESS или нет ключей. Подробности — в справке.',
    ],
    'xdrive service' => [
        'en' => 'Storage',
        'ru' => 'Хранилище',
    ],
    'xdrive plain http' => [
        'en' => 'The storage address uses http://: the storage password travels unencrypted.',
        'ru' => 'Адрес хранилища начинается с http://: пароль хранилища передаётся открыто.',
    ],
    'xdrive url' => [
        'en' => 'WebDAV address',
        'ru' => 'Адрес WebDAV',
    ],
    'xdrive folder' => [
        'en' => 'Folder',
        'ru' => 'Папка',
    ],
    'xdrive login' => [
        'en' => 'Login',
        'ru' => 'Логин',
    ],
    'xdrive password' => [
        'en' => 'Password',
        'ru' => 'Пароль',
    ],
    'xdrive folder id' => [
        'en' => 'Folder ID',
        'ru' => 'ID папки',
    ],
    'xdrive template' => [
        'en' => 'Template',
        'ru' => 'Шаблон',
    ],
    'xdrive secrets' => [
        'en' => 'Secrets',
        'ru' => 'Секреты',
    ],
    'xdrive poll' => [
        'en' => 'Idle polling',
        'ru' => 'Опрос в простое',
    ],
    'xdrive probe' => [
        'en' => 'Check storage',
        'ru' => 'Проверить хранилище',
    ],
    'xdrive rotate' => [
        'en' => 'New keys',
        'ru' => 'Новые ключи',
    ],
    'xdrive profiles' => [
        'en' => 'Client profiles',
        'ru' => 'Профили клиентов',
    ],
    'xdrive enabled' => [
        'en' => 'XDRIVE enabled. Send the profiles to users.',
        'ru' => 'XDRIVE включён. Раздайте профили пользователям.',
    ],
    'xdrive disabled' => [
        'en' => 'XDRIVE disabled.',
        'ru' => 'XDRIVE выключен.',
    ],
    'xdrive rotate off' => [
        'en' => 'Enable XDRIVE first.',
        'ru' => 'Сначала включите XDRIVE.',
    ],
    'xdrive rotated' => [
        'en' => 'New encryption keys are in effect. Old profiles no longer work — send new ones.',
        'ru' => 'Новые ключи шифрования действуют. Старые профили больше не работают — раздайте новые.',
    ],
    'xdrive probe ok' => [
        'en' => 'The storage works: listing, writing, reading and deleting succeeded.',
        'ru' => 'Хранилище работает: список, запись, чтение и удаление прошли.',
    ],
    'xdrive need url' => [
        'en' => 'Set the WebDAV address, e.g. https://webdav.yandex.ru',
        'ru' => 'Задайте адрес WebDAV, например https://webdav.yandex.ru',
    ],
    'xdrive unresolved'  => [
        'en' => 'The storage address does not resolve right now (DNS). Check the name or try again later.',
        'ru' => 'Адрес хранилища сейчас не разрешается (DNS). Проверьте имя или повторите позже.',
    ],
    'xdrive private url' => [
        'en' => 'The storage address points to a private or local network; an external storage is required.',
        'ru' => 'Адрес хранилища ведёт в частную или локальную сеть; нужно внешнее хранилище.',
    ],
    'xdrive need folder' => [
        'en' => 'Set the folder name: Latin letters, digits, dot, dash, underscore.',
        'ru' => 'Задайте имя папки: латинские буквы, цифры, точка, дефис, подчёркивание.',
    ],
    'xdrive need login' => [
        'en' => 'Set the storage login and password.',
        'ru' => 'Задайте логин и пароль хранилища.',
    ],
    'xdrive need folder id' => [
        'en' => 'Set the Google Drive folder ID (the part of the folder link after /folders/).',
        'ru' => 'Задайте ID папки Google Drive (часть ссылки на папку после /folders/).',
    ],
    'xdrive need google keys' => [
        'en' => 'Set Client ID, Client Secret and Refresh Token.',
        'ru' => 'Задайте Client ID, Client Secret и Refresh Token.',
    ],
    'xdrive need template' => [
        'en' => 'Set a valid template: a JSON object with put, get, delete and list (with namesRegex).',
        'ru' => 'Задайте корректный шаблон: объект JSON с put, get, delete и list (с namesRegex).',
    ],
    'xdrive needs vless' => [
        'en' => 'XDRIVE needs a VLESS main inbound; the current transport uses another protocol.',
        'ru' => 'XDRIVE требует основной вход VLESS; текущий транспорт использует другой протокол.',
    ],
    'xdrive core old' => [
        'en' => 'The selected Xray core does not support XDRIVE. Select the upstream core 26.9.30+ or the fork 26.10.5+.',
        'ru' => 'Выбранное ядро Xray не поддерживает XDRIVE. Выберите оригинальное ядро 26.9.30+ или форк 26.10.5+.',
    ],
    'xdrive keys failed' => [
        'en' => 'Could not generate encryption keys: the xr container did not answer.',
        'ru' => 'Не удалось создать ключи шифрования: контейнер xr не ответил.',
    ],
    'xdrive check failed' => [
        'en' => 'The Xray core rejected the configuration; nothing was changed.',
        'ru' => 'Ядро Xray отклонило конфигурацию; ничего не изменено.',
    ],
    'xdrive save failed' => [
        'en' => 'Could not apply the settings; the previous ones remain.',
        'ru' => 'Не удалось применить настройки; прежние сохранены.',
    ],
    'xdrive probe incomplete' => [
        'en' => 'Fill in the storage settings first.',
        'ru' => 'Сначала заполните настройки хранилища.',
    ],
    'xdrive probe unreachable' => [
        'en' => 'The storage did not answer: check the address and the server\'s Internet access.',
        'ru' => 'Хранилище не ответило: проверьте адрес и доступ сервера в Интернет.',
    ],
    'xdrive probe auth' => [
        'en' => 'The storage rejected the credentials.',
        'ru' => 'Хранилище отклонило учётные данные.',
    ],
    'xdrive probe folder' => [
        'en' => 'The folder was not found in the storage: create it first.',
        'ru' => 'Папка в хранилище не найдена: сначала создайте её.',
    ],
    'xdrive probe denied' => [
        'en' => 'The storage refused the request.',
        'ru' => 'Хранилище отказало в запросе.',
    ],
    'xdrive probe template' => [
        'en' => 'A custom template cannot be checked from the bot; enable XDRIVE and try a client.',
        'ru' => 'Свой шаблон из бота не проверяется; включите XDRIVE и проверьте клиентом.',
    ],
    'xdrive probe write' => [
        'en' => 'The storage does not allow writing to the folder.',
        'ru' => 'Хранилище не даёт записывать в папку.',
    ],
    'xdrive probe read' => [
        'en' => 'A written file could not be read back unchanged.',
        'ru' => 'Записанный файл не удалось прочитать без искажений.',
    ],
    'xdrive probe list' => [
        'en' => 'A written file is missing from the folder listing: the server answers PROPFIND in an unsupported form.',
        'ru' => 'Записанный файл не виден в списке папки: сервер отвечает на PROPFIND в неподдерживаемом виде.',
    ],
    'xdrive probe delete' => [
        'en' => 'The storage does not allow deleting files: the folder would overflow.',
        'ru' => 'Хранилище не даёт удалять файлы: папка переполнится.',
    ],
    'xdrive hint url' => [
        'en' => 'WebDAV address without the folder, e.g. https://webdav.yandex.ru or https://cloud.example.com/remote.php/dav/files/user',
        'ru' => 'Адрес WebDAV без папки, например https://webdav.yandex.ru или https://cloud.example.com/remote.php/dav/files/user',
    ],
    'xdrive hint folder' => [
        'en' => 'WebDAV: the name of an existing empty folder used only for XDRIVE. Google Drive: the folder ID from its link.',
        'ru' => 'WebDAV: имя существующей пустой папки, отведённой только под XDRIVE. Google Drive: ID папки из ссылки на неё.',
    ],
    'xdrive hint template' => [
        'en' => 'Template JSON in one message. Placeholders: {folder}, {name}, {prefix}, {secret0}, {secret1}…',
        'ru' => 'JSON шаблона одним сообщением. Подстановки: {folder}, {name}, {prefix}, {secret0}, {secret1}…',
    ],
    'xdrive hint secrets' => [
        'en' => 'Template secrets, one per line: the first becomes {secret0}, the second {secret1}, and so on. Your message will be deleted.',
        'ru' => 'Секреты шаблона, по одному на строку: первый станет {secret0}, второй — {secret1} и так далее. Сообщение будет удалено.',
    ],
    'xdrive hint poll' => [
        'en' => 'How often an idle server asks the storage for new connections, in ms: 500–10000. Larger values mean fewer requests and a slower first response.',
        'ru' => 'Как часто сервер в простое спрашивает хранилище о новых подключениях, в мс: 500–10000. Больше — меньше запросов и медленнее первый ответ.',
    ],
    'xdrive hint secret' => [
        'en' => 'The value is saved to the bot settings and placed into client profiles. Your message will be deleted.',
        'ru' => 'Значение сохраняется в настройках бота и попадает в профили клиентов. Сообщение будет удалено.',
    ],
    'xdrive profiles hint' => [
        'en' => 'Choose a user: the bot sends a ready Xray config. The file contains the storage credentials and the encryption key.',
        'ru' => 'Выберите пользователя: бот пришлёт готовый конфиг Xray. В файле лежат доступ к хранилищу и ключ шифрования.',
    ],
    'xdrive profile unavailable' => [
        'en' => 'The profile is unavailable: enable and complete XDRIVE first.',
        'ru' => 'Профиль недоступен: сначала включите и настройте XDRIVE.',
    ],
    'xdrive profile caption' => [
        'en' => 'XDRIVE profile for Xray: xray run -c file.json, then SOCKS 127.0.0.1:10808 or HTTP 127.0.0.1:10809. Do not forward it to strangers.',
        'ru' => 'Профиль XDRIVE для Xray: xray run -c файл.json, затем SOCKS 127.0.0.1:10808 или HTTP 127.0.0.1:10809. Не пересылайте посторонним.',
    ],
    'xhttp mux hint' => [
        'en' => 'Mux.Cool (XHTTP): the fork 26.10.5+ carries all TCP streams of an Xray client in one XHTTP session and keeps its idle downlink alive. Only JSON profiles of Xray clients get it; with SMUX enabled SMUX wins. XHTTP already multiplexes requests itself, so enable this only when the number of sessions matters (CDN limits).',
        'ru' => 'Mux.Cool (XHTTP): форк 26.10.5+ ведёт все TCP-потоки клиента Xray одной сессией XHTTP и не даёт её простаивающему каналу оборваться. Блок получают только JSON-профили клиентов Xray; при включённом SMUX действует SMUX. XHTTP и сам мультиплексирует запросы, поэтому включайте только когда важно число сессий (лимиты CDN).',
    ],
    'xhttp mux needs xhttp' => [
        'en' => 'Mux.Cool over XHTTP needs the XHTTP transport.',
        'ru' => 'Mux.Cool поверх XHTTP доступен только с транспортом XHTTP.',
    ],
    'xhttp mux old fork' => [
        'en' => 'The fork core in this xr image is older than 26.10.5 (or xr is unreachable): it drops Mux.Cool TCP sessions over XHTTP. Update the xr image first.',
        'ru' => 'Форк-ядро в образе xr старше 26.10.5 (или xr недоступен): оно рвёт TCP-сессии Mux.Cool поверх XHTTP. Сначала обновите образ xr.',
    ],
    'xhttp mux enabled' => [
        'en' => 'Mux.Cool over XHTTP is on. Xray clients must update their subscription.',
        'ru' => 'Mux.Cool поверх XHTTP включён. Клиентам Xray нужно обновить подписку.',
    ],
    'xhttp mux disabled' => [
        'en' => 'Mux.Cool over XHTTP is off. Xray clients must update their subscription.',
        'ru' => 'Mux.Cool поверх XHTTP выключен. Клиентам Xray нужно обновить подписку.',
    ],
    'smux select fork' => [
        'en' => 'Select the fork (smux) core first to enable SMUX.',
        'ru' => 'Для включения SMUX сначала выберите ядро fork (smux).',
    ],
    'smux apply failed' => [
        'en' => 'Could not apply the settings. Check config access and Xray status, then retry.',
        'ru' => 'Не удалось применить настройки. Проверьте доступ к конфигам и состояние Xray, затем повторите.',
    ],
    'smux fork missing'    => [
        'en' => 'The fork core is not in this image. Update the xr image (or rebuild it) and try again.',
        'ru' => 'Форк-ядра нет в этом образе. Обновите образ xr (или пересоберите его) и повторите.',
    ],
    'smux xr unreachable'  => [
        'en' => 'The xr container did not answer — the core state is unknown. Nothing was changed; check that xray is up and try again.',
        'ru' => 'Контейнер xr не ответил — состояние ядра неизвестно. Ничего не меняли; проверьте, что xray поднят, и повторите.',
    ],
    'smux core mismatch'   => [
        'en' => '⚠️ The core actually running is %s — it does not match the setting. Toggle the core again so the subscriptions and the server agree.',
        'ru' => '⚠️ Реально запущено ядро %s — оно не совпадает с настройкой. Переключите ядро ещё раз, чтобы подписки и сервер сошлись.',
    ],
    'smux sing compatibility' => [
        'en' => 'sing-box subscriptions use Vision/REALITY and Trojan/gRPC without SMUX/H2MUX: multiplexing these transports with the current fork can interrupt traffic. WebSocket, Xray and mihomo keep their multiplex settings.',
        'ru' => 'В подписках sing-box Vision/REALITY и Trojan/gRPC работают без SMUX/H2MUX: мультиплексирование этих транспортов с текущим форком может обрывать трафик. Для WebSocket, Xray и mihomo настройки мультиплексирования сохраняются.',
    ],
    'update write failed' => [
        'en' => 'Could not prepare the update/restart files. Check free space and permissions on the update directory.',
        'ru' => 'Не удалось подготовить файлы обновления/перезапуска. Проверьте свободное место и права на каталог update.',
    ],
    'smux link warn'       => [
        'en' => 'SMUX travels in the json/yaml subscriptions only (v2ray, sing-box, mihomo). A plain vless:// link cannot carry it — import by subscription.',
        'ru' => 'SMUX уезжает только в json/yaml-подписках (v2ray, sing-box, mihomo). Ссылка vless:// его не несёт — импортируйте подпиской.',
    ],
    'smux xhttp warn'      => [
        'en' => '⚠️ The xhttp transport already multiplexes on its own (xmux). Stacking SMUX on top adds a second layer with no gain — extra latency and head-of-line blocking.',
        'ru' => '⚠️ Транспорт xhttp уже мультиплексирует сам (xmux). SMUX поверх — второй слой без выигрыша: лишняя задержка и head-of-line blocking.',
    ],
    'smux halfclose hint'  => [
        'en' => 'Half-close lets an upload finish while the answer keeps coming back: without it an EOF-driven origin waits for the idle timeout and its late reply gets truncated. auto negotiates with the server and silently falls back to the old carrier if it cannot; require refuses that fallback — with an older core on the other side the connection will not come up at all. Needs the fork 26.8.25+ on BOTH ends and travels only in the xray (v2ray json) subscription — sing-box and mihomo have no such key.',
        'ru' => 'Половинное закрытие даёт дослать загрузку и продолжить читать ответ: без него origin, который ждёт EOF, досиживает до таймаута простоя, а его поздний ответ обрезается. auto договаривается с сервером и молча откатывается на прежний несущий коннект, если тот не умеет; require откат запрещает — со старым ядром на той стороне соединение не поднимется вовсе. Нужен форк 26.8.25+ на ОБОИХ концах, уезжает только в xray-подписке (v2ray json) — у sing-box и mihomo такого ключа нет.',
    ],
    'smux halfclose old'   => [
        'en' => '⚠️ The core on the server is older than 26.8.25: it cannot negotiate half-close. require is unavailable, auto just stays on the old carrier. Update (rebuild) the xr image to use it.',
        'ru' => '⚠️ Ядро на сервере старее 26.8.25: договариваться о половинном закрытии оно не умеет. require недоступен, auto останется на прежнем несущем коннекте. Обновите (пересоберите) образ xr.',
    ],
    'smux frame old'       => [
        'en' => '⚠️ The core on the server is older than 26.9.3: it does not know h2muxMaxReadFrameSize and silently ignores it. The carrier keeps the 1 MiB default. Update (rebuild) the xr image to use it.',
        'ru' => '⚠️ Ядро на сервере старее 26.9.3: про h2muxMaxReadFrameSize оно не знает и молча его игнорирует — несущий коннект останется на дефолтном 1 МиБ. Обновите (пересоберите) образ xr.',
    ],
    'smux brutal hint'     => [
        'en' => 'Brutal sends at exactly the configured rate, ignoring loss. Set both ceilings BELOW the real link speed.',
        'ru' => 'Brutal льёт ровно с заданной скоростью, игнорируя потери. Ставьте обе полки НИЖЕ реальной скорости канала.',
    ],
    'smux brutal warn'     => [
        'en' => 'TCP Brutal needs the `brutal` congestion module on the HOST kernel — it is missing, so the option is unavailable. Enabling it without the module tears down the carrier connection.',
        'ru' => 'TCP Brutal требует модуль конгестии `brutal` в ядре ХОСТА — его нет, поэтому опция недоступна. Включение без модуля рвёт несущее соединение.',
    ],
    'smux tpl hint'        => [
        'en' => 'SMUX: put <code>"%s": "~smux~"</code> into the node you want multiplexed — the block is filled in from the SMUX menu. <code>~smux:h2mux~</code> overrides the protocol for this template only. If the core is not the fork, SMUX is off, or a sing-box node uses Vision or Trojan/gRPC, the key is dropped from the subscription.',
        'ru' => 'SMUX: впишите <code>"%s": "~smux~"</code> в нужный узел — блок подставится по настройкам меню SMUX. <code>~smux:h2mux~</code> задаёт протокол только этому шаблону. Если ядро не форк, SMUX выключен либо узел sing-box использует Vision или Trojan/gRPC, ключ из подписки удаляется.',
    ],
    'finalmask hint'       => [
        'en' => 'Server-side masking (Xray-core finalmask, works on BOTH cores — upstream and fork). This is NOT the fragment/noise above: those shape what the CLIENT sends toward the server; this shapes what the SERVER writes back (accept path/replies). Independent toggle, safe to combine with the client-side one.',
        'ru' => 'Серверная маскировка (finalmask самого Xray-core, работает на ОБОИХ ядрах — апстримном и форке). Это НЕ тот fragment/noise, что выше: те режут то, что КЛИЕНТ шлёт серверу; этот — то, что СЕРВЕР пишет обратно (accept-путь/ответы). Независимый тумблер, можно сочетать с клиентским.',
    ],
    'finalmask fragment hint' => [
        'en' => 'Splits the server\'s own TCP writes into pieces. Same packets/length/delay/maxSplit idea as client-side fragment, applied on the accept path instead.',
        'ru' => 'Режет на куски то, что сервер сам пишет в TCP. Те же packets/length/delay/maxSplit, что у клиентского fragment, только на accept-пути.',
    ],
    'finalmask noise hint' => [
        'en' => 'Injects decoy UDP packets from the server before real replies. "reset" sets how often (seconds) the decoy burst may repeat to the same address.',
        'ru' => 'Досылает от сервера поддельные UDP-пакеты перед настоящими ответами. "reset" — через сколько секунд пачку можно повторить на тот же адрес.',
    ],
    'fragment'             => [
        'en' => 'TLS fragment',
        'ru' => 'TLS-фрагментация',
    ],
    'noise'                => [
        'en' => 'UDP noise',
        'ru' => 'UDP-шум',
    ],
    'presets'              => [
        'en' => 'presets',
        'ru' => 'шаблоны',
    ],
    'noise tcp warn'       => [
        'en' => '⚠️ Your transport (%s) runs over TCP — UDP noise is NOT sent over it and masks nothing. For TCP enable TLS fragmentation instead. Noise only helps a UDP transport.',
        'ru' => '⚠️ Ваш транспорт (%s) работает по TCP — UDP-шум по нему НЕ отправляется и ничего не маскирует. Для TCP включите TLS-фрагментацию. noise полезен только для UDP-транспорта.',
    ],
    'xray link file' => [
        'ru' => 'Ссылка (.txt) ⬇️',
        'en' => 'Link (.txt) ⬇️',
    ],
    'xray link file hint' => [
        'ru' => 'Полная ссылка доступна по кнопке «Ссылка (.txt) ⬇️». Импорт и подписки — ниже.',
        'en' => 'The full link is available via “Link (.txt) ⬇️”. Import and subscriptions are below.',
    ],
    'vless encryption hint' => [
        'en' => 'VLESS Encryption adds encryption inside TLS/REALITY. Choose X25519 authentication or post-quantum ML-KEM-768; both use a post-quantum ephemeral key exchange. Modes: native, xorpub, random. Defaults from Xray: 600s tickets, 0-RTT resumption, automatic padding. Changing settings or rotating keys requires all clients to refresh their profiles. REALITY keys stay separate.',
        'ru' => 'VLESS Encryption добавляет шифрование внутри TLS/REALITY. Выберите аутентификацию X25519 или постквантовую ML-KEM-768; обмен временными ключами в обоих случаях постквантовый. Режимы: native, xorpub, random. Параметры Xray: билеты 600 с, возобновление 0-RTT, автоматический padding. После изменения настроек или ротации все клиенты должны обновить профили. Ключи REALITY независимы.',
    ],
    'vless encryption singbox' => [
        'en' => 'VLESS Encryption needs a compatible Xray or mihomo client. Official sing-box 1.14.2 does not support it. Disable Encryption to use sing-box.',
        'ru' => 'VLESS Encryption требует совместимого Xray или mihomo. Официальный sing-box 1.14.2 его не поддерживает. Для sing-box отключите Encryption.',
    ],
    'vless encryption transport' => [
        'en' => 'Select a VLESS transport (REALITY, WebSocket or XHTTP) first. Encryption does not apply to Trojan.',
        'ru' => 'Сначала выберите транспорт VLESS: REALITY, WebSocket или XHTTP. К Trojan это шифрование не применяется.',
    ],
    'vless encryption rotate' => [
        'en' => 'Rotate Encryption keys (refresh all clients)',
        'ru' => 'Сменить ключи Encryption (обновить все клиенты)',
    ],
    'vless encryption updated' => [
        'en' => 'Encryption settings saved. Refresh client profiles.',
        'ru' => 'Настройки Encryption сохранены. Обновите клиентские профили.',
    ],
    'vless encryption unavailable' => [
        'en' => 'Encryption settings do not match the server or the profile is unavailable. Check the VLESS Encryption menu.',
        'ru' => 'Параметры Encryption не совпадают с сервером или профиль недоступен. Проверьте меню VLESS Encryption.',
    ],
    'vless encryption generate failed' => [
        'en' => 'Could not generate a valid key pair. Check that the active Xray core supports vlessenc. Settings were not changed.',
        'ru' => 'Не удалось получить пару ключей. Проверьте поддержку vlessenc активным ядром Xray. Настройки не изменены.',
    ],
    'vless encryption check failed' => [
        'en' => 'Xray rejected the candidate config or is unreachable. Check core compatibility and VLESS fallbacks. Settings were not changed.',
        'ru' => 'Xray не принял новый конфиг или недоступен. Проверьте совместимость ядра и VLESS fallbacks. Настройки не изменены.',
    ],
    'vless encryption save failed' => [
        'en' => 'Could not save Encryption settings. Check config access and retry.',
        'ru' => 'Не удалось сохранить настройки Encryption. Проверьте доступ к конфигам и повторите попытку.',
    ],
    'reality require mlkem' => [
        'en' => 'Require ML-KEM',
        'ru' => 'Требовать ML-KEM',
    ],
    'reality require mlkem hint' => [
        'en' => 'Require ML-KEM (fork 26.10.13+): the REALITY server rejects a ClientHello without the X25519MLKEM768 key share and shows the cover site, as original Xray always does. Turned away: sing-box, mihomo without support-x25519mlkem768, Xray fingerprints ios/edge/qq. Accepted: chrome, firefox, safari.',
        'ru' => 'Требовать ML-KEM (форк 26.10.13+): сервер REALITY отклоняет ClientHello без ключа X25519MLKEM768 и показывает сайт-маску, как всегда делает оригинальный Xray. Не подключатся: sing-box, mihomo без support-x25519mlkem768, отпечатки Xray ios/edge/qq. Подключатся: chrome, firefox, safari.',
    ],
    'reality mlkem origin always' => [
        'en' => 'Original Xray core: REALITY always requires X25519MLKEM768 (not configurable). The fork core lets you choose.',
        'ru' => 'Оригинальное ядро Xray: REALITY всегда требует X25519MLKEM768 (не настраивается). Выбор есть у форк-ядра.',
    ],
    'reality mlkem select fork' => [
        'en' => 'Select the fork core first: the original core always requires ML-KEM.',
        'ru' => 'Сначала выберите форк-ядро: оригинальное и так всегда требует ML-KEM.',
    ],
    'reality mlkem old fork' => [
        'en' => 'The fork core in this xr image is older than 26.10.13 (or xr is unreachable) and ignores this setting. Update the xr image first.',
        'ru' => 'Форк-ядро в образе xr старше 26.10.13 (или xr недоступен) и не знает этой настройки. Сначала обновите образ xr.',
    ],
    'reality singbox mlkem' => [
        'en' => 'This REALITY core requires X25519MLKEM768; official sing-box 1.14.2 removes it from ClientHello. Use Xray/mihomo, a compatible server core (the fork 26.10.5+ accepts sing-box), or WebSocket/TLS or Trojan/gRPC.',
        'ru' => 'Это ядро REALITY требует X25519MLKEM768; официальный sing-box 1.14.2 удаляет его из ClientHello. Используйте Xray/mihomo, совместимое серверное ядро (форк 26.10.5+ принимает sing-box) либо WebSocket/TLS или Trojan/gRPC.',
    ],
    'xhttp singbox warn'   => [
        'en' => '⚠️ XHTTP is an Xray transport: stock sing-box has no such transport type and will reject the config. Use v2rayNG / v2rayN / mihomo, or a sing-box build with XHTTP support.',
        'ru' => '⚠️ XHTTP — транспорт Xray: в обычном sing-box такого типа нет, конфиг он не примет. Используйте v2rayNG / v2rayN / mihomo либо сборку sing-box с поддержкой XHTTP.',
    ],
    'sniffing'             => [
        'en' => 'Sniffing',
        'ru' => 'Сниффинг',
    ],
    'mldsa'                => [
        'en' => 'Reality ML-DSA-65',
        'ru' => 'Reality ML-DSA-65',
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
    'relay port'           => [
        'en' => 'relay port',
        'ru' => 'порт relay',
    ],
    'enter relay port'     => [
        'en' => 'enter relay port 1-65535 (overrides the port map), 0 to clear',
        'ru' => 'введите порт relay 1-65535 (перебивает маппинг портов), 0 — очистить',
    ],
    'enter relay name'     => [
        'en' => 'enter relay name (letters, digits, - . _)',
        'ru' => 'введите имя relay (буквы, цифры, - . _)',
    ],
    'enter relay address'  => [
        'en' => 'enter relay address (domain or IP), 0 to clear',
        'ru' => 'введите адрес relay (домен или IP), 0 — очистить',
    ],
    'enter relay port map' => [
        'en' => 'enter port map src:dst,src:dst (e.g. 443:8443), 0 to clear',
        'ru' => 'введите маппинг портов src:dst,src:dst (напр. 443:8443), 0 — очистить',
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
        'en' => 'enter WG/AWG relay address (domain or IP), 0 to clear',
        'ru' => 'введите адрес relay для WG/AWG (домен или IP), 0 — очистить',
    ],
    'enter relay awg port map' => [
        'en' => 'enter WG/AWG port map src:dst,src:dst (e.g. 51820:443), 0 to clear',
        'ru' => 'введите маппинг портов WG/AWG src:dst,src:dst (напр. 51820:443), 0 — очистить',
    ],
    'direct'               => [
        'en' => 'direct',
        'ru' => 'напрямую',
    ],
    'wg relay hint'        => [
        'en' => 'Relay swaps only the Endpoint of generated configs/QR to the WG/AWG relay address (ports via the WG/AWG port map); keys/DNS stay from origin. The relay must DNAT the WG UDP port to origin. Already imported client configs keep their old Endpoint until re-imported.',
        'ru' => 'Relay подменяет только Endpoint генерируемых конфигов/QR на адрес relay для WG/AWG (порты через маппинг WG/AWG); ключи/DNS остаются от origin. Relay должен DNAT-ить UDP-порт WG на origin. Уже импортированные клиентами конфиги сохраняют старый Endpoint до переимпорта.',
    ],
    'relay hy address'     => [
        'en' => 'Hysteria relay address',
        'ru' => 'адрес relay для Hysteria',
    ],
    'enter relay hy address' => [
        'en' => 'enter Hysteria relay address (domain or IP), 0 to clear',
        'ru' => 'введите адрес relay для Hysteria (домен или IP), 0 — очистить',
    ],
    'relay hy port map'    => [
        'en' => 'Hysteria port map (src:dst)',
        'ru' => 'маппинг портов Hysteria (src:dst)',
    ],
    'enter relay hy port map' => [
        'en' => 'enter Hysteria port map src:dst,src:dst (e.g. 36712:443), 0 to clear',
        'ru' => 'введите маппинг портов Hysteria src:dst,src:dst (напр. 36712:443), 0 — очистить',
    ],
    'relay hy port'        => [
        'en' => 'Hysteria relay port',
        'ru' => 'порт relay для Hysteria',
    ],
    'enter relay hy port'  => [
        'en' => 'enter the single Hysteria relay UDP port 1-65535 (overrides the port map and the hopping range in the link), 0 to clear',
        'ru' => 'введите единственный UDP-порт relay для Hysteria 1-65535 (перебивает маппинг портов и диапазон hopping в ссылке), 0 — очистить',
    ],
    'relay np address'     => [
        'en' => 'NaiveProxy relay address',
        'ru' => 'адрес relay для NaiveProxy',
    ],
    'enter relay np address' => [
        'en' => 'enter NaiveProxy relay address — a domain covered by the origin certificate, 0 to clear',
        'ru' => 'введите адрес relay для NaiveProxy — домен, входящий в сертификат origin, 0 — очистить',
    ],
    'relay np port'        => [
        'en' => 'NaiveProxy relay port',
        'ru' => 'порт relay для NaiveProxy',
    ],
    'enter relay np port'  => [
        'en' => 'enter NaiveProxy relay port 1-65535 (empty = 443), 0 to clear',
        'ru' => 'введите порт relay для NaiveProxy 1-65535 (пусто = 443), 0 — очистить',
    ],
    'naive relay hint'     => [
        'en' => 'The link swaps only address+port to the relay; login/password stay from origin and TLS terminates on origin via DNAT. IMPORTANT: the naive client takes the SNI from the link host and validates the certificate against it, so the relay address must be a DOMAIN present in the origin certificate (add it as a domain alias and renew SSL) with an A record pointing at the relay. A bare IP will fail certificate validation. The SNI route on the origin (upstream nginx) is added by the bot itself when the address is set — that host then goes wholly to naive, so cloak/DoH on it stop working.',
        'ru' => 'Ссылка подменяет только адрес+порт на relay; логин/пароль остаются от origin, TLS терминируется на origin через DNAT. ВАЖНО: клиент naive берёт SNI из хоста ссылки и по нему проверяет сертификат, поэтому адрес relay должен быть ДОМЕНОМ, входящим в сертификат origin (добавьте его алиасом домена и обновите SSL), с A-записью на relay. С голым IP проверка сертификата упадёт. SNI-маршрут на origin (upstream nginx) бот добавляет сам при задании адреса — этот хост целиком уходит в naive, поэтому cloak/DoH на нём работать перестанут.',
    ],
    'naive relay sni skipped' => [
        'en' => 'the address is saved, but no SNI route was added on the origin: only a domain other than the main one works (clients send no SNI for a bare IP) — the link through this relay will land on the cloak site instead of the proxy',
        'ru' => 'адрес сохранён, но SNI-маршрут на origin не добавлен: годится только домен, отличный от основного (по голому IP клиент SNI не шлёт) — ссылка через этот relay попадёт на cloak-сайт вместо прокси',
    ],
    'naive no link'        => [
        'en' => 'no link: set the NaiveProxy login and password first',
        'ru' => 'ссылки нет: сначала задайте логин и пароль NaiveProxy',
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
    'dedupe'               => [
        'en' => 'merge duplicates',
        'ru' => 'схлопнуть дубли',
    ],
    'duplicates skipped'   => [
        'en' => 'duplicates skipped',
        'ru' => 'дубли пропущены',
    ],
    'duplicates merged'    => [
        'en' => 'duplicates merged',
        'ru' => 'дубли объединены',
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
    'torrent wg on' => [
        'en' => 'BitTorrent signature blocking enabled. Encrypted traffic is not guaranteed to be detected.',
        'ru' => 'Блокировка сигнатур BitTorrent включена. Обнаружение зашифрованного трафика не гарантируется.',
    ],
    'torrent wg off' => [
        'en' => 'BitTorrent signature blocking disabled.',
        'ru' => 'Блокировка сигнатур BitTorrent выключена.',
    ],
    'torrent wg incomplete' => [
        'en' => 'Torrent blocking is requested, but not all ipp2p rules are active. Check the block_torrent log and the host kernel headers / xtables-addons-dkms. String rules alone provide partial coverage.',
        'ru' => 'Блокировка торрентов выбрана, но не все правила ipp2p действуют. Проверьте журнал block_torrent и заголовки ядра / xtables-addons-dkms на хосте. Одни строковые правила дают лишь частичную защиту.',
    ],
    'torrent xray on'  => [
        'en' => 'torrents blocked for xray clients',
        'ru' => 'торренты для клиентов xray блокируются',
    ],
    'torrent xray off'  => [
        'en' => 'torrents allowed for xray clients',
        'ru' => 'торренты для клиентов xray разрешены',
    ],
    'torrent xray hint'  => [
        'en' => 'Fork core: caught via sniffing — handshake, uTP, DHT, UDP trackers. MSE-encrypted peers and HTTPS trackers stay invisible.',
        'ru' => 'Форк-ядро: ловится через sniffing — handshake, uTP, DHT, UDP-трекеры. MSE-шифрование и HTTPS-трекеры не видны.',
    ],
    'torrent xray hint origin'  => [
        'en' => 'Upstream core: caught via sniffing — handshake and uTP (since 26.9.8). DHT and UDP trackers need the fork core; MSE-encrypted peers and HTTPS trackers stay invisible on both.',
        'ru' => 'Апстрим-ядро: ловится через sniffing — handshake и uTP (с 26.9.8). DHT и UDP-трекеры видит только форк-ядро; MSE-шифрование и HTTPS-трекеры не видны ни на одном.',
    ],
    'torrent xray hint origin old'  => [
        'en' => '⚠️ The upstream core on the server is older than 26.9.8: only the TCP handshake is caught, its uTP sniffer never fires. Rebuild the xr image (or switch to the fork core) for uTP.',
        'ru' => '⚠️ Апстрим-ядро на сервере старее 26.9.8: ловится только TCP-handshake, его uTP-сниффер не срабатывает ни разу. Для uTP пересоберите образ xr (или переключитесь на форк-ядро).',
    ],
    'torrent xray hint fork old'  => [
        'en' => '⚠️ The fork core on the server is older than 26.8.21: only the TCP handshake is caught — uTP, DHT and UDP trackers still go through the upstream sniffer, which never fires. Rebuild the xr image.',
        'ru' => '⚠️ Форк-ядро на сервере старее 26.8.21: ловится только TCP-handshake — uTP, DHT и UDP-трекеры идут через апстримный сниффер, который не срабатывает ни разу. Пересоберите образ xr.',
    ],
    'torrent needs sniffing'  => [
        'en' => 'Rule will never match: turn sniffing on (DPI masking) and metadataOnly off — without them the core does not detect the protocol.',
        'ru' => 'Правило не сработает: включите sniffing (DPI-маскировка) и выключите metadataOnly — без них ядро не определяет протокол.',
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
        'en' => 'subnet list',
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
    'telemt web'  => [
        'en' => 'WEB proxy',
        'ru' => 'WEB-прокси',
    ],
    'telemt web note'  => [
        'en' => 'WEB carries MTProto inside HTTPS on its own subdomain (port 443, no port in the link). Use a Telegram build supporting WEB: import the link in Desktop connection settings or open it in compatible Android. For iOS, an experimental implementation exists; availability in the App Store app is not confirmed. See Help for details. Clients without WEB support use regular tg://proxy links.',
        'ru' => 'WEB несёт MTProto внутри HTTPS на своём поддомене (порт 443, в ссылке порта нет). Нужна сборка Telegram с поддержкой WEB: импортируйте ссылку в настройках соединения Desktop или откройте в совместимом Android. Для iOS существует экспериментальная реализация; наличие WEB в приложении из App Store пока не подтверждено. Подробности — в справке. Клиентам без WEB нужны обычные ссылки tg://proxy.',
    ],
    'telemt web link'  => [
        'en' => 'WEB link for compatible Telegram clients',
        'ru' => 'ссылка WEB для совместимых клиентов Telegram',
    ],
    'telemt web cert hint'  => [
        'en' => 'the WEB host needs its own SAN in the certificate: run "renew SSL" once after enabling, otherwise Telegram (Desktop, Android) refuses the connection',
        'ru' => 'хосту WEB нужен свой SAN в сертификате: после включения один раз выполните "renew SSL", иначе Telegram (Desktop, Android) не откроет соединение',
    ],
    'telemt web blocked'  => [
        'en' => 'WEB requirements are not met',
        'ru' => 'условия для WEB не выполнены',
    ],
    'telemt web need domain'  => [
        'en' => 'set a domain first (Settings -> domain): WEB needs a hostname of its own',
        'ru' => 'сначала задайте домен (настройки -> domain): WEB нужен собственный хостнейм',
    ],
    'telemt web need cert'  => [
        'en' => 'install a certificate first (Settings -> SSL): Telegram validates it',
        'ru' => 'сначала установите сертификат (настройки -> SSL): Telegram его проверяет',
    ],
    'telemt web need ip'  => [
        'en' => 'the server IP is unknown (env IP is empty): WEB needs a concrete public address',
        'ru' => 'IP сервера неизвестен (переменная IP пуста): WEB нужен конкретный публичный адрес',
    ],
    'telemt web secret changed'  => [
        'en' => 'WEB secret format changed. Issue links from user cards. Rotate the user secret for permanent revocation.',
        'ru' => 'Формат WEB-секрета изменён. Выдайте ссылки из карточек пользователей. Для окончательного отзыва доступа смените секрет пользователя.',
    ],
    'telemt web need version'  => [
        'en' => 'the running telemt is older than 3.5.0 — it ignores the WEB config entirely, so the links would be handed out with nothing serving them. Update the telemt image.',
        'ru' => 'запущенный telemt старше 3.5.0 — он целиком игнорирует WEB-конфиг, и ссылки окажутся выданы, а обслуживать их некому. Обновите образ telemt.',
    ],
    'telemt web need users'  => [
        'en' => 'add at least one user',
        'ru' => 'заведите хотя бы одного пользователя',
    ],
    'telemt web profiles capped'  => [
        'en' => 'only the first 32 users get a WEB profile — that is the telemt limit, and exceeding it stops the proxy from starting at all',
        'ru' => 'профиль WEB получают только первые 32 пользователя — это лимит telemt, а его превышение не даёт прокси стартовать вовсе',
    ],
    'telemt web negotiation'  => [
        'en' => 'carrier negotiation',
        'ru' => 'подбор carrier',
    ],
    'telemt web negotiation off'  => [
        'en' => 'off',
        'ru' => 'выкл',
    ],
    'telemt web negotiation https'  => [
        'en' => 'HTTPS only',
        'ru' => 'только HTTPS',
    ],
    'telemt web negotiation full'  => [
        'en' => 'full (WebSocket)',
        'ru' => 'полный (WebSocket)',
    ],
    'telemt web negotiation note'  => [
        'en' => 'with negotiation on, Telegram Desktop and Android try the carriers in order and settles on the first one that works, so a network that blocks one transport no longer breaks WEB. The last carrier is the fallback: it stays https, the only one clients without negotiation metadata (Telegram iOS) support. Needs telemt 3.5.4+.',
        'ru' => 'при включённом подборе Telegram Desktop и Android перебирают carrier по порядку и остаётся на первом заработавшем — сеть, которая режет один транспорт, больше не ломает WEB. Последний carrier запасной: он остаётся https, единственный поддерживаемый клиентами без метаданных подбора (Telegram iOS). Нужен telemt 3.5.4+.',
    ],
    'telemt web negotiation need version'  => [
        'en' => 'the running telemt is older than 3.5.4 — it silently ignores the carrier list, so the menu would show negotiation that is not actually happening. Update the telemt image.',
        'ru' => 'запущенный telemt старше 3.5.4 — он молча игнорирует список carrier, и меню показывало бы подбор, которого на деле нет. Обновите образ telemt.',
    ],
    'telemt web 358 need version'  => [
        'en' => 'WEB path and bridge diagnostics need telemt 3.5.8+: an older binary silently ignores them, so path links would point where nothing answers. Update the telemt image.',
        'ru' => 'путь WEB и диагностика бриджа требуют telemt 3.5.8+: старый бинарь молча их игнорирует, и ссылки с путём вели бы туда, где никто не отвечает. Обновите образ telemt.',
    ],
    'telemt web path note'  => [
        'en' => 'path adds a secret prefix to the WEB address. Generate a new path, then distribute the updated links from user cards. Clients must support WEB links with paths. Native MTProxy links stay valid.',
        'ru' => 'path добавляет секретный префикс к WEB-адресу. Сгенерируйте новый путь, затем раздайте обновлённые ссылки из карточек пользователей. Клиент должен поддерживать WEB-ссылки с путём. Обычные MTProxy-ссылки сохраняются.',
    ],
    'telemt web path changed'  => [
        'en' => 'WEB path changed. Issue links from user cards. Restoring an old path may reactivate its old links.',
        'ru' => 'Путь WEB изменён. Выдайте ссылки из карточек пользователей. При возврате к прежнему пути соответствующие старые ссылки могут снова заработать.',
    ],
    'telemt web diag'  => [
        'en' => 'bridge diagnostics',
        'ru' => 'диагностика бриджа',
    ],
    'telemt web diag note'  => [
        'en' => 'bridge diagnostics: newly issued bridge pages report why Telegram (Desktop, Android) failed before the handshake (no native boundary, no HELLO, page closed). Counts for the last hour appear in the TeleMT report (Diagnostics, needs beobachten). While it is on, telemt also keeps short request records (method, path, IP, User-Agent — no headers or bodies) in a bounded in-memory ring.',
        'ru' => 'диагностика бриджа: новые страницы бриджа сообщают, почему Telegram (Desktop, Android) сорвался до рукопожатия (нет нативной границы, нет HELLO, страница закрыта). Счётчики за последний час — в отчёте TeleMT (диагностика, нужен beobachten). Пока она включена, telemt держит в памяти, в ограниченном кольце, и краткие записи запросов (метод, путь, IP, User-Agent — без заголовков и тел).',
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
    'defaultDNS'  => [
        'en' => 'default DNS',
        'ru' => 'дефолтный днс',
    ],
    'defaultMTU'  => [
        'en' => 'default MTU',
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
    'log empty' => [
        'ru' => 'Журнал пока пуст.',
        'en' => 'The log is empty.',
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
        'en' => 'fake domain',
        'ru' => 'фейковый домен',
    ],
    'fingerprint'  => [
        'en' => 'fingerprint',
        'ru' => 'отпечаток',
    ],
    'check fake domain'  => [
        'en' => 'check',
        'ru' => 'проверить',
    ],
    'reality mask short' => [
        'en' => 'Fake domain %s answers without ALPN: Xray 26.10.17+ rejects every REALITY client with it. Before updating the core pick a site with HTTP/2 or «steal from yourself».',
        'ru' => 'Фейковый домен %s отвечает без ALPN: Xray 26.10.17+ с ним отвергает всех клиентов REALITY. До обновления ядра выберите сайт с HTTP/2 или «маска своим сайтом».',
    ],
    'reality mask short now' => [
        'en' => 'Fake domain %s answers without ALPN: this REALITY core rejects every client with it. Pick a site with HTTP/2 or «steal from yourself».',
        'ru' => 'Фейковый домен %s отвечает без ALPN: это ядро REALITY отвергает с ним всех клиентов. Выберите сайт с HTTP/2 или «маска своим сайтом».',
    ],
    'reality mask tls12' => [
        'en' => 'Fake domain %s does not answer with TLS 1.3: REALITY does not work with it.',
        'ru' => 'Фейковый домен %s не отвечает по TLS 1.3: REALITY с ним не работает.',
    ],
    'reality mask fail' => [
        'en' => 'Fake domain %s is unreachable from the server (%s): REALITY clients cannot connect.',
        'ru' => 'Фейковый домен %s недоступен с сервера (%s): клиенты REALITY не подключатся.',
    ],
    'selfFakeDomain'  => [
        'en' => 'steal from yourself',
        'ru' => 'маска своим сайтом',
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
    'disable secret'  => [
        'en' => 'disable secret',
        'ru' => 'отключить секрет',
    ],
    'camouflage'  => [
        'en' => 'camouflage',
        'ru' => 'маскировка',
    ],
    'server'  => [
        'en' => 'server',
        'ru' => 'сервер',
    ],
    'username'  => [
        'en' => 'username',
        'ru' => 'логин',
    ],
    'password'  => [
        'en' => 'password',
        'ru' => 'пароль',
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
    'try again'  => [
        'en' => 'open the menu and try again',
        'ru' => 'откройте меню и повторите',
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
    'connection log'  => [
        'en' => 'connection log',
        'ru' => 'лог подключений',
    ],
    'no log'  => [
        'en' => 'no connections logged yet',
        'ru' => 'подключений пока не зафиксировано',
    ],
    'clear log'  => [
        'en' => 'clear log',
        'ru' => 'очистить лог',
    ],
    'log cleared'  => [
        'en' => 'connection log cleared',
        'ru' => 'лог подключений очищен',
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
    'ovpn bad name'  => [
        'en' => 'Invalid name: use Latin letters, digits, dot, dash and underscore.',
        'ru' => 'Недопустимое имя: используйте латинские буквы, цифры, точку, дефис и подчёркивание.',
    ],
    'ovpn long name'  => [
        'en' => 'The name is too long (40 characters at most).',
        'ru' => 'Имя слишком длинное (не более 40 символов).',
    ],
    'ovpn user exists'  => [
        'en' => 'a client with this name already exists',
        'ru' => 'клиент с таким именем уже есть',
    ],
    'ovpn issue failed'  => [
        'en' => 'the certificate was not issued — see the OpenVPN log (button "log tail")',
        'ru' => 'сертификат не выпущен — причина в журнале OpenVPN (кнопка «журнал»)',
    ],
    'ovpn pki busy'  => [
        'en' => 'the PKI is busy (the container is initialising) — try again in a minute',
        'ru' => 'PKI занят (контейнер инициализируется) — повторите через минуту',
    ],
    'ovpn pki not ready'  => [
        'en' => 'The PKI is not ready — restart OpenVPN from this menu and try again.',
        'ru' => 'PKI не готов — нажмите «перезагрузка» в этом меню и повторите.',
    ],
    'ovpn pki incomplete user'  => [
        'en' => 'the client files are incomplete — reissue the certificate or restart OpenVPN',
        'ru' => 'файлы клиента неполные — перевыпустите сертификат или перезапустите OpenVPN',
    ],
    'ovpn pki missing'  => [
        'en' => 'PKI is incomplete, missing',
        'ru' => 'PKI неполный, не хватает',
    ],
    'ovpn pki restart'  => [
        'en' => 'restart the ovpn container to finish the initialisation: <code>docker compose restart ovpn</code>',
        'ru' => 'перезапустите контейнер ovpn, чтобы завершить инициализацию: <code>docker compose restart ovpn</code>',
    ],
    'ovpn clients'  => [
        'en' => 'clients',
        'ru' => 'клиенты',
    ],
    'ovpn proto'  => [
        'en' => 'protocol',
        'ru' => 'протокол',
    ],
    'ovpn gateway'  => [
        'en' => 'all traffic via VPN',
        'ru' => 'весь трафик через VPN',
    ],
    'ovpn routes'  => [
        'en' => 'networks',
        'ru' => 'сети',
    ],
    'ovpn mss auto'  => [
        'en' => 'auto',
        'ru' => 'авто',
    ],
    'ovpn split empty'  => [
        'en' => '"All traffic via VPN" is off and no networks are set: clients connect, but only DNS goes through the tunnel. Add networks or turn the switch on.',
        'ru' => '«Весь трафик через VPN» выключен, а сети не заданы: клиенты подключаются, но через туннель идёт только DNS. Добавьте сети или включите переключатель.',
    ],
    'ovpn routes hint'  => [
        'en' => 'Networks that clients reach through the VPN, in CIDR form, separated by spaces, commas or new lines — for example <code>203.0.113.0/24 198.51.100.7</code>. An address without a prefix is a single host. Send <code>-</code> to clear the list. Clients receive the change on the next connection; current sessions are restarted.',
        'ru' => 'Сети, в которые клиенты ходят через VPN, в записи CIDR через пробел, запятую или с новой строки — например <code>203.0.113.0/24 198.51.100.7</code>. Адрес без префикса — один узел. Отправьте <code>-</code>, чтобы очистить список. Клиенты получают изменение при следующем подключении; текущие сессии перезапускаются.',
    ],
    'ovpn routes bad'  => [
        'en' => 'Not an IPv4 network',
        'ru' => 'Это не сеть IPv4',
    ],
    'ovpn routes many'  => [
        'en' => 'Too many networks, the limit is',
        'ru' => 'Слишком много сетей, не более',
    ],
    'ovpn conf markers'  => [
        'en' => 'server.conf has no markers for this setting and the migration did not add them — see the OpenVPN log.',
        'ru' => 'В server.conf нет маркеров этой настройки, и миграция их не добавила — смотрите журнал OpenVPN.',
    ],
    'ovpn renew'  => [
        'en' => 'reissue certificate',
        'ru' => 'перевыпустить сертификат',
    ],
    'ovpn renew confirm'  => [
        'en' => 'The current certificate will be revoked and a new one issued under the same name, valid for 10 years. The old .ovpn file stops working at once and the active session is closed; the bot sends a new .ovpn that must be delivered to the client. Blocking, the traffic counter and the limit are kept.',
        'ru' => 'Действующий сертификат будет отозван, и под тем же именем выпущен новый, на 10 лет. Прежний файл .ovpn сразу перестанет работать, активная сессия закроется; бот пришлёт новый .ovpn, который нужно передать клиенту. Блокировка, счётчик трафика и лимит сохраняются.',
    ],
    'ovpn renew failed'  => [
        'en' => 'The certificate was not revoked, nothing has changed — see the OpenVPN log.',
        'ru' => 'Сертификат отозвать не удалось, ничего не изменилось — смотрите журнал OpenVPN.',
    ],
    'ovpn renew lost'  => [
        'en' => 'The old certificate is revoked, but the new one was not issued — see the OpenVPN log. Add the client again:',
        'ru' => 'Старый сертификат отозван, а новый выпустить не удалось — причина в журнале OpenVPN. Добавьте клиента заново:',
    ],
    'ovpn traffic total'  => [
        'en' => 'traffic total',
        'ru' => 'трафик всего',
    ],
    'ovpn traffic since'  => [
        'en' => 'since',
        'ru' => 'с',
    ],
    'ovpn traffic reset'  => [
        'en' => 'reset counter',
        'ru' => 'сбросить счётчик',
    ],
    'ovpn limit'  => [
        'en' => 'traffic limit',
        'ru' => 'лимит трафика',
    ],
    'ovpn limit hint'  => [
        'en' => 'Traffic limit in gigabytes (download plus upload), for example <code>50</code> or <code>0.5</code>. <code>0</code> removes the limit. When the counter reaches the limit, the client is blocked and you get a message; to let the client back in, raise the limit or reset the counter and press "enable".',
        'ru' => 'Лимит трафика в гигабайтах (приём плюс отдача), например <code>50</code> или <code>0.5</code>. <code>0</code> — снять лимит. Когда счётчик дойдёт до лимита, клиент блокируется, а вам приходит сообщение; чтобы вернуть доступ, увеличьте лимит или сбросьте счётчик и нажмите «разблокировать».',
    ],
    'ovpn limit bad'  => [
        'en' => 'Enter a number of gigabytes, for example 50 or 0.5.',
        'ru' => 'Введите число гигабайт, например 50 или 0.5.',
    ],
    'ovpn limit reached'  => [
        'en' => 'the traffic limit is reached, the client is blocked',
        'ru' => 'лимит трафика исчерпан, клиент заблокирован',
    ],
    'ovpn limit enable'  => [
        'en' => 'The traffic limit is used up. Raise the limit or reset the counter first.',
        'ru' => 'Лимит трафика исчерпан. Сначала увеличьте лимит или сбросьте счётчик.',
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
    'rotate all peer keys'  => [
        'en' => 'rotate all peer keys',
        'ru' => 'ротировать все ключи клиентов',
    ],
    'confirm rotate peer keys'  => [
        'en' => 'Regenerate EVERY client\'s private/public key at once (and the shared presharedkey, if AmneziaWG). Every currently saved config/QR stops working immediately and SILENTLY — no error, the connection just drops. There is no way to auto-notify or re-push new configs to users; you must redistribute them by hand afterward.',
        'ru' => 'Разово перевыпустить приватный/публичный ключ КАЖДОГО клиента (и общий presharedkey, если это AmneziaWG). Все уже сохранённые у пользователей конфиги/QR перестанут работать сразу и МОЛЧА — без ошибки, соединение просто пропадёт. Автоматически уведомить или переслать новые конфиги пользователям бот не может — только вручную.',
    ],
    'l2tp profile ports'  => [
        'en' => 'The built-in iOS/macOS L2TP client works only with the standard IPsec ports 500 and 4500. The server uses other ports, so the profile is not issued — use IKEv2.',
        'ru' => 'Встроенный клиент L2TP в iOS и macOS работает только со стандартными портами IPsec 500 и 4500. На сервере заданы другие порты, поэтому профиль не выдаётся — используйте IKEv2.',
    ],
    'ikev2 on demand'  => [
        'en' => 'auto-connect',
        'ru' => 'автоподключение',
    ],
    'ikev2 on demand hint'  => [
        'en' => 'Profile with Connect On Demand: iOS/macOS bring the VPN up by themselves and restore it after a drop. The VPN switch will turn back on — to stop it, disable "Connect On Demand" in the VPN settings (ⓘ next to the profile). Installing it replaces the regular vpnbot profile of this user.',
        'ru' => 'Профиль с подключением по требованию: iOS и macOS сами поднимают VPN и возвращают его после обрыва. Переключатель VPN будет включаться обратно — чтобы остановить, выключите «Подключать по запросу» в настройках VPN (ⓘ рядом с профилем). Установка заменяет обычный профиль vpnbot этого пользователя.',
    ],
    'no native l2tp'  => [
        'en' => 'no native L2TP client, use IKEv2 instead',
        'ru' => 'нет нативного L2TP-клиента, используйте IKEv2',
    ],
    'behind NAT'  => [
        'en' => 'behind NAT (registry fix + reboot)',
        'ru' => 'за NAT (правка реестра + перезагрузка)',
    ],
    'warp key format'  => [
        'en' => 'Invalid key format: only Latin letters, digits and dashes.',
        'ru' => 'Неверный формат ключа: допустимы латинские буквы, цифры и дефис.',
    ],
    'warp up failed'  => [
        'en' => 'WARP did not come up: no handshake with the Cloudflare server within 15 seconds. The switch stays off; see the warp log.',
        'ru' => 'WARP не поднялся: за 15 секунд нет рукопожатия с сервером Cloudflare. Переключатель остался выключенным; подробности в журнале warp.',
    ],
    'warp stop failed'  => [
        'en' => 'WARP was marked as off, but the stop command did not finish — check the wp container.',
        'ru' => 'WARP отмечен выключенным, но команда остановки не завершилась — проверьте контейнер wp.',
    ],
    'warp backup found'  => [
        'en' => 'A previous key change was interrupted halfway: a copy of the old account is still stored. A new change is not started so that this copy is not lost. Restore the previous account from the copy, or delete the copy if the current account suits you.',
        'ru' => 'Прошлая смена ключа оборвалась посередине: копия прежнего аккаунта осталась на сервере. Новая смена не начинается, чтобы эту копию не потерять. Верните прежний аккаунт из копии или удалите копию, если текущий аккаунт вас устраивает.',
    ],
    'warp backup restore'  => [
        'en' => 'restore previous account',
        'ru' => 'вернуть прежний аккаунт',
    ],
    'warp backup drop'  => [
        'en' => 'delete the copy',
        'ru' => 'удалить копию',
    ],
    'warp backup restored'  => [
        'en' => 'The previous WARP account is restored.',
        'ru' => 'Прежний аккаунт WARP возвращён.',
    ],
    'warp backup dropped'  => [
        'en' => 'The copy is deleted. You can change the key now.',
        'ru' => 'Копия удалена. Теперь ключ можно менять.',
    ],
    'warp backup failed'  => [
        'en' => 'Could not finish; the copy is kept. See the warp log.',
        'ru' => 'Не удалось завершить; копия сохранена. Подробности в журнале warp.',
    ],
    'warp tunnel'  => [
        'en' => 'tunnel',
        'ru' => 'туннель',
    ],
    'warp tunnel down'  => [
        'en' => 'down',
        'ru' => 'не поднят',
    ],
    'warp handshake'  => [
        'en' => 'handshake',
        'ru' => 'рукопожатие',
    ],
    'warp seconds ago'  => [
        'en' => 's ago',
        'ru' => 'с назад',
    ],
    'warp socks'  => [
        'en' => 'SOCKS for Xray',
        'ru' => 'SOCKS для Xray',
    ],
    'warp socks pending'  => [
        'en' => 'starts within a minute',
        'ru' => 'запустится в течение минуты',
    ],
    'warp mode'  => [
        'en' => 'mode',
        'ru' => 'режим',
    ],
    'warp mode switched'  => [
        'en' => 'WARP mode:',
        'ru' => 'Режим WARP:',
    ],
    'warp mode reverted'  => [
        'en' => 'The new mode did not come up within the waiting time, so the previous one is restored. Details are in the warp log.',
        'ru' => 'Новый режим не заработал за отведённое время — возвращён прежний. Подробности в журнале warp.',
    ],
    'warp masque transport'  => [
        'en' => 'MASQUE transport',
        'ru' => 'транспорт MASQUE',
    ],
    'warp masque device'  => [
        'en' => 'MASQUE device',
        'ru' => 'устройство MASQUE',
    ],
    'warp masque no device'  => [
        'en' => 'not registered',
        'ru' => 'не зарегистрировано',
    ],
    'warp masque plan'  => [
        'en' => 'plan',
        'ru' => 'тариф',
    ],
    'warp masque endpoint'  => [
        'en' => 'endpoint',
        'ru' => 'узел',
    ],
    'warp masque no container'  => [
        'en' => 'The WARP container does not answer. Check that it is running and try again.',
        'ru' => 'Контейнер WARP не отвечает. Проверьте, что он запущен, и повторите.',
    ],
    'warp masque old image'  => [
        'en' => 'This WARP container does not support MASQUE. Update the bot so that the containers are recreated with the current images.',
        'ru' => 'Этот контейнер WARP не поддерживает MASQUE. Обновите бота, чтобы контейнеры пересоздались с актуальными образами.',
    ],
    'warp masque old core'  => [
        'en' => 'MASQUE needs Xray 26.10.10 or newer inside the WARP container; it has',
        'ru' => 'Для MASQUE в контейнере WARP нужно ядро Xray 26.10.10 или новее; сейчас там',
    ],
    'warp masque register failed'  => [
        'en' => 'The MASQUE device was not registered at Cloudflare, the mode is unchanged. If a WARP+ key is set, check it; Cloudflare may also be limiting registrations from this address — try again later. Details are in the warp log.',
        'ru' => 'Устройство MASQUE не зарегистрировано в Cloudflare, режим не изменён. Если задан ключ WARP+, проверьте его; возможно также, что Cloudflare временно ограничил регистрации с этого адреса — повторите позже. Подробности в журнале warp.',
    ],
    'warp masque unreachable'  => [
        'en' => 'The trial MASQUE connection from this server did not get through, the mode is unchanged. The server network may block UDP 443 to Cloudflare; WireGuard keeps working.',
        'ru' => 'Пробное подключение по MASQUE с этого сервера не прошло, режим не изменён. Возможно, сеть сервера не пропускает UDP 443 до Cloudflare; WireGuard продолжает работать.',
    ],
    'warp masque transport unreachable'  => [
        'en' => 'The trial connection over this transport did not get through, the transport is unchanged.',
        'ru' => 'Пробное подключение по этому транспорту не прошло, транспорт не изменён.',
    ],
    'warp masque up failed'  => [
        'en' => 'WARP did not come up over MASQUE: the proxy gave no WARP answer within the waiting time. The switch stays off; see the warp log.',
        'ru' => 'WARP по MASQUE не поднялся: прокси не дал ответа WARP за отведённое время. Переключатель остался выключенным; подробности в журнале warp.',
    ],
    'warp no profile'  => [
        'en' => 'wgcf profile is missing — restart the wp container',
        'ru' => 'профиль wgcf отсутствует — перезапустите контейнер wp',
    ],
    'fp no h2 warn'  => [
        'en' => '«%s» offers no HTTP/2 (ALPN): with gRPC and XHTTP, Xray and Mihomo clients will not connect. Use chrome, firefox, safari, ios, edge or qq.',
        'ru' => '«%s» не предлагает HTTP/2 (ALPN): с gRPC и XHTTP клиенты Xray и Mihomo не подключатся. Выберите chrome, firefox, safari, ios, edge или qq.',
    ],
    'fp noalpn warn'  => [
        'en' => 'randomizednoalpn sends no ALPN: gRPC will not negotiate h2 and XHTTP falls back to http/1.1',
        'ru' => 'randomizednoalpn не отправляет ALPN: gRPC не согласует h2, а XHTTP откатится на http/1.1',
    ],
    'optional'  => [
        'en' => 'optional',
        'ru' => 'необязательно',
    ],
    'change port'  => [
        'en' => 'change port',
        'ru' => 'сменить порт',
    ],
    'TrustTunnel'  => [
        'en' => 'TrustTunnel',
        'ru' => 'TrustTunnel',
    ],
    'link'  => [
        'en' => 'link',
        'ru' => 'ссылка',
    ],
    'tt config hint'  => [
        'en' => 'endpoint config: setup_wizard --mode non-interactive --endpoint_config &lt;file&gt; --settings trusttunnel_client.toml',
        'ru' => 'конфиг эндпоинта: setup_wizard --mode non-interactive --endpoint_config &lt;файл&gt; --settings trusttunnel_client.toml',
    ],
    'tt fallback'  => [
        'en' => 'built without the endpoint binary — check the tt container',
        'ru' => 'собран без обращения к бинарю эндпоинта — проверьте контейнер tt',
    ],
    'tt no deeplink'  => [
        'en' => 'endpoint did not return a deep link (is the tt container up?)',
        'ru' => 'эндпоинт не отдал deep link (контейнер tt поднят?)',
    ],
    'tt blocked'  => [
        'en' => 'not started, missing',
        'ru' => 'не запущен, не хватает',
    ],
    'tt client hint'  => [
        'en' => 'link — for mobile apps, file — for the CLI client',
        'ru' => 'ссылка — для мобильных приложений, файл — для CLI-клиента',
    ],
    'tt bad name'  => [
        'en' => 'name is unsupported by the bot, rename it in credentials.toml',
        'ru' => 'имя не поддерживается ботом, переименуйте в credentials.toml',
    ],
    'tt stats unavailable' => [
        'ru' => 'Статистика недоступна: проверьте запуск TrustTunnel и настройки метрик. Подробности — в справке.',
        'en' => 'Statistics unavailable: check TrustTunnel and its metrics settings. See Help.',
    ],
    'tt sessions' => ['ru' => 'Активные сессии', 'en' => 'Active sessions'],
    'tt uploaded' => ['ru' => 'Отправлено клиентом', 'en' => 'Uploaded by client'],
    'tt downloaded' => ['ru' => 'Получено клиентом', 'en' => 'Downloaded by client'],
    'tt peer ip' => ['ru' => 'IP соединения у сервера', 'en' => 'Peer IP seen by endpoint'],
    'tt stats lifetime' => [
        'ru' => 'Трафик с запуска ядра; после перезапуска счётчики обнуляются.',
        'en' => 'Traffic since core startup; counters reset on restart.',
    ],
    'win dns guard'  => [
        'en' => 'block-outside-dns (Windows)',
        'ru' => 'block-outside-dns (Windows)',
    ],
    'win dns warn'  => [
        'en' => 'Windows-only: non-Windows clients fail to connect',
        'ru' => 'только Windows: остальные клиенты не подключатся',
    ],
    'ip via nginx'  => [
        'en' => 'address of the nginx proxy, not the client: OpenVPN has no PROXY protocol',
        'ru' => 'это адрес nginx-прокси, а не клиента: OpenVPN не понимает PROXY protocol',
    ],

    // ── Ключи, которых не хватало (аудит 2026-08-12) ────────────────────────
    // i18n() отдавала сам ключ, то есть в русском интерфейсе оставался
    // английский текст — и это ещё в лучшем случае: чтение шло без ??, так что
    // каждая такая кнопка добавляла warning в лог.
    //
    // Названия протоколов, ядер и технических полей одинаковы в обоих языках
    // (как у 'warp'/'amnezia' выше): переводить их значило бы расходиться с
    // документацией и с интерфейсом самих клиентов.
    'vless'  => [
        'en' => 'vless',
        'ru' => 'vless',
    ],
    'hysteria'  => [
        'en' => 'hysteria',
        'ru' => 'hysteria',
    ],
    'Hysteria'  => [
        'en' => 'Hysteria',
        'ru' => 'Hysteria',
    ],
    'dnstt'  => [
        'en' => 'dnstt',
        'ru' => 'dnstt',
    ],
    'DNSTT'  => [
        'en' => 'DNSTT',
        'ru' => 'DNSTT',
    ],
    'singbox'  => [
        'en' => 'sing-box',
        'ru' => 'sing-box',
    ],
    'mihomo'  => [
        'en' => 'mihomo',
        'ru' => 'mihomo',
    ],
    'v2ray'  => [
        'en' => 'v2ray',
        'ru' => 'v2ray',
    ],
    'RLTY'  => [
        'en' => 'RLTY',
        'ru' => 'RLTY',
    ],
    'WS'  => [
        'en' => 'WS',
        'ru' => 'WS',
    ],
    'XHTTP'  => [
        'en' => 'XHTTP',
        'ru' => 'XHTTP',
    ],
    'MTU'  => [
        'en' => 'MTU',
        'ru' => 'MTU',
    ],
    'nip.io'  => [
        'en' => 'nip.io',
        'ru' => 'nip.io',
    ],
    'cdn'  => [
        'en' => 'CDN domain',
        'ru' => 'домен CDN',
    ],
    'endpoint'  => [
        'en' => 'endpoint',
        'ru' => 'адрес подключения',
    ],
    'Ports'  => [
        'en' => 'ports',
        'ru' => 'порты',
    ],
    // Оставлены по-английски осознанно: так эти кнопки выглядели до аудита
    // 2026-08-12 (ключа в словаре не было, i18n() отдавала сам ключ), и
    // пользователи бота их узнают именно в таком виде.
    'routes'  => [
        'en' => 'routes',
        'ru' => 'routes',
    ],
    'rulesset'  => [
        'en' => 'rulesset',
        'ru' => 'rulesset',
    ],
    'tun lists'  => [
        'en' => 'tun lists',
        'ru' => 'списки tun',
    ],
    'process'  => [
        'en' => 'process',
        'ru' => 'процессы',
    ],
    'package'  => [
        'en' => 'package',
        'ru' => 'приложения',
    ],
    'block'  => [
        'en' => 'block',
        'ru' => 'block',
    ],
    'blocklist'  => [
        'en' => 'block list',
        'ru' => 'список блокировки',
    ],
    'ignore'  => [
        'en' => 'ignore',
        'ru' => 'игнорировать',
    ],
    'ignorelist'  => [
        'en' => 'ignore list',
        'ru' => 'список игнорирования',
    ],
    'IP ban'  => [
        'en' => 'IP ban',
        'ru' => 'бан по IP',
    ],
    'ip limit'  => [
        'en' => 'IP limit',
        'ru' => 'лимит IP',
    ],
    'ip limit hint'  => [
        'en' => "Format: <code>seconds:count</code> — the observation window in seconds and how many different IPs one client is allowed inside it.\n\n"
            . "Examples:\n"
            . "<code>300:2</code> — no more than 2 different IPs per 5 minutes\n"
            . "<code>3600:1</code> — a single IP per hour (strict)\n"
            . "<code>600</code> — count omitted = 1 IP per 10 minutes\n"
            . "<code>0</code> — turn the limit off\n\n"
            . "Digits only, separator <code>:</code> (a space or a comma also works). Count is 1 by default.",
        'ru' => "Формат: <code>секунды:количество</code> — окно наблюдения в секундах и сколько разных IP разрешено одному клиенту внутри него.\n\n"
            . "Примеры:\n"
            . "<code>300:2</code> — не больше 2 разных IP за 5 минут\n"
            . "<code>3600:1</code> — один IP в час (строго)\n"
            . "<code>600</code> — количество не указано = 1 IP за 10 минут\n"
            . "<code>0</code> — выключить лимит\n\n"
            . "Только цифры, разделитель <code>:</code> (пробел или запятая тоже подойдут). Количество по умолчанию — 1.",
    ],
    'ip limit notice'  => [
        'en' => 'Applies to xray (vless) clients: on excess the bot sends admins an alert with a button to switch that client off — nothing is blocked automatically.',
        'ru' => 'Работает для клиентов xray (vless): при превышении бот шлёт админам уведомление с кнопкой отключения клиента — автоматически никто не блокируется.',
    ],
    'current value'  => [
        'en' => 'now',
        'ru' => 'сейчас',
    ],
    'analyze'  => [
        'en' => 'analyze',
        'ru' => 'анализ',
    ],
    'autoscan'  => [
        'en' => 'autoscan',
        'ru' => 'автопроверка',
    ],
    'autoblock'  => [
        'en' => 'autoblock',
        'ru' => 'автоблокировка',
    ],
    'autoclean'  => [
        'en' => 'autoclean',
        'ru' => 'автоочистка',
    ],
    'autoupdate'  => [
        'en' => 'autoupdate',
        'ru' => 'автообновление',
    ],
    'notify'  => [
        'en' => 'notifications',
        'ru' => 'уведомления',
    ],
    'clean'  => [
        'en' => 'clean',
        'ru' => 'очистить',
    ],
    'clean all'  => [
        'en' => 'clean all',
        'ru' => 'очистить всё',
    ],
    'delete all'  => [
        'en' => 'delete all',
        'ru' => 'удалить всё',
    ],
    'all logs'  => [
        'en' => 'all logs',
        'ru' => 'все логи',
    ],
    'suspicious log'  => [
        'en' => 'suspicious log',
        'ru' => 'подозрительное',
    ],
    'telegram IPs'  => [
        'en' => 'telegram IPs',
        'ru' => 'адреса telegram',
    ],
    'gcore IPs'  => [
        'en' => 'gcore IPs',
        'ru' => 'адреса gcore',
    ],
    'cloudflare IPs'  => [
        'en' => 'cloudflare IPs',
        'ru' => 'адреса cloudflare',
    ],
    'reset stats'  => [
        'en' => 'reset stats',
        'ru' => 'сбросить статистику',
    ],
    'reset monthly'  => [
        'en' => 'monthly reset',
        'ru' => 'ежемесячный сброс',
    ],
    'changelog branch'  => [
        'en' => 'branch',
        'ru' => 'ветка',
    ],
    'changelog installed'  => [
        'en' => 'Installed',
        'ru' => 'Установлено',
    ],
    'changelog available'  => [
        'en' => 'In the branch',
        'ru' => 'В ветке',
    ],
    'changelog pending'  => [
        'en' => 'Not installed yet',
        'ru' => 'Ещё не установлено',
    ],
    'changelog pending note'  => [
        'en' => 'These changes are in the branch; they arrive with the next bot update once the image set is built.',
        'ru' => 'Эти изменения уже есть в ветке; они придут со следующим обновлением бота, когда соберётся комплект образов.',
    ],
    'changelog up to date'  => [
        'en' => 'The installed version matches the branch.',
        'ru' => 'Установленная версия совпадает с веткой.',
    ],
    'changelog history'  => [
        'en' => 'Installed changes',
        'ru' => 'Установленные изменения',
    ],
    'changelog upstream'  => [
        'en' => 'Versions of the original project',
        'ru' => 'Версии исходного проекта',
    ],
    'changelog'  => [
        'en' => 'changelog',
        'ru' => 'список изменений',
    ],
    'branches'  => [
        'en' => 'branches',
        'ru' => 'ветки',
    ],
    'yes'  => [
        'en' => 'yes',
        'ru' => 'да',
    ],
    'set key'  => [
        'en' => 'set key',
        'ru' => 'задать ключ',
    ],
    'set password'  => [
        'en' => 'set password',
        'ru' => 'задать пароль',
    ],
    'set subdomain'  => [
        'en' => 'set subdomain',
        'ru' => 'задать поддомен',
    ],
    'change subdomain'  => [
        'en' => 'change subdomain',
        'ru' => 'сменить поддомен',
    ],
    'download pubkey'  => [
        'en' => 'download pubkey',
        'ru' => 'скачать публичный ключ',
    ],
    'link awg'  => [
        'en' => 'AmneziaWG link',
        'ru' => 'ссылка AmneziaWG',
    ],
    'qr short'  => [
        'en' => 'QR (short link)',
        'ru' => 'QR (короткая ссылка)',
    ],
    'qr singbox'  => [
        'en' => 'QR sing-box',
        'ru' => 'QR sing-box',
    ],
    'qr v2ray'  => [
        'en' => 'QR v2ray',
        'ru' => 'QR v2ray',
    ],
    'singbox ⬇️'  => [
        'en' => 'sing-box ⬇️',
        'ru' => 'sing-box ⬇️',
    ],
    'mihomo ⬇️'  => [
        'en' => 'mihomo ⬇️',
        'ru' => 'mihomo ⬇️',
    ],
    'v2ray ⬇️'  => [
        'en' => 'v2ray ⬇️',
        'ru' => 'v2ray ⬇️',
    ],
    'sing-box templates'  => [
        'en' => 'sing-box templates',
        'ru' => 'шаблоны sing-box',
    ],
    'mihomo templates'  => [
        'en' => 'mihomo templates',
        'ru' => 'шаблоны mihomo',
    ],
    'v2ray templates'  => [
        'en' => 'v2ray templates',
        'ru' => 'шаблоны v2ray',
    ],
    // С хвостовым пробелом: ключ подставляется перед значением в одну строку.
    'main outbound name: '  => [
        'en' => 'main outbound name: ',
        'ru' => 'имя основного аутбаунда: ',
    ],
    'auto update' => [
        'en' => 'auto update',
        'ru' => 'автообновление',
    ],
    'last update' => [
        'en' => 'last update',
        'ru' => 'последнее обновление',
    ],
    'next update' => [
        'en' => 'next update',
        'ru' => 'следующее обновление',
    ],
    'select update interval' => [
        'en' => 'Select update interval',
        'ru' => 'Выберите интервал обновления',
    ],
    'custom interval' => [
        'en' => 'custom interval',
        'ru' => 'свой интервал',
    ],
    'dat run hour' => [
        'en' => 'Run hour',
        'ru' => 'Час запуска',
    ],
    'dat any hour' => [
        'en' => 'any hour',
        'ru' => 'без привязки к часу',
    ],
    'dat categories' => [
        'en' => 'categories',
        'ru' => 'категории',
    ],
    'dat not downloaded' => [
        'en' => 'not downloaded',
        'ru' => 'не скачан',
    ],
    'dat no files' => [
        'en' => 'No downloaded .dat files yet.',
        'ru' => 'Скачанных .dat пока нет.',
    ],
    'dat category usage' => [
        'en' => 'use in block / WARP as',
        'ru' => 'в block / WARP пишите',
    ],
    'dat show all' => [
        'en' => 'show all',
        'ru' => 'показать все',
    ],
    'dat search prompt' => [
        'en' => 'part of the category name',
        'ru' => 'часть названия категории',
    ],
    'dat interval prompt' => [
        'en' => 'update interval: number and unit, e.g. 90m, 36h, 10d (from 15m to 90d)',
        'ru' => 'интервал обновления: число и единица, например 90m, 36h, 10d (от 15m до 90d)',
    ],
    'dat interval invalid' => [
        'en' => 'Interval not accepted. Enter a number with m, h or d, from 15m to 90d.',
        'ru' => 'Интервал не принят. Введите число с m, h или d, от 15m до 90d.',
    ],
    'search' => [
        'en' => 'search',
        'ru' => 'поиск',
    ],
    'enter ext user agent' => [
        'en' => 'User-Agent for fetching external subscriptions (one value for all of them). Send "-" to restore the default. Current:',
        'ru' => 'User-Agent для загрузки внешних подписок (общий для всех). Отправьте «-», чтобы вернуть значение по умолчанию. Сейчас:',
    ],
    'ext user agent invalid' => [
        'en' => 'User-Agent not accepted: printable Latin characters only, up to 200.',
        'ru' => 'User-Agent не принят: только печатные латинские символы, до 200.',
    ],
    'status time' => [
        'en' => 'Server time',
        'ru' => 'Время сервера',
    ],
    'status uptime' => [
        'en' => 'Uptime',
        'ru' => 'Работает без перезагрузки',
    ],
    'status kernel' => [
        'en' => 'Kernel',
        'ru' => 'Ядро',
    ],
    'status cpu' => [
        'en' => 'CPU',
        'ru' => 'Процессор',
    ],
    'status cores' => [
        'en' => 'cores',
        'ru' => 'ядер',
    ],
    'status load' => [
        'en' => 'load average, 1 / 5 / 15 min',
        'ru' => 'средняя нагрузка за 1 / 5 / 15 мин',
    ],
    'status memory' => [
        'en' => 'Memory',
        'ru' => 'Память',
    ],
    'status swap' => [
        'en' => 'swap used',
        'ru' => 'подкачка: занято',
    ],
    'status disk' => [
        'en' => 'Disk',
        'ru' => 'Диск',
    ],
    'status data disk' => [
        'en' => 'Bot data disk',
        'ru' => 'Диск с данными бота',
    ],
    'status used' => [
        'en' => 'used',
        'ru' => 'занято',
    ],
    'status of' => [
        'en' => 'of',
        'ru' => 'из',
    ],
    'status free' => [
        'en' => 'free',
        'ru' => 'свободно',
    ],
    'disk alert' => [
        'en' => 'Disk is almost full',
        'ru' => 'Диск почти заполнен',
    ],
    'disk alert cleared' => [
        'en' => 'Disk space is back to normal',
        'ru' => 'Место на диске снова в норме',
    ],
    'cpu alert' => [
        'en' => 'CPU load has stayed high for the last hour, average',
        'ru' => 'Процессор загружен уже час, в среднем',
    ],
    'cpu alert cleared' => [
        'en' => 'CPU load is back to normal, last 10 minutes average',
        'ru' => 'Загрузка процессора снова в норме, за последние 10 минут в среднем',
    ],
    'status alerts hint' => [
        'en' => 'The bot will message admins when a disk is 90% full or CPU load stays at 90% for an hour.',
        'ru' => 'Бот сообщит администраторам, если диск заполнен на 90% или процессор час загружен на 90%.',
    ],
    'adg settings' => [
        'en' => "settings",
        'ru' => "настройки",
    ],
    'adg statistics' => [
        'en' => "statistics",
        'ru' => "статистика",
    ],
    'adg protection' => [
        'en' => "protection",
        'ru' => "защита",
    ],
    'adg queries' => [
        'en' => "queries",
        'ru' => "запросов",
    ],
    'adg blocked' => [
        'en' => "blocked",
        'ru' => "заблокировано",
    ],
    'adg rate limit' => [
        'en' => "rate limit",
        'ru' => "лимит запросов",
    ],
    'adg dot open' => [
        'en' => "DoT port is published and the allowed clients list is empty: anyone can use this resolver. Press «fill allowed clients».",
        'ru' => "Порт DoT опубликован, а список разрешённых пуст: резолвером может пользоваться любой. Нажмите «заполнить список разрешённых».",
    ],
    'adg reset confirm' => [
        'en' => "Reset AdGuard to defaults? Filters, clients, upstreams and the allowed clients list will be erased.",
        'ru' => "Сбросить AdGuard к заводским настройкам? Будут стёрты фильтры, клиенты, апстримы и список разрешённых.",
    ],
    'adg not responding' => [
        'en' => "AdGuard does not respond",
        'ru' => "AdGuard не отвечает",
    ],
    'adg not applied' => [
        'en' => "Setting not applied",
        'ru' => "Настройка не применена",
    ],
    'adg days' => [
        'en' => "d",
        'ru' => "дн.",
    ],
    'adg query log' => [
        'en' => "query log",
        'ru' => "журнал запросов",
    ],
    'adg stats keep' => [
        'en' => "statistics",
        'ru' => "статистика",
    ],
    'adg hide ip' => [
        'en' => "hide client IPs in the log",
        'ru' => "скрывать IP клиентов в журнале",
    ],
    'adg safe search' => [
        'en' => "safe search",
        'ru' => "безопасный поиск",
    ],
    'adg mode lb' => [
        'en' => "in turn",
        'ru' => "по очереди",
    ],
    'adg mode parallel' => [
        'en' => "parallel",
        'ru' => "параллельно",
    ],
    'adg mode fastest' => [
        'en' => "fastest",
        'ru' => "самый быстрый",
    ],
    'adg settings hint' => [
        'en' => "Changes apply at once, AdGuard is not restarted.",
        'ru' => "Изменения применяются сразу, AdGuard не перезапускается.",
    ],
    'adg hint rate' => [
        'en' => "Answers per second for one /24 subnet. All WireGuard clients share one subnet, and so do clients that reach AdGuard through containers: with many users 20/s is not enough.",
        'ru' => "Ответов в секунду на одну подсеть /24. Все клиенты WireGuard — одна подсеть, как и те, кто приходит через контейнеры: при большом числе пользователей 20/с мало.",
    ],
    'adg hint qlog' => [
        'en' => "How long every DNS request of every user is kept. Shorter means less disk space and less stored data.",
        'ru' => "Сколько хранится каждый DNS-запрос каждого пользователя. Короче — меньше места на диске и меньше хранимых данных.",
    ],
    'adg hint stats' => [
        'en' => "How long the counters for the statistics screen are kept.",
        'ru' => "Сколько хранятся счётчики для экрана статистики.",
    ],
    'adg period' => [
        'en' => "period",
        'ru' => "период",
    ],
    'adg avg time' => [
        'en' => "average answer time",
        'ru' => "среднее время ответа",
    ],
    'adg top blocked' => [
        'en' => "Top blocked",
        'ru' => "Чаще всего блокируется",
    ],
    'adg top domains' => [
        'en' => "Top domains",
        'ru' => "Чаще всего запрашивается",
    ],
    'adg top clients' => [
        'en' => "Top clients",
        'ru' => "Самые активные клиенты",
    ],
    'fp reality no tls13' => [
        'en' => '«%s» has no TLS 1.3: no REALITY server accepts it, clients will not connect.',
        'ru' => '«%s» без TLS 1.3: его не принимает ни один сервер REALITY, клиенты не подключатся.',
    ],
    'fp reality mlkem' => [
        'en' => 'This REALITY core requires X25519MLKEM768, and «%s» does not carry it: clients will get the cover site. Known to work: %s.',
        'ru' => 'Это ядро REALITY требует X25519MLKEM768, а у «%s» его нет: клиенты получат сайт-маску. Работают: %s.',
    ],
    'fp reality mihomo' => [
        'en' => 'Mihomo connects to this REALITY core with chrome only.',
        'ru' => 'Mihomo подключится к этому ядру REALITY только с chrome.',
    ],
    'fp reality random' => [
        'en' => 'random picks a browser sample when the client starts: this REALITY core accepts only samples with X25519MLKEM768, so the client connects only sometimes.',
        'ru' => 'random при запуске клиента берёт образец браузера: это ядро REALITY принимает лишь образцы с X25519MLKEM768, поэтому клиент подключается только иногда.',
    ],
    'fp reality core mlkem' => [
        'en' => 'REALITY core: requires X25519MLKEM768 (original Xray 26.9.8+ or the fork with «Require ML-KEM»). Fingerprints marked ⚠ will not connect.',
        'ru' => 'Ядро REALITY требует X25519MLKEM768 (оригинальный Xray 26.9.8+ или форк с «Требовать ML-KEM»). Отпечатки с пометкой ⚠ не подключатся.',
    ],
    'fp reality core any' => [
        'en' => 'REALITY core: accepts any fingerprint with TLS 1.3 (the fork without «Require ML-KEM»).',
        'ru' => 'Ядро REALITY принимает любой отпечаток с TLS 1.3 (форк без «Требовать ML-KEM»).',
    ],
];

if (file_exists(__DIR__ . '/i18n.override.php')) {
    include __DIR__ . '/i18n.override.php';
}
