telegram bot to manage servers (inside the bot)

- VLESS (Reality OR Websocket)
- NaiveProxy
- OpenConnect
- Wireguard
- Amnezia
- AdguardHome
- TeleMT (MTProto, + WEB-прокси для Telegram Desktop)
- PAC
- automatic ssl

---
environment: ubuntu 22.04/24.04, debian 11/12

## Install:

Репозиторий приватный — установка возможна только с вашим GitHub-токеном
(fine-grained PAT, доступ только к `axiomshiftbit/vpnbot`, права `Contents: Read`).
Без токена ни ссылка, ни клонирование не работают, и сам репозиторий другим не виден.

Сохраните токен в переменной (держите в секрете). Чтобы команда с токеном не
попала в историю shell, поставьте пробел перед командой (` export GH_TOKEN=...`):
```shell
 export GH_TOKEN=github_pat_xxx
```

stable (master):
```shell
curl -fsSL -H "Authorization: Bearer $GH_TOKEN" -H "Accept: application/vnd.github.raw" \
  "https://api.github.com/repos/axiomshiftbit/vpnbot/contents/scripts/init.sh?ref=master" \
  | GH_TOKEN="$GH_TOKEN" VPNBOT_KEY=YOUR_TELEGRAM_BOT_KEY bash -s master
```
development (dev):
```shell
curl -fsSL -H "Authorization: Bearer $GH_TOKEN" -H "Accept: application/vnd.github.raw" \
  "https://api.github.com/repos/axiomshiftbit/vpnbot/contents/scripts/init.sh?ref=dev" \
  | GH_TOKEN="$GH_TOKEN" VPNBOT_KEY=YOUR_TELEGRAM_BOT_KEY bash -s dev
```
Ключ бота передаётся переменной `VPNBOT_KEY`, а не аргументом: аргумент виден
в `ps` всем процессам хоста и остаётся в history. Старая форма
(`bash init.sh YOUR_TELEGRAM_BOT_KEY master`) ещё работает, но предупреждает.

GitHub-токен в URL репозитория больше не вшивается: `origin` остаётся чистым,
а токен ложится в `/root/.vpnbot-git-credentials` (0600) и подхватывается
`credential.helper`. Установка поверх старой инсталляции заодно вычищает PAT
из `.git/config`.

Установка из архива (offline, токен не нужен) — положите `vpnbot.zip` рядом
со скриптом и запустите `VPNBOT_KEY=YOUR_TELEGRAM_BOT_KEY bash init.sh master`.
#### Tests:
```shell
make test
```
Прогон запускается **на хосте**, а не внутри контейнера: тесты подменяют пути
конфигов через свойства объекта, но соседство с боевыми `/config` и `/logs`
проверять на них незачем. Те же проверки гоняет CI на каждый push.

#### Restart:
```shell
make r
```
#### autoload:
```shell
crontab -e
```
add `@reboot cd /root/vpnbot && make r` and save

---

## Xray 26.9.9, REALITY и VLESS Encryption

Новое рукопожатие REALITY и VLESS Encryption — независимые настройки.
Для REALITY бот выдаёт Xray/mihomo профиль с fingerprint `chrome`, а mihomo
дополнительно получает `reality-opts.support-x25519mlkem768: true`.
Остальные транспорты сохраняют выбранный в меню fingerprint.
[Требование REALITY](https://github.com/XTLS/REALITY/commit/8cdf7bf9c7f09cb9814bf08c3eb877f68b85fba8),
[настройка mihomo](https://wiki.metacubex.one/en/config/proxies/tls/).

Меню **Xray → VLESS Encryption** включает дополнительное шифрование для
REALITY, WebSocket или XHTTP. Доступны аутентификация X25519/ML-KEM-768
и режимы `native`, `xorpub`, `random`, как в 3x-ui. Ключи создаёт активное ядро
командой `xray vlessenc`; конфиг проверяется до применения. Выключение и
повторное включение сохраняют ключи; для ротации есть отдельная кнопка.
После изменения параметров все клиенты должны обновить подписку.
Серверные ключи не включаются в клиентские профили. При переходе на Trojan
Encryption не применяется; при возврате к VLESS выбранная пара сохраняется.
[Документация VLESS Encryption](https://xtls.github.io/en/config/outbounds/vless.html).

Официальный sing-box 1.14.1 не поддерживает VLESS Encryption и новое
рукопожатие REALITY Xray 26.9.8+. Несовместимая подписка отклоняется с
объяснением; отключение Encryption не исправляет новое рукопожатие REALITY.
Для sing-box нужны прежнее серверное ядро либо WebSocket/TLS или Trojan/gRPC
без VLESS Encryption. XHTTP также отсутствует в официальном sing-box.
[Формат VLESS sing-box](https://sing-box.sagernet.org/configuration/outbound/vless/),
[его REALITY-клиент](https://github.com/SagerNet/sing-box/blob/v1.14.1/common/tls/reality_client.go).

В ветке `dev` штатное ядро закреплено на `v26.9.9`
([upstream помечает выпуск как prerelease](https://github.com/XTLS/Xray-core/releases/tag/v26.9.9)).
Обновите опубликованный образ `xr`; выбор активного ядра в меню должен быть
`XTLS`. У форка SMUX своя версия. Локальный `XRAY_VERSION` в `override.env`
влияет на **сборку**, а скачивание готового образа её не меняет. Если требуется
прежнее ядро для REALITY в sing-box, задайте `XRAY_VERSION=v26.7.28` в
`override.env` и пересоберите `xr`. Обычный `make start` скачивает опубликованные
образы, поэтому собственную сборку запускайте без `pull`.

Поддержка общая для XTLS и форка Jolymmiles: новое рукопожатие не включается
переключателем в JSON, его реализует само ядро. Бот проверяет версию REALITY
из метаданных бинарника, поэтому будущий выпуск форка с прежней зависимостью
не считается новым REALITY только по дате релиза. Клиентские параметры MLKEM
выдаются для обоих ядер. Обновление форка задаётся отдельно через
`XRAY_FORK_VERSION` в `override.env` с пересборкой `xr`; перед переключением
при включённом Encryption конфиг проверяется выбранным бинарником.

Shadowrocket объявил VLESS Encryption в версии 2.2.79. Это не подтверждает
работу нового рукопожатия REALITY с любым TLS fingerprint. В журнале бета-версий
есть импорт `support-x25519mlkem768` (2.2.90), а в 2.2.93 исправляется описание
совместимости REALITY/отпечатков. Проверка конкретной версии на iOS необходима;
её нельзя заменить успешным тестом mihomo или Xray.
[App Store](https://apps.apple.com/us/app/shadowrocket/id932747118),
[Shadowrocket News: импорт MLKEM](https://t.me/ShadowrocketNews/1575),
[исправление описания отпечатка](https://t.me/ShadowrocketNews/1634).

В карточке клиента Xray и его relay доступны ссылки `import://` для
**Shadowrocket, v2rayNG, sing-box, Streisand, Hiddify, Karing, mihomo и Rabbit Hole**.
Ссылка открывает установленное приложение и передаёт ему адрес подписки;
приложение или браузер могут запросить подтверждение добавления. Для mihomo
ссылку `clash://` обрабатывает установленный графический клиент с поддержкой
этой схемы. В Hiddify используется команда `hiddify://import/` и подписка
со списком узлов; маршрутизацию приложение настраивает самостоятельно.
При включённом HWID переход из браузера доступен, а проверка устройства
выполняется при загрузке конфигурации приложением. Ограничения совместимости
протоколов сохраняются независимо от способа импорта.
[Импорт sing-box](https://sing-box.sagernet.org/clients/general/),
[Hiddify](https://hiddify.com/app/URL-Scheme/),
[Karing](https://karing.app/cooperation/scheme),
[Rabbit Hole](https://rabbit-hole-1.gitbook.io/rabbit-hole-docs/for-devs/deep-linking).

## Веб-панель: управление ботом без Telegram

Если Telegram недоступен (заблокированы исходящие к `api.telegram.org` либо нет
самого клиента), тем же ботом можно управлять из браузера. Панель не копия меню,
а тот же самый код: клик по кнопке превращается в такой же `update`, какой
прислал бы Telegram, и уходит в `Bot::input()`, а ответы перехватывает
`app/panel/PanelTransport.php` вместо curl'а наружу. Меню, диалоги «введите
значение», QR, файлы конфигов и редактор шаблонов работают один в один.

Панель поднимается на **отдельном слушателе unit (порт 8090)**, проброшенном
только на `127.0.0.1` сервера: снаружи её нет, на публичном 443 путь `/panel…`
отвечает 404. Заходить — через SSH-туннель.

```shell
# на сервере: адрес панели и, при первом запуске, сгенерированный пароль
docker compose exec php php panel.php url
docker compose exec php php panel.php passwd          # сменить пароль
docker compose exec php php panel.php admin <tg-id>   # если $c['admin'] пуст

# на своей машине
ssh -L 8090:127.0.0.1:8090 <сервер>
# затем открыть http://127.0.0.1:8090/panel<hash>/
```

Пароль хранится хешем в `pac.json`; его смена разом сбрасывает все открытые
сессии панели. Лента, вложения и загруженные файлы лежат в `/config/panel/`.

Публикации порта на `127.0.0.1` мало: слушатель unit виден всей внутренней сети
`10.10.0.0/24`, а freedom-outbound xray её разрешает (иначе не работает WARP), —
то есть до `10.10.0.7:8090` дотягивался бы любой VPN-клиент, а `<hash>` в адресе
панели есть в каждой ссылке подписки. Поэтому панель дополнительно проверяет,
откуда пришёл запрос: пускает только loopback и шлюз docker-сети (с него
приходит и проброшенный порт, и обращение с самого сервера). Проверка стоит на
**весь слушатель**, а не только на `/panel<hash>`: всё остальное на этом порту
обслуживает тот же `index.php` (подписки, `t=changelog`, `/webapp<hash>/*`,
вебхук `/tlgrm`), и на 8090 они шли бы мимо nginx. Если ходить нужно откуда-то
ещё — перечислите адреса или сети в `.env`:

```shell
PANEL_TRUSTED=                     # напр. 10.10.0.0/24 или 192.168.1.5
PANEL_HOSTS=                       # имя в Host, если заходите не по IP
```

### Если заблокированы только исходящие к Telegram

Полноценный бот в Telegram возвращается двумя переменными в `.env`:

```shell
TELEGRAM_API=api.telegram.org      # или адрес своего зеркала Bot API
TELEGRAM_PROXY=socks5h://wp:1080   # прокси; wp — WARP из этого же compose
```

---

## Routes: правила маршрутизации (regexp / keyword / full / domain)

Списки маршрутизации (**routes** в боте) поддерживают xray-совместимые префиксы,
которые единообразно транслируются в конфиги всех движков — **xray, sing-box,
mihomo/clash** — и работают в том числе для маршрута через **warp**.

Префиксы можно использовать в списках:
- **proxy (domains)** — завернуть в прокси;
- **block** — заблокировать (blackhole / REJECT);
- **warp** — направить через WARP.

### Как вводить

После нажатия **add** отправьте список записей. Разделитель — **перевод строки
или запятая**. Записи с `regexp:` пишите **каждую с новой строки**: регулярное
выражение может само содержать запятые (например `a{1,3}`), поэтому по запятой
такая строка не разбивается.

```
regexp:.*\.ru$
regexp:^([\w\-\.]+\.)xn--p1ai$
keyword:reddit
full:example.com
domain:пример.рф
google.com
```

Или в одну строку через запятую (без regexp):
```
keyword:gigabyte, keyword:reddit, domain:vk.com, 1.2.3.4/24
```

### Префиксы

| Префикс         | Что делает                          | Пример                     |
|-----------------|-------------------------------------|----------------------------|
| `regexp:`       | регулярное выражение                | `regexp:.*\.ru$`           |
| `keyword:`      | совпадение по подстроке             | `keyword:reddit`           |
| `full:`         | точное совпадение домена            | `full:example.com`         |
| `domain:`       | домен и все его поддомены            | `domain:vk.com`            |
| *(без префикса)*| суффикс на sing-box/mihomo, **подстрока на xray** (см. ниже) | `google.com` |
| *(IPv4[/cidr])* | IP-адрес / подсеть                  | `1.2.3.4`, `10.0.0.0/24`   |
| *(IPv6[/cidr])* | IPv6-адрес / подсеть                | `2001:db8::1`, `2001:db8::/32` |
| `ext:`          | категория доменов из внешнего xray `.dat` (**только block/warp, сервер**) | `ext:dlc.dat:github` |
| `extip:`        | категория IP из внешнего xray `.dat` (**только block/warp, сервер**)       | `extip:zkeenip.dat:akamai` |
| `geosite:`      | категория доменов из штатной geodata xray | `geosite:category-ads-all` |
| `geoip:`        | категория IP из штатной geodata xray      | `geoip:cn`                 |

У `ext:`/`extip:` **категория обязательна**: `ext:dlc.dat` без `:категория`
xray не разбирает и не стартует, поэтому такие записи вырезаются из серверного
конфига (в списке они остаются, но ни на что не влияют).

`geosite:`/`geoip:` понимает только xray — в правила sing-box и mihomo они не
попадают (у тех своя geodata и свой синтаксис).

Записи с **пустым значением** (`keyword:`, `regexp:` и т.п.) и **некорректные
IP** (`999.1.1.1`, `1.2.3.4/64`, префикс вне 0–32 для IPv4 и 0–128 для IPv6) в
конфиги не попадают и при вводе не сохраняются. Пустой `keyword:` особенно
опасен: в поле `domain[]` у xray голая строка означает совпадение по подстроке,
а пустая подстрока входит в любой домен — весь список превращался бы в
«блокировать всё».

Домены (кроме `regexp:`/`keyword:`/`ext:`/`extip:`) автоматически приводятся к
punycode (`domain:пример.рф` → `domain:xn--e1afmkfd.xn--p1ai`).

### Во что транслируется

| Ввод          | xray `domain[]` | sing-box         | mihomo/clash       |
|---------------|-----------------|------------------|--------------------|
| `regexp:X`    | `regexp:X`      | `domain_regex`   | `DOMAIN-REGEX,X`   |
| `keyword:X`   | `X` *(подстрока)* | `domain_keyword` | `DOMAIN-KEYWORD,X` |
| `full:X`      | `full:X`        | `domain`         | `DOMAIN,X`         |
| `domain:X`    | `domain:X`      | `domain_suffix`  | `DOMAIN-SUFFIX,X`  |
| голый домен   | `X`             | `domain_suffix`  | `DOMAIN-SUFFIX,X`  |
| IPv4[/cidr]   | поле `ip`       | `ip_cidr`        | `IP-CIDR,X/32`     |
| IPv6[/cidr]   | поле `ip`       | `ip_cidr`        | `IP-CIDR6,X/128`   |
| `ext:file:tag`   | `ext:file:tag` в `domain[]` | *(вырезается)* | *(вырезается)* |
| `extip:file:tag` | `ext:file:tag` в `ip[]`     | *(вырезается)* | *(вырезается)* |
| `geosite:X`      | `geosite:X` в `domain[]`    | *(вырезается)* | *(вырезается)* |
| `geoip:X`        | `geoip:X` в `ip[]`          | *(вырезается)* | *(вырезается)* |

> У xray нет отдельного префикса `keyword:` — голая строка в поле `domain`
> уже означает совпадение по подстроке, поэтому `keyword:X` отдаётся как `X`.

### Внешние xray `.dat` (меню routes → dat)

Xray-ядро умеет матчить домены/IP по внешним `.dat` файлам (формат
`geosite.dat`/`geoip.dat`) через токены `ext:file:tag` (домены) и `ext:file:tag`
в поле `ip` (IP). Бот сам качает `.dat` по URL на сервер и подставляет ссылки в
серверные правила `block`/`warp`.

- **routes → dat** — реестр источников. Формат записи: `name.dat:URL`, напр.
  `dlc.dat:https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat`.
  Несколько — по одному на строку. Кнопка **🔄 обновить** перекачивает все `.dat`.
  В **⏱ auto update** выбирается расписание: выкл., 1/6/12 часов или 1/3/7 дней.
  Меню показывает дату и время последнего успешного обновления и следующего
  запуска. Планировщик использует условный запрос (ETag / Last-Modified): если
  источник отвечает `304 Not Modified`, файл не качается вовсе. xray
  перезапускается только когда содержимое `.dat` реально изменилось.
- В списках **block**/**warp** ссылайтесь на категории: `ext:dlc.dat:github`
  (домены) или `extip:zkeenip.dat:akamai` (IP).
- Работает **только на сервере** (block/warp применяются серверным ядром xray).
  В клиентские подписки (xray/sing-box/mihomo) `ext:`/`extip:` не попадают — у
  клиента этих `.dat` нет; для клиента используйте `geosite:`/`geoip:` вручную в
  шаблоне. `includelist`(domains)/`subnetlist` префиксы `.dat` не поддерживают.

**Настройка сервера — не требуется.** Бот кладёт `.dat` в общий каталог
`/logs/geodata` (виден контейнеру `xr`) и сам задаёт ядру `XRAY_LOCATION_ASSET=/logs/geodata`
при каждом старте xray (`restartXray` и `scripts/start_xray.sh`). Правки
`override.env`/пересоздание контейнера не нужны. Guard дополнительно не пишет ссылку
`ext:`/`extip:` в серверный конфиг, пока сам `.dat` не скачан, — ядро не падает.

### `full:` — полный (точный) домен

`full:X` матчит **только сам домен X целиком**, без поддоменов. Нужен, когда
правило должно сработать ровно для одного хоста.

```
full:example.com
```
- ✅ `example.com`
- ❌ `www.example.com` — это поддомен, не совпадает
- ❌ `example.com.evil.net`

Транслируется: xray `full:example.com` · sing-box `domain` · mihomo `DOMAIN`.

### `domain:` и голый домен — домен-суффикс

`domain:X` матчит **сам домен и все его поддомены** — на всех трёх движках
одинаково.

```
domain:vk.com
```
- ✅ `vk.com`, ✅ `m.vk.com`, ✅ `sun9-1.userapi.vk.com`
- ❌ `notvk.com`, ❌ `vk.com.evil.net`

Голый домен без префикса (`google.com`) тоже даёт суффикс на sing-box и mihomo,
**но на xray он трактуется как подстрока** (legacy-поведение: `google.com`
совпадёт и с `google.com.cn`, и с `mygoogle.com`). Поэтому для предсказуемого
суффиксного совпадения на всех движках используйте явный префикс `domain:`.

| Ввод           | xray                | sing-box / mihomo      |
|----------------|---------------------|------------------------|
| `domain:vk.com`| суффикс (`domain:`) | суффикс (`DOMAIN-SUFFIX`) |
| `vk.com`       | **подстрока**       | суффикс (`DOMAIN-SUFFIX`) |

Транслируется: xray `domain:X` · sing-box `domain_suffix` · mihomo `DOMAIN-SUFFIX`.

### `regexp:` — обратный слэш (важно)

В регулярных выражениях ставьте **одинарный** обратный слэш: `\.`, `\w`, `\-`.
Движок — RE2 (Go), общий для xray, sing-box и mihomo.

```
regexp:.*\.ru$
regexp:^([\w\-\.]+\.)ru$
```

⚠️ Если копируете regexp из **JSON-файла**, там слэш экранирован дважды
(`"regexp:.*\\.ru$"` в JSON = один `\` в реальной строке). Вводить в бота нужно с
**одинарным** слэшем (`regexp:.*\.ru$`). Паттерн с двойным слэшем (`.*\\.ru$`) в
RE2 требует литеральный бэкслэш и не совпадёт ни с одним доменом. Бот
автоматически схлопывает случайный двойной `\\` в одинарный `\` (в доменных
именах бэкслэшей не бывает), но канонично вводить с одинарным.

### Пример: домены зоны RU через один список

```
regexp:.*\.ru$
regexp:.*\.by$
regexp:.*\.su$
regexp:.*\.xn--p1ai$
regexp:^([\w\-\.]+\.)ru$
regexp:^([\w\-\.]+\.)xn--p1ai$
regexp:^([\w\-\.]+\.)moscow$
keyword:gigabyte
keyword:ventusky
keyword:qbittorrent
keyword:reddit
```
