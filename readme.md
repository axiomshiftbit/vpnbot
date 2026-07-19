telegram bot to manage servers (inside the bot)

- VLESS (Reality OR Websocket)
- NaiveProxy
- OpenConnect
- Wireguard
- Amnezia
- AdguardHome
- TeleMT (MTProto)
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
  | GH_TOKEN="$GH_TOKEN" bash -s YOUR_TELEGRAM_BOT_KEY master
```
development (dev):
```shell
curl -fsSL -H "Authorization: Bearer $GH_TOKEN" -H "Accept: application/vnd.github.raw" \
  "https://api.github.com/repos/axiomshiftbit/vpnbot/contents/scripts/init.sh?ref=dev" \
  | GH_TOKEN="$GH_TOKEN" bash -s YOUR_TELEGRAM_BOT_KEY dev
```
Установка из архива (offline, токен не нужен) — положите `vpnbot.zip` рядом
со скриптом и запустите `bash init.sh YOUR_TELEGRAM_BOT_KEY master`.
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
