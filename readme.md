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
| *(без префикса)*| домен-суффикс (как раньше)          | `google.com`               |
| *(IPv4[/cidr])* | IP-адрес / подсеть                  | `1.2.3.4`, `10.0.0.0/24`   |

Домены (кроме `regexp:`/`keyword:`) автоматически приводятся к punycode
(`domain:пример.рф` → `domain:xn--e1afmkfd.xn--p1ai`).

### Во что транслируется

| Ввод          | xray `domain[]` | sing-box         | mihomo/clash       |
|---------------|-----------------|------------------|--------------------|
| `regexp:X`    | `regexp:X`      | `domain_regex`   | `DOMAIN-REGEX,X`   |
| `keyword:X`   | `X` *(подстрока)* | `domain_keyword` | `DOMAIN-KEYWORD,X` |
| `full:X`      | `full:X`        | `domain`         | `DOMAIN,X`         |
| `domain:X`    | `domain:X`      | `domain_suffix`  | `DOMAIN-SUFFIX,X`  |
| голый домен   | `X`             | `domain_suffix`  | `DOMAIN-SUFFIX,X`  |
| IPv4[/cidr]   | поле `ip`       | `ip_cidr`        | `IP-CIDR,X/32`     |

> У xray нет отдельного префикса `keyword:` — голая строка в поле `domain`
> уже означает совпадение по подстроке, поэтому `keyword:X` отдаётся как `X`.

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
