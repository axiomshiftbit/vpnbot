telegram bot to manage servers (inside the bot)

- VLESS (Reality OR Websocket)
- NaiveProxy
- OpenConnect
- Wireguard
- Amnezia
- AdguardHome
- MTProto
- PAC
- automatic ssl

---
environment: ubuntu 22.04/24.04, debian 11/12

## Install:

Репозиторий приватный — установка возможна только с вашим GitHub-токеном
(fine-grained PAT, доступ только к `axiomshiftbit/vpnbot`, права `Contents: Read`).
Без токена ни ссылка, ни клонирование не работают, и сам репозиторий другим не виден.

Сохраните токен в переменной (держите в секрете):
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
