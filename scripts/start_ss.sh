#!/bin/sh
cat /ssh/key.pub > /root/.ssh/authorized_keys
ssh-keygen -A
# Без exec: `exec cmd &` порождает подоболочку, которую exec собой и
# заменяет, то есть это обычный фоновый запуск, но читается как «заменить
# текущий процесс» (то же пояснение есть в start_wp.sh).
/usr/sbin/sshd -D -e "$@" &
# Через временный файл, а не через полуфабрикат в корне контейнера: /config.json
# это файловый bind-mount на config/ssserver.json (там пароль SS), и редирект
# усекал бы хостовый файл ещё до записи. cat > , а не mv — инод держит mount.
tmp=$(mktemp) || exit 1
jq '.server_port = 8388 | if (.acl // "") == "" then .acl = "/config/ss.acl" else . end' /config.json > "$tmp"
[ -s "$tmp" ] && cat "$tmp" > /config.json
rm -f "$tmp"
mkdir -p /logs
nohup setsid ssserver -v -c /config.json </dev/null >>/logs/shadowsocks 2>&1 &

# Cloak (ck-server) рядом с ssserver: терминирует TLS на $CKPORT и
# форвардит расшифрованный shadowsocks-трафик в ssserver на 127.0.0.1:8388.
# Запускается только если бот включил cloak (поле "Enabled":1 в ckserver.json).
# Поле Enabled нестандартное для самого ck-server — ниже мы его игнорируем,
# потому что cloak его не понимает; используется чисто как флаг для нас.
#
# Также чистим возможные пустые AdminUID/DatabasePath: ck-server
# воспринимает их как пути и крашится сразу после bind при первом
# коннекте, не пишет ни ошибки, ни строки в лог — выглядело бы как
# "стартовал и умер" в ck-server.log.
#
# Запуск через nohup + setsid + </dev/null — чтобы ck-server пережил
# любые сигналы от шелла-родителя (busybox ash в alpine иногда
# прибивает фоновых детей при exit-фазе скрипта).
if [ -f /config/ckserver.json ] && [ "$(jq -r '.Enabled // 0' /config/ckserver.json 2>/dev/null)" = "1" ]; then
    mkdir -p /logs
    jq 'del(.Enabled)
        | if (.AdminUID // "") == "" then del(.AdminUID) else . end
        | if (.DatabasePath // "") == "" then del(.DatabasePath) else . end' \
        /config/ckserver.json > /tmp/ckserver.json

    # ck-server резолвит RedirAddr один раз на старте и падает с fatal,
    # если DNS не ответил. Контейнерный резолвер 127.0.0.11 проксирует
    # запрос в adguard (10.10.0.5), а тот при старте compose может быть
    # ещё не готов — гонка: иногда стартуем за секунды до adguard.
    # Ждём, пока имя резолвится (≤ ~30s), прежде чем поднимать ck-server.
    REDIR=$(jq -r '.RedirAddr // empty' /tmp/ckserver.json | sed 's/:[0-9]*$//')
    if [ -n "$REDIR" ]; then
        i=0
        while [ $i -lt 30 ] && ! nslookup "$REDIR" >/dev/null 2>&1; do
            i=$((i + 1))
            sleep 1
        done
    fi

    nohup setsid ck-server -c /tmp/ckserver.json </dev/null >>/logs/ck-server.log 2>&1 &
fi

# simple-tls (https://github.com/IrineSistiana/simple-tls): TLS-обёртка для SS,
# слушает на $STLSPORT и форвардит расшифрованный shadowsocks-трафик в
# ssserver на 127.0.0.1:8388. Использует тот же сертификат, что nginx:
# letsencrypt-бандл (cert_public/cert_private) если есть, иначе self-signed.
# Запускается только если /config/stlsserver.json содержит "Enabled":1.
if [ -f /config/stlsserver.json ] && [ "$(jq -r '.Enabled // 0' /config/stlsserver.json 2>/dev/null)" = "1" ]; then
    mkdir -p /logs
    if [ -s /certs/cert_public ] && [ -s /certs/cert_private ]; then
        STLS_CERT=/certs/cert_public
        STLS_KEY=/certs/cert_private
    else
        STLS_CERT=/certs/self_public
        STLS_KEY=/certs/self_private
    fi
    # 8388 жёстко: строка 4 этого же скрипта переписывает server_port в конфиге
    # именно на него, поэтому заданный SSPORT (скажем, внешний порт из
    # override.env) увёл бы апстрим simple-tls мимо живого ssserver.
    nohup setsid simple-tls -s -b ":${STLSPORT:-3443}" -d "127.0.0.1:8388" \
        -cert "$STLS_CERT" -key "$STLS_KEY" \
        </dev/null >>/logs/simple-tls.log 2>&1 &
fi

tail -f /dev/null
