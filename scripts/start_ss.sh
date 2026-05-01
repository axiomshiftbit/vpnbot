cat /ssh/key.pub > /root/.ssh/authorized_keys
ssh-keygen -A
exec /usr/sbin/sshd -D -e "$@" &
sed "s/\"server_port\": [0-9]\+/\"server_port\": $SSPORT/" /config.json > change_port
cat change_port > /config.json
ssserver -v -d -c /config.json

# Cloak (ck-server) рядом с ssserver: терминирует TLS на $CKPORT и
# форвардит расшифрованный shadowsocks-трафик в ssserver на 127.0.0.1:$SSPORT.
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

tail -f /dev/null
