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
if [ -f /config/ckserver.json ] && [ "$(jq -r '.Enabled // 0' /config/ckserver.json 2>/dev/null)" = "1" ]; then
    mkdir -p /logs
    jq 'del(.Enabled)' /config/ckserver.json > /tmp/ckserver.json
    ck-server -c /tmp/ckserver.json >>/logs/ck-server.log 2>&1 &
fi

tail -f /dev/null
