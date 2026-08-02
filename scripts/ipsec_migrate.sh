#!/bin/sh
# Миграции существующего swanctl.conf — ЕДИНСТВЕННЫЙ источник правды.
# Вызывается из двух мест:
#   1. start_ipsec.sh — при старте контейнера;
#   2. бот, restartIpsec() через ssh — потому что swanctl.conf попадает в
#      бэкап и importIpsecPki() кладёт его обратно ЦЕЛИКОМ. Контейнер при
#      этом не пересоздаётся, и без вызова отсюда восстановление из бэкапа
#      откатывало бы всё, что чинится ниже (ровно этот баг был найден на
#      живом сервере у OpenVPN — см. scripts/ovpn_migrate.sh).
#
# Требования: идемпотентность и никаких побочных эффектов, кроме правки
# swanctl.conf. Демоны не трогаем — перезапуск делает вызывающий.

CONF="${1:-/config/ipsec/swanctl.conf}"
LOG=/logs/ipsec.log
[ -f "$CONF" ] || exit 0

mlog() { echo "[ipsec_migrate $(date +%H:%M:%S)] $*" >> "$LOG" 2>/dev/null; }

# #1: server id обязан совпадать с SAN серверного серта. Серт перевыпускается
# автоматически при смене IP, а `id` в conn ikev2 остался бы старым — клиенты
# рвали бы соединение на несовпадении IDr.
if [ -n "$IP" ]; then
    sed -i "s|^\([[:space:]]*\)id = .* # managed-server-id\$|\1id = $IP # managed-server-id|" "$CONF"
fi

# #2: AEAD-proposals для conn ikev2 в уже существующих конфигах. Матчим ТОЧНЫЕ
# старые строки ikev2 (у l2tp они другие), поэтому conn l2tp не заденет.
sed -i "s|^\([[:space:]]*\)proposals = aes256-sha256-ecp256,aes256-sha256-modp2048,aes256-sha1-modp2048,aes128-sha256-modp2048,default\$|\1proposals = aes256gcm16-prfsha384-ecp384,aes256gcm16-prfsha256-ecp256,aes256gcm16-prfsha256-curve25519,chacha20poly1305-prfsha256-curve25519,aes256-sha256-ecp256,aes256-sha256-modp2048,aes256-sha1-modp2048,aes128-sha256-modp2048,default|" "$CONF"
sed -i "s|^\([[:space:]]*\)esp_proposals = aes256-sha256,aes256-sha1,aes128-sha256,default\$|\1esp_proposals = aes256gcm16-ecp384,aes256gcm16-ecp256,aes256gcm16,chacha20poly1305,aes256-sha256,aes256-sha1,aes128-sha256,default|" "$CONF"

# #3: L2TP и нативные клиенты. Windows/macOS/iOS в IKEv1 для L2TP предлагают
# DH group 2 (modp1024), а strongSwan его давно не предлагает по умолчанию —
# фаза 1 не согласуется и клиент просто «не подключается». Дописываем modp1024
# В КОНЕЦ: strongSwan выбирает первый подходящий из СВОЕГО списка, поэтому
# клиент, умеющий modp2048, по-прежнему получит modp2048.
# Win11 к тому же предлагает AES-GCM для ESP — добавляем AEAD в начало.
if grep -q '^[[:space:]]*proposals = aes256-sha256-modp2048,aes256-sha1-modp2048,aes128-sha1-modp2048$' "$CONF"; then
    mlog 'l2tp: add modp1024 fallback (native Windows/macOS/iOS IKEv1 clients)'
    sed -i "s|^\([[:space:]]*\)proposals = aes256-sha256-modp2048,aes256-sha1-modp2048,aes128-sha1-modp2048\$|\1proposals = aes256-sha256-modp2048,aes256-sha1-modp2048,aes128-sha1-modp2048,aes256-sha256-modp1024,aes256-sha1-modp1024,aes128-sha1-modp1024|" "$CONF"
fi
sed -i "s|^\([[:space:]]*\)esp_proposals = aes256-sha256,aes256-sha1,aes128-sha1\$|\1esp_proposals = aes256gcm16,aes128gcm16,aes256-sha256,aes256-sha1,aes128-sha1|" "$CONF"

# #4: updown-хук для журнала подключений IKEv2. У IKEv2 нет ppp-хуков, поэтому
# без него в меню бота не было ни «был в сети», ни истории — в отличие от L2TP
# и OpenVPN. Якорь `dpd_action = clear` уникален: он есть только у conn ikev2.
if ! grep -q '^[[:space:]]*updown = /etc/ipsec-updown.sh$' "$CONF"; then
    if grep -q '^[[:space:]]*dpd_action = clear$' "$CONF"; then
        mlog 'ikev2: enable updown hook (connection log)'
        sed -i '/^[[:space:]]*dpd_action = clear$/a\                updown = /etc/ipsec-updown.sh' "$CONF"
    fi
fi

exit 0
