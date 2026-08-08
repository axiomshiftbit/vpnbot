#!/bin/sh
# Миграции существующего /etc/openvpn/server.conf — ЕДИНСТВЕННЫЙ источник
# правды. Вызывается из двух мест:
#   1. start_ovpn.sh — при старте контейнера;
#   2. бот, restartOvpn() через ssh — потому что server.conf попадает в
#      бэкап и importOvpnPki() кладёт его обратно ЦЕЛИКОМ. Контейнер при
#      этом не пересоздаётся, и без вызова отсюда восстановление из бэкапа
#      откатывало бы все правки ниже (проверено на живом сервере: после
#      restore возвращались cipher и push "block-outside-dns").
#
# Требования: идемпотентность (запуск N раз == запуск один раз) и отсутствие
# побочных эффектов, кроме правки server.conf. Никаких запусков демонов.

SRV="${1:-/etc/openvpn/server.conf}"
[ -f "$SRV" ] || exit 0

mlog() { echo "[ovpn_migrate $(date +%H:%M:%S)] $*" >> /logs/openvpn.log 2>/dev/null; }

# Внутренний bind-порт всегда 1194: и docker-override (host:EXT -> ovpn:1194),
# и nginx upstream (#ovpn-port) целятся именно туда. Старый server.conf с
# OVPNPORT в поле port делал демон «поднятым», но недоступным снаружи.
sed -i 's/^port[[:space:]]\+[0-9]\+[[:space:]]*$/port 1194/' "$SRV"

# ecdh-curve игнорируется в OpenSSL 3.0+ с warning'ом.
sed -i '/^ecdh-curve[[:space:]]/d' "$SRV"

# management через TCP на 127.0.0.1 → unix-сокет (убирает "TCP port WITHOUT
# passwords is STRONGLY discouraged" и безопаснее).
sed -i 's|^management[[:space:]]\+127\.0\.0\.1[[:space:]]\+7505[[:space:]]*$|management /var/run/openvpn-mgmt.sock unix|' "$SRV"

# explicit-exit-notify игнорируется для --proto tcp — держим только для UDP.
if grep -qE '^proto[[:space:]]+tcp' "$SRV"; then
    sed -i '/^explicit-exit-notify[[:space:]]/d' "$SRV"
elif ! grep -qE '^explicit-exit-notify[[:space:]]' "$SRV"; then
    printf '\nexplicit-exit-notify 1\n' >> "$SRV"
fi

# #1: маркеры изоляции. Без них toggleOvpnIsolation() — молчаливый no-op, и
# кнопка «трафик между клиентами» навсегда показывает off.
if ! grep -q '^#ovpn-isolation[[:space:]]*$' "$SRV"; then
    printf '\n# Bot toggles client isolation between these markers — do not edit by hand.\n#ovpn-isolation\n#ovpn-isolation\n' >> "$SRV"
fi

# #2: без `status` файл openvpn-status.log не пишется, getOvpnStatus() отдаёт
# пусто и все клиенты в меню выглядят offline (⚪).
if ! grep -qE '^status[[:space:]]' "$SRV"; then
    printf '\nstatus /etc/openvpn/openvpn-status.log 5\n' >> "$SRV"
fi
if ! grep -qE '^status-version[[:space:]]' "$SRV"; then
    printf 'status-version 2\n' >> "$SRV"
fi

# #3: hook журнала подключений (CN + адрес клиента). Требует script-security 2.
if ! grep -qE '^script-security[[:space:]]' "$SRV"; then
    printf '\nscript-security 2\n' >> "$SRV"
fi
if ! grep -qE '^client-connect[[:space:]]' "$SRV"; then
    printf 'client-connect /etc/openvpn/connect.sh\n' >> "$SRV"
fi
if ! grep -qE '^client-disconnect[[:space:]]' "$SRV"; then
    printf 'client-disconnect /etc/openvpn/connect.sh\n' >> "$SRV"
fi

# #4: `push "block-outside-dns"` роняет ВСЕХ не-Windows клиентов — опция
# разбирается только под #ifdef _WIN32 (src/openvpn/options.c), а неизвестная
# опция в PUSH_REPLY фатальна для клиента. Убираем безусловный push и заводим
# маркеры, между которыми бот включает его по кнопке.
if ! grep -q '^#ovpn-winblockdns[[:space:]]*$' "$SRV"; then
    if grep -qE '^[[:space:]]*push[[:space:]]+"block-outside-dns"' "$SRV"; then
        mlog 'push "block-outside-dns" disabled (breaks non-Windows clients); re-enable via bot menu'
    fi
    sed -i '/^[[:space:]]*push[[:space:]]\+"block-outside-dns"/d' "$SRV"
    printf '\n# Bot toggles the Windows-only DNS-leak guard between these markers.\n#ovpn-winblockdns\n#ovpn-winblockdns\n' >> "$SRV"
fi

# #5: `cipher` в TLS-режиме игнорируется начиная с 2.6 («this option is always
# ignored in TLS mode when it comes to configuring the cipher») — только шум.
sed -i '/^[[:space:]]*cipher[[:space:]]/d' "$SRV"

# #6: 2.7 пишет «DEPRECATED OPTION: --persist-key option ignored. Keys are now
# always persisted across restarts.» — директива больше ничего не делает.
sed -i '/^[[:space:]]*persist-key[[:space:]]*$/d' "$SRV"

exit 0
