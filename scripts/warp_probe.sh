#!/bin/sh
# Проверка живости WARP: exit 0 = здоров. ОБЩАЯ для watchdog'а в start_wp.sh
# и healthcheck'а контейнера (docker-compose.yml).
SOCKS_PORT="${SOCKS_PORT:-1080}"

if command -v curl >/dev/null 2>&1; then
    # вся цепочка: socks → DNS (socks5h, резолвит microsocks) → туннель WARP
    curl -m 10 -s -x "socks5h://127.0.0.1:$SOCKS_PORT" \
        https://www.cloudflare.com/cdn-cgi/trace | grep -qE '^warp=(on|plus)'
else
    # curl'а нет: stale-образ, собранный до его добавления в
    # wireguard.dockerfile, или апстримный образ с Docker Hub. Fallback —
    # возраст последнего handshake: с PersistentKeepalive=25 рукопожатие
    # обновляется каждые ~2 мин, 300с — с запасом. Без fallback'а watchdog
    # считал бы ЗДОРОВЫЙ туннель мёртвым (curl: not found) и бесконечно
    # рвал его bounce'ами и рестартами контейнера.
    # Берём самое свежее рукопожатие среди всех пиров (одна строка), иначе при
    # нескольких пирах $hs многострочный и `[ "$hs" -gt 0 ]` падает.
    hs=$(wg show wgcf-profile latest-handshakes 2>/dev/null | awk '{print $2}' | sort -n | tail -1)
    [ -n "$hs" ] && [ "$hs" -gt 0 ] && [ $(( $(date +%s) - hs )) -lt 300 ]
fi
