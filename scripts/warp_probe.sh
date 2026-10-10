#!/bin/sh
# Проверка живости WARP: exit 0 = здоров. ОБЩАЯ для watchdog'а в start_wp.sh
# и healthcheck'а контейнера (docker-compose.yml).
SOCKS_PORT="${SOCKS_PORT:-1080}"

# WARP выключен кнопкой бота: туннеля и не должно быть. Для healthcheck это
# здоровое состояние — иначе контейнер числился бы unhealthy всё время, пока
# выключатель стоит в «off». Сторож пробу в этом состоянии не вызывает.
if [ "$(jq -r '.warpoff // empty' /config/pac.json 2>/dev/null)" = "1" ]; then
    exit 0
fi

trace() {
    curl -m 6 -s -x "$1://127.0.0.1:$SOCKS_PORT" "$2" 2>/dev/null
}

if command -v curl >/dev/null 2>&1; then
    # Вся цепочка: socks → DNS (socks5h, имя разрешает прокси) → туннель WARP.
    answer=$(trace socks5h https://www.cloudflare.com/cdn-cgi/trace)
    if [ -n "$answer" ]; then
        # Ответ получен — ему и верим, в том числе ответу «не WARP».
        printf '%s\n' "$answer" | grep -qE '^warp=(on|plus)'
    else
        # Ответа нет вовсе: медленное соединение или сбой разрешения имени.
        # Вторая попытка идёт по адресу, без DNS — один такой сбой не должен
        # считаться отказом туннеля: три «отказа» подряд рвут рабочий туннель у
        # всех пользователей. Две попытки по 6 с укладываются в 15 с,
        # отведённые healthcheck в compose.
        trace socks5 https://1.1.1.1/cdn-cgi/trace | grep -qE '^warp=(on|plus)'
    fi
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
