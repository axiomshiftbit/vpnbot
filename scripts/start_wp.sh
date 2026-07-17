#!/bin/bash
set -e

cat /ssh/key.pub > /root/.ssh/authorized_keys
ssh-keygen -A
exec /usr/sbin/sshd -D -e "$@" &

WGCF_DIR="/etc/warp"
WGCF_CONF="$WGCF_DIR/wgcf-profile.conf"
WGCF_TOML="$WGCF_DIR/wgcf-account.toml"
SOCKS_PORT="${SOCKS_PORT:-1080}"

WARP_LICENSE_KEY=$(cat /config/pac.json | jq -r '.warp // empty')

mkdir -p "$WGCF_DIR"
cd "$WGCF_DIR"

# wgcf ходит в API Cloudflare, а сеть на старте контейнера может быть ещё не
# готова — все вызовы wgcf идут с ретраями (4 попытки, бэкофф 5/15/30с).
retry() {
    local delay
    for delay in 5 15 30; do
        "$@" && return 0
        echo "[warp] '$*' failed, retry in ${delay}s..."
        sleep "$delay"
    done
    "$@"
}

# Профиль wgcf-profile.conf — единственное, что нужно wg-quick для подъёма
# туннеля. Аккаунт wgcf-account.toml нужен лишь чтобы СГЕНЕРИРОВАТЬ профиль.
# Раньше оба шага (register и generate) сидели под одним условием
# `[ ! -f profile.conf ]`. Когда аккаунт уже был, а профиль пропадал (частый
# кейс после ручной пересборки: named-volume vpnbot_warp сохраняет
# account.toml, но profile.conf в нём не оказывалось), скрипт всё равно шёл
# регистрироваться, `wgcf register` падал с "existing account detected", а
# из-за set -e умирал весь скрипт → контейнер в креш-луп (off/красный).
# Поэтому условия РАЗДЕЛЕНЫ и теперь независимы:
#   1) регистрируем аккаунт, только если его нет;
#   2) генерируем профиль, только если его нет (в т.ч. восстанавливаем
#      пропавший профиль из уже существующего аккаунта — чинит случай рабочего сервера).
if [ ! -f "$WGCF_TOML" ]; then
    echo "[warp] Registering WARP account..."
    retry wgcf register --accept-tos
    if [ -n "$WARP_LICENSE_KEY" ]; then
        echo "[warp] Applying license key..."
        # Заменяем license_key в wgcf-account.toml на WARP_LICENSE_KEY
        if grep -q '^license_key' "$WGCF_TOML"; then
            sed -i "s/^license_key.*/license_key = \"$WARP_LICENSE_KEY\"/" "$WGCF_TOML"
        fi
        # Провал update (невалидный/исчерпанный ключ) НЕ фатален: иначе скрипт
        # умирал до generate, рестартился, на втором проходе блок пропускался
        # (toml уже есть) — и warp молча поднимался free-tier. Лучше явный
        # WARNING в лог и тот же free-tier без лишнего краш-цикла.
        retry wgcf update || \
            echo "[warp] WARNING: wgcf update failed — license key NOT applied, continuing free tier"
    fi
fi

if [ ! -f "$WGCF_CONF" ]; then
    echo "[warp] Generating WireGuard profile..."
    retry wgcf generate
fi

# Фиксапы профиля (IPv6 из списков, DNS-строка, PersistentKeepalive) — общий
# с кнопкой «set key» бота скрипт, правки только в warp_fixup.sh. Выполняется
# БЕЗУСЛОВНО при каждом старте, а не при генерации: профиль обычно уже лежит
# в named-volume, и блок генерации выше не выполняется.
sh /warp_fixup.sh

echo "[warp] Starting WireGuard (WARP)..."
# best-effort down: чистит хвосты (интерфейс/маршруты) после нештатного рестарта
wg-quick down "$WGCF_CONF" 2>/dev/null || true
wg-quick up "$WGCF_CONF"

# DNS контейнера — через туннель. Пишем напрямую, без resolvconf (он в docker
# не работает, см. выше). 1.1.1.1 доступен и БЕЗ туннеля, поэтому резолв
# endpoint'а (engage.cloudflareclient.com) при пере-поднятии не ломается.
printf 'nameserver 1.1.1.1\nnameserver 1.0.0.1\n' > /etc/resolv.conf

echo "[warp] Starting microsocks on port $SOCKS_PORT..."
microsocks -p "$SOCKS_PORT" &
MS_PID=$!

# ---- watchdog ----
# Раз в 60с — warp_probe.sh (общий с healthcheck'ом): trace Cloudflare через
# socks5h должен ответить warp=on|plus, а при отсутствии curl в образе
# (stale/апстримный) — fallback на возраст handshake. 3 подряд провала →
# пере-поднимаем туннель (свежий handshake + пере-резолв endpoint). Если и
# после 3 пере-поднятий подряд не ожил — exit 1: контейнер перезапустит
# restart-политика (unless-stopped в compose), это чинит и умерший sshd/т.п.
# Профиль и аккаунт НЕ трогаем: авто-перегенерация при ложном срабатывании
# потеряла бы аккаунт с license key.
set +e
FAILS=0
BOUNCES=0
while true; do
    sleep 60
    if ! kill -0 "$MS_PID" 2>/dev/null; then
        echo "[warp] microsocks died — restarting..."
        microsocks -p "$SOCKS_PORT" &
        MS_PID=$!
    fi
    if sh /warp_probe.sh; then
        FAILS=0
        BOUNCES=0
        continue
    fi
    FAILS=$((FAILS + 1))
    echo "[warp] health check failed ($FAILS/3)"
    if [ "$FAILS" -ge 3 ]; then
        BOUNCES=$((BOUNCES + 1))
        if [ "$BOUNCES" -gt 3 ]; then
            echo "[warp] tunnel did not recover after 3 restarts — exiting for container restart"
            exit 1
        fi
        echo "[warp] restarting tunnel (bounce $BOUNCES/3)..."
        wg-quick down "$WGCF_CONF" 2>/dev/null
        wg-quick up "$WGCF_CONF"
        FAILS=0
    fi
done
