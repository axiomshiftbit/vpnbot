ARG image=alpine:3.23
FROM $image

# Пины версий (задаются в .env, пробрасываются через args в compose).
# amneziawg-go с v3.0.3 требует go >= 1.24.4 — Go ставится пакетом из edge
# в .build-deps и удаляется после сборки (раньше golang:1.22.3-alpine
# копировался в образ целиком и оставался в рантайме).
#
# v3.0.20260805 обязателен для 3.0 с ContentPaddingAddition: до него keepalive
# опознавался по длине пакета (send.go `len(elem.packet) != MessageKeepaliveSize`,
# receive.go `len(elem.packet) == 0`), а паддинг эту длину меняет — keepalive
# считались данными и наоборот («fix: keepalives are ignored»). Условие остаётся
# в силе и для 3.1 — она строго новее.
#
# AWG_GO_VERSION и AWG_TOOLS_VERSION НЕ обязаны совпадать по тегу-дате: апстрим
# ведёт их независимыми релизами, и на 3.1 разъехались (go ушёл на три патча
# вперёд от первого тега tools). AWG_TOOLS_VERSION v3.1.20260812 — первый тег с
# парсингом RandomTrailers/DisableCookies (`feat: add awg 3.1 params`), новее
# пока не выходило.
#
# У AWG_GO_VERSION два последовательных порога, оба завязаны на тумблеры бота:
#
#   >= v3.1.20260814 — в v3.1.20260812/.813 баг переполнения буфера в
#   HandshakeCookie (длину трейлера перепутали с capacity) даёт панику рантайма
#   amneziawg-go при включённом тумблере RandomTrailers («fix: wrong behavior
#   and runtime panic while RandomTrailers is used»).
#
#   >= v3.1.20260828 — до него тумблер DisableCookies ломал подключение под
#   нагрузкой: отправку cookie он глушил, а проверку MAC2 в RoutineHandshake
#   оставлял включённой (receive.go: `if device.IsUnderLoad()`), то есть клиент
#   обязан был предъявить cookie, которого ему принципиально не могли выдать, и
#   handshake не проходил, пока держится нагрузка («fix: disable the whole
#   underload if DisableCookies is on»). Второй фикс того же тега считает
#   ContentPaddingAddition от наблюдаемого окна UDP пира, а не от MTU, и
#   учитывает в размере пакета служебный заголовок («fix: use udp window for
#   RandomPaddingAddition») — паддинг перестаёт выбиваться за размер, который
#   этот путь уже доказал.
ARG AWG_GO_VERSION=v3.1.20260828
ARG AWG_TOOLS_VERSION=v3.1.20260812
ARG WGCF_VERSION=v2.3.0
ARG TUN2SOCKS_VERSION=v2.7.0
# microsocks пинится коммитом, а не тегом: последний тег v1.0.5 от 2024-05-24,
# master с тех пор ушёл на два коммита вперёд, и клонировался как раз master —
# то есть образ менялся молча от пересборки к пересборке. Приём тот же, что у
# TT_REF. Обновлять: сменить MICROSOCKS_REF в .env и закоммитить.
ARG MICROSOCKS_REF=96bf8a87408c36951b73b7957687f42904e620f8

# Инвалидация кеша apk-слоя: передайте новое значение, чтобы пересборка
# реально сходила в edge за свежими wireguard-tools/openssh без --no-cache.
#   docker compose build --build-arg APK_REFRESH=$(date +%F) wg
# Дефолт статичный — обычный build переиспользует кеш.
ARG APK_REFRESH=2026-07-04

RUN set -eux; \
    echo "apk refresh token: $APK_REFRESH"; \
    printf '%s\n' \
        'https://dl-cdn.alpinelinux.org/alpine/edge/main' \
        'https://dl-cdn.alpinelinux.org/alpine/edge/community' \
        > /etc/apk/repositories; \
    apk update; \
    apk upgrade --no-cache --available; \
    apk add --no-cache \
        iproute2 \
        iptables \
        xtables-addons \
        openssh \
        wireguard-tools \
        curl \
        jq \
        bash \
        htop; \
    apk add --no-cache --virtual .build-deps \
        alpine-sdk \
        git \
        go \
        linux-headers; \
    git clone --depth 1 --branch ${AWG_GO_VERSION} https://github.com/amnezia-vpn/amneziawg-go; \
    git clone --depth 1 --branch ${AWG_TOOLS_VERSION} https://github.com/amnezia-vpn/amneziawg-tools.git; \
    mkdir -p /microsocks; \
    cd /microsocks; \
    git init -q .; \
    git remote add origin https://github.com/rofl0r/microsocks.git; \
    git fetch -q --depth 1 origin "${MICROSOCKS_REF}"; \
    git checkout -q FETCH_HEAD; \
    cd /amneziawg-go; \
    make install; \
    cd /amneziawg-tools/src; \
    make install WITH_WGQUICK=yes; \
    cd /microsocks; \
    make; \
    mv microsocks /usr/bin/microsocks; \
    cd /; \
    rm -rf /amneziawg-go /amneziawg-tools /microsocks /root/go /root/.cache; \
    apk del .build-deps; \
    mkdir -p /root/.ssh; \
    cd /tmp; \
    wget -O tun2socks.zip https://github.com/xjasonlyu/tun2socks/releases/download/${TUN2SOCKS_VERSION}/tun2socks-linux-amd64.zip; \
    unzip tun2socks.zip; \
    mv tun2socks-linux-amd64 /usr/bin/tun2socks; \
    chmod +x /usr/bin/tun2socks; \
    rm -f tun2socks.zip; \
    wget -O /usr/bin/wgcf https://github.com/ViRb3/wgcf/releases/download/${WGCF_VERSION}/wgcf_${WGCF_VERSION#v}_linux_amd64; \
    chmod +x /usr/bin/wgcf; \
    # у wgcf нет `--version`/`version` — версию для меню бота (warpVersion)
    # фиксируем в файл на этапе сборки
    printf '%s\n' "${WGCF_VERSION#v}" > /etc/wgcf_version; \
    sed -i 's/sysctl -q net\.ipv4\.conf\.all\.src_valid_mark=1/echo "skip sysctl src_valid_mark"/' $(which wg-quick); \
    # sanity: все бинарники, которые зовут бот и start_wg.sh, на месте
    # (без пайпов — код возврата не маскируется, set -e уронит сборку)
    command -v awg; \
    command -v awg-quick; \
    command -v amneziawg-go; \
    command -v wg-quick; \
    command -v tun2socks; \
    command -v wgcf; \
    command -v microsocks; \
    wg --version; \
    awg --version
