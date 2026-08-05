ARG image
FROM $image

# Пины версий (задаются в .env, пробрасываются через args в compose).
# amneziawg-go с v3.0.3 требует go >= 1.24.4 — Go ставится пакетом из edge
# в .build-deps и удаляется после сборки (раньше golang:1.22.3-alpine
# копировался в образ целиком и оставался в рантайме).
#
# v3.0.20260805 обязателен для 3.0 с ContentPaddingAddition: до него keepalive
# опознавался по длине пакета (send.go `len(elem.packet) != MessageKeepaliveSize`,
# receive.go `len(elem.packet) == 0`), а паддинг эту длину меняет — keepalive
# считались данными и наоборот («fix: keepalives are ignored»).
ARG AWG_GO_VERSION=v3.0.20260805
ARG AWG_TOOLS_VERSION=v3.0.20260805
ARG WGCF_VERSION=v2.2.32
ARG TUN2SOCKS_VERSION=v2.6.0

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
    git clone --depth 1 https://github.com/rofl0r/microsocks; \
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
