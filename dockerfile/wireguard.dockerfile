ARG image=alpine:3.24
ARG PROTOCOL_GO_VERSION=1.27.2
FROM golang:${PROTOCOL_GO_VERSION}-alpine AS helpers
ARG WGCF_VERSION=v2.3.0
ARG TUN2SOCKS_VERSION=v2.7.0
ARG AWG_GO_VERSION=v3.1.20260828
ARG XRAY_VERSION=v26.9.30
RUN apk add --no-cache ca-certificates curl git jq
COPY dockerfile/go-*.sh dockerfile/go-sources.sha256 dockerfile/build-xray.sh /build-tools/
RUN sh /build-tools/build-xray.sh XTLS/Xray-core "$XRAY_VERSION" /out/warp-socks
RUN sh /build-tools/go-source.sh ViRb3/wgcf "$WGCF_VERSION" /wgcf \
    && cd /wgcf && sh /build-tools/go-security.sh \
    && CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o /out/wgcf .
RUN sh /build-tools/go-source.sh xjasonlyu/tun2socks "$TUN2SOCKS_VERSION" /tun2socks \
    && cd /tun2socks && sh /build-tools/go-security.sh \
    && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X github.com/xjasonlyu/tun2socks/v2/internal/version.Version=$TUN2SOCKS_VERSION" -o /out/tun2socks .

# Go стабильной Alpine может отставать от требований исправленных модулей.
# Компилятор закреплён отдельно и не попадает в рабочий образ.
RUN sh /build-tools/go-source.sh amnezia-vpn/amneziawg-go "$AWG_GO_VERSION" /amneziawg-go \
    && cd /amneziawg-go && sh /build-tools/go-security.sh \
    && CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o /out/amneziawg-go .

FROM $image
COPY --from=helpers /out/ /usr/bin/

# Пины версий (задаются в .env, пробрасываются через args в compose).
# amneziawg-go собирается в helpers с закреплённым Go; runtime использует
# только пакеты стабильной Alpine, без смешивания репозиториев.
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
ARG AWG_TOOLS_VERSION=v3.1.20260812
ARG WGCF_VERSION=v2.3.0
ARG TUN2SOCKS_VERSION=v2.7.0

# Инвалидация кеша apk-слоя: передайте новое значение, чтобы пересборка
# обновила пакеты стабильной ветки: wireguard-tools/openssh без --no-cache.
#   docker compose build --build-arg APK_REFRESH=$(date +%F) wg
# Дефолт статичный — обычный build переиспользует кеш.
ARG APK_REFRESH=2026-10-05

RUN set -eux; \
    echo "apk refresh token: $APK_REFRESH"; \
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
        linux-headers; \
    git clone --depth 1 --branch ${AWG_TOOLS_VERSION} https://github.com/amnezia-vpn/amneziawg-tools.git; \
    cd /amneziawg-tools/src; \
    make install WITH_WGQUICK=yes; \
    cd /; \
    rm -rf /amneziawg-tools /root/go /root/.cache; \
    apk del .build-deps; \
    mkdir -p /root/.ssh; \
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
    command -v warp-socks; \
    wg --version; \
    awg --version
