ARG image=alpine:3.24
ARG PROTOCOL_GO_VERSION=1.27.3
FROM golang:${PROTOCOL_GO_VERSION}-alpine AS plugins
ARG V2RAY_PLUGIN_VERSION=v5.49.0
ARG CLOAK_VERSION=v2.12.0
ARG SIMPLE_TLS_VERSION=v0.8.0
RUN apk add --no-cache ca-certificates curl git
COPY dockerfile/go-*.sh dockerfile/download-file.sh dockerfile/go-sources.sha256 /build-tools/
RUN sh /build-tools/go-source.sh teddysun/v2ray-plugin "$V2RAY_PLUGIN_VERSION" /v2ray-plugin \
    && cd /v2ray-plugin && sh /build-tools/go-security.sh \
    && CGO_ENABLED=0 sh /build-tools/go-retry.sh go build -trimpath -ldflags '-s -w' -o /out/v2ray-plugin .
RUN sh /build-tools/go-source.sh cbeuw/Cloak "$CLOAK_VERSION" /cloak \
    && cd /cloak && sh /build-tools/go-security.sh \
    && CGO_ENABLED=0 sh /build-tools/go-retry.sh go build -trimpath -ldflags "-s -w -X main.version=${CLOAK_VERSION#v}" -o /out/ck-server ./cmd/ck-server \
    && CGO_ENABLED=0 sh /build-tools/go-retry.sh go build -trimpath -ldflags "-s -w -X main.version=${CLOAK_VERSION#v}" -o /out/ck-client ./cmd/ck-client
RUN sh /build-tools/go-source.sh IrineSistiana/simple-tls "$SIMPLE_TLS_VERSION" /simple-tls \
    && cd /simple-tls && sh /build-tools/go-security.sh \
    && CGO_ENABLED=0 sh /build-tools/go-retry.sh go build -trimpath -ldflags "-s -w -X main.version=${SIMPLE_TLS_VERSION#v}" -o /out/simple-tls .

FROM $image
COPY --from=plugins /out/ /usr/bin/

# ── Версии (задаются в .env, пробрасываются через args в compose) ─────────────
# Раньше все четыре компонента тянулись через releases/latest: пересборка молча
# давала другой набор бинарей, откатиться было нельзя, а понять, что стоит в
# контейнере, можно было только зайдя в него руками.
#
# Архив закреплён тегом и SHA-256. Пустые значения версии не допускаются.
ARG SS_RUST_VERSION=v1.25.0
ARG V2RAY_PLUGIN_VERSION=v5.49.0
ARG CLOAK_VERSION=v2.12.0
ARG SIMPLE_TLS_VERSION=v0.8.0
COPY dockerfile/sources.sha256 /sources.sha256
COPY dockerfile/download-file.sh /build-tools/download-file.sh

RUN set -eux; \
    apk upgrade --no-cache; \
    apk add --no-cache openssh git xz jq unzip curl; \
    mkdir /root/.ssh; \
    sh /build-tools/download-file.sh "https://github.com/shadowsocks/shadowsocks-rust/releases/download/${SS_RUST_VERSION}/shadowsocks-${SS_RUST_VERSION}.x86_64-unknown-linux-musl.tar.xz" shadowsocks-rust.tar.xz; \
    # Готовый бинарник: сверяем с суммой, закреплённой для этой версии.
    awk -v key="shadowsocks-rust/${SS_RUST_VERSION}" '$2 == key {print $1 "  shadowsocks-rust.tar.xz"}' /sources.sha256 | sha256sum -c -; \
    tar -xf shadowsocks-rust.tar.xz; \
    mv sslocal ssserver ssmanager ssservice ssurl /usr/bin/; \
    rm -f shadowsocks-rust.tar.xz /build-tools/download-file.sh; \
    # sanity: все четыре бинаря на месте и запускаются — иначе битая сборка
    # всплыла бы только в рантайме (ср. `caddy version` в naive.dockerfile)
    ssserver --version; \
    v2ray-plugin -version | head -1; \
    ck-server -v; \
    simple-tls -v; \
    # git/xz/unzip нужны только распаковке выше — в рантайме их не зовёт ни
    # start_ss.sh, ни бот (там из этого списка живёт только jq). Сборочные
    # утилиты в рантайм-образе — лишняя поверхность у контейнера, который
    # терминирует недоверенный клиентский трафик.
    apk del git xz unzip curl
ENV ENV="/root/.ashrc"
