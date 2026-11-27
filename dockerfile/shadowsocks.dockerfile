ARG image=alpine:3.24
ARG RUST_VERSION=1.100.0
ARG CARGO_AUDITABLE_VERSION=0.7.8
ARG PROTOCOL_GO_VERSION=1.27.4
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

FROM rust:${RUST_VERSION}-alpine AS ss_build
ARG SS_RUST_VERSION=v1.25.0
ARG RUST_VERSION
ARG CARGO_AUDITABLE_VERSION
ENV RUSTUP_TOOLCHAIN=${RUST_VERSION} CARGO_NET_RETRY=5 CARGO_BUILD_JOBS=2 \
    RUSTFLAGS="-C target-feature=+crt-static -C panic=abort"
RUN apk add --no-cache build-base cmake perl pkgconf linux-headers curl binutils \
    && RUSTFLAGS="-C target-feature=-crt-static" cargo install --locked cargo-auditable --version "=${CARGO_AUDITABLE_VERSION}"
COPY dockerfile/sources.sha256 /sources.sha256
COPY dockerfile/download-file.sh /build-tools/download-file.sh
WORKDIR /rust-source
RUN ref=$(awk -v key="shadowsocks-rust-commit/${SS_RUST_VERSION}" '$2 == key {print $1}' /sources.sha256) \
    && test "${#ref}" = 40 \
    && sh /build-tools/download-file.sh "https://codeload.github.com/shadowsocks/shadowsocks-rust/tar.gz/$ref" source.tar.gz \
    && awk -v key="shadowsocks-rust-source/${SS_RUST_VERSION}" '$2 == key {print $1 "  source.tar.gz"}' /sources.sha256 | sha256sum -c - \
    && tar -xzf source.tar.gz --strip-components=1 && rm source.tar.gz \
    # Cargo.lock выпуска v1.25.0 держит hickory-resolver 0.26.1 (GHSA-5j98-2g5x-46v6,
    # GHSA-6w6g-hm98-mhgm, HIGH). Новее выпуска нет: поднимаем только семейство
    # hickory до исправленной 0.26.2 (resolver требует proto/net той же версии) и
    # сверяем весь итоговый lock с суммой shadowsocks-rust-lock/. С новым
    # SS_RUST_VERSION строку пересмотреть: лишний подъём даст другую сумму.
    && for crate in hickory-proto hickory-net hickory-resolver; do cargo update -p $crate --precise 0.26.2; done \
    && awk -v key="shadowsocks-rust-lock/${SS_RUST_VERSION}" '$2 == key {print $1 "  Cargo.lock"}' /sources.sha256 | sha256sum -c - \
    && sha256sum Cargo.lock > /tmp/cargo-lock.sha256 \
    && cargo auditable build --locked --release --target x86_64-unknown-linux-musl --features full --bins \
    && sha256sum -c /tmp/cargo-lock.sha256 \
    && mkdir /out \
    && for binary in sslocal ssserver ssmanager ssservice ssurl; do \
         strip target/x86_64-unknown-linux-musl/release/$binary; readelf -S target/x86_64-unknown-linux-musl/release/$binary | grep -q '\.dep-v0'; \
         cp target/x86_64-unknown-linux-musl/release/$binary /out/; \
       done

FROM $image
COPY --from=plugins /out/ /usr/bin/
COPY --from=ss_build /out/ /usr/bin/
COPY --from=ss_build /rust-source/Cargo.lock /usr/local/share/shadowsocks-rust/Cargo.lock

# ── Версии (задаются в .env, пробрасываются через args в compose) ─────────────
# Раньше все четыре компонента тянулись через releases/latest: пересборка молча
# давала другой набор бинарей, откатиться было нельзя, а понять, что стоит в
# контейнере, можно было только зайдя в него руками.
#
# shadowsocks-rust собирается выше из исходников закреплённого коммита
# (сумма архива в sources.sha256) через cargo auditable: зависимости Rust
# видит сканер образа. Пустые значения версии не допускаются.
ARG SS_RUST_VERSION=v1.25.0
ARG V2RAY_PLUGIN_VERSION=v5.49.0
ARG CLOAK_VERSION=v2.12.0
ARG SIMPLE_TLS_VERSION=v0.8.0

RUN set -eux; \
    apk upgrade --no-cache; \
    apk add --no-cache openssh jq; \
    mkdir /root/.ssh; \
    # sanity: все четыре бинаря на месте и запускаются — иначе битая сборка
    # всплыла бы только в рантайме (ср. `caddy version` в naive.dockerfile)
    ssserver --version | grep -F "${SS_RUST_VERSION#v}"; \
    v2ray-plugin -version | head -1; \
    ck-server -v; \
    simple-tls -v
ENV ENV="/root/.ashrc"
