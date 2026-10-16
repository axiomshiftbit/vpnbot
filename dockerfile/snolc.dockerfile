# snolc 0.0.4 с исправлениями VPNBot: ядро и модули из закреплённых исходников.
# Версию компилятора держим в синхроне с rust-toolchain.toml апстрима (1.98.1).
ARG RUST_VERSION=1.98.1
ARG image=alpine:3.24

# Исходники с исправлениями и все зависимости Cargo готовятся один раз; обе
# сборки ниже идут без сети.
FROM rust:${RUST_VERSION}-alpine AS sources
ARG RUST_VERSION
RUN apk add --no-cache patch
ENV RUSTUP_TOOLCHAIN=${RUST_VERSION}
WORKDIR /build
COPY dockerfile/snolc-sources/snolc-source.tar.gz /tmp/core.tar.gz
COPY dockerfile/snolc-core.patch /tmp/core.patch
RUN echo '945144323ac0c1c71cf2a3ea6a5ef082b101baa63ca0a679f357df2130991e0d  /tmp/core.tar.gz' | sha256sum -c - \
    && tar xzf /tmp/core.tar.gz --strip-components=1 \
    && patch -p1 --fuzz=0 < /tmp/core.patch \
    && cargo fetch --locked
WORKDIR /modules
COPY dockerfile/snolc-sources/modules-source.tar.gz /tmp/modules.tar.gz
COPY dockerfile/snolc-modules.patch /tmp/modules.patch
RUN echo 'f07ae9949c89875365bf65d4eb01d737fc8307f323ac24e4d44af4579c1e3c7e  /tmp/modules.tar.gz' | sha256sum -c - \
    && tar xzf /tmp/modules.tar.gz --strip-components=1 \
    && patch -p1 --fuzz=0 < /tmp/modules.patch \
    && cargo fetch --locked

# Сервер собирается под Alpine (musl) целиком из исходников: выпуски модулей
# upstream собраны под glibc и в musl-ядро не загружаются. -crt-static: модули —
# динамические библиотеки (cdylib), статическая программа на musl их не загрузит.
FROM rust:${RUST_VERSION}-alpine AS server
ARG RUST_VERSION
RUN apk add --no-cache build-base
ENV RUSTUP_TOOLCHAIN=${RUST_VERSION} \
    RUSTFLAGS="-C target-feature=-crt-static" \
    CARGO_NET_OFFLINE=true
COPY --from=sources /usr/local/cargo/registry /usr/local/cargo/registry
COPY --from=sources /build /build
COPY --from=sources /modules /modules
WORKDIR /build
RUN cargo test --locked --release --workspace \
    && cargo build --locked --release -p snolc-cli
WORKDIR /modules
RUN cargo test --locked --release -p snolc-adapter-direct -p snolc-adapter-socks5 -p snolc-carrier-ssh \
        -p snolc-protection-noise -p snolc-policy-local \
    && cargo build --locked --release -p snolc-adapter-direct -p snolc-carrier-ssh -p snolc-protection-noise -p snolc-policy-local \
    && mkdir /out && cp /build/target/release/snolc target/release/libsnolc_adapter_direct.so target/release/libsnolc_carrier_ssh.so \
        target/release/libsnolc_protection_noise.so target/release/libsnolc_policy_local.so /out/

# Клиентский комплект — для Linux x86_64 с glibc, как у выпусков upstream.
# Эта стадия только собирает файлы для ZIP клиента: в образе они не
# запускаются, а сам образ остаётся на Alpine. Тесты того же кода прошли выше.
FROM rust:${RUST_VERSION}-slim-trixie AS client
ARG RUST_VERSION
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
ENV RUSTUP_TOOLCHAIN=${RUST_VERSION} \
    CARGO_NET_OFFLINE=true
COPY --from=sources /usr/local/cargo/registry /usr/local/cargo/registry
COPY --from=sources /build /build
COPY --from=sources /modules /modules
WORKDIR /build
RUN cargo build --locked --release -p snolc-cli
WORKDIR /modules
RUN cargo build --locked --release -p snolc-adapter-socks5 -p snolc-policy-local \
    && mkdir /out && cp /build/target/release/snolc target/release/libsnolc_adapter_socks5.so target/release/libsnolc_policy_local.so /out/

FROM $image
LABEL io.vpnbot.snolc.version="0.0.4+vpnbot.3"
# libgcc: размотка стека Rust при динамической сборке на musl.
RUN apk upgrade --no-cache --available \
    && apk add --no-cache libgcc python3 py3-cryptography
COPY app/snolc /snolc
# Результаты сборки подключаются только на время команды: скопированные во
# временный каталог и удалённые файлы остались бы в нижнем слое образа.
RUN --mount=type=bind,from=server,source=/out,target=/mnt/server \
    --mount=type=bind,from=client,source=/out,target=/mnt/client \
    mkdir -p /opt/snolc \
    && python3 /snolc/build_patches.py /mnt/client/snolc /mnt/client/libsnolc_adapter_socks5.so /mnt/client/libsnolc_policy_local.so /opt/snolc/client-patches.zip \
    && PYTHONPATH=/snolc python3 -c 'from snolc_config import install; install("/opt/snolc/runtime", server=True, built="/mnt/server")' \
    && test "$(/opt/snolc/runtime/bin/snolc --version)" = "snolc 0.0.4+vpnbot.3 wire 1"
COPY scripts/protocol_service.py scripts/snolc_service.py /
ENV PYTHONPATH=/snolc
HEALTHCHECK --interval=15s --timeout=3s --start-period=30s --retries=3 \
    CMD python3 -c 'import json,time; s=json.load(open("/state/status.json")); assert time.time()-s["time"]<15 and s["phase"] in ("running","idle","disabled")'
ENTRYPOINT ["python3", "/snolc_service.py", "/state"]
