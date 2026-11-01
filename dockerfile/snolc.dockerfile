# snolc 0.0.4 с исправлениями VPNBot: ядро и модули из закреплённых исходников.
# Последний стабильный Rust. rust-toolchain.toml апстрима закрепляет 1.98.1
# (это и минимальная версия, rust-version); RUSTUP_TOOLCHAIN ниже его заменяет.
ARG RUST_VERSION=1.99.1
ARG CARGO_AUDITABLE_VERSION=0.7.7
# Закреплённый выпуск snolc (исходники в dockerfile/snolc-sources).
ARG SNOLC_VERSION=0.0.4
ARG image=alpine:3.24

# Исходники с исправлениями и все зависимости Cargo готовятся один раз; обе
# сборки ниже идут без сети.
FROM rust:${RUST_VERSION}-alpine AS sources
ARG RUST_VERSION
ARG CARGO_AUDITABLE_VERSION
RUN apk add --no-cache patch
ENV RUSTUP_TOOLCHAIN=${RUST_VERSION}
# cargo auditable вшивает в бинарники список пакетов Cargo.lock: шлюз Trivy
# видит их версии и блокирует уязвимые так же, как модули Go. Собираем тем же
# компилятором (пакет Alpine потянул бы второй, системный cargo).
RUN cargo install --locked --root /tools cargo-auditable --version "=${CARGO_AUDITABLE_VERSION}"
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
COPY --from=sources /tools/bin/cargo-auditable /usr/local/bin/
COPY --from=sources /build /build
COPY --from=sources /modules /modules
WORKDIR /build
RUN cargo test --locked --release --workspace \
    && cargo auditable build --locked --release -p snolc-cli
WORKDIR /modules
RUN cargo test --locked --release -p snolc-adapter-direct -p snolc-adapter-socks5 -p snolc-carrier-ssh \
        -p snolc-protection-noise -p snolc-policy-local \
    && cargo auditable build --locked --release -p snolc-adapter-direct -p snolc-carrier-ssh -p snolc-protection-noise -p snolc-policy-local \
    && mkdir /out && cp /build/target/release/snolc target/release/libsnolc_adapter_direct.so target/release/libsnolc_carrier_ssh.so \
        target/release/libsnolc_protection_noise.so target/release/libsnolc_policy_local.so /out/
# Модули — cdylib, cargo auditable не вшивает в них список пакетов, и Trivy их
# не видел. Пустая программа, зависящая от всех модулей сервера и клиента,
# несёт этот список: шлюз проверяет и их зависимости. Lock берётся из модулей
# офлайн и обязан остаться их подмножеством — ни одна версия не меняется.
WORKDIR /sbom
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
    && printf '%s\n' '[package]' 'name = "vpnbot-snolc-modules"' 'version = "0.0.4"' 'edition = "2024"' 'publish = false' \
        '[dependencies]' \
        'snolc-adapter-direct = { path = "/modules/modules/adapter-direct" }' \
        'snolc-adapter-socks5 = { path = "/modules/modules/adapter-socks5" }' \
        'snolc-carrier-ssh = { path = "/modules/modules/carrier-ssh" }' \
        'snolc-protection-noise = { path = "/modules/modules/protection-noise" }' \
        'snolc-policy-local = { path = "/modules/modules/policy-local" }' \
        '[workspace]' > Cargo.toml \
    && cp /modules/Cargo.lock . \
    && cargo auditable build --offline --release \
    && grep -A2 '^name = ' /modules/Cargo.lock | grep -v '^--' | paste - - - | sort > /tmp/modules.lock \
    && grep -A2 '^name = ' Cargo.lock | grep -v '^--' | paste - - - | grep -v '"vpnbot-snolc-modules"' | sort > /tmp/sbom.lock \
    && test -s /tmp/sbom.lock && test -z "$(comm -13 /tmp/modules.lock /tmp/sbom.lock)" \
    && cp target/release/vpnbot-snolc-modules /out/

# Клиентский комплект — для Linux x86_64 с glibc, как у выпусков upstream.
# Эта стадия только собирает файлы для ZIP клиента: в образе они не
# запускаются, а сам образ остаётся на Alpine. Тесты того же кода прошли выше.
# Все пять компонентов клиента собираются здесь: бинарники выпуска автора
# дают при установке только лицензии и lock-файлы и сразу перезаписываются.
FROM rust:${RUST_VERSION}-slim-trixie AS client
ARG RUST_VERSION
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
ENV RUSTUP_TOOLCHAIN=${RUST_VERSION} \
    CARGO_NET_OFFLINE=true
COPY --from=sources /usr/local/cargo/registry /usr/local/cargo/registry
COPY --from=sources /tools/bin/cargo-auditable /usr/local/bin/
COPY --from=sources /build /build
COPY --from=sources /modules /modules
WORKDIR /build
RUN cargo auditable build --locked --release -p snolc-cli
WORKDIR /modules
RUN cargo auditable build --locked --release -p snolc-adapter-socks5 -p snolc-policy-local -p snolc-carrier-ssh -p snolc-protection-noise \
    && mkdir /out && cp /build/target/release/snolc target/release/libsnolc_adapter_socks5.so target/release/libsnolc_policy_local.so \
        target/release/libsnolc_carrier_ssh.so target/release/libsnolc_protection_noise.so /out/

FROM $image
ARG SNOLC_VERSION
LABEL io.vpnbot.snolc.version="${SNOLC_VERSION}+vpnbot.5"
# libgcc: размотка стека Rust при динамической сборке на musl.
RUN apk upgrade --no-cache --available \
    && apk add --no-cache libgcc python3 py3-cryptography
COPY app/snolc /snolc
# Результаты сборки подключаются только на время команды: скопированные во
# временный каталог и удалённые файлы остались бы в нижнем слое образа.
RUN --mount=type=bind,from=server,source=/out,target=/mnt/server \
    --mount=type=bind,from=client,source=/out,target=/mnt/client \
    mkdir -p /opt/snolc \
    && python3 /snolc/build_patches.py /mnt/client /opt/snolc/client-patches.zip \
    && PYTHONPATH=/snolc python3 -c 'from snolc_config import install; install("/opt/snolc/runtime", server=True, built="/mnt/server")' \
    && install -D -m 0555 /mnt/server/vpnbot-snolc-modules /opt/snolc/sbom/vpnbot-snolc-modules \
    && test "$(/opt/snolc/runtime/bin/snolc --version)" = "snolc 0.0.4+vpnbot.5 wire 1"
COPY scripts/protocol_service.py scripts/snolc_service.py /
ENV PYTHONPATH=/snolc
HEALTHCHECK --interval=15s --timeout=3s --start-period=30s --retries=3 \
    CMD python3 -c 'import json,time; s=json.load(open("/state/status.json")); assert time.time()-s["time"]<15 and s["phase"] in ("running","idle","disabled")'
ENTRYPOINT ["python3", "/snolc_service.py", "/state"]
