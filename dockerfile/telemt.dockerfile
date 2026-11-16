# telemt — MTProto-прокси (Rust, fake-TLS) из проекта telemt/telemt.
#
# Собирается из исходников закреплённого коммита (коммит и SHA-256 архива —
# в sources.sha256) через cargo auditable с --locked: список зависимостей
# Rust встроен в бинарь, и сканер образа проверяет их на уязвимости. Флаги
# повторяют musl-сборку выпусков upstream (+crt-static, panic=abort), бинарь
# статический и работает в alpine-базе vpnbot без доустановки рантайма.
#
# Бинарь запускается ботом по ssh: restartTelemt() пишет /telemt/telemt.toml
# и поднимает `telemt run`. Entrypoint восстанавливает процесс после сбоя,
# учитывая сохранённый выключатель сервиса и общую с ботом блокировку.
ARG image=alpine:3.24
ARG TELEMT_VERSION=3.5.17
ARG RUST_VERSION=1.100.0
ARG CARGO_AUDITABLE_VERSION=0.7.7

FROM rust:${RUST_VERSION}-alpine AS telemt_build
ARG TELEMT_VERSION=3.5.17
ARG RUST_VERSION
ARG CARGO_AUDITABLE_VERSION
ENV RUSTUP_TOOLCHAIN=${RUST_VERSION} CARGO_NET_RETRY=5 CARGO_BUILD_JOBS=2 \
    RUSTFLAGS="-C target-feature=+crt-static -C panic=abort"
RUN apk add --no-cache build-base cmake perl pkgconf linux-headers curl binutils \
    && RUSTFLAGS="-C target-feature=-crt-static" cargo install --locked cargo-auditable --version "=${CARGO_AUDITABLE_VERSION}"
COPY dockerfile/sources.sha256 /sources.sha256
COPY dockerfile/download-file.sh /build-tools/download-file.sh
WORKDIR /rust-source
RUN ref=$(awk -v key="telemt-commit/${TELEMT_VERSION}" '$2 == key {print $1}' /sources.sha256) \
    && test "${#ref}" = 40 \
    && sh /build-tools/download-file.sh "https://codeload.github.com/telemt/telemt/tar.gz/$ref" source.tar.gz \
    && awk -v key="telemt-source/${TELEMT_VERSION}" '$2 == key {print $1 "  source.tar.gz"}' /sources.sha256 | sha256sum -c - \
    && tar -xzf source.tar.gz --strip-components=1 && rm source.tar.gz \
    && sha256sum Cargo.lock > /tmp/cargo-lock.sha256 \
    && cargo auditable build --locked --release --target x86_64-unknown-linux-musl --bin telemt \
    && sha256sum -c /tmp/cargo-lock.sha256 \
    && mkdir /out \
    && for binary in telemt; do \
         strip target/x86_64-unknown-linux-musl/release/$binary; readelf -S target/x86_64-unknown-linux-musl/release/$binary | grep -q '\.dep-v0'; \
         cp target/x86_64-unknown-linux-musl/release/$binary /out/; \
       done

FROM $image
ARG TELEMT_VERSION=3.5.17
COPY --from=telemt_build /out/telemt /usr/local/bin/telemt
COPY --from=telemt_build /rust-source/Cargo.lock /usr/local/share/telemt/Cargo.lock
# У бинаря telemt нет команды версии (неизвестный флаг уходит в Run), поэтому
# версию впекаем в образ файлом — бот читает её по ssh из контейнера
# (telemtVersion()), как /etc/wgcf_version у warp. Это версия РЕАЛЬНО
# запущенного образа, а не пин из .env.
RUN apk upgrade --no-cache \
    && apk add --no-cache openssh python3 \
    && echo "${TELEMT_VERSION}" > /etc/telemt_version \
    && mkdir -p /root/.ssh
ENV ENV="/root/.ashrc"
