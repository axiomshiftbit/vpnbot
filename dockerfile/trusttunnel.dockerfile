# TrustTunnel endpoint: build from source.
# Update:
#   поменять TT_REF в .env (пин на коммит/тег) и закоммитить — CI пересоберёт
#   или локально: TT_REF=<sha|tag> docker compose build tt
ARG TT_REF=v1.3.1

# Сборка и итоговый образ на Alpine, как у остальных сервисов. Компилятор
# берётся готовым образом rust:<версия>-alpine: установщик rustup из сети
# (без контрольной суммы) больше не нужен.
# Последний стабильный Rust; rust-toolchain.toml апстрима закрепляет канал
# 1.95, RUSTUP_TOOLCHAIN ниже его заменяет.
ARG RUST_VERSION=1.100.0
ARG CARGO_AUDITABLE_VERSION=0.7.8
ARG image=alpine:3.24

FROM rust:${RUST_VERSION}-alpine AS build
ARG TT_REF
ARG RUST_VERSION
ARG CARGO_AUDITABLE_VERSION
RUN apk add --no-cache build-base cmake git patch clang-dev linux-headers perl pkgconf
# RUSTUP_TOOLCHAIN: компилятор уже в образе; без переменной rustup по
# rust-toolchain.toml апстрима скачал бы тот же канал заново.
# -crt-static: сборочным скриптам (bindgen) нужна динамическая загрузка
# libclang, а статически слинкованная программа на musl её не умеет.
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true \
    CARGO_NET_RETRY=5 \
    RUSTUP_TOOLCHAIN=${RUST_VERSION} \
    RUSTFLAGS="-C target-feature=-crt-static"
RUN cargo install --locked cargo-auditable --version "=${CARGO_AUDITABLE_VERSION}"
COPY sources.sha256 /sources.sha256
COPY rustls-0.23.46.patch /tmp/rustls.patch
WORKDIR /src
# Фетчим ровно нужный ref, а не клонируем ветку: `clone --depth 50` + checkout
# работал только пока пин лежал в последних 50 коммитах master, а с пином на
# коммит это вопрос времени. GitHub отдаёт fetch по sha, так что depth 1
# хватает и для тега, и для коммита.
# Upstream определяет версию через git describe: fetch тега только
# в FETCH_HEAD теряет его имя. Сохраняем ref тега; SHA-пины тоже допустимы.
RUN git init -q . \
    && git remote add origin https://github.com/TrustTunnel/TrustTunnel.git \
    && for attempt in 1 2 3 4 5 6; do \
         case "${TT_REF}" in \
           v[0-9]*) git fetch -q --depth 1 origin "refs/tags/${TT_REF}:refs/tags/${TT_REF}" ;; \
           *) git fetch -q --depth 1 origin "${TT_REF}" ;; \
         esac && break; \
         [ "$attempt" -lt 6 ] || exit 1; \
         sleep 15; \
       done \
    && git checkout -q FETCH_HEAD \
    # Тег можно переписать: коммит обязан совпасть с закреплённым для этой
    # версии. Пин на полный коммит проверяет сам себя.
    && pinned=$(awk -v key="trusttunnel/${TT_REF}" '$2 == key {print $1}' /sources.sha256) \
    && test "$(git rev-parse HEAD)" = "${pinned:-$TT_REF}" \
    && patch -p1 --fuzz=0 < /tmp/rustls.patch \
    && sha256sum Cargo.lock > /tmp/cargo-lock.sha256
# Внутренний HTTP/1 обработчик метрик паникует, если публичный HTTP/1
# выключен. Оставляем публичную политику прежней; исправляем только default.
COPY trusttunnel-metrics.patch /trusttunnel-metrics.patch
RUN git apply --check /trusttunnel-metrics.patch && git apply /trusttunnel-metrics.patch \
    && cargo test --locked --release -p trusttunnel --lib metrics_without_public_http1 \
    && cargo auditable build --locked --release --bin trusttunnel_endpoint \
    && strip target/release/trusttunnel_endpoint \
    && sha256sum -c /tmp/cargo-lock.sha256 \
    && readelf -S target/release/trusttunnel_endpoint | grep -q '\.dep-v0'

FROM $image
# Alpine вместо Debian: в образе на Debian сканер находил десятки уязвимостей
# высокой важности без исправления, и блокировать по ним было нечем. Ключи
# узла SSH пакет openssh в Alpine при установке не создаёт — их делает
# start_tt.sh при старте контейнера.
RUN apk upgrade --no-cache --available \
    && apk add --no-cache ca-certificates curl iproute2 openssh libgcc mimalloc2 \
    && mkdir -p /root/.ssh /trusttunnel_endpoint /usr/local/libexec
COPY --from=build /src/target/release/trusttunnel_endpoint /usr/local/libexec/
COPY --from=build /src/Cargo.lock /usr/local/share/trusttunnel/Cargo.lock
# Распределитель памяти musl плохо переносит многопоточную нагрузку: при пяти
# одновременных клиентах endpoint тратил втрое-вчетверо больше процессора и
# отдавал в 2,5 раза меньше, чем сборка под glibc (замер 2026-10-10: 2,6 против
# 6,6 Гбит/с). С mimalloc показатели прежние. Библиотека подключается только
# самому endpoint (защищённый вариант со сторожевыми страницами), а не sshd и
# оболочке; exec сохраняет имя процесса, по которому его ищет бот.
RUN test -f /usr/lib/libmimalloc-secure.so.2 \
    && printf '%s\n' '#!/bin/sh' 'LD_PRELOAD=/usr/lib/libmimalloc-secure.so.2 exec /usr/local/libexec/trusttunnel_endpoint "$@"' \
        > /usr/local/bin/trusttunnel_endpoint \
    && printf '%s\n' '#!/bin/sh' 'exec /usr/local/bin/trusttunnel_endpoint --setup-wizard "$@"' \
        > /usr/local/bin/setup_wizard \
    && chmod 755 /usr/local/bin/trusttunnel_endpoint /usr/local/bin/setup_wizard
WORKDIR /trusttunnel_endpoint
# Сборка откажет, если бинарнику не хватает библиотеки в итоговом образе.
RUN trusttunnel_endpoint --version && setup_wizard --help >/dev/null
