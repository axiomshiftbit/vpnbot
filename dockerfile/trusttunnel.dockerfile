# TrustTunnel endpoint: build from source.
# Update:
#   поменять TT_REF в .env (пин на коммит/тег) и закоммитить — CI пересоберёт
#   или локально: TT_REF=<sha|tag> docker compose build tt
ARG TT_REF=v1.1.0

# Сборка и итоговый образ на Alpine, как у остальных сервисов. Компилятор
# берётся готовым образом rust:<версия>-alpine: установщик rustup из сети
# (без контрольной суммы) больше не нужен.
# Последний стабильный Rust; rust-toolchain.toml апстрима закрепляет канал
# 1.95, RUSTUP_TOOLCHAIN ниже его заменяет.
ARG RUST_VERSION=1.99.1
ARG image=alpine:3.24

FROM rust:${RUST_VERSION}-alpine AS build
ARG TT_REF
ARG RUST_VERSION
RUN apk add --no-cache build-base cmake git clang-dev linux-headers perl pkgconf
# RUSTUP_TOOLCHAIN: компилятор уже в образе; без переменной rustup по
# rust-toolchain.toml апстрима скачал бы тот же канал заново.
# -crt-static: сборочным скриптам (bindgen) нужна динамическая загрузка
# libclang, а статически слинкованная программа на musl её не умеет.
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true \
    RUSTUP_TOOLCHAIN=${RUST_VERSION} \
    RUSTFLAGS="-C target-feature=-crt-static"
COPY sources.sha256 /sources.sha256
WORKDIR /src
# Фетчим ровно нужный ref, а не клонируем ветку: `clone --depth 50` + checkout
# работал только пока пин лежал в последних 50 коммитах master, а с пином на
# коммит это вопрос времени. GitHub отдаёт fetch по sha, так что depth 1
# хватает и для тега, и для коммита.
# Upstream 1.1.0 определяет версию через git describe: fetch тега только
# в FETCH_HEAD теряет его имя. Сохраняем ref тега; SHA-пины тоже допустимы.
RUN git init -q . \
    && git remote add origin https://github.com/TrustTunnel/TrustTunnel.git \
    && case "${TT_REF}" in \
        v[0-9]*) git fetch -q --depth 1 origin "refs/tags/${TT_REF}:refs/tags/${TT_REF}" ;; \
        *) git fetch -q --depth 1 origin "${TT_REF}" ;; \
    esac \
    && git checkout -q FETCH_HEAD \
    # Тег можно переписать: коммит обязан совпасть с закреплённым для этой
    # версии. Пин на полный коммит проверяет сам себя.
    && pinned=$(awk -v key="trusttunnel/${TT_REF}" '$2 == key {print $1}' /sources.sha256) \
    && test "$(git rev-parse HEAD)" = "${pinned:-$TT_REF}"
RUN cargo build --release --bin trusttunnel_endpoint \
    && cargo build --release --bin setup_wizard \
    && strip target/release/trusttunnel_endpoint target/release/setup_wizard
# 1.1.0: внутренний HTTP/1 обработчик метрик паникует, если публичный HTTP/1
# выключен. Оставляем публичную политику прежней; исправляем только default.
COPY trusttunnel-metrics.patch /trusttunnel-metrics.patch
RUN git apply --check /trusttunnel-metrics.patch && git apply /trusttunnel-metrics.patch \
    && cargo test --release -p trusttunnel --lib metrics_without_public_http1 \
    && cargo build --release --bin trusttunnel_endpoint --bin setup_wizard \
    && strip target/release/trusttunnel_endpoint target/release/setup_wizard

FROM $image
# Alpine вместо Debian: в образе на Debian сканер находил десятки уязвимостей
# высокой важности без исправления, и блокировать по ним было нечем. Ключи
# узла SSH пакет openssh в Alpine при установке не создаёт — их делает
# start_tt.sh при старте контейнера.
RUN apk upgrade --no-cache --available \
    && apk add --no-cache ca-certificates curl iproute2 openssh libgcc mimalloc2 \
    && mkdir -p /root/.ssh /trusttunnel_endpoint /usr/local/libexec
COPY --from=build /src/target/release/trusttunnel_endpoint /usr/local/libexec/
COPY --from=build /src/target/release/setup_wizard         /usr/local/bin/
# Распределитель памяти musl плохо переносит многопоточную нагрузку: при пяти
# одновременных клиентах endpoint тратил втрое-вчетверо больше процессора и
# отдавал в 2,5 раза меньше, чем сборка под glibc (замер 2026-10-10: 2,6 против
# 6,6 Гбит/с). С mimalloc показатели прежние. Библиотека подключается только
# самому endpoint (защищённый вариант со сторожевыми страницами), а не sshd и
# оболочке; exec сохраняет имя процесса, по которому его ищет бот.
RUN test -f /usr/lib/libmimalloc-secure.so.2 \
    && printf '%s\n' '#!/bin/sh' 'LD_PRELOAD=/usr/lib/libmimalloc-secure.so.2 exec /usr/local/libexec/trusttunnel_endpoint "$@"' \
        > /usr/local/bin/trusttunnel_endpoint \
    && chmod 755 /usr/local/bin/trusttunnel_endpoint
WORKDIR /trusttunnel_endpoint
# Сборка откажет, если бинарнику не хватает библиотеки в итоговом образе.
RUN trusttunnel_endpoint --version && setup_wizard --help >/dev/null
