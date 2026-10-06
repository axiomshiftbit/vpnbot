# TrustTunnel endpoint: build from source.
# Update:
#   поменять TT_REF в .env (пин на коммит/тег) и закоммитить — CI пересоберёт
#   или локально: TT_REF=<sha|tag> docker compose build tt
ARG TT_REF=v1.1.0

FROM python:3.13-slim-bookworm AS build
ARG TT_REF
# Держим в синхроне с rust-toolchain.toml апстрима (сейчас channel = "1.95").
# Если разойдётся — rustup всё равно доскачает нужный канал по toolchain-файлу
# из клона, но это лишний слой и минуты сборки.
ARG RUST_VERSION=1.95
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential cmake curl make git libclang-dev ca-certificates pkg-config \
    && rm -rf /var/lib/apt/lists/*
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- --default-toolchain "${RUST_VERSION}" -y --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}" \
    CARGO_NET_GIT_FETCH_WITH_CLI=true
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
    && git checkout -q FETCH_HEAD
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

FROM debian:bookworm-slim
RUN apt-get update && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl iproute2 openssh-server \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /root/.ssh /run/sshd /trusttunnel_endpoint
COPY --from=build /src/target/release/trusttunnel_endpoint /usr/local/bin/
COPY --from=build /src/target/release/setup_wizard         /usr/local/bin/
WORKDIR /trusttunnel_endpoint
