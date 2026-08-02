# TrustTunnel endpoint: build from source.
# Update:
#   docker compose build --no-cache tt
#   или: TT_REF=<sha|tag> docker compose build tt
ARG TT_REF=master

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
RUN git clone --depth 50 https://github.com/TrustTunnel/TrustTunnel.git . \
    && git checkout "${TT_REF}"
RUN cargo build --release --bin trusttunnel_endpoint \
    && cargo build --release --bin setup_wizard \
    && strip target/release/trusttunnel_endpoint target/release/setup_wizard

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates iproute2 openssh-server \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /root/.ssh /run/sshd /trusttunnel_endpoint
COPY --from=build /src/target/release/trusttunnel_endpoint /usr/local/bin/
COPY --from=build /src/target/release/setup_wizard         /usr/local/bin/
WORKDIR /trusttunnel_endpoint
