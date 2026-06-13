# telemt — MTProto-прокси (Rust, fake-TLS) из проекта telemt/telemt.
#
# Бинарь берём из официального образа GHCR (ghcr.io/telemt/telemt:<version>).
# В upstream-образе он лежит в /app/telemt и статически слинкован с musl
# (asset telemt-*-linux-musl), поэтому работает в alpine-базе vpnbot без
# доустановки рантайма. Это убирает зависимость от доступности GitHub
# Releases и ручного разбора имён ассетов: смена TELEMT_VERSION просто
# меняет тег base-образа и пересборка тянет нужную версию.
#
# Бинарь запускается ботом по ssh: restartTelemt() пишет /telemt/telemt.toml
# и поднимает `telemt run`.
ARG image
ARG TELEMT_VERSION=3.4.18

FROM ghcr.io/telemt/telemt:${TELEMT_VERSION} AS dl

FROM $image
COPY --from=dl /app/telemt /usr/local/bin/telemt
RUN apk add --no-cache openssh \
    && chmod +x /usr/local/bin/telemt \
    && mkdir -p /root/.ssh
ENV ENV="/root/.ashrc"
