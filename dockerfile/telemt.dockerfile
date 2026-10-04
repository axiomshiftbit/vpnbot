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
# и поднимает `telemt run`. Entrypoint восстанавливает процесс после сбоя,
# учитывая сохранённый выключатель сервиса и общую с ботом блокировку.
ARG image=alpine:3.23
ARG TELEMT_VERSION=3.5.13

FROM ghcr.io/telemt/telemt:${TELEMT_VERSION} AS dl

FROM $image
# ARG до FROM не виден после него — объявляем повторно для финальной стадии.
ARG TELEMT_VERSION=3.5.13
COPY --from=dl /app/telemt /usr/local/bin/telemt
# У бинаря telemt нет команды версии (неизвестный флаг уходит в Run), поэтому
# версию впекаем в образ файлом — бот читает её по ssh из контейнера
# (telemtVersion()), как /etc/wgcf_version у warp. Это версия РЕАЛЬНО
# запущенного образа, а не пин из .env (они расходятся, пока образ не
# пересобран после смены TELEMT_VERSION).
RUN apk add --no-cache openssh python3 \
    && chmod +x /usr/local/bin/telemt \
    && echo "${TELEMT_VERSION}" > /etc/telemt_version \
    && mkdir -p /root/.ssh
ENV ENV="/root/.ashrc"
