# telemt — MTProto-прокси (Rust, fake-TLS) из проекта telemt/telemt.
#
# Upstream раздаёт статически слинкованные musl-бинарники (static-pie) через
# GitHub releases — их можно положить прямо в alpine-базу vpnbot без сборки из
# исходников (как dnstt). Бинарь запускается ботом по ssh: restartTelemt()
# пишет /telemt/telemt.toml и поднимает `telemt run`.
ARG image

FROM alpine:3.18 AS dl
ARG TELEMT_VERSION=3.4.18
RUN apk add --no-cache curl tar \
    && arch="$(uname -m)" \
    && case "$arch" in \
         x86_64)  asset="telemt-x86_64-linux-musl.tar.gz" ;; \
         aarch64) asset="telemt-aarch64-linux-musl.tar.gz" ;; \
         *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
       esac \
    && curl -fsSL -o /tmp/telemt.tgz \
         "https://github.com/telemt/telemt/releases/download/${TELEMT_VERSION}/${asset}" \
    && tar xzf /tmp/telemt.tgz -C /usr/local/bin telemt \
    && chmod +x /usr/local/bin/telemt \
    && rm -f /tmp/telemt.tgz

FROM $image
COPY --from=dl /usr/local/bin/telemt /usr/local/bin/telemt
RUN apk add --no-cache openssh \
    && mkdir -p /root/.ssh
ENV ENV="/root/.ashrc"
