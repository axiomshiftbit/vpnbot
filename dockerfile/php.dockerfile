ARG image=alpine:3.23
FROM $image

# Версии живут в .env (см. аннотации renovate там же) и приезжают build-args
# из docker-compose.yml. Значения по умолчанию — на случай сборки напрямую
# `docker build`, без compose.
ARG DNSLOOKUP_VERSION=v1.12.0
ARG SINGBOX_VERSION=v1.14.2
ARG MIHOMO_VERSION=v1.19.32
ARG SINGBOX_SHA256=8f6cb4bcf94d2b33c65d52e0d5b142db29a938336f1ff7267f397ac3758fc297
ARG MIHOMO_SHA256=8451100836c9eda194331c2babfad490b2faf30cebc1a04b0e76fd8ac2d35d10
LABEL io.vpnbot.sing-box.version=$SINGBOX_VERSION io.vpnbot.mihomo.version=$MIHOMO_VERSION

# libqrencode-tools, а НЕ libqrencode: второй кладёт только libqrencode.so, а
# sendQr() запускает CLI `qrencode`. С миграции на alpine (c421dc2, где
# debian-пакет qrencode заменили на libqrencode) бинаря в образе не было вовсе,
# и «show QR» молча не работал: qrencode не находился, png не создавался,
# sendPhoto уходил с несуществующим путём. Пакет лежит в репозитории community,
# он включён в /etc/apk/repositories базового образа.
RUN apk add --no-cache --update php84 \
    php84-mbstring \
    php84-session \
    php84-phar \
    php84-zip \
    php84-curl \
    php84-opcache \
    php84-openssl \
    php84-iconv \
    php84-intl \
    php84-pecl-ssh2 \
    php84-pecl-yaml \
    unit \
    unit-php84 \
    xxd \
    certbot \
    libqrencode-tools \
    openssh \
    openssl \
    curl \
    git \
    py3-qt5 \
    && mkdir /root/.ssh \
    # ${VER#v} — тег без ведущей «v»: в именах ассетов sing-box версия идёт без
    # неё, а в теге релиза она есть.
    && SB=${SINGBOX_VERSION#v} \
    && wget "https://github.com/ameshkov/dnslookup/releases/download/${DNSLOOKUP_VERSION}/dnslookup-linux-amd64-${DNSLOOKUP_VERSION}.tar.gz" \
    && tar -xf "dnslookup-linux-amd64-${DNSLOOKUP_VERSION}.tar.gz" \
    && mv linux-amd64/dnslookup /usr/bin \
    && rm "dnslookup-linux-amd64-${DNSLOOKUP_VERSION}.tar.gz" \
    && rm -rf /linux-amd64 \
    # Ассет -musl, а НЕ голый linux-amd64: с 1.13.0 апстрим разделил сборки, и
    # безсуффиксный тарбол стал glibc-динамическим (interpreter
    # /lib64/ld-linux-x86-64.so.2). В alpine такого загрузчика нет, exec падает
    # с "not found" — createSrs() получал пустой вывод и отдавал клиенту .srs на
    # 0 байт. Вариант -musl слинкован статически, как безсуффиксный до 1.13.
    # NB: ассета -musl нет у релизов < 1.13.0, откат пина ниже потребует вернуть
    # и имя ассета.
    && wget "https://github.com/SagerNet/sing-box/releases/download/${SINGBOX_VERSION}/sing-box-${SB}-linux-amd64-musl.tar.gz" \
    && echo "${SINGBOX_SHA256}  sing-box-${SB}-linux-amd64-musl.tar.gz" | sha256sum -c - \
    && tar -xf "sing-box-${SB}-linux-amd64-musl.tar.gz" \
    && mv "sing-box-${SB}-linux-amd64-musl/sing-box" /usr/bin \
    && rm "sing-box-${SB}-linux-amd64-musl.tar.gz" \
    && rm -rf "/sing-box-${SB}-linux-amd64-musl" \
    && wget "https://github.com/MetaCubeX/mihomo/releases/download/${MIHOMO_VERSION}/mihomo-linux-amd64-${MIHOMO_VERSION}.gz" \
    && echo "${MIHOMO_SHA256}  mihomo-linux-amd64-${MIHOMO_VERSION}.gz" | sha256sum -c - \
    && gunzip "mihomo-linux-amd64-${MIHOMO_VERSION}.gz" \
    && mv "mihomo-linux-amd64-${MIHOMO_VERSION}" /usr/bin/mihomo \
    && chmod +x /usr/bin/mihomo
