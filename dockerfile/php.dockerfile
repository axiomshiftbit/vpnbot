ARG image=alpine:3.24
ARG PROTOCOL_GO_VERSION=1.27.3
FROM golang:${PROTOCOL_GO_VERSION}-alpine AS helpers
ARG DNSLOOKUP_VERSION=v1.12.0
ARG SINGBOX_VERSION=v1.14.4
ARG MIHOMO_VERSION=v1.19.33
ARG SINGBOX_SOURCE_SHA256=0958ccd23b1ea9a141d715d15478b1e040fd04bcca19d8ff5529636b1b753e18
ARG MIHOMO_SOURCE_SHA256=e7c596b37ff27ec487d19b1920f73e0c97a78067ea35766530ee9659ade72711
RUN apk add --no-cache ca-certificates curl git
COPY dockerfile/go-*.sh dockerfile/go-sources.sha256 /build-tools/
RUN sh /build-tools/go-source.sh ameshkov/dnslookup "$DNSLOOKUP_VERSION" /dnslookup \
    && cd /dnslookup && sh /build-tools/go-security.sh \
    && CGO_ENABLED=0 sh /build-tools/go-retry.sh go build -trimpath -ldflags "-s -w -X main.VersionString=${DNSLOOKUP_VERSION#v}" -o /out/dnslookup .
RUN sh /build-tools/go-source.sh SagerNet/sing-box "$SINGBOX_VERSION" /singbox "$SINGBOX_SOURCE_SHA256" \
    && cd /singbox && sh /build-tools/go-security.sh \
    && CGO_ENABLED=0 sh /build-tools/go-retry.sh go build -trimpath -tags with_quic,with_utls,with_v2ray_api \
       -ldflags "-s -w -X github.com/sagernet/sing-box/constant.Version=${SINGBOX_VERSION#v}" -o /out/sing-box ./cmd/sing-box
RUN sh /build-tools/go-source.sh MetaCubeX/mihomo "$MIHOMO_VERSION" /mihomo "$MIHOMO_SOURCE_SHA256" \
    && cd /mihomo && sh /build-tools/go-security.sh \
    && CGO_ENABLED=0 sh /build-tools/go-retry.sh go build -trimpath -tags with_gvisor \
       -ldflags "-s -w -X github.com/metacubex/mihomo/constant.Version=$MIHOMO_VERSION" -o /out/mihomo .

FROM $image
ARG SINGBOX_VERSION=v1.14.4
ARG MIHOMO_VERSION=v1.19.33
LABEL io.vpnbot.sing-box.version=$SINGBOX_VERSION io.vpnbot.mihomo.version=$MIHOMO_VERSION
COPY --from=helpers /out/ /usr/bin/

# libqrencode-tools, а НЕ libqrencode: второй кладёт только libqrencode.so, а
# sendQr() запускает CLI `qrencode`. С миграции на alpine (c421dc2, где
# debian-пакет qrencode заменили на libqrencode) бинаря в образе не было вовсе,
# и «show QR» молча не работал: qrencode не находился, png не создавался,
# sendPhoto уходил с несуществующим путём. Пакет лежит в репозитории community,
# он включён в /etc/apk/repositories базового образа.
RUN apk upgrade --no-cache \
    && apk add --no-cache --update php85 \
    php85-mbstring \
    php85-session \
    php85-phar \
    php85-zip \
    php85-curl \
    php85-openssl \
    php85-iconv \
    php85-intl \
    php85-pecl-ssh2 \
    php85-pecl-yaml \
    freeunit \
    freeunit-php85 \
    xxd \
    certbot \
    libqrencode-tools \
    openssh \
    openssl \
    curl \
    git \
    py3-qt5 \
    # Скрипты бота вызывают php; обновляем ссылку и при её наличии в APK.
    && ln -sf /usr/bin/php85 /usr/bin/php \
    # OPcache встроен в PHP 8.5, отдельного php85-opcache в Alpine нет.
    && php -r 'foreach (["mbstring", "session", "phar", "zip", "curl", "openssl", "iconv", "intl", "ssh2", "yaml", "Zend OPcache"] as $module) { if (!extension_loaded($module)) { fwrite(STDERR, "Missing PHP module: $module\n"); exit(1); } }' \
    # Учебные сертификаты и закрытые ключи из тестов certbot и acme в работе не
    # нужны, а проверка слоёв образа допускает закрытые ключи только по списку.
    && find /usr/lib/python3*/site-packages/certbot /usr/lib/python3*/site-packages/acme -type d -name testdata -prune -exec rm -rf {} + \
    && certbot --version \
    && mkdir /root/.ssh
