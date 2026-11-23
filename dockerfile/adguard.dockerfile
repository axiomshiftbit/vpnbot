ARG ADGUARD_VERSION=v1.0.0
ARG PROTOCOL_GO_VERSION=1.27.4
FROM golang:${PROTOCOL_GO_VERSION}-alpine AS source
ARG ADGUARD_VERSION
RUN apk add --no-cache ca-certificates curl git
COPY dockerfile/go-*.sh dockerfile/download-file.sh dockerfile/go-sources.sha256 /build-tools/
RUN sh /build-tools/go-source.sh AdguardTeam/AdGuardHome "$ADGUARD_VERSION" /source

FROM node:24-alpine AS frontend
ARG ADGUARD_VERSION
COPY --from=source /source /source
COPY dockerfile/sources.sha256 /sources.sha256
WORKDIR /source
# Сохраняем путь панели за обратным прокси при входе и восстановлении пароля.
COPY dockerfile/adguard-panel-path.patch dockerfile/adguard-frontend-lock.patch /tmp/
RUN apk add --no-cache patch && patch --fuzz=0 -p1 < /tmp/adguard-panel-path.patch \
    && patch --fuzz=0 -p1 < /tmp/adguard-frontend-lock.patch
# В выпуске 1.0 upstream собирает интерфейс client_v2. Сверяем его lock до и после сборки.
# Исправленные версии nanoid обеих веток и valibot входят в проверенный lock.
RUN npm --prefix client_v2 pkg set dependencies.nanoid=5.1.16 overrides.postcss.nanoid=3.3.16 overrides.valibot=1.4.2 \
    && awk -v key="adguard-frontend-lock/${ADGUARD_VERSION}" '$2 == key {print $1 "  client_v2/package-lock.json"}' /sources.sha256 | sha256sum -c - \
    && sha256sum client_v2/package-lock.json > /tmp/frontend-lock.sha256 \
    && npm --prefix client_v2 ci --no-audit --no-fund --fetch-retries=5 \
    && npm --prefix client_v2 test -- panel-subpath.test.tsx \
    && npm --prefix client_v2 run build-prod \
    && sha256sum -c /tmp/frontend-lock.sha256 \
    && npm --prefix client_v2 sbom --omit dev --package-lock-only --sbom-format cyclonedx > /adguard-frontend.cdx.json

FROM source AS core
ARG ADGUARD_VERSION
COPY --from=frontend /source/build /source/build
WORKDIR /source
COPY dockerfile/adguard-session-rotation.patch /tmp/session-rotation.patch
RUN apk add --no-cache patch && patch --fuzz=0 -p1 < /tmp/session-rotation.patch \
    && sh /build-tools/go-security.sh \
    && CGO_ENABLED=0 sh /build-tools/go-retry.sh go build -trimpath \
       -ldflags "-s -w -X github.com/AdguardTeam/AdGuardHome/internal/version.version=$ADGUARD_VERSION -X github.com/AdguardTeam/AdGuardHome/internal/version.channel=release" -o /AdGuardHome .

FROM adguard/adguardhome:${ADGUARD_VERSION}
COPY --from=core /AdGuardHome /opt/adguardhome/AdGuardHome
# SBOM и lock, по которым собран встроенный интерфейс: Trivy проверяет его зависимости.
COPY --from=frontend /adguard-frontend.cdx.json /source/client_v2/package-lock.json /usr/local/share/vpnbot/adguard-frontend/
RUN apk upgrade --no-cache \
    && apk add --no-cache --update openssh \
    && mkdir /root/.ssh
ENV ENV="/root/.ashrc"
