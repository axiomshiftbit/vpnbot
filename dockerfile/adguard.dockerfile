ARG ADGUARD_VERSION=v0.107.80
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
# Интерфейс — каталог client, как в официальных выпусках каналов release и
# beta (bamboo-specs/release.yaml: clientDir 'client'). Новый интерфейс
# client_v2 AdGuard пока выпускает только в канале edge; Makefile в тегах
# указывает на него по умолчанию, поэтому сборка «как в Makefile» давала
# стабильную версию с интерфейсом edge — не таким, как у официального архива.
#
# Lock выпуска v0.107.80 держит js-yaml 3.14.2 (GHSA-52cp-r559-cp3m,
# GHSA-2883-xcg3-v3hh, GHSA-5p4m-2wfm-xmqj, HIGH) — прямую зависимость
# интерфейса. Ставим исправленную 3.15.2 той же ветки 3.x и сверяем весь
# итоговый lock с суммой adguard-frontend-lock/. Список production-зависимостей
# интерфейса пишется в CycloneDX SBOM: в образе Trivy читает его, а lock-файлы —
# только при сканировании каталога.
RUN npm --prefix client pkg set dependencies.js-yaml=3.15.2 \
    && npm --prefix client install --package-lock-only --ignore-scripts --no-audit --no-fund --fetch-retries=5 \
    && awk -v key="adguard-frontend-lock/${ADGUARD_VERSION}" '$2 == key {print $1 "  client/package-lock.json"}' /sources.sha256 | sha256sum -c - \
    && sha256sum client/package-lock.json > /tmp/frontend-lock.sha256 \
    && npm --prefix client ci --no-audit --no-fund --fetch-retries=5 \
    && npm --prefix client run build-prod \
    && sha256sum -c /tmp/frontend-lock.sha256 \
    && npm --prefix client sbom --omit dev --package-lock-only --sbom-format cyclonedx > /adguard-frontend.cdx.json

FROM source AS core
ARG ADGUARD_VERSION
COPY --from=frontend /source/build /source/build
WORKDIR /source
RUN sh /build-tools/go-security.sh \
    && CGO_ENABLED=0 sh /build-tools/go-retry.sh go build -trimpath \
       -ldflags "-s -w -X github.com/AdguardTeam/AdGuardHome/internal/version.version=$ADGUARD_VERSION -X github.com/AdguardTeam/AdGuardHome/internal/version.channel=release" -o /AdGuardHome .

FROM adguard/adguardhome:${ADGUARD_VERSION}
COPY --from=core /AdGuardHome /opt/adguardhome/AdGuardHome
# SBOM и lock, по которым собран встроенный интерфейс: Trivy проверяет его зависимости.
COPY --from=frontend /adguard-frontend.cdx.json /source/client/package-lock.json /usr/local/share/vpnbot/adguard-frontend/
RUN apk upgrade --no-cache \
    && apk add --no-cache --update openssh \
    && mkdir /root/.ssh
ENV ENV="/root/.ashrc"
