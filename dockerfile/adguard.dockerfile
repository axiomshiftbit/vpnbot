ARG ADGUARD_VERSION=v0.107.79
ARG PROTOCOL_GO_VERSION=1.27.2
FROM golang:${PROTOCOL_GO_VERSION}-alpine AS source
ARG ADGUARD_VERSION
RUN apk add --no-cache ca-certificates curl git
COPY dockerfile/go-*.sh dockerfile/go-sources.sha256 /build-tools/
RUN sh /build-tools/go-source.sh AdguardTeam/AdGuardHome "$ADGUARD_VERSION" /source

FROM node:24-alpine AS frontend
COPY --from=source /source /source
WORKDIR /source
RUN npm --prefix client_v2 ci --no-audit --no-fund \
    && npm --prefix client_v2 run build-prod

FROM source AS core
ARG ADGUARD_VERSION
COPY --from=frontend /source/build /source/build
WORKDIR /source
RUN sh /build-tools/go-security.sh \
    && CGO_ENABLED=0 go build -trimpath \
       -ldflags "-s -w -X github.com/AdguardTeam/AdGuardHome/internal/version.version=$ADGUARD_VERSION -X github.com/AdguardTeam/AdGuardHome/internal/version.channel=release" -o /AdGuardHome .

FROM adguard/adguardhome:${ADGUARD_VERSION}
COPY --from=core /AdGuardHome /opt/adguardhome/AdGuardHome
RUN apk upgrade --no-cache \
    && apk add --no-cache --update openssh \
    && mkdir /root/.ssh
ENV ENV="/root/.ashrc"
