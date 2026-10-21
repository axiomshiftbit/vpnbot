ARG HYSTERIA_VERSION=v2.13.0
ARG PROTOCOL_GO_VERSION=1.27.3
FROM golang:${PROTOCOL_GO_VERSION}-alpine AS core
ARG HYSTERIA_VERSION
ENV GOWORK=off
RUN apk add --no-cache ca-certificates curl git
COPY dockerfile/go-*.sh dockerfile/go-sources.sha256 /build-tools/
RUN sh /build-tools/go-source.sh apernet/hysteria "app/$HYSTERIA_VERSION" /source \
    && cd /source/app && sh /build-tools/go-security.sh \
    && CGO_ENABLED=0 sh /build-tools/go-retry.sh go build -trimpath \
       -ldflags "-s -w -X github.com/apernet/hysteria/app/v2/cmd.appVersion=$HYSTERIA_VERSION -X github.com/apernet/hysteria/app/v2/cmd.appType=release" -o /hysteria .

FROM tobyxdd/hysteria:${HYSTERIA_VERSION}
COPY --from=core /hysteria /usr/local/bin/hysteria
RUN apk upgrade --no-cache \
    && apk add --no-cache openssh python3 py3-yaml \
    && mkdir -p /root/.ssh
COPY scripts/hysteria_service.py /hysteria_service.py
ENV ENV="/root/.ashrc"
ENTRYPOINT []
