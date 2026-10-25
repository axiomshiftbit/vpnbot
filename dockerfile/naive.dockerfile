ARG image=alpine:3.24
# Плагин требует патчи Caddy из того же стабильного релиза forwardproxy.
ARG CADDY_GO_VERSION=1.27.3
ARG XCADDY_VERSION=v0.4.7
ARG CADDY_VERSION=v2.11.7
ARG FORWARDPROXY_VERSION=v2.11.7-naive2

FROM golang:${CADDY_GO_VERSION}-alpine AS source
ARG XCADDY_VERSION
ARG CADDY_VERSION
ARG FORWARDPROXY_VERSION
RUN apk add --no-cache ca-certificates curl git patch
COPY dockerfile/go-*.sh dockerfile/go-sources.sha256 /build-tools/
RUN sh /build-tools/go-source.sh caddyserver/caddy "$CADDY_VERSION" /caddy \
    && sh /build-tools/go-source.sh klzgrad/forwardproxy "$FORWARDPROXY_VERSION" /forwardproxy \
    && test "$(cat /forwardproxy/CADDY_VERSION)" = "$CADDY_VERSION" \
    && cd /caddy \
    && patch -p1 --fuzz=0 < /forwardproxy/caddy-sing-quic-bbrv1.patch \
    && patch -p1 --fuzz=0 < /forwardproxy/caddy-read-idle-timeout.patch \
    && sh /build-tools/go-security.sh

FROM source AS go
COPY dockerfile/naive-tests/*.go /caddy/modules/caddyhttp/
COPY dockerfile/naive-tests/upstream-redirect.patch /forwardproxy-tests.patch
RUN cd /caddy \
    && sh /build-tools/go-retry.sh go test -mod=mod ./modules/caddyhttp -run 'Test(VPNBot|Idle)' -count=1 \
    && cd /forwardproxy \
    && patch -p1 --fuzz=0 < /forwardproxy-tests.patch \
    && sh /build-tools/go-retry.sh go mod edit -replace github.com/caddyserver/caddy/v2=/caddy \
    && sh /build-tools/go-security.sh \
    && sh /build-tools/go-retry.sh go test -mod=mod ./... -count=1
RUN sh /build-tools/go-retry.sh go install github.com/caddyserver/xcaddy/cmd/xcaddy@${XCADDY_VERSION} \
    && /go/bin/xcaddy build ${CADDY_VERSION} \
        --replace github.com/caddyserver/caddy/v2=/caddy \
        --with github.com/caddyserver/forwardproxy=/forwardproxy \
        --replace golang.org/x/net=golang.org/x/net@v0.60.0 \
    && ./caddy version | grep -q "${CADDY_VERSION}" \
    && ./caddy list-modules | grep -qx http.handlers.forward_proxy

FROM $image
COPY --from=go /go/caddy /usr/local/bin/
RUN apk upgrade --no-cache \
    && apk add --no-cache openssh \
    && mkdir /root/.ssh \
    && caddy version
