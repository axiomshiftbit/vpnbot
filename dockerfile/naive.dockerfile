ARG image=alpine:3.24
# Патчи forwardproxy проверены на закреплённой security-паре Caddy.
ARG CADDY_GO_VERSION=1.27.4
ARG XCADDY_VERSION=v0.4.7
ARG CADDY_VERSION=v2.11.9
ARG FORWARDPROXY_VERSION=v2.11.7-naive2

FROM golang:${CADDY_GO_VERSION}-alpine AS source
ARG XCADDY_VERSION
ARG CADDY_VERSION
ARG FORWARDPROXY_VERSION
RUN apk add --no-cache ca-certificates curl git patch
COPY dockerfile/go-*.sh dockerfile/download-file.sh dockerfile/go-sources.sha256 dockerfile/naive-caddy-2.11.9.patch /build-tools/
RUN sh /build-tools/go-source.sh caddyserver/caddy "$CADDY_VERSION" /caddy \
    && sh /build-tools/go-source.sh klzgrad/forwardproxy "$FORWARDPROXY_VERSION" /forwardproxy \
    && case "$CADDY_VERSION:$FORWARDPROXY_VERSION:$(cat /forwardproxy/CADDY_VERSION)" in \
        v2.11.7:v2.11.7-naive2:v2.11.7|v2.11.9:v2.11.7-naive2:v2.11.7) ;; \
        *) echo "Unverified Caddy/forwardproxy pair" >&2; exit 1 ;; \
       esac \
    && if [ "$CADDY_VERSION" = v2.11.9 ]; then \
        (cd /forwardproxy && patch -p1 --fuzz=0 < /build-tools/naive-caddy-2.11.9.patch); \
       fi \
    && cd /caddy \
    && patch -p1 --fuzz=0 < /forwardproxy/caddy-sing-quic-bbrv1.patch \
    && if [ "$CADDY_VERSION" = v2.11.7 ]; then \
        patch -p1 --fuzz=0 < /forwardproxy/caddy-read-idle-timeout.patch; \
       fi \
    && sh /build-tools/go-security.sh \
    && sh /build-tools/go-retry.sh go get golang.org/x/crypto@v0.59.0 go.opentelemetry.io/otel/sdk/log@v1.47.0 \
        github.com/smallstep/certificates@v0.30.3-0.20261105204752-cddde30af36e go.step.sm/crypto@v0.92.1

# Caddy 2.11.9 already contains the idle override API; the shared tests below
# verify the same CONNECT contract without reapplying its 2.11.7 backport.
FROM source AS go
COPY dockerfile/naive-tests/*.go /caddy/modules/caddyhttp/
COPY dockerfile/naive-tests/upstream-redirect.patch /forwardproxy-tests.patch
RUN cd /caddy \
    && sh /build-tools/go-retry.sh go test -p 1 -mod=mod ./modules/caddyhttp/... -count=1 \
    && cd /forwardproxy \
    && patch -p1 --fuzz=0 < /forwardproxy-tests.patch \
    && sh /build-tools/go-retry.sh go mod edit -replace github.com/caddyserver/caddy/v2=/caddy \
    && sh /build-tools/go-security.sh \
    && sh /build-tools/go-retry.sh go test -p 1 -mod=mod ./... -count=1
RUN sh /build-tools/go-retry.sh go install github.com/caddyserver/xcaddy/cmd/xcaddy@${XCADDY_VERSION} \
    && /go/bin/xcaddy build ${CADDY_VERSION} \
        --replace github.com/caddyserver/caddy/v2=/caddy \
        --with github.com/caddyserver/forwardproxy=/forwardproxy \
        --replace golang.org/x/net=golang.org/x/net@v0.62.0 \
    && ./caddy version | grep -q "${CADDY_VERSION}" \
    && ./caddy list-modules | grep -qx http.handlers.forward_proxy \
    && go version -m ./caddy > /tmp/caddy-modules \
    && grep -Fq 'github.com/go-jose/go-jose/v4' /tmp/caddy-modules \
    && ! grep -Fq 'github.com/go-jose/go-jose/v3' /tmp/caddy-modules

FROM $image
COPY --from=go /go/caddy /usr/local/bin/
RUN apk upgrade --no-cache \
    && apk add --no-cache openssh \
    && mkdir /root/.ssh \
    && caddy version
