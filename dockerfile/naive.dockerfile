ARG image

# ── Версии (задаются в .env, пробрасываются через args в compose) ─────────────
# ВАЖНО: тег forwardproxy обязан СОВПАДАТЬ с CADDY_VERSION — у klzgrad теги
# называются по версии caddy, под которую плагин проверен: v2.11.2 ↔
# v2.11.2-naive. Другой пары upstream не проверял.
#
# Ветку `@naive`, как было раньше, не используем: README naiveproxy прямо
# говорит «Do not use the master branch to track updates… Use stable releases
# and the associated tags». С плавающей веткой (и xcaddy@latest, и
# golang:alpine) каждая пересборка давала другой бинарь без возможности отката.
#
# Известные пары: v2.11.2-naive, v2.10.0-naive, v2.9.1-naive — все три тега
# указывают на один коммит forwardproxy, меняется только заявленная
# совместимость. CADDY_GO_VERSION держим не ниже требования caddy (go.mod caddy
# v2.11.2 → go 1.25.0).
ARG CADDY_GO_VERSION=1.25
ARG XCADDY_VERSION=v0.4.5
ARG CADDY_VERSION=v2.11.2
ARG FORWARDPROXY_VERSION=v2.11.2-naive

FROM golang:${CADDY_GO_VERSION}-alpine as go
ARG XCADDY_VERSION
ARG CADDY_VERSION
ARG FORWARDPROXY_VERSION
RUN set -eux; \
    go install github.com/caddyserver/xcaddy/cmd/xcaddy@${XCADDY_VERSION}; \
    /go/bin/xcaddy build ${CADDY_VERSION} \
        --with github.com/caddyserver/forwardproxy=github.com/klzgrad/forwardproxy@${FORWARDPROXY_VERSION}; \
    # sanity: собрался ровно запрошенный caddy — иначе расхождение всплыло бы
    # только в рантайме (ср. `wg --version` в wireguard.dockerfile)
    ./caddy version | grep -q "${CADDY_VERSION}"

FROM $image
COPY --from=go /go/caddy /usr/local/bin/
RUN apk add openssh \
    && mkdir /root/.ssh \
    && caddy version
