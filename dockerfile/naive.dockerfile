ARG image=alpine:3.24
# Caddy и forwardproxy закреплены отдельно. Плагин v2.11.2-naive сохраняет
# совместимый API; сочетание с исправленным Caddy допускают только native-тесты.
ARG CADDY_GO_VERSION=1.27.1
ARG XCADDY_VERSION=v0.4.7
ARG CADDY_VERSION=v2.11.7
ARG FORWARDPROXY_VERSION=v2.11.2-naive

FROM golang:${CADDY_GO_VERSION}-alpine AS go
ARG XCADDY_VERSION
ARG CADDY_VERSION
ARG FORWARDPROXY_VERSION
RUN set -eux; \
    apk add --no-cache git; \
    # Тег forwardproxy НЕЛЬЗЯ отдать go как версию модуля: «v2.11.2-naive» —
    # валидный semver с мажором 2, а путь github.com/klzgrad/forwardproxy идёт
    # без суффикса /v2, и go падает ещё на разборе go.mod:
    #   replace github.com/klzgrad/forwardproxy: version "v2.11.2-naive"
    #   invalid: should be v0 or v1, not v2
    # Имена веток и хеши коммитов go, наоборот, резолвит сам (VersionFixer →
    # псевдоверсия v0.0.0-<дата>-<хеш>), поэтому тег разворачиваем в коммит
    # здесь: пин остаётся ровно тем же (тег неизменяем), а go его принимает.
    # Ветку @naive не берём по той же причине, что и раньше — она плавающая.
    FORWARDPROXY_REF="$(git ls-remote https://github.com/klzgrad/forwardproxy \
        "refs/tags/${FORWARDPROXY_VERSION}^{}" "refs/tags/${FORWARDPROXY_VERSION}" \
        | tail -1 | cut -f1)"; \
    if [ -z "$FORWARDPROXY_REF" ]; then \
        echo "нет тега ${FORWARDPROXY_VERSION} в klzgrad/forwardproxy — у upstream теги есть не под каждый релиз caddy" >&2; \
        exit 1; \
    fi; \
    echo "forwardproxy ${FORWARDPROXY_VERSION} -> ${FORWARDPROXY_REF}"; \
    go install github.com/caddyserver/xcaddy/cmd/xcaddy@${XCADDY_VERSION}; \
    /go/bin/xcaddy build ${CADDY_VERSION} \
        --with github.com/caddyserver/forwardproxy=github.com/klzgrad/forwardproxy@${FORWARDPROXY_REF}; \
    # sanity: собрался ровно запрошенный caddy и именно с форком klzgrad —
    # иначе расхождение всплыло бы только в рантайме (ср. `wg --version` в
    # wireguard.dockerfile)
    ./caddy version | grep -q "${CADDY_VERSION}"; \
    ./caddy build-info | grep -q "klzgrad/forwardproxy"

FROM $image
COPY --from=go /go/caddy /usr/local/bin/
RUN apk upgrade --no-cache \
    && apk add --no-cache openssh \
    && mkdir /root/.ssh \
    && caddy version
