ARG image=alpine:3.23

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
# указывают на один коммит forwardproxy (d62c80d), меняется только заявленная
# совместимость. CADDY_GO_VERSION держим не ниже требования caddy (go.mod caddy
# v2.11.2 → go 1.25.0).
#
# Тег здесь — ЧЕЛОВЕЧЕСКИЙ пин: go его как версию модуля не примет, сборка
# разворачивает его в коммит через git ls-remote (см. ниже).
ARG CADDY_GO_VERSION=1.25
ARG XCADDY_VERSION=v0.4.5
ARG CADDY_VERSION=v2.11.2
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
RUN apk add --no-cache openssh \
    && mkdir /root/.ssh \
    && caddy version
