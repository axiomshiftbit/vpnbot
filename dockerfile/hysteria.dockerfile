# Пин версии hysteria. Без него FROM тянул :latest, и каждая пересборка
# приносила произвольную версию — та же болезнь, что была у adguard: сервер и
# клиентские конфиги расходятся молча, а понять, что именно поменялось, уже
# нельзя. Значение приходит из .env через build.args (HYSTERIA_VERSION).
ARG HYSTERIA_VERSION=v2.12.3
FROM tobyxdd/hysteria:${HYSTERIA_VERSION}
RUN apk upgrade --no-cache \
    && apk add --no-cache openssh python3 py3-yaml \
    && mkdir -p /root/.ssh
COPY scripts/hysteria_service.py /hysteria_service.py
ENV ENV="/root/.ashrc"
ENTRYPOINT []
