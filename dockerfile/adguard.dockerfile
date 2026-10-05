# Пин версии AdGuardHome. Без него FROM тянул :latest, и на каждой пересборке
# в контейнер приезжала произвольная версия. Для AdGuardHome это дороже, чем
# для остальных сервисов: /config/AdGuardHome.yaml мигрируется вперёд без
# обратной совместимости, то есть откатиться после такого обновления уже нельзя.
# Значение приходит из .env через build.args (ADGUARD_VERSION).
ARG ADGUARD_VERSION=v0.107.79
FROM adguard/adguardhome:${ADGUARD_VERSION}
RUN apk upgrade --no-cache \
    && apk add --no-cache --update openssh \
    && mkdir /root/.ssh
ENV ENV="/root/.ashrc"
