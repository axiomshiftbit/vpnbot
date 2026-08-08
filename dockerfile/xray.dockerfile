ARG image=alpine:3.18.2
FROM $image

# ── Версия Xray-core ──────────────────────────────────────────────────────────
# Управляется ОДНОЙ переменной XRAY_VERSION (build-arg). Допустимые значения:
#
#   ""           → последний СТАБИЛЬНЫЙ релиз (releases/latest) — поведение по умолчанию
#   "prerelease" → последний релиз, СТРОГО помеченный как pre-release / beta
#   "vX.Y.Z"     → КОНКРЕТНАЯ версия по тегу, напр. "v1.8.24" (releases/tags/<tag>)
#
# Способ 1 — через .env / docker-compose (рекомендуется, ничего тут править не нужно):
#   build:
#     args:
#       XRAY_VERSION: ${XRAY_VERSION}      # значение берётся из .env
#
# Способ 2 — вручную: раскомментируйте РОВНО ОДНУ строку ниже (она переопределит default).
ARG XRAY_VERSION=""
# ARG XRAY_VERSION="prerelease"
# ARG XRAY_VERSION="v1.8.24"

RUN apk add openssh openssl jq curl \
    && mkdir /root/.ssh \
    && case "$XRAY_VERSION" in \
         "")          api_url="https://api.github.com/repos/XTLS/Xray-core/releases/latest" ;; \
         prerelease)  api_url="https://api.github.com/repos/XTLS/Xray-core/releases" ;; \
         *)           api_url="https://api.github.com/repos/XTLS/Xray-core/releases/tags/$XRAY_VERSION" ;; \
       esac \
    && dl_url=$(curl -fsSL "$api_url" \
         | jq -r 'if type=="array" then (map(select(.prerelease==true)) | .[0]) else . end | .assets[] | select(.name=="Xray-linux-64.zip") | .browser_download_url') \
    && wget -O Xray-linux-64.zip "$dl_url" \
    && unzip Xray-linux-64.zip \
    && mv xray /usr/bin/ \
    && rm Xray-linux-64.zip \
    && rm geoip.dat \
    && rm geosite.dat \
    && chmod +x /usr/bin/xray
ENV ENV="/root/.ashrc"
