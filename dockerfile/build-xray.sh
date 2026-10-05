#!/bin/sh
set -eu
repo=$1; version=$2; output=$3
# Сохраняем выбор стабильного/prerelease, но новый источник обязан иметь
# проверенную контрольную сумму. Слоты и выбор пользователя не меняются.
case "$version" in
    '') version=$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" | jq -er .tag_name) ;;
    prerelease) version=$(curl -fsSL "https://api.github.com/repos/$repo/releases" | jq -er '[.[] | select(.prerelease==true)][0].tag_name') ;;
esac
source="/sources/$repo/$version"
sh /build-tools/go-source.sh "$repo" "$version" "$source"
cd "$source"
sh /build-tools/go-security.sh
CGO_ENABLED=0 go build -trimpath -buildvcs=false \
    -ldflags '-s -w -X github.com/xtls/xray-core/core.build=vpnbot-security.1' -o "$output" ./main
"$output" version
