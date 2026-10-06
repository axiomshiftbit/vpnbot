#!/bin/sh
set -eu
repo=$1; version=$2; output=$3; tags=${4:-}; tests=${5:-}
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
if [ -n "$tests" ]; then
    # go-security.sh поднимает зависимости выше проверенных автором ядра:
    # прогоняем его собственные тесты уже на этом дереве. Тесты геоданных
    # требуют файлов, которых нет в исходниках. Пакеты, которых в этой версии
    # ещё нет, пропускаем: откат пина через override.env должен собираться.
    present=
    for pattern in $tests; do
        [ ! -d "${pattern%/...}" ] || present="$present $pattern"
    done
    # shellcheck disable=SC2086
    [ -z "$present" ] || CGO_ENABLED=0 go test ${tags:+-tags "$tags"} -count=1 -timeout 15m -skip Geodata $present
fi
CGO_ENABLED=0 go build ${tags:+-tags "$tags"} -trimpath -buildvcs=false \
    -ldflags '-s -w -X github.com/xtls/xray-core/core.build=vpnbot-security.1' -o "$output" ./main
"$output" version
# Тег сборки меняет поведение ядра, а без него сборка тоже проходит: сверяем
# то, что реально записано в бинарнике.
if [ -n "$tags" ]; then
    go version -m "$output" | grep -Eq -- "-tags=([^[:space:]]*,)?$tags(,|\$)" || {
        echo "Ядро $repo/$version собрано без тега $tags" >&2
        exit 1
    }
fi
