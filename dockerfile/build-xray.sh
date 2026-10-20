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
    # Форк 26.10.13 добавил в testing/release проверки самого репозитория:
    # им нужны git-чекаут (git check-ignore, ls-files) и bash, а сборка идёт
    # из архива исходников на Alpine. Тег http2legacy сверяется ниже по
    # готовому бинарнику. Два теста splithttp форка сравнивают скорость с
    # обычным HTTP/2 (не ниже 85 %), автор сам помечает их timing-sensitive:
    # на загруженном сборщике (2 vCPU, четыре сборки рядом) они падают.
    skip='Geodata|^TestAgentDocPathsExist$|^TestExplicitBuildTagsKeepHTTP2Legacy$|^TestSetupWorktree|^TestGates|^TestFlowFastReaderKeepsThroughput$|^TestFlowClientKeepsThroughput$'
    # shellcheck disable=SC2086
    [ -z "$present" ] || CGO_ENABLED=0 sh /build-tools/go-retry.sh go test ${tags:+-tags "$tags"} -count=1 -timeout 15m -skip "$skip" $present
fi
CGO_ENABLED=0 sh /build-tools/go-retry.sh go build ${tags:+-tags "$tags"} -trimpath -buildvcs=false \
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
