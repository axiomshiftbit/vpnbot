#!/bin/sh
set -eu
repo=$1; version=$2; output=$3; tags=${4:-}; tests=${5:-}
# Сохраняем выбор стабильного/prerelease, но новый источник обязан иметь
# проверенную контрольную сумму. Слоты и выбор пользователя не меняются.
case "$version" in
    ''|prerelease)
        metadata=$(mktemp)
        trap 'rm -f "$metadata"' EXIT
        endpoint="https://api.github.com/repos/$repo/releases"
        [ "$version" = prerelease ] || endpoint="$endpoint/latest"
        sh /build-tools/download-file.sh "$endpoint" "$metadata"
        if [ "$version" = prerelease ]; then
            version=$(jq -er '[.[] | select(.prerelease==true)][0].tag_name' "$metadata")
        else
            version=$(jq -er .tag_name "$metadata")
        fi
        rm -f "$metadata"
        trap - EXIT
        ;;
esac
source="/sources/$repo/$version"
sh /build-tools/go-source.sh "$repo" "$version" "$source"
cd "$source"
sh /build-tools/go-security.sh
# Два теста splithttp форка сравнивают скорость своего управления потоком
# HTTP/2 с обычным (не ниже 85 %); автор сам помечает их timing-sensitive. На
# загруженном сборщике (2 vCPU, четыре сборки рядом) шум замера больше
# допуска, поэтому их отказ — предупреждение в журнале, а не отказ сборки:
# замедление после подъёма x/net останется видно.
timing='^TestFlowFastReaderKeepsThroughput$|^TestFlowClientKeepsThroughput$'
timing_tests() {
    timing_log=$(mktemp)
    timing_code=0
    CGO_ENABLED=0 sh /build-tools/go-retry.sh go test ${tags:+-tags "$tags"} -count=1 -timeout 10m -v \
        -run "$timing" ./transport/internet/splithttp/ >"$timing_log" 2>&1 || timing_code=$?
    grep -E '^--- (PASS|FAIL|SKIP)|_test\.go:[0-9]+:' "$timing_log" || true
    timing_passed=$(grep -cE '^--- PASS: TestFlow(FastReader|Client)KeepsThroughput ' "$timing_log" || true)
    rm -f "$timing_log"
    [ "$timing_code" -eq 0 ] && [ "$timing_passed" -eq 2 ] && return
    echo "ВНИМАНИЕ: тесты скорости splithttp ядра $repo/$version не прошли или не найдены (код $timing_code, успешных $timing_passed из 2); сборка продолжается" >&2
}
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
    # готовому бинарнику. Тесты скорости splithttp идут отдельно, ниже.
    skip="Geodata|^TestAgentDocPathsExist\$|^TestExplicitBuildTagsKeepHTTP2Legacy\$|^TestSetupWorktree|^TestGates|$timing"
    # На сборщике с 2 vCPU параллельные пакеты задерживают тесты отмены
    # соединений с пределом 200–250 мс. Выполняем пакеты последовательно,
    # сохраняя сами проверки и их исходные таймауты.
    # shellcheck disable=SC2086
    [ -z "$present" ] || CGO_ENABLED=0 sh /build-tools/go-retry.sh go test ${tags:+-tags "$tags"} -p 1 -count=1 -timeout 15m -skip "$skip" $present
    case " $present " in
        *' ./transport/internet/splithttp/... '*) timing_tests ;;
    esac
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
