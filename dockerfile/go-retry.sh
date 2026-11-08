#!/bin/sh
# Повтор команды Go при сбое сети. Прокси модулей (proxy.golang.org) и GitHub
# иногда не отвечают на минуту-две — «TLS handshake timeout» посреди сборки
# обрывал образ и весь прогон. Уже скачанные модули остаются в кеше, поэтому
# повтор продолжает с места сбоя. Ошибки компиляции и тестов не повторяются.
set -u
# «|» вместо запятой: при любой ошибке прокси, включая таймаут, модуль берётся
# напрямую из репозитория. Подмену исключают go.sum и sum.golang.org.
export GOPROXY="${GOPROXY:-https://proxy.golang.org|direct}"
log=$(mktemp)
trap 'rm -f "$log"' EXIT
for delay in ${GO_RETRY_DELAYS:-10 30 60 90 120} last; do
    "$@" 2>"$log" && { cat "$log" >&2; exit 0; }
    code=$?
    cat "$log" >&2
    [ "$delay" != last ] || exit "$code"
    # Только сообщения о загрузке модулей: «go: модуль: Get …» у go get/list и
    # «файл.go:7:2: модуль@версия: Get "https://…": …» у go build. Слова
    # «i/o timeout» в выводе упавшего теста поводом для повтора не являются.
    grep -Eq '(^go: |[^ ]+@v[^ ]*: (Get|reading|verifying) ).*(TLS handshake timeout|i/o timeout|connection reset|connection refused|unexpected EOF|dial tcp|no such host|proxyconnect|server misbehaving|context deadline exceeded|50[234] (Bad Gateway|Service|Gateway))' "$log" || exit "$code"
    echo "go-retry: сбой сети при «$*», повтор через $delay с" >&2
    sleep "$delay"
done
