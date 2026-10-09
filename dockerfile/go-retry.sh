#!/bin/sh
# Повтор команды Go при сбое сети. Прокси модулей (proxy.golang.org) и GitHub
# иногда не отвечают на минуту-две — «TLS handshake timeout» посреди сборки
# обрывал образ и весь прогон. Уже скачанные модули остаются в кеше, поэтому
# повтор продолжает с места сбоя. Ошибки компиляции и тестов не повторяются.
set -u
log=$(mktemp)
trap 'rm -f "$log"' EXIT
for delay in ${GO_RETRY_DELAYS:-10 30 60} last; do
    "$@" 2>"$log" && { cat "$log" >&2; exit 0; }
    code=$?
    cat "$log" >&2
    [ "$delay" != last ] || exit "$code"
    # Только сообщения самой команды go о загрузке («go: модуль: Get …»): слова
    # «i/o timeout» в выводе упавшего теста поводом для повтора не являются.
    grep -Eq '^go: .*(TLS handshake timeout|i/o timeout|connection reset|connection refused|unexpected EOF|dial tcp|no such host|proxyconnect|server misbehaving|context deadline exceeded|50[234] (Bad Gateway|Service|Gateway))' "$log" || exit "$code"
    echo "go-retry: сбой сети при «$*», повтор через $delay с" >&2
    sleep "$delay"
done
