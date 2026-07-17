#!/bin/sh
# Быстрая диагностика бота/вебхука одним прогоном (запускать на сервере из
# корня репо). Только чтение — ничего не перезапускает и не правит.
# Использование: sh scripts/diagnose_bot.sh
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

section() {
    echo ""
    echo "=== $1 ==="
}

section "git / версия"
echo "branch: $(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'no git')"
echo "commit: $(git rev-parse --short HEAD 2>/dev/null || true)"
grep -E '^(VER|BUILD_COMMIT)=' .env 2>/dev/null || true

VER="$(grep -E '^VER=' .env 2>/dev/null | cut -d= -f2-)"
PHP_CNT="php-${VER}"

section "контейнеры (${VER:-VER не найден})"
docker ps -a --format '{{.Names}}\t{{.Status}}' | grep -- "-${VER}\$" || docker ps -a --format '{{.Names}}\t{{.Status}}'

section "php: health"
docker inspect -f '{{.State.Status}} health={{if .State.Health}}{{.State.Health.Status}}{{else}}n/a{{end}}' "$PHP_CNT" 2>/dev/null \
    || echo "контейнер $PHP_CNT не найден"
docker inspect -f '{{range .State.Health.Log}}{{.End}} exit={{.ExitCode}} {{.Output}}{{end}}' "$PHP_CNT" 2>/dev/null | tail -3 || true

section "host :443 / :80 (вебхуку нужен 443)"
# /dev/tcp — башизм, в dash его нет: без nc пробу честно пропускаем,
# а не рапортуем ложный CLOSED.
if command -v nc >/dev/null 2>&1; then
    for p in 443 80; do
        nc -z -w 2 127.0.0.1 "$p" 2>/dev/null && echo ":$p open" || echo ":$p CLOSED"
    done
else
    echo "nc не установлен — проба портов пропущена (ss -tlnp | grep ':443')"
fi

section "getWebhookInfo"
# checkwebhook.php читает ./config.php — выполняем из /app внутри php-контейнера.
# Вебхук-URL содержит ключ бота (?k=…) — маскируем, чтобы вывод можно было
# безопасно копировать в issue/чат.
docker exec -w /app "$PHP_CNT" php checkwebhook.php 2>/dev/null \
    | sed -E 's/k=[^"&\\]+/k=***/g; s#/bot[0-9]+:[A-Za-z0-9_-]+/#/bot***/#g' \
    || echo "не удалось выполнить checkwebhook.php (php-контейнер лежит?)"

section "logs: requests_error (ошибки Telegram API)"
tail -5 logs/requests_error 2>/dev/null || echo "нет logs/requests_error (ошибок не было или бот не писал)"

section "logs: свежие ошибки"
for f in logs/upstream_error logs/nginx_error logs/error; do
    [ -f "$f" ] && { echo "--- $f"; tail -5 "$f"; }
done
# Всё, что менялось за последние сутки — быстрый указатель, куда смотреть.
find logs -maxdepth 1 -type f -mtime -1 2>/dev/null | head -15

section "диск / права /logs"
df -h . | tail -1
ls -ld logs 2>/dev/null || true
