#!/bin/bash
# Канал образов (VPNBOT_TAG) приводится к ВЕТКЕ КОДА.
#
# Зачем: dockerfile и использующий его PHP лежат в одном коммите, поэтому канал
# образов обязан совпадать с веткой (ПРАВИЛО ПАРНОСТИ, см. комментарий в .env).
# Ветку бот переключает кнопкой (пишет update/branch, дальше update/update.sh
# делает checkout), а VPNBOT_TAG до сих пор правился на машине руками — то есть
# после «сменил ветку на dev и нажал обновление» приезжал код dev с образами
# master. Скрипт закрывает вторую половину: его зовёт update/update.sh перед
# `make start`, уже ПОСЛЕ checkout, по фактическому HEAD.
#
# Куда пишем: override.env. Он подключается вторым (см. makefile) и перекрывает
# .env, не отслеживается git и переживает `git reset --hard && git clean -fd`,
# которым update.sh чистит дерево. Писать в .env нельзя — его тем же reset'ом
# вернёт к шаблону.
#
# Соответствие каналов задано в .github/workflows/images.yml:
#   ветка master -> тег latest,  любая другая ветка -> тег dev.
#
# Печатает ОДНУ строку, только если тег реально сменился (её update.sh кладёт в
# отчёт об обновлении). Молчит, когда всё уже согласовано.
#
# Использование: sync_image_tag.sh [repo_root]
# -e, а не только -u: ниже собирается временный файл, содержимое которого потом
# ЗАТИРАЕТ override.env целиком. Провал grep/записи (ENOSPC, права) оставлял бы
# пустой tmp, и следующая строка сносила настройки машины — порты, TZ, пины.
set -eu

root="${1:-$(pwd)}"
env_file="$root/override.env"

# `|| true`: вне репозитория git отдаёт ненулевой код, и под set -e присваивание
# уронило бы скрипт — а это штатная ситуация, ниже она обрабатывается.
branch=$(git -C "$root" rev-parse --abbrev-ref HEAD 2>/dev/null || true)
# Пусто (не репозиторий, git недоступен) или detached HEAD (`checkout <sha>`):
# ветки нет — угадывать канал не из чего, молча выходим.
if [[ -z "$branch" || "$branch" == "HEAD" ]]; then
    exit 0
fi

if [[ "$branch" == "master" ]]; then
    want=latest
else
    want=dev
fi

cur=""
if [[ -f "$env_file" ]]; then
    cur=$(grep -m1 '^VPNBOT_TAG=' "$env_file" | cut -d= -f2- || true)
fi

if [[ "$cur" == "$want" ]]; then
    exit 0
fi

# Пин на конкретную сборку (sha-<commit>) — осознанный откат, описанный в .env.
# Его правило парности не отменяет: канальные теги latest/dev разъезжаются сами,
# а sha- ставят руками и ровно для того, чтобы он держался. Снимается тоже
# руками — удалением строки из override.env.
if [[ "$cur" == sha-* ]]; then
    exit 0
fi

# Лок берём ровно перед перезаписью — и только когда точно будем писать:
# иначе .lock появлялся бы даже там, где скрипту делать нечего.
if command -v flock >/dev/null 2>&1; then
    exec 9>"$env_file.lock"
    flock -w 10 9 || {
        echo "sync_image_tag: не дождался лока override.env" >&2
        exit 0
    }
fi

tmp="$env_file.tmp.$$"
# Все прочие строки сохраняем: в override.env лежат и другие настройки машины
# (порты, TZ). Пишем через `cat >` в исходный файл, а не mv: у файла может быть
# уже открытый читатель, а inode менять незачем.
if [[ -f "$env_file" ]]; then
    # grep возвращает 1, когда не осталось ни одной строки, — под set -e это
    # прервало бы скрипт на пустом (кроме VPNBOT_TAG) override.env.
    grep -v '^VPNBOT_TAG=' "$env_file" > "$tmp" || true
else
    : > "$tmp"
fi
echo "VPNBOT_TAG=$want" >> "$tmp"
# [ -s ] обязателен: пустой tmp означал бы затирание override.env целиком.
if [ ! -s "$tmp" ]; then
    rm -f "$tmp"
    echo "sync_image_tag: временный файл пуст — override.env не трогаем" >&2
    exit 1
fi
cat "$tmp" > "$env_file"
rm -f "$tmp"

echo "images: ${cur:-<.env>} -> $want (branch $branch)"
