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
set -u

root="${1:-$(pwd)}"
env_file="$root/override.env"

branch=$(git -C "$root" rev-parse --abbrev-ref HEAD 2>/dev/null)
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
    cur=$(grep -m1 '^VPNBOT_TAG=' "$env_file" | cut -d= -f2-)
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

tmp="$env_file.tmp.$$"
# Все прочие строки сохраняем: в override.env лежат и другие настройки машины
# (порты, TZ). Пишем через `cat >` в исходный файл, а не mv: у файла может быть
# уже открытый читатель, а inode менять незачем.
if [[ -f "$env_file" ]]; then
    grep -v '^VPNBOT_TAG=' "$env_file" > "$tmp"
else
    : > "$tmp"
fi
echo "VPNBOT_TAG=$want" >> "$tmp"
cat "$tmp" > "$env_file"
rm -f "$tmp"

echo "images: ${cur:-<.env>} -> $want (branch $branch)"
