#!/bin/bash
pwd=$(pwd)
TELEGRAM_API=$(grep -m1 '^TELEGRAM_API=' "$pwd/.env" 2>/dev/null | cut -d'=' -f2-)
TELEGRAM_API=${TELEGRAM_API:-api.telegram.org}
# Взаимное исключение через flock, а не через «убить всё похожее».
# Было: pgrep -f "$pwd/update/update.sh" + kill -9. Это матчило ЛЮБУЮ командную
# строку с этой подстрокой — `tail -f …/update.sh`, `vim …/update.sh`,
# `grep … update.sh` — и убивало их. Хуже: kill -9 прилетал работающему
# экземпляру в любой момент, в том числе посреди `git reset --hard` или
# `docker compose down`, оставляя дерево и контейнеры в промежуточном
# состоянии, а update_pid — указывающим на труп.
#
# -w 10, а не -n: в конце цикла скрипт перезапускает сам себя
# (`bash update.sh &` + exit), и ребёнок обязан дождаться, пока родитель
# отпустит лок. Настоящий второй экземпляр столько не ждёт и просто выходит.
# Если flock в системе нет (util-linux не установлен), работаем как раньше —
# лучше без лока, чем не запуститься вовсе.
if command -v flock >/dev/null 2>&1; then
    exec 9>"$pwd/update/.lock"
    if ! flock -w 10 9; then
        echo "update.sh: другой экземпляр уже работает, выходим" >&2
        exit 0
    fi
fi

: > "$pwd/update/pipe"
echo "$$" > "$pwd/update/update_pid"

tg_draft() {
    local text="$1"
    local escaped="${text//\\/\\\\}"
    escaped="${escaped//\"/\\\"}"
    curl -s -H "Content-Type: application/json" \
        -X POST "https://$TELEGRAM_API/bot$_key/sendMessageDraft" \
        -d "{\"chat_id\":$_chat_id,\"draft_id\":1,\"text\":\"$escaped\"}" > /dev/null
}

while true
do
    cmd=$(cat "$pwd/update/pipe")
    branch=$(cat "$pwd/update/branch" 2>/dev/null)
    if [[ -n "$cmd" ]]
    then
        _key=$(cat "$pwd/update/key")
        _curl_data=$(cat "$pwd/update/curl")
        _chat_id=$(echo "$_curl_data" | grep -o '"chat_id":[0-9-]*' | head -1 | cut -d: -f2)
        _message_id=$(echo "$_curl_data" | grep -o '"message_id":[0-9]*' | head -1 | cut -d: -f2)

        tg_draft "stopping the bot"
        docker compose down --remove-orphans

        if [[ "$cmd" == "1" ]]
        then
            # Коммит ДО всех операций. Код обновляется не только `git pull`:
            # при заданном update/branch он переезжает уже на `git checkout -t`,
            # и pull после этого честно печатает «Already up to date.». Раньше в
            # отчёт уходил вывод одного лишь pull, поэтому смена ветки выглядела
            # как «ничего не обновилось», хотя приезжали десятки коммитов.
            before=$(git rev-parse HEAD 2>/dev/null)
            tg_draft "clearing the directory"
            git reset --hard && git clean -fd
            tg_draft "downloading the update"
            git fetch
            if [[ -n "$branch" ]]
            then
                tg_draft "changing branch"
                git checkout -t "origin/$branch" || git checkout "$branch"
            fi
            tg_draft "applying updates"
            pull_out=$(git pull 2>&1)
            after=$(git rev-parse HEAD 2>/dev/null)

            if [[ -z "$before" || -z "$after" || "$before" == "$after" ]]
            then
                # Ничего не поменялось — отдаём вывод pull как есть: там либо
                # «Already up to date.», либо текст ошибки, и терять его нельзя.
                echo "$pull_out" > ./update/message
            else
                applied=$(git log --oneline --no-decorate -30 "$before..$after" 2>/dev/null)
                total=$(git rev-list --count "$before..$after" 2>/dev/null || echo 0)
                {
                    echo "$(git rev-parse --abbrev-ref HEAD): ${before:0:7} -> ${after:0:7}"
                    if [[ -n "$applied" ]]
                    then
                        echo "$applied"
                        # Ограничение сверху: первый переезд между ветками даёт
                        # сотни строк, а сообщение Telegram обрезано 4096.
                        [[ "$total" -gt 30 ]] && echo "…и ещё $((total - 30))"
                    else
                        echo "(откат назад по истории)"
                    fi
                } > ./update/message
            fi
        fi

        # Канал образов приводим к ветке ПОСЛЕ checkout и ДО `make start` (тот
        # первым делом делает pull образов). Снаружи if'а по $cmd намеренно:
        # рестарт (cmd=2) обязан чинить пару так же, как обновление, иначе
        # разъехавшийся VPNBOT_TAG живёт до следующего git-обновления.
        #
        # Исполняем КОПИЮ в update/ (каталог вне git: .gitignore update/*), а
        # свежую кладём туда же, если она есть в только что выкаченном дереве.
        # Порядок именно такой из-за переезда НА ветку, где скрипта ещё нет:
        # scripts/ читается уже после checkout, и без пережившей checkout копии
        # канал образов остался бы от прежней ветки. Сам update.sh переживает
        # подмену только потому, что git checkout заводит новый inode, а bash
        # держит открытым старый.
        if [[ -f "$pwd/scripts/sync_image_tag.sh" ]]
        then
            cp -f "$pwd/scripts/sync_image_tag.sh" "$pwd/update/sync_image_tag.sh"
        fi
        # Скрипт молчит, когда менять нечего; строку об изменении дописываем в
        # отчёт, который бот отправит после старта.
        if [[ -f "$pwd/update/sync_image_tag.sh" ]]
        then
            tg_draft "syncing image channel"
            bash "$pwd/update/sync_image_tag.sh" "$pwd" >> "$pwd/update/message"
        fi

        tg_draft "launching the bot"
        make start

        : > "$pwd/update/key"
        : > "$pwd/update/curl"

        curl -s -H "Content-Type: application/json" \
            -X POST "https://$TELEGRAM_API/bot$_key/sendMessage" \
            -d "{\"chat_id\":$_chat_id,\"text\":\"bot started\"}" > /dev/null

        bash "$pwd/update/update.sh" &
        exit 0
    fi
    sleep 1
done
