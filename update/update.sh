#!/bin/bash
pwd=$(pwd)
TELEGRAM_API=$(grep -m1 '^TELEGRAM_API=' "$pwd/.env" 2>/dev/null | cut -d'=' -f2-)
TELEGRAM_API=${TELEGRAM_API:-api.telegram.org}
process_name="$pwd/update/update.sh"
current_pid=$$
pids=$(pgrep -f "$process_name")
for pid in $pids; do
    if [ "$pid" -ne "$current_pid" ]; then
        kill -9 "$pid"
    fi
done

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
