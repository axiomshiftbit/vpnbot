#!/usr/bin/env bash
# Рабочие данные не должны проходить через пустые Git-шаблоны при обновлении.
# Неизменённые шаблоны не копируем: они должны обновляться вместе с кодом.
set -euo pipefail
umask 077
action=$1
cd "${2:-.}"
state=update/runtime-state

case "$action" in
    save)
        # Неполную предыдущую операцию нельзя затереть новым снимком.
        if [[ -e "$state" ]]; then
            echo 'update: unfinished runtime-state backup; restore it before retrying' >&2
            exit 1
        fi
        target=$state
        state=$(mktemp -d update/.runtime-state.XXXXXX)
        trap 'rm -rf -- "$state"' EXIT
        mkdir -m 700 "$state/files"
        roots=(config certs ssh app/config.php .env override.env docker-compose.override.yml)
        for root in "${roots[@]}"; do
            [[ -e "$root" || -L "$root" ]] || continue
            find "$root" \( -type f -o -type l \) -print0 >> "$state/paths"
        done
        while IFS= read -r -d '' path; do
            if [[ ! -L "$path" ]] && git cat-file -e "HEAD:$path" 2>/dev/null \
                && cmp -s -- "$path" <(git show "HEAD:$path"); then
                continue
            fi
            cp -a --parents -- "$path" "$state/files/"
        done < "$state/paths"
        # Сохраняем и намеренное отсутствие отслеживаемого runtime-файла.
        git ls-tree -r --name-only -z HEAD -- "${roots[@]}" > "$state/tracked"
        : > "$state/deleted"
        while IFS= read -r -d '' path; do
            [[ -e "$path" || -L "$path" ]] || printf '%s\0' "$path" >> "$state/deleted"
        done < "$state/tracked"
        touch "$state/ready"
        mv -- "$state" "$target"
        trap - EXIT
        ;;
    restore)
        [[ -f "$state/ready" ]]
        find "$state/files" -mindepth 1 -maxdepth 1 -exec cp -a -t . -- {} +
        while IFS= read -r -d '' path; do
            rm -f -- "$path"
        done < "$state/deleted"
        # service.php не должен поверх точной копии повторно импортировать JSON.
        touch update/state-restored
        # Один последний снимок остаётся для восстановления, без роста архива.
        rm -rf -- update/runtime-state.last
        mv -- "$state" update/runtime-state.last
        ;;
    *) exit 2 ;;
esac
