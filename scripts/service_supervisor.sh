#!/bin/sh
# Контейнер сохраняет SSH при intentional off; аварийный exit перезапускает
# только собственный процесс. PID + Linux starttime защищают от PID reuse.
set -u
umask 077
BASE=/run/vpnbot-services
HELPER=/service_daemon.sh
ACTION=${1:-}
NAME=${2:-}

fail() { echo 'Service operation failed' >&2; exit 1; }
case "$ACTION" in supervise|start|stop|restart|status|health) ;; *) fail;; esac
if [ "$ACTION" != supervise ] && [ "${3:-}" != --bounded ]; then
    # Общий предел включает ожидание lock, остановку и readiness.
    exec timeout 45 /bin/sh "$0" "$ACTION" "$NAME" --bounded
fi
[ ! -L "$BASE" ] && mkdir -p "$BASE" && chmod 700 "$BASE" || fail

identity() {
    case "$1" in ''|*[!0-9]*) return 1;; esac
    [ -r "/proc/$1/stat" ] || return 1
    read -r state < "/proc/$1/stat" || return 1
    state=${state##*) }
    [ "${state%% *}" != Z ] || return 1
    printf '%s\n' "$state" | awk '{print $20}'
}

select_service() {
    NAME=$1
    case "$NAME" in adguard|ssserver|sslocal|ck-server|simple-tls|naive|trusttunnel|dnstt) ;; *) return 1;; esac
    DIR=$BASE/$NAME
    [ ! -L "$DIR" ] && mkdir -p "$DIR" && chmod 700 "$DIR"
}

lock_service() {
    exec 9>"$DIR/lock" || return 1
    tries=0
    until flock -n 9; do
        tries=$((tries + 1)); [ "$tries" -lt 75 ] || return 1
        sleep .2
    done
}

alive() {
    [ -r "$DIR/pid" ] && read -r PID START < "$DIR/pid" || return 1
    [ -n "$START" ] && [ "$(identity "$PID")" = "$START" ]
}

plugin_children() {
    [ -s "$DIR/plugin-executable" ] || return 0
    read -r plugin_executable < "$DIR/plugin-executable" || return 1
    for directory in /proc/[0-9]*; do
        [ -r "$directory/stat" ] || continue
        read -r child_state < "$directory/stat" || continue
        child_state=${child_state##*) }
        child_session=$(printf '%s\n' "$child_state" | awk '{print $4}')
        child_start=$(printf '%s\n' "$child_state" | awk '{print $20}')
        child_pid=${directory##*/}
        # setsid создал отдельную сессию только для этого сервиса. После
        # SIGKILL родителя plugin может стать orphan, сохранив session ID.
        [ "$child_session" = "$PID" ] && [ "$child_pid" != "$PID" ] && [ "$child_start" -ge "$START" ] || continue
        [ "$(readlink "$directory/exe" 2>/dev/null)" = "$plugin_executable" ] || continue
        [ "$(identity "$child_pid")" = "$child_start" ] || continue
        printf '%s %s\n' "$child_pid" "$child_start"
    done
}

append_sockets() {
    for fd in /proc/"$1"/fd/*; do
        target=$(readlink "$fd" 2>/dev/null) || continue
        case "$target" in socket:\[*\]) inode=${target#socket:[}; inode=${inode%]}; inodes="$inodes$inode ";; esac
    done
}

ready() {
    alive || return 1
    expected=$(sh "$HELPER" executable "$NAME") || return 1
    [ "$(readlink "/proc/$PID/exe" 2>/dev/null)" = "$expected" ] || return 1
    # Сокет принадлежит именно этому процессу; другой listener не даёт READY.
    inodes=' '
    append_sockets "$PID"
    if [ -s "$DIR/plugin-executable" ]; then
        children=$(plugin_children) || return 1
        [ -n "$children" ] || return 1
        # Child identity проверяется до и после чтения его дескрипторов.
        old_ifs=$IFS; IFS='
'
        for child in $children; do
            IFS=$old_ifs; read -r child_pid child_start <<EOF
$child
EOF
            append_sockets "$child_pid"
            [ "$(identity "$child_pid")" = "$child_start" ] || return 1
            IFS='
'
        done
        IFS=$old_ifs
    fi
    [ -s "$DIR/ports" ] || return 1
    set --
    for table in /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6; do
        [ ! -r "$table" ] || set -- "$@" "$table"
    done
    [ "$#" -gt 0 ] || return 1
    awk -v inodes="$inodes" 'NR==FNR {
            split($0,parts,":"); required[parts[1] ":" sprintf("%04X",parts[2]+0)]=1; next
        }
        FNR>1 && index(inodes," "$10" ") &&
        ($4=="0A" || (FILENAME ~ /udp/ && $4=="07")) {
            split($2,address,":"); found[(FILENAME ~ /udp/?"udp:":"tcp:") address[2]]=1
        }
        END {for (key in required) if (!found[key]) exit 1}' "$DIR/ports" "$@" 2>/dev/null || return 1
    alive
}

stopped() {
    # desired=off records intent; it is not evidence that a failed/interrupted
    # stop has removed the old process and its independently living plugin.
    [ ! -L "$DIR/pid" ] || return 1
    [ -e "$DIR/pid" ] || return 0
    [ -f "$DIR/pid" ] && awk 'NR!=1 || NF!=2 || $1!~/^[0-9]+$/ || $2!~/^[0-9]+$/ || $1+0<1 || $2+0<1 {bad=1}
        END {exit bad || NR!=1}' "$DIR/pid" || return 1
    read -r PID START < "$DIR/pid" || return 1
    [ "$(identity "$PID")" != "$START" ] || return 1
    if [ -e "$DIR/plugin-executable" ] || [ -L "$DIR/plugin-executable" ]; then
        [ ! -L "$DIR/plugin-executable" ] && [ -f "$DIR/plugin-executable" ] && [ -s "$DIR/plugin-executable" ] || return 1
        awk 'NR!=1 || substr($0,1,1)!="/" {bad=1} END {exit bad || NR!=1}' "$DIR/plugin-executable" || return 1
    fi
    children=$(plugin_children) || return 1
    [ -z "$children" ]
}

stop_daemon() {
    if alive; then
        # Только PID, полученный при нашем запуске, с тем же starttime.
        kill -TERM "$PID" 2>/dev/null || true
        tries=0; grace=50
        [ "$NAME" != adguard ] || grace=80
        while alive && [ "$tries" -lt "$grace" ]; do sleep .1; tries=$((tries + 1)); done
        if alive; then
            kill -KILL "$PID" 2>/dev/null || true
            tries=0
            while alive && [ "$tries" -lt 20 ]; do sleep .1; tries=$((tries + 1)); done
        fi
        alive && return 1
        wait "$PID" 2>/dev/null || true
    fi
    # Старый plugin не должен держать порт после смерти ssserver/sslocal.
    if [ -r "$DIR/pid" ] && read -r PID START < "$DIR/pid"; then
        children=$(plugin_children) || return 1
        old_ifs=$IFS; IFS='
'
        for child in $children; do
            IFS=$old_ifs; read -r child_pid child_start <<EOF
$child
EOF
            if [ "$(identity "$child_pid")" = "$child_start" ]; then
                kill -TERM "$child_pid" 2>/dev/null || true
                tries=0
                while [ "$(identity "$child_pid")" = "$child_start" ] && [ "$tries" -lt 20 ]; do sleep .1; tries=$((tries + 1)); done
                if [ "$(identity "$child_pid")" = "$child_start" ]; then
                    kill -KILL "$child_pid" 2>/dev/null || true
                    tries=0
                    while [ "$(identity "$child_pid")" = "$child_start" ] && [ "$tries" -lt 20 ]; do sleep .1; tries=$((tries + 1)); done
                    [ "$(identity "$child_pid")" != "$child_start" ] || return 1
                fi
                wait "$child_pid" 2>/dev/null || true
            fi
            IFS='
'
        done
        IFS=$old_ifs
    fi
    rm -f "$DIR/pid"
    sh "$HELPER" stopped "$NAME"
}

start_daemon() {
    if ready; then return 0; fi
    stop_daemon || return 1
    sh "$HELPER" enabled "$NAME" || return 1
    rm -f "$DIR/ports" "$DIR/plugin-executable"
    # Закрываем lock/guardian descriptors до exec: демон не удерживает locks.
    nohup setsid sh "$HELPER" run "$NAME" 9>&- 8>&- </dev/null >>"$DIR/launcher.log" 2>&1 &
    PID=$!
    START=$(identity "$PID") || return 1
    printf '%s %s\n' "$PID" "$START" > "$DIR/pid" || return 1
    tries=0
    while [ "$tries" -lt 100 ]; do
        ready && return 0
        alive || break
        sleep .2; tries=$((tries + 1))
    done
    stop_daemon || true
    return 1
}

guardian_alive() {
    [ -r "$BASE/guardian" ] && read -r guardian_pid guardian_start < "$BASE/guardian" || return 1
    [ -n "$guardian_start" ] && [ "$(identity "$guardian_pid")" = "$guardian_start" ]
}

if [ "$ACTION" = supervise ]; then
    case "$NAME" in
        ad) members=adguard;; ss) members='ssserver ck-server simple-tls';;
        proxy) members=sslocal;; np) members=naive;; tt) members=trusttunnel;; dnstt) members=dnstt;;
        *) fail;;
    esac
    exec 8>"$BASE/guardian.lock" || fail
    flock -n 8 || fail
    printf '%s %s\n' "$$" "$(identity "$$")" > "$BASE/guardian"
    printf '%s\n' "$members" > "$BASE/members"
    for member in $members; do
        select_service "$member" && lock_service || fail
        case "$member" in
            adguard|ssserver|sslocal) echo on > "$DIR/desired";;
            *) if sh "$HELPER" enabled "$member"; then echo on > "$DIR/desired"; else echo off > "$DIR/desired"; fi;;
        esac
        flock -u 9
    done
    # docker stop завершает только управляемые PID; SSH не получает service-stop.
    shutdown() {
        trap '' TERM INT
        for member in $members; do
            if select_service "$member" && lock_service; then
                echo off > "$DIR/desired"; stop_daemon || true; flock -u 9
            fi
        done
        rm -f "$BASE/guardian"
        exit 0
    }
    trap shutdown TERM INT
    while :; do
        for member in $members; do
            if select_service "$member" && lock_service; then
                read -r desired < "$DIR/desired" || desired=off
                if [ "$desired" = on ]; then
                    ready || start_daemon || true
                fi
                flock -u 9
            fi
        done
        sleep 1
    done
fi

guardian_alive || fail
[ -r "$BASE/members" ] && read -r members < "$BASE/members" || fail
if [ "$ACTION" = health ]; then
    for member in $members; do
        select_service "$member" && lock_service || fail
        read -r desired < "$DIR/desired" || fail
        if [ "$desired" = off ]; then stopped || fail; else ready || fail; fi
        flock -u 9
    done
    exit 0
fi
case " $members " in *" $NAME "*) ;; *) fail;; esac
select_service "$NAME" && lock_service || fail
case "$ACTION" in
    stop)
        echo off > "$DIR/desired"
        stop_daemon || fail
        echo "VPNBOT_SERVICE_STOPPED:$NAME";;
    start|restart)
        echo on > "$DIR/desired"
        if [ "$ACTION" = restart ]; then stop_daemon || fail; fi
        start_daemon || fail
        echo "VPNBOT_SERVICE_READY:$NAME";;
    status)
        read -r desired < "$DIR/desired" || fail
        if [ "$desired" = off ]; then stopped || fail; exit 3; fi
        ready || fail;;
esac
