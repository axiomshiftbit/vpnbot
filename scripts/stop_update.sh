#!/bin/sh
# Остановка фонового update/update.sh по pid-файлу.
#
# Было: `kill -9 $(cat ./update/update_pid)` в makefile (цель d) и в
# ExecStopPost юнита. PID'ы переиспользуются, а pid-файл переживает
# перезагрузку — после ребута сигнал уходил ПРОИЗВОЛЬНОМУ процессу с тем же
# номером (докеру, systemd-юниту, чему угодно), причём `> /dev/null` даже не
# прятал stderr, а прятал только вывод cat.
#
# Поэтому: сверяем /proc/<pid>/cmdline и шлём TERM, а не KILL — update.sh
# успевает доиграть текущий шаг, вместо того чтобы умереть посреди
# `git reset --hard` или `docker compose down`.
pidfile=${1:-./update/update_pid}

pid=$(tr -dc '0-9' < "$pidfile" 2>/dev/null)

# -a: cmdline разделён нулями, grep без него считает файл бинарным.
if [ -n "$pid" ] && grep -qa 'update.sh' "/proc/$pid/cmdline" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
fi

# TERM может завершить bash раньше его дочерней операции Compose. Дочерний
# процесс сохраняет унаследованный lock воркера до завершения операции.
# Ждём и при уже умершем родителе; иначе следующий up/down гоняется с apply.
lock="$(dirname "$pidfile")/.lock"
if [ -e "$lock" ] && ! flock -w 60 "$lock" true; then
    echo 'update.sh: операция ещё выполняется; остановка контейнеров отменена' >&2
    exit 1
fi
exit 0
