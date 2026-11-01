#!/bin/sh
cat /ssh/key.pub > /root/.ssh/authorized_keys
# Ключ узла выдаёт контейнер php (ssh/hosts/<сервис>): бот сверяет его
# отпечаток перед каждой командой. Случайный ключ бот не примет.
# Каталог подключён, а ключа ещё нет — php не успел его создать: ждём.
hostkey_wait=0; while [ -d /hostkey ] && [ ! -s /hostkey/ssh_host_ed25519_key.pub ] && [ "$hostkey_wait" -lt 60 ]; do sleep 1; hostkey_wait=$((hostkey_wait + 1)); done
cp -p /hostkey/ssh_host_ed25519_key /hostkey/ssh_host_ed25519_key.pub /etc/ssh/ 2>/dev/null || ssh-keygen -A
# Без exec: `exec cmd &` порождает подоболочку, которую exec собой и
# заменяет, то есть это обычный фоновый запуск, но читается как «заменить
# текущий процесс» (то же пояснение есть в start_wp.sh).
/usr/sbin/sshd -D -e "$@" &
# Каталог с внешними .dat (ext:/extip: из routes → dat) — общий с php через /logs.
# Задаём asset-путь ядру, иначе ext:geoip.dat:… не резолвится и xray не стартует.
mkdir -p /logs/geodata
export XRAY_LOCATION_ASSET=/logs/geodata
# Активное ядро: три версии XTLS и форк со sing-mux. Выбор бот пишет
# в /logs/xray_core (общий с php том),
# а сюда оно приезжает симлинком — так все вызовы `xray …` (бот, статистика,
# ручной ssh) сами попадают в нужный бинарь. Симлинк живёт в слое контейнера и
# пропадает при пересоздании, поэтому восстанавливаем его на каждом старте.
case "$(cat /logs/xray_core 2>/dev/null)" in
    origin2) bin=/usr/bin/xray-2 ;;
    origin3) bin=/usr/bin/xray-3 ;;
    fork) bin=/usr/bin/xray-smux ;;
    *) bin=/usr/bin/xray ;;
esac
mkdir -p /usr/local/bin
ln -sf "$bin" /usr/local/bin/xray
# Optional fixed AWG carriers are supervised separately from core restarts.
# No keys are passed on the command line or written into logs.
python3 -I /node-carrier/node_awg_client.py >/dev/null 2>&1 &
uuid=$(jq -r '.inbounds[0].settings.clients[0].id // empty' /xray.json 2>/dev/null)
if [ ! -x "$bin" ]; then
    # SSH остаётся доступен, чтобы выбрать имеющуюся версию из бота.
    # Тихая замена версии может нарушить совместимость REALITY и SMUX.
    echo "$(date '+%Y-%m-%d %H:%M:%S') start_xray: selected core $bin missing — xray NOT started" >> /logs/xray_stdout
elif [ -n "$uuid" ]; then
    # stderr ядра — в лог, а не в /dev/null: при битом xray.json причина старта
    # не была видна нигде, а контейнер жил через `tail -f /dev/null` и выглядел
    # здоровым.
    xray run -config /xray.json >> /logs/xray_stdout 2>&1 &
    xray_pid=$!
    # Частное состояние привязано к конкретному процессу, а не только PID.
    # Старый образ без python/helper продолжает работать с полным restart.
    python3 /xray_hot_apply.py mark --pid "$xray_pid" >/dev/null 2>&1 || true
else
    # Пустой uuid — это не «нечего запускать»: первый inbound без clients
    # (dokodemo/fallback-раскладка) или ошибка jq на битом конфиге дают ровно
    # то же значение, и ядро молча не запускалось вовсе.
    echo "$(date '+%Y-%m-%d %H:%M:%S') start_xray: no client uuid in /xray.json — xray NOT started" >> /logs/xray_stdout
fi
tail -f /dev/null
