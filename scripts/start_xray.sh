#!/bin/sh
cat /ssh/key.pub > /root/.ssh/authorized_keys
ssh-keygen -A
# Без exec: `exec cmd &` порождает подоболочку, которую exec собой и
# заменяет, то есть это обычный фоновый запуск, но читается как «заменить
# текущий процесс» (то же пояснение есть в start_wp.sh).
/usr/sbin/sshd -D -e "$@" &
# Каталог с внешними .dat (ext:/extip: из routes → dat) — общий с php через /logs.
# Задаём asset-путь ядру, иначе ext:geoip.dat:… не резолвится и xray не стартует.
mkdir -p /logs/geodata
export XRAY_LOCATION_ASSET=/logs/geodata
# Активное ядро. В образе лежат оба: апстрим /usr/bin/xray и форк со sing-mux
# /usr/bin/xray-smux; выбранное бот пишет в /logs/xray_core (общий с php том),
# а сюда оно приезжает симлинком — так все вызовы `xray …` (бот, статистика,
# ручной ssh) сами попадают в нужный бинарь. Симлинк живёт в слое контейнера и
# пропадает при пересоздании, поэтому восстанавливаем его на каждом старте.
# Маркер просит форк, а бинаря нет (образ старее правки) — молча берём апстрим:
# контейнер обязан подняться в любом случае.
bin=/usr/bin/xray
if [ "$(cat /logs/xray_core 2>/dev/null)" = fork ] && [ -x /usr/bin/xray-smux ]; then
    bin=/usr/bin/xray-smux
fi
mkdir -p /usr/local/bin
ln -sf "$bin" /usr/local/bin/xray
uuid=$(jq -r '.inbounds[0].settings.clients[0].id // empty' /xray.json 2>/dev/null)
if [ -n "$uuid" ]; then
    # stderr ядра — в лог, а не в /dev/null: при битом xray.json причина старта
    # не была видна нигде, а контейнер жил через `tail -f /dev/null` и выглядел
    # здоровым.
    xray run -config /xray.json >> /logs/xray_stdout 2>&1 &
else
    # Пустой uuid — это не «нечего запускать»: первый inbound без clients
    # (dokodemo/fallback-раскладка) или ошибка jq на битом конфиге дают ровно
    # то же значение, и ядро молча не запускалось вовсе.
    echo "$(date '+%Y-%m-%d %H:%M:%S') start_xray: no client uuid in /xray.json — xray NOT started" >> /logs/xray_stdout
fi
tail -f /dev/null
