cat /ssh/key.pub > /root/.ssh/authorized_keys
ssh-keygen -A
exec /usr/sbin/sshd -D -e "$@" &
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
uuid=$(cat /xray.json | jq -r '.inbounds[0].settings.clients[0].id // empty')
if [ -n "$uuid" ]; then
    xray run -config /xray.json > /dev/null 2>&1 &
fi
tail -f /dev/null
