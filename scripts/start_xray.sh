cat /ssh/key.pub > /root/.ssh/authorized_keys
ssh-keygen -A
exec /usr/sbin/sshd -D -e "$@" &
# Каталог с внешними .dat (ext:/extip: из routes → dat) — общий с php через /logs.
# Задаём asset-путь ядру, иначе ext:geoip.dat:… не резолвится и xray не стартует.
mkdir -p /logs/geodata
export XRAY_LOCATION_ASSET=/logs/geodata
uuid=$(cat /xray.json | jq -r '.inbounds[0].settings.clients[0].id // empty')
if [ -n "$uuid" ]; then
    xray run -config /xray.json > /dev/null 2>&1 &
fi
tail -f /dev/null
