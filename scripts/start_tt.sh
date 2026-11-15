#!/bin/sh
cat /ssh/key.pub > /root/.ssh/authorized_keys 2>/dev/null || true
# Ключ узла выдаёт контейнер php (ssh/hosts/<сервис>): бот сверяет его
# отпечаток перед каждой командой. Случайный ключ бот не примет.
# Каталог подключён, а ключа ещё нет — php не успел его создать: ждём.
hostkey_wait=0; while [ -d /hostkey ] && [ ! -s /hostkey/ssh_host_ed25519_key.pub ] && [ "$hostkey_wait" -lt 60 ]; do sleep 1; hostkey_wait=$((hostkey_wait + 1)); done
{ cp -p /hostkey/ssh_host_ed25519_key /hostkey/ssh_host_ed25519_key.pub /etc/ssh/ 2>/dev/null || ssh-keygen -A; } >/dev/null 2>&1 || true
/usr/sbin/sshd -D -e "$@" &

# /logs — bind-mount с хоста; создаём каталог и pre-touch лог, чтобы
# просмотр журнала в боте не падал на ENOENT, если конфиги TT ещё
# не разложены и демон не стартовал.
mkdir -p /logs
[ -f /logs/trusttunnel.log ] || : > /logs/trusttunnel.log

CFG=/trusttunnel_endpoint

# Условия старта те же, что в боте (ttBlockers): наличия четырёх файлов мало.
#  - credentials.toml без единого [[client]] = паника на разборе настроек
#    («invalid value: Not an array of clients»), потому что credentials_file
#    десериализуется в Vec<Client>, а публичный listen_address без клиентов
#    эндпоинт считает ошибкой безопасности. Шаблон в репозитории — это только
#    комментарии, так что на свежей установке демон гарантированно падал;
#  - без cert_public/cert_private нечем поднять TLS-хост.
# Не стартуем молча и пишем причину в журнал, который показывает бот.
ttlog() { echo "[start_tt $(date +%H:%M:%S)] $*" >> /logs/trusttunnel.log; }

start_ok=1
for f in vpn.toml hosts.toml credentials.toml rules.toml; do
    if [ ! -f "$CFG/$f" ]; then
        ttlog "not started: missing $f"
        start_ok=0
    fi
done
if [ "$start_ok" = 1 ] && ! grep -q '^[[:space:]]*\[\[client\]\]' "$CFG/credentials.toml"; then
    ttlog "not started: credentials.toml has no [[client]] — add a peer via the bot menu"
    start_ok=0
fi
if [ "$start_ok" = 1 ] && { [ ! -f /certs/cert_public ] || [ ! -f /certs/cert_private ]; }; then
    ttlog "not started: missing /certs/cert_public or /certs/cert_private"
    start_ok=0
fi

exec /bin/sh /service_supervisor.sh supervise tt
