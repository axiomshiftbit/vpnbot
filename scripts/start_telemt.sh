cat /ssh/key.pub > /root/.ssh/authorized_keys
ssh-keygen -A
exec /usr/sbin/sshd -D -e "$@" &

# /telemt — bind-mount конфига (config/telemt). data/ хранит replay-кэш и
# fake-сертификаты telemt. /logs — для просмотра журнала в боте.
mkdir -p /telemt/data /logs
[ -f /logs/telemt ] || : > /logs/telemt

# Бинарь поднимает сам бот (restartTelemt) после записи telemt.toml, поэтому
# здесь только держим контейнер живым.
tail -f /dev/null
