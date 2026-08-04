cat /ssh/key.pub > /root/.ssh/authorized_keys
ssh-keygen -A
exec /usr/sbin/sshd -D -e "$@" &

# Не поднимаем caddy с плейсхолдерными кредами. Гард `!empty(naive.pass)` есть в
# restartNaive(), но на ЭТОТ путь он не распространялся: контейнер стартует сам,
# и на свежей установке naive уходил в сеть с угадываемыми «_ __». Поддомен при
# этом не секрет — certbot добавляет -d np.<domain>, то есть имя публикуется в
# Certificate Transparency.
if grep -qE '^[[:space:]]*basic_auth[[:space:]]+(CHANGEME[[:space:]]+CHANGEME|_[[:space:]]+__)[[:space:]]*$' /config/Caddyfile; then
    echo "naive: basic_auth не настроен (плейсхолдер) — caddy не запущен, задайте логин/пароль в боте" >> /logs/caddy
else
    # stdout/stderr в /logs/caddy, а не в /dev/null: сюда падают ошибки старта,
    # которых раньше не было видно нигде (в docker logs только sshd).
    caddy run -c /config/Caddyfile >> /logs/caddy 2>&1 &
fi

tail -f /dev/null
