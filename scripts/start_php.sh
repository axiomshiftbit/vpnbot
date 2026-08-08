rm /ssh/key*
ssh-keygen -m PEM -t rsa -f /ssh/key -N ''
# Публичный ключ отдельным каталогом для контейнеров, которые терминируют
# НЕДОВЕРЕННЫЙ клиентский трафик (wg, wg1). Им нужен только key.pub — положить
# его в authorized_keys, чтобы бот мог зайти внутрь. Раньше туда монтировался
# весь /ssh, то есть вместе с ПРИВАТНЫМ ключом, а он даёт root-SSH во все
# остальные контейнеры (xr, ng, php…): одна дыра в wireguard-контейнере
# превращалась в компрометацию всей сборки.
mkdir -p /ssh/pub
cp /ssh/key.pub /ssh/pub/key.pub
chmod 0644 /ssh/pub/key.pub
openssl req -newkey rsa:2048 -sha256 -nodes -x509 -days 365 -keyout /certs/self_private -out /certs/self_public  -subj "/C=NN/ST=N/L=N/O=N/CN=$IP"
if [[ -f "/ssh/key.pub" && -s "/ssh/key.pub" ]]; then
    unitd --control 0.0.0.0:8080 --log /logs/unit_error
    curl -X PUT --data-binary @/config/unit.json http://127.0.0.1:8080/config
    php init.php
else
    exit 1;
fi
