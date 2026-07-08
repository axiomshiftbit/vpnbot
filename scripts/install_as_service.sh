path=`pwd`
# Заменяем отличимый плейсхолдер, а не слово «path» глобально, иначе замена
# затронула бы любое вхождение подстроки в шаблоне.
sed "s|__VPNBOT_PATH__|$path|g" "$path/scripts/vpnbot.service" > /etc/systemd/system/vpnbot.service
systemctl daemon-reload
systemctl enable vpnbot
