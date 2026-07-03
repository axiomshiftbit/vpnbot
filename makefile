-include .env
export

IP := $(or $(IP),$(shell hostname -I | awk '{print $$1}'))
# VER идёт в имена контейнеров (container_name: php-${VER} и т.д.). Если в клоне
# нет тегов (теги не запушены в форк / не подтянуты), `git describe --tags`
# отдаёт ПУСТО → имена схлопываются в "php-"/"mtproto-"/… → конфликт имён при
# `up --force-recreate`, и бот/сервисы не стартуют. `--always` даёт короткий SHA
# без тегов, `|| echo local` страхует, если git недоступен — VER не пустой.
VER := $(shell git describe --tags --always 2>/dev/null || echo local)

b:
	docker compose build
preup:
	bash ./update/update.sh &
start: # запуск контейнеров
	touch ./override.env ./docker-compose.override.yml ./config/location.conf ./config/override.conf
	# L2TP/IPsec (сервис ipsec) требует модуль ядра l2tp_ppp на ХОСТЕ — контейнер
	# его загрузить не может. Дублирует шаг из init.sh, но покрывает ПУТЬ ОБНОВЛЕНИЯ
	# (кнопка бота -> update.sh -> make start) и ребут (cron make r), где init.sh не
	# запускается. Префикс `-` обязателен: без модуля в ядре make не должен ронять
	# запуск контейнеров (L2TP отвалится, IKEv2 и остальное работают).
	-modprobe l2tp_ppp 2>/dev/null && echo l2tp_ppp > /etc/modules-load.d/vpnbot-l2tp.conf || echo "WARN: l2tp_ppp unavailable — L2TP off, IKEv2 ok"
	IP=$(IP) VER=$(VER) docker compose --env-file ./.env --env-file ./override.env up -d --force-recreate
u: preup start
d: # остановка контейнеров
	-kill -9 $(shell cat ./update/update_pid) > /dev/null
	docker compose down --remove-orphans
dv: # остановка контейнеров
	docker compose down -v
r: d u
ps: # список контейнеров
	docker compose ps
l: # логи из контейнеров
	docker compose logs
php: # консоль сервиса
	docker compose exec php /bin/sh
wg: # консоль сервиса
	docker compose exec wg /bin/sh
wg1: # консоль сервиса
	docker compose exec wg1 /bin/sh
ss: # консоль сервиса
	docker compose exec ss /bin/sh
ng: # консоль сервиса
	docker compose exec ng /bin/sh
np: # консоль сервиса
	docker compose exec np /bin/sh
up: # консоль сервиса
	docker compose exec up /bin/sh
ad: # консоль сервиса
	docker compose exec ad /bin/sh
wp: # консоль сервиса
	docker compose exec wp /bin/sh
proxy: # консоль сервиса
	docker compose exec proxy /bin/sh
tg: # консоль сервиса
	docker compose exec tg /bin/bash
telemt: # консоль сервиса
	docker compose exec telemt /bin/sh
dnstt: # консоль сервиса
	docker compose exec dnstt /bin/sh
hy: # консоль сервиса
	docker compose exec hy /bin/sh
xr: # консоль сервиса
	docker compose exec xr /bin/sh
oc: # консоль сервиса
	docker compose exec oc /bin/sh
service: # консоль сервиса
	docker compose exec service /bin/sh
delete:
	make d
	docker system prune -f -a
	docker volume prune -f -a
	rm -rf /root/vpnbot
push:
	docker compose push
s:
	git status -su
c:
	git add config/
	git checkout .
	git reset
webhook:
	docker compose exec php php checkwebhook.php
reset:
	make d
	git reset --hard
	git clean -fd
	docker volume rm vpnbot_adguard vpnbot_warp
	make u
backup:
	docker compose exec php php backup.php > backup.json
mtproto:
	docker compose exec php php mtproto.php
cron: # установка задачи в cron для автозапуска при перезагрузке
	@(crontab -l 2>/dev/null | grep -v "cd /root/vpnbot && make r"; echo "@reboot cd /root/vpnbot && make r") | crontab -
uncron: # удаление задачи из cron
	@crontab -l 2>/dev/null | grep -v "cd /root/vpnbot && make r" | crontab -