-include .env
# override.env подключается ВТОРЫМ и обязательно здесь, а не только через
# --env-file у compose: `export` ниже выкладывает все переменные .env в
# ОКРУЖЕНИЕ процесса, а окружение у compose приоритетнее любого --env-file.
# Без этой строки override.env молча не работал для всего, что уже есть в
# .env (VPNBOT_TAG, TZ, IP, порты) — правка в нём просто игнорировалась.
-include override.env
export

IP := $(or $(IP),$(shell hostname -I | awk '{print $$1}'))
# VER идёт в имена контейнеров (container_name: php-${VER} и т.д.). Если в клоне
# нет тегов (теги не запушены в форк / не подтянуты), `git describe --tags`
# отдаёт ПУСТО → имена схлопываются в "php-"/"telemt-"/… → конфликт имён при
# `up --force-recreate`, и бот/сервисы не стартуют. `--always` даёт короткий SHA
# без тегов, `|| echo local` страхует, если git недоступен — VER не пустой.
VER := $(shell git describe --tags --always 2>/dev/null || echo local)

b:
	python3 scripts/protocol_modules.py compose build
test: # прогон тестов (на ХОСТЕ, не внутри контейнера)
	@python3 -m unittest discover -s tests -p '*_test.py'
	@# 42+ файла в tests/ закрывают конкретные регрессии, но их не звал никто:
	@# ни CI, ни makefile, ни readme. Правка ломала охрану, закрытую полгода
	@# назад, и об этом никто не узнавал.
	@php -l app/bot.php > /dev/null
	@for f in app/*.php app/panel/*.php tests/*.php; do \
		php -l "$$f" > /dev/null || exit 1; \
	done
	@fail=0; for f in tests/*_test.php; do \
		out=$$(php "$$f" 2>&1) || { echo "$$out"; fail=1; }; \
	done; \
	if [ $$fail -eq 0 ]; then echo "tests OK"; else echo "TESTS FAILED"; exit 1; fi
preup:
	bash ./update/update.sh &
pull: # обновление образов из ghcr.io/axiomshiftbit
	touch ./override.env
	# Тег канала (dev/latest) плавающий, а pull_policy по умолчанию = missing:
	# `up` НЕ станет обновлять уже лежащий локально образ с тем же тегом, поэтому
	# pull делается явно. Префикс `-` и --ignore-pull-failures обязательны:
	# недоступный registry не должен мешать запуску — останутся локальные образы,
	# а чего нет вовсе, соберётся из dockerfile (секции build: сохранены).
	# --ignore-buildable здесь НЕ годится: build: есть у всех сервисов, и она
	# пропустила бы вообще всё.
	-python3 scripts/protocol_modules.py compose pull --ignore-pull-failures
start: pull # запуск контейнеров
	touch ./override.env ./docker-compose.override.yml ./config/location.conf ./config/override.conf
	# L2TP/IPsec (сервис ipsec) требует модуль ядра l2tp_ppp на ХОСТЕ — контейнер
	# его загрузить не может. Дублирует шаг из init.sh, но покрывает ПУТЬ ОБНОВЛЕНИЯ
	# (кнопка бота -> update.sh -> make start) и ребут (cron make r), где init.sh не
	# запускается. Префикс `-` обязателен: без модуля в ядре make не должен ронять
	# запуск контейнеров (L2TP отвалится, IKEv2 и остальное работают).
	-modprobe l2tp_ppp 2>/dev/null && echo l2tp_ppp > /etc/modules-load.d/vpnbot-l2tp.conf || echo "WARN: l2tp_ppp unavailable — L2TP off, IKEv2 ok"
	IP=$(IP) VER=$(VER) python3 scripts/protocol_modules.py compose up -d --force-recreate
u: preup start
d: # остановка контейнеров
	# Через скрипт: PID из update_pid переиспользуются, и голый kill -9 после
	# ребута уходил произвольному процессу. См. scripts/stop_update.sh.
	-sh ./scripts/stop_update.sh ./update/update_pid
	docker compose --profile '*' down --remove-orphans
dv: # остановка контейнеров
	docker compose --profile '*' down -v
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
push: # образы публикует CI, вручную не пушим
	@echo "Образы собирает и публикует CI: .github/workflows/images.yml -> ghcr.io/axiomshiftbit."
	@echo "Ручной 'docker compose push' перезаписал бы их сборкой с этой машины —"
	@echo "с другими версиями базовых образов и без записи о том, из какого коммита."
	@echo "Нужна внеочередная сборка: gh workflow run images.yml [-f services=ss,tt]"
	@exit 1
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
cron: # установка задачи в cron для автозапуска при перезагрузке
	@(crontab -l 2>/dev/null | grep -v "cd /root/vpnbot && make r"; echo "@reboot cd /root/vpnbot && make r") | crontab -
uncron: # удаление задачи из cron
	@crontab -l 2>/dev/null | grep -v "cd /root/vpnbot && make r" | crontab -
