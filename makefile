-include .env
# override.env подключается ВТОРЫМ и обязательно здесь, а не только через
# --env-file у compose: `export` ниже выкладывает все переменные .env в
# ОКРУЖЕНИЕ процесса, а окружение у compose приоритетнее любого --env-file.
# Без этой строки override.env молча не работал для всего, что уже есть в
# .env (VPNBOT_TAG, TZ, IP, порты) — правка в нём просто игнорировалась.
-include override.env
export
# cron (@reboot make r из make cron) запускает make с PATH=/usr/bin:/bin, а
# modprobe, sysctl, nft и ip лежат в sbin: после перезагрузки рецепты молча
# не находили их («command not found» гасили «|| echo WARN»). Дописываем sbin
# в конец, не меняя порядок уже заданного PATH.
export PATH := $(PATH):/usr/local/sbin:/usr/sbin:/sbin

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
versions: # закреплённые версии: уязвимости и новые выпуски (перед полным прогоном; GH_TOKEN — от лимита API GitHub)
	@python3 scripts/ci_check_components.py
preup:
	bash ./update/update.sh &
pull: # обновление образов из ghcr.io/axiomshiftbit
	touch ./override.env
	# Проверенный комплект выбирается целиком. Ошибка допуска/сети не разрешает
	# собрать случайную замену из Dockerfile или смешать теги разных запусков.
	python3 scripts/image_bundle.py ensure
	# Digest неизменяем: уже скачанный проверенный образ пригоден и без сети.
	# Недостающий образ обязан успешно скачаться до остановки служб.
	python3 scripts/protocol_modules.py compose pull --policy missing
start: pull # запуск контейнеров
	touch ./override.env ./docker-compose.override.yml ./config/location.conf ./config/override.conf
	# L2TP/IPsec (сервис ipsec) требует модуль ядра l2tp_ppp на ХОСТЕ — контейнер
	# его загрузить не может. Дублирует шаг из init.sh, но покрывает ПУТЬ ОБНОВЛЕНИЯ
	# (кнопка бота -> update.sh -> make start) и ребут (cron make r), где init.sh не
	# запускается. Префикс `-` обязателен: без модуля в ядре make не должен ронять
	# запуск контейнеров (L2TP отвалится, IKEv2 и остальное работают).
	-modprobe l2tp_ppp 2>/dev/null && echo l2tp_ppp > /etc/modules-load.d/vpnbot-l2tp.conf || echo "WARN: l2tp_ppp unavailable — L2TP off, IKEv2 ok"
	# WARP wg-quick требует эти модули при восстановлении правил netfilter.
	-modprobe -a xt_comment xt_mark xt_connmark 2>/dev/null && printf 'xt_comment\nxt_mark\nxt_connmark\n' > /etc/modules-load.d/vpnbot-warp.conf || echo "WARN: netfilter modules unavailable — WARP wg-quick may fail"
	# Только ради чистого журнала ipsec (см. init.sh); на ядре без IPv6 модуль
	# не загружается — молча пропускаем, чтобы не шуметь при каждом обновлении.
	-modprobe xfrm_interface 2>/dev/null && echo xfrm_interface > /etc/modules-load.d/vpnbot-xfrm.conf || true
	IP=$(IP) VER=$(VER) python3 scripts/protocol_modules.py compose up -d --force-recreate
u: start
	$(MAKE) preup
d: # остановка контейнеров
	# Через скрипт: PID из update_pid переиспользуются, и голый kill -9 после
	# ребута уходил произвольному процессу. См. scripts/stop_update.sh.
	sh ./scripts/stop_update.sh ./update/update_pid
	docker compose --profile '*' down --remove-orphans
dv: # остановка контейнеров
	docker compose --profile '*' down -v
r: pull
	$(MAKE) d
	$(MAKE) u
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
	@echo "Нужна внеочередная сборка: gh workflow run images.yml --ref dev"
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
