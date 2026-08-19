#!/bin/bash

# Параметры (можно менять)
PORTS=(80 443 853 ~ss~ ~wg1~ ~wg2~)          # Прослушиваемые порты
TARGET="~ip~"               # Куда перенаправляем трафик
# Без строк-команд и eval: значения ~ip~/~ss~/~wg1~/~wg2~ подставляет бот, и
# раньше готовая строка уходила в `eval`, то есть любая неожиданность в
# подставленном значении исполнялась шеллом от root на relay-хосте. Теперь
# socat зовётся напрямую, а значения остаются данными.
TARGET_IS_VALID=0
case "$TARGET" in
    *[!0-9.]*|'') ;;
    *.*.*.*) TARGET_IS_VALID=1 ;;
esac
if [ "$TARGET_IS_VALID" != 1 ]; then
    echo "Ошибка: TARGET='$TARGET' не похож на IPv4-адрес — шаблон не заполнен?" >&2
    exit 1
fi

# Проверяем, установлен ли socat
if ! command -v socat &> /dev/null; then
    echo "socat не установлен. Устанавливаем..."
    if [[ -f /etc/debian_version ]]; then
        sudo apt update && sudo apt install -y socat
    elif [[ -f /etc/redhat-release ]]; then
        sudo yum install -y socat
    else
        echo "Ошибка: Неизвестный дистрибутив. Установите socat вручную."
        exit 1
    fi
fi

# Проверяем, заняты ли порты (TCP и UDP)
for PORT in "${PORTS[@]}"; do
    # Проверка TCP
    if ss -tulnp | grep -q ":$PORT "; then
        PROCESS=$(ss -tulnp | grep ":$PORT " | awk '{print $7}')
        echo "Ошибка: Порт $PORT (TCP) занят процессом: $PROCESS"
        exit 1
    fi
    # Проверка UDP
    if ss -ulnp | grep -q ":$PORT "; then
        PROCESS=$(ss -ulnp | grep ":$PORT " | awk '{print $6}')
        echo "Ошибка: Порт $PORT (UDP) занят процессом: $PROCESS"
        exit 1
    fi
done

# Запускаем socat для каждого порта (TCP и UDP)
for PORT in "${PORTS[@]}"; do
    case "$PORT" in
        ''|*[!0-9]*)
            echo "Пропуск: '$PORT' не число (шаблон не заполнен?)" >&2
            continue
            ;;
    esac
    echo "Запуск (TCP): $PORT -> $TARGET:$PORT"
    socat "TCP-LISTEN:$PORT,fork,reuseaddr" "TCP:$TARGET:$PORT" &
    echo "Запуск (UDP): $PORT -> $TARGET:$PORT"
    socat "UDP-LISTEN:$PORT,fork,reuseaddr" "UDP:$TARGET:$PORT" &
done

echo "socat запущен для портов: ${PORTS[*]} (TCP и UDP)"
echo "Трафик перенаправляется на: $TARGET"
echo "Для остановки выполните: pkill socat"