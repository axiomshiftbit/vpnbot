"""Повтор сетевых команд CI: до четырёх попыток с паузами 15, 45 и 90 с.

Связь runner с GitHub и реестром образов иногда рвётся на минуту-две. Повторять
можно только идемпотентные действия: чтение, загрузку образа, присвоение тега
тому же содержимому. Решения по результату (ветка сдвинулась, комплект чужой)
принимает вызывающий код и не повторяет.
"""
import os
import time

# Пустая переменная окружения — те же паузы по умолчанию, как в ci_retry.sh.
DELAYS = tuple(float(value) for value in (os.environ.get('CI_RETRY_DELAYS') or '15 45 90').split())


def retrying(run, *args, errors=(RuntimeError,)):
    for delay in (*DELAYS, None):
        try:
            return run(*args)
        except errors:
            if delay is None:
                raise
            # Текст ошибки Docker может содержать адреса и учётные данные.
            print('Retrying a failed network operation in', format(delay, 'g'), 'seconds', flush=True)
            time.sleep(delay)
