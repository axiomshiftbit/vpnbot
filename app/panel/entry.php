<?php

/**
 * Точка входа выделенного слушателя unit (config/unit.json → applications/panel).
 *
 * Отличить панельный слушатель по порту из PHP нельзя: unit 1.31 сообщает
 * SERVER_PORT = 80 на любом listener'е, а SERVER_NAME/Host приходят от клиента
 * и подделываются с публичного 443. Признаком служит сам факт, что запрос
 * пришёл в этот файл: он назначен script'ом только панельного приложения, на
 * *:80 unit по-прежнему отдаёт index.php.
 */

define('PANEL_LISTENER', true);

require __DIR__ . '/../index.php';
