<?php

// ?: 'UTC' — getenv() отдаёт false, когда переменной нет. В контейнере TZ
// приходит из .env, но этот файл первым делом подключают все CLI-точки входа
// (cron.php, backup.php, init.php, updatepac.php), и при запуске вне docker
// PHP получал пустую строку, писал warning и молча оставался на UTC — а
// отметки времени в логах, расписании бэкапов и именах экспортов уезжали.
date_default_timezone_set(getenv('TZ') ?: 'UTC');
