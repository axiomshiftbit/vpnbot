<?php

return [
    <<<'TEXT'
<b>Как задавать домены</b>

<code>domain:vk.com</code> или просто <code>vk.com</code>
✅ vk.com, m.vk.com
❌ notvk.com, vk.com.other.org

<code>full:example.com</code> — только этот домен.
✅ example.com
❌ www.example.com

<code>keyword:reddit</code> — подстрока в имени.
✅ reddit.com, myreddit.example
Это более широкое правило, чем domain:.

Вводите без https://, порта и пути. Обычные записи — по одной на строку или через запятую:
<code>domain:vk.com, full:example.com</code>

<b>IP и подсети</b>
<code>198.51.100.8</code> — один IP;
<code>198.51.100.0/24</code> — подсеть;
<code>2001:db8::/32</code> — IPv6-подсеть.
В Subnet вводятся только IP/CIDR. Замените адреса из примеров своими.
TEXT,
    <<<'TEXT'
<b>regexp: — регулярное выражение</b>

<code>regexp:.*\.ru$</code>
✅ example.ru, a.example.ru
❌ example.ru.com

<code>regexp:^ads[0-9]{1,3}\.example\.com$</code>
✅ ads1.example.com, ads123.example.com
❌ ads.example.com, ads1234.example.com

<code>^</code> — начало; <code>$</code> — конец;
<code>\.</code> — точка; <code>.*</code> — любые символы;
<code>[0-9]</code> — цифра; <code>{1,3}</code> — 1–3 повторения;
<code>(com|net)</code> — com или net.

Каждое regexp: вводите <b>с новой строки</b>: запятая может быть частью выражения. Без кавычек и внешних /.../. В Telegram пишите один обратный слэш: <code>\.</code>.

Пишите домены строчными буквами. RE2 не поддерживает проверки вперёд/назад и обратные ссылки вроде <code>\1</code>; неверное выражение не сохранится. Для обычного домена проще domain:.
TEXT,
    <<<'TEXT'
<b>Когда применятся изменения</b>

Block/WARP применяются на сервере Xray. WARP должен быть подключён. Domains и Subnet используются в клиентском профиле; block/WARP также включаются в стандартные шаблоны клиента.

После изменения <b>обновите подписку и примените профиль</b>. Отдельная ссылка vless:// не переносит эти правила. В стандартных шаблонах блокировка имеет приоритет; пользовательский шаблон может задавать другой порядок.

Доменное правило требует известного имени назначения. При подключении только к IP оно может не сработать; IP-правила также зависят от DNS-стратегии клиента.

OFF исключает запись. Повторное добавление не включает её обратно. Импорт <b>заменяет</b> список — заранее сделайте экспорт.

Process: <code>firefox</code> / <code>chrome.exe</code>.
Package: <code>org.telegram.messenger</code>.
Эти списки используют шаблоны sing-box/Mihomo; поддержка зависит от ОС и режима клиента. На сервере имя приложения телефона недоступно.
TEXT,
];
