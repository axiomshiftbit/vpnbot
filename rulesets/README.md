# Наборы правил sing-box

Двоичные наборы правил (`.srs`), которые шаблоны подписок sing-box
(`config/templates/sing/*.json`) подключают как удалённые `rule_set`:

- `ruleset-ai.srs` — домены и сети сервисов ИИ, направляемые через прокси;
- `ruleset-test.srs` — небольшой проверочный набор.

Клиенты скачивают их по адресу
`https://github.com/axiomshiftbit/vpnbot/raw/refs/heads/master/rulesets/<файл>`
раз в сутки. Посмотреть содержимое: `sing-box rule-set decompile ruleset-ai.srs`.
