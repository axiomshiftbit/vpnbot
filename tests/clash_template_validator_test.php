<?php

// Валидатор mihomo-шаблонов: предупреждения не должны срабатывать на штатных
// конструкциях mihomo — иначе бот ругается при каждом сохранении рабочего
// шаблона, и на фоне этого шума теряются настоящие находки.
//
// Регрессия 2026-08-31: группа с include-all (узлы подставляет само ядро,
// список proxies в ней не пишут) давала «proxy-groups[N].proxies is empty».
// mihomo v1.19.30 такой конфиг принимает без замечаний.

require_once __DIR__ . '/../app/ClashTemplateValidator.php';

$failed = 0;

function cvAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

function cvTemplate(array $groups): array
{
    return [
        'proxies'      => [['name' => 'node', 'type' => 'vless', 'server' => '~domain~']],
        'proxy-groups' => $groups,
        'rules'        => ['MATCH,DIRECT'],
    ];
}

function cvWarnings(array $groups): array
{
    $v = ClashTemplateValidator::validate(cvTemplate($groups));

    return array_values(array_filter($v['warnings'], fn($w) => str_contains($w, 'proxies is empty')));
}

// Самонаполняющиеся группы: список узлов отсутствует по делу.
foreach (['include-all', 'include-all-proxies', 'include-all-providers'] as $key) {
    $w = cvWarnings([['name' => 'auto', 'type' => 'select', $key => true, 'exclude-filter' => 'DIRECT']]);
    cvAssert($w === [], "$key: предупреждения нет — " . json_encode($w));
}
$w = cvWarnings([['name' => 'from-provider', 'type' => 'select', 'use' => ['my-provider']]]);
cvAssert($w === [], 'use: предупреждения нет — ' . json_encode($w));

// А группа, которая узлы не перечисляет и сама их не набирает, — по-прежнему
// повод предупредить: она уедет клиенту пустой.
$w = cvWarnings([['name' => 'empty', 'type' => 'select']]);
cvAssert(count($w) === 1 && str_contains($w[0], 'proxy-groups[0]'),
    'группа без узлов и без include-all по-прежнему ловится — ' . json_encode($w));

// Флаг, выключенный явно, самонаполнением не считается.
$w = cvWarnings([['name' => 'off', 'type' => 'select', 'include-all' => false]]);
cvAssert(count($w) === 1, 'include-all: false не отменяет предупреждение — ' . json_encode($w));

if ($failed) {
    echo "clash_template_validator_test FAILED: $failed\n";
    exit(1);
}
echo "clash_template_validator_test OK\n";
