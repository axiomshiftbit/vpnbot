<?php
// Только маршрутизатор синтетической лаборатории. Panel/Auth не переопределяются.
declare(strict_types=1);
ini_set('display_errors', '0');
ini_set('log_errors', '0');
$source = getenv('PANEL_TEST_SOURCE') ?: '';
$root = getenv('PANEL_TEST_ROOT') ?: '';
if (getenv('PANEL_TEST_ISOLATED') !== 'owned-unit-panel-v1'
    || !is_file($root . '/.synthetic-only')
    || !is_file($source . '/app/bot.php')) {
    http_response_code(503); exit;
}
require_once $source . '/app/bot.php';
require_once $source . '/app/panel/Panel.php';
// Открытые тестовые строки не являются настоящими учётными данными.
const AUDIT_KEY = 'synthetic-panel-unit-hmac-key';
const AUDIT_PASSWORD = 'SyntheticPanelPassword-2026';
const AUDIT_ADMIN = 900001;
const AUDIT_HASH = 'auditfixturev1';

try {
    if (PHP_SAPI === 'cli' && ($argv[1] ?? '') === 'init') {
        $hash = password_hash(AUDIT_PASSWORD, PASSWORD_DEFAULT);
        $pac = ['hashbot' => AUDIT_HASH, 'panelpswd' => $hash,
            'singtemplates' => ['audit_template' => ['fixture' => true, 'value' => 1]]];
        if (file_put_contents($root . '/pac.json', json_encode($pac, JSON_THROW_ON_ERROR)) === false) throw new RuntimeException('fixture');
        chmod($root . '/pac.json', 0600);
        $store = new PanelStore($root . '/panel');
        $response = (new PanelTransport($store))->call('sendMessage', ['chat_id' => AUDIT_ADMIN,
            'text' => 'Синтетический редактор', 'reply_markup' => ['inline_keyboard' => [[[
                'text' => 'Редактор', 'web_app' => ['url' => 'https://example.invalid/pacfixture?t=te&ty=sing&te=audit_template'],
            ]]]]]);
        if (empty($response['ok'])) throw new RuntimeException('fixture transport');
        $exp = time() + 600;
        // Исторический формат подписи fixture; проверку выполняет настоящий Panel.
        // stdout читает только Python через private pipe; не запускать init вручную.
        $signature = hash_hmac('sha256', 'panel|' . $exp . '|' . AUDIT_ADMIN . '|' . $hash, AUDIT_KEY);
        echo json_encode(['legacy_two' => $exp . '.' . $signature,
            'legacy_three' => $exp . '.' . AUDIT_ADMIN . '.' . $signature], JSON_THROW_ON_ERROR);
        exit;
    }
    // FreeUnit 1.37 сообщает PHP_SAPI=cli-server; сервер узнаём по SERVER_SOFTWARE.
    if (PHP_SAPI === 'cli' || !str_starts_with((string) ($_SERVER['SERVER_SOFTWARE'] ?? ''), 'Unit/')) { http_response_code(503); exit; }
    $path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
    $cookie = (string) ($_COOKIE['panel'] ?? '');
    // Только наблюдение результата реального PHP HTTP parser. Значения не выводятся.
    header('X-Audit-Cookie-Present: ' . (isset($_COOKIE['panel']) ? '1' : '0'));
    header('X-Audit-Cookie-LF: ' . (str_ends_with($cookie, "\n") ? '1' : '0'));
    header('X-Audit-Cookie-CRLF: ' . (str_ends_with($cookie, "\r\n") ? '1' : '0'));
    if ($path === '/__audit/health') {
        header('Content-Type: application/json');
        echo '{"ok":true,"parser":"php-unit"}'; exit;
    }
    // Конструктор Bot читает окружение приложения; он здесь не нужен.
    // Все вызываемые далее методы Bot/Panel/Store остаются исходными.
    $bot = (new ReflectionClass(Bot::class))->newInstanceWithoutConstructor();
    $bot->pac = $root . '/pac.json';
    $bot->key = AUDIT_KEY;
    $bot->language = 'ru';
    $bot->input = ['from' => AUDIT_ADMIN, 'chat' => AUDIT_ADMIN];
    $panel = new Panel($bot, ['key' => AUDIT_KEY, 'admin' => [AUDIT_ADMIN]], new PanelStore($root . '/panel'));
    if (!$panel->matches($_SERVER['REQUEST_URI'] ?? '/')) {
        http_response_code(404); exit;
    }
    $panel->route($_SERVER['REQUEST_URI']);
} catch (Throwable $error) {
    http_response_code(500);
    header('Content-Type: application/json');
    echo json_encode(['ok' => false, 'error' => 'synthetic-harness', 'exception_class' => get_class($error)]);
}
