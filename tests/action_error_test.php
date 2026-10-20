<?php
// Необработанное исключение действия не роняет обработку апдейта: ошибка
// уходит в журнал, администратор получает ответ на нажатие или сообщение.
// Раньше (найдено обходом меню 2026-10-20) недоступный контейнер TeleMT давал
// фатальную ошибку PHP, и кнопка «крутилась» без ответа.
require_once __DIR__ . '/../app/bot.php';
require __DIR__ . '/../app/i18n.php';

final class ActionErrorBot extends Bot
{
    public array $calls = [];
    public function __construct(array $strings) { $this->i18n = $strings; }
    public function auth() { $this->admin = true; }
    public function session() {}
    public function action() { throw new RuntimeException('контейнер не ответил <b>'); }
    public function request($method, $data, $json_header = 0) { $this->calls[] = [$method, $data]; return ['ok' => true]; }
}

$failed = 0;
$check = static function (bool $ok, string $name) use (&$failed) { if (!$ok) { $failed++; echo "FAIL: $name\n"; } };
$log = tempnam(sys_get_temp_dir(), 'action-error-');
ini_set('error_log', $log);

$b = new ActionErrorBot($i);
$b->language = 'ru';
$b->input(['callback_query' => ['id' => 'cb1', 'data' => '/telemtSetMode tls', 'from' => ['id' => 5], 'message' => ['message_id' => 3, 'chat' => ['id' => 5], 'text' => 'x']]]);
$answers = array_values(array_filter($b->calls, static fn($c) => $c[0] === 'answerCallbackQuery'));
$check(count($answers) === 1 && $answers[0][1]['show_alert'] === true && $answers[0][1]['text'] === 'Не выполнено: контейнер не ответил <b>', 'нажатие получает всплывающий ответ с причиной');
$check(str_contains((string) file_get_contents($log), 'action /telemtSetMode tls: RuntimeException: контейнер не ответил'), 'отказ записан в журнал');

$b = new ActionErrorBot($i);
$b->language = 'en';
$b->input(['message' => ['message_id' => 4, 'chat' => ['id' => 5], 'from' => ['id' => 5], 'text' => 'secret-password']]);
$sends = array_values(array_filter($b->calls, static fn($c) => $c[0] === 'sendMessage'));
$check(count($sends) === 1 && $sends[0][1]['text'] === 'Not done: контейнер не ответил &lt;b&gt;', 'сообщение: ответ на языке интерфейса, текст экранирован');
$check(!str_contains((string) file_get_contents($log), 'secret-password'), 'введённый текст в журнал не попадает');
@unlink($log);

if ($failed) { echo "action_error_test FAILED: $failed\n"; exit(1); }
echo "action_error_test OK\n";
