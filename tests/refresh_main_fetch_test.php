<?php
// Main menu "status" (refresh) must check the repository now: it only read
// origin/<branch> from the hourly fetch in checkVersion(), so right after a new
// commit reached master the menu kept saying "no updates" and showed neither
// the changelog nor the "update bot" button for up to an hour.
require_once __DIR__ . '/../app/bot.php';

class RefreshMainBot extends Bot
{
    public array $events = [];
    public function __construct() { $this->input = ['chat' => 1, 'message_id' => 2, 'callback_id' => 'cb']; $this->language = 'en'; $this->i18n = ['refreshed' => ['en' => 'refreshed']]; }
    public function answer($callback_id, $textNotify = false, $notify = false) {}
    public function serviceStatuses($refresh = false) { $this->events[] = 'statuses'; return []; }
    public function expireMenuVersionsCache(): void { $this->events[] = 'versions'; }
    public function menu($type = false, $arg = false, $return = false) { $this->events[] = 'menu'; }
    protected function fetchUpdates(): void { $this->events[] = 'fetch'; }
}
$failed = 0; $count = 0;
$check = static function (bool $ok, string $what) use (&$failed, &$count) { $count++; if (!$ok) { $failed++; echo "FAIL: $what\n"; } };
$b = new RefreshMainBot();
$b->refreshMain();
$check(in_array('fetch', $b->events, true), 'status refresh fetches the repository');
$check(array_search('fetch', $b->events, true) < array_search('menu', $b->events, true), 'fetch happens before the menu is rendered');
$source = file_get_contents(__DIR__ . '/../app/bot.php');
$check((bool) preg_match('~function fetchUpdates\(\).*?timeout \d+ git -C / fetch -q~s', $source), 'the fetch is bounded by a timeout');
echo "refresh_main_fetch_test: " . ($count - $failed) . "/$count\n";
exit($failed ? 1 : 0);
