<?php

require_once __DIR__ . '/../app/bot.php';

function datTestAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

class DatDownloadTestBot extends Bot
{
    public string $testDir;
    public string $body = 'first';
    public bool $notModified = false;
    public array $lastValidators = [];

    public function datDir(): string
    {
        return $this->testDir;
    }

    public function datFetchRaw(string $url, array $validators = []): array
    {
        $this->lastValidators = $validators;
        if ($this->notModified) {
            return ['ok' => true, 'not_modified' => true];
        }
        return [
            'ok'            => true,
            'body'          => $this->body,
            'etag'          => '"e-' . md5($this->body) . '"',
            'last_modified' => '',
        ];
    }
}

class DatScheduleTestBot extends Bot
{
    public int $syncCount = 0;
    public int $restartCount = 0;
    public int $scheduleMenuCount = 0;
    public bool $contentChanged = true;
    public bool $forced = false;

    public function datSync(bool $force = false, ?bool &$changed = null): array
    {
        $this->syncCount++;
        $this->forced = $force;
        $changed = $this->contentChanged;
        return [];
    }

    public function xrayUpdateRules()
    {
        $this->restartCount++;
    }

    public function datSchedule(): void
    {
        $this->scheduleMenuCount++;
    }
}

class DatMenuTestBot extends Bot
{
    public string $testDir;
    public string $capturedText = '';
    public array $capturedButtons = [];

    public function datDir(): string
    {
        return $this->testDir;
    }

    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML')
    {
        $this->capturedText = $text;
        $this->capturedButtons = is_array($button) ? $button : [];
    }

    public function listPac($type, $page, $menu, $basename = false)
    {
        return [[[['text' => 'add', 'callback_data' => '/include datlist']]], []];
    }
}

$dir = sys_get_temp_dir() . '/vpnbot-dat-schedule-' . getmypid();
if (!mkdir($dir, 0700) && !is_dir($dir)) {
    throw new RuntimeException("cannot create $dir");
}

try {
    $download = (new ReflectionClass(DatDownloadTestBot::class))->newInstanceWithoutConstructor();
    $download->testDir = $dir;

    $changed = null;
    datTestAssert($download->datDownload('sample.dat', 'https://example.test/a', $changed) === '', 'initial download failed');
    datTestAssert($changed === true, 'initial download must be marked changed');
    datTestAssert(file_get_contents("$dir/sample.dat") === 'first', 'initial body mismatch');

    $changed = null;
    datTestAssert($download->datDownload('sample.dat', 'https://example.test/a', $changed) === '', 'same-body refresh failed');
    datTestAssert($changed === false, 'same body must not be marked changed');

    $download->body = 'second';
    $changed = null;
    datTestAssert($download->datDownload('sample.dat', 'https://example.test/a', $changed) === '', 'changed-body refresh failed');
    datTestAssert($changed === true, 'changed body must be marked changed');
    datTestAssert(file_get_contents("$dir/sample.dat") === 'second', 'updated body mismatch');

    // Условный GET: сохранённый etag ушёл в запрос, а 304 не трогает файл.
    $download->notModified = true;
    $changed = null;
    datTestAssert($download->datDownload('sample.dat', 'https://example.test/a', $changed) === '', '304 refresh failed');
    datTestAssert($changed === false, '304 must not be marked changed');
    datTestAssert(file_get_contents("$dir/sample.dat") === 'second', '304 must not alter file');
    datTestAssert(($download->lastValidators['etag'] ?? '') === '"e-' . md5('second') . '"', 'stored etag was not sent as validator');
    $download->notModified = false;

    datTestAssert($download->datLastUpdateAt([]) > 0, 'file mtime fallback is missing');
    datTestAssert($download->datLastUpdateAt(['dat_update_last_success' => 123]) === 123, 'stored success timestamp must win');

    $schedule = (new ReflectionClass(DatScheduleTestBot::class))->newInstanceWithoutConstructor();
    $schedule->pac = "$dir/pac.json";
    $conf = [
        'datlist' => ['sample.dat:https://example.test/a' => true],
        'dat_update_interval' => 3600,
        'dat_update_next' => time() + 3600,
    ];
    file_put_contents($schedule->pac, json_encode($conf));
    $schedule->checkDatUpdates();
    datTestAssert($schedule->syncCount === 0, 'future schedule ran too early');

    $conf['dat_update_next'] = time() - 1;
    file_put_contents($schedule->pac, json_encode($conf));
    $started = time();
    $schedule->checkDatUpdates();
    $saved = json_decode(file_get_contents($schedule->pac), true);
    datTestAssert($schedule->syncCount === 1 && $schedule->forced, 'due schedule did not force refresh');
    datTestAssert($schedule->restartCount === 1, 'changed content did not restart xray');
    datTestAssert(($saved['dat_update_last_success'] ?? 0) >= $started, 'success timestamp was not saved');
    datTestAssert(
        ($saved['dat_update_next'] ?? 0) === $saved['dat_update_last_attempt'] + 3600,
        'next run was not scheduled from the attempt time'
    );

    $schedule->contentChanged = false;
    $saved['dat_update_next'] = 0;
    file_put_contents($schedule->pac, json_encode($saved));
    $schedule->checkDatUpdates();
    datTestAssert($schedule->syncCount === 2, 'second due schedule did not run');
    datTestAssert($schedule->restartCount === 1, 'unchanged content restarted xray');

    $beforeSet = time();
    $schedule->datScheduleSet(21600);
    $saved = json_decode(file_get_contents($schedule->pac), true);
    datTestAssert(($saved['dat_update_interval'] ?? 0) === 21600, 'selected interval was not saved');
    datTestAssert(($saved['dat_update_next'] ?? 0) >= $beforeSet + 21600, 'selected interval did not schedule next run');
    datTestAssert($schedule->scheduleMenuCount === 1, 'schedule menu was not redrawn');
    datTestAssert($schedule->datUpdateIntervalLabel(21600) === '6h', 'interval label mismatch');

    $schedule->datScheduleSet(0);
    $saved = json_decode(file_get_contents($schedule->pac), true);
    datTestAssert(($saved['dat_update_interval'] ?? -1) === 0, 'off interval was not saved');
    datTestAssert(!isset($saved['dat_update_next']), 'off interval kept a next run');

    $menu = (new ReflectionClass(DatMenuTestBot::class))->newInstanceWithoutConstructor();
    $menu->testDir = $dir;
    $menu->pac = "$dir/menu-pac.json";
    $menu->limit = 5;
    $menu->language = 'en';
    $menu->i18n = [
        'xray' => ['en' => 'xray'],
        'routes' => ['en' => 'routes'],
        'add' => ['en' => 'add'],
        'back' => ['en' => 'back'],
        'update' => ['en' => 'update'],
    ];
    $menu->input = ['chat' => 1, 'message_id' => 2];
    $lastUpdate = 1700000000;
    file_put_contents($menu->pac, json_encode([
        'datlist' => [],
        'dat_update_interval' => 21600,
        'dat_update_last_success' => $lastUpdate,
        'dat_update_next' => $lastUpdate + 21600,
    ]));
    $menu->xtlsdat();
    datTestAssert(str_contains($menu->capturedText, 'auto update: 6h'), 'dat menu interval is missing');
    datTestAssert(str_contains($menu->capturedText, date('Y-m-d H:i:s', $lastUpdate)), 'last update time is missing');
    datTestAssert(str_contains(json_encode($menu->capturedButtons), '/datschedule'), 'schedule button is missing');

    $menu->datSchedule();
    datTestAssert(str_contains(json_encode($menu->capturedButtons, JSON_UNESCAPED_UNICODE), '✅ 6h'), 'current schedule is not selected');
    datTestAssert(str_contains(json_encode($menu->capturedButtons), '/datscheduleset 604800'), 'weekly schedule is missing');

    echo "dat_schedule_test OK\n";
} finally {
    foreach (glob("$dir/*") ?: [] as $file) {
        @unlink($file);
    }
    @rmdir($dir);
}
