<?php

require_once __DIR__ . '/../app/bot.php';

function datTestAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

// Наименьший корректный .dat: записи поля 1, у каждой первым полем код категории.
function datBlob(array $codes): string
{
    $out = '';
    foreach ($codes as $code) {
        $inner = "\x0a" . chr(strlen($code)) . $code . "\x12\x03abc";
        $out  .= "\x0a" . chr(strlen($inner)) . $inner;
    }
    return $out;
}

class DatDownloadTestBot extends Bot
{
    public string $testDir;
    public string $body = '';
    public ?string $sum = null;
    public int $sumRequests = 0;
    public bool $notModified = false;
    public array $lastValidators = [];

    public function datDir(): string
    {
        return $this->testDir;
    }

    public function datFetchSum(string $url): ?string
    {
        $this->sumRequests++;
        return $this->sum;
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

class DatStreamTestBot extends DatDownloadTestBot
{
    public function datFetchRaw(string $url, array $validators = []): array
    {
        $file = $this->testDir . '/fetch.' . getmypid() . '.' . uniqid();
        file_put_contents($file, $this->body);
        return ['ok' => true, 'file' => $file, 'etag' => '', 'last_modified' => ''];
    }
}

// Правка реестра целиком: настоящие changeRouteList/datSync, подменены только
// сеть и ядро.
class DatRollbackTestBot extends DatDownloadTestBot
{
    public array $sent = [];
    public bool $rulesOk = true;

    public function datFetchRaw(string $url, array $validators = []): array
    {
        return str_contains($url, 'missing') ? ['ok' => false, 'err' => 'http 404'] : parent::datFetchRaw($url, $validators);
    }

    public function getXray()
    {
        return null;
    }

    protected function xrayUpdateRulesLocked(?array $previousPac = null) { return $this->xrayUpdateRules($previousPac); }
    public function xrayUpdateRules(?array $previousPac = null)
    {
        return $this->rulesOk;
    }

    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false)
    {
        $this->sent[] = $text;
    }
}

class DatScheduleTestBot extends Bot
{
    public int $syncCount = 0;
    public int $restartCount = 0;
    public int $scheduleMenuCount = 0;
    public bool $contentChanged = true;
    public bool $forced = false;
    public array $syncErrors = [];
    public array $notices = [];
    public array $sent = [];

    public function datSync(bool $force = false, ?bool &$changed = null): array
    {
        $this->syncCount++;
        $this->forced = $force;
        $changed = $this->contentChanged;
        return $this->syncErrors;
    }

    public function xtlsdat($page = 0)
    {
    }

    public function datNotifyAdmins(string $text): void
    {
        $this->notices[] = $text;
    }

    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false)
    {
        $this->sent[] = $text;
    }

    protected function xrayUpdateRulesLocked(?array $previousPac = null) { return $this->xrayUpdateRules($previousPac); }
    public function xrayUpdateRules(?array $previousPac = null)
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
    $first = datBlob(['FIRST', 'Ads']);
    $second = datBlob(['SECOND']);
    $download->body = $first;

    $changed = null;
    datTestAssert($download->datDownload('sample.dat', 'https://example.test/a', $changed) === '', 'initial download failed');
    datTestAssert($changed === true, 'initial download must be marked changed');
    datTestAssert(file_get_contents("$dir/sample.dat") === $first, 'initial body mismatch');

    $changed = null;
    datTestAssert($download->datDownload('sample.dat', 'https://example.test/a', $changed) === '', 'same-body refresh failed');
    datTestAssert($changed === false, 'same body must not be marked changed');

    $download->body = $second;
    $changed = null;
    datTestAssert($download->datDownload('sample.dat', 'https://example.test/a', $changed) === '', 'changed-body refresh failed');
    datTestAssert($changed === true, 'changed body must be marked changed');
    datTestAssert(file_get_contents("$dir/sample.dat") === $second, 'updated body mismatch');

    // Условный GET: сохранённый etag ушёл в запрос, а 304 не трогает файл.
    $download->notModified = true;
    $changed = null;
    datTestAssert($download->datDownload('sample.dat', 'https://example.test/a', $changed) === '', '304 refresh failed');
    datTestAssert($changed === false, '304 must not be marked changed');
    datTestAssert(file_get_contents("$dir/sample.dat") === $second, '304 must not alter file');
    datTestAssert(($download->lastValidators['etag'] ?? '') === '"e-' . md5($second) . '"', 'stored etag was not sent as validator');
    $download->notModified = false;

    datTestAssert($download->datLastUpdateAt([]) > 0, 'file mtime fallback is missing');
    datTestAssert($download->datLastUpdateAt(['dat_update_last_success' => 123]) === 123, 'stored success timestamp must win');

    $schedule = (new ReflectionClass(DatScheduleTestBot::class))->newInstanceWithoutConstructor();
    $schedule->pac = "$dir/pac.json";
    $schedule->input = ['chat' => 1, 'from' => 1, 'message_id' => 2];
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

    // ── Проверка формата и суммы ────────────────────────────────────────────
    $download->body = '<html>502 Bad Gateway</html>';
    $changed = null;
    $err = $download->datDownload('sample.dat', 'https://example.test/a', $changed);
    datTestAssert($err !== '' && $changed === false, 'HTML body was accepted as .dat');
    datTestAssert(file_get_contents("$dir/sample.dat") === $second, 'rejected body replaced the file');
    $meta = $download->datReadMeta('sample.dat');
    datTestAssert(($meta['error'] ?? '') === $err && ($meta['checked_at'] ?? 0) > 0, 'failure was not recorded in meta');
    datTestAssert(($meta['sha'] ?? '') === hash('sha256', $second), 'failure dropped validators of the kept file');

    $third = datBlob(['THIRD']);
    $download->body = $third;
    $download->sum = str_repeat('0', 64);
    $download->sumRequests = 0;
    $err = $download->datDownload('sample.dat', 'https://example.test/a', $changed);
    datTestAssert(str_contains($err, 'sha256'), 'sha256 mismatch was accepted');
    datTestAssert($download->sumRequests === 2, 'mismatch must be retried exactly once');
    datTestAssert(file_get_contents("$dir/sample.dat") === $second, 'mismatched body replaced the file');

    $download->sum = hash('sha256', $third);
    datTestAssert($download->datDownload('sample.dat', 'https://example.test/a', $changed) === '', 'verified download failed');
    datTestAssert($changed === true && file_get_contents("$dir/sample.dat") === $third, 'verified body was not stored');
    $meta = $download->datReadMeta('sample.dat');
    datTestAssert(($meta['verified'] ?? null) === true && ($meta['error'] ?? 'x') === '', 'verified flag or clean status missing');
    // Те же байты: сумму повторно не запрашиваем, отметка «сверено» остаётся.
    $download->sumRequests = 0;
    $download->sum = null;
    datTestAssert($download->datDownload('sample.dat', 'https://example.test/a', $changed) === '' && $changed === false, 'same verified body failed');
    datTestAssert($download->sumRequests === 0, 'unchanged body must not refetch the sum');
    datTestAssert(($download->datReadMeta('sample.dat')['verified'] ?? null) === true, 'verified flag lost on unchanged body');
    // Источник без опубликованной суммы принимается, но не помечается сверенным.
    $download->body = datBlob(['FOURTH', 'RU']);
    datTestAssert($download->datDownload('sample.dat', 'https://example.test/a', $changed) === '', 'download without sum failed');
    datTestAssert(($download->datReadMeta('sample.dat')['verified'] ?? null) === false, 'unverified body marked verified');
    // Сумму ищем только у прямой ссылки на .dat без параметров.
    $plain = (new ReflectionClass(Bot::class))->newInstanceWithoutConstructor();
    datTestAssert($plain->datFetchSum('https://example.test/a?x=1.dat') === null, 'sum requested for URL with query');
    datTestAssert($plain->datFetchSum('https://example.test/list.txt') === null, 'sum requested for non-.dat URL');

    // Настоящая загрузка отдаёт тело файлом (в памяти его не держим): файл
    // либо становится .dat, либо убирается — в каталоге ничего не остаётся.
    $stream = (new ReflectionClass(DatStreamTestBot::class))->newInstanceWithoutConstructor();
    $stream->testDir = $dir;
    $stream->body = datBlob(['STREAMED']);
    datTestAssert($stream->datDownload('stream.dat', 'https://example.test/s', $changed) === '' && $changed === true
        && $stream->datCategories('stream.dat') === ['streamed'], 'streamed body was not stored');
    $stream->body = 'not a dat';
    datTestAssert($stream->datDownload('stream.dat', 'https://example.test/s', $changed) !== ''
        && $stream->datCategories('stream.dat') === ['streamed'], 'streamed junk replaced the file');
    $stream->body = datBlob(['STREAMED']);
    datTestAssert($stream->datDownload('stream.dat', 'https://example.test/s', $changed) === '' && $changed === false, 'same streamed body failed');
    datTestAssert(glob("$dir/fetch.*") === [] && preg_grep('~\.\d+\.[0-9a-f]+$~', glob("$dir/*")) === [], 'temporary files were left behind');
    @unlink("$dir/stream.dat"); @unlink("$dir/stream.dat.meta");

    // ── Отклонённая правка реестра не оставляет в каталоге ничего лишнего ───
    $rollDir = "$dir/roll";
    mkdir($rollDir);
    $roll = (new ReflectionClass(DatRollbackTestBot::class))->newInstanceWithoutConstructor();
    $roll->testDir = $rollDir;
    $roll->pac = "$dir/roll-pac.json";
    $roll->input = ['chat' => 1, 'from' => 1, 'message_id' => 2];
    $roll->body = datBlob(['ADS']);
    file_put_contents($roll->pac, json_encode(['datlist' => []]));
    $edit = fn(string $key) => $roll->changeRouteList('datlist', function (&$list) use ($key) { $list[$key] = true; });
    $files = fn() => array_map('basename', glob("$rollDir/*") ?: []);
    datTestAssert($edit('a.dat:https://example.test/a') === true && $files() === ['a.dat', 'a.dat.meta'], 'source was not added: ' . json_encode($files()));
    // Ядро отвергло правила: новый файл убран, копии прежних не остаются.
    $roll->rulesOk = false;
    datTestAssert($edit('b.dat:https://example.test/b') === false, 'rejected edit reported success');
    datTestAssert($files() === ['a.dat', 'a.dat.meta'], 'rejected edit left files behind: ' . json_encode($files()));
    datTestAssert(array_keys(json_decode(file_get_contents($roll->pac), true)['datlist']) === ['a.dat:https://example.test/a'], 'rejected edit changed the registry');
    // Источник не скачался: причина доходит до администратора, отметка об отказе не остаётся.
    $roll->rulesOk = true;
    $roll->sent = [];
    datTestAssert($edit('c.dat:https://example.test/missing') === false && str_contains(implode("\n", $roll->sent), 'c.dat — http 404'), 'download error was not reported: ' . json_encode($roll->sent));
    datTestAssert($files() === ['a.dat', 'a.dat.meta'], 'failed download left files behind: ' . json_encode($files()));
    // Выключение источника, на который ссылается правило, — с предупреждением.
    file_put_contents($roll->pac, json_encode(['datlist' => ['a.dat:https://example.test/a' => true], 'blocklist' => ['ext:a.dat:ads' => true]]));
    $roll->sent = [];
    datTestAssert($roll->changeRouteList('datlist', function (&$list) { $list['a.dat:https://example.test/a'] = false; }) === true
        && $files() === [] && str_contains(implode("\n", $roll->sent), 'a.dat — 1'), 'disabling a referenced source gave no warning: ' . json_encode($roll->sent));
    @unlink($roll->pac);
    @rmdir($rollDir);

    // ── Категории ───────────────────────────────────────────────────────────
    datTestAssert($download->datCategories('sample.dat') === ['fourth', 'ru'], 'categories were not parsed');
    file_put_contents("$dir/broken.dat", "\x0a\x7f\x0a\x02RU");
    datTestAssert($download->datParseCategories("$dir/broken.dat") === null, 'truncated file parsed as valid');
    file_put_contents("$dir/empty.dat", '');
    datTestAssert($download->datParseCategories("$dir/empty.dat") === null, 'empty file parsed as valid');
    $big = "\x0a\x84\x02\x0a\x02CN" . str_repeat("\x00", 256) . datBlob(['Tail']);
    file_put_contents("$dir/big.dat", $big);
    datTestAssert($download->datParseCategories("$dir/big.dat") === ['cn', 'tail'], 'multi-byte length was not skipped');
    $cat = fn(string $e) => $download->datCategoryError($download->classifyRouteEntry($e));
    datTestAssert($cat('ext:sample.dat:RU') === null, 'existing category rejected');
    datTestAssert($cat('extip:sample.dat:!ru') === null, 'negated category rejected');
    datTestAssert($cat('ext:sample.dat:fourth@attr') === null, 'category with attribute rejected');
    datTestAssert(str_contains((string) $cat('ext:sample.dat:nope'), 'nope'), 'missing category accepted');
    datTestAssert($cat('ext:absent.dat:x') === null, 'missing file must be left to the asset check');
    datTestAssert($cat('ext:broken.dat:x') === null, 'unparsed file must be left to xray');
    datTestAssert($cat('geosite:cn') === null, 'core file absent: no verdict expected');
    copy("$dir/sample.dat", "$dir/geoip.dat");
    datTestAssert(str_contains((string) $cat('geoip:zz'), 'geoip.dat'), 'missing core category accepted');
    datTestAssert($cat('geoip:ru') === null, 'existing core category rejected');
    // Регистр имени: в правиле «Sample.DAT», на диске «sample.dat».
    datTestAssert($download->datFileReady('Sample.DAT:ru'), 'case-insensitive name was not resolved');
    datTestAssert($download->extAssetRef('Sample.DAT:ru') === 'sample.dat:ru', 'asset ref keeps a name that is not on disk');
    datTestAssert($download->datRefCount(['blocklist' => ['ext:Sample.dat:ru' => true, 'ext:sample.dat:x' => false, 'extip:other.dat:ru' => true]], 'sample.dat') === 1, 'reference count mismatch');
    datTestAssert($download->datEnabledNames(['datlist' => ['a.dat:https://x/a.dat' => true, 'b.dat:https://x/b.dat' => false]]) === ['a.dat'], 'enabled names mismatch');

    // ── Расписание: пределы, свой интервал, час запуска ─────────────────────
    $tz = date_default_timezone_get();
    date_default_timezone_set('UTC');
    datTestAssert($schedule->datParseInterval('90m') === 5400 && $schedule->datParseInterval(' 36 H ') === 129600
        && $schedule->datParseInterval('10д') === 864000, 'custom interval was not parsed');
    foreach (['14m', '91d', '0h', '5', 'abc', '1.5h', '-2h', ''] as $bad) {
        datTestAssert($schedule->datParseInterval($bad) === null, "bad interval accepted: $bad");
    }
    datTestAssert($schedule->datUpdateIntervalLabel(5400) === '90m' && $schedule->datUpdateIntervalLabel(129600) === '36h'
        && $schedule->datUpdateIntervalLabel(864000) === '10d' && $schedule->datUpdateIntervalLabel(60) === 'off'
        && $schedule->datUpdateIntervalLabel(1209600) === '14d', 'interval label mismatch');
    $at = fn(string $t) => strtotime("$t UTC");
    datTestAssert($schedule->datNextRun($at('2026-10-13 15:00'), 3600, 4) === $at('2026-10-13 16:00'), 'hour must not apply below 1d');
    datTestAssert($schedule->datNextRun($at('2026-10-13 15:00'), 86400, null) === $at('2026-10-14 15:00'), 'plain interval mismatch');
    datTestAssert($schedule->datNextRun($at('2026-10-13 15:00'), 86400, 4) === $at('2026-10-14 04:00'), 'daily hour: first run');
    datTestAssert($schedule->datNextRun($at('2026-10-14 04:00:07'), 86400, 4) === $at('2026-10-15 04:00'), 'daily hour drifted');
    datTestAssert($schedule->datNextRun($at('2026-10-14 04:00:00'), 86400, 4) === $at('2026-10-15 04:00'), 'daily hour: exact boundary');
    datTestAssert($schedule->datNextRun($at('2026-10-14 23:30'), 86400, 4) === $at('2026-10-15 04:00'), 'late run must return to its hour');
    datTestAssert($schedule->datNextRun($at('2026-10-12 04:00:05'), 604800, 4) === $at('2026-10-19 04:00'), 'weekly hour mismatch');
    datTestAssert($schedule->datNextRun($at('2026-12-31 23:10'), 172800, 0) === $at('2027-01-02 00:00'), 'year boundary mismatch');

    $schedule->datScheduleCustomSet('90m');
    $saved = json_decode(file_get_contents($schedule->pac), true);
    datTestAssert(($saved['dat_update_interval'] ?? 0) === 5400, 'custom interval was not saved');
    $schedule->sent = [];
    $schedule->datScheduleCustomSet('3 weeks');
    $saved = json_decode(file_get_contents($schedule->pac), true);
    datTestAssert(($saved['dat_update_interval'] ?? 0) === 5400 && count($schedule->sent) === 1, 'bad custom interval changed the schedule');
    $schedule->datScheduleSet(60);
    datTestAssert((json_decode(file_get_contents($schedule->pac), true)['dat_update_interval'] ?? 0) === 5400, 'out-of-range interval saved');

    $schedule->datScheduleSet(86400);
    $schedule->datScheduleHour(4);
    $saved = json_decode(file_get_contents($schedule->pac), true);
    datTestAssert(($saved['dat_update_hour'] ?? null) === 4 && date('H:i', $saved['dat_update_next']) === '04:00'
        && $saved['dat_update_next'] > time() && $saved['dat_update_next'] <= time() + 86400, 'run hour was not applied');
    datTestAssert($schedule->datScheduleLabel($saved) === '1d, 04:00', 'schedule label mismatch');
    $schedule->datScheduleHour(24);
    datTestAssert((json_decode(file_get_contents($schedule->pac), true)['dat_update_hour'] ?? null) === 4, 'hour 24 accepted');
    $schedule->datScheduleHour(null);
    $saved = json_decode(file_get_contents($schedule->pac), true);
    datTestAssert(!isset($saved['dat_update_hour']) && $saved['dat_update_next'] >= time() + 86399, 'run hour was not removed');

    // ── Отказ автообновления: повтор через час, одно уведомление ────────────
    $conf = [
        'datlist' => ['sample.dat:https://example.test/a' => true],
        'dat_update_interval' => 604800,
        'dat_update_next' => 1,
    ];
    file_put_contents($schedule->pac, json_encode($conf));
    $schedule->syncErrors = ['sample.dat' => 'http 404'];
    $schedule->contentChanged = false;
    $schedule->notices = [];
    $t0 = time();
    $schedule->checkDatUpdates();
    $saved = json_decode(file_get_contents($schedule->pac), true);
    datTestAssert($saved['dat_update_next'] >= $t0 + 3600 && $saved['dat_update_next'] <= time() + 3600, 'failure must retry in one hour');
    datTestAssert(!array_key_exists('dat_update_last_success', $saved), 'failed first attempt wrote a zero success mark');
    datTestAssert(count($schedule->notices) === 1 && str_contains($schedule->notices[0], 'http 404'), 'failure was not reported');
    $saved['dat_update_next'] = 1;
    file_put_contents($schedule->pac, json_encode($saved));
    $schedule->checkDatUpdates();
    datTestAssert(count($schedule->notices) === 1, 'repeated failure reported twice');
    $saved = json_decode(file_get_contents($schedule->pac), true);
    $saved['dat_update_next'] = 1;
    file_put_contents($schedule->pac, json_encode($saved));
    $schedule->syncErrors = [];
    $schedule->checkDatUpdates();
    $saved = json_decode(file_get_contents($schedule->pac), true);
    datTestAssert(count($schedule->notices) === 2 && empty($saved['dat_update_failed']), 'recovery was not reported');
    datTestAssert($saved['dat_update_next'] >= $t0 + 604800, 'recovery did not restore the full interval');

    // ── Встроенные geosite.dat/geoip.dat обновляются и при пустом реестре ───
    $before = $schedule->syncCount;
    file_put_contents($schedule->pac, json_encode([
        'datlist' => [], 'blocklist' => ['geosite:category-ads-all' => true],
        'dat_update_interval' => 3600, 'dat_update_next' => 1,
    ]));
    $schedule->checkDatUpdates();
    datTestAssert($schedule->syncCount === $before + 1, 'core dat files are not auto-updated without registry entries');
    file_put_contents($schedule->pac, json_encode(['datlist' => [], 'dat_update_interval' => 3600, 'dat_update_next' => 1]));
    $schedule->checkDatUpdates();
    datTestAssert($schedule->syncCount === $before + 1, 'schedule ran with nothing to update');
    datTestAssert($download->datLastUpdateAt(['dat_update_last_success' => 0]) > 0, 'zero success mark hides file time');

    // ── Меню: расписание с часом, состояние файлов, категории ───────────────
    file_put_contents($menu->pac, json_encode([
        'datlist' => ['sample.dat:https://example.test/a' => true, 'gone.dat:https://example.test/g.dat' => true],
        'dat_update_interval' => 86400, 'dat_update_hour' => 5, 'dat_update_next' => time() + 100,
    ]));
    copy("$dir/sample.dat", "$dir/keep.dat");
    $menu->datWriteMeta('gone.dat', ['error' => 'http 404 <x>', 'checked_at' => time()]);
    $menu->xtlsdat();
    datTestAssert(str_contains($menu->capturedText, 'auto update: 1d, 05:00'), 'run hour missing in dat menu');
    datTestAssert(str_contains($menu->capturedText, 'sample.dat — ') && str_contains($menu->capturedText, 'http 404 &lt;x&gt;'), 'file status missing or unescaped');
    datTestAssert(str_contains(json_encode($menu->capturedButtons), '/datfiles'), 'categories button is missing');
    $menu->datSchedule();
    $buttons = json_encode($menu->capturedButtons, JSON_UNESCAPED_UNICODE);
    datTestAssert(str_contains($buttons, '✅05') && str_contains($buttons, '/datschedulehour 23') && str_contains($buttons, '/datschedulehour off')
        && str_contains($buttons, '/datschedulecustom') && str_contains($buttons, '/datscheduleset 2592000'), 'schedule menu is incomplete');
    file_put_contents($menu->pac, json_encode(['dat_update_interval' => 5400, 'dat_update_hour' => 5]));
    $menu->datSchedule();
    $buttons = json_encode($menu->capturedButtons, JSON_UNESCAPED_UNICODE);
    datTestAssert(!str_contains($buttons, '/datschedulehour') && str_contains($buttons, '✅ 90m'), 'sub-daily schedule must hide hours and mark custom');
    $menu->datFiles();
    $key = $menu->datFileKey('sample.dat');
    datTestAssert(str_contains(json_encode($menu->capturedButtons), "/datcats $key"), 'file is missing in categories menu');
    $many = [];
    for ($i = 0; $i < 130; $i++) $many[] = sprintf('CATEGORY-LONG-NAME-NUMBER-%03d', $i);
    file_put_contents("$dir/sample.dat", datBlob($many));
    $menu->datCats($key, 1);
    datTestAssert(str_contains($menu->capturedText, 'category-long-name-number-060') && !str_contains($menu->capturedText, 'number-059')
        && mb_strlen($menu->capturedText) < 4096, 'categories page is wrong or too long');
    foreach ($menu->capturedButtons as $row) foreach ($row as $button) {
        datTestAssert(strlen($button['callback_data']) <= 64, 'callback data too long: ' . $button['callback_data']);
    }
    $menu->datCatSearchSet(' Number-12<b>', $key);
    datTestAssert(str_contains($menu->capturedText, 'number-12b') || str_contains($menu->capturedText, ': 0 / 130'), 'search query was not sanitised');
    $menu->datCatSearchSet('NUMBER-12', $key);
    datTestAssert(str_contains($menu->capturedText, ': 10 / 130') && str_contains($menu->capturedText, 'number-129'), 'category search failed');
    $menu->datCats('k000000000000', 0);
    datTestAssert(str_contains(json_encode($menu->capturedButtons), '/xtlsdat'), 'unknown file key must fall back to the file list');
    date_default_timezone_set($tz);

    echo "dat_schedule_test OK\n";
} finally {
    foreach (glob("$dir/*") ?: [] as $file) {
        @unlink($file);
    }
    @rmdir($dir);
}
