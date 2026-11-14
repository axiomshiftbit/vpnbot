<?php

// Восстановление резервной копии из командной строки (app/restore.php,
// make restore FILE=backup.json): когда бот не может ответить в Telegram или
// сервер переносится без связи с ним. Восстановление то же, что у файла из
// Telegram (Bot::importCliFile), ход печатается в stdout вместо сообщений.
class BackupCli extends Bot
{
    /** @var resource */
    public $cliOut = STDOUT;
    /** @var resource */
    public $cliErr = STDERR;
    private string $cliShown = '';

    public static function cliText(string $html): string
    {
        return html_entity_decode(strip_tags($html), ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }

    // restoreBackup() каждый раз передаёт весь список этапов: печатаем новые строки.
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML')
    {
        $text = (string) $text;
        $new = str_starts_with($text, $this->cliShown) ? substr($text, strlen($this->cliShown)) : $text;
        $this->cliShown = $text;
        $new = trim($new, "\n");
        if ($new !== '') fwrite($this->cliOut, self::cliText($new) . "\n");
        return ['ok' => true];
    }

    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false)
    {
        if ((string) $text !== '') fwrite($this->cliOut, self::cliText((string) $text) . "\n");
        return ['ok' => true, 'result' => ['message_id' => 0]];
    }

    protected function backupImportError(string $stage, bool $local, ?Throwable $error = null): bool
    {
        parent::backupImportError($stage, true, $error);
        fwrite($this->cliErr, '❌ ' . $this->i18n('backup restore interrupted') . ' ' . $this->i18n('backup stage ' . $stage) . "\n");
        return false;
    }

    /** @param resource $in */
    public function cli(array $args, $in): int
    {
        $this->input = ['chat' => 0, 'message_id' => 0, 'callback_id' => 0, 'username' => '', 'from' => 0];
        $check = $args === ['--check'];
        if ($args !== [] && !$check) {
            fwrite($this->cliErr, $this->t(
                "make restore FILE=backup.json        восстановить настройки из копии\nmake restore-check FILE=backup.json  только проверить файл\nбез make: docker compose exec -T php php /app/restore.php [--check] < backup.json\n",
                "make restore FILE=backup.json        restore the settings from a backup\nmake restore-check FILE=backup.json  only check the file\nwithout make: docker compose exec -T php php /app/restore.php [--check] < backup.json\n"));
            return 2;
        }
        $raw = stream_get_contents($in, self::BACKUP_MAX_BYTES + 1);
        $json = is_string($raw) && strlen($raw) <= self::BACKUP_MAX_BYTES ? json_decode($raw, true, 128) : null;
        $found = is_array($json) ? array_values(array_intersect(self::BACKUP_SECTIONS, array_keys($json))) : [];
        if (!$found) { $this->backupImportError('file', true); return 1; }
        try { $this->validateBackup($json); }
        catch (Throwable $error) { $this->backupImportError('file', true, $error); return 1; }
        fwrite($this->cliOut, $this->t('Разделы копии: ', 'Backup sections: ') . implode(', ', $found) . "\n");
        if ($check) return 0;
        $mask = umask(0077);
        $tmp = tempnam(sys_get_temp_dir(), 'vpnbot-restore-');
        umask($mask);
        try {
            if ($tmp === false || @file_put_contents($tmp, $raw) !== strlen($raw)) { $this->backupImportError('file', true); return 1; }
            unset($raw, $json);
            return $this->importCliFile($tmp) ? 0 : 1;
        } finally {
            if ($tmp !== false) @unlink($tmp);
        }
    }
}
