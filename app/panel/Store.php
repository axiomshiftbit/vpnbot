<?php

/**
 * Хранилище переписки веб-панели.
 *
 * Панель показывает ровно то, что бот отправил бы в Telegram: сообщения с
 * inline-клавиатурой, правки (editMessageText), удаления, вложения. Всё это
 * складывается сюда вместо api.telegram.org (см. PanelTransport).
 *
 * Формат state.json:
 *   rev      — глобальный счётчик изменений; UI опрашивает since=<rev> и
 *              получает только то, что поменялось (новое, правки, удаления)
 *   next_id  — следующий message_id
 *   messages — id => запись сообщения (в т.ч. удалённые: UI должен узнать,
 *              что бабл пропал)
 *   toast    — последний answerCallbackQuery
 *
 * Все записи идут под flock: панельные запросы обслуживаются несколькими
 * процессами unit (см. applications/panel в config/unit.json), и опрос ленты
 * идёт параллельно с длинным обработчиком.
 */
class PanelStore
{
    /**
     * message_id панели начинаются отсюда. Телеграмные id в личке — небольшие
     * последовательные числа, а карта wg_msg.json и $_SESSION['reply'] общие
     * для обоих интерфейсов: смещение исключает пересечение ключей.
     */
    public const ID_BASE = 1000000000;

    /** Сколько сообщений держим в ленте (старые вытесняются вместе с файлами). */
    private const KEEP = 300;

    private $dir;
    private $file;
    private $filesDir;

    public function __construct($dir = '/config/panel')
    {
        $this->dir      = rtrim($dir, '/');
        $this->file     = $this->dir . '/state.json';
        $this->filesDir = $this->dir . '/files';
        if (!is_dir($this->filesDir)) {
            @mkdir($this->filesDir, 0700, true);
        }
        @chmod($this->dir, 0700);
    }

    public function filesDir()
    {
        return $this->filesDir . '/';
    }

    public function dir()
    {
        return $this->dir;
    }

    private function blank()
    {
        return [
            'rev'      => 0,
            'next_id'  => self::ID_BASE,
            'messages' => [],
            'toast'    => null,
        ];
    }

    /**
     * Чтение без блокировки на запись. Частичная запись невозможна: save()
     * пишет через временный файл и rename(), то есть читатель всегда видит
     * либо старое состояние целиком, либо новое целиком.
     */
    public function read()
    {
        $raw = @file_get_contents($this->file);
        $s   = $raw === false ? null : json_decode($raw, true);

        return is_array($s) && isset($s['messages']) ? $s : $this->blank();
    }

    /**
     * Атомарная правка состояния: $fn получает состояние по ссылке и может
     * вернуть значение — оно же вернётся наружу.
     */
    public function mutate(callable $fn)
    {
        $lock = @fopen($this->file . '.lock', 'c');
        if ($lock) {
            @chmod($this->file . '.lock', 0600);
            flock($lock, LOCK_EX);
        }
        try {
            $state = $this->read();
            $state['rev']++;
            $out = $fn($state);
            $this->trim($state);
            $this->save($state);

            return $out;
        } finally {
            if ($lock) {
                flock($lock, LOCK_UN);
                fclose($lock);
            }
        }
    }

    private function save(array $state)
    {
        // Текст сообщений — это вывод команд и ssh-проб, то есть сырые байты:
        // невалидный UTF-8 заставляет json_encode() вернуть FALSE, а
        // file_put_contents($f, false) пишет ПУСТОЙ файл и рапортует об успехе —
        // rename() ниже подменил бы всю ленту нулями. Лучше потерять один ответ
        // (SUBSTITUTE подставит U+FFFD), чем всю переписку.
        $json = json_encode($state, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        if (false === $json) {
            error_log('panel store: json_encode failed — ' . json_last_error_msg());

            return;
        }
        $tmp = $this->file . '.tmp';
        if (!file_exists($this->file)) {
            @touch($this->file);
            @chmod($this->file, 0600);
        }
        if (file_put_contents($tmp, $json) === false) {
            @unlink($tmp);

            return;
        }
        @chmod($tmp, 0600);
        rename($tmp, $this->file);
    }

    /** Вытесняем самые старые сообщения вместе с их вложениями. */
    private function trim(array &$state)
    {
        $over = count($state['messages']) - self::KEEP;
        if ($over <= 0) {
            return;
        }
        ksort($state['messages'], SORT_NUMERIC);
        foreach (array_slice(array_keys($state['messages']), 0, $over) as $id) {
            $att = $state['messages'][$id]['attach'] ?? null;
            if (!empty($att['file'])) {
                @unlink($this->filesDir . '/' . $att['file']);
            }
            unset($state['messages'][$id]);
        }
    }

    /** Новое сообщение. Возвращает его message_id. */
    public function put(array $msg)
    {
        return $this->mutate(function (&$state) use ($msg) {
            $id  = $state['next_id']++;
            $rec = $msg + [
                'id'      => $id,
                'date'    => time(),
                'text'    => '',
                'buttons' => [],
                'reply'   => null,
                'attach'  => null,
                'deleted' => false,
            ];
            $rec['id']  = $id;
            $rec['rev'] = $state['rev'];
            $state['messages'][$id] = $rec;

            return $id;
        });
    }

    /** Правка существующего сообщения. false — такого сообщения нет. */
    public function edit($id, array $fields)
    {
        return $this->mutate(function (&$state) use ($id, $fields) {
            if (empty($state['messages'][$id]) || !empty($state['messages'][$id]['deleted'])) {
                return false;
            }
            $state['messages'][$id] = array_merge($state['messages'][$id], $fields, [
                'rev'    => $state['rev'],
                'edited' => time(),
            ]);

            return true;
        });
    }

    public function delete($id)
    {
        return $this->mutate(function (&$state) use ($id) {
            if (empty($state['messages'][$id])) {
                return false;
            }
            $att = $state['messages'][$id]['attach'] ?? null;
            if (!empty($att['file'])) {
                @unlink($this->filesDir . '/' . $att['file']);
            }
            $state['messages'][$id]['deleted'] = true;
            $state['messages'][$id]['attach']  = null;
            $state['messages'][$id]['buttons'] = [];
            $state['messages'][$id]['rev']     = $state['rev'];

            return true;
        });
    }

    public function toast($text, $alert = false)
    {
        return $this->mutate(function (&$state) use ($text, $alert) {
            $state['toast'] = [
                'text'  => (string) $text,
                'alert' => (bool) $alert,
                'rev'   => $state['rev'],
            ];

            return true;
        });
    }

    /**
     * Кладёт содержимое во внутреннюю папку файлов и возвращает имя, под
     * которым оно там лежит. Это же имя работает как file_id: getFile()
     * отдаёт его как file_path, а Bot::$file в панель-режиме указывает на
     * filesDir(), поэтому существующие file_get_contents($this->file . $path)
     * читают файл без правок.
     */
    public function storeFile($contents, $name)
    {
        $safe = preg_replace('~[^\w.-]~u', '_', (string) $name) ?: 'file';
        $safe = trim(str_replace('..', '_', $safe), '.') ?: 'file';
        $id   = bin2hex(random_bytes(8)) . '_' . $safe;
        file_put_contents($this->filesDir . '/' . $id, $contents);
        @chmod($this->filesDir . '/' . $id, 0600);

        return $id;
    }

    /**
     * Удаляет файлы, на которые не ссылается ни одно сообщение ленты и
     * которые старше суток. Это загруженные через панель конфиги: привязать
     * их к баблу нельзя (Bot::reply() удаляет наше сообщение раньше, чем
     * обработчик прочитает файл), поэтому вытеснение ленты их не трогает.
     */
    public function pruneUploads($olderThan = 86400)
    {
        $used = [];
        foreach ($this->read()['messages'] as $m) {
            if (!empty($m['attach']['file'])) {
                $used[$m['attach']['file']] = true;
            }
        }
        foreach (glob($this->filesDir . '/*') ?: [] as $f) {
            if (isset($used[basename($f)])) {
                continue;
            }
            if (time() - (int) @filemtime($f) > $olderThan) {
                @unlink($f);
            }
        }
    }

    public function fileExists($id)
    {
        return $this->isSafeId($id) && is_file($this->filesDir . '/' . $id);
    }

    public function filePath($id)
    {
        return $this->isSafeId($id) ? $this->filesDir . '/' . $id : false;
    }

    /** Имена файлов приходят из query панели — за пределы папки не выпускаем. */
    private function isSafeId($id)
    {
        return is_string($id) && $id !== '' && !str_contains($id, '/') && !str_contains($id, '..');
    }

    /**
     * Всё, что изменилось после ревизии $since: сообщения (включая удалённые),
     * тост и текущая ревизия. Первый запрос ($since = 0) отдаёт ленту целиком.
     */
    public function since($since)
    {
        $state = $this->read();
        $out   = [];
        foreach ($state['messages'] as $m) {
            if (($m['rev'] ?? 0) > $since) {
                $out[] = $m;
            }
        }
        usort($out, fn ($a, $b) => $a['id'] <=> $b['id']);
        $toast = $state['toast'] ?? null;
        if ($toast && ($toast['rev'] ?? 0) <= $since) {
            $toast = null;
        }

        return [
            'rev'      => $state['rev'],
            'messages' => $out,
            'toast'    => $toast,
        ];
    }

    /**
     * Полная очистка ленты (кнопка «очистить» в панели).
     *
     * Файлы убираем ВНУТРИ блокировки и только те, на которые ссылается лента:
     * прежний `glob() + unlink` до mutate() сносил в том числе вложение,
     * которое параллельный обработчик уже записал через storeFile(), но ещё не
     * успел прикрепить к сообщению, — в ленте оставался бабл с битой
     * картинкой. Осиротевшие остатки подчищает pruneUploads() ниже: свежие
     * (моложе минуты) переживают очистку, как и должны.
     */
    public function reset()
    {
        $this->mutate(function (&$state) {
            foreach ($state['messages'] as $m) {
                if (!empty($m['attach']['file'])) {
                    @unlink($this->filesDir . '/' . $m['attach']['file']);
                }
            }
            $next             = $state['next_id'];
            $rev              = $state['rev'];
            $state            = $this->blank();
            $state['next_id'] = $next;
            $state['rev']     = $rev;

            return true;
        });
        $this->pruneUploads(60);
    }
}
