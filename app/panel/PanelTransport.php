<?php

require_once __DIR__ . '/Store.php';

/**
 * Транспорт Bot API поверх локального хранилища.
 *
 * Подставляется в Bot::$transport, после чего Bot::request() не ходит в сеть.
 * Реализованы ровно те 14 методов, которые бот вообще вызывает; формат ответа
 * повторяет телеграмный, потому что код читает $r['result']['message_id']
 * (Bot::send(), Bot::stashReply(), Bot::qrPeer() и т.д.).
 */
class PanelTransport
{
    private $store;
    /** draft_id => message_id пузыря с ходом выполнения (см. draft()). */
    private $drafts = [];

    public function __construct(PanelStore $store)
    {
        $this->store = $store;
    }

    public function store()
    {
        return $this->store;
    }

    public function call($method, $data, $json_header = 0)
    {
        // setMyCommands/sendMessageDraft уходят JSON-строкой ($json_header=1).
        if (is_string($data)) {
            $data = json_decode($data, true) ?: [];
        }
        if (!is_array($data)) {
            $data = [];
        }

        switch ($method) {
            case 'sendMessage':
                $this->closeDrafts();

                return $this->sendMessage($data);

            case 'editMessageText':
                $this->closeDrafts();

                return $this->editMessageText($data);

            case 'sendMessageDraft':
                return $this->draft($data);

            case 'deleteMessage':
                $this->store->delete((int) ($data['message_id'] ?? 0));

                return ['ok' => true, 'result' => true];

            case 'answerCallbackQuery':
                // Пустой answer — это просто «сними часики» у телеграмной
                // кнопки, показывать в панели нечего.
                if (!empty($data['text'])) {
                    $this->store->toast($data['text'], !empty($data['show_alert']));
                }

                return ['ok' => true, 'result' => true];

            case 'sendPhoto':
                $this->closeDrafts();

                return $this->sendAttachment($data, 'photo');

            case 'sendDocument':
                $this->closeDrafts();

                return $this->sendAttachment($data, 'document');

            case 'getFile':
                // file_id в панели — это имя файла в filesDir(), а Bot::$file
                // в панель-режиме указывает туда же.
                return ['ok' => true, 'result' => ['file_id' => $data['file_id'] ?? '', 'file_path' => $data['file_id'] ?? '']];

            case 'getMyName':
                return ['ok' => true, 'result' => ['name' => 'panel']];

            // Смысла вне Telegram не имеют, но вызываются: молча подтверждаем.
            case 'pinChatMessage':
            case 'unpinChatMessage':
            case 'setMyCommands':
            case 'deleteWebhook':
                return ['ok' => true, 'result' => true];

            case 'getUpdates':
                return ['ok' => true, 'result' => []];
        }

        return ['ok' => true, 'result' => true];
    }

    private function sendMessage(array $data)
    {
        $markup = $this->markup($data['reply_markup'] ?? null);
        $id     = $this->store->put([
            'text'    => (string) ($data['text'] ?? ''),
            'buttons' => $markup['buttons'],
            'reply'   => $markup['reply'],
            'to'      => (int) ($data['reply_to_message_id'] ?? 0) ?: null,
        ]);

        return $this->result($id, $data);
    }

    /**
     * Черновик Telegram — ход долгой операции (переключение WARP, проверки
     * MASQUE): бот шлёт его повторно с тем же draft_id и растущим текстом, а
     * итог — обычным сообщением. В панели черновик — пузырь, который
     * правится на месте; опрос ленты идёт параллельно с обработчиком, так что
     * ход виден вживую. Итоговое сообщение того же действия черновик убирает
     * (closeDrafts()). Ответ — как у Telegram: true, без message_id.
     */
    private function draft(array $data)
    {
        $key  = (string) ($data['draft_id'] ?? '');
        $text = (string) ($data['text'] ?? '');
        if (isset($this->drafts[$key]) && $this->store->edit($this->drafts[$key], ['text' => $text])) {
            return ['ok' => true, 'result' => true];
        }
        if ('' !== $text) {
            $this->drafts[$key] = $this->store->put(['text' => $text, 'draft' => true]);
        }

        return ['ok' => true, 'result' => true];
    }

    /** Убирает черновики: их заменяет итоговое сообщение. */
    public function closeDrafts()
    {
        foreach ($this->drafts as $id) {
            $this->store->delete($id);
        }
        $this->drafts = [];
    }

    private function editMessageText(array $data)
    {
        $id     = (int) ($data['message_id'] ?? 0);
        $markup = $this->markup($data['reply_markup'] ?? null);
        $ok     = $this->store->edit($id, [
            'text'    => (string) ($data['text'] ?? ''),
            'buttons' => $markup['buttons'],
            'reply'   => $markup['reply'],
        ]);
        if (!$ok) {
            // Тот же ответ, что у Telegram на правку исчезнувшего сообщения —
            // Bot::request() такие в лог не пишет только для «not modified»,
            // поэтому строку берём телеграмную.
            return ['ok' => false, 'error_code' => 400, 'description' => 'Bad Request: message to edit not found'];
        }

        return $this->result($id, $data);
    }

    private function sendAttachment(array $data, $kind)
    {
        $src  = $data[$kind] ?? null;
        $file = $this->ingest($src);
        $id   = $this->store->put([
            'text'   => (string) ($data['caption'] ?? ''),
            'attach' => $file,
            'to'     => (int) ($data['reply_to_message_id'] ?? 0) ?: null,
        ]);

        return $this->result($id, $data);
    }

    /**
     * Приводит то, что бот передал в sendPhoto/sendDocument, к записи вложения.
     * Файлы копируем СЕЙЧАС: sendQr() удаляет png сразу после отправки.
     */
    private function ingest($src)
    {
        if ($src instanceof CURLStringFile) {
            return [
                'kind' => $this->kindOf($src->postname, $src->mime),
                'file' => $this->store->storeFile($src->data, $src->postname),
                'name' => $src->postname,
                'mime' => $src->mime,
            ];
        }
        if ($src instanceof CURLFile) {
            $path = $src->getFilename();
            $name = $src->getPostFilename() ?: basename($path);
            $body = @file_get_contents($path);
            if ($body === false) {
                return null;
            }

            return [
                'kind' => $this->kindOf($name, $src->getMimeType()),
                'file' => $this->store->storeFile($body, $name),
                'name' => $name,
                'mime' => $src->getMimeType() ?: '',
            ];
        }
        if (is_string($src) && $src !== '') {
            // Уже загруженный файл (file_id панели) или внешний URL.
            if ($this->store->fileExists($src)) {
                return [
                    'kind' => $this->kindOf($src, ''),
                    'file' => $src,
                    'name' => preg_replace('~^[0-9a-f]{16}_~', '', $src),
                    'mime' => '',
                ];
            }

            return self::safeUrl($src)
                ? ['kind' => 'link', 'url' => $src, 'name' => $src, 'file' => null]
                : null;
        }

        return null;
    }

    /**
     * Кнопки и вложения-ссылки уходят прямо в href. Схемы клиентских
     * deep-link'ов (vless://, sing-box://…) нужны, поэтому запрещаем не всё
     * кроме http, а только то, что исполняется в странице.
     */
    public static function safeUrl($url)
    {
        if (!is_string($url)) {
            return false;
        }
        // Перед разбором схемы браузер выбрасывает из URL пробельные и
        // управляющие символы: "java\tscript:alert(1)" и "\njavascript:…"
        // исполняются, а прежний шаблон (^\s* и \s* только вокруг) их
        // пропускал. Сверяем ту же строку, что увидит браузер.
        $u = (string) preg_replace('~[\x00-\x20\x7f]~', '', $url);

        return !preg_match('~^(javascript|data|vbscript):~i', $u);
    }

    private function kindOf($name, $mime)
    {
        if (str_starts_with((string) $mime, 'image/')) {
            return 'photo';
        }

        return preg_match('~\.(png|jpe?g|gif|webp)$~i', (string) $name) ? 'photo' : 'document';
    }

    /**
     * reply_markup приходит JSON-строкой (Bot::send() его json_encode'ит).
     * Разбираем в вид, удобный UI: плоские кнопки с cb/url и подсказка
     * force_reply.
     */
    private function markup($raw)
    {
        $out = ['buttons' => [], 'reply' => null];
        if (empty($raw)) {
            return $out;
        }
        $m = is_string($raw) ? json_decode($raw, true) : $raw;
        if (!is_array($m)) {
            return $out;
        }
        if (!empty($m['force_reply'])) {
            $out['reply'] = (string) ($m['input_field_placeholder'] ?? '');

            return $out;
        }
        foreach ($m['inline_keyboard'] ?? [] as $row) {
            $r = [];
            foreach ((array) $row as $b) {
                if (!is_array($b) || !isset($b['text'])) {
                    continue;
                }
                $btn = ['text' => (string) $b['text']];
                if (isset($b['callback_data'])) {
                    $btn['cb'] = (string) $b['callback_data'];
                } elseif (isset($b['web_app']['url']) && self::safeUrl($b['web_app']['url'])) {
                    $btn['url']    = (string) $b['web_app']['url'];
                    $btn['webapp'] = true;
                } elseif (isset($b['url']) && self::safeUrl($b['url'])) {
                    $btn['url'] = (string) $b['url'];
                } else {
                    continue;
                }
                $r[] = $btn;
            }
            if ($r) {
                $out['buttons'][] = $r;
            }
        }

        return $out;
    }

    private function result($id, array $data)
    {
        return [
            'ok'     => true,
            'result' => [
                'message_id' => $id,
                'date'       => time(),
                'chat'       => ['id' => $data['chat_id'] ?? 0],
                'text'       => (string) ($data['text'] ?? $data['caption'] ?? ''),
            ],
        ];
    }
}
