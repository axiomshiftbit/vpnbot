<?php

trait BotProtocolOptions
{
    public function protocolOptions(string $protocol, string $action = 'show', string $path = '', string $choice = ''): void
    {
        if (!$this->admin) return;
        try {
            $store = $this->protocolStore($protocol);
            $path = ProtocolOptions::resolvePath($protocol, $path);
            $rule = ProtocolOptions::definition($protocol, $path);
            if ($action === 'export') {
                $document = json_encode((object) $store->read()['settings']['options'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
                $this->sendFile($this->input['chat'], new CURLStringFile($document, "$protocol-options.json", 'application/json'));
                return;
            }
            if ($action === 'reset') $store->configureOption($path, null);
            elseif ($action === 'pick') {
                $values = $rule[0] === 'bool' ? [false, true] : ($rule[0] === 'enum' ? $rule[1] : []);
                if (!preg_match('/\A[0-9]{1,2}\z/D', $choice) || !array_key_exists((int) $choice, $values)) throw new InvalidArgumentException('Неверный вариант');
                $store->configureOption($path, $values[(int) $choice]);
            } elseif ($action === 'edit') {
                if ($rule[0] === 'object') throw new InvalidArgumentException('Выберите параметр внутри группы');
                $prompt = self::esc(ManagedProtocol::NAMES[$protocol] . ' · ' . $path . "\n" . ProtocolOptions::describe($rule));
                $r = $this->send($this->input['chat'], $prompt, $this->input['message_id'], reply: 'Значение параметра');
                $this->stashReply($r, ['start_message' => $this->input['message_id'], 'callback' => 'protocolOptionReply', 'args' => [$protocol, $path]]);
                return;
            } elseif ($action !== 'show') throw new InvalidArgumentException('Неизвестное действие');
            $options = $store->read()['settings']['options'];
            $value = ProtocolOptions::at($options, $path);
            $text = [self::esc(ManagedProtocol::NAMES[$protocol]) . ' · дополнительные настройки'];
            $buttons = []; $prefix = "/po $protocol";
            if ($path !== '') $text[] = '<code>' . self::esc($path) . '</code>';
            if ($rule[0] === 'object') {
                $text[] = $path === ''
                    ? 'Общие параметры переносятся во все совместимые форматы. Разделы sing-box, Mihomo и нативного Mieru действуют только на указанный клиент. Адрес, SNI, ключи, доступ и маршруты управляются отдельно.'
                    : ProtocolOptions::hint($protocol, $path);
                $fields = [];
                foreach ($rule[1] as $field => $child) {
                    $childPath = $path === '' ? $field : $path . '.' . $field;
                    $current = ProtocolOptions::at($options, $childPath);
                    $label = $path === '' ? ProtocolOptions::groups($protocol)[$field] : $field;
                    $fields[] = ['text' => ($current === null || $current === [] ? '⚪ ' : '🟢 ') . $label,
                        'callback_data' => ProtocolOptions::callback($protocol, 'show', $childPath)];
                }
                $buttons = array_chunk($fields, 2);
                if ($path === '') $buttons[] = [['text' => 'Файл настроек JSON', 'callback_data' => "$prefix export"]];
            } else {
                $text[] = self::esc(ProtocolOptions::describe($rule));
                $text[] = self::esc(ProtocolOptions::hint($protocol, $path));
                $current = $value === null ? 'штатное значение' : json_encode($value, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                $text[] = 'Сейчас: <pre>' . self::esc(mb_strimwidth($current, 0, 1600, '…')) . '</pre>';
                if (in_array($rule[0], ['enum', 'bool'], true)) {
                    $values = $rule[0] === 'bool' ? [false, true] : $rule[1];
                    $picks = [];
                    foreach ($values as $index => $item) {
                        $picks[] = ['text' => ($value === $item ? '🟢 ' : '') . (is_bool($item) ? ($item ? 'Включено' : 'Выключено') : $item),
                            'callback_data' => ProtocolOptions::callback($protocol, 'pick', $path, $index)];
                    }
                    $buttons = array_chunk($picks, 2);
                } else $buttons[] = [['text' => 'Изменить', 'callback_data' => ProtocolOptions::callback($protocol, 'edit', $path)]];
            }
            $buttons[] = [['text' => $path === '' ? 'Сбросить дополнительные настройки' : 'Сбросить', 'callback_data' => ProtocolOptions::callback($protocol, 'reset', $path)]];
            $parent = str_contains($path, '.') ? substr($path, 0, strrpos($path, '.')) : '';
            $buttons[] = [['text' => $this->i18n('back'), 'callback_data' => $path === '' ? "/protocol $protocol" : ProtocolOptions::callback($protocol, 'show', $parent)]];
            $this->send($this->input['chat'], implode("\n", $text), $this->input['message_id'], $buttons);
        } catch (InvalidArgumentException | RuntimeException $e) {
            $this->send($this->input['chat'], self::esc($e->getMessage()));
        }
    }

    public function protocolOptionReply($input, string $protocol, string $path): void
    {
        if (!$this->admin) return;
        try {
            $rule = ProtocolOptions::definition($protocol, $path);
            if ($rule[0] === 'object') throw new InvalidArgumentException('Выберите параметр');
            $input = trim((string) $input);
            if (strlen($input) > 16384) throw new InvalidArgumentException('Слишком большое значение');
            if (in_array($rule[0], ['text', 'duration', 'hostname', 'ip', 'pin', 'hex', 'rotation'], true)) $value = $input;
            else $value = json_decode($input, true, 16, JSON_THROW_ON_ERROR);
            if ($value === null) throw new InvalidArgumentException('Для удаления используйте кнопку «Сбросить»');
            $this->protocolStore($protocol)->configureOption($path, $value);
            $this->protocolOptions($protocol, path: $path);
        } catch (JsonException $e) {
            $this->send($this->input['chat'], 'Неверный JSON. Для списка нужны квадратные скобки, строки заключаются в двойные кавычки.');
        } catch (InvalidArgumentException | RuntimeException $e) {
            $this->send($this->input['chat'], self::esc($e->getMessage()));
        }
    }
}
