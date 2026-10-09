<?php

require_once __DIR__ . '/HysteriaUsers.php';

trait BotHysteria
{
    public string $hysteriaConf = '/config/hysteria.yaml';
    public string $hysteriaUsersRoot = '/config/hysteria';

    public function hysteriaUsersStore(): HysteriaUsers { return new HysteriaUsers($this->hysteriaUsersRoot); }

    public function hyPersonalReady(): bool
    {
        $status = $this->hysteriaUsersStore()->status();
        return ($status['schema'] ?? null) === 1 && ($status['time'] ?? 0) >= time() - 15
            && !empty($status['running']) && empty($status['error']);
    }

    public function hyUsers(int $page = 0): void
    {
        if (!$this->admin) return;
        try {
            $state = $this->hysteriaUsersStore()->read();
            $pages = max(1, (int) ceil(count($state['users']) / 8));
            $page = max(0, min($page, $pages - 1));
            $text = ['Hysteria → Персональные доступы',
                'У каждого пользователя свои реквизиты, срок и квота. Общий пароль остаётся отдельным доступом без этих ограничений; отключите его после перехода клиентов.',
                'Отзыв и смена пароля, истечение срока или квоты разрывают активные соединения Hysteria. Остальные пользователи переподключаются. Проверка ограничений выполняется примерно раз в секунду; возможен перерасход между проверками.'];
            if (!$this->hyPersonalReady()) $text[] = 'Контроль доступа пока недоступен. Обновите образ Hysteria и проверьте состояние сервиса.';
            $buttons = [];
            foreach (array_slice($state['users'], $page * 8, 8, true) as $id => $user) {
                $buttons[] = [['text' => ($user['enabled'] ? '🟢 ' : '🔴 ') . $user['name'], 'callback_data' => "/hyUser $id"]];
            }
            if ($pages > 1) $buttons[] = [
                ['text' => '←', 'callback_data' => '/hyUsers ' . max(0, $page - 1)],
                ['text' => ($page + 1) . "/$pages", 'callback_data' => "/hyUsers $page"],
                ['text' => '→', 'callback_data' => '/hyUsers ' . min($pages - 1, $page + 1)],
            ];
            $buttons[] = [['text' => 'Добавить пользователя', 'callback_data' => '/hyUser add']];
            $buttons[] = [['text' => 'Групповые действия', 'callback_data' => '/abstart hy']];
            if (!empty($this->getPacConf()['hysteria_pass'])) {
                $buttons[] = [['text' => 'Отключить общий пароль', 'callback_data' => '/hyUser legacy-off']];
            }
            $buttons[] = [['text' => $this->i18n('back'), 'callback_data' => '/menu hy']];
            $this->update($this->input['chat'], $this->input['message_id'], implode("\n\n", $text), $buttons);
        } catch (RuntimeException | InvalidArgumentException $e) { $this->protocolError($e->getMessage(), '/menu hy'); }
    }

    public function hyUserCommand(string $id, string $action = 'show'): void
    {
        if (!$this->admin) return;
        try {
            if ($id === 'add') { $this->hyUserPrompt('', 'name'); return; }
            if ($id === 'legacy-off') {
                $this->update($this->input['chat'], $this->input['message_id'],
                    'Отключить общий пароль Hysteria? Все старые общие ссылки перестанут подключаться. Персональные доступы сохранятся.',
                    [[['text' => 'Отключить', 'callback_data' => '/hyUser legacy-confirm']],
                     [['text' => 'Отмена', 'callback_data' => '/hyUsers']]]);
                return;
            }
            if ($id === 'legacy-confirm') {
                $this->withLock('hysteria', function () {
                    $this->pacConfUpdate(static function (&$pac) { unset($pac['hysteria_pass']); });
                });
                $this->restartHysteria();
                $this->hyUsers();
                return;
            }
            $store = $this->hysteriaUsersStore();
            if (!isset($store->read()['users'][$id])) { $this->hyUsers(); return; }
            if (in_array($action, ['name', 'expires', 'quota'], true)) { $this->hyUserPrompt($id, $action); return; }
            if ($action === 'delete') {
                $this->update($this->input['chat'], $this->input['message_id'], 'Удалить персональный доступ Hysteria?',
                    [[['text' => 'Удалить', 'callback_data' => "/hyUser $id delete-confirm"]],
                     [['text' => 'Отмена', 'callback_data' => "/hyUser $id"]]]);
                return;
            }
            if (in_array($action, ['toggle', 'rotate', 'reset', 'delete-confirm'], true)) {
                $store->edit($id, $action === 'delete-confirm' ? 'delete' : $action);
                if ($action === 'delete-confirm') { $this->hyUsers(); return; }
            } elseif (!in_array($action, ['show', 'file', 'qr'], true)) {
                throw new InvalidArgumentException('Неизвестное действие Hysteria');
            }
            $this->hyUserMenu($id);
            if (in_array($action, ['file', 'qr'], true)) {
                $link = $this->hyPersonalLink($id);
                if ($link === '') throw new RuntimeException('Доступ выключен, ограничен или ещё не применён');
                $this->protocolOutput = true;
                if ($action === 'qr') $this->sendQr('hysteria-' . $id, $link, 'Hysteria');
                else $this->sendFile($this->input['chat'], new CURLStringFile($link . "\n", 'hysteria-' . $id . '.txt', 'text/plain'));
                $this->protocolOutput = false;
            }
        } catch (RuntimeException | InvalidArgumentException $e) {
            $this->protocolOutput = false;
            $this->protocolError($e->getMessage(), '/hyUsers');
        }
    }

    public function hyUserPrompt(string $id, string $field): void
    {
        $prompts = ['name' => 'Введите имя пользователя Hysteria (до 60 символов).',
            'expires' => 'Введите срок в UTC: YYYY-MM-DD HH:MM. Значение 0 снимает ограничение.',
            'quota' => 'Введите общий лимит отправленного и полученного трафика в GiB, например 10 или 0.5. Значение 0 снимает ограничение.'];
        if (!$this->admin || !isset($prompts[$field])) return;
        $r = $this->send($this->input['chat'], $prompts[$field], $this->input['message_id'], reply: 'Введите значение');
        $this->stashReply($r, ['start_message' => $this->input['message_id'], 'callback' => 'hyUserReply', 'args' => [$id, $field]]);
    }

    public function hyUserReply(string $text, string $id, string $field): void
    {
        if (!$this->admin) return;
        try {
            $store = $this->hysteriaUsersStore();
            $text = trim($text);
            if ($id === '') {
                if ($field !== 'name') throw new InvalidArgumentException('Неверное действие');
                if (!$this->hyPersonalReady()) throw new RuntimeException('Сначала обновите и запустите образ Hysteria с поддержкой персональных доступов');
                $id = $store->add($text);
            } else {
                if ($field === 'name') $value = $text;
                elseif ($field === 'expires') {
                    $value = null;
                    if ($text !== '0') {
                        $date = DateTimeImmutable::createFromFormat('!Y-m-d H:i', $text, new DateTimeZone('UTC'));
                        if (!$date || $date->format('Y-m-d H:i') !== $text) throw new InvalidArgumentException('Нужна дата YYYY-MM-DD HH:MM в UTC или 0');
                        $value = $date->getTimestamp();
                    }
                } elseif ($field === 'quota') {
                    if (!preg_match('/\A[0-9]{1,7}(?:[.,][0-9]{1,6})?\z/D', $text)) throw new InvalidArgumentException('Нужен лимит от 0 до 1000000 GiB');
                    $gib = (float) str_replace(',', '.', $text);
                    if ($gib > 1000000) throw new InvalidArgumentException('Лимит слишком велик');
                    $value = $gib > 0 ? max(1, (int) round($gib * 1073741824)) : null;
                } else throw new InvalidArgumentException('Неизвестное поле');
                $store->edit($id, $field, $value);
            }
            $this->hyUserMenu($id);
        } catch (RuntimeException | InvalidArgumentException $e) { $this->protocolError($e->getMessage(), $id === '' ? '/hyUsers' : "/hyUser $id"); }
    }

    public function hyPersonalLink(string $id): string
    {
        $store = $this->hysteriaUsersStore();
        $state = $store->read();
        $user = $state['users'][$id] ?? null;
        if (!$user || !$user['enabled'] || ($user['expires'] !== null && $user['expires'] <= time())
            || !$this->protocolModuleEnabled('hy') || !$this->hyPersonalReady()) return '';
        $row = $store->usage()['users'][$id] ?? null;
        if ($user['quota'] !== null && (!$row || $row['reset'] !== $user['reset'] || $row['upload'] + $row['download'] >= $user['quota'])) return '';
        $link = $this->linkHysteria(null, $id . ':' . $user['password']);
        return $link === '' ? '' : explode('#', $link, 2)[0] . '#' . rawurlencode('Hysteria · ' . $user['name']);
    }

    public function hyUserMenu(string $id): void
    {
        if (!$this->admin) return;
        $store = $this->hysteriaUsersStore();
        $user = $store->read()['users'][$id] ?? null;
        if (!$user) { $this->hyUsers(); return; }
        $usage = $store->usage();
        $row = $usage['users'][$id] ?? null;
        $bytes = $row && $row['reset'] === $user['reset'] ? $row['upload'] + $row['download'] : 0;
        $text = ['Hysteria → ' . self::esc($user['name']),
            'Доступ: ' . AccessPolicy::reason($user, AccessPolicy::bytes($user, $row), time()),
            'Срок (UTC): ' . ($user['expires'] === null ? 'без ограничения' : gmdate('Y-m-d H:i', $user['expires'])),
            'Расход: ' . number_format($bytes / 1073741824, 3, '.', '') . ' GiB',
            'Квота: ' . ($user['quota'] === null ? 'без ограничения' : number_format($user['quota'] / 1073741824, 6, '.', '') . ' GiB')];
        if ($user['quota'] !== null && AccessPolicy::bytes($user, $row) !== null) $text[] = 'Осталось: ' . $this->getBytes(max(0, $user['quota'] - $bytes));
        array_push($text, ...$this->accessPolicySummary($user));
        $link = $this->hyPersonalLink($id);
        if ($link !== '') $text[] = '<code>' . self::esc($link) . '</code>';
        else $text[] = 'Ссылка недоступна: проверьте ограничения и состояние Hysteria.';
        $buttons = [
            [['text' => 'Календарь и уведомления', 'callback_data' => "/ap hy $id"]],
            [['text' => $user['enabled'] ? 'Выключить' : 'Включить', 'callback_data' => "/hyUser $id toggle"], ['text' => 'Имя', 'callback_data' => "/hyUser $id name"]],
            [['text' => 'Срок', 'callback_data' => "/hyUser $id expires"], ['text' => 'Квота', 'callback_data' => "/hyUser $id quota"]],
            [['text' => 'Сменить реквизиты', 'callback_data' => "/hyUser $id rotate"], ['text' => 'Сбросить расход', 'callback_data' => "/hyUser $id reset"]],
        ];
        if ($link !== '') $buttons[] = [['text' => 'Ссылка TXT', 'callback_data' => "/hyUser $id file"], ['text' => 'QR', 'callback_data' => "/hyUser $id qr"]];
        $buttons[] = [['text' => 'Удалить', 'callback_data' => "/hyUser $id delete"], ['text' => $this->i18n('back'), 'callback_data' => '/hyUsers']];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n\n", $text), $buttons);
    }

    // ── Тонкие настройки ядра (Hysteria 2.8–2.13) ───────────────────────────
    // Обфускация: Salamander превращает пакеты в шум; Gecko (с 2.9.2,
    // экспериментальная) дополнительно дробит пакеты рукопожатия QUIC. Тип
    // обязан совпадать у сервера и клиента и уходит в hy2://-ссылку.
    public const HY_OBFS_TYPES = ['salamander', 'gecko'];
    // Управление перегрузкой без Brutal (с 2.8.0): три профиля BBR и Reno.
    public const HY_CC = [
        'bbr'              => ['type' => 'bbr', 'bbrProfile' => 'standard'],
        'bbr-conservative' => ['type' => 'bbr', 'bbrProfile' => 'conservative'],
        'bbr-aggressive'   => ['type' => 'bbr', 'bbrProfile' => 'aggressive'],
        'reno'             => ['type' => 'reno'],
    ];

    public function hyObfsType(array $pac): string
    {
        return in_array($pac['hysteria_obfs_type'] ?? '', self::HY_OBFS_TYPES, true) ? $pac['hysteria_obfs_type'] : 'salamander';
    }

    public function hyCc(array $pac): string
    {
        return isset(self::HY_CC[$pac['hysteria_cc'] ?? '']) ? $pac['hysteria_cc'] : 'bbr';
    }

    // Gecko старое ядро не знает и с таким конфигом не стартует вовсе.
    public function hyGeckoSupported(): bool
    {
        return preg_match('~\d+(?:\.\d+)+~', html_entity_decode($this->hysteriaVersion()), $m) === 1 && version_compare($m[0], '2.9.2', '>=');
    }

    // Единственное место, где настройки из pac попадают в hysteria.yaml.
    public function hyApplyTuning(array $c, array $pac): array
    {
        if (!empty($pac['hysteria_obfs'])) {
            $type = $this->hyObfsType($pac);
            $c['obfs'] = ['type' => $type, $type => ['password' => $pac['hysteria_obfs']]];
        } else {
            unset($c['obfs']);
        }
        if (!empty($pac['hysteria_bw_up']) && !empty($pac['hysteria_bw_down'])) {
            $c['bandwidth'] = ['up' => $pac['hysteria_bw_up'], 'down' => $pac['hysteria_bw_down']];
            // Компенсация потерь Brutal шлёт быстрее заданной полосы; на
            // некоторых каналах её отключение делает скорость ровнее (с 2.10.0).
            if (!empty($pac['hysteria_no_loss_comp'])) $c['bandwidth']['disableLossCompensation'] = true;
        } else {
            unset($c['bandwidth']);
        }
        $c['congestion'] = self::HY_CC[$this->hyCc($pac)];
        // Сервер не верит полосе, заявленной клиентом, и применяет свой
        // контроллер: клиент не может выпросить себе Brutal.
        if (!empty($pac['hysteria_ignore_client_bw'])) $c['ignoreClientBandwidth'] = true;
        else unset($c['ignoreClientBandwidth']);
        // Sniff достаёт домен из HTTP/TLS/QUIC и заменяет им адрес назначения:
        // имя резолвит AdGuard сервера, и его фильтры действуют, даже когда
        // клиент прислал готовый IP.
        if (!empty($pac['hysteria_sniff'])) $c['sniff'] = ['enable' => true, 'timeout' => '2s'];
        else unset($c['sniff']);

        return $c;
    }

    public function hyTune(string $action = ''): void
    {
        $pac = $this->getPacConf();
        $before = $pac;
        $notice = '';
        switch ($action) {
            case 'obfs':
                if (empty($pac['hysteria_obfs'])) break;
                if ($this->hyObfsType($pac) === 'salamander' && !$this->hyGeckoSupported()) {
                    $notice = 'Gecko требует ядро Hysteria 2.9.2 или новее: обновите образ.';
                    break;
                }
                $pac['hysteria_obfs_type'] = $this->hyObfsType($pac) === 'gecko' ? 'salamander' : 'gecko';
                break;
            case 'cc':
                $keys = array_keys(self::HY_CC);
                $pac['hysteria_cc'] = $keys[(array_search($this->hyCc($pac), $keys, true) + 1) % count($keys)];
                break;
            case 'loss':
            case 'ignorebw':
            case 'sniff':
                $key = ['loss' => 'hysteria_no_loss_comp', 'ignorebw' => 'hysteria_ignore_client_bw', 'sniff' => 'hysteria_sniff'][$action];
                if (empty($pac[$key])) $pac[$key] = 1;
                else unset($pac[$key]);
                break;
        }
        if ($pac !== $before) {
            $this->setPacConf($pac);
            if (!$this->restartHysteria()) {
                // Конфиг не записан или ядро его не приняло: настройку не оставляем.
                $this->setPacConf($before);
                $pac = $before;
                $notice = 'Не удалось применить настройку: конфигурация Hysteria не изменена.';
            }
        }
        $brutal = !empty($pac['hysteria_bw_up']) && !empty($pac['hysteria_bw_down']);
        $obfs = !empty($pac['hysteria_obfs']);
        $on = fn($value) => $this->i18n($value ? 'on' : 'off');
        $text = ['Menu -> Hysteria -> ' . $this->i18n('hy tune')];
        if ($notice !== '') $text[] = '⚠️ ' . $notice;
        $text[] = '<b>obfs</b>: ' . ($obfs ? $this->hyObfsType($pac) : $this->i18n('off')) . "\n" . $this->i18n('hy tune obfs');
        $text[] = '<b>cc</b>: ' . ($brutal ? 'brutal · ' : '') . $this->hyCc($pac) . "\n" . $this->i18n('hy tune cc');
        $text[] = '<b>' . $this->i18n('hy tune loss') . '</b>: ' . $on(empty($pac['hysteria_no_loss_comp'])) . "\n" . $this->i18n('hy tune loss note');
        $text[] = '<b>' . $this->i18n('hy tune ignorebw') . '</b>: ' . $on(!empty($pac['hysteria_ignore_client_bw'])) . "\n" . $this->i18n('hy tune ignorebw note');
        $text[] = '<b>sniff</b>: ' . $on(!empty($pac['hysteria_sniff'])) . "\n" . $this->i18n('hy tune sniff note');
        $data = [];
        if ($obfs) $data[] = [['text' => 'obfs: ' . $this->hyObfsType($pac), 'callback_data' => '/hyTune obfs']];
        $data[] = [['text' => 'cc: ' . $this->hyCc($pac), 'callback_data' => '/hyTune cc']];
        $data[] = [['text' => $this->i18n('hy tune loss') . ': ' . $on(empty($pac['hysteria_no_loss_comp'])), 'callback_data' => '/hyTune loss']];
        $data[] = [['text' => $this->i18n('hy tune ignorebw') . ': ' . $on(!empty($pac['hysteria_ignore_client_bw'])), 'callback_data' => '/hyTune ignorebw']];
        $data[] = [['text' => 'sniff: ' . $on(!empty($pac['hysteria_sniff'])), 'callback_data' => '/hyTune sniff']];
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => '/menu hy']];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n\n", $text), $data);
    }
}
