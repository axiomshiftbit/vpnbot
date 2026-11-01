<?php

/** Node maintenance descriptions, certificate screens and explicit snapshots. */
trait BotManagedNodeTools
{
    public function managedNodeTlsProbe(string $id, string $group = 'reality'): void
    {
        if (!in_array($group, ['reality', 'domains'], true)) return;
        $node=$this->managedNodes()[$id] ?? null;
        if (!$node || !$node['connected']) return;
        $lines=[$this->t('Ноды → Проверка TLS / ALPN', 'Nodes → TLS / ALPN check')];
        try {
            if (!empty($node['job'])) throw new RuntimeException('Node busy');
            $r=$this->managedNodeRpc($id,['action'=>'tls_probe']);
            if (!in_array($r['tls'] ?? '',['TLSv1.2','TLSv1.3'],true) || !in_array($r['alpn'] ?? '',['h2','http/1.1',''],true)
                || !is_int($r['record'] ?? null) || $r['record']<0 || $r['record']>18432
                || !is_string($r['name'] ?? null) || !filter_var($r['name'],FILTER_VALIDATE_DOMAIN,FILTER_FLAG_HOSTNAME)) throw new RuntimeException('Invalid probe');
            $raw='New, '.$r['tls'].",\nALPN protocol: ".$r['alpn']."\n<<< TLS RecordHeader\n17 03 03 ".sprintf('%02x %02x',$r['record']>>8,$r['record']&255);
            $verdict=self::realityMaskVerdict($raw);
            $lines[]='TLS: <b>'.self::esc($r['tls']).'</b> · ALPN: <b>'.self::esc($r['alpn'] ?: '—').'</b>';
            $lines[]='SNI: <code>'.self::esc($r['name']).'</code>';
            $lines[]=$this->t('Проверка выполнена с ноды. Сертификат и имя проверены. Проверяется применённая конфигурация, не черновик.', 'Checked from the node. Certificate and name verified. This probes applied settings, not a draft.');
            if (($r['transport'] ?? '')==='reality') {
                $lines[]=$this->t(...match($verdict['status']) {
                    'ok'=>['ru'=>'✅ Сайт отвечает по TLS 1.3; размер TLS-записи подходит для REALITY.', 'en'=>'✅ TLS 1.3 and a suitable REALITY record size confirmed.'],
                    'tls12'=>['ru'=>'❌ Сайт согласовал TLS 1.2. Для REALITY нужен TLS 1.3.', 'en'=>'❌ The site negotiated TLS 1.2. REALITY needs TLS 1.3.'],
                    default=>['ru'=>'⚠️ TLS-запись слишком короткая для новых ядер REALITY. Выберите другой сайт и проверьте соединение.', 'en'=>'⚠️ The TLS record is too short for recent REALITY cores. Select another site and test connectivity.'],
                });
            }
            $lines[]=$r['alpn']==='h2' ? $this->t('✅ Согласован ALPN h2.', '✅ ALPN h2 negotiated.') : $this->t('ℹ️ В этой проверке h2 не согласован. Настройки транспорта не изменены.', 'ℹ️ h2 was not negotiated in this probe. Transport settings are unchanged.');
        } catch (Throwable $e) {
            $lines[]=$this->t('❌ Проверка не завершена: возможны ошибка TLS/DNS, недоступность ноды, запрещённый адрес или выполняющаяся операция. Успех не подтверждён.', '❌ Probe did not complete: TLS/DNS failure, an unreachable node, a prohibited address or a running operation. Success is not confirmed.');
        }
        $this->update($this->input['chat'],$this->input['message_id'],implode("\n\n",$lines),[
            [['text'=>$this->t('Повторить проверку','Retry probe'),'callback_data'=>"/nodeTls $id $group"]],
            $this->menuHelpButton('nodeconfig', $id.'_'.$group),
            [['text'=>$this->i18n('back'),'callback_data'=>"/nodeSettings $id $group"]],
        ]);
    }

    private function managedNodeActionHelp(string $action): string
    {
        return $this->t(...(match ($action) {
            'restart' => ['ru'=>'Перезапускает контейнеры ноды с текущей конфигурацией. Ключи и пользователи сохраняются; бот проверит соединение.', 'en'=>'Restarts node containers with the current configuration. Keys and peers stay; the bot tests connectivity.'],
            'update_latest' => ['ru'=>'Устанавливает опубликованные образы из ветки master. Проверяет конфигурацию и трафик; при отказе возвращает предыдущую версию.', 'en'=>'Installs published master images, validates configuration and traffic, and rolls back on failure.'],
            'update_dev' => ['ru'=>'Устанавливает опубликованные тестовые образы из ветки dev. Это предварительная версия; при неудачной проверке выполняется откат.', 'en'=>'Installs published dev images. This is a preview version; failed checks cause rollback.'],
            'rollback' => ['ru'=>'Возвращает предыдущую подтверждённую конфигурацию ноды, её образы, сертификат и ключи. Внешним клиентам могут потребоваться прежние профили.', 'en'=>'Restores the previous confirmed configuration, images, certificate and keys. External clients may need their previous profiles.'],
            'renew' => ['ru'=>'Проверяет срок сертификата и продлевает его, когда это требуется. Если сертификат ещё действителен и не заменён, бот сообщит, что продление не требовалось. TCP/80 открывается только на время ACME.', 'en'=>'Checks certificate renewal. A certificate kept by the CA is reported as unchanged. TCP/80 opens only during ACME.'],
            'renew_force' => ['ru'=>'Запрашивает новый сертификат даже до истечения текущего. Возможны ограничения удостоверяющего центра. Успех подтверждается заменой сертификата, проверкой доменов и трафика; до этого рабочий сертификат сохраняется.', 'en'=>'Requests a new certificate even before expiry. CA limits apply. Success requires a changed installed certificate, domain validation and a traffic test.'],
            'certificate_delete' => ['ru'=>'Удаляет сертификат из текущей конфигурации и регистрации Certbot. Сначала примените REALITY с внешним доменом и отключённой заглушкой. Активный TLS удалить нельзя. Исторические резервные копии сохраняются; сертификат не отзывается в удостоверяющем центре.', 'en'=>'Removes the current certificate and Certbot registration. First apply external REALITY with cover disabled. Active TLS cannot be deleted. Historical backups remain; this does not revoke the certificate at the CA.'],
            'rotate_controller' => ['ru'=>'Заменяет UUID VLESS, которым основной бот входит на ноду. Это не токен Telegram и не ключ SSH. Бот автоматически получает новый профиль и проверяет его; UUID внешних подключений сохраняются.', 'en'=>'Changes the main bot’s VLESS UUID, not its Telegram token or SSH key. The new profile is adopted and tested automatically. External peer UUIDs stay.'],
            'rotate_reality' => ['ru'=>'Заменяет общие ключи REALITY и short ID. Основной бот обновится автоматически; внешним панелям потребуется обновить подписку или импортировать новый профиль.', 'en'=>'Rotates shared REALITY keys and short ID. The main bot updates automatically; external panels need an updated subscription or profile.'],
            'rotate_encryption' => ['ru'=>'Заменяет ключи включённого VLESS Encryption. Основной бот получает их автоматически. Обновите профили внешних клиентов.', 'en'=>'Rotates enabled VLESS Encryption keys. The main bot updates automatically. Refresh external client profiles.'],
            'rotate_mldsa' => ['ru'=>'Заменяет ключи включённой постквантовой подписи ML-DSA. Обновите внешние профили; основной бот обновится автоматически.', 'en'=>'Rotates enabled ML-DSA signing keys. Refresh external profiles; the main bot updates automatically.'],
            'rotate_wireguard' => ['ru'=>'Заменяет ключи и PSK канала WireGuard между ботом и нодой. Бот автоматически получает новые данные; текущая сессия канала будет пересоздана.', 'en'=>'Rotates WireGuard keys and PSK for the bot–node channel. The bot adopts them and recreates the session.'],
            'rotate_amnezia' => ['ru'=>'Заменяет ключи, PSK и Header Protection Key канала AmneziaWG. Настроенные параметры шаблона сохраняются. Для смены обфускации используйте «Перегенерировать» в AmneziaWG.', 'en'=>'Rotates AmneziaWG keys, PSK and Header Protection Key. Template overrides stay. Use Regenerate in AmneziaWG to change obfuscation.'],
            'new_domain' => ['ru'=>'Введите домен и направьте все его A/AAAA на ноду. Бот подготовит черновик со своей заглушкой. Проверьте дополнительные имена и нажмите «Применить»: выпуск, установка и проверка трафика выполняются одной операцией с откатом при отказе.', 'en'=>'Point every A/AAAA record to the node and enter the domain. Review the cover draft and aliases, then Apply. Issuance, installation and traffic verification form one operation with rollback on failure.'],
            'restore' => ['ru'=>'После подтверждения заменяет конфигурацию, ключи, сертификат, образы и внешние подключения ноды сохранённой копией. Бот проверяет SSH и реальный трафик. Сначала примените или отмените черновики. Для новой установки сначала привяжите SSH; общий архив бота дополнительно восстанавливает маршруты и подписки.', 'en'=>'After confirmation replaces node settings, keys, certificate, images and peers from the saved snapshot. SSH and traffic are verified. Apply or discard drafts first. Rebind SSH after reinstall; the full bot archive also restores routes and subscriptions.'],
            'rebind' => ['ru'=>'Используется после переустановки ноды или смены её SSH-ключа. Укажите адрес, порт и проверенный публичный ключ сервера. Новый ключ не принимается автоматически. Сохранённая копия остаётся на основном боте; затем выполните восстановление. До восстановления остальные изменения заблокированы.', 'en'=>'Use after reinstall or an SSH host-key change. Enter the address, port and verified public host key. New keys are never trusted automatically. The main bot keeps its snapshot; restore it next. Other changes remain blocked until recovery.'],
            'backup' => ['ru'=>'Сохраняет подтверждённую конфигурацию ноды, ключи, сертификат и внешние подключения на основном сервере. Копия заменяет предыдущую сохранённую копию ноды. Для скачивания архива используйте общий бэкап бота: он включает также SSH-привязку, маршруты и подписки.', 'en'=>'Saves confirmed node settings, keys, certificate and peers on the main server, replacing its saved snapshot. Download a full bot backup to include SSH enrollment, routes and subscriptions too.'],
            default => ['ru'=>'Операция может кратковременно прервать соединения ноды.', 'en'=>'This operation may briefly interrupt node connections.'],
        }));
    }

    private function managedNodeMaintenancePages(): array
    {
        $titles = [
            'restart'=>['ru'=>'Перезапустить','en'=>'Restart'],
            'update_latest'=>['ru'=>'Обновить с ветки master','en'=>'Update from master'],
            'update_dev'=>['ru'=>'Обновить с ветки dev','en'=>'Update from dev'],
            'rollback'=>['ru'=>'Откатить последнее изменение','en'=>'Roll back last change'],
            'renew'=>['ru'=>'Обновить сертификат','en'=>'Renew certificate'],
            'renew_force'=>['ru'=>'Принудительно выпустить сертификат','en'=>'Force certificate issuance'],
            'certificate_delete'=>['ru'=>'Удалить сертификат','en'=>'Delete certificate'],
            'new_domain'=>['ru'=>'Выпустить сертификат для нового домена','en'=>'Issue for a new domain'],
            'rotate_controller'=>['ru'=>'Сменить ключ клиента основного бота','en'=>'Rotate main bot client key'],
            'rotate_reality'=>['ru'=>'Сменить ключи REALITY','en'=>'Rotate REALITY keys'],
            'rotate_encryption'=>['ru'=>'Сменить ключи VLESS Encryption','en'=>'Rotate VLESS Encryption keys'],
            'rotate_mldsa'=>['ru'=>'Сменить ключи ML-DSA','en'=>'Rotate ML-DSA keys'],
            'rotate_wireguard'=>['ru'=>'Сменить ключи WireGuard','en'=>'Rotate WireGuard keys'],
            'rotate_amnezia'=>['ru'=>'Сменить ключи AmneziaWG','en'=>'Rotate AmneziaWG keys'],
            'backup'=>['ru'=>'Создать копию ноды','en'=>'Create node snapshot'],
            'restore'=>['ru'=>'Восстановить сохранённую копию ноды','en'=>'Restore saved node snapshot'],
            'rebind'=>['ru'=>'Привязать SSH после переустановки','en'=>'Rebind SSH after reinstall'],
        ];
        $pages=[];
        foreach ($titles as $action=>$title) $pages[$this->t(...$title)]=$this->managedNodeActionHelp($action);
        return $pages;
    }

    public function managedNodeMaintenanceHelp(string $id, int $page = 0): void
    {
        // Preserve callbacks in messages sent before the common help menu.
        if (isset($this->managedNodes()[$id])) $this->menuHelp('nodemaint', $page, $id);
    }

    public function managedNodeCertificateMenu(string $id, string $notice = ''): void
    {
        $node = $this->managedNodes()[$id] ?? null;
        if (!$node || !$node['connected']) return;
        $text = [$this->t('Ноды → Обслуживание → Сертификат', 'Nodes → Maintenance → Certificate'), ...$this->managedNodeDomainSummary($node),
            $this->t('Смена домена и дополнительных имён создаёт черновик. «Применить» выпустит сертификат, проверит все имена и переключит ноду с проверкой трафика. Каждый A/AAAA домена должен указывать на эту ноду.',
                'Changing the domain or aliases creates a draft. Apply issues and checks the certificate for every name, then switches the node with a traffic test. Every domain A/AAAA record must point to this node.')];
        if ($notice !== '') $text[] = self::esc($notice);
        $data = [];
        foreach (['renew'=>$this->t('Обновить сертификат','Renew certificate'), 'renew_force'=>$this->t('Принудительно выпустить сертификат','Force certificate issuance'),
            'certificate_delete'=>$this->t('Удалить сертификат','Delete certificate')] as $action=>$title) $data[] = [['text'=>$title,'callback_data'=>"/nodeRun $id $action"]];
        $data[] = [['text'=>$this->t('Выпустить сертификат для нового домена','Issue for a new domain'), 'callback_data'=>"/nodeNewDomain $id"]];
        $data[] = [['text'=>$this->t('Изменить домены и заглушку','Edit domains and cover'), 'callback_data'=>"/nodeSettings $id domains"]];
        $data[] = [['text'=>$this->i18n('back'), 'callback_data'=>"/nodeMaintenance $id"]];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n\n", $text), $data);
    }

    public function managedNodeNewDomain(string $id): void
    {
        $node=$this->managedNodes()[$id] ?? null;
        if (!$node || !$node['connected'] || $node['job']) return;
        $this->exitPrompt($this->t('Введите новый домен ноды. Будет подготовлен черновик с заглушкой под паролем и сертификатом для этого домена. Сначала направьте все A/AAAA на ноду; выпуск начнётся после «Применить».',
            'Enter the new node domain. A draft with a password cover and certificate will be prepared. First point every A/AAAA to the node; issuance starts on Apply.'), 'saveManagedNodeNewDomain', [$id]);
    }

    public function saveManagedNodeNewDomain($text, $id): void
    {
        $domain=strtolower(trim((string) $text));
        if (strlen($domain)>253 || !str_contains($domain,'.') || filter_var($domain,FILTER_VALIDATE_IP)
            || !filter_var($domain,FILTER_VALIDATE_DOMAIN,FILTER_FLAG_HOSTNAME)) {
            $this->managedNodeCertificateMenu($id,$this->t('Введите доменное имя без схемы, порта и пути.','Enter a domain name without scheme, port or path.')); return;
        }
        try {
            $this->managedNodeDraftWrite($id, static function (&$node) use ($domain) {
                if (!isset($node['draft'])) $node['draft_generation']=$node['status']['generation'] ?? '';
                $options=$node['draft'] ?? $node['status']['options'];
                $options['domain']=$domain; $options['cover']=true;
                if ($options['transport']==='reality') $options['mask']=$domain;
                $node['draft']=$options;
            });
            $this->managedNodeSettingsMenu($id,'domains',$this->t('Новый домен подготовлен. Проверьте дополнительные имена и примените настройки для выпуска сертификата.',
                'New domain prepared. Review aliases and apply to issue its certificate.'));
        } catch (Throwable $e) { $this->managedNodeCertificateMenu($id,$this->t('Изменение не подготовлено: нода занята.','Change not prepared: node busy.')); }
    }

    public function managedNodeBackup(string $id, bool $confirmed = false): void
    {
        if (!isset($this->managedNodes()[$id])) return;
        if (!$confirmed) {
            $this->update($this->input['chat'], $this->input['message_id'], $this->managedNodeActionHelp('backup'),
                [[['text'=>$this->t('Создать копию ноды','Create node snapshot'), 'callback_data'=>"/nodeBackup $id yes"]],
                 [['text'=>$this->i18n('back'), 'callback_data'=>"/nodeMaintenance $id"]]]);
            return;
        }
        try {
            $this->managedNodeLocked($id, function () use ($id) {
                $node = $this->managedNodes()[$id] ?? null;
                if (!$node || !$node['connected'] || $node['job'] || !empty($node['recovery_required'])) throw new RuntimeException('Node not ready');
                $status = $this->managedNodeRpc($id, ['action'=>'status']);
                if (!empty($status['pending'])) throw new RuntimeException('Unconfirmed change');
                if (($this->managedNodeTransport($id, 'snapshot')['saved'] ?? false) !== true) throw new RuntimeException('Snapshot not saved');
                // Read back via the protected helper: validate the stored JSON,
                // without sending its keys or certificate to Telegram.
                $saved = $this->managedNodeTransport($id, 'saved');
                if (!is_array($saved['snapshot'] ?? null) || !preg_match('~^[a-f0-9]{16}$~D', $saved['hash'] ?? '')) throw new RuntimeException('Snapshot unreadable');
                $this->managedNodeWrite($id, static function (&$node) { $node['backup_time'] = time(); });
            });
            $this->managedNodeMaintenance($id, $this->t('✅ Копия ноды создана и проверена. Скачайте общий бэкап бота, чтобы сохранить её вне основного сервера.', '✅ Node snapshot saved and verified. Download a full bot backup to keep it off the main server.'));
        } catch (Throwable $e) {
            $this->managedNodeMaintenance($id, $this->t('❌ Создание или проверка копии не завершены. Проверьте SSH и дождитесь завершения текущих операций.', '❌ Snapshot creation or verification failed. Check SSH and wait for active operations.'));
        }
    }

    private function managedNodeCertificateResult(array $job, array $status): string
    {
        $result = $job['result'] ?? [];
        if (($result['certificate_result'] ?? '') === 'unchanged') return 'unchanged';
        if (($result['certificate_result'] ?? '') === 'deleted') return empty($status['certificate']) ? 'deleted' : 'unverified';
        if (in_array($result['certificate_result'] ?? '', ['issued','renewed'], true)
            && preg_match('~^[a-f0-9]{64}$~D', $result['certificate_fingerprint'] ?? '')
            && hash_equals($result['certificate_fingerprint'], $status['certificate']['fingerprint'] ?? '')
            && ($status['certificate']['expires'] ?? 0) > time()+3600) return $result['certificate_result'];
        return 'unverified';
    }

    private function managedNodeCertificateNotice(string $result): string
    {
        return $this->t(...match ($result) {
            'renewed'=> ['ru'=>'✅ Сертификат обновлён успешно. Новый сертификат установлен; домены и соединение проверены.', 'en'=>'✅ Certificate renewed successfully. The new certificate is installed; domains and connectivity were checked.'],
            'issued'=> ['ru'=>'✅ Сертификат выпущен и установлен. Домены и соединение проверены.', 'en'=>'✅ Certificate issued and installed. Domains and connectivity were checked.'],
            'deleted'=> ['ru'=>'✅ Сертификат удалён из текущей конфигурации. Резервные копии сохранены.', 'en'=>'✅ Certificate removed from current configuration. Backups are retained.'],
            'unchanged'=> ['ru'=>'ℹ️ Сертификат не изменился: продление не требовалось. Для досрочной замены используйте принудительный выпуск.', 'en'=>'ℹ️ Certificate unchanged: renewal was not needed. Use forced issuance for early replacement.'],
            default=> ['ru'=>'⚠️ Обновление сертификата не подтверждено. Обновите состояние ноды и проверьте сертификат.', 'en'=>'⚠️ Certificate renewal is not verified. Refresh node status and check its certificate.'],
        });
    }
}
