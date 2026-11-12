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
            'update_latest' => ['ru'=>'Полное обновление до последнего опубликованного комплекта ветки master, прошедшего CI. Нода получает его коммит из GitHub по своему deploy-ключу, устанавливает управляющий код и службы, перестраивает защиту nftables, затем заменяет образы. Настройки, ключи и подключения сохраняются; образы подтверждаются только после проверки трафика, при отказе возвращаются прежние. Более старый код не устанавливается: ноду с dev нельзя откатить кнопкой master. Локальные правки в /root/vpnbot на ноде не трогаются.', 'en'=>'Full update to the latest published master bundle that passed CI. The node fetches its commit from GitHub with its deploy key, installs the control code and services, rebuilds the nftables guard, then replaces the images. Settings, keys and peers stay; images are confirmed only after a traffic test and restored on failure. Older code is never installed: a dev node cannot be downgraded by the master button. Local edits in /root/vpnbot on the node are left alone.'],
            'update_dev' => ['ru'=>'Полное обновление до опубликованного тестового комплекта ветки dev: сначала управляющий код ноды из коммита комплекта, затем образы с проверкой трафика и откатом образов при отказе. Это предварительная версия; вернуться на master можно только после выхода в master не менее нового коммита.', 'en'=>'Full update to the published dev preview bundle: first the node control code from the bundle commit, then the images with a traffic test and image rollback on failure. This is a preview version; returning to master requires a master release at least as new.'],
            // Nodes without the upgrade unit: the same buttons replace only images.
            'images_latest' => ['ru'=>'Устанавливает опубликованные образы из ветки master. Проверяет конфигурацию и трафик; при отказе возвращает предыдущую версию.', 'en'=>'Installs published master images, validates configuration and traffic, and rolls back on failure.'],
            'images_dev' => ['ru'=>'Устанавливает опубликованные тестовые образы из ветки dev. Это предварительная версия; при неудачной проверке выполняется откат.', 'en'=>'Installs published dev images. This is a preview version; failed checks cause rollback.'],
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
            'backup' => ['ru'=>'Сохраняет подтверждённую конфигурацию ноды, ключи, сертификат и внешние подключения на основном сервере. Копия заменяет предыдущую сохранённую копию ноды; файла при этом не создаётся. Файл этой ноды выдаёт «Скачать копию ноды». Общий бэкап бота (Настройки → «сохранить») включает копии всех нод, SSH-привязку, маршруты и подписки.', 'en'=>'Saves confirmed node settings, keys, certificate and peers on the main server, replacing its saved snapshot; no file is created. Download node snapshot sends this node’s file. The full bot backup (Settings → backup) includes all node snapshots, SSH enrollment, routes and subscriptions.'],
            'import' => ['ru'=>'Принимает файл из «Скачать копию ноды» этой же ноды и заменяет им сохранённую копию на основном сервере. Бот проверяет формат, контрольную сумму и ключ управления: копию другой ноды, изменённый или повреждённый файл он не принимает. Сама нода не меняется: сразу после загрузки бот предлагает «Восстановить эту копию» с проверкой трафика и автоматическим откатом. Если до восстановления сохранённая копия обновится (новое изменение ноды или общий бэкап), бот откажется восстанавливать — загрузите файл ещё раз.', 'en'=>'Accepts a file from Download node snapshot of this same node and replaces the saved snapshot on the main server with it. The bot checks the format, checksum and controller key: it rejects another node’s snapshot and edited or damaged files. The node itself does not change: right after the upload the bot offers Restore this snapshot with a traffic test and automatic rollback. If the saved snapshot is refreshed before the restore (a new node change or a full backup), the bot refuses to restore — upload the file again.'],
            'export' => ['ru'=>'Отправляет в ваш личный чат файл .json с копией этой ноды: настройки Xray, ключи подключений и REALITY, сертификат, внешние подключения и резервные каналы. Если нода доступна, бот сначала делает свежую копию; иначе отправляет последнюю сохранённую и пишет её дату. В файле нет SSH-ключа управления: восстановить из него можно только эту же ноду в этом основном боте. При потере основного сервера нужен общий бэкап бота. Файл содержит секреты — храните его как пароль.', 'en'=>'Sends a .json file with this node’s snapshot to your private chat: Xray settings, connection and REALITY keys, certificate, external peers and backup carriers. A reachable node gets a fresh snapshot first; otherwise the last saved one is sent with its date. The file has no SSH controller key: it restores only this node in this main bot. If the main server is lost, use the full bot backup. The file holds secrets — keep it like a password.'],
            default => ['ru'=>'Операция может кратковременно прервать соединения ноды.', 'en'=>'This operation may briefly interrupt node connections.'],
        }));
    }

    private function managedNodeManualCode(): string
    {
        return $this->t('Код этой ноды ещё не поддерживает обновление кнопкой: кнопки обновят только образы. Один раз обновите код на ноде вручную по разделу readme «Обновление кода ноды с сервера» — после этого кнопки будут обновлять и код, и образы.',
            'This node’s code does not support updating by button yet: the buttons update only images. Update the code on the node manually once, as in the readme section on updating node code from the server; afterwards the buttons update both code and images.');
    }

    private function managedNodeUpgradeFailure(string $stage): string
    {
        $reason = match ($stage) {
            'bundle' => ['ru'=>'не удалось получить опубликованный комплект образов из реестра','en'=>'the published image bundle could not be fetched from the registry'],
            'repository' => ['ru'=>'на ноде нет Git-клона /root/vpnbot (установка из архива); обновите код вручную','en'=>'the node has no Git clone in /root/vpnbot (archive installation); update the code manually'],
            'fetch' => ['ru'=>'нода не получила коммит из GitHub: проверьте deploy-ключ и доступ к ssh.github.com:443','en'=>'the node could not fetch the commit from GitHub: check its deploy key and access to ssh.github.com:443'],
            'downgrade' => ['ru'=>'опубликованный комплект старее установленного кода (например, нода установлена с dev); более старый код не устанавливается','en'=>'the published bundle is older than the installed code (for example, a dev node); older code is never installed'],
            'source' => ['ru'=>'не удалось извлечь исходники коммита','en'=>'the commit sources could not be extracted'],
            default => str_starts_with($stage, 'setup_')
                ? ['ru'=>'установщик кода остановился на этапе [%s]; подробности в /var/log/vpnbot-node/setup.log на ноде','en'=>'the code installer stopped at stage [%s]; see /var/log/vpnbot-node/setup.log on the node']
                : ['ru'=>'непредвиденный сбой; подробности в /var/log/vpnbot-node/setup.log на ноде','en'=>'unexpected failure; see /var/log/vpnbot-node/setup.log on the node'],
        };
        $reason = str_replace('%s', substr($stage, 6), $this->t(...$reason));
        // These installer stages run after the new modules were copied.
        $copied = in_array($stage, ['setup_firewall', 'setup_verify'], true)
            ? ' ' . $this->t('Новый код ноды уже скопирован, но защита nftables не подтверждена; повторное обновление установит код заново.', 'The new node code was already copied, but the nftables guard was not confirmed; repeating the update installs the code again.')
            : '';
        return $this->t('❌ Обновление кода ноды не выполнено: ', '❌ Node code update failed: ') . self::esc($reason) . '.' . $copied . ' '
            . $this->t('Образы не менялись, контейнеры продолжают работать. Устраните причину и повторите обновление.', 'Images were not changed and the containers keep running. Fix the cause and repeat the update.');
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
            'export'=>['ru'=>'Скачать копию ноды','en'=>'Download node snapshot'],
            'import'=>['ru'=>'Загрузить копию ноды','en'=>'Upload node snapshot'],
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
            $this->managedNodeMaintenance($id, $this->t('✅ Копия ноды создана и проверена. Она хранится на основном сервере; чтобы сохранить её у себя, нажмите «📥 Скачать копию ноды».', '✅ Node snapshot saved and verified. It is kept on the main server; to keep a copy yourself, press 📥 Download node snapshot.'));
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
