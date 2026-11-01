<?php

/** Reuse the full bot's public presets; private channel keys stay on the node. */
trait BotManagedNodePresets
{
    private function managedNodeAmneziaGenerated(array $options, string $template): array
    {
        $version=$options['amnezia']['version'] ?? '3.1';
        if (!in_array($template, self::amneziaTemplateList((int)$version), true)) throw new InvalidArgumentException('Unsupported node template');
        // Never generate or transfer a HeaderProtectionKey in the controller.
        $params = $this->generateAmneziaKeys($template, static fn() => 'remote');
        unset($params['HeaderProtectionKey']);
        foreach (['H1','H2','H3','H4'] as $name) $params[$name]=(string)$params[$name];
        if (!str_starts_with($version,'3.')) $options['amnezia']['keepalive']=(string)(int)($options['amnezia']['keepalive'] ?? 25);
        $options['amnezia']['parameters'] = $params;
        $options['amnezia']['template'] = $template;
        $options['amnezia']['generated_at'] = time();
        $options['amnezia']['enabled'] = true;
        return $options;
    }

    private function managedNodePresetItems(string $kind, string $version = '3.1'): array
    {
        if ($kind === 'amnezia') {
            $result = [];
            foreach (self::amneziaTemplateList((int)$version) as $key) $result[$key] = ['label'=>self::AMNEZIA_TEMPLATE_LABELS[$key]];
            return $result;
        }
        if (preg_match('~^cps[1-5]$~D', $kind)) {
            $result = [];
            foreach ($this->cpsPresets() as $group=>$items) foreach ($items as $label=>$value) $result[(string) count($result)] = ['label'=>$group . ': ' . $label, 'value'=>$value];
            $result['quic'] = ['label'=>'QUIC Initial (RFC 9001)'];
            $result['clear'] = ['label'=>$this->t('Очистить пакет','Clear packet'), 'value'=>''];
            return $result;
        }
        if (in_array($kind, ['dpi_fragment','finalmask_fragment'], true)) return $this->fragmentPresets();
        if (in_array($kind, ['dpi_noise','finalmask_noise'], true)) return $this->noisePresets();
        return [];
    }

    public function managedNodePresets(string $id, string $kind, string $selected = ''): void
    {
        $node = $this->managedNodes()[$id] ?? null;
        $options=$node['draft'] ?? $node['status']['options'] ?? [];
        $version=$options['amnezia']['version'] ?? '3.1';
        $items = $this->managedNodePresetItems($kind,$version);
        if (!$node || !$node['connected'] || !$items) return;
        $group = $kind === 'amnezia' || str_starts_with($kind,'cps') ? 'amnezia' : explode('_',$kind)[0];
        if ($selected !== '') {
            try {
                $this->managedNodeDraftWrite($id, function (&$node) use ($kind, $selected, $items) {
                    $options = $node['draft'] ?? $node['status']['options'];
                    if ($kind === 'amnezia') {
                        $template = $selected === 'generate' ? ($options['amnezia']['template'] ?? self::awgTemplateForVer('standard_3',(int)($options['amnezia']['version']??'3.1'))) : $selected;
                        $options = $this->managedNodeAmneziaGenerated($options, $template);
                    } elseif (isset($items[$selected])) {
                        if (str_starts_with($kind,'cps')) {
                            $value = $selected === 'quic' ? $this->cpsQUICInitial('www.cloudflare.com') : $items[$selected]['value'];
                            $options = ManagedNodeFields::change($options, 'amnezia.parameters.I'.substr($kind,-1), $value);
                        } else {
                            [$target,$type] = explode('_',$kind);
                            $preset = $items[$selected];
                            $value = $type === 'fragment'
                                ? ['enabled'=>true,'packets'=>$preset['packets'],'length'=>$preset['length'],'delay'=>$preset['interval'],'maxSplit'=>$preset['maxSplit']]
                                : ['enabled'=>true,'reset'=>$options['xray'][$target]['noise']['reset'] ?? '5-10','list'=>$preset['list']];
                            $options['xray'][$target][$type] = $value;
                        }
                    } else throw new InvalidArgumentException('Unknown preset');
                    if (!isset($node['draft'])) $node['draft_generation'] = $node['status']['generation'] ?? '';
                    $node['draft'] = $options;
                });
                $this->managedNodeSettingsMenu($id, $group, $this->t('Шаблон подготовлен. Проверьте параметры и нажмите «Применить».', 'Preset prepared. Review the settings and choose Apply.'));
            } catch (Throwable $e) { $this->managedNodeSettingsMenu($id, $group, $this->t('Шаблон не подготовлен. Дождитесь завершения операции и проверьте состояние ноды.', 'Preset was not prepared. Wait for active operations and check node status.')); }
            return;
        }
        $text = [$this->t('Ноды → Готовые настройки', 'Nodes → Presets')];
        if ($kind === 'amnezia') {
            $text[] = $this->t('Шаблоны основного бота для выбранной версии: Classic — режим 1.5; Standard — баланс; Aggressive — больше обфускации и трафика; Mobile — меньше служебных пакетов. При применении проверяются оба конца канала.',
                'Full bot templates for the selected version: Classic for 1.5; Standard balances traffic; Aggressive adds obfuscation and overhead; Mobile reduces overhead. Both ends are tested.');
            $text[] = $this->t('«Перегенерировать» создаёт новые J/S/H/I и тайминги выбранного шаблона. Ключи канала сохраняются. Автогенерация делает то же по расписанию и заменяет ручные правки обфускации; при неудаче — откат и повтор не чаще раза в час.',
                'Regenerate replaces J/S/H/I and timings using the selected template while keeping channel keys. Scheduled generation also replaces manual obfuscation overrides; failure causes rollback and retries at most hourly.');
        } else $text[] = $this->t('Пресеты взяты из полной версии бота. Они не гарантируют обход DPI: после применения проверьте задержку и реальный трафик. QUIC Initial создаёт один корректный пакет; для обновления используйте повторную генерацию.',
            'Presets come from the full bot. They do not guarantee DPI evasion: check latency and traffic after applying. QUIC Initial generates one valid packet; regenerate to replace it.');
        $data=[];
        foreach ($items as $key=>$item) $data[]=[['text'=>mb_substr($item['label'],0,60), 'callback_data'=>"/nodePreset $id $kind $key"]];
        if ($kind === 'amnezia') {
            $data[]=[['text'=>$this->t('Перегенерировать конфигурацию','Regenerate configuration'), 'callback_data'=>"/nodePreset $id amnezia generate"]];
            $data[]=[['text'=>$this->t('Автогенерация по расписанию','Scheduled generation'), 'callback_data'=>"/nodeField $id amnezia.rotation_days"]];
        }
        $data[]=[['text'=>$this->i18n('back'),'callback_data'=>"/nodeSettings $id $group"]];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n\n",$text),$data);
    }

    private function managedNodeAutoAmnezia(string $id): void
    {
        $this->managedNodeLocked($id, function () use ($id) {
            $node = $this->managedNodes()[$id] ?? null;
            if (!$node || empty($node['connected']) || $node['job'] || isset($node['draft']) || !empty($node['recovery_required'])) return;
            $options = $node['status']['options'] ?? [];
            $awg = $options['amnezia'] ?? [];
            $days = $awg['rotation_days'] ?? 0;
            if (empty($awg['enabled']) || !in_array($days,[1,3,7,14,30],true)
                || (int) ($awg['generated_at'] ?? 0)+$days*86400 > time()
                || (int) ($node['awg_rotation_attempt'] ?? 0)+3600 > time()) return;
            $this->managedNodeWrite($id, static function (&$node) { $node['awg_rotation_attempt'] = time(); });
            $options = $this->managedNodeAmneziaGenerated($options, $awg['template'] ?? self::awgTemplateForVer('standard_3',(int)($awg['version']??'3.1')));
            $this->managedNodeSubmitLocked($id, 'configure', $options);
        });
    }
}
