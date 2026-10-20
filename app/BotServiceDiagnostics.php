<?php

trait BotServiceDiagnostics
{
    public static function serviceErrorText(string $code): string
    {
        return match ($code) {
            '' => Lang::t('нет', 'none'),
            'tls_expired' => Lang::t('сертификат TLS истёк; обновите SSL', 'the TLS certificate has expired; renew SSL'),
            'tls_not_yet_valid' => Lang::t('сертификат TLS ещё не действует; проверьте время сервера', 'the TLS certificate is not valid yet; check the server time'),
            'tls_name_mismatch' => Lang::t('сертификат не соответствует SNI', 'the certificate does not match the SNI'),
            'tls_key_mismatch' => Lang::t('сертификат TLS и закрытый ключ не соответствуют друг другу', 'the TLS certificate and private key do not match'),
            'tls_invalid' => Lang::t('сертификат TLS не прошёл проверку', 'the TLS certificate failed verification'),
            'tls_unavailable' => Lang::t('не удалось прочитать сертификат или ключ TLS', 'could not read the TLS certificate or key'),
            'port_in_use' => Lang::t('порт уже занят; выберите свободный порт', 'the port is already in use; choose a free port'),
            'port_unavailable' => Lang::t('порт или адрес недоступен для привязки', 'the port or address cannot be bound'),
            'core_unavailable' => Lang::t('исполняемый файл ядра отсутствует или недоступен', 'the core executable is missing or unavailable'),
            'configuration_rejected' => Lang::t('ядро отклонило конфигурацию; проверьте параметры', 'the core rejected the configuration; check the parameters'),
            'stats_unavailable', 'quota_stats_unavailable' => Lang::t('недоступен учёт трафика', 'traffic accounting is unavailable'),
            'start_failed' => Lang::t('ядро не подтвердило готовность после запуска', 'the core did not confirm readiness after start'),
            default => Lang::t('состояние или конфигурация недоступны; проверьте сервис', 'the state or configuration is unavailable; check the service'),
        };
    }

    public function serviceDiagnosticLines(string $scope): array
    {
        $store = $this->accessStore($scope); $state = $store->read(); $status = $store->status();
        $name = $scope === 'hy' ? 'Hysteria' : ManagedProtocol::NAMES[$scope];
        $lines = [$name . $this->t(' → Диагностика', ' → Diagnostics')];
        $fresh = ($status['time'] ?? 0) >= time() - 15;
        $lines[] = $this->t('Состояние: ', 'State: ') . (!$fresh ? $this->t('нет свежего ответа контроллера', 'no fresh answer from the controller') : (!empty($status['running']) ? $this->t('работает', 'running') : $this->t('остановлен', 'stopped')));
        $lines[] = $this->t('Применение настроек: ', 'Applying settings: ') . (($status['revision'] ?? null) === $state['revision'] ? $this->t('завершено', 'done') : $this->t('ожидается', 'pending'));
        $lines[] = $this->t('Ошибка: ', 'Error: ') . self::serviceErrorText((string) ($status['error'] ?? ''));
        foreach (['last_validation' => $this->t('Последняя успешная проверка', 'Last successful check'), 'last_success' => $this->t('Последнее успешное применение', 'Last successful apply')] as $field => $label) {
            $lines[] = $label . ' (UTC): ' . (!empty($status[$field]) ? gmdate('Y-m-d H:i:s', $status[$field]) : $this->t('ещё нет данных', 'no data yet'));
        }
        $cert = null;
        if ($scope === 'hy') {
            $config = @yaml_parse_file($this->hysteriaConf);
            if (is_array($config) && is_string($config['tls']['cert'] ?? null)) $cert = $config['tls']['cert'];
        } elseif (in_array($scope, ['anytls', 'tuic', 'masque'], true)) $cert = $state['settings']['certificate'];
        elseif ($scope === 'shadowtls' && !empty($state['settings']['self_hosted'])) $cert = '/certs/cert_public';
        if ($cert !== null) {
            try {
                $path = $this->managedCertificatePath($cert);
                $pem = @file_get_contents($path, false, null, 0, 1048576);
                $info = $pem ? @openssl_x509_parse($pem) : false;
            } catch (RuntimeException | InvalidArgumentException $e) { $info = false; }
            if (!$info || empty($info['validTo_time_t'])) $lines[] = $this->t('TLS: сертификат не найден или повреждён', 'TLS: certificate not found or damaged');
            else {
                $end = $info['validTo_time_t']; $start = $info['validFrom_time_t'] ?? 0;
                $phase = $end <= time() ? $this->t('истёк', 'expired') : ($start > time() ? $this->t('ещё не действует', 'not valid yet') : $this->t('действует', 'valid'));
                $lines[] = 'TLS: ' . $phase . $this->t('; до ', '; until ') . gmdate('Y-m-d H:i', $end) . ' UTC';
            }
        } elseif ($scope === 'mieru') $lines[] = $this->t('TLS: не используется протоколом Mieru', 'TLS: not used by the Mieru protocol');
        elseif ($scope === 'snolc') $lines[] = $this->t('SSH + Noise: ключи сервера закреплены в профиле; TLS не используется', 'SSH + Noise: the server keys are pinned in the profile; TLS is not used');
        elseif ($scope === 'shadowtls') $lines[] = $this->t('TLS сайта прикрытия проверяется клиентом; локального сертификата нет', 'The cover site TLS is verified by the client; there is no local certificate');
        if ($scope !== 'hy') {
            $file = dirname($this->protocolModulesFile) . '/protocol-services.status.json';
            $modules = is_file($file) ? ManagedProtocol::readJson($file) : [];
            if (isset($modules['errors'][$scope])) $lines[] = $this->t('Публикация порта: ', 'Port publishing: ') . self::serviceErrorText((string) $modules['errors'][$scope]);
            else $lines[] = $this->t('Публикация порта: ', 'Port publishing: ') . ($this->protocolPortApplied($scope, $state) ? $this->t('применена', 'applied') : $this->t('ожидается', 'pending'));
        }
        return $lines;
    }

    public function serviceDiagnostics(string $scope): void
    {
        if (!$this->admin) return;
        $back = $scope === 'hy' ? '/menu hy' : "/protocol $scope";
        try {
            $this->update($this->input['chat'], $this->input['message_id'], implode("\n\n", array_map([self::class, 'esc'], $this->serviceDiagnosticLines($scope))), [
                [['text' => $this->t('Обновить', 'Refresh'), 'callback_data' => "/diag $scope"]],
                [['text' => $this->i18n('back'), 'callback_data' => $back]],
            ]);
        } catch (RuntimeException | InvalidArgumentException $e) { $this->protocolError($e->getMessage(), $back); }
    }
}
